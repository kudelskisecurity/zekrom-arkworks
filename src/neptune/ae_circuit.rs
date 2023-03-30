/* zekrom-arkworks
* Copyright (C) 2023
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, EqGadget},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::{
    api::{Sponge, SpongeAPI},
    common::pattern::gen_ae_pattern,
};

use super::chip::NeptuneChip;

#[derive(Clone)]
pub struct NeptuneAECircuit<F: PrimeField> {
    pub sponge: Sponge<NeptuneChip<F>>,
    pub message: Vec<F>,
    pub ciphertext: Vec<F>,
    pub key: F,
    pub nonce: F,
}

impl<F: PrimeField> NeptuneAECircuit<F> {
    /// Use the sponge to perform authenticated encryption
    ///
    /// This function encrypt a message over F (N blocks -> one field element in F)
    /// It takes a key and a nonce and will return a ciphertext made of N+1 elements in F
    /// The last of these elements is the tag, allowing authenticated encryption
    /// It follows the [SAFE API specification](https://hackmd.io/bHgsH6mMStCVibM_wYvb2w)
    pub fn encrypt(
        self,
        message: &[FpVar<F>],
        key: FpVar<F>,
        nonce: FpVar<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Generate the AE pattern of the SAFE API using the helper function
        let pattern = gen_ae_pattern(message.len(), 1, 1);

        let mut ciphertext = Vec::with_capacity(message.len() + 1);
        let mut sponge = self.sponge;

        // Initialize the sponge with the pattern, then absord the key and nonce
        sponge.start(pattern, None);
        sponge.absorb(1, &[key]);
        sponge.absorb(1, &[nonce]);

        // Generates the ciphertext by iterating over the message
        for block in message {
            ciphertext.push(sponge.squeeze(1)[0].clone() + block);
            sponge.absorb(1, &[block.clone()]);
        }

        // This is the tag of the message, we append it at the end of the ct
        ciphertext.push(sponge.squeeze(1)[0].clone());

        let res = sponge.finish();
        assert!(res.is_ok(), "The sponge didn't finish properly!");

        Ok(ciphertext)
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for NeptuneAECircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut m = Vec::with_capacity(self.message.len());
        let mut ct = Vec::with_capacity(self.message.len() + 1);

        for elem in self.message.iter() {
            m.push(FpVar::new_witness(cs.clone(), || Ok(elem))?);
        }

        for elem in self.ciphertext.iter() {
            ct.push(FpVar::new_input(cs.clone(), || Ok(elem))?);
        }

        let k = FpVar::new_witness(cs.clone(), || Ok(self.key))?;
        let n = FpVar::new_input(cs, || Ok(self.nonce))?;

        let result = self.encrypt(&m, k, n)?;

        result.enforce_equal(&ct)?;

        Ok(())
    }
}
