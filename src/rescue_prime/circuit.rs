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
    common::pattern::gen_hash_pattern,
};

use super::chip::RescuePrimeChip;

#[derive(Clone)]
pub struct RescuePrimeHashCircuit<F: PrimeField> {
    pub hash: F,
    pub message: Vec<F>,
    pub sponge: Sponge<RescuePrimeChip<F>>,
}

impl<F: PrimeField> RescuePrimeHashCircuit<F> {
    /// Use the sponge to compute the hash of a message
    ///
    /// It takes a message composed of blocks where a block is a field element in F
    /// It'll return a hash composed of one element in that safe field F
    /// This prototype could be extended to support larger digest size easily
    /// It follows the [SAFE API specification](https://hackmd.io/bHgsH6mMStCVibM_wYvb2w)
    pub fn hash(self, message: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
        let pattern = gen_hash_pattern(message.len(), 1);

        let mut sponge = self.sponge;

        sponge.start(pattern, None);
        sponge.absorb(message.len() as u32, message);
        let hash = sponge.squeeze(1)[0].clone();
        let res = sponge.finish();
        assert!(res.is_ok(), "The sponge didn't finish properly!");

        Ok(hash)
    }
}

// This is the important part where the constraints are created
impl<F: PrimeField> ConstraintSynthesizer<F> for RescuePrimeHashCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut v = Vec::with_capacity(self.message.len());
        for elem in self.message.iter() {
            v.push(FpVar::new_witness(cs.clone(), || Ok(elem))?);
        }
        let hash = FpVar::new_input(cs, || Ok(self.hash))?;

        let result = self.hash(&v)?;

        result.enforce_equal(&hash)?;

        Ok(())
    }
}
