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

use std::iter::zip;

use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::FieldVar};
use ark_relations::r1cs::SynthesisError;

use ark_r1cs_std::R1CSVar;

#[derive(Clone)]
pub struct CiminionParameters<F: PrimeField> {
    pub nb_rounds_pe: usize,
    pub nb_rounds_pc: usize,
    pub round_constants: Vec<FpVar<F>>,
}

#[derive(Clone)]
pub struct CiminionChip<F: PrimeField> {
    parameters: CiminionParameters<F>,
    keys: Vec<FpVar<F>>,
}

impl<F: PrimeField> CiminionChip<F> {
    pub fn new(parameters: CiminionParameters<F>) -> Self {
        Self {
            parameters,
            keys: vec![],
        }
    }

    /// This inits an existing CiminionChip to perform encryption from the master keys MK1 and MK2.
    /// The parameter max_len defines the maximum length of a message that can be encrypted
    /// (it defines how many subkeys are generated, a costly process we want to run only once).
    /// By design, max_len shouldn't be odd, as N and N-1 use the same number of keys for any even N
    pub fn init(&mut self, mk1: FpVar<F>, mk2: FpVar<F>, max_len: usize) {
        self.keys = self.gen_keys(mk1, mk2, max_len)
    }

    pub fn ae(
        &self,
        message: &[FpVar<F>],
        nonce: FpVar<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        assert!(
            self.keys.len() >= message.len() + 3,
            "Stop talking! The chip doesn't support messages that long!"
        );

        let (state, t1) = self.gen_state_and_t(nonce);

        let mut ciphertext = Vec::with_capacity(message.len() + 1);
        let keystream = self.gen_keystream(state, message.len());

        for (pt_block, ks_block) in zip(message, keystream) {
            ciphertext.push(pt_block + ks_block)
        }

        let tag = Self::authenticate(&ciphertext, t1, self.keys[self.keys.len() - 1].clone());

        ciphertext.push(tag);

        Ok(ciphertext)
    }

    pub fn ad(
        &self,
        mut ciphertext: Vec<FpVar<F>>,
        nonce: FpVar<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        assert!(
            self.keys.len() >= ciphertext.len() + 2,
            "Ciphertext too long!"
        );

        let (state, t1) = self.gen_state_and_t(nonce);

        // We verify the tag before anything else
        let expected = ciphertext.pop().unwrap_or_else(|| FpVar::zero());
        let tag = Self::authenticate(&ciphertext, t1, self.keys[self.keys.len()].clone());
        assert!(
            tag.value() == expected.value(),
            "The tag didn't match, aborting!"
        );

        // If the tag matches, then proceed to decrypt
        let mut message = Vec::with_capacity(ciphertext.len());
        let keystream = self.gen_keystream(state, ciphertext.len());

        for (ct_block, ks_block) in zip(ciphertext, keystream) {
            message.push(ct_block + ks_block)
        }

        Ok(message)
    }

    fn gen_state_and_t(&self, nonce: FpVar<F>) -> ([FpVar<F>; 3], FpVar<F>) {
        let mut state = [nonce, self.keys[0].clone(), self.keys[1].clone()];
        self.pc(&mut state);
        let (t1, _) = self.pe(state.clone());

        (state, t1)
    }

    fn gen_keystream(&self, mut state: [FpVar<F>; 3], len: usize) -> Vec<FpVar<F>> {
        let mut keystream: Vec<FpVar<F>> = Vec::with_capacity(len);

        for i in (0..len).step_by(2) {
            self.iter(
                &mut state,
                self.keys[i + 2].clone(),
                self.keys[i + 3].clone(),
            );
            let (out1, out2) = self.pe(state.clone());
            keystream.push(out1);
            if i < len - 1 {
                keystream.push(out2);
            }
        }

        keystream
    }

    fn authenticate(ct: &[FpVar<F>], t1: FpVar<F>, key: FpVar<F>) -> FpVar<F> {
        let mut tag = FpVar::<F>::zero();

        for block in ct {
            tag += block;
            tag *= key.clone();
        }

        tag += FpVar::Constant(F::from(ct.len() as u32));
        tag *= key;
        tag += t1;

        tag
    }

    fn gen_keys(&self, mk1: FpVar<F>, mk2: FpVar<F>, len: usize) -> Vec<FpVar<F>> {
        let mut state = vec![FpVar::one(), mk1, mk2];

        let mut number_keys = len + 3;
        if len % 2 != 0 {
            number_keys += 1
        };

        let mut keys = Vec::with_capacity(number_keys);

        for _i in 0..number_keys {
            self.pc(&mut state);
            keys.push(state[0].clone());
        }

        keys
    }

    fn iter(&self, state: &mut [FpVar<F>], k1: FpVar<F>, k2: FpVar<F>) {
        // Add both keys to the state
        state[0] += k2;
        state[1] += k1;

        // Apply the rol function
        let tmp = state[2].clone() + state[1].clone() * state[0].clone();
        state[2] = state[1].clone();
        state[1] = state[0].clone();
        state[0] = tmp;
    }

    fn pc(&self, state: &mut [FpVar<F>]) {
        for i in 0..self.parameters.nb_rounds_pc {
            self.permutation(state, i);
        }
    }

    fn pe(&self, mut state: [FpVar<F>; 3]) -> (FpVar<F>, FpVar<F>) {
        for i in self.parameters.nb_rounds_pc - self.parameters.nb_rounds_pe
            ..self.parameters.nb_rounds_pc
        {
            self.permutation(&mut state, i);
        }

        (state[0].clone(), state[1].clone())
    }

    fn permutation(&self, state: &mut [FpVar<F>], i: usize) {
        let tmp = state[2].clone() + state[1].clone() * state[0].clone() + state[1].clone();

        let a = state[2].clone()
            + state[1].clone() * state[0].clone()
            + self.parameters.round_constants[4 * i + 2].clone();
        let b = state[0].clone()
            + self.parameters.round_constants[4 * i + 3].clone() * tmp.clone()
            + self.parameters.round_constants[4 * i].clone();
        let c = tmp.clone() + self.parameters.round_constants[4 * i + 1].clone();

        state[0] = a;
        state[1] = b;
        state[2] = c;
    }
}
