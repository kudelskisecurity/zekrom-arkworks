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

use super::chip::CiminionChip;

#[derive(Clone)]
pub struct CiminionCircuit<F: PrimeField> {
    pub chip: CiminionChip<F>,
    pub message: Vec<F>,
    pub ciphertext: Vec<F>,
    pub keys: (F, F),
    pub nonce: F,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for CiminionCircuit<F> {
    fn generate_constraints(mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut m = Vec::with_capacity(self.message.len());
        let mut ct = Vec::with_capacity(self.message.len() + 1);

        for elem in self.message.iter() {
            m.push(FpVar::new_witness(cs.clone(), || Ok(elem))?);
        }

        for elem in self.ciphertext.iter() {
            ct.push(FpVar::new_input(cs.clone(), || Ok(elem))?);
        }

        let mk1 = FpVar::new_witness(cs.clone(), || Ok(self.keys.0))?;
        let mk2 = FpVar::new_witness(cs.clone(), || Ok(self.keys.1))?;
        let n = FpVar::new_input(cs, || Ok(self.nonce))?;

        self.chip.init(mk1, mk2, self.message.len());
        let result = self.chip.ae(&m, n)?;

        result.enforce_equal(&ct)?;

        Ok(())
    }
}
