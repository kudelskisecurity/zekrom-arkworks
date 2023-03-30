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
use ark_r1cs_std::{fields::fp::FpVar, prelude::FieldVar};

use crate::{
    api::{ChipAPI, Sponge},
    common::pattern::IOPattern,
    griffin::params::*,
};

#[derive(Clone)]
pub struct GriffinParameters<F: PrimeField> {
    pub nb_rounds: usize,
    pub round_constants: Vec<FpVar<F>>,
    pub alpha: FpVar<F>,
    pub beta: FpVar<F>,
    pub d: [u64; 4],
    pub d_inv: [u64; 4],
}

#[derive(Clone)]
pub struct GriffinChip<F: PrimeField> {
    parameters: GriffinParameters<F>,
    state: [FpVar<F>; M],
}

impl<F: PrimeField> GriffinChip<F> {
    pub fn new(parameters: GriffinParameters<F>) -> Self {
        Self {
            parameters,
            state: [FpVar::zero(), FpVar::zero(), FpVar::zero()],
        }
    }
}

impl<F: PrimeField> ChipAPI for GriffinChip<F> {
    type Value = FpVar<F>;

    fn init(&mut self, tag: u128) -> Result<(), anyhow::Error> {
        // This allows to "reset" when called with 0
        self.state = [FpVar::zero(), FpVar::zero(), FpVar::zero()];
        self.state[1] = FpVar::Constant(F::from(tag));
        Ok(())
    }

    fn read(&mut self) -> Self::Value {
        self.state[0].clone()
    }

    fn add(&mut self, val: &Self::Value) -> Result<(), anyhow::Error> {
        self.state[0] += val;
        Ok(())
    }

    fn permutation(&mut self) -> Result<(), anyhow::Error> {
        // First we apply the MDS(m) initial operation
        let sum = self.state[0].clone() + self.state[1].clone() + self.state[2].clone();
        self.state[0] = self.state[0].clone() + sum.clone();
        self.state[1] = self.state[1].clone() + sum.clone();
        self.state[2] = self.state[2].clone() + sum;

        for i in 0..self.parameters.nb_rounds - 1 {
            // Apply S
            self.state[0] = self.state[0]
                .clone()
                .pow_by_constant(self.parameters.d_inv)?;
            self.state[1] = self.state[1].clone().pow_by_constant(self.parameters.d)?;
            self.state[2] = (self.state[0].clone() + self.state[1].clone()).square()?
                + self.parameters.alpha.clone() * (self.state[0].clone() + self.state[1].clone())
                + self.parameters.beta.clone();

            // Apply M and C
            let sum = self.state[0].clone() + self.state[1].clone() + self.state[2].clone();
            self.state[0] = self.state[0].clone()
                + sum.clone()
                + self.parameters.round_constants[3 * i].clone();
            self.state[1] = self.state[1].clone()
                + sum.clone()
                + self.parameters.round_constants[3 * i + 1].clone();
            self.state[2] =
                self.state[2].clone() + sum + self.parameters.round_constants[3 * i + 2].clone();
        }

        // Apply S
        self.state[0] = self.state[0]
            .clone()
            .pow_by_constant(self.parameters.d_inv)?;
        self.state[1] = self.state[1].clone().pow_by_constant(self.parameters.d)?;
        self.state[2] = (self.state[0].clone() + self.state[1].clone()).square()?
            + self.parameters.alpha.clone() * (self.state[0].clone() + self.state[1].clone())
            + self.parameters.beta.clone();

        // Apply M - without the RC for the final one
        let sum = self.state[0].clone() + self.state[1].clone() + self.state[2].clone();
        self.state[0] = self.state[0].clone() + sum.clone();
        self.state[1] = self.state[1].clone() + sum.clone();
        self.state[2] = self.state[2].clone() + sum;

        Ok(())
    }
}

impl<F: PrimeField> Sponge<GriffinChip<F>> {
    pub fn new(chip: GriffinChip<F>) -> Self {
        Self {
            chip,
            absord_pos: 0,
            squeeze_pos: 0,
            op_count: 0,
            pattern: IOPattern::new(vec![]),
            rate: R,
        }
    }
}
