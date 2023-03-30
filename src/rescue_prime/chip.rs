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

use crate::{
    api::{ChipAPI, Sponge},
    common::pattern::IOPattern,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::FieldVar};

use super::params::{M, N, R};

// All parameters are generic in this one
#[derive(Clone)]
pub struct RescuePrimeParameters<F: PrimeField> {
    pub round_constants: Vec<FpVar<F>>,
    pub mds: Vec<FpVar<F>>,
    pub alpha_inv: [u64; 4],
    pub alpha: [u64; 4],
}

#[derive(Clone)]
pub struct RescuePrimeChip<F: PrimeField> {
    parameters: RescuePrimeParameters<F>,
    state: [FpVar<F>; M],
}

impl<F: PrimeField> RescuePrimeChip<F> {
    pub fn new(parameters: RescuePrimeParameters<F>) -> Self {
        Self {
            parameters,
            state: [FpVar::zero(), FpVar::zero(), FpVar::zero()],
        }
    }
}

// Implement the chip
impl<F: PrimeField> ChipAPI for RescuePrimeChip<F> {
    type Value = FpVar<F>;

    fn init(&mut self, tag: u128) -> Result<(), anyhow::Error> {
        self.state[1] = FpVar::Constant(F::from(tag));
        Ok(())
    }

    fn read(&mut self) -> FpVar<F> {
        self.state[0].clone()
    }

    fn add(&mut self, val: &FpVar<F>) -> Result<(), anyhow::Error> {
        self.state[0] += val;
        Ok(())
    }

    fn permutation(&mut self) -> Result<(), anyhow::Error> {
        for i in 0..N {
            for j in 0..M {
                self.state[j] = self.state[j].pow_by_constant(self.parameters.alpha)?;
            }

            self.state[0] = self.state[0].clone() * self.parameters.mds[0].clone()
                + self.state[1].clone() * self.parameters.mds[1].clone()
                + self.state[2].clone() * self.parameters.mds[2].clone()
                + self.parameters.round_constants[6 * i].clone();
            self.state[1] = self.state[0].clone() * self.parameters.mds[3].clone()
                + self.state[1].clone() * self.parameters.mds[4].clone()
                + self.state[2].clone() * self.parameters.mds[5].clone()
                + self.parameters.round_constants[6 * i + 1].clone();
            self.state[2] = self.state[0].clone() * self.parameters.mds[6].clone()
                + self.state[1].clone() * self.parameters.mds[7].clone()
                + self.state[2].clone() * self.parameters.mds[8].clone()
                + self.parameters.round_constants[6 * i + 2].clone();

            for j in 0..M {
                self.state[j] = self.state[j].pow_by_constant(self.parameters.alpha_inv)?;
            }

            self.state[0] = self.state[0].clone() * self.parameters.mds[0].clone()
                + self.state[1].clone() * self.parameters.mds[1].clone()
                + self.state[2].clone() * self.parameters.mds[2].clone()
                + self.parameters.round_constants[6 * i + 3].clone();
            self.state[1] = self.state[0].clone() * self.parameters.mds[3].clone()
                + self.state[1].clone() * self.parameters.mds[4].clone()
                + self.state[2].clone() * self.parameters.mds[5].clone()
                + self.parameters.round_constants[6 * i + 4].clone();
            self.state[2] = self.state[0].clone() * self.parameters.mds[6].clone()
                + self.state[1].clone() * self.parameters.mds[7].clone()
                + self.state[2].clone() * self.parameters.mds[8].clone()
                + self.parameters.round_constants[6 * i + 5].clone();
        }

        Ok(())
    }
}

impl<F: PrimeField> Sponge<RescuePrimeChip<F>> {
    pub fn new(chip: RescuePrimeChip<F>) -> Self {
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
