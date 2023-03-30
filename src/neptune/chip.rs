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
use ark_relations::r1cs::SynthesisError;

use crate::{
    api::{ChipAPI, Sponge},
    common::pattern::IOPattern,
};

use super::params::*;

#[derive(Clone)]
pub struct NeptuneParameters<F: PrimeField> {
    pub nb_rounds_ext: [usize; 2],
    pub nb_rounds_int: usize,
    pub round_constants: Vec<FpVar<F>>,
    pub gamma: FpVar<F>,
    pub d: [u64; 4],
    pub matrix_int: Vec<FpVar<F>>,
}

/// This chip implements the [Neptune permutation](https://eprint.iacr.org/2021/1695.pdf)
///
/// It manages the state internally in order to only expose helper functions
/// This will allow us to create a sponge around it and implement SAFE
#[derive(Clone)]
pub struct NeptuneChip<F: PrimeField> {
    parameters: NeptuneParameters<F>,
    state: [FpVar<F>; M],
}

impl<F: PrimeField> NeptuneChip<F> {
    pub fn new(parameters: NeptuneParameters<F>) -> Self {
        Self {
            parameters,
            state: [FpVar::zero(), FpVar::zero(), FpVar::zero(), FpVar::zero()],
        }
    }

    fn internal_round(
        &self,
        index: usize,
        mut state: [FpVar<F>; 4],
    ) -> Result<[FpVar<F>; 4], SynthesisError> {
        // do the simple operation ^d on the first element of the state
        state[0] = state[0].pow_by_constant(self.parameters.d)?;

        let sum: FpVar<F> =
            state[0].clone() + state[1].clone() + state[2].clone() + state[3].clone();

        // Compute the state
        // + sum - state operation equal to adding every other element
        // the matrix diagonal value is used from the parameters
        // and finally the constant is added
        // a = a * matrix_val + b + c + d + const
        for (i, item) in state.iter_mut().enumerate() {
            *item = item.clone() * self.parameters.matrix_int[i].clone() + sum.clone()
                - item.clone()
                + self.parameters.round_constants[i + index * 4].clone();
        }

        Ok(state)
    }

    fn external_round(
        &self,
        index: usize,
        mut state: [FpVar<F>; 4],
    ) -> Result<[FpVar<F>; 4], SynthesisError> {
        // Compute the S(.) operation using s_func(x0,x1) -> y0, y1
        let (a, b) = Self::s_func(
            state[0].clone(),
            state[1].clone(),
            self.parameters.gamma.clone(),
        )?;
        let (c, d) = Self::s_func(
            state[2].clone(),
            state[3].clone(),
            self.parameters.gamma.clone(),
        )?;

        // Apply the M matrix and add the round constants
        state = [
            a.clone() + a.clone() + c.clone() + self.parameters.round_constants[index * 4].clone(),
            b.clone()
                + d.clone()
                + d.clone()
                + self.parameters.round_constants[index * 4 + 1].clone(),
            a + c.clone() + c + self.parameters.round_constants[index * 4 + 2].clone(),
            b.clone() + b + d + self.parameters.round_constants[index * 4 + 3].clone(),
        ];

        Ok(state)
    }

    /// This function represents the S(.) function of the external rounds in Neptune-p
    ///
    /// It takes as input two different elements (x0, x1) and map them to (y0, y1)
    /// It's the non-linear layer of the external round
    fn s_func(
        x0: FpVar<F>,
        x1: FpVar<F>,
        gamma: FpVar<F>,
    ) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
        // (x0 - x1)^2
        // (gamma + (x0-2x1) - (x0-x1)^2)^2
        let x0_x1_2 = (x0.clone() - x1.clone()).square()?;
        let last_term =
            (gamma + x0.clone() - x1.clone() - x1.clone() - x0_x1_2.clone()).square()?;

        let y0 = x0.clone()
            + x0.clone()
            + x1.clone()
            + x0_x1_2.clone()
            + x0_x1_2.clone()
            + x0_x1_2.clone()
            + last_term.clone();
        let y1 = x0
            + x1.clone()
            + x1.clone()
            + x1
            + x0_x1_2.clone()
            + x0_x1_2.clone()
            + x0_x1_2.clone()
            + x0_x1_2
            + last_term;

        Ok((y0, y1))
    }
}

impl<F: PrimeField> ChipAPI for NeptuneChip<F> {
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

    /// This function will do a permutation on the state, without exposing it
    /// It returns a result in order to propagate the potential error of internal rounds
    fn permutation(&mut self) -> Result<(), anyhow::Error> {
        for i in 0..self.parameters.nb_rounds_ext[0] {
            self.state = self.external_round(i, self.state.clone())?;
        }

        for i in 0..self.parameters.nb_rounds_int {
            self.state = self.internal_round(i + 4, self.state.clone())?;
        }

        for i in 0..self.parameters.nb_rounds_ext[1] {
            self.state = self.external_round(i + 68, self.state.clone())?;
        }

        Ok(())
    }
}

impl<F: PrimeField> Sponge<NeptuneChip<F>> {
    pub fn new(chip: NeptuneChip<F>) -> Self {
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
