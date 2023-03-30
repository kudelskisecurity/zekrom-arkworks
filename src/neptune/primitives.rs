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

//! This module contains primitives used only for testing purpose with Neptune
//! They implement both hashing and authenticated encryption on both BLS12_381 and Vesta

#![allow(unused)] // Only used within tests

pub struct NeptunePrimitivesBlsFr {}

use std::io::Error;

use ark_r1cs_std::{fields::fp::FpVar, prelude::FieldVar};
use ark_relations::r1cs::SynthesisError;

use ark_bls12_381::Fr as BlsFr;
use ark_ff::BigInteger256 as I256;

use super::params::*;
use crate::common::pattern::*;

impl NeptunePrimitivesBlsFr {
    fn internal_round(
        index: usize,
        mut state: [FpVar<BlsFr>; 4],
    ) -> Result<[FpVar<BlsFr>; 4], SynthesisError> {
        // do the simple operation ^d on the first element of the state

        state[0] = state[0].clone().pow_by_constant(D)?;

        let sum: FpVar<BlsFr> =
            state[0].clone() + state[1].clone() + state[2].clone() + state[3].clone();

        // Compute the state
        // + sum - state operation equal to adding every other element
        // the matrix diagonal value is used from the parameters
        // and finally the constant is added
        // a = a * matrix_val + b + c + d + const
        for i in 0..state.len() {
            state[i] = state[i].clone()
                * FpVar::Constant(BlsFr::from(I256(INTERNAL_MATRIX_BLS[i])))
                + sum.clone()
                - state[i].clone()
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS_BLS[i + 4 * index])));
        }

        Ok(state)
    }

    fn external_round(
        index: usize,
        mut state: [FpVar<BlsFr>; 4],
    ) -> Result<[FpVar<BlsFr>; 4], SynthesisError> {
        // Compute the S(.) operation using s_func(x0,x1) -> y0, y1
        let (a, b) = Self::s_func(
            state[0].clone(),
            state[1].clone(),
            FpVar::Constant(BlsFr::from(I256(GAMMA_BLS))),
        )?;
        let (c, d) = Self::s_func(
            state[2].clone(),
            state[3].clone(),
            FpVar::Constant(BlsFr::from(I256(GAMMA_BLS))),
        )?;

        // Apply the M matrix and add the round constants
        state = [
            a.clone()
                + a.clone()
                + c.clone()
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS_BLS[4 * index]))),
            b.clone()
                + d.clone()
                + d.clone()
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS_BLS[4 * index + 1]))),
            a + c.clone()
                + c
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS_BLS[4 * index + 2]))),
            b.clone()
                + b
                + d
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS_BLS[4 * index + 3]))),
        ];

        Ok(state)
    }

    fn s_func(
        x0: FpVar<BlsFr>,
        x1: FpVar<BlsFr>,
        gamma: FpVar<BlsFr>,
    ) -> Result<(FpVar<BlsFr>, FpVar<BlsFr>), SynthesisError> {
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

    fn permutation(mut state: [FpVar<BlsFr>; 4]) -> [FpVar<BlsFr>; 4] {

        for i in 0..NEB {
            state = Self::external_round(i, state).unwrap();
        }

        for i in 0..NI {
            state = Self::internal_round(i + 4, state).unwrap();
        }

        for i in 0..NEE {
            state = Self::external_round(i + 68, state).unwrap();
        }

        state
    }

    pub fn hash(message: Vec<BlsFr>) -> Result<FpVar<BlsFr>, Error> {
        let mut state = [
            FpVar::zero(),
            FpVar::constant(BlsFr::from(
                gen_hash_pattern(message.len(), 1).get_tag(None),
            )),
            FpVar::zero(),
            FpVar::zero(),
        ];

        for element in message {
            state[0] = state[0].clone() + element;
            state = Self::permutation(state);
        }

        Ok(state[0].clone())
    }

    pub fn ae(message: Vec<BlsFr>, key: BlsFr, nonce: BlsFr) -> Result<Vec<FpVar<BlsFr>>, Error> {
        let mut state = [
            FpVar::zero(),
            FpVar::constant(BlsFr::from(
                gen_ae_pattern(message.len(), 1, 1).get_tag(None),
            )),
            FpVar::zero(),
            FpVar::zero(),
        ];

        let mut ret = Vec::with_capacity(message.len() + 1);

        // Absorb both the key and the nonce
        state[0] = state[0].clone() + key;
        state = Self::permutation(state);
        state[0] = state[0].clone() + nonce;
        state = Self::permutation(state);

        // Get the ciphertext from the sponge and the message
        for block in message {
            ret.push(state[0].clone() + block);
            state[0] = state[0].clone() + block;
            state = Self::permutation(state);
        }

        ret.push(state[0].clone());

        Ok(ret)
    }
}
