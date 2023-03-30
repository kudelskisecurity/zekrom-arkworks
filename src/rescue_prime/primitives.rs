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

/*!
This module contains primitives used only for testing purpose with Rescue
They implement hashing on the BLS12_381 pairing-friendly curve.
*/

#![allow(unused)] // Only used within tests

pub struct RescuePrimePrimitivesBlsFr {}

use ark_r1cs_std::{fields::fp::FpVar, prelude::FieldVar};
use ark_relations::r1cs::SynthesisError;

use ark_bls12_381::Fr as BlsFr;
use ark_ff::BigInteger256 as I256;

use crate::{common::pattern::*, rescue_prime::params::*};

impl RescuePrimePrimitivesBlsFr {
    fn permutation(mut state: [FpVar<BlsFr>; 3]) -> Result<[FpVar<BlsFr>; 3], anyhow::Error> {
        for i in 0..N {
            for j in 0..M {
                state[j] = state[j].pow_by_constant(ALPHA_BLS381)?;
            }

            state[0] = state[0].clone() * FpVar::Constant(BlsFr::from(I256(MDS[0])))
                + state[1].clone() * FpVar::Constant(BlsFr::from(I256(MDS[1]))).clone()
                + state[2].clone() * FpVar::Constant(BlsFr::from(I256(MDS[2]))).clone()
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS[6 * i])));
            state[1] = state[0].clone() * FpVar::Constant(BlsFr::from(I256(MDS[3]))).clone()
                + state[1].clone() * FpVar::Constant(BlsFr::from(I256(MDS[4])))
                + state[2].clone() * FpVar::Constant(BlsFr::from(I256(MDS[5])))
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS[6 * i + 1])));
            state[2] = state[0].clone() * FpVar::Constant(BlsFr::from(I256(MDS[6])))
                + state[1].clone() * FpVar::Constant(BlsFr::from(I256(MDS[7])))
                + state[2].clone() * FpVar::Constant(BlsFr::from(I256(MDS[8])))
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS[6 * i + 2])));

            for j in 0..M {
                state[j] = state[j].pow_by_constant(ALPHAINV_BLS381)?;
            }

            state[0] = state[0].clone() * FpVar::Constant(BlsFr::from(I256(MDS[0])))
                + state[1].clone() * FpVar::Constant(BlsFr::from(I256(MDS[1]))).clone()
                + state[2].clone() * FpVar::Constant(BlsFr::from(I256(MDS[2]))).clone()
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS[6 * i + 3])));
            state[1] = state[0].clone() * FpVar::Constant(BlsFr::from(I256(MDS[3]))).clone()
                + state[1].clone() * FpVar::Constant(BlsFr::from(I256(MDS[4])))
                + state[2].clone() * FpVar::Constant(BlsFr::from(I256(MDS[5])))
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS[6 * i + 4])));
            state[2] = state[0].clone() * FpVar::Constant(BlsFr::from(I256(MDS[6])))
                + state[1].clone() * FpVar::Constant(BlsFr::from(I256(MDS[7])))
                + state[2].clone() * FpVar::Constant(BlsFr::from(I256(MDS[8])))
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS[6 * i + 5])));
        }

        Ok(state)
    }

    pub fn hash(message: Vec<BlsFr>) -> Result<FpVar<BlsFr>, anyhow::Error> {
        let mut state = [
            FpVar::zero(),
            FpVar::constant(BlsFr::from(
                gen_hash_pattern(message.len(), 1).get_tag(None),
            )),
            FpVar::zero(),
        ];

        for element in message {
            state[0] = state[0].clone() + element;
            state = Self::permutation(state)?;
        }

        Ok(state[0].clone())
    }
}
