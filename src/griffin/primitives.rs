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
This module contains primitives used only for testing purpose with Griffin
They implement both hashing and authenticated encryption.
*/

#![allow(unused)] // Only used within tests

pub struct GriffinPrimitivesBlsFr {}

use ark_r1cs_std::{fields::fp::FpVar, prelude::FieldVar};
use ark_relations::r1cs::SynthesisError;

use ark_bls12_381::Fr as BlsFr;
use ark_ff::BigInteger256 as I256;

use crate::{common::pattern::*, griffin::params::*};

impl GriffinPrimitivesBlsFr {
    fn permutation(mut state: [FpVar<BlsFr>; 3]) -> Result<[FpVar<BlsFr>; 3], anyhow::Error> {
        // First we apply the MDS(m) initial operation
        let sum = state[0].clone() + state[1].clone() + state[2].clone();
        state[0] += sum.clone();
        state[1] = state[1].clone() + sum.clone();
        state[2] = state[2].clone() + sum;

        for i in 0..N - 1 {
            // Apply S
            state[0] = state[0].clone().pow_by_constant(D_INV_BLS381)?;
            state[1] = state[1].clone().pow_by_constant(D_BLS381)?;
            state[2] = (state[0].clone() + state[1].clone()).square()?
                + FpVar::Constant(BlsFr::from(I256(ALPHA))) * (state[0].clone() + state[1].clone())
                + FpVar::Constant(BlsFr::from(I256(BETA)));

            // Apply M and C
            let sum = state[0].clone() + state[1].clone() + state[2].clone();
            state[0] = state[0].clone()
                + sum.clone()
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS[3 * i])));
            state[1] = state[1].clone()
                + sum.clone()
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS[3 * i + 1])));
            state[2] = state[2].clone()
                + sum
                + FpVar::Constant(BlsFr::from(I256(ROUND_CONSTANTS[3 * i + 2])));
        }

        // Apply S
        state[0] = state[0].clone().pow_by_constant(D_INV_BLS381)?;
        state[1] = state[1].clone().pow_by_constant(D_BLS381)?;
        state[2] = (state[0].clone() + state[1].clone()).square()?
            + FpVar::Constant(BlsFr::from(I256(ALPHA))) * (state[0].clone() + state[1].clone())
            + FpVar::Constant(BlsFr::from(I256(BETA)));

        // Apply M - without the RC for the final one
        let sum = state[0].clone() + state[1].clone() + state[2].clone();
        state[0] = state[0].clone() + sum.clone();
        state[1] = state[1].clone() + sum.clone();
        state[2] = state[2].clone() + sum;

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

    pub fn ae(
        message: Vec<BlsFr>,
        key: BlsFr,
        nonce: BlsFr,
    ) -> Result<Vec<FpVar<BlsFr>>, anyhow::Error> {
        let mut state = [
            FpVar::zero(),
            FpVar::constant(BlsFr::from(
                gen_ae_pattern(message.len(), 1, 1).get_tag(None),
            )),
            FpVar::zero(),
        ];

        let mut ret = Vec::with_capacity(message.len() + 1);

        // Absorb both the key and the nonce
        state[0] = state[0].clone() + key;
        state = Self::permutation(state)?;
        state[0] = state[0].clone() + nonce;
        state = Self::permutation(state)?;

        // Get the ciphertext from the sponge and the message
        for block in message {
            ret.push(state[0].clone() + block);
            state[0] = state[0].clone() + block;
            state = Self::permutation(state)?;
        }

        ret.push(state[0].clone());

        Ok(ret)
    }
}
