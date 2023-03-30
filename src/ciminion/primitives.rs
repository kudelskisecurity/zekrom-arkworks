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

#![allow(dead_code)]

use ark_bls12_381::Fr as F;
use ark_ff::{BigInteger256 as I256, One, Zero};

use super::params::*;

pub struct CiminionPrimitiveBlsFr {}

impl CiminionPrimitiveBlsFr {
    pub fn encrypt(message: &[F], master_key: (F, F), nonce: F) -> Vec<F> {
        // Init the state for key generation
        let keys = Self::gen_keys(master_key.0, master_key.1, message.len());

        // Now we init the state with the first derived key
        let mut state = [nonce, keys[0], keys[1]];

        Self::pc(&mut state);

        let mut ct: Vec<F> = Vec::with_capacity(message.len() + 1);

        let (t1, _) = Self::pe(state);

        for i in (0..message.len()).step_by(2) {
            Self::iter(&mut state, keys[i + 2], keys[i + 3]);
            let (out1, out2) = Self::pe(state);
            ct.push(message[i] + out1);
            if i < message.len() - 1 {
                ct.push(message[i + 1] + out2);
            }
        }

        let tag = Self::authenticate(&ct, t1, keys[keys.len() - 1]);

        ct.push(tag);

        ct
    }

    fn authenticate(ct: &[F], t1: F, key: F) -> F {
        let mut tag = F::zero();

        for block in ct {
            tag += block;
            tag *= key;
        }

        tag += F::from(ct.len() as i32);
        tag *= key;
        tag += t1;

        tag
    }

    fn gen_keys(mk1: F, mk2: F, len: usize) -> Vec<F> {
        let mut state = vec![F::one(), mk1, mk2];

        let mut number_keys = len + 3;
        if len % 2 != 0 {
            number_keys += 1
        };

        let mut keys = Vec::with_capacity(number_keys);

        for _i in 0..number_keys {
            Self::pc(&mut state);
            keys.push(state[0]);
        }

        keys
    }

    fn iter(state: &mut [F], k1: F, k2: F) {
        // Add both keys to the state
        state[0] += k2;
        state[1] += k1;

        // Apply the rol function
        let tmp = state[2] + state[1] * state[0];
        state[2] = state[1];
        state[1] = state[0];
        state[0] = tmp;
    }

    fn pc(state: &mut [F]) {
        for i in 0..NB_R_PC {
            Self::permutation(state, i);
        }
    }

    fn pe(mut state: [F; 3]) -> (F, F) {
        for i in NB_R_PC - NB_R_PE_C..NB_R_PC {
            Self::permutation(&mut state, i);
        }

        (state[0], state[1])
    }

    fn permutation(state: &mut [F], index: usize) {
        let tmp = state[2] + state[1] * state[0] + state[1];

        let a = state[2] + state[1] * state[0] + F::from(I256(ROUND_CONSTANTS_BLS[4 * index + 2]));
        let b = state[0]
            + F::from(I256(ROUND_CONSTANTS_BLS[4 * index + 3])) * tmp
            + F::from(I256(ROUND_CONSTANTS_BLS[4 * index]));
        let c = tmp + F::from(I256(ROUND_CONSTANTS_BLS[4 * index + 1]));

        state[0] = a;
        state[1] = b;
        state[2] = c;
    }
}
