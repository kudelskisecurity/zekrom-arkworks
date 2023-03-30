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

#![cfg(test)]

use ark_bls12_381::{Bls12_381 as Bls381, Fr as BlsFr};

use super::chip::{RescuePrimeChip, RescuePrimeParameters};
use super::circuit::RescuePrimeHashCircuit;
use super::params::*;
use crate::api::Sponge;
use crate::common::test_utils::to_bls;
use crate::rescue_prime::primitives::RescuePrimePrimitivesBlsFr;
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_marlin::{AHPForR1CS, Marlin};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_r1cs_std::R1CSVar;
use ark_snark::SNARK;
use blake2::Blake2s;

type RpChpBls381 = RescuePrimeChip<BlsFr>;
type RpHshCrcBls381 = RescuePrimeHashCircuit<BlsFr>;
type RpPrmBls381 = RescuePrimeParameters<BlsFr>;
type RpSpnBls381 = Sponge<RpChpBls381>;

pub fn get_sponge() -> RpSpnBls381 {
    let parameters = RpPrmBls381 {
        round_constants: to_bls(&ROUND_CONSTANTS),
        mds: to_bls(&MDS),
        alpha_inv: ALPHAINV_BLS381,
        alpha: ALPHA_BLS381,
    };
    let chip = RpChpBls381::new(parameters);

    RpSpnBls381::new(chip)
}
#[test]
fn marlin_bls_381() {
    let sponge = get_sponge();
    let rng = &mut ark_std::test_rng();
    let message = vec![BlsFr::rand(rng)];
    let hash = RescuePrimePrimitivesBlsFr::hash(message.clone())
        .unwrap()
        .value()
        .unwrap();
    let circuit = RpHshCrcBls381 {
        hash,
        message,
        sponge,
    };
    type KZG10 = MarlinKZG10<Bls381, DensePolynomial<BlsFr>>;
    type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;
    // todo : this looks fairly wrong
    let nc = 20000;
    let nv = 1;
    let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();
    let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();
    let proof = MarlinSetup::prove(&pk, circuit, rng).unwrap();
    let res = MarlinSetup::verify(&vk, &[hash], &proof, rng).unwrap();
    assert!(res)
}
#[test]
fn groth16_bls381() {
    let sponge = get_sponge();
    let rng = &mut ark_std::test_rng();
    let message = vec![BlsFr::rand(rng)];
    let hash = RescuePrimePrimitivesBlsFr::hash(message.clone())
        .unwrap()
        .value()
        .unwrap();
    let circuit = RpHshCrcBls381 {
        hash,
        message,
        sponge,
    };

    let index = AHPForR1CS::index(circuit.clone()).unwrap();
    println!(
        "Number of constraints for R1CS - Rescue . {}",
        index.index_info.num_constraints
    );

    type GrothSetup = Groth16<Bls381>;
    let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();
    let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();
    let res = GrothSetup::verify(&vk, &[hash], &proof).unwrap();
    assert!(res);
}
