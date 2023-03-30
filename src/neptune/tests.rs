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

use super::ae_circuit::*;
use super::chip::*;
use super::hash_circuit::*;
use super::params::*;
use super::primitives::*;
use crate::api::Sponge;

use ark_bls12_381::{Bls12_381 as Bls381, Fr as BlsFr};

use ark_ff::{BigInteger256 as I256, UniformRand};
use ark_groth16::Groth16;
use ark_marlin::AHPForR1CS;
use ark_marlin::Marlin;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_r1cs_std::{fields::fp::FpVar, R1CSVar};
use ark_snark::SNARK;
use blake2::Blake2s;

type NepChpBls381 = NeptuneChip<BlsFr>;
type NepSpnBls381 = Sponge<NepChpBls381>;
type NepHshCrcBls381 = NeptuneHashCircuit<BlsFr>;
type NepAECrcBls381 = NeptuneAECircuit<BlsFr>;
type NepPrmBls381 = NeptuneParameters<BlsFr>;

// Convert my generic generated parameters on the curve we use to test
fn to_bls381(array: &[[u64; 4]]) -> Vec<FpVar<BlsFr>> {
    let mut ret = Vec::new();

    for element in array {
        ret.push(FpVar::Constant(BlsFr::from(I256(*element))));
    }

    ret
}

fn get_sponge() -> Sponge<NeptuneChip<BlsFr>> {
    let parameters = NepPrmBls381 {
        nb_rounds_ext: [NEB, NEE],
        nb_rounds_int: NI,
        round_constants: to_bls381(&ROUND_CONSTANTS_BLS),
        gamma: FpVar::Constant(BlsFr::from(I256(GAMMA_BLS))),
        d: D,
        matrix_int: to_bls381(&INTERNAL_MATRIX_BLS),
    };
    let chip = NepChpBls381::new(parameters);

    NepSpnBls381::new(chip)
}

#[test]
fn marlin_hash_bls() {
    let rng = &mut ark_std::test_rng();

    let sponge = get_sponge();

    let message_1 = vec![BlsFr::rand(rng)];
    let message_2 = vec![BlsFr::rand(rng), BlsFr::rand(rng)];
    let message_3 = vec![BlsFr::rand(rng), BlsFr::rand(rng), BlsFr::rand(rng)];

    let hash_1 = NeptunePrimitivesBlsFr::hash(message_1.clone())
        .unwrap()
        .value()
        .unwrap();
    let hash_2 = NeptunePrimitivesBlsFr::hash(message_2.clone())
        .unwrap()
        .value()
        .unwrap();
    let hash_3 = NeptunePrimitivesBlsFr::hash(message_3.clone())
        .unwrap()
        .value()
        .unwrap();

    let circuit_1 = NepHshCrcBls381 {
        message: message_1,
        hash: hash_1,
        sponge: sponge.clone(),
    };
    let circuit_2 = NepHshCrcBls381 {
        message: message_2,
        hash: hash_2,
        sponge: sponge.clone(),
    };
    let circuit_3 = NepHshCrcBls381 {
        message: message_3,
        hash: hash_3,
        sponge,
    };

    type KZG10 = MarlinKZG10<Bls381, DensePolynomial<BlsFr>>;
    type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

    // todo : this looks fairly wrong
    let nc = 6000;
    let nv = 1;

    let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();

    let (pk, vk) = MarlinSetup::index(&srs, circuit_1.clone()).unwrap();
    let proof = MarlinSetup::prove(&pk, circuit_1, rng).unwrap();

    let res_1 = MarlinSetup::verify(&vk, &[hash_1], &proof, rng).unwrap();

    let nv = 2;

    let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();

    let (pk, vk) = MarlinSetup::index(&srs, circuit_2.clone()).unwrap();
    let proof = MarlinSetup::prove(&pk, circuit_2, rng).unwrap();

    let res_2 = MarlinSetup::verify(&vk, &[hash_2], &proof, rng).unwrap();

    let nv = 3;

    let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();

    let (pk, vk) = MarlinSetup::index(&srs, circuit_3.clone()).unwrap();
    let proof = MarlinSetup::prove(&pk, circuit_3, rng).unwrap();

    let res_3 = MarlinSetup::verify(&vk, &[hash_3], &proof, rng).unwrap();

    assert!(res_1);
    assert!(res_2);
    assert!(res_3);
}

#[test]
fn groth16_hash_bls() {
    let parameters = NepPrmBls381 {
        nb_rounds_ext: [NEB, NEE],
        nb_rounds_int: NI,
        round_constants: to_bls381(&ROUND_CONSTANTS_BLS),
        gamma: FpVar::Constant(BlsFr::from(I256(GAMMA_BLS))),
        d: D,
        matrix_int: to_bls381(&INTERNAL_MATRIX_BLS),
    };
    let chip = NepChpBls381::new(parameters);

    let sponge = NepSpnBls381::new(chip);

    let rng = &mut ark_std::test_rng();
    let message = vec![BlsFr::rand(rng)];
    /* let hash = chip
    .hash(FpVar::Constant(message))
    .unwrap()
    .value()
    .unwrap(); */

    // let hash = message.first().unwrap().clone();
    let hash = NeptunePrimitivesBlsFr::hash(message.clone())
        .unwrap()
        .value()
        .unwrap();

    let circuit = NepHshCrcBls381 {
        message,
        hash,
        sponge,
    };

    let index = AHPForR1CS::index(circuit.clone()).unwrap();
    println!(
        "Number of constraints for R1CS - Neptune Hash . {}",
        index.index_info.num_constraints
    );

    type GrothSetup = Groth16<Bls381>;

    let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();
    let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

    let res = GrothSetup::verify(&vk, &[hash], &proof).unwrap();
    assert!(res);
}

#[test]
fn marlin_ae_bls() {
    let parameters = NepPrmBls381 {
        nb_rounds_ext: [NEB, NEE],
        nb_rounds_int: NI,
        round_constants: to_bls381(&ROUND_CONSTANTS_BLS),
        gamma: FpVar::Constant(BlsFr::from(I256(GAMMA_BLS))),
        d: D,
        matrix_int: to_bls381(&INTERNAL_MATRIX_BLS),
    };
    let chip = NepChpBls381::new(parameters);

    let sponge = NepSpnBls381::new(chip);

    let rng = &mut ark_std::test_rng();
    let message = vec![BlsFr::rand(rng)];
    let key = BlsFr::rand(rng);
    let nonce = BlsFr::rand(rng);

    let ciphertext = NeptunePrimitivesBlsFr::ae(message.clone(), key, nonce)
        .unwrap()
        .value()
        .unwrap();

    let circuit = NepAECrcBls381 {
        sponge,
        message,
        ciphertext: ciphertext.clone(),
        key,
        nonce,
    };

    type KZG10 = MarlinKZG10<Bls381, DensePolynomial<BlsFr>>;
    type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

    // todo : this looks fairly wrong
    let nc = 40000;
    let nv = ciphertext.len() + 1;

    let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();

    let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();
    let proof = MarlinSetup::prove(&pk, circuit, rng).unwrap();

    let mut public = ciphertext;
    public.push(nonce);

    let res = MarlinSetup::verify(&vk, &public, &proof, rng).unwrap();

    assert!(res)
}

#[test]
fn groth16_ae_bls() {
    let parameters = NepPrmBls381 {
        nb_rounds_ext: [NEB, NEE],
        nb_rounds_int: NI,
        round_constants: to_bls381(&ROUND_CONSTANTS_BLS),
        gamma: FpVar::Constant(BlsFr::from(I256(GAMMA_BLS))),
        d: D,
        matrix_int: to_bls381(&INTERNAL_MATRIX_BLS),
    };
    let chip = NepChpBls381::new(parameters);

    let sponge = NepSpnBls381::new(chip);

    let rng = &mut ark_std::test_rng();
    let message = vec![BlsFr::rand(rng)];
    let key = BlsFr::rand(rng);
    let nonce = BlsFr::rand(rng);

    let ciphertext = NeptunePrimitivesBlsFr::ae(message.clone(), key, nonce)
        .unwrap()
        .value()
        .unwrap();

    let circuit = NepAECrcBls381 {
        sponge,
        message,
        ciphertext: ciphertext.clone(),
        key,
        nonce,
    };

    let index = AHPForR1CS::index(circuit.clone()).unwrap();
    println!(
        "Number of constraints for R1CS - Neptune AE . {}",
        index.index_info.num_constraints
    );

    type GrothSetup = Groth16<Bls381>;

    let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();
    let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

    let mut public = ciphertext;
    public.push(nonce);

    let res = GrothSetup::verify(&vk, &public, &proof).unwrap();
    assert!(res);
}
