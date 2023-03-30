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

use crate::griffin::params::*;
use crate::griffin::primitives::GriffinPrimitivesBlsFr;
use crate::{api::Sponge, griffin::params::ROUND_CONSTANTS};

use crate::common::test_utils::to_bls;

use ark_bls12_381::{Bls12_381 as Bls381, Fr as BlsFr};

use ark_ff::{BigInteger256 as I256, UniformRand};
use ark_groth16::Groth16;
use ark_marlin::{AHPForR1CS, Marlin};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_r1cs_std::{fields::fp::FpVar, R1CSVar};
use ark_snark::SNARK;
use blake2::Blake2s;

use super::ae_circuit::GriffinAECircuit;
use super::chip::GriffinChip;
use super::chip::GriffinParameters;
use super::hash_circuit::GriffinHashCircuit;

type GrifChpBls381 = GriffinChip<BlsFr>;
type GrifHshCrcBls381 = GriffinHashCircuit<BlsFr>;
type GrifPrmBls381 = GriffinParameters<BlsFr>;

type GrifSpnBls381 = Sponge<GrifChpBls381>;
type GrifAECrcBls381 = GriffinAECircuit<BlsFr>;

#[test]
fn marlin_hash_bls() {
    let parameters = GrifPrmBls381 {
        nb_rounds: N,
        round_constants: to_bls(&ROUND_CONSTANTS),
        alpha: FpVar::Constant(BlsFr::from(I256(ALPHA))),
        beta: FpVar::Constant(BlsFr::from(I256(BETA))),
        d: D_BLS381,
        d_inv: D_INV_BLS381,
    };
    let chip = GrifChpBls381::new(parameters);

    let sponge = GrifSpnBls381::new(chip);

    let rng = &mut ark_std::test_rng();
    let message = vec![BlsFr::rand(rng)];
    /* let hash = chip
    .hash(FpVar::Constant(message))
    .unwrap()
    .value()
    .unwrap(); */

    // let hash = message.first().unwrap().clone();

    let hash = GriffinPrimitivesBlsFr::hash(message.clone())
        .unwrap()
        .value()
        .unwrap();

    let circuit = GrifHshCrcBls381 {
        message,
        hash,
        sponge,
    };

    type KZG10 = MarlinKZG10<Bls381, DensePolynomial<BlsFr>>;
    type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

    // todo : this looks fairly wrong
    let nc = 10000;
    let nv = 1;

    let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();

    let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();
    let proof = MarlinSetup::prove(&pk, circuit, rng).unwrap();

    let res = MarlinSetup::verify(&vk, &[hash], &proof, rng).unwrap();

    assert!(res)
}

#[test]
fn groth16_hash_bls() {
    let parameters = GrifPrmBls381 {
        nb_rounds: N,
        round_constants: to_bls(&ROUND_CONSTANTS),
        alpha: FpVar::Constant(BlsFr::from(I256(ALPHA))),
        beta: FpVar::Constant(BlsFr::from(I256(BETA))),
        d: D_BLS381,
        d_inv: D_INV_BLS381,
    };
    let chip = GrifChpBls381::new(parameters);

    let sponge = GrifSpnBls381::new(chip);

    let rng = &mut ark_std::test_rng();
    let message = vec![BlsFr::rand(rng)];
    /* let hash = chip
    .hash(FpVar::Constant(message))
    .unwrap()
    .value()
    .unwrap(); */

    // let hash = message.first().unwrap().clone();
    let hash = GriffinPrimitivesBlsFr::hash(message.clone())
        .unwrap()
        .value()
        .unwrap();

    let circuit = GrifHshCrcBls381 {
        message,
        hash,
        sponge,
    };

    let index = AHPForR1CS::index(circuit.clone()).unwrap();
    println!(
        "Number of constraints for R1CS - Griffin Hash . {}",
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
    let parameters = GrifPrmBls381 {
        nb_rounds: N,
        round_constants: to_bls(&ROUND_CONSTANTS),
        alpha: FpVar::Constant(BlsFr::from(I256(ALPHA))),
        beta: FpVar::Constant(BlsFr::from(I256(BETA))),
        d: D_BLS381,
        d_inv: D_INV_BLS381,
    };
    let chip = GrifChpBls381::new(parameters);

    let sponge = GrifSpnBls381::new(chip);

    let rng = &mut ark_std::test_rng();
    let message = vec![BlsFr::rand(rng)];
    let key = BlsFr::rand(rng);
    let nonce = BlsFr::rand(rng);

    let ciphertext = GriffinPrimitivesBlsFr::ae(message.clone(), key, nonce)
        .unwrap()
        .value()
        .unwrap();

    let circuit = GrifAECrcBls381 {
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
    let parameters = GrifPrmBls381 {
        nb_rounds: N,
        round_constants: to_bls(&ROUND_CONSTANTS),
        alpha: FpVar::Constant(BlsFr::from(I256(ALPHA))),
        beta: FpVar::Constant(BlsFr::from(I256(BETA))),
        d: D_BLS381,
        d_inv: D_INV_BLS381,
    };
    let chip = GrifChpBls381::new(parameters);

    let sponge = GrifSpnBls381::new(chip);

    let rng = &mut ark_std::test_rng();
    let message = vec![BlsFr::rand(rng)];
    let key = BlsFr::rand(rng);
    let nonce = BlsFr::rand(rng);

    let ciphertext = GriffinPrimitivesBlsFr::ae(message.clone(), key, nonce)
        .unwrap()
        .value()
        .unwrap();

    let circuit = GrifAECrcBls381 {
        sponge,
        message,
        ciphertext: ciphertext.clone(),
        key,
        nonce,
    };

    let index = AHPForR1CS::index(circuit.clone()).unwrap();
    println!(
        "Number of constraints for R1CS - Griffin AE . {}",
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
