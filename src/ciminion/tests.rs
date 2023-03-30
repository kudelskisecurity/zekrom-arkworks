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

use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_marlin::{AHPForR1CS, Marlin};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_snark::SNARK;
use blake2::Blake2s;

use crate::common::test_utils::to_bls;

use super::chip::*;
use super::circuit::CiminionCircuit;
use super::params::*;
use super::primitives::CiminionPrimitiveBlsFr;

#[test]
fn marlin_ae_bls() {
    let parameters = CiminionParameters {
        nb_rounds_pe: NB_R_PE_C,
        nb_rounds_pc: NB_R_PC,
        round_constants: to_bls(&ROUND_CONSTANTS_BLS),
    };
    let chip = CiminionChip::new(parameters);

    let rng = &mut ark_std::test_rng();
    let message = vec![BlsFr::rand(rng)];
    let keys = (BlsFr::rand(rng), BlsFr::rand(rng));
    let nonce = BlsFr::rand(rng);

    let ciphertext = CiminionPrimitiveBlsFr::encrypt(&message, keys, nonce);

    let circuit = CiminionCircuit {
        chip,
        message,
        ciphertext: ciphertext.clone(),
        keys,
        nonce,
    };

    type KZG10 = MarlinKZG10<Bls381, DensePolynomial<BlsFr>>;
    type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

    // todo : this looks fairly wrong
    let nc = 45000;
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
    let parameters = CiminionParameters {
        nb_rounds_pe: NB_R_PE_C,
        nb_rounds_pc: NB_R_PC,
        round_constants: to_bls(&ROUND_CONSTANTS_BLS),
    };
    let chip = CiminionChip::new(parameters);

    let rng = &mut ark_std::test_rng();
    let message = vec![BlsFr::rand(rng)];
    let keys = (BlsFr::rand(rng), BlsFr::rand(rng));
    let nonce = BlsFr::rand(rng);

    let ciphertext = CiminionPrimitiveBlsFr::encrypt(&message, keys, nonce);

    let circuit = CiminionCircuit {
        chip,
        message,
        ciphertext: ciphertext.clone(),
        keys,
        nonce,
    };

    let index = AHPForR1CS::index(circuit.clone()).unwrap();
    println!(
        "Number of constraints for R1CS - Ciminion . {}",
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
