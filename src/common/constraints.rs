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

use std::{mem::size_of_val, time::Instant};

use ark_ec::bls12::Bls12;
use ark_ff::{BigInteger256 as I256, Fp256, PrimeField, UniformRand, Zero};

use crate::{
    api::Sponge,
    ciminion::{
        self,
        chip::CiminionChip,
        params::{NB_R_PC, NB_R_PE_C},
    },
    common::test_utils::to_bls,
    neptune::{
        ae_circuit::NeptuneAECircuit,
        chip::{NeptuneChip, NeptuneParameters},
        hash_circuit::NeptuneHashCircuit,
        params::*,
        primitives::NeptunePrimitivesBlsFr,
    },
    rescue_prime::{
        chip::{RescuePrimeChip, RescuePrimeParameters},
        circuit::RescuePrimeHashCircuit,
        primitives::RescuePrimePrimitivesBlsFr,
    },
};
use ark_bls12_381::{Bls12_381 as Bls381, Fr as BlsFr, FrParameters, Parameters};
use ark_groth16::Groth16;
use ark_marlin::{ahp::prover::ProverMsg, Marlin, Proof};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{marlin_pc::MarlinKZG10, PCCommitment, PCProof};
use ark_r1cs_std::{fields::fp::FpVar, R1CSVar};
use ark_snark::SNARK;
use blake2::Blake2s;

use rand::rngs::OsRng;

use crate::rescue_prime::params::*;

const MAX_SIZE: usize = 2;
const MAX_SIZE_HALO2: usize = 5;

#[test]
#[ignore = "Benchmark test"]
fn bench_proof_size_marlin() {
    type KZG10 = MarlinKZG10<Bls381, DensePolynomial<BlsFr>>;
    type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;
    let rng = &mut ark_std::test_rng();
    let key = BlsFr::rand(rng);
    let nonce = BlsFr::rand(rng);

    for size in 1..MAX_SIZE + 1 {
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();
        let hash = RescuePrimePrimitivesBlsFr::hash(message.clone())
            .unwrap()
            .value()
            .unwrap();
        let parameters = RescuePrimeParameters {
            round_constants: to_bls(&ROUND_CONSTANTS),
            mds: to_bls(&MDS),
            alpha_inv: ALPHAINV_BLS381,
            alpha: ALPHA_BLS381,
        };
        let chip = RescuePrimeChip::new(parameters);

        type RpSpnBls381 = Sponge<RescuePrimeChip<BlsFr>>;
        let sponge = RpSpnBls381::new(chip);
        let circuit = RescuePrimeHashCircuit {
            hash,
            message: message.clone(),
            sponge,
        };

        let nc = 20000 * MAX_SIZE;
        let nv = 1;
        let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();
        let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();
        let rescue_prime_proof = MarlinSetup::prove(&pk, circuit, rng).unwrap();

        println!("Proof size for Rescue Prime for a message of len {}.", size);
        get_size(rescue_prime_proof);

        type NepChpBls381 = NeptuneChip<BlsFr>;
        type NepSpnBls381 = Sponge<NepChpBls381>;
        type NepHshCrcBls381 = NeptuneHashCircuit<BlsFr>;
        type NepAECrcBls381 = NeptuneAECircuit<BlsFr>;
        type NepPrmBls381 = NeptuneParameters<BlsFr>;

        let parameters = NepPrmBls381 {
            nb_rounds_ext: [NEB, NEE],
            nb_rounds_int: NI,
            round_constants: to_bls(&ROUND_CONSTANTS_BLS),
            gamma: FpVar::Constant(BlsFr::from(I256(GAMMA_BLS))),
            d: D,
            matrix_int: to_bls(&INTERNAL_MATRIX_BLS),
        };
        let chip = NepChpBls381::new(parameters);

        let sponge = NepSpnBls381::new(chip);

        let hash = NeptunePrimitivesBlsFr::hash(message.clone())
            .unwrap()
            .value()
            .unwrap();

        let circuit = NepHshCrcBls381 {
            message: message.clone(),
            hash,
            sponge: sponge.clone(),
        };

        let nc = 2000;
        let nv = 1;

        let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();

        let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();
        let neptune_hash_proof = MarlinSetup::prove(&pk, circuit, rng).unwrap();

        let ciphertext = NeptunePrimitivesBlsFr::ae(message.clone(), key, nonce)
            .unwrap()
            .value()
            .unwrap();

        let circuit = NepAECrcBls381 {
            sponge: sponge.clone(),
            message,
            ciphertext: ciphertext.clone(),
            key,
            nonce,
        };

        let nc = 40000;
        let nv = ciphertext.len() + 1;

        let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();

        let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();
        let neptune_ae_proof = MarlinSetup::prove(&pk, circuit, rng).unwrap();

        println!("Proof size for Neptune Hash for a message of len {}.", size);
        get_size(neptune_hash_proof);

        println!("Proof size for Neptune AE for a message of len {}.", size);
        get_size(neptune_ae_proof);
    }
}

#[test]
#[ignore = "Benchmark test"]
fn bench_proof_size_groth16() {
    type GrothSetup = Groth16<Bls381>;
    let rng = &mut ark_std::test_rng();
    let keys = (BlsFr::rand(rng), BlsFr::rand(rng));
    let nonce = BlsFr::rand(rng);

    let parameters_cim = ciminion::chip::CiminionParameters {
        nb_rounds_pe: NB_R_PE_C,
        nb_rounds_pc: NB_R_PC,
        round_constants: to_bls(&ciminion::params::ROUND_CONSTANTS_BLS),
    };

    let parameters = RescuePrimeParameters {
        round_constants: to_bls(&ROUND_CONSTANTS),
        mds: to_bls(&MDS),
        alpha_inv: ALPHAINV_BLS381,
        alpha: ALPHA_BLS381,
    };

    let cim_chip = crate::ciminion::chip::CiminionChip::new(parameters_cim);

    for size in 1..MAX_SIZE + 1 {
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();
        let hash = RescuePrimePrimitivesBlsFr::hash(message.clone())
            .unwrap()
            .value()
            .unwrap();

        let chip = RescuePrimeChip::new(parameters.clone());

        type RpSpnBls381 = Sponge<RescuePrimeChip<BlsFr>>;
        let sponge = RpSpnBls381::new(chip);
        let circuit = RescuePrimeHashCircuit {
            hash,
            message: message.clone(),
            sponge,
        };

        let (pk, _vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();
        let rescue_prime_proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

        println!(
            "Proof size for Rescue Prime : {} Bytes for a message of len {}.",
            size_of_val(&rescue_prime_proof),
            size
        );

        let ciphertext =
            crate::ciminion::primitives::CiminionPrimitiveBlsFr::encrypt(&message, keys, nonce);

        let circuit = crate::ciminion::circuit::CiminionCircuit {
            chip: cim_chip.clone(),
            message,
            ciphertext: ciphertext.clone(),
            keys,
            nonce,
        };

        let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();

        let ciminion_proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

        println!(
            "Proof size for Ciminion : {} Bytes for a message of len {}.",
            size_of_val(&ciminion_proof),
            size
        );
    }
}

pub fn get_size(
    proof: Proof<
        Fp256<FrParameters>,
        MarlinKZG10<Bls12<Parameters>, DensePolynomial<Fp256<FrParameters>>>,
    >,
) {
    let size_of_fe_in_bytes = Fp256::<FrParameters>::zero().into_repr().as_ref().len() * 8;
    let mut num_comms_without_degree_bounds = 0;
    let mut num_comms_with_degree_bounds = 0;
    let mut size_bytes_comms_without_degree_bounds = 0;
    let mut size_bytes_comms_with_degree_bounds = 0;
    let mut size_bytes_proofs = 0;
    for c in proof.commitments.iter().flat_map(|c| c) {
        if !c.has_degree_bound() {
            num_comms_without_degree_bounds += 1;
            size_bytes_comms_without_degree_bounds += c.size_in_bytes();
        } else {
            num_comms_with_degree_bounds += 1;
            size_bytes_comms_with_degree_bounds += c.size_in_bytes();
        }
    }

    let proofs = proof.pc_proof.proof.clone().to_vec();
    for proof in &proofs {
        size_bytes_proofs += proof.size_in_bytes();
    }

    let num_evals = proof.evaluations.len();
    let evals_size_in_bytes = num_evals * size_of_fe_in_bytes;
    let num_prover_messages: usize = proof
        .prover_messages
        .iter()
        .map(|v| match v {
            ProverMsg::EmptyMessage => 0,
            ProverMsg::FieldElements(elems) => elems.len(),
        })
        .sum();
    let prover_msg_size_in_bytes = num_prover_messages * size_of_fe_in_bytes;
    let arg_size = size_bytes_comms_with_degree_bounds
        + size_bytes_comms_without_degree_bounds
        + size_bytes_proofs
        + prover_msg_size_in_bytes
        + evals_size_in_bytes;
    println!("{} Bytes", arg_size);
}
