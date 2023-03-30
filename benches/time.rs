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

use ark_groth16::Groth16;
use ark_marlin::{AHPForR1CS, Marlin};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_r1cs_std::{fields::fp::FpVar, R1CSVar};
use ark_snark::SNARK;
use blake2::Blake2s;
use criterion::*;

use ark_ff::{BigInteger256 as I256, UniformRand};

use ark_bls12_381::{Bls12_381 as Bls381, Fr as BlsFr};

use zekrom_arkworks::{
    api::Sponge,

    common::test_utils::to_bls,
    griffin::{
        ae_circuit::GriffinAECircuit,
        chip::{GriffinChip, GriffinParameters},
        hash_circuit::GriffinHashCircuit,
        primitives::GriffinPrimitivesBlsFr,
    }, rescue_prime::{chip::{RescuePrimeParameters, RescuePrimeChip}, params::{ROUND_CONSTANTS, MDS, ALPHAINV_BLS381, ALPHA_BLS381}, primitives::RescuePrimePrimitivesBlsFr, circuit::RescuePrimeHashCircuit}, neptune::{chip::{NeptuneChip, NeptuneParameters}, hash_circuit::NeptuneHashCircuit, primitives::NeptunePrimitivesBlsFr, ae_circuit::NeptuneAECircuit}, ciminion::params::{NB_R_PE_C, NB_R_PC},
};

const MAX_SIZE: usize = 10;
const KRC: u32 = 11;
const KRP: u32 = 6;
const KNH: u32 = 6;
const KNC: u32 = 7;
const KGH: u32 = 8;
const KGC: u32 = 9;
const KC: u32 = 14;

pub fn hash_duration_marlin_rescue(c: &mut Criterion) {
    let mut group = c.benchmark_group("Rescue Prime Hash - marlin - Time bench");
    type KZG10 = MarlinKZG10<Bls381, DensePolynomial<BlsFr>>;
    type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

    let rng = &mut ark_std::test_rng();

    let nc = 200000;
    let nv = 1;

    let parameters = RescuePrimeParameters {
        round_constants: to_bls(&ROUND_CONSTANTS),
        mds: to_bls(&MDS),
        alpha_inv: ALPHAINV_BLS381,
        alpha: ALPHA_BLS381,
    };
    let chip = RescuePrimeChip::new(parameters);

    type RpSpnBls381 = Sponge<RescuePrimeChip<BlsFr>>;
    let sponge = RpSpnBls381::new(chip);

    // Iterate over the message size to produce the benchmark
    for size in 1..MAX_SIZE + 1 {
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();

        let hash = RescuePrimePrimitivesBlsFr::hash(message.clone())
            .unwrap()
            .value()
            .unwrap();

        let circuit = RescuePrimeHashCircuit {
            hash,
            message,
            sponge: sponge.clone(),
        };

        let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();
        let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();

        group.bench_function(
            format!("Rescue Prime Marlin proof Generation with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = MarlinSetup::prove(&pk, circuit.clone(), rng).unwrap();
                })
            },
        );

        let proof = MarlinSetup::prove(&pk, circuit.clone(), rng).unwrap();

        group.bench_function(
            &format!("Rescue Prime Marlin proof Verification with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = MarlinSetup::verify(&vk, &[hash], &proof, rng).unwrap();
                });
            },
        );
    }
}

pub fn hash_duration_marlin_neptune(c: &mut Criterion) {
    let mut group = c.benchmark_group("Neptune Hash - marlin - Time bench");

    type KZG10 = MarlinKZG10<Bls381, DensePolynomial<BlsFr>>;
    type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;
    type NepChpBls381 = NeptuneChip<BlsFr>;
    type NepSpnBls381 = Sponge<NepChpBls381>;
    type NepHshCrcBls381 = NeptuneHashCircuit<BlsFr>;
    type NepPrmBls381 = NeptuneParameters<BlsFr>;

    let rng = &mut ark_std::test_rng();

    let mut nc = 10000;
    let nv = 1;

    let parameters = NepPrmBls381 {
        nb_rounds_ext: [
            zekrom_arkworks::neptune::params::NEB,
            zekrom_arkworks::neptune::params::NEE,
        ],
        nb_rounds_int: zekrom_arkworks::neptune::params::NI,
        round_constants: to_bls(&zekrom_arkworks::neptune::params::ROUND_CONSTANTS_BLS),
        gamma: FpVar::Constant(BlsFr::from(I256(zekrom_arkworks::neptune::params::GAMMA_BLS))),
        d: zekrom_arkworks::neptune::params::D,
        matrix_int: to_bls(&zekrom_arkworks::neptune::params::INTERNAL_MATRIX_BLS),
    };
    let chip = NepChpBls381::new(parameters);
    let sponge = NepSpnBls381::new(chip);

    // Iterate over the message size to produce the benchmark
    for size in 1..MAX_SIZE + 1 {
        if size >= 7 {
            nc += 200;
        }
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();

        let hash = NeptunePrimitivesBlsFr::hash(message.clone())
            .unwrap()
            .value()
            .unwrap();

        let circuit = NepHshCrcBls381 {
            hash,
            message,
            sponge: sponge.clone(),
        };

        let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();
        let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();

        group.bench_function(
            format!("Neptune Hash Marlin proof Generation with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = MarlinSetup::prove(&pk, circuit.clone(), rng).unwrap();
                })
            },
        );

        let proof = MarlinSetup::prove(&pk, circuit.clone(), rng).unwrap();

        group.bench_function(
            &format!("Neptune Hash Marlin proof Verification with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = MarlinSetup::verify(&vk, &[hash], &proof, rng).unwrap();
                });
            },
        );
    }
}

pub fn hash_duration_marlin_griffin(c: &mut Criterion) {
    let mut group = c.benchmark_group("Griffin Hash - marlin - Time bench");

    type KZG10 = MarlinKZG10<Bls381, DensePolynomial<BlsFr>>;
    type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

    type GrifChpBls381 = GriffinChip<BlsFr>;
    type GrifHshCrcBls381 = GriffinHashCircuit<BlsFr>;
    type GrifPrmBls381 = GriffinParameters<BlsFr>;

    type GrifSpnBls381 = Sponge<GrifChpBls381>;

    let rng = &mut ark_std::test_rng();

    let nc = 50000;
    let nv = 1;

    let parameters = GrifPrmBls381 {
        nb_rounds: zekrom_arkworks::griffin::params::N,
        round_constants: to_bls(&ROUND_CONSTANTS),
        alpha: FpVar::Constant(BlsFr::from(I256(zekrom_arkworks::griffin::params::ALPHA))),
        beta: FpVar::Constant(BlsFr::from(I256(zekrom_arkworks::griffin::params::BETA))),
        d: zekrom_arkworks::griffin::params::D_BLS381,
        d_inv: zekrom_arkworks::griffin::params::D_INV_BLS381,
    };
    let chip = GrifChpBls381::new(parameters);

    let sponge = GrifSpnBls381::new(chip);

    // Iterate over the message size to produce the benchmark
    for size in 1..MAX_SIZE + 1 {
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();
        let hash = GriffinPrimitivesBlsFr::hash(message.clone())
            .unwrap()
            .value()
            .unwrap();

        let circuit = GrifHshCrcBls381 {
            message,
            hash,
            sponge: sponge.clone(),
        };

        let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();
        let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();

        group.bench_function(
            format!("Griffin Hash Marlin proof Generation with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = MarlinSetup::prove(&pk, circuit.clone(), rng).unwrap();
                })
            },
        );

        let proof = MarlinSetup::prove(&pk, circuit.clone(), rng).unwrap();

        group.bench_function(
            &format!("Griffin Hash Marlin proof Verification with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = MarlinSetup::verify(&vk, &[hash], &proof, rng).unwrap();
                });
            },
        );
    }
}

pub fn ae_duration_marlin_griffin(c: &mut Criterion) {
    let mut group = c.benchmark_group("Griffin AE - marlin - Time bench");

    type KZG10 = MarlinKZG10<Bls381, DensePolynomial<BlsFr>>;
    type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

    type GrifChpBls381 = GriffinChip<BlsFr>;
    type GrifPrmBls381 = GriffinParameters<BlsFr>;

    type GrifSpnBls381 = Sponge<GrifChpBls381>;
    type GrifAECrcBls381 = GriffinAECircuit<BlsFr>;

    let rng = &mut ark_std::test_rng();

    let nc = 40000;

    let parameters = GrifPrmBls381 {
        nb_rounds: zekrom_arkworks::griffin::params::N,
        round_constants: to_bls(&ROUND_CONSTANTS),
        alpha: FpVar::Constant(BlsFr::from(I256(zekrom_arkworks::griffin::params::ALPHA))),
        beta: FpVar::Constant(BlsFr::from(I256(zekrom_arkworks::griffin::params::BETA))),
        d: zekrom_arkworks::griffin::params::D_BLS381,
        d_inv: zekrom_arkworks::griffin::params::D_INV_BLS381,
    };
    let chip = GrifChpBls381::new(parameters);

    let sponge = GrifSpnBls381::new(chip);

    let key = BlsFr::rand(rng);
    let nonce = BlsFr::rand(rng);

    // Iterate over the message size to produce the benchmark
    for size in 1..MAX_SIZE + 1 {
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();

        let ciphertext = GriffinPrimitivesBlsFr::ae(message.clone(), key, nonce)
            .unwrap()
            .value()
            .unwrap();

        let circuit = GrifAECrcBls381 {
            sponge: sponge.clone(),
            message,
            ciphertext: ciphertext.clone(),
            key,
            nonce,
        };
        let nv = ciphertext.len() + 1;

        let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();
        let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();

        group.bench_function(
            format!("Griffin AE Marlin proof Generation with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = MarlinSetup::prove(&pk, circuit.clone(), rng).unwrap();
                })
            },
        );

        let proof = MarlinSetup::prove(&pk, circuit.clone(), rng).unwrap();
        let mut public = ciphertext;
        public.push(nonce);

        group.bench_function(
            &format!("Griffin AE Marlin proof Verification with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = MarlinSetup::verify(&vk, &public, &proof, rng).unwrap();
                });
            },
        );
    }
}

pub fn ae_duration_marlin_neptune(c: &mut Criterion) {
    let mut group = c.benchmark_group("Neptune AE - marlin - Time bench");

    type KZG10 = MarlinKZG10<Bls381, DensePolynomial<BlsFr>>;
    type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;
    type NepChpBls381 = NeptuneChip<BlsFr>;
    type NepSpnBls381 = Sponge<NepChpBls381>;
    type NepAECrcBls381 = NeptuneAECircuit<BlsFr>;
    type NepPrmBls381 = NeptuneParameters<BlsFr>;

    let rng = &mut ark_std::test_rng();

    let nc = 40000;

    let parameters = NepPrmBls381 {
        nb_rounds_ext: [
            zekrom_arkworks::neptune::params::NEB,
            zekrom_arkworks::neptune::params::NEE,
        ],
        nb_rounds_int: zekrom_arkworks::neptune::params::NI,
        round_constants: to_bls(&zekrom_arkworks::neptune::params::ROUND_CONSTANTS_BLS),
        gamma: FpVar::Constant(BlsFr::from(I256(zekrom_arkworks::neptune::params::GAMMA_BLS))),
        d: zekrom_arkworks::neptune::params::D,
        matrix_int: to_bls(&zekrom_arkworks::neptune::params::INTERNAL_MATRIX_BLS),
    };
    let chip = NepChpBls381::new(parameters);
    let sponge = NepSpnBls381::new(chip);

    let key = BlsFr::rand(rng);
    let nonce = BlsFr::rand(rng);

    // Iterate over the message size to produce the benchmark
    for size in 1..MAX_SIZE + 1 {
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();

        let ciphertext = NeptunePrimitivesBlsFr::ae(message.clone(), key, nonce)
            .unwrap()
            .value()
            .unwrap();

        let nv = ciphertext.len() + 1;

        let circuit = NepAECrcBls381 {
            sponge: sponge.clone(),
            message,
            ciphertext: ciphertext.clone(),
            key,
            nonce,
        };

        let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();
        let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();

        group.bench_function(
            format!("Neptune AE Marlin proof Generation with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = MarlinSetup::prove(&pk, circuit.clone(), rng).unwrap();
                })
            },
        );

        let proof = MarlinSetup::prove(&pk, circuit.clone(), rng).unwrap();
        let mut public = ciphertext;
        public.push(nonce);

        group.bench_function(
            &format!("Neptune AE Marlin proof Verification with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = MarlinSetup::verify(&vk, &public, &proof, rng).unwrap();
                });
            },
        );
    }
}

pub fn ae_duration_marlin_ciminion(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ciminion AE - marlin - Time bench");

    type KZG10 = MarlinKZG10<Bls381, DensePolynomial<BlsFr>>;
    type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

    let rng = &mut ark_std::test_rng();

    let nc = 20000;
    let nv = 1;

    let keys = (BlsFr::rand(rng), BlsFr::rand(rng));
    let nonce = BlsFr::rand(rng);

    let parameters = zekrom_arkworks::ciminion::chip::CiminionParameters {
        nb_rounds_pe: NB_R_PE_C,
        nb_rounds_pc: NB_R_PC,
        round_constants: to_bls(&zekrom_arkworks::ciminion::params::ROUND_CONSTANTS_BLS),
    };

    let chip = zekrom_arkworks::ciminion::chip::CiminionChip::new(parameters);

    // Iterate over the message size to produce the benchmark
    for size in 1..MAX_SIZE + 1 {
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();

        let ciphertext = zekrom_arkworks::ciminion::primitives::CiminionPrimitiveBlsFr::encrypt(
            &message, keys, nonce,
        );

        let circuit = zekrom_arkworks::ciminion::circuit::CiminionCircuit {
            chip: chip.clone(),
            message,
            ciphertext: ciphertext.clone(),
            keys,
            nonce,
        };

        let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();
        let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();

        group.bench_function(
            format!("Ciminion AE Marlin proof Generation with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = MarlinSetup::prove(&pk, circuit.clone(), rng).unwrap();
                })
            },
        );

        let proof = MarlinSetup::prove(&pk, circuit.clone(), rng).unwrap();
        let mut public = ciphertext;
        public.push(nonce);

        group.bench_function(
            &format!("Ciminion AE Marlin proof Verification with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = MarlinSetup::verify(&vk, &public, &proof, rng).unwrap();
                });
            },
        );
    }
}

pub fn hash_duration_groth16_rescue(c: &mut Criterion) {
    let mut group = c.benchmark_group("Rescue Prime Hash - groth16 - Time bench");

    let rng = &mut ark_std::test_rng();

    let parameters = RescuePrimeParameters {
        round_constants: to_bls(&ROUND_CONSTANTS),
        mds: to_bls(&MDS),
        alpha_inv: ALPHAINV_BLS381,
        alpha: ALPHA_BLS381,
    };
    let chip = RescuePrimeChip::new(parameters);

    type RpSpnBls381 = Sponge<RescuePrimeChip<BlsFr>>;
    let sponge = RpSpnBls381::new(chip);

    type GrothSetup = Groth16<Bls381>;

    // Iterate over the message size to produce the benchmark
    for size in 1..MAX_SIZE + 1 {
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();

        let hash = RescuePrimePrimitivesBlsFr::hash(message.clone())
            .unwrap()
            .value()
            .unwrap();

        let circuit = RescuePrimeHashCircuit {
            hash,
            message,
            sponge: sponge.clone(),
        };

        let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();

        group.bench_function(
            format!("Rescue Prime Groth16 proof Generation with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = GrothSetup::prove(&pk, circuit.clone(), rng).unwrap();
                })
            },
        );

        let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

        group.bench_function(
            &format!("Rescue Prime Groth16 proof Verification with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = GrothSetup::verify(&vk, &[hash], &proof).unwrap();
                });
            },
        );
    }
}

pub fn hash_duration_groth16_neptune(c: &mut Criterion) {
    let mut group = c.benchmark_group("Neptune Hash - groth16 - Time bench");

    type NepChpBls381 = NeptuneChip<BlsFr>;
    type NepSpnBls381 = Sponge<NepChpBls381>;
    type NepHshCrcBls381 = NeptuneHashCircuit<BlsFr>;
    type NepPrmBls381 = NeptuneParameters<BlsFr>;

    let rng = &mut ark_std::test_rng();

    let parameters = NepPrmBls381 {
        nb_rounds_ext: [
            zekrom_arkworks::neptune::params::NEB,
            zekrom_arkworks::neptune::params::NEE,
        ],
        nb_rounds_int: zekrom_arkworks::neptune::params::NI,
        round_constants: to_bls(&zekrom_arkworks::neptune::params::ROUND_CONSTANTS_BLS),
        gamma: FpVar::Constant(BlsFr::from(I256(zekrom_arkworks::neptune::params::GAMMA_BLS))),
        d: zekrom_arkworks::neptune::params::D,
        matrix_int: to_bls(&zekrom_arkworks::neptune::params::INTERNAL_MATRIX_BLS),
    };
    let chip = NepChpBls381::new(parameters);
    let sponge = NepSpnBls381::new(chip);

    type GrothSetup = Groth16<Bls381>;

    // Iterate over the message size to produce the benchmark
    for size in 1..MAX_SIZE + 1 {
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();

        let hash = NeptunePrimitivesBlsFr::hash(message.clone())
            .unwrap()
            .value()
            .unwrap();

        let circuit = NepHshCrcBls381 {
            hash,
            message,
            sponge: sponge.clone(),
        };

        let index = AHPForR1CS::index(circuit.clone()).unwrap();
        println!(
            "Number of constraints for R1CS - Neptune Hash . {} for size {}",
            index.index_info.num_constraints, size
        );

        let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();

        group.bench_function(
            format!("Neptune Hash Groth16 proof Generation with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = GrothSetup::prove(&pk, circuit.clone(), rng).unwrap();
                })
            },
        );

        let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

        group.bench_function(
            &format!("Neptune Hash Groth16 proof Verification with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = GrothSetup::verify(&vk, &[hash], &proof).unwrap();
                });
            },
        );
    }
}

pub fn hash_duration_groth16_griffin(c: &mut Criterion) {
    let mut group = c.benchmark_group("Griffin Hash - groth16 - Time bench");

    type GrothSetup = Groth16<Bls381>;

    type GrifChpBls381 = GriffinChip<BlsFr>;
    type GrifHshCrcBls381 = GriffinHashCircuit<BlsFr>;
    type GrifPrmBls381 = GriffinParameters<BlsFr>;

    type GrifSpnBls381 = Sponge<GrifChpBls381>;

    let rng = &mut ark_std::test_rng();

    let parameters = GrifPrmBls381 {
        nb_rounds: zekrom_arkworks::griffin::params::N,
        round_constants: to_bls(&ROUND_CONSTANTS),
        alpha: FpVar::Constant(BlsFr::from(I256(zekrom_arkworks::griffin::params::ALPHA))),
        beta: FpVar::Constant(BlsFr::from(I256(zekrom_arkworks::griffin::params::BETA))),
        d: zekrom_arkworks::griffin::params::D_BLS381,
        d_inv: zekrom_arkworks::griffin::params::D_INV_BLS381,
    };
    let chip = GrifChpBls381::new(parameters);

    let sponge = GrifSpnBls381::new(chip);

    // Iterate over the message size to produce the benchmark
    for size in 1..MAX_SIZE + 1 {
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();
        let hash = GriffinPrimitivesBlsFr::hash(message.clone())
            .unwrap()
            .value()
            .unwrap();

        let circuit = GrifHshCrcBls381 {
            message,
            hash,
            sponge: sponge.clone(),
        };

        let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();

        group.bench_function(
            format!("Griffin Hash Groth16 proof Generation with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = GrothSetup::prove(&pk, circuit.clone(), rng).unwrap();
                })
            },
        );

        let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

        group.bench_function(
            &format!("Griffin Hash Groth16 proof Verification with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = GrothSetup::verify(&vk, &[hash], &proof).unwrap();
                });
            },
        );
    }
}

pub fn ae_duration_groth16_griffin(c: &mut Criterion) {
    let mut group = c.benchmark_group("Griffin AE - groth16 - Time bench");

    type GrothSetup = Groth16<Bls381>;

    type GrifChpBls381 = GriffinChip<BlsFr>;
    type GrifPrmBls381 = GriffinParameters<BlsFr>;

    type GrifSpnBls381 = Sponge<GrifChpBls381>;
    type GrifAECrcBls381 = GriffinAECircuit<BlsFr>;

    let rng = &mut ark_std::test_rng();

    let parameters = GrifPrmBls381 {
        nb_rounds: zekrom_arkworks::griffin::params::N,
        round_constants: to_bls(&ROUND_CONSTANTS),
        alpha: FpVar::Constant(BlsFr::from(I256(zekrom_arkworks::griffin::params::ALPHA))),
        beta: FpVar::Constant(BlsFr::from(I256(zekrom_arkworks::griffin::params::BETA))),
        d: zekrom_arkworks::griffin::params::D_BLS381,
        d_inv: zekrom_arkworks::griffin::params::D_INV_BLS381,
    };
    let chip = GrifChpBls381::new(parameters);

    let sponge = GrifSpnBls381::new(chip);

    let key = BlsFr::rand(rng);
    let nonce = BlsFr::rand(rng);

    // Iterate over the message size to produce the benchmark
    for size in 1..MAX_SIZE + 1 {
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();

        let ciphertext = GriffinPrimitivesBlsFr::ae(message.clone(), key, nonce)
            .unwrap()
            .value()
            .unwrap();

        let circuit = GrifAECrcBls381 {
            sponge: sponge.clone(),
            message,
            ciphertext: ciphertext.clone(),
            key,
            nonce,
        };

        let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();

        group.bench_function(
            format!("Griffin AE Groth16 proof Generation with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = GrothSetup::prove(&pk, circuit.clone(), rng).unwrap();
                })
            },
        );

        let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();
        let mut public = ciphertext;
        public.push(nonce);

        group.bench_function(
            &format!("Griffin AE Groth16 proof Verification with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = GrothSetup::verify(&vk, &public, &proof).unwrap();
                });
            },
        );
    }
}

pub fn ae_duration_groth16_neptune(c: &mut Criterion) {
    let mut group = c.benchmark_group("Neptune AE - groth16 - Time bench");

    type GrothSetup = Groth16<Bls381>;

    type NepChpBls381 = NeptuneChip<BlsFr>;
    type NepSpnBls381 = Sponge<NepChpBls381>;
    type NepAECrcBls381 = NeptuneAECircuit<BlsFr>;
    type NepPrmBls381 = NeptuneParameters<BlsFr>;

    let rng = &mut ark_std::test_rng();

    let parameters = NepPrmBls381 {
        nb_rounds_ext: [
            zekrom_arkworks::neptune::params::NEB,
            zekrom_arkworks::neptune::params::NEE,
        ],
        nb_rounds_int: zekrom_arkworks::neptune::params::NI,
        round_constants: to_bls(&zekrom_arkworks::neptune::params::ROUND_CONSTANTS_BLS),
        gamma: FpVar::Constant(BlsFr::from(I256(zekrom_arkworks::neptune::params::GAMMA_BLS))),
        d: zekrom_arkworks::neptune::params::D,
        matrix_int: to_bls(&zekrom_arkworks::neptune::params::INTERNAL_MATRIX_BLS),
    };
    let chip = NepChpBls381::new(parameters);
    let sponge = NepSpnBls381::new(chip);

    let key = BlsFr::rand(rng);
    let nonce = BlsFr::rand(rng);

    // Iterate over the message size to produce the benchmark
    for size in 1..MAX_SIZE + 1 {
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();

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

        let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();

        group.bench_function(
            format!("Neptune AE Groth16 proof Generation with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = GrothSetup::prove(&pk, circuit.clone(), rng).unwrap();
                })
            },
        );

        let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();
        let mut public = ciphertext;
        public.push(nonce);

        group.bench_function(
            &format!("Neptune AE Groth16 proof Verification with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = GrothSetup::verify(&vk, &public, &proof).unwrap();
                });
            },
        );
    }
}

pub fn ae_duration_groth16_ciminion(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ciminion AE - groth16 - Time bench");

    type GrothSetup = Groth16<Bls381>;

    let rng = &mut ark_std::test_rng();

    let keys = (BlsFr::rand(rng), BlsFr::rand(rng));
    let nonce = BlsFr::rand(rng);

    let parameters = zekrom_arkworks::ciminion::chip::CiminionParameters {
        nb_rounds_pe: NB_R_PE_C,
        nb_rounds_pc: NB_R_PC,
        round_constants: to_bls(&zekrom_arkworks::ciminion::params::ROUND_CONSTANTS_BLS),
    };

    let chip = zekrom_arkworks::ciminion::chip::CiminionChip::new(parameters);

    // Iterate over the message size to produce the benchmark
    for size in 1..MAX_SIZE + 1 {
        let message = (0..size).map(|_| BlsFr::rand(rng)).collect::<Vec<_>>();

        let ciphertext = zekrom_arkworks::ciminion::primitives::CiminionPrimitiveBlsFr::encrypt(
            &message, keys, nonce,
        );

        let circuit = zekrom_arkworks::ciminion::circuit::CiminionCircuit {
            chip: chip.clone(),
            message,
            ciphertext: ciphertext.clone(),
            keys,
            nonce,
        };

        let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();

        group.bench_function(
            format!("Ciminion AE Groth16 proof Generation with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = GrothSetup::prove(&pk, circuit.clone(), rng).unwrap();
                })
            },
        );

        let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();
        let mut public = ciphertext;
        public.push(nonce);

        group.bench_function(
            &format!("Ciminion AE Groth16 proof Verification with N = {}", size),
            |b| {
                b.iter(|| {
                    let _ = GrothSetup::verify(&vk, &public, &proof).unwrap();
                });
            },
        );
    }
}
