use ark_bls12_377::{Config as BLSConfig, Fq, Fr, G1Affine, G2Affine, Fq12, Bls12_377};
use ark_bw6_761::{BW6_761, Fr as BW6Fr};
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{Field, ToConstraintField, PrimeField, UniformRand};
use ark_groth16::{Groth16, Proof};
use ark_relations::r1cs::ConstraintSystem;
use ark_snark::SNARK;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_std::rand::thread_rng;
use sha2::{Sha256, Digest};
use circuit::PairingCircuit;
use std::time::Instant;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_ff::BigInteger;
use ark_ff::BigInt;
use std::ops::Mul;
use std::time::Duration;
mod circuit;






fn compute_block_id_hash_from_scalar(k: Fr) -> [u8; 32] {
    // Convert Fr scalar to bytes for hashing
    let k_bytes = k.into_bigint().to_bytes_le();
    let mut hasher = Sha256::new();
    hasher.update(&k_bytes);
    hasher.finalize().into()
}

fn fq_to_bw6fr(fq: Fq) -> BW6Fr {
    let big = fq.into_bigint();
    BW6Fr::from_le_bytes_mod_order(&big.to_bytes_le())
}

fn main() {
    let mut rng = thread_rng();
    println!("🚀 Starting Pairing Circuit ZK-SNARK Demo");

    // === Constants ===
    let iterations = 10;
    let mut total_setup = Duration::ZERO;
    let mut total_proving = Duration::ZERO;
    let mut total_verifying = Duration::ZERO;

    // === Shared inputs ===
    let s = Fr::from(3u8);
    let lambda = Fr::from(3u8);
    let t = Fr::from(3u8);
    let w = Fr::from(3u8);
    let g1_gen = G1Affine::generator();
    let g2_gen = G2Affine::generator();
    let g = Fr::from(2u64);
    let attr_hash_point = (g1_gen * Fr::from(3u8)).into_affine();
    let alpha = Fr::from(3u8);
    let y = Fr::from(3u8);
    let pk0 = Bls12_377::pairing(g1_gen, g2_gen).0.pow(alpha.into_bigint());
    let pk1 = g.pow(y.into_bigint());
    let k_scalar = Fr::from(3u8);
    let base_pairing = Bls12_377::pairing(g1_gen, g2_gen);
    let k_plus_s = k_scalar + s;
    let ct0 = base_pairing.0.pow(k_plus_s.into_bigint());
    let bid = compute_block_id_hash_from_scalar(k_scalar);
    let ct1 = base_pairing.0.pow(lambda.into_bigint()) * pk0.pow(t.into_bigint());
    let neg_t = -t;
    let ct2 = (g1_gen * neg_t).into_affine();
    let ct3 = pk1.pow(t.into_bigint()) * g.pow(w.into_bigint());
    let ct4 = (attr_hash_point * t).into_affine();

    println!("\n🚀 Running {} iterations for benchmark...\n", iterations);

    for i in 0..iterations {
        println!("🔁 Iteration {}/{}", i + 1, iterations);

        let circuit = PairingCircuit {
            s,
            k: k_scalar,
            bid,
            attr_hash_point,
            ct0,
            ct1,
            ct2,
            ct3,
            ct4,
            lambda,
            t,
            w,
            pk0,
            pk1,
        };

        // Constraint system (for public inputs)
        let cs = ConstraintSystem::<Fq>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();

        if !cs.is_satisfied().unwrap() {
            panic!("❌ Circuit constraints not satisfied in iteration {}", i + 1);
        }

        // === Setup ===
        let setup_start = Instant::now();
        let (pk, vk) = Groth16::<BW6_761, LibsnarkReduction>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let setup_time = setup_start.elapsed();
        total_setup += setup_time;

        // === Prove ===
        let proving_start = Instant::now();
        let proof = Groth16::<BW6_761, LibsnarkReduction>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        let proving_time = proving_start.elapsed();
        total_proving += proving_time;

        // === Public Inputs ===
        let instance_assignment = cs.borrow().unwrap().instance_assignment.clone();
        let public_inputs: Vec<BW6Fr> = instance_assignment.iter().skip(1)
            .map(|fq_elem| fq_to_bw6fr(*fq_elem))
            .collect();

        // === Verify ===
        let verification_start = Instant::now();
        let is_valid = Groth16::<BW6_761, LibsnarkReduction>::verify(&vk, &public_inputs, &proof).unwrap();
        let verification_time = verification_start.elapsed();
        total_verifying += verification_time;

        if is_valid {
            println!("✅ Passed (Setup: {:?}, Prove: {:?}, Verify: {:?})", setup_time, proving_time, verification_time);
        } else {
            println!("❌ Failed verification in iteration {}", i + 1);
        }
    }

    // === Average Results ===
    println!("\n📊 Average Benchmark Results over {} iterations:", iterations);
    println!("   🔧 Avg Setup Time:        {:.2?}", total_setup / iterations);
    println!("   🎯 Avg Proving Time:      {:.2?}", total_proving / iterations);
    println!("   🔍 Avg Verification Time: {:.2?}", total_verifying / iterations);
}
