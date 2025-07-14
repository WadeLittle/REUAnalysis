use ark_bls12_377::{Fr, G1Affine, Fq};
use ark_bw6_761::{BW6_761, Fr as BW6Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, ToConstraintField, PrimeField};
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
use ark_poly::evaluations::multivariate::multilinear::MultilinearExtension;
 use ark_std::UniformRand;
mod circuit;

fn compute_gamma_hash(gamma: Fr) -> [u8; 32] {
    let mut gamma_bytes = gamma.into_bigint().to_bytes_le();
    gamma_bytes.resize(32, 0);
    let mut hasher = Sha256::new();
    hasher.update(&gamma_bytes);
    hasher.finalize().into()
}

fn fq_to_bw6fr(fq: Fq) -> BW6Fr {
    let big = fq.into_bigint();
    BW6Fr::from_le_bytes_mod_order(&big.to_bytes_le())
}

fn main() {
    let mut rng = thread_rng();
    let iterations = 10;

    use std::time::Duration;
    let mut total_setup = Duration::ZERO;
    let mut total_proving = Duration::ZERO;
    let mut total_verifying = Duration::ZERO;

    println!("\n🚀 Running {} benchmark iterations...\n", iterations);

    for i in 0..iterations {
        println!("🔁 Iteration {}/{}", i + 1, iterations);

        // === Witness values ===
        let beta = Fr::from(3u8);
        let gamma = Fr::from(7u8);
        let gamma_inv = gamma.inverse().unwrap();
        let beta_over_gamma = beta * gamma_inv;

        // === Create public group element ===
        let g1_gen = G1Affine::generator();
        let c_star_affine = (g1_gen * beta_over_gamma).into_affine();

        // === Compute hash ===
        let gamma_hash = compute_gamma_hash(gamma);

        // === Create circuit ===
        let circuit = PairingCircuit {
            c_star_affine,
            beta,
            gamma,
            gamma_hash,
        };

        // === Create constraint system and verify ===
        let cs = ConstraintSystem::<Fq>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap(), "❌ Constraints not satisfied");

        // === Setup ===
        let setup_start = Instant::now();
        let (pk, vk) = Groth16::<BW6_761, LibsnarkReduction>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let setup_time = setup_start.elapsed();
        total_setup += setup_time;

        // === Proving ===
        let proving_start = Instant::now();
        let proof = Groth16::<BW6_761, LibsnarkReduction>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        let proving_time = proving_start.elapsed();
        total_proving += proving_time;

        // === Extract public inputs ===
        let instance_assignment = cs.borrow().unwrap().instance_assignment.clone();
        let public_inputs: Vec<BW6Fr> = instance_assignment.iter().skip(1)
            .map(|fq_elem| fq_to_bw6fr(*fq_elem)).collect();

        // === Verification ===
        let verify_start = Instant::now();
        let is_valid = Groth16::<BW6_761, LibsnarkReduction>::verify(&vk, &public_inputs, &proof).unwrap();
        let verify_time = verify_start.elapsed();
        total_verifying += verify_time;

        assert!(is_valid, "❌ Proof failed verification");

        println!("✅ Iteration {} passed (Setup: {:?}, Prove: {:?}, Verify: {:?})", i + 1, setup_time, proving_time, verify_time);
    }

    // === Averages ===
    println!("\n📊 Benchmark Summary ({} runs):", iterations);
    println!("   🔧 Avg Setup Time:        {:.2?}", total_setup / iterations);
    println!("   🎯 Avg Proving Time:      {:.2?}", total_proving / iterations);
    println!("   🔍 Avg Verification Time: {:.2?}", total_verifying / iterations);
}
