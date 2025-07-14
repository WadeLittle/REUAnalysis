use ark_ff::{PrimeField, UniformRand, BigInteger};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_bls12_381::Fr;
use ark_groth16::Groth16;
use ark_crypto_primitives::snark::SNARK;
use ark_std::rand::{Rng, SeedableRng};
use ark_std::rand::rngs::StdRng;
use ark_serialize::CanonicalSerialize;
use std::time::Instant;
use sha2::Digest;
use circuit::OptimizedElGamalEncryptionCircuit;
use ark_bls12_381::Bls12_381;
use ark_ff::Field;
use ark_relations::r1cs::ConstraintSystem;

mod circuit;

/// Helper function to compute base^exponent in the field
/// This is a simplified implementation - in practice you'd want more efficient exponentiation
fn compute_power(base: &Fr, exponent: &Fr) -> Fr {
    // Convert exponent to bits and use square-and-multiply
    let exp_bits = exponent.into_bigint().to_bits_le();
    let mut result = Fr::from(1u64);
    let mut current_base = *base;
    
    for bit in exp_bits {
        if bit {
            result *= current_base;
        }
        current_base = current_base.square();
    }
    
    result
}

/// Generates ElGamal parameters and encrypts a message
fn setup_elgamal(rng: &mut StdRng) -> (Fr, Fr, Fr, Fr, Fr, [u8; 32]) {
    let h2 = Fr::from(2u64); // Generator
    let hdk = Fr::rand(rng); // Private key
    let message = Fr::rand(rng); // Random message to encrypt
    
    // Compute public key: hek = h2^hdk mod p1
    let hek = compute_power(&h2, &hdk);
    
    // ElGamal encryption
    let y = Fr::rand(rng); // Random nonce
    let c1 = compute_power(&h2, &y); // c1 = h2^y mod p1
    let s = compute_power(&hek, &y); // s = hek^y mod p1 (shared secret)
    let c2 = message * s; // c2 = m * s mod p1
    
    // Verify decryption works correctly
    let decrypted_s = compute_power(&c1, &hdk); // s = c1^hdk mod p1
    let decrypted_message = c2 * decrypted_s.inverse().unwrap(); // m = c2 * s^(-1) mod p1
    assert_eq!(message, decrypted_message, "Decryption failed - implementation error!");
    
    // Compute block ID as SHA256 hash of the original message
    let mut hasher = sha2::Sha256::new();
    let message_bytes = message.into_bigint().to_bytes_le();
    hasher.update(&message_bytes);
    let hash_result = hasher.finalize();
    let mut bid = [0u8; 32];
    bid.copy_from_slice(&hash_result);
    
    (c1, c2, hdk, message, hek, bid)
}

/// Extracts public inputs from a circuit
fn extract_public_inputs(circuit: &OptimizedElGamalEncryptionCircuit) -> Result<Vec<Fr>, SynthesisError> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.clone().generate_constraints(cs.clone())?;
    
    let instance_assignment = cs.borrow().unwrap().instance_assignment.clone();
    let public_inputs: Vec<Fr> = instance_assignment.iter().skip(1).cloned().collect();
    
    Ok(public_inputs)
}

fn main() {
    println!("=== ElGamal Decryption Proof System - Benchmark Analysis ===\n");
    
    const ITERATIONS: usize = 10;
    let mut setup_times = Vec::new();
    let mut prove_times = Vec::new();
    let mut verify_times = Vec::new();
    
    let mut constraint_counts = Vec::new();
    let mut variable_counts = Vec::new();
    let mut proof_sizes = Vec::new();
    
    for i in 0..ITERATIONS {
        println!("🔄 Running iteration {} of {}", i + 1, ITERATIONS);
        
        let mut rng = StdRng::seed_from_u64(12345 + i as u64); // Different seed each time
        let (c1, c2, hdk, _message, _hek, bid) = setup_elgamal(&mut rng);
        
        let circuit = OptimizedElGamalEncryptionCircuit {
            ct: [c1, c2],
            bid,
            hdk,
        };
        
        // Measure constraint generation (for stats)
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        constraint_counts.push(cs.num_constraints());
        variable_counts.push(cs.num_witness_variables());
        
        // Measure trusted setup
        let setup_start = Instant::now();
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng)
            .expect("Failed to perform trusted setup");
        let setup_time = setup_start.elapsed();
        setup_times.push(setup_time);
        
        // Measure proof generation
        let prove_start = Instant::now();
        let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng)
            .expect("Failed to generate proof");
        let prove_time = prove_start.elapsed();
        prove_times.push(prove_time);
        
        // Measure verification
        let public_inputs = extract_public_inputs(&circuit).unwrap();
        let verify_start = Instant::now();
        let is_valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof)
            .expect("Failed to verify proof");
        let verify_time = verify_start.elapsed();
        verify_times.push(verify_time);
        
        assert!(is_valid, "Proof should be valid");
        
        // Get proof size
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        proof_sizes.push(proof_bytes.len());
        
        println!("   ✅ Setup: {:?}, Prove: {:?}, Verify: {:?}", 
                 setup_time, prove_time, verify_time);
    }
    
    // Calculate statistics
    let avg_setup = setup_times.iter().sum::<std::time::Duration>() / ITERATIONS as u32;
    let avg_prove = prove_times.iter().sum::<std::time::Duration>() / ITERATIONS as u32;
    let avg_verify = verify_times.iter().sum::<std::time::Duration>() / ITERATIONS as u32;
    
    let min_setup = *setup_times.iter().min().unwrap();
    let max_setup = *setup_times.iter().max().unwrap();
    let min_prove = *prove_times.iter().min().unwrap();
    let max_prove = *prove_times.iter().max().unwrap();
    let min_verify = *verify_times.iter().min().unwrap();
    let max_verify = *verify_times.iter().max().unwrap();
    
    let avg_constraints = constraint_counts.iter().sum::<usize>() / ITERATIONS;
    let avg_variables = variable_counts.iter().sum::<usize>() / ITERATIONS;
    let avg_proof_size = proof_sizes.iter().sum::<usize>() / ITERATIONS;
    
    println!("\n📊 === BENCHMARK RESULTS ({} iterations) ===", ITERATIONS);
    println!("\n🏗️  Circuit Statistics:");
    println!("   - Constraints: {} (consistent across iterations)", avg_constraints);
    println!("   - Variables: {} (consistent across iterations)", avg_variables);
    println!("   - Proof Size: {} bytes", avg_proof_size);
    
    println!("\n⏱️  Timing Analysis:");
    println!("   TRUSTED SETUP:");
    println!("     - Average: {:?}", avg_setup);
    println!("     - Min: {:?}", min_setup);
    println!("     - Max: {:?}", max_setup);
    
    println!("   PROOF GENERATION:");
    println!("     - Average: {:?}", avg_prove);
    println!("     - Min: {:?}", min_prove);
    println!("     - Max: {:?}", max_prove);
    
    println!("   PROOF VERIFICATION:");
    println!("     - Average: {:?}", avg_verify);
    println!("     - Min: {:?}", min_verify);
    println!("     - Max: {:?}", max_verify);
    
    println!("\n📈 Raw Timing Data (for further analysis):");
    println!("Setup times (ms): {:?}", 
             setup_times.iter().map(|t| t.as_millis()).collect::<Vec<_>>());
    println!("Prove times (ms): {:?}", 
             prove_times.iter().map(|t| t.as_millis()).collect::<Vec<_>>());
    println!("Verify times (μs): {:?}", 
             verify_times.iter().map(|t| t.as_micros()).collect::<Vec<_>>());
    
    println!("\n🎯 Performance Summary:");
    println!("   - Total runtime: {:?}", 
             setup_times.iter().sum::<std::time::Duration>() + 
             prove_times.iter().sum::<std::time::Duration>() + 
             verify_times.iter().sum::<std::time::Duration>());
    println!("   - Average per iteration: {:?}", 
             (setup_times.iter().sum::<std::time::Duration>() + 
              prove_times.iter().sum::<std::time::Duration>() + 
              verify_times.iter().sum::<std::time::Duration>()) / ITERATIONS as u32);
}