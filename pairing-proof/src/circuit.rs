use ark_bls12_377::{Config as BLSConfig, Fq, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::emulated_fp::EmulatedFpVar,
    groups::{
        bls12::{G1Var, G2Var},
        CurveVar,
    },
    pairing::bls12::PairingVar as BLS12PairingVar,
    pairing::PairingVar,
};
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::uint8::UInt8;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_r1cs_std::prelude::Boolean;
use ark_crypto_primitives::crh::sha256::constraints::UnitVar;

#[derive(Clone)]
pub struct PairingCircuit {
    pub c_star_affine: G1Affine, // Public input C*
    pub beta: Fr, // Private witness β
    pub gamma: Fr, // Private witness γ
    pub gamma_hash: [u8; 32], // Hash of γ as public input
}

impl ConstraintSynthesizer<Fq> for PairingCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
        // === Allocate β and γ as emulated field variables (private witnesses) ===
        let beta_var = EmulatedFpVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(self.beta))?;
        let gamma_var = EmulatedFpVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(self.gamma))?;
        
        // === Allocate C* as public input ===
        let c_star_var = G1Var::<BLSConfig>::new_input(
            ark_relations::ns!(cs, "c_star"),
            || Ok(self.c_star_affine),
        )?;
        
        // === Allocate gamma hash as public input ===
        let gamma_hash_var = UInt8::<Fq>::new_input_vec(cs.clone(), &self.gamma_hash.to_vec())?;
        
        // === Constants (reuse prepared versions when possible) ===
        let g1_gen = G1Var::<BLSConfig>::new_constant(
            ark_relations::ns!(cs, "g1_generator"),
            G1Affine::generator(),
        )?;
        let g2_gen = G2Var::<BLSConfig>::new_constant(
            ark_relations::ns!(cs, "g2_generator"),
            G2Affine::generator(),
        )?;
        
        // === Prepare generators once (memory optimization) ===
        let g1_prepared = BLS12PairingVar::<BLSConfig>::prepare_g1(&g1_gen)?;
        let g2_prepared = BLS12PairingVar::<BLSConfig>::prepare_g2(&g2_gen)?;
        
        // === Convert gamma to bits for scalar multiplication ===
        let gamma_bits = gamma_var.to_bits_le()?;
        
        // === Verify hash of gamma ===
        // Optimize bit padding - use exact size needed
        let field_size_bits = Fr::MODULUS_BIT_SIZE as usize;
        let mut gamma_bits_padded = gamma_bits.clone();
        
        // Pad only to next byte boundary for efficiency
        let needed_padding = (8 - (field_size_bits % 8)) % 8;
        for _ in 0..needed_padding {
            gamma_bits_padded.push(Boolean::constant(false));
        }
        
        // Convert to bytes more efficiently
        let gamma_bytes: Vec<UInt8<Fq>> = gamma_bits_padded
            .chunks_exact(8)
            .map(|chunk| UInt8::from_bits_le(chunk))
            .collect();

        // Compute SHA256(gamma_bytes)
        let params_var = UnitVar::default();
        let sha_hash = Sha256Gadget::evaluate(&params_var, &gamma_bytes)?;
        
        // Enforce equality: computed SHA256(gamma) == public input hash
        sha_hash.0.enforce_equal(&gamma_hash_var)?;
        
        // === Compute g2^γ (reuse gamma_bits from hash computation) ===
        let g2_gamma_var = g2_gen.scalar_mul_le(gamma_bits.iter())?;
        
        // === Compute pairing(C*, g2^γ) ===
        let c_star_prepared = BLS12PairingVar::<BLSConfig>::prepare_g1(&c_star_var)?;
        let g2_gamma_prepared = BLS12PairingVar::<BLSConfig>::prepare_g2(&g2_gamma_var)?;
        let left_side = BLS12PairingVar::<BLSConfig>::pairing(c_star_prepared, g2_gamma_prepared)?;

        // === Compute pairing(g1, g2)^β ===
        // Reuse prepared generators
        let base_pairing = BLS12PairingVar::<BLSConfig>::pairing(g1_prepared, g2_prepared)?;

        let beta_bits = beta_var.to_bits_le()?;
        let right_side = base_pairing.pow_le(&beta_bits)?;

        // === Enforce the main pairing equation: pairing(C*, g2^γ) = pairing(g1, g2)^β ===
        left_side.enforce_equal(&right_side)?;
        
        Ok(())
    }
}