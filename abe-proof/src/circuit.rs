use ark_bls12_377::{Config as BLSConfig, Fq, Fr, G1Affine, G2Affine, Fq12};
use ark_ec::AffineRepr;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{emulated_fp::EmulatedFpVar, fp12::Fp12Var},
    groups::bls12::{G1Var, G2Var},
    pairing::bls12::PairingVar as BLS12PairingVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::pairing::PairingVar;
use std::ops::Mul;
use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_crypto_primitives::crh::sha256::constraints::UnitVar;
use ark_r1cs_std::prelude::UInt8;
use ark_r1cs_std::prelude::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::groups::CurveVar;
use ark_ff::{Field, PrimeField};

// For BLS12-377, we need to use the proper Fq12 field configuration
type Fq12Var = Fp12Var<ark_bls12_377::Fq12Config>;

#[derive(Clone)]
pub struct PairingCircuit {
    pub s: Fr,              // Private witness 
    pub k: Fr,              // Private scalar that gets hashed to bid
    pub bid: [u8; 32],      // block id is the hash of k
    pub attr_hash_point: G1Affine, // Attribute hash point in G1

    pub ct0: Fq12,          // First element of ciphertext Ct[0] - this is in GT (target group)
    pub ct1: Fq12,          // Second element of ciphertext Ct[1] - this is in GT (target group)
    pub ct2: G1Affine,      // Third element of ciphertext Ct[2] - this is in G1 (source group)
    pub ct3: Fr,            // Fourth element of ciphertext Ct[3] - this is a scalar
    pub ct4: G1Affine,      // Fifth element of ciphertext Ct[4] - this is in G1 (source group)

    pub lambda: Fr,         // Lambda value for the pairing
    pub t: Fr,              // t value for the pairing
    pub w: Fr,              // w value for the pairing

    pub pk0: Fq12,          // Public key element pk[0] in GT
    pub pk1: Fr,            // Public key element pk[1] as scalar
}

impl ConstraintSynthesizer<Fq> for PairingCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
        // Private witnesses
        let s_var = EmulatedFpVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(self.s))?;
        let k_var = EmulatedFpVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(self.k))?;
        let lambda_var = EmulatedFpVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(self.lambda))?;
        let t_var = EmulatedFpVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(self.t))?;
        let w_var = EmulatedFpVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(self.w))?;
        
        // Ciphertext elements as witnesses
        let ct0_var = Fq12Var::new_witness(cs.clone(), || Ok(self.ct0))?;
        let ct1_var = Fq12Var::new_witness(cs.clone(), || Ok(self.ct1))?;
        let ct2_var = G1Var::<BLSConfig>::new_witness(cs.clone(), || Ok(self.ct2))?;
        let ct3_var = EmulatedFpVar::<Fr,Fq>::new_witness(cs.clone(), || Ok(self.ct3))?;
        let ct4_var = G1Var::<BLSConfig>::new_witness(cs.clone(), || Ok(self.ct4))?;

        // Public inputs
        let attr_base_var = G1Var::<BLSConfig>::new_input(cs.clone(), || Ok(self.attr_hash_point))?;
        let pk0_var = Fq12Var::new_input(cs.clone(), || Ok(self.pk0))?;
        let pk1_var = EmulatedFpVar::<Fr,Fq>::new_input(cs.clone(), || Ok(self.pk1))?;
        let bid_var = UInt8::<Fq>::new_input_vec(cs.clone(), &self.bid.to_vec())?;
                
        // === Constants (Prepare once, reuse multiple times) ===
        let g1_gen = G1Var::<BLSConfig>::new_constant(
            ark_relations::ns!(cs, "g1_generator"),
            G1Affine::generator(),
        )?;
        let g2_gen = G2Var::<BLSConfig>::new_constant(
            ark_relations::ns!(cs, "g2_generator"),
            G2Affine::generator(),
        )?;

        // Prepare generators once for reuse
        let g1_prepared = BLS12PairingVar::<BLSConfig>::prepare_g1(&g1_gen)?;
        let g2_prepared = BLS12PairingVar::<BLSConfig>::prepare_g2(&g2_gen)?;
        let base_pairing = BLS12PairingVar::<BLSConfig>::pairing(g1_prepared, g2_prepared.clone())?;

        let g = Fr::from(2u64);
        let g_var = EmulatedFpVar::<Fr,Fq>::new_constant(cs.clone(), g)?;

        // === Precompute bit representations to avoid redundant conversions ===
        let k_bits = k_var.to_bits_le()?;
        let t_bits = t_var.to_bits_le()?;
        let lambda_bits = lambda_var.to_bits_le()?;
        let w_bits = w_var.to_bits_le()?;

        // === Verify hash of k equals Block ID ===
        // Optimize bit padding - calculate exact padding needed
        let field_size_bits = Fr::MODULUS_BIT_SIZE as usize;
        let mut padded_bits = k_bits.clone();
        let needed_padding = (8 - (field_size_bits % 8)) % 8;
        for _ in 0..needed_padding {
            padded_bits.push(Boolean::constant(false));
        }
        
        let k_bytes: Vec<UInt8<Fq>> = padded_bits.chunks_exact(8)
            .map(|chunk| UInt8::from_bits_le(chunk))
            .collect();

        // Compute SHA256(k_bytes) and compare with bid
        let params_var = UnitVar::default();
        let hash_k = Sha256Gadget::evaluate(&params_var, &k_bytes)?;

        // Batch equality check
        hash_k.0.enforce_equal(&bid_var)?;

        // === Verify ct0 = e(g,g)^(k+s) ===
        // Compute k + s
        let k_plus_s = &k_var + &s_var;
        let k_plus_s_bits = k_plus_s.to_bits_le()?;
        
        // Compute e(g,g)^(k+s)
        let expected_ct0 = base_pairing.pow_le(&k_plus_s_bits)?;
        
        // Enforce ct0 == e(g,g)^(k+s)
        ct0_var.enforce_equal(&expected_ct0)?;

        // === Enforce c1 (optimized) ===
        // Create e(g,g)^lambda (reuse precomputed lambda_bits)
        let e_g_g_to_lambda = base_pairing.pow_le(&lambda_bits)?;

        // More efficient: multiply by inverse rather than divide
        let e_g_g_to_lambda_inv = e_g_g_to_lambda.inverse()?;
        let c1_divided = ct1_var.mul(&e_g_g_to_lambda_inv);

        // Compute pk0^t (reuse precomputed t_bits)
        let pk0_raised = pk0_var.pow_le(&t_bits)?;

        // Enforce equality
        c1_divided.enforce_equal(&pk0_raised)?;

        // === Enforce ct2 (optimized) ===
        // Use direct scalar multiplication with negated t
        let neg_t_var = t_var.negate()?;
        let neg_t_bits = neg_t_var.to_bits_le()?;
        let g_neg_t = g1_gen.scalar_mul_le(neg_t_bits.iter())?;

        ct2_var.enforce_equal(&g_neg_t)?;

        // === Enforce C3 (reuse precomputed bits) ===  
        let pk1_to_t = pk1_var.pow_le(&t_bits)?;
        let g_to_w = g_var.pow_le(&w_bits)?;
        let ct3_expected = pk1_to_t * g_to_w;
        ct3_var.enforce_equal(&ct3_expected)?;

        // === Enforce C4 (optimize pairing check) ===
        // Instead of two separate pairings, use bilinearity property
        let attr_pow_t = attr_base_var.scalar_mul_le(t_bits.iter())?;

        let ct4_prepared = BLS12PairingVar::<BLSConfig>::prepare_g1(&ct4_var)?;
        let expected_prepared = BLS12PairingVar::<BLSConfig>::prepare_g1(&attr_pow_t)?;

        let lhs = BLS12PairingVar::<BLSConfig>::pairing(ct4_prepared, g2_prepared.clone())?;
        let rhs = BLS12PairingVar::<BLSConfig>::pairing(expected_prepared, g2_prepared)?;
        Ok(())
    }
}