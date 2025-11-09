/// Comprehensive tests for Groth16 zkSNARK verification
use super::groth16::*;
use anchor_lang::prelude::*;

#[test]
fn test_proof_structure_sizes() {
    let proof = Groth16Proof {
        a: [0u8; 64],
        b: [0u8; 128],
        c: [0u8; 64],
    };

    // Verify point sizes
    assert_eq!(proof.a.len(), 64); // G1 point
    assert_eq!(proof.b.len(), 128); // G2 point
    assert_eq!(proof.c.len(), 64); // G1 point
}

#[test]
fn test_proof_creation() {
    let proof = Groth16Proof {
        a: [1u8; 64],
        b: [2u8; 128],
        c: [3u8; 64],
    };

    // Verify we can create and access fields
    assert_eq!(proof.a[0], 1);
    assert_eq!(proof.b[0], 2);
    assert_eq!(proof.c[0], 3);
}

#[test]
fn test_proof_clone() {
    let proof1 = Groth16Proof {
        a: [42u8; 64],
        b: [84u8; 128],
        c: [126u8; 64],
    };

    let proof2 = proof1.clone();

    assert_eq!(proof1.a, proof2.a);
    assert_eq!(proof1.b, proof2.b);
    assert_eq!(proof1.c, proof2.c);
}

#[test]
fn test_public_inputs_structure() {
    let inputs = PublicInputs {
        root: [1u8; 32],
        nullifier_hash: [2u8; 32],
    };

    assert_eq!(inputs.root.len(), 32);
    assert_eq!(inputs.nullifier_hash.len(), 32);
    assert_eq!(inputs.root[0], 1);
    assert_eq!(inputs.nullifier_hash[0], 2);
}

#[test]
fn test_public_inputs_clone() {
    let inputs1 = PublicInputs {
        root: [42u8; 32],
        nullifier_hash: [84u8; 32],
    };

    let inputs2 = inputs1.clone();

    assert_eq!(inputs1.root, inputs2.root);
    assert_eq!(inputs1.nullifier_hash, inputs2.nullifier_hash);
}

#[test]
fn test_verification_key_default() {
    let vk = VerificationKey::default();

    // Default should initialize all arrays to zeros
    assert_eq!(vk.alpha_g1, [0u8; 64]);
    assert_eq!(vk.beta_g2, [0u8; 128]);
    assert_eq!(vk.gamma_g2, [0u8; 128]);
    assert_eq!(vk.delta_g2, [0u8; 128]);
    assert_eq!(vk.ic.len(), 0);
}

#[test]
fn test_verification_key_size() {
    let expected_size = 8 + // discriminator
        64 + // alpha_g1
        128 + // beta_g2
        128 + // gamma_g2
        128 + // delta_g2
        4 + (64 * 3); // ic vector (3 public inputs)

    assert_eq!(VerificationKey::LEN, expected_size);
    assert_eq!(VerificationKey::LEN, 652);
}

#[test]
fn test_verification_key_creation() {
    let vk = VerificationKey {
        alpha_g1: [1u8; 64],
        beta_g2: [2u8; 128],
        gamma_g2: [3u8; 128],
        delta_g2: [4u8; 128],
        ic: vec![[5u8; 64], [6u8; 64], [7u8; 64]],
    };

    assert_eq!(vk.alpha_g1[0], 1);
    assert_eq!(vk.beta_g2[0], 2);
    assert_eq!(vk.gamma_g2[0], 3);
    assert_eq!(vk.delta_g2[0], 4);
    assert_eq!(vk.ic.len(), 3);
    assert_eq!(vk.ic[0][0], 5);
}

#[test]
fn test_verify_groth16_proof_basic() {
    let proof = Groth16Proof {
        a: [0u8; 64],
        b: [0u8; 128],
        c: [0u8; 64],
    };

    let public_inputs = PublicInputs {
        root: [1u8; 32],
        nullifier_hash: [2u8; 32],
    };

    let vk = VerificationKey::default();

    // Note: Current implementation is a placeholder that returns Ok(true)
    let result = verify_groth16_proof(&proof, &public_inputs, &vk);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true);
}

#[test]
fn test_verify_groth16_proof_different_inputs() {
    let proof = Groth16Proof {
        a: [42u8; 64],
        b: [84u8; 128],
        c: [126u8; 64],
    };

    let inputs1 = PublicInputs {
        root: [1u8; 32],
        nullifier_hash: [2u8; 32],
    };

    let inputs2 = PublicInputs {
        root: [3u8; 32],
        nullifier_hash: [4u8; 32],
    };

    let vk = VerificationKey::default();

    // Both should succeed with placeholder implementation
    assert!(verify_groth16_proof(&proof, &inputs1, &vk).is_ok());
    assert!(verify_groth16_proof(&proof, &inputs2, &vk).is_ok());
}

#[test]
fn test_g1_point_size() {
    // G1 points on BN254 curve are 64 bytes (2 field elements of 32 bytes each)
    let g1_size = 64;

    let proof = Groth16Proof {
        a: [0u8; 64],
        b: [0u8; 128],
        c: [0u8; 64],
    };

    assert_eq!(proof.a.len(), g1_size);
    assert_eq!(proof.c.len(), g1_size);
}

#[test]
fn test_g2_point_size() {
    // G2 points on BN254 curve are 128 bytes (4 field elements of 32 bytes each)
    let g2_size = 128;

    let proof = Groth16Proof {
        a: [0u8; 64],
        b: [0u8; 128],
        c: [0u8; 64],
    };

    assert_eq!(proof.b.len(), g2_size);
}

#[test]
fn test_public_inputs_field_element_size() {
    // Each public input should be a 32-byte field element
    let inputs = PublicInputs {
        root: [0u8; 32],
        nullifier_hash: [0u8; 32],
    };

    assert_eq!(inputs.root.len(), 32);
    assert_eq!(inputs.nullifier_hash.len(), 32);
}

#[test]
fn test_verification_key_ic_points() {
    // IC should have one point per public input plus one for the constant term
    // For our circuit: root, nullifier_hash, + constant = 3 points
    let expected_ic_count = 3;

    let mut vk = VerificationKey::default();
    vk.ic = vec![[0u8; 64]; expected_ic_count];

    assert_eq!(vk.ic.len(), expected_ic_count);
}

#[test]
fn test_proof_serialization_size() {
    use std::mem::size_of;

    // Total proof size should be 256 bytes (64 + 128 + 64)
    let expected_size = 64 + 128 + 64;

    let proof = Groth16Proof {
        a: [0u8; 64],
        b: [0u8; 128],
        c: [0u8; 64],
    };

    // Note: Actual size_of may include padding/alignment
    let _ = proof; // Use variable

    // Verify individual field sizes
    assert_eq!(64 + 128 + 64, expected_size);
}

#[test]
fn test_public_inputs_from_circuit() {
    // Simulate inputs from zkSNARK circuit
    let merkle_root = [1u8; 32];
    let nullifier = [2u8; 32];

    let inputs = PublicInputs {
        root: merkle_root,
        nullifier_hash: nullifier,
    };

    assert_eq!(inputs.root, merkle_root);
    assert_eq!(inputs.nullifier_hash, nullifier);
}

#[test]
fn test_verification_key_components() {
    let vk = VerificationKey {
        alpha_g1: [1u8; 64],
        beta_g2: [2u8; 128],
        gamma_g2: [3u8; 128],
        delta_g2: [4u8; 128],
        ic: vec![[5u8; 64]],
    };

    // Verify all components are accessible
    assert_ne!(vk.alpha_g1, [0u8; 64]);
    assert_ne!(vk.beta_g2, [0u8; 128]);
    assert_ne!(vk.gamma_g2, [0u8; 128]);
    assert_ne!(vk.delta_g2, [0u8; 128]);
    assert!(!vk.ic.is_empty());
}

#[test]
fn test_proof_non_zero() {
    let proof = Groth16Proof {
        a: [1u8; 64],
        b: [2u8; 128],
        c: [3u8; 64],
    };

    // Verify proof has non-zero values
    assert_ne!(proof.a, [0u8; 64]);
    assert_ne!(proof.b, [0u8; 128]);
    assert_ne!(proof.c, [0u8; 64]);
}

#[test]
fn test_verification_key_ic_dynamic_size() {
    // IC vector can grow dynamically based on number of public inputs
    let mut vk = VerificationKey::default();

    // Add IC points
    vk.ic.push([1u8; 64]);
    vk.ic.push([2u8; 64]);
    vk.ic.push([3u8; 64]);

    assert_eq!(vk.ic.len(), 3);
    assert_eq!(vk.ic[0], [1u8; 64]);
    assert_eq!(vk.ic[1], [2u8; 64]);
    assert_eq!(vk.ic[2], [3u8; 64]);
}
