/// Comprehensive tests for SHA256 Merkle tree implementation
use super::merkle::*;

#[test]
fn test_merkle_tree_depth() {
    assert_eq!(MERKLE_TREE_DEPTH, 20);

    // Verify capacity
    let max_leaves = 1u32 << MERKLE_TREE_DEPTH;
    assert_eq!(max_leaves, 1_048_576);
}

#[test]
fn test_hash_pair() {
    let left = [1u8; 32];
    let right = [2u8; 32];

    let hash1 = hash_pair(&left, &right);
    let hash2 = hash_pair(&left, &right);

    // Same inputs should produce same output
    assert_eq!(hash1, hash2);

    // Different order should produce different hash
    let hash3 = hash_pair(&right, &left);
    assert_ne!(hash1, hash3);
}

#[test]
fn test_hash_pair_properties() {
    let left = [42u8; 32];
    let right = [84u8; 32];

    let result = hash_pair(&left, &right);

    // Result should be 32 bytes
    assert_eq!(result.len(), 32);

    // Result should not be all zeros
    assert_ne!(result, [0u8; 32]);

    // Result should be deterministic
    let result2 = hash_pair(&left, &right);
    assert_eq!(result, result2);
}

#[test]
fn test_compute_merkle_root_single_leaf() {
    let leaf = [1u8; 32];
    let path = [[0u8; 32]; MERKLE_TREE_DEPTH];
    let path_indices = [false; MERKLE_TREE_DEPTH];

    let root = compute_merkle_root(&leaf, &path, &path_indices);

    // Should produce a valid 32-byte hash
    assert_eq!(root.len(), 32);
    assert_ne!(root, [0u8; 32]);
}

#[test]
fn test_compute_merkle_root_left_path() {
    let leaf = [1u8; 32];
    let mut path = [[0u8; 32]; MERKLE_TREE_DEPTH];
    path[0] = [2u8; 32];
    let path_indices = [false; MERKLE_TREE_DEPTH]; // All left

    let root = compute_merkle_root(&leaf, &path, &path_indices);

    assert_eq!(root.len(), 32);
    assert_ne!(root, [0u8; 32]);
}

#[test]
fn test_compute_merkle_root_right_path() {
    let leaf = [1u8; 32];
    let mut path = [[0u8; 32]; MERKLE_TREE_DEPTH];
    path[0] = [2u8; 32];
    let path_indices = [true; MERKLE_TREE_DEPTH]; // All right

    let root = compute_merkle_root(&leaf, &path, &path_indices);

    assert_eq!(root.len(), 32);
    assert_ne!(root, [0u8; 32]);
}

#[test]
fn test_compute_merkle_root_mixed_path() {
    let leaf = [1u8; 32];
    let mut path = [[0u8; 32]; MERKLE_TREE_DEPTH];
    for i in 0..MERKLE_TREE_DEPTH {
        path[i] = [i as u8; 32];
    }
    let mut path_indices = [false; MERKLE_TREE_DEPTH];
    path_indices[0] = true;
    path_indices[2] = true;
    path_indices[5] = true;

    let root = compute_merkle_root(&leaf, &path, &path_indices);

    assert_eq!(root.len(), 32);
    assert_ne!(root, [0u8; 32]);
}

#[test]
fn test_verify_merkle_proof_valid() {
    let leaf = [1u8; 32];
    let path = [[0u8; 32]; MERKLE_TREE_DEPTH];
    let path_indices = [false; MERKLE_TREE_DEPTH];

    let root = compute_merkle_root(&leaf, &path, &path_indices);

    // Verify the proof
    assert!(verify_merkle_proof(&leaf, &path, &path_indices, &root));
}

#[test]
fn test_verify_merkle_proof_invalid_leaf() {
    let leaf = [1u8; 32];
    let wrong_leaf = [2u8; 32];
    let path = [[0u8; 32]; MERKLE_TREE_DEPTH];
    let path_indices = [false; MERKLE_TREE_DEPTH];

    let root = compute_merkle_root(&leaf, &path, &path_indices);

    // Wrong leaf should fail verification
    assert!(!verify_merkle_proof(&wrong_leaf, &path, &path_indices, &root));
}

#[test]
fn test_verify_merkle_proof_invalid_path() {
    let leaf = [1u8; 32];
    let path = [[0u8; 32]; MERKLE_TREE_DEPTH];
    let mut wrong_path = [[0u8; 32]; MERKLE_TREE_DEPTH];
    wrong_path[0] = [99u8; 32];
    let path_indices = [false; MERKLE_TREE_DEPTH];

    let root = compute_merkle_root(&leaf, &path, &path_indices);

    // Wrong path should fail verification
    assert!(!verify_merkle_proof(&leaf, &wrong_path, &path_indices, &root));
}

#[test]
fn test_verify_merkle_proof_invalid_indices() {
    let leaf = [1u8; 32];
    let path = [[0u8; 32]; MERKLE_TREE_DEPTH];
    let path_indices = [false; MERKLE_TREE_DEPTH];
    let mut wrong_indices = [false; MERKLE_TREE_DEPTH];
    wrong_indices[0] = true;

    let root = compute_merkle_root(&leaf, &path, &path_indices);

    // Wrong indices should fail verification
    assert!(!verify_merkle_proof(&leaf, &path, &wrong_indices, &root));
}

#[test]
fn test_verify_merkle_proof_invalid_root() {
    let leaf = [1u8; 32];
    let path = [[0u8; 32]; MERKLE_TREE_DEPTH];
    let path_indices = [false; MERKLE_TREE_DEPTH];

    let root = compute_merkle_root(&leaf, &path, &path_indices);
    let mut wrong_root = root;
    wrong_root[0] ^= 1; // Flip one bit

    // Wrong root should fail verification
    assert!(!verify_merkle_proof(&leaf, &path, &path_indices, &wrong_root));
}

#[test]
fn test_merkle_tree_multiple_leaves() {
    // Simulate a tree with 4 leaves
    let leaf0 = [0u8; 32];
    let leaf1 = [1u8; 32];
    let leaf2 = [2u8; 32];
    let leaf3 = [3u8; 32];

    // Build level 1 (pairs of leaves)
    let node01 = hash_pair(&leaf0, &leaf1);
    let node23 = hash_pair(&leaf2, &leaf3);

    // Build level 2 (root of 4-leaf subtree)
    let mut current_root = hash_pair(&node01, &node23);

    // Compute zero values
    let zeros = compute_zero_values();

    // Continue hashing with zeros up to full depth
    for i in 2..MERKLE_TREE_DEPTH {
        current_root = hash_pair(&current_root, &zeros[i]);
    }
    let root = current_root;

    // Verify each leaf can prove membership
    // Leaf 0 (left-left path)
    let mut path0 = [[0u8; 32]; MERKLE_TREE_DEPTH];
    path0[0] = leaf1; // Sibling at level 0
    path0[1] = node23; // Sibling at level 1
    // Fill remaining levels with zero values
    for i in 2..MERKLE_TREE_DEPTH {
        path0[i] = zeros[i];
    }
    let indices0 = [false; MERKLE_TREE_DEPTH]; // all left
    assert!(verify_merkle_proof(&leaf0, &path0, &indices0, &root));

    // Leaf 1 (right-left path)
    let mut path1 = [[0u8; 32]; MERKLE_TREE_DEPTH];
    path1[0] = leaf0;
    path1[1] = node23;
    // Fill remaining levels with zero values
    for i in 2..MERKLE_TREE_DEPTH {
        path1[i] = zeros[i];
    }
    let mut indices1 = [false; MERKLE_TREE_DEPTH];
    indices1[0] = true; // right at level 0
    assert!(verify_merkle_proof(&leaf1, &path1, &indices1, &root));
}

#[test]
fn test_commitment_hash() {
    let secret = [42u8; 32];
    let nullifier = [84u8; 32];

    let commitment = compute_commitment(&secret, &nullifier);

    // Should produce valid 32-byte hash
    assert_eq!(commitment.len(), 32);
    assert_ne!(commitment, [0u8; 32]);

    // Should be deterministic
    let commitment2 = compute_commitment(&secret, &nullifier);
    assert_eq!(commitment, commitment2);

    // Different inputs should produce different output
    let secret2 = [43u8; 32];
    let commitment3 = compute_commitment(&secret2, &nullifier);
    assert_ne!(commitment, commitment3);
}

#[test]
fn test_commitment_different_nullifiers() {
    let secret = [1u8; 32];
    let nullifier1 = [2u8; 32];
    let nullifier2 = [3u8; 32];

    let commitment1 = compute_commitment(&secret, &nullifier1);
    let commitment2 = compute_commitment(&secret, &nullifier2);

    // Different nullifiers should produce different commitments
    assert_ne!(commitment1, commitment2);
}

#[test]
fn test_zero_values() {
    let zeros = compute_zero_values();

    // First zero should be all zeros
    assert_eq!(zeros[0], [0u8; 32]);

    // Each subsequent zero should be hash of previous
    for i in 1..=MERKLE_TREE_DEPTH {
        let expected = hash_pair(&zeros[i - 1], &zeros[i - 1]);
        assert_eq!(zeros[i], expected);
    }
}

#[test]
fn test_empty_tree_root() {
    let zeros = compute_zero_values();
    let empty_root = zeros[MERKLE_TREE_DEPTH];

    // Empty tree root should be deterministic
    assert_ne!(empty_root, [0u8; 32]);
}
