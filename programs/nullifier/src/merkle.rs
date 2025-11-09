use sha2::{Digest, Sha256};

/// Merkle tree depth (supports 2^20 = 1,048,576 deposits)
pub const MERKLE_TREE_DEPTH: usize = 20;

/// Zero values for each level of the Merkle tree
/// These are computed as: zeros[i+1] = Hash(zeros[i] || zeros[i])
/// Verified against frontend implementation
pub const ZERO_VALUES: [[u8; 32]; MERKLE_TREE_DEPTH + 1] = [
    // Level 0
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    // Level 1
    [245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151, 155, 67, 0, 61, 35, 32, 217, 240, 232, 234, 152, 49, 169, 39, 89, 251, 75],
    // Level 2
    [219, 86, 17, 78, 0, 253, 212, 193, 248, 92, 137, 43, 243, 90, 201, 168, 146, 137, 170, 236, 177, 235, 208, 169, 108, 222, 96, 106, 116, 139, 93, 113],
    // Level 3
    [199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60],
    // Level 4
    [83, 109, 152, 131, 127, 45, 209, 101, 165, 93, 94, 234, 233, 20, 133, 149, 68, 114, 213, 111, 36, 109, 242, 86, 191, 60, 174, 25, 53, 42, 18, 60],
    // Level 5
    [158, 253, 224, 82, 170, 21, 66, 159, 174, 5, 186, 212, 208, 177, 215, 198, 77, 166, 77, 3, 215, 161, 133, 74, 88, 140, 44, 184, 67, 12, 13, 48],
    // Level 6
    [216, 141, 223, 238, 212, 0, 168, 117, 85, 150, 178, 25, 66, 193, 73, 126, 17, 76, 48, 46, 97, 24, 41, 15, 145, 230, 119, 41, 118, 4, 31, 161],
    // Level 7
    [135, 235, 13, 219, 165, 126, 53, 246, 210, 134, 103, 56, 2, 164, 175, 89, 117, 226, 37, 6, 199, 207, 76, 100, 187, 107, 229, 238, 17, 82, 127, 44],
    // Level 8
    [38, 132, 100, 118, 253, 95, 197, 74, 93, 67, 56, 81, 103, 201, 81, 68, 242, 100, 63, 83, 60, 200, 91, 185, 209, 107, 120, 47, 141, 125, 177, 147],
    // Level 9
    [80, 109, 134, 88, 45, 37, 36, 5, 184, 64, 1, 135, 146, 202, 210, 191, 18, 89, 241, 239, 90, 165, 248, 135, 225, 60, 178, 240, 9, 79, 81, 225],
    // Level 10
    [255, 255, 10, 215, 230, 89, 119, 47, 149, 52, 193, 149, 200, 21, 239, 196, 1, 78, 241, 225, 218, 237, 68, 4, 192, 99, 133, 209, 17, 146, 233, 43],
    // Level 11
    [108, 240, 65, 39, 219, 5, 68, 28, 216, 51, 16, 122, 82, 190, 133, 40, 104, 137, 14, 67, 23, 230, 160, 42, 180, 118, 131, 170, 117, 150, 66, 32],
    // Level 12
    [183, 208, 95, 135, 95, 20, 0, 39, 239, 81, 24, 162, 36, 123, 187, 132, 206, 143, 47, 15, 17, 35, 98, 48, 133, 218, 247, 150, 12, 50, 159, 95],
    // Level 13
    [223, 106, 245, 245, 187, 219, 107, 233, 239, 138, 166, 24, 228, 191, 128, 115, 150, 8, 103, 23, 30, 41, 103, 111, 139, 40, 77, 234, 106, 8, 168, 94],
    // Level 14
    [181, 141, 144, 15, 94, 24, 46, 60, 80, 239, 116, 150, 158, 161, 108, 119, 38, 197, 73, 117, 124, 194, 53, 35, 195, 105, 88, 125, 167, 41, 55, 132],
    // Level 15
    [212, 154, 117, 2, 255, 207, 176, 52, 11, 29, 120, 133, 104, 133, 0, 202, 48, 129, 97, 167, 249, 107, 98, 223, 157, 8, 59, 113, 252, 200, 242, 187],
    // Level 16
    [143, 230, 177, 104, 146, 86, 192, 211, 133, 244, 47, 91, 190, 32, 39, 162, 44, 25, 150, 225, 16, 186, 151, 193, 113, 211, 229, 148, 141, 233, 43, 235],
    // Level 17
    [141, 13, 99, 195, 158, 186, 222, 133, 9, 224, 174, 60, 156, 56, 118, 251, 95, 161, 18, 190, 24, 249, 5, 236, 172, 254, 203, 146, 5, 118, 3, 171],
    // Level 18
    [149, 238, 200, 178, 229, 65, 202, 212, 233, 29, 227, 131, 133, 242, 224, 70, 97, 159, 84, 73, 108, 35, 130, 203, 108, 172, 213, 185, 140, 38, 245, 164],
    // Level 19
    [248, 147, 233, 8, 145, 119, 117, 182, 43, 255, 35, 41, 77, 187, 227, 161, 205, 142, 108, 193, 195, 91, 72, 1, 136, 123, 100, 106, 111, 129, 241, 127],
    // Level 20
    [205, 219, 167, 181, 146, 227, 19, 51, 147, 193, 97, 148, 250, 199, 67, 26, 191, 47, 84, 133, 237, 113, 29, 178, 130, 24, 60, 129, 158, 8, 235, 170],
];

/// Compute SHA256 hash of two 32-byte values
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    result.into()
}

/// Compute commitment from secret and nullifier
pub fn compute_commitment(secret: &[u8; 32], nullifier: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(nullifier);
    let result = hasher.finalize();
    result.into()
}

/// Verify Merkle proof
pub fn verify_merkle_proof(
    leaf: &[u8; 32],
    path: &[[u8; 32]; MERKLE_TREE_DEPTH],
    path_indices: &[bool; MERKLE_TREE_DEPTH],
    root: &[u8; 32],
) -> bool {
    let mut current = *leaf;

    for i in 0..MERKLE_TREE_DEPTH {
        let (left, right) = if path_indices[i] {
            (&path[i], &current)
        } else {
            (&current, &path[i])
        };

        current = hash_pair(left, right);
    }

    current == *root
}

/// Compute Merkle root from leaf and path
pub fn compute_merkle_root(
    leaf: &[u8; 32],
    path: &[[u8; 32]; MERKLE_TREE_DEPTH],
    path_indices: &[bool; MERKLE_TREE_DEPTH],
) -> [u8; 32] {
    let mut current = *leaf;

    for i in 0..MERKLE_TREE_DEPTH {
        let (left, right) = if path_indices[i] {
            (&path[i], &current)
        } else {
            (&current, &path[i])
        };

        current = hash_pair(left, right);
    }

    current
}

/// Compute zero values for each level of the tree (for testing)
pub fn compute_zero_values() -> [[u8; 32]; MERKLE_TREE_DEPTH + 1] {
    let mut zeros = [[0u8; 32]; MERKLE_TREE_DEPTH + 1];
    zeros[0] = [0u8; 32];

    for i in 1..=MERKLE_TREE_DEPTH {
        zeros[i] = hash_pair(&zeros[i - 1], &zeros[i - 1]);
    }

    zeros
}
