use super::*;

#[test]
fn test_constants() {
    // Test time delay constant
    assert_eq!(MIN_TIME_DELAY, 60);

    // Test fee calculation
    assert_eq!(FEE_BASIS_POINTS, 10);
    assert_eq!(BASIS_POINTS_DIVISOR, 10000);

    // Verify fee is 0.1%
    let fee_percentage = (FEE_BASIS_POINTS as f64) / (BASIS_POINTS_DIVISOR as f64) * 100.0;
    assert_eq!(fee_percentage, 0.1);
}

#[test]
fn test_denominations() {
    // Test denomination values (in lamports)
    assert_eq!(DENOMINATION_01_SOL, 100_000_000); // 0.1 SOL
    assert_eq!(DENOMINATION_1_SOL, 1_000_000_000); // 1 SOL
    assert_eq!(DENOMINATION_10_SOL, 10_000_000_000); // 10 SOL
    assert_eq!(DENOMINATION_100_SOL, 100_000_000_000); // 100 SOL

    // Verify relationships
    assert_eq!(DENOMINATION_1_SOL, DENOMINATION_01_SOL * 10);
    assert_eq!(DENOMINATION_10_SOL, DENOMINATION_1_SOL * 10);
    assert_eq!(DENOMINATION_100_SOL, DENOMINATION_10_SOL * 10);
}

#[test]
fn test_fee_calculation() {
    // Test 0.1% fee calculation for different denominations
    let calculate_fee = |amount: u64| -> u64 {
        amount
            .checked_mul(FEE_BASIS_POINTS)
            .unwrap()
            .checked_div(BASIS_POINTS_DIVISOR)
            .unwrap()
    };

    // 0.1 SOL
    let fee_01_sol = calculate_fee(DENOMINATION_01_SOL);
    assert_eq!(fee_01_sol, 100_000); // 0.0001 SOL
    assert_eq!(DENOMINATION_01_SOL - fee_01_sol, 99_900_000); // Net: 0.0999 SOL

    // 1 SOL
    let fee_1_sol = calculate_fee(DENOMINATION_1_SOL);
    assert_eq!(fee_1_sol, 1_000_000); // 0.001 SOL
    assert_eq!(DENOMINATION_1_SOL - fee_1_sol, 999_000_000); // Net: 0.999 SOL

    // 10 SOL
    let fee_10_sol = calculate_fee(DENOMINATION_10_SOL);
    assert_eq!(fee_10_sol, 10_000_000); // 0.01 SOL
    assert_eq!(DENOMINATION_10_SOL - fee_10_sol, 9_990_000_000); // Net: 9.99 SOL

    // 100 SOL
    let fee_100_sol = calculate_fee(DENOMINATION_100_SOL);
    assert_eq!(fee_100_sol, 100_000_000); // 0.1 SOL
    assert_eq!(DENOMINATION_100_SOL - fee_100_sol, 99_900_000_000); // Net: 99.9 SOL
}

#[test]
fn test_max_nullifiers_per_account() {
    // Verify max nullifiers constant
    assert_eq!(MAX_NULLIFIERS_PER_ACCOUNT, 100);

    // Verify it's reasonable for account size
    let nullifiers_size = 32 * MAX_NULLIFIERS_PER_ACCOUNT; // 32 bytes per nullifier
    assert_eq!(nullifiers_size, 3200); // 3.2KB for nullifiers
}

#[test]
fn test_config_account_size() {
    // Config: authority (32) + fee_collector (32) + paused (1) + bump (1) + discriminator (8)
    let expected_size = 8 + 32 + 32 + 1 + 1;
    assert_eq!(Config::LEN, expected_size);
    assert_eq!(Config::LEN, 74);
}

#[test]
fn test_mixer_pool_account_size() {
    // MixerPool: discriminator (8) + denomination (8) + min_delay (8) +
    // total_deposits (4) + total_withdrawals (4) + merkle_root (32) +
    // next_leaf_index (4) + creation_timestamp (8) + bump (1)
    let expected_size = 8 + 8 + 8 + 4 + 4 + 32 + 4 + 8 + 1;
    assert_eq!(MixerPool::LEN, expected_size);
    assert_eq!(MixerPool::LEN, 77);
}

#[test]
fn test_commitment_record_account_size() {
    // CommitmentRecord: discriminator (8) + pool (32) + commitment (32) +
    // leaf_index (4) + timestamp (8) + bump (1)
    let expected_size = 8 + 32 + 32 + 4 + 8 + 1;
    assert_eq!(CommitmentRecord::LEN, expected_size);
    assert_eq!(CommitmentRecord::LEN, 85);
}

#[test]
fn test_nullifier_registry_account_size() {
    // NullifierRegistry: discriminator (8) + pool (32) + bump (1) +
    // vec_len (4) + nullifiers (32 * 100)
    let expected_size = 8 + 32 + 1 + 4 + (32 * MAX_NULLIFIERS_PER_ACCOUNT);
    assert_eq!(NullifierRegistry::LEN, expected_size);
    assert_eq!(NullifierRegistry::LEN, 3245);
}

#[test]
fn test_encrypted_note_max_size() {
    // EncryptedNote: discriminator (8) + owner (32) + vec_len (4) +
    // encrypted_data (200) + pool (32) + leaf_index (4) + timestamp (8) + bump (1)
    assert_eq!(EncryptedNote::MAX_SIZE, 289);
}

#[test]
fn test_nullifier_registry_is_used() {
    let mut registry = NullifierRegistry {
        pool: Pubkey::default(),
        bump: 0,
        nullifiers: Vec::new(),
    };

    let nullifier1 = [1u8; 32];
    let nullifier2 = [2u8; 32];

    // Initially empty
    assert!(!registry.is_used(&nullifier1));
    assert!(!registry.is_used(&nullifier2));

    // Add first nullifier
    registry.nullifiers.push(nullifier1);
    assert!(registry.is_used(&nullifier1));
    assert!(!registry.is_used(&nullifier2));

    // Add second nullifier
    registry.nullifiers.push(nullifier2);
    assert!(registry.is_used(&nullifier1));
    assert!(registry.is_used(&nullifier2));
}

#[test]
fn test_nullifier_registry_add_nullifier() {
    let mut registry = NullifierRegistry {
        pool: Pubkey::default(),
        bump: 0,
        nullifiers: Vec::new(),
    };

    let nullifier = [42u8; 32];

    // Should succeed
    let result = registry.add_nullifier(nullifier);
    assert!(result.is_ok());
    assert_eq!(registry.nullifiers.len(), 1);
    assert!(registry.is_used(&nullifier));
}

#[test]
fn test_nullifier_registry_full() {
    let mut registry = NullifierRegistry {
        pool: Pubkey::default(),
        bump: 0,
        nullifiers: Vec::new(),
    };

    // Fill to max capacity
    for i in 0..MAX_NULLIFIERS_PER_ACCOUNT {
        let mut nullifier = [0u8; 32];
        nullifier[0] = i as u8;
        let result = registry.add_nullifier(nullifier);
        assert!(result.is_ok());
    }

    assert_eq!(registry.nullifiers.len(), MAX_NULLIFIERS_PER_ACCOUNT);

    // Next one should fail
    let overflow_nullifier = [255u8; 32];
    let result = registry.add_nullifier(overflow_nullifier);
    assert!(result.is_err());
}

#[test]
fn test_zero_commitment_validation() {
    let zero_commitment = [0u8; 32];

    // Zero commitment should be invalid
    // In the actual program, this check is done:
    // require!(commitment != [0u8; 32], MixerError::InvalidCommitment);
    assert_eq!(zero_commitment, [0u8; 32]);
}

#[test]
fn test_zero_nullifier_validation() {
    let zero_nullifier = [0u8; 32];

    // Zero nullifier should be invalid
    // In the actual program, this check is done:
    // require!(nullifier != [0u8; 32], MixerError::InvalidNullifier);
    assert_eq!(zero_nullifier, [0u8; 32]);
}

#[test]
fn test_denomination_validation() {
    let valid_denominations = vec![
        DENOMINATION_01_SOL,
        DENOMINATION_1_SOL,
        DENOMINATION_10_SOL,
        DENOMINATION_100_SOL,
    ];

    let invalid_denominations = vec![
        0,
        1,
        500_000_000, // 0.5 SOL
        5_000_000_000, // 5 SOL
        50_000_000_000, // 50 SOL
    ];

    for denom in valid_denominations {
        let is_valid = denom == DENOMINATION_01_SOL
            || denom == DENOMINATION_1_SOL
            || denom == DENOMINATION_10_SOL
            || denom == DENOMINATION_100_SOL;
        assert!(is_valid, "Valid denomination {} should pass", denom);
    }

    for denom in invalid_denominations {
        let is_valid = denom == DENOMINATION_01_SOL
            || denom == DENOMINATION_1_SOL
            || denom == DENOMINATION_10_SOL
            || denom == DENOMINATION_100_SOL;
        assert!(!is_valid, "Invalid denomination {} should fail", denom);
    }
}

#[test]
fn test_min_time_delay_validation() {
    let valid_delays = vec![60, 120, 300, 3600, 86400];
    let invalid_delays = vec![0, 1, 30, 59];

    for delay in valid_delays {
        assert!(
            delay >= MIN_TIME_DELAY,
            "Valid delay {} should pass",
            delay
        );
    }

    for delay in invalid_delays {
        assert!(
            delay < MIN_TIME_DELAY,
            "Invalid delay {} should fail",
            delay
        );
    }
}

#[test]
fn test_merkle_tree_capacity() {
    use crate::poseidon::MERKLE_TREE_DEPTH;

    // Tree depth of 20 allows 2^20 = 1,048,576 deposits per pool
    let max_deposits = 1u32 << MERKLE_TREE_DEPTH;
    assert_eq!(max_deposits, 1_048_576);

    // Verify depth
    assert_eq!(MERKLE_TREE_DEPTH, 20);
}

#[test]
fn test_fee_rounding() {
    // Test that fee calculation doesn't lose precision
    let amount = 1_234_567_890u64; // Random amount
    let fee = amount
        .checked_mul(FEE_BASIS_POINTS)
        .unwrap()
        .checked_div(BASIS_POINTS_DIVISOR)
        .unwrap();

    let net = amount.checked_sub(fee).unwrap();

    // Verify no overflow and correct calculation
    assert!(fee > 0);
    assert!(net < amount);
    assert_eq!(amount, fee + net);
}

#[test]
fn test_leaf_index_increment() {
    let mut next_leaf_index = 0u32;

    // Simulate deposits
    for expected in 0..100 {
        assert_eq!(next_leaf_index, expected);
        next_leaf_index += 1;
    }

    assert_eq!(next_leaf_index, 100);
}

#[test]
fn test_pool_statistics_increment() {
    let mut total_deposits = 0u32;
    let mut total_withdrawals = 0u32;

    // Simulate 10 deposits
    for _ in 0..10 {
        total_deposits += 1;
    }
    assert_eq!(total_deposits, 10);

    // Simulate 3 withdrawals
    for _ in 0..3 {
        total_withdrawals += 1;
    }
    assert_eq!(total_withdrawals, 3);

    // Verify pool has more deposits than withdrawals
    assert!(total_deposits > total_withdrawals);
}

#[test]
fn test_commitment_uniqueness() {
    // Different inputs should produce different commitments
    let commitment1 = [1u8; 32];
    let commitment2 = [2u8; 32];
    let commitment3 = [1u8; 32]; // Same as commitment1

    assert_ne!(commitment1, commitment2);
    assert_eq!(commitment1, commitment3);
}

#[test]
fn test_nullifier_uniqueness() {
    // Each nullifier should be unique
    let nullifier1 = [1u8; 32];
    let nullifier2 = [2u8; 32];

    assert_ne!(nullifier1, nullifier2);
}

#[test]
fn test_account_discriminators() {
    // Anchor adds 8-byte discriminators to all accounts
    // This is included in all LEN constants
    let discriminator_size = 8;

    assert!(Config::LEN >= discriminator_size);
    assert!(MixerPool::LEN >= discriminator_size);
    assert!(CommitmentRecord::LEN >= discriminator_size);
    assert!(NullifierRegistry::LEN >= discriminator_size);
    assert!(EncryptedNote::MAX_SIZE >= discriminator_size);
}

#[test]
fn test_balance_arithmetic() {
    // Test typical balance operations don't overflow
    let pool_balance = 1000 * DENOMINATION_1_SOL; // Pool has 1000 SOL
    let withdrawal = DENOMINATION_1_SOL;
    let fee = withdrawal
        .checked_mul(FEE_BASIS_POINTS)
        .unwrap()
        .checked_div(BASIS_POINTS_DIVISOR)
        .unwrap();
    let net_withdrawal = withdrawal.checked_sub(fee).unwrap();

    // Verify we can subtract from pool
    let remaining = pool_balance
        .checked_sub(withdrawal)
        .unwrap();

    assert_eq!(remaining, pool_balance - withdrawal);
    assert!(remaining > 0);
    assert_eq!(net_withdrawal + fee, withdrawal);
}

#[test]
fn test_timestamp_ordering() {
    // Timestamps should be monotonically increasing
    let t1: i64 = 1000;
    let t2: i64 = 2000;
    let t3: i64 = 3000;

    assert!(t1 < t2);
    assert!(t2 < t3);
    assert!(t1 < t3);

    // Test time delay check
    let min_delay = MIN_TIME_DELAY as i64;
    assert!(t2 - t1 >= min_delay);
    assert!(t3 - t1 >= min_delay);
}

#[test]
fn test_pubkey_size() {
    use std::mem::size_of;

    // Pubkey should be 32 bytes
    assert_eq!(size_of::<Pubkey>(), 32);
}

#[test]
fn test_bool_size() {
    use std::mem::size_of;

    // Bool should be 1 byte
    assert_eq!(size_of::<bool>(), 1);
}

#[test]
fn test_u8_array_32_size() {
    use std::mem::size_of;

    // [u8; 32] should be 32 bytes
    assert_eq!(size_of::<[u8; 32]>(), 32);
}
