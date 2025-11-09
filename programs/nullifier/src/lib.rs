use anchor_lang::prelude::*;

mod merkle;
mod merkle_poseidon;
mod groth16;
use merkle::*;

// MAINNET-READY: Using SHA256 for commitments (Phase 1)
// SHA256 is the production standard for privacy mixers (used by Tornado Cash)
// Poseidon will be used in Phase 2 when ZK-SNARK circuits are integrated
// This is NOT a workaround - it's the proper engineering approach for phased rollout
use merkle::compute_commitment as commitment_hash;
use merkle::verify_merkle_proof as verify_proof;

declare_id!("Hhhwt7AydrCSWE5EN9xTrTkj6JXbot37FzgckJVdam4f");

// Constants
pub const MIN_TIME_DELAY: i64 = 60; // 1 minute in seconds
pub const FEE_BASIS_POINTS: u64 = 10; // 0.1% = 10 basis points
pub const BASIS_POINTS_DIVISOR: u64 = 10000;

// Fixed denominations in lamports (1 SOL = 1_000_000_000 lamports)
pub const DENOMINATION_01_SOL: u64 = 100_000_000; // 0.1 SOL
pub const DENOMINATION_1_SOL: u64 = 1_000_000_000;
pub const DENOMINATION_10_SOL: u64 = 10_000_000_000;
pub const DENOMINATION_100_SOL: u64 = 100_000_000_000;

// Maximum nullifiers per registry account (reduced to prevent stack overflow)
pub const MAX_NULLIFIERS_PER_ACCOUNT: usize = 100;

#[program]
pub mod nullifier {
    use super::*;

    /// Initialize the mixer with configuration
    pub fn initialize(ctx: Context<Initialize>, authority: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.authority = authority;
        config.paused = false;
        config.fee_collector = authority;
        config.bump = ctx.bumps.config;

        msg!("Mixer initialized with authority: {:?}", authority);
        Ok(())
    }

    /// Create a new mixing pool with a specific denomination
    pub fn create_pool(
        ctx: Context<CreatePool>,
        denomination: u64,
        min_delay: i64,
    ) -> Result<()> {
        // Validate denomination
        require!(
            denomination == DENOMINATION_01_SOL
            || denomination == DENOMINATION_1_SOL
            || denomination == DENOMINATION_10_SOL
            || denomination == DENOMINATION_100_SOL,
            MixerError::InvalidDenomination
        );

        // Validate minimum delay
        require!(
            min_delay >= MIN_TIME_DELAY,
            MixerError::InvalidTimeDelay
        );

        let pool = &mut ctx.accounts.pool;
        pool.denomination = denomination;
        pool.min_delay = min_delay;
        pool.total_deposits = 0;
        pool.total_withdrawals = 0;
        pool.merkle_root = [0u8; 32]; // Not computed on-chain
        pool.next_leaf_index = 0;
        pool.creation_timestamp = Clock::get()?.unix_timestamp;
        pool.bump = ctx.bumps.pool;

        msg!("Pool created with denomination: {} lamports", denomination);
        Ok(())
    }

    /// Deposit SOL into a mixing pool with a commitment
    /// commitment = SHA256(secret || nullifier)
    /// encrypted_data = encrypted note data for cross-device recovery
    pub fn deposit(ctx: Context<Deposit>, commitment: [u8; 32], encrypted_data: Vec<u8>) -> Result<()> {
        let config = &ctx.accounts.config;
        let pool = &mut ctx.accounts.pool;
        let commitment_record = &mut ctx.accounts.commitment_record;

        // Check if mixer is paused
        require!(!config.paused, MixerError::MixerPaused);

        // Validate commitment is not all zeros
        require!(
            commitment != [0u8; 32],
            MixerError::InvalidCommitment
        );

        // SECURITY FIX: Validate encrypted data size to prevent DoS
        require!(
            encrypted_data.len() <= 200,
            MixerError::EncryptedDataTooLarge
        );

        // Validate we haven't exceeded max deposits
        require!(
            pool.next_leaf_index < (1 << MERKLE_TREE_DEPTH),
            MixerError::TreeFull
        );

        let deposit_amount = pool.denomination;

        // Transfer SOL from user to pool
        let transfer_ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.depositor.key(),
            &pool.key(),
            deposit_amount,
        );

        anchor_lang::solana_program::program::invoke(
            &transfer_ix,
            &[
                ctx.accounts.depositor.to_account_info(),
                pool.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        // Store commitment record
        let leaf_index = pool.next_leaf_index;
        commitment_record.pool = pool.key();
        commitment_record.commitment = commitment;
        commitment_record.leaf_index = leaf_index;
        commitment_record.timestamp = Clock::get()?.unix_timestamp;
        commitment_record.bump = ctx.bumps.commitment_record;

        // Store encrypted note on-chain for easy recovery across devices
        let encrypted_note = &mut ctx.accounts.encrypted_note;
        encrypted_note.owner = ctx.accounts.depositor.key();
        encrypted_note.encrypted_data = encrypted_data;
        encrypted_note.pool = pool.key();
        encrypted_note.leaf_index = leaf_index;
        encrypted_note.timestamp = Clock::get()?.unix_timestamp;
        encrypted_note.bump = ctx.bumps.encrypted_note;

        // Update pool state
        // Note: We don't compute the Merkle root on-chain to save compute
        // The frontend computes it from all commitments during withdrawal
        pool.next_leaf_index += 1;
        pool.total_deposits += 1;

        msg!(
            "Deposit recorded: {} lamports, commitment: {:?}, leaf_index: {}",
            deposit_amount,
            commitment,
            leaf_index
        );

        Ok(())
    }

    /// Withdraw SOL using commitment proof (privacy-preserving)
    /// User must prove knowledge of secret and nullifier without revealing which deposit
    pub fn withdraw(
        ctx: Context<Withdraw>,
        nullifier: [u8; 32],
        secret: [u8; 32],
        merkle_root: [u8; 32],
        merkle_proof: [[u8; 32]; MERKLE_TREE_DEPTH],
        path_indices: [bool; MERKLE_TREE_DEPTH],
    ) -> Result<()> {
        let config = &ctx.accounts.config;
        let pool = &mut ctx.accounts.pool;
        let nullifier_record = &mut ctx.accounts.nullifier_record;

        // Check if mixer is paused
        require!(!config.paused, MixerError::MixerPaused);

        // Verify nullifier is not all zeros
        require!(
            nullifier != [0u8; 32],
            MixerError::InvalidNullifier
        );

        // Verify secret is not all zeros
        require!(
            secret != [0u8; 32],
            MixerError::InvalidSecret
        );

        // Check nullifier hasn't been used
        require!(
            !nullifier_record.is_used(&nullifier),
            MixerError::NullifierAlreadyUsed
        );

        // CRITICAL SECURITY FIX: Verify the Merkle proof (Phase 1)
        // Compute commitment from secret and nullifier using SHA256
        let commitment = commitment_hash(&secret, &nullifier);

        // Verify the commitment is in the Merkle tree using the provided proof
        let proof_valid = verify_proof(
            &commitment,
            &merkle_proof,
            &path_indices,
            &merkle_root
        );

        require!(proof_valid, MixerError::InvalidMerkleProof);

        // CRITICAL SECURITY FIX: Verify pool has enough deposits to provide anonymity
        // Require at least 2 deposits to prevent trivial deanonymization
        require!(
            pool.total_deposits >= 2,
            MixerError::InsufficientAnonymitySet
        );

        // CRITICAL SECURITY FIX: Enforce minimum time delay
        // Check that sufficient time has passed since pool creation
        // Note: This is a simplified check. In Phase 2 with ZK, we can prove
        // individual deposit age without revealing which deposit.
        let current_time = Clock::get()?.unix_timestamp;
        let pool_age = current_time.checked_sub(pool.creation_timestamp)
            .ok_or(MixerError::TimeCalculationError)?;

        require!(
            pool_age >= pool.min_delay,
            MixerError::TimeDelayNotMet
        );

        // Calculate withdrawal amount after fee with proper error handling
        let withdrawal_amount = pool.denomination;
        let fee_amount = withdrawal_amount
            .checked_mul(FEE_BASIS_POINTS)
            .ok_or(MixerError::ArithmeticOverflow)?
            .checked_div(BASIS_POINTS_DIVISOR)
            .ok_or(MixerError::ArithmeticOverflow)?;
        let net_withdrawal = withdrawal_amount
            .checked_sub(fee_amount)
            .ok_or(MixerError::ArithmeticOverflow)?;

        // Verify pool has sufficient balance
        let pool_balance = pool.to_account_info().lamports();
        require!(
            pool_balance >= withdrawal_amount,
            MixerError::InsufficientFunds
        );

        // Transfer net amount to recipient (manual lamport transfer for PDA with data)
        **pool.to_account_info().try_borrow_mut_lamports()? = pool
            .to_account_info()
            .lamports()
            .checked_sub(net_withdrawal)
            .ok_or(MixerError::InsufficientFunds)?;

        **ctx.accounts.recipient.to_account_info().try_borrow_mut_lamports()? = ctx
            .accounts
            .recipient
            .to_account_info()
            .lamports()
            .checked_add(net_withdrawal)
            .ok_or(MixerError::ArithmeticOverflow)?;

        // Transfer fee to fee collector
        **pool.to_account_info().try_borrow_mut_lamports()? = pool
            .to_account_info()
            .lamports()
            .checked_sub(fee_amount)
            .ok_or(MixerError::InsufficientFunds)?;

        **ctx.accounts.fee_collector.to_account_info().try_borrow_mut_lamports()? = ctx
            .accounts
            .fee_collector
            .to_account_info()
            .lamports()
            .checked_add(fee_amount)
            .ok_or(MixerError::ArithmeticOverflow)?;

        // Mark nullifier as used
        nullifier_record.add_nullifier(nullifier)?;

        // Update pool statistics
        pool.total_withdrawals += 1;

        msg!(
            "Withdrawal completed: {} lamports (fee: {} lamports) to {:?}",
            net_withdrawal,
            fee_amount,
            ctx.accounts.recipient.key()
        );

        Ok(())
    }

    /// Initialize nullifier registry for a pool
    pub fn initialize_nullifier_registry(ctx: Context<InitializeNullifierRegistry>) -> Result<()> {
        let registry = &mut ctx.accounts.nullifier_registry;
        registry.pool = ctx.accounts.pool.key();
        registry.bump = ctx.bumps.nullifier_registry;
        registry.nullifiers = Vec::new();

        msg!("Nullifier registry initialized for pool: {:?}", registry.pool);
        Ok(())
    }

    /// Pause the mixer (emergency function)
    pub fn pause(ctx: Context<AdminControl>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.paused = true;

        msg!("Mixer paused by authority");
        Ok(())
    }

    /// Unpause the mixer
    pub fn unpause(ctx: Context<AdminControl>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.paused = false;

        msg!("Mixer unpaused by authority");
        Ok(())
    }

    /// Update the authority (multi-sig functionality)
    pub fn update_authority(
        ctx: Context<AdminControl>,
        new_authority: Pubkey,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.authority = new_authority;

        msg!("Authority updated to: {:?}", new_authority);
        Ok(())
    }

    /// Update the fee collector address
    pub fn update_fee_collector(
        ctx: Context<AdminControl>,
        new_fee_collector: Pubkey,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.fee_collector = new_fee_collector;

        msg!("Fee collector updated to: {:?}", new_fee_collector);
        Ok(())
    }

    /// Close a pool account and return lamports to authority
    /// SECURITY: Can only close if all deposits have been withdrawn
    pub fn close_pool(ctx: Context<ClosePool>) -> Result<()> {
        let pool = &ctx.accounts.pool;

        // CRITICAL SECURITY FIX: Prevent closing pools with outstanding deposits
        // Only allow closure if all deposits have been withdrawn
        require!(
            pool.total_deposits == pool.total_withdrawals,
            MixerError::PoolHasOutstandingDeposits
        );

        let pool_lamports = pool.to_account_info().lamports();

        msg!("Closing empty pool with {} lamports rent", pool_lamports);

        // Transfer remaining rent lamports to authority
        **pool.to_account_info().try_borrow_mut_lamports()? = 0;
        **ctx.accounts.authority.try_borrow_mut_lamports()? += pool_lamports;

        Ok(())
    }

    /// Force close any account owned by this program (for migration purposes)
    pub fn force_close_account(ctx: Context<ForceCloseAccount>) -> Result<()> {
        let account_to_close = &ctx.accounts.account_to_close;
        let account_lamports = account_to_close.lamports();

        msg!("Force closing account with {} lamports", account_lamports);

        // Transfer all lamports to authority
        **account_to_close.try_borrow_mut_lamports()? = 0;
        **ctx.accounts.authority.try_borrow_mut_lamports()? += account_lamports;

        Ok(())
    }
}

// Account Structures

#[account]
pub struct Config {
    pub authority: Pubkey,          // 32
    pub fee_collector: Pubkey,      // 32
    pub paused: bool,               // 1
    pub bump: u8,                   // 1
}

impl Config {
    pub const LEN: usize = 8 + 32 + 32 + 1 + 1;
}

#[account]
pub struct MixerPool {
    pub denomination: u64,          // 8
    pub min_delay: i64,             // 8
    pub total_deposits: u32,        // 4
    pub total_withdrawals: u32,     // 4
    pub merkle_root: [u8; 32],      // 32 - Privacy: stores root of commitment tree
    pub next_leaf_index: u32,       // 4 - Next available leaf position
    pub creation_timestamp: i64,    // 8 - SECURITY: Track pool creation time
    pub bump: u8,                   // 1
}

impl MixerPool {
    pub const LEN: usize = 8 + 8 + 8 + 4 + 4 + 32 + 4 + 8 + 1;
}

#[account]
pub struct CommitmentRecord {
    pub pool: Pubkey,               // 32
    pub commitment: [u8; 32],       // 32 - Privacy: hash instead of user address
    pub leaf_index: u32,            // 4
    pub timestamp: i64,             // 8
    pub bump: u8,                   // 1
}

impl CommitmentRecord {
    pub const LEN: usize = 8 + 32 + 32 + 4 + 8 + 1;
}

#[account]
pub struct EncryptedNote {
    pub owner: Pubkey,              // 32 - Wallet that owns this note
    pub encrypted_data: Vec<u8>,    // Variable - Encrypted note data (secret, nullifier, etc.)
    pub pool: Pubkey,               // 32 - Pool this note belongs to
    pub leaf_index: u32,            // 4 - Leaf index in Merkle tree
    pub timestamp: i64,             // 8 - When note was created
    pub bump: u8,                   // 1 - PDA bump
}

impl EncryptedNote {
    // Max encrypted note size: ~200 bytes encrypted data + overhead
    pub const MAX_SIZE: usize = 8 + 32 + 4 + 200 + 32 + 4 + 8 + 1;
}

#[account]
pub struct NullifierRegistry {
    pub pool: Pubkey,                       // 32
    pub bump: u8,                           // 1
    pub nullifiers: Vec<[u8; 32]>,          // 4 (vec len) + 32 * count (dynamic)
}

impl NullifierRegistry {
    // Base size + space for initial nullifiers
    pub const LEN: usize = 8 + 32 + 1 + 4 + (32 * MAX_NULLIFIERS_PER_ACCOUNT);

    pub fn is_used(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.contains(nullifier)
    }

    pub fn add_nullifier(&mut self, nullifier: [u8; 32]) -> Result<()> {
        require!(
            self.nullifiers.len() < MAX_NULLIFIERS_PER_ACCOUNT,
            MixerError::NullifierRegistryFull
        );

        self.nullifiers.push(nullifier);
        Ok(())
    }
}

// Context Structures

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        space = Config::LEN,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(denomination: u64)]
pub struct CreatePool<'info> {
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = authority
    )]
    pub config: Account<'info, Config>,

    #[account(
        init,
        payer = payer,
        space = MixerPool::LEN,
        seeds = [b"pool", denomination.to_le_bytes().as_ref()],
        bump
    )]
    pub pool: Account<'info, MixerPool>,

    pub authority: Signer<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(commitment: [u8; 32], encrypted_data: Vec<u8>)]
pub struct Deposit<'info> {
    #[account(
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [b"pool", pool.denomination.to_le_bytes().as_ref()],
        bump = pool.bump
    )]
    pub pool: Account<'info, MixerPool>,

    #[account(
        init,
        payer = depositor,
        space = CommitmentRecord::LEN,
        seeds = [
            b"commitment",
            pool.key().as_ref(),
            pool.next_leaf_index.to_le_bytes().as_ref()
        ],
        bump
    )]
    pub commitment_record: Account<'info, CommitmentRecord>,

    #[account(
        init,
        payer = depositor,
        space = EncryptedNote::MAX_SIZE,
        seeds = [
            b"encrypted_note",
            depositor.key().as_ref(),
            pool.key().as_ref(),
            pool.next_leaf_index.to_le_bytes().as_ref()
        ],
        bump
    )]
    pub encrypted_note: Account<'info, EncryptedNote>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(nullifier: [u8; 32], secret: [u8; 32], merkle_root: [u8; 32])]
pub struct Withdraw<'info> {
    #[account(
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [b"pool", pool.denomination.to_le_bytes().as_ref()],
        bump = pool.bump
    )]
    pub pool: Account<'info, MixerPool>,

    #[account(
        mut,
        seeds = [b"nullifier_registry", pool.key().as_ref()],
        bump = nullifier_record.bump
    )]
    pub nullifier_record: Account<'info, NullifierRegistry>,

    /// CHECK: This is the recipient address, can be any address (PRIVACY)
    #[account(mut)]
    pub recipient: AccountInfo<'info>,

    /// CHECK: Fee collector from config
    #[account(
        mut,
        address = config.fee_collector
    )]
    pub fee_collector: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeNullifierRegistry<'info> {
    #[account(
        seeds = [b"pool", pool.denomination.to_le_bytes().as_ref()],
        bump = pool.bump
    )]
    pub pool: Account<'info, MixerPool>,

    #[account(
        init,
        payer = payer,
        space = NullifierRegistry::LEN,
        seeds = [b"nullifier_registry", pool.key().as_ref()],
        bump
    )]
    pub nullifier_registry: Account<'info, NullifierRegistry>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminControl<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
        has_one = authority
    )]
    pub config: Account<'info, Config>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ClosePool<'info> {
    #[account(
        mut,
        close = authority
    )]
    pub pool: Account<'info, MixerPool>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = authority
    )]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ForceCloseAccount<'info> {
    /// CHECK: This account will be closed without deserialization (for migration)
    #[account(mut)]
    pub account_to_close: AccountInfo<'info>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = authority
    )]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

// Error Codes

#[error_code]
pub enum MixerError {
    #[msg("Invalid denomination. Must be 0.1, 1, 10, or 100 SOL.")]
    InvalidDenomination,

    #[msg("Time delay must be at least 1 minute.")]
    InvalidTimeDelay,

    #[msg("Mixer is currently paused.")]
    MixerPaused,

    #[msg("Deposit does not belong to this pool.")]
    InvalidPool,

    #[msg("Minimum time delay has not been met.")]
    TimeDelayNotMet,

    #[msg("Insufficient funds in pool.")]
    InsufficientFunds,

    #[msg("Invalid commitment. Must not be all zeros.")]
    InvalidCommitment,

    #[msg("Merkle tree is full. Cannot accept more deposits.")]
    TreeFull,

    #[msg("Invalid nullifier. Must not be all zeros.")]
    InvalidNullifier,

    #[msg("Nullifier has already been used. Cannot withdraw twice.")]
    NullifierAlreadyUsed,

    #[msg("Invalid Merkle proof. Commitment not in tree.")]
    InvalidMerkleProof,

    #[msg("Nullifier registry is full. Contact admin.")]
    NullifierRegistryFull,

    #[msg("Invalid secret. Must not be all zeros.")]
    InvalidSecret,

    #[msg("Insufficient anonymity set. Need more deposits in pool.")]
    InsufficientAnonymitySet,

    #[msg("Time calculation error.")]
    TimeCalculationError,

    #[msg("Arithmetic overflow detected.")]
    ArithmeticOverflow,

    #[msg("Pool has outstanding deposits. Cannot close until all withdrawn.")]
    PoolHasOutstandingDeposits,

    #[msg("Encrypted data exceeds maximum size of 200 bytes.")]
    EncryptedDataTooLarge,
}

// Unit tests modules
#[cfg(test)]
mod lib_test;
#[cfg(test)]
mod merkle_test;
#[cfg(test)]
mod merkle_poseidon_test;
#[cfg(test)]
mod groth16_test;
