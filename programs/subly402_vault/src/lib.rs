use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;

pub mod asc_claim;
pub mod batch_hash;
pub mod constants;
pub mod ed25519_utils;
pub mod error;
pub mod instructions;
pub mod state;

use constants::{
    BUDGET_REQUEST_SCALARS, RECONCILE_REPORT_SCALARS, WITHDRAWAL_REPORT_SCALARS,
    WITHDRAWAL_REQUEST_SCALARS,
};
use instructions::*;

declare_id!("3iusaL6ys79DsbpweDwGhHvtjdnhAhtpyczPtMbu5Mbe");

#[arcium_program]
pub mod subly402_vault {
    use super::*;

    pub fn initialize_vault(
        ctx: Context<InitializeVault>,
        vault_id: u64,
        vault_signer_pubkey: Pubkey,
        auditor_master_pubkey: [u8; 32],
        attestation_policy_hash: [u8; 32],
    ) -> Result<()> {
        instructions::initialize_vault::handler(
            ctx,
            vault_id,
            vault_signer_pubkey,
            auditor_master_pubkey,
            attestation_policy_hash,
        )
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        instructions::deposit::handler(ctx, amount)
    }

    pub fn deposit_with_credit(
        ctx: Context<DepositWithCredit>,
        amount: u64,
        deposit_nonce: u64,
    ) -> Result<()> {
        instructions::deposit_with_credit::handler(ctx, amount, deposit_nonce)
    }

    pub fn withdraw(
        ctx: Context<Withdraw>,
        amount: u64,
        withdraw_nonce: u64,
        expires_at: i64,
        enclave_signature: [u8; 64],
    ) -> Result<()> {
        instructions::withdraw::handler(ctx, amount, withdraw_nonce, expires_at, enclave_signature)
    }

    pub fn settle_vault<'info>(
        ctx: Context<'_, '_, 'info, 'info, SettleVault<'info>>,
        batch_id: u64,
        batch_chunk_hash: [u8; 32],
        settlements: Vec<SettlementEntry>,
    ) -> Result<()> {
        instructions::settle_vault::handler(ctx, batch_id, batch_chunk_hash, settlements)
    }

    pub fn record_audit<'info>(
        ctx: Context<'_, '_, 'info, 'info, RecordAudit<'info>>,
        batch_id: u64,
        batch_chunk_hash: [u8; 32],
        records: Vec<AuditRecordData>,
    ) -> Result<()> {
        instructions::record_audit::handler(ctx, batch_id, batch_chunk_hash, records)
    }

    pub fn initialize_arcium_config(
        ctx: Context<InitializeArciumConfig>,
        status: u8,
        arcium_program_id: Pubkey,
        mxe_account: Pubkey,
        cluster_account: Pubkey,
        mempool_account: Pubkey,
        comp_def_version: u32,
        tee_x25519_pubkey: [u8; 32],
        strategy_controller: Pubkey,
        min_liquid_reserve_bps: u16,
        max_strategy_allocation_bps: u16,
        settlement_buffer_amount: u64,
        strategy_withdrawal_sla_sec: u64,
    ) -> Result<()> {
        instructions::initialize_arcium_config::handler(
            ctx,
            status,
            arcium_program_id,
            mxe_account,
            cluster_account,
            mempool_account,
            comp_def_version,
            tee_x25519_pubkey,
            strategy_controller,
            min_liquid_reserve_bps,
            max_strategy_allocation_bps,
            settlement_buffer_amount,
            strategy_withdrawal_sla_sec,
        )
    }

    pub fn set_arcium_status(ctx: Context<SetArciumStatus>, status: u8) -> Result<()> {
        instructions::set_arcium_status::handler(ctx, status)
    }

    pub fn update_arcium_deployment(
        ctx: Context<UpdateArciumDeployment>,
        arcium_program_id: Pubkey,
        mxe_account: Pubkey,
        cluster_account: Pubkey,
        mempool_account: Pubkey,
        comp_def_version: u32,
        tee_x25519_pubkey: [u8; 32],
    ) -> Result<()> {
        instructions::update_arcium_deployment::handler(
            ctx,
            arcium_program_id,
            mxe_account,
            cluster_account,
            mempool_account,
            comp_def_version,
            tee_x25519_pubkey,
        )
    }

    pub fn record_yield_epoch(
        ctx: Context<RecordYieldEpoch>,
        epoch_id: u64,
        realized_yield_amount: u64,
        total_eligible_shares: u64,
        strategy_receipt_hash: [u8; 32],
    ) -> Result<()> {
        instructions::record_yield_epoch::handler(
            ctx,
            epoch_id,
            realized_yield_amount,
            total_eligible_shares,
            strategy_receipt_hash,
        )
    }

    pub fn init_init_agent_vault_comp_def(ctx: Context<InitAgentVaultCompDef>) -> Result<()> {
        instructions::arcium_mirror::init_init_agent_vault_comp_def_handler(ctx)
    }

    pub fn init_agent_vault(ctx: Context<InitAgentVault>, computation_offset: u64) -> Result<()> {
        instructions::arcium_mirror::init_agent_vault_handler(ctx, computation_offset)
    }

    #[arcium_callback(encrypted_ix = "init_agent_vault")]
    pub fn init_agent_vault_callback(
        ctx: Context<InitAgentVaultCallback>,
        output: SignedComputationOutputs<InitAgentVaultOutput>,
    ) -> Result<()> {
        instructions::arcium_mirror::init_agent_vault_callback_handler(ctx, output)
    }

    pub fn init_apply_deposit_comp_def(ctx: Context<ApplyDepositCompDef>) -> Result<()> {
        instructions::arcium_mirror::init_apply_deposit_comp_def_handler(ctx)
    }

    pub fn apply_deposit(ctx: Context<ApplyDeposit>, computation_offset: u64) -> Result<()> {
        instructions::arcium_mirror::apply_deposit_handler(ctx, computation_offset)
    }

    #[arcium_callback(encrypted_ix = "apply_deposit")]
    pub fn apply_deposit_callback(
        ctx: Context<ApplyDepositCallback>,
        output: SignedComputationOutputs<ApplyDepositOutput>,
    ) -> Result<()> {
        instructions::arcium_mirror::apply_deposit_callback_handler(ctx, output)
    }

    pub fn init_settle_yield_comp_def(ctx: Context<SettleYieldCompDef>) -> Result<()> {
        instructions::arcium_mirror::init_settle_yield_comp_def_handler(ctx)
    }

    pub fn settle_yield(ctx: Context<SettleYield>, computation_offset: u64) -> Result<()> {
        instructions::arcium_mirror::settle_yield_handler(ctx, computation_offset)
    }

    #[arcium_callback(encrypted_ix = "settle_yield")]
    pub fn settle_yield_callback(
        ctx: Context<SettleYieldCallback>,
        output: SignedComputationOutputs<SettleYieldOutput>,
    ) -> Result<()> {
        instructions::arcium_mirror::settle_yield_callback_handler(ctx, output)
    }

    pub fn init_owner_view_comp_def(ctx: Context<OwnerViewCompDef>) -> Result<()> {
        instructions::arcium_mirror::init_owner_view_comp_def_handler(ctx)
    }

    pub fn owner_view(
        ctx: Context<OwnerView>,
        computation_offset: u64,
        owner_x25519_pubkey: [u8; 32],
    ) -> Result<()> {
        instructions::arcium_mirror::owner_view_handler(
            ctx,
            computation_offset,
            owner_x25519_pubkey,
        )
    }

    #[arcium_callback(encrypted_ix = "owner_view")]
    pub fn owner_view_callback(
        ctx: Context<OwnerViewCallback>,
        output: SignedComputationOutputs<OwnerViewOutput>,
    ) -> Result<()> {
        instructions::arcium_mirror::owner_view_callback_handler(ctx, output)
    }

    pub fn init_authorize_budget_comp_def(ctx: Context<AuthorizeBudgetCompDef>) -> Result<()> {
        instructions::arcium_mirror::init_authorize_budget_comp_def_handler(ctx)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_budget(
        ctx: Context<AuthorizeBudget>,
        computation_offset: u64,
        budget_id: u64,
        request_nonce: u64,
        expires_at: i64,
        request_x25519_pubkey: [u8; 32],
        request_ciphertexts: [[u8; 32]; BUDGET_REQUEST_SCALARS],
        request_ciphertext_nonce: [u8; 16],
    ) -> Result<()> {
        instructions::arcium_mirror::authorize_budget_handler(
            ctx,
            computation_offset,
            budget_id,
            request_nonce,
            expires_at,
            request_x25519_pubkey,
            request_ciphertexts,
            request_ciphertext_nonce,
        )
    }

    #[arcium_callback(encrypted_ix = "authorize_budget")]
    pub fn authorize_budget_callback(
        ctx: Context<AuthorizeBudgetCallback>,
        output: SignedComputationOutputs<AuthorizeBudgetOutput>,
    ) -> Result<()> {
        instructions::arcium_mirror::authorize_budget_callback_handler(ctx, output)
    }

    pub fn init_reconcile_budget_comp_def(ctx: Context<ReconcileBudgetCompDef>) -> Result<()> {
        instructions::arcium_mirror::init_reconcile_budget_comp_def_handler(ctx)
    }

    pub fn reconcile_budget(
        ctx: Context<ReconcileBudget>,
        computation_offset: u64,
        report_ciphertexts: [[u8; 32]; RECONCILE_REPORT_SCALARS],
        report_ciphertext_nonce: [u8; 16],
    ) -> Result<()> {
        instructions::arcium_mirror::reconcile_budget_handler(
            ctx,
            computation_offset,
            report_ciphertexts,
            report_ciphertext_nonce,
        )
    }

    #[arcium_callback(encrypted_ix = "reconcile_budget")]
    pub fn reconcile_budget_callback(
        ctx: Context<ReconcileBudgetCallback>,
        output: SignedComputationOutputs<ReconcileBudgetOutput>,
    ) -> Result<()> {
        instructions::arcium_mirror::reconcile_budget_callback_handler(ctx, output)
    }

    pub fn cancel_pending_arcium(ctx: Context<CancelPendingArcium>) -> Result<()> {
        instructions::arcium_mirror::cancel_pending_arcium_handler(ctx)
    }

    pub fn cancel_pending_budget(ctx: Context<CancelPendingBudget>) -> Result<()> {
        instructions::arcium_mirror::cancel_pending_budget_handler(ctx)
    }

    pub fn init_authorize_withdrawal_comp_def(
        ctx: Context<AuthorizeWithdrawalCompDef>,
    ) -> Result<()> {
        instructions::arcium_mirror::init_authorize_withdrawal_comp_def_handler(ctx)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_withdrawal(
        ctx: Context<AuthorizeWithdrawal>,
        computation_offset: u64,
        withdrawal_id: u64,
        expires_at: i64,
        recipient_ata: Pubkey,
        request_x25519_pubkey: [u8; 32],
        request_ciphertexts: [[u8; 32]; WITHDRAWAL_REQUEST_SCALARS],
        request_ciphertext_nonce: [u8; 16],
    ) -> Result<()> {
        instructions::arcium_mirror::authorize_withdrawal_handler(
            ctx,
            computation_offset,
            withdrawal_id,
            expires_at,
            recipient_ata,
            request_x25519_pubkey,
            request_ciphertexts,
            request_ciphertext_nonce,
        )
    }

    #[arcium_callback(encrypted_ix = "authorize_withdrawal")]
    pub fn authorize_withdrawal_callback(
        ctx: Context<AuthorizeWithdrawalCallback>,
        output: SignedComputationOutputs<AuthorizeWithdrawalOutput>,
    ) -> Result<()> {
        instructions::arcium_mirror::authorize_withdrawal_callback_handler(ctx, output)
    }

    pub fn init_reconcile_withdrawal_comp_def(
        ctx: Context<ReconcileWithdrawalCompDef>,
    ) -> Result<()> {
        instructions::arcium_mirror::init_reconcile_withdrawal_comp_def_handler(ctx)
    }

    pub fn reconcile_withdrawal(
        ctx: Context<ReconcileWithdrawal>,
        computation_offset: u64,
        report_ciphertexts: [[u8; 32]; WITHDRAWAL_REPORT_SCALARS],
        report_ciphertext_nonce: [u8; 16],
    ) -> Result<()> {
        instructions::arcium_mirror::reconcile_withdrawal_handler(
            ctx,
            computation_offset,
            report_ciphertexts,
            report_ciphertext_nonce,
        )
    }

    #[arcium_callback(encrypted_ix = "reconcile_withdrawal")]
    pub fn reconcile_withdrawal_callback(
        ctx: Context<ReconcileWithdrawalCallback>,
        output: SignedComputationOutputs<ReconcileWithdrawalOutput>,
    ) -> Result<()> {
        instructions::arcium_mirror::reconcile_withdrawal_callback_handler(ctx, output)
    }

    pub fn init_prepare_recovery_claim_comp_def(
        ctx: Context<PrepareRecoveryClaimCompDef>,
    ) -> Result<()> {
        instructions::arcium_mirror::init_prepare_recovery_claim_comp_def_handler(ctx)
    }

    pub fn prepare_recovery_claim(
        ctx: Context<PrepareRecoveryClaim>,
        computation_offset: u64,
        recovery_nonce: u64,
        recipient_ata: Pubkey,
    ) -> Result<()> {
        instructions::arcium_mirror::prepare_recovery_claim_handler(
            ctx,
            computation_offset,
            recovery_nonce,
            recipient_ata,
        )
    }

    #[arcium_callback(encrypted_ix = "prepare_recovery_claim")]
    pub fn prepare_recovery_claim_callback(
        ctx: Context<PrepareRecoveryClaimCallback>,
        output: SignedComputationOutputs<PrepareRecoveryClaimOutput>,
    ) -> Result<()> {
        instructions::arcium_mirror::prepare_recovery_claim_callback_handler(ctx, output)
    }

    pub fn arcium_force_settle_finalize(ctx: Context<ArciumForceSettleFinalize>) -> Result<()> {
        instructions::arcium_mirror::arcium_force_settle_finalize_handler(ctx)
    }

    pub fn asc_close_claim(
        ctx: Context<AscCloseClaimAccounts>,
        channel_id_hash: [u8; 32],
        request_id_hash: [u8; 32],
    ) -> Result<()> {
        instructions::asc_close_claim::handler(ctx, channel_id_hash, request_id_hash)
    }

    pub fn pause_vault(ctx: Context<PauseVault>) -> Result<()> {
        instructions::pause_vault::handler(ctx)
    }

    pub fn announce_migration(
        ctx: Context<AnnounceMigration>,
        successor_vault: Pubkey,
        exit_deadline: i64,
    ) -> Result<()> {
        instructions::announce_migration::handler(ctx, successor_vault, exit_deadline)
    }

    pub fn retire_vault(ctx: Context<RetireVault>) -> Result<()> {
        instructions::retire_vault::handler(ctx)
    }

    pub fn rotate_auditor(
        ctx: Context<RotateAuditor>,
        new_auditor_master_pubkey: [u8; 32],
    ) -> Result<()> {
        instructions::rotate_auditor::handler(ctx, new_auditor_master_pubkey)
    }

    pub fn force_settle_init(
        ctx: Context<ForceSettleInit>,
        participant_kind: u8,
        recipient_ata: Pubkey,
        free_balance: u64,
        locked_balance: u64,
        max_lock_expires_at: i64,
        receipt_nonce: u64,
        receipt_signature: [u8; 64],
        receipt_message: Vec<u8>,
    ) -> Result<()> {
        instructions::force_settle_init::handler(
            ctx,
            participant_kind,
            recipient_ata,
            free_balance,
            locked_balance,
            max_lock_expires_at,
            receipt_nonce,
            receipt_signature,
            receipt_message,
        )
    }

    pub fn force_settle_challenge(
        ctx: Context<ForceSettleChallenge>,
        newer_recipient_ata: Pubkey,
        newer_free_balance: u64,
        newer_locked_balance: u64,
        newer_max_lock_expires_at: i64,
        newer_receipt_nonce: u64,
        newer_receipt_signature: [u8; 64],
        newer_receipt_message: Vec<u8>,
    ) -> Result<()> {
        instructions::force_settle_challenge::handler(
            ctx,
            newer_recipient_ata,
            newer_free_balance,
            newer_locked_balance,
            newer_max_lock_expires_at,
            newer_receipt_nonce,
            newer_receipt_signature,
            newer_receipt_message,
        )
    }

    pub fn force_settle_finalize(ctx: Context<ForceSettleFinalize>) -> Result<()> {
        instructions::force_settle_finalize::handler(ctx)
    }
}
