use anchor_lang::prelude::*;

use crate::constants::{
    AGENT_VAULT_SCALARS, ARCIUM_STATUS_ENFORCED, ARCIUM_STATUS_MIRROR, BUDGET_GRANT_SCALARS,
    BUDGET_GRANT_STATE_SCALARS, WITHDRAWAL_GRANT_SCALARS, WITHDRAWAL_GRANT_STATE_SCALARS,
};

#[account]
pub struct ArciumConfig {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub status: u8,
    pub arcium_program_id: Pubkey,
    pub mxe_account: Pubkey,
    pub cluster_account: Pubkey,
    pub mempool_account: Pubkey,
    pub comp_def_version: u32,
    pub tee_x25519_pubkey: [u8; 32],
    pub attestation_policy_hash: [u8; 32],
    pub strategy_controller: Pubkey,
    pub last_recorded_yield_epoch: u64,
    pub current_yield_index_q64: u128,
    pub min_liquid_reserve_bps: u16,
    pub max_strategy_allocation_bps: u16,
    pub settlement_buffer_amount: u64,
    pub strategy_withdrawal_sla_sec: u64,
}

impl ArciumConfig {
    pub const LEN: usize =
        8 + 1 + 32 + 1 + 32 + 32 + 32 + 32 + 4 + 32 + 32 + 32 + 8 + 16 + 2 + 2 + 8 + 8;

    pub fn writes_enabled(&self) -> bool {
        self.status == ARCIUM_STATUS_MIRROR || self.status == ARCIUM_STATUS_ENFORCED
    }

    pub fn status_requires_deployment(status: u8) -> bool {
        status == ARCIUM_STATUS_MIRROR || status == ARCIUM_STATUS_ENFORCED
    }

    pub fn deployment_configured(&self) -> bool {
        self.arcium_program_id != Pubkey::default()
            && self.mxe_account != Pubkey::default()
            && self.cluster_account != Pubkey::default()
            && self.mempool_account != Pubkey::default()
            && self.tee_x25519_pubkey != [0u8; 32]
    }
}

#[account]
pub struct ClientVaultState {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub client: Pubkey,
    pub status: u8,
    pub state_version: u64,
    pub pending_offset: u64,
    pub pending_started_at: i64,
    pub agent_vault_ciphertexts: [[u8; 32]; AGENT_VAULT_SCALARS],
    pub agent_vault_nonce: [u8; 16],
}

impl ClientVaultState {
    pub const LEN: usize = 8 + 1 + 32 + 32 + 1 + 8 + 8 + 8 + (32 * AGENT_VAULT_SCALARS) + 16;
}

#[account]
pub struct DepositCredit {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub client: Pubkey,
    pub deposit_nonce: u64,
    pub amount: u64,
    pub status: u8,
    pub created_at: i64,
    pub applied_state_version: u64,
}

impl DepositCredit {
    pub const LEN: usize = 8 + 1 + 32 + 32 + 8 + 8 + 1 + 8 + 8;
}

#[account]
pub struct BudgetGrant {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub client_vault_state: Pubkey,
    pub client: Pubkey,
    pub budget_id: u64,
    pub request_nonce: u64,
    pub status: u8,
    pub created_at: i64,
    pub expires_at: i64,
    pub state_version_at_authorization: u64,
    pub grant_state_ciphertexts: [[u8; 32]; BUDGET_GRANT_STATE_SCALARS],
    pub grant_state_nonce: [u8; 16],
    pub grant_ciphertexts: [[u8; 32]; BUDGET_GRANT_SCALARS],
    pub grant_nonce: [u8; 16],
}

impl BudgetGrant {
    pub const LEN: usize = 8
        + 1
        + 32
        + 32
        + 32
        + 8
        + 8
        + 1
        + 8
        + 8
        + 8
        + (32 * BUDGET_GRANT_STATE_SCALARS)
        + 16
        + (32 * BUDGET_GRANT_SCALARS)
        + 16;
}

#[account]
pub struct WithdrawalGrant {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub client_vault_state: Pubkey,
    pub client: Pubkey,
    pub withdrawal_id: u64,
    pub status: u8,
    pub recipient_ata: Pubkey,
    pub expires_at: i64,
    pub state_version_at_authorization: u64,
    pub grant_state_ciphertexts: [[u8; 32]; WITHDRAWAL_GRANT_STATE_SCALARS],
    pub grant_state_nonce: [u8; 16],
    pub grant_ciphertexts: [[u8; 32]; WITHDRAWAL_GRANT_SCALARS],
    pub grant_nonce: [u8; 16],
}

impl WithdrawalGrant {
    pub const LEN: usize = 8
        + 1
        + 32
        + 32
        + 32
        + 8
        + 1
        + 32
        + 8
        + 8
        + (32 * WITHDRAWAL_GRANT_STATE_SCALARS)
        + 16
        + (32 * WITHDRAWAL_GRANT_SCALARS)
        + 16;
}

#[account]
pub struct YieldEpoch {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub epoch_id: u64,
    pub realized_yield_amount: u64,
    pub total_eligible_shares: u64,
    pub previous_yield_index_q64: u128,
    pub new_yield_index_q64: u128,
    pub strategy_receipt_hash: [u8; 32],
    pub status: u8,
}

impl YieldEpoch {
    pub const LEN: usize = 8 + 1 + 32 + 8 + 8 + 8 + 16 + 16 + 32 + 1;
}

#[account]
pub struct RecoveryClaim {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub client_vault_state: Pubkey,
    pub client: Pubkey,
    pub recipient_ata: Pubkey,
    pub recovery_nonce: u64,
    pub status: u8,
    pub free_balance_due: u64,
    pub locked_balance_due: u64,
    pub max_lock_expires_at: i64,
    pub state_version: u64,
    pub initiated_at: i64,
    pub dispute_deadline: i64,
}

impl RecoveryClaim {
    pub const LEN: usize = 8 + 1 + 32 + 32 + 32 + 32 + 8 + 1 + 8 + 8 + 8 + 8 + 8 + 8;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured_arcium_config() -> ArciumConfig {
        ArciumConfig {
            bump: 255,
            vault_config: Pubkey::new_unique(),
            status: 0,
            arcium_program_id: Pubkey::new_unique(),
            mxe_account: Pubkey::new_unique(),
            cluster_account: Pubkey::new_unique(),
            mempool_account: Pubkey::new_unique(),
            comp_def_version: 0,
            tee_x25519_pubkey: [7u8; 32],
            attestation_policy_hash: [3u8; 32],
            strategy_controller: Pubkey::new_unique(),
            last_recorded_yield_epoch: 0,
            current_yield_index_q64: 0,
            min_liquid_reserve_bps: 0,
            max_strategy_allocation_bps: 0,
            settlement_buffer_amount: 0,
            strategy_withdrawal_sla_sec: 0,
        }
    }

    #[test]
    fn deployment_configured_requires_arcium_accounts_and_tee_key() {
        let config = configured_arcium_config();
        assert!(config.deployment_configured());

        let mut missing_program = configured_arcium_config();
        missing_program.arcium_program_id = Pubkey::default();
        assert!(!missing_program.deployment_configured());

        let mut missing_mxe = configured_arcium_config();
        missing_mxe.mxe_account = Pubkey::default();
        assert!(!missing_mxe.deployment_configured());

        let mut missing_cluster = configured_arcium_config();
        missing_cluster.cluster_account = Pubkey::default();
        assert!(!missing_cluster.deployment_configured());

        let mut missing_mempool = configured_arcium_config();
        missing_mempool.mempool_account = Pubkey::default();
        assert!(!missing_mempool.deployment_configured());

        let mut missing_tee_key = configured_arcium_config();
        missing_tee_key.tee_x25519_pubkey = [0u8; 32];
        assert!(!missing_tee_key.deployment_configured());
    }

    #[test]
    fn status_requires_deployment_only_for_write_modes() {
        assert!(!ArciumConfig::status_requires_deployment(0));
        assert!(ArciumConfig::status_requires_deployment(1));
        assert!(ArciumConfig::status_requires_deployment(2));
        assert!(!ArciumConfig::status_requires_deployment(3));
    }
}
