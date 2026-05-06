use crate::{
    constants::{
        AGENT_VAULT_SCALARS, ARCIUM_PENDING_TIMEOUT_SEC, BUDGET_GRANT_SCALARS,
        BUDGET_GRANT_STATE_SCALARS, BUDGET_GRANT_STATUS_CANCELLED, BUDGET_GRANT_STATUS_CLOSED,
        BUDGET_GRANT_STATUS_PENDING, BUDGET_GRANT_STATUS_READY, BUDGET_GRANT_STATUS_RECONCILING,
        BUDGET_REQUEST_SCALARS, CLIENT_VAULT_STATUS_CLOSED, CLIENT_VAULT_STATUS_IDLE,
        CLIENT_VAULT_STATUS_PENDING, COMP_DEF_OFFSET_APPLY_DEPOSIT,
        COMP_DEF_OFFSET_AUTHORIZE_BUDGET, COMP_DEF_OFFSET_AUTHORIZE_WITHDRAWAL,
        COMP_DEF_OFFSET_INIT_AGENT_VAULT, COMP_DEF_OFFSET_OWNER_VIEW,
        COMP_DEF_OFFSET_PREPARE_RECOVERY_CLAIM, COMP_DEF_OFFSET_RECONCILE_BUDGET,
        COMP_DEF_OFFSET_RECONCILE_WITHDRAWAL, COMP_DEF_OFFSET_SETTLE_YIELD,
        DEPOSIT_CREDIT_STATUS_APPLIED, DEPOSIT_CREDIT_STATUS_PENDING, RECONCILE_REPORT_SCALARS,
        RECOVERY_CLAIM_STATUS_CANCELLED, RECOVERY_CLAIM_STATUS_FINALIZED,
        RECOVERY_CLAIM_STATUS_PENDING, RECOVERY_CLAIM_STATUS_READY, VAULT_STATUS_ACTIVE,
        VAULT_STATUS_MIGRATING, VAULT_STATUS_PAUSED, WITHDRAWAL_GRANT_SCALARS,
        WITHDRAWAL_GRANT_STATE_SCALARS, WITHDRAWAL_GRANT_STATUS_CANCELLED,
        WITHDRAWAL_GRANT_STATUS_CLOSED, WITHDRAWAL_GRANT_STATUS_PENDING,
        WITHDRAWAL_GRANT_STATUS_READY, WITHDRAWAL_GRANT_STATUS_RECONCILING,
        WITHDRAWAL_REPORT_SCALARS, WITHDRAWAL_REQUEST_SCALARS,
    },
    error::VaultError,
    error::VaultError as ErrorCode,
    state::{
        ArciumConfig, BudgetGrant, ClientVaultState, DepositCredit, RecoveryClaim, VaultConfig,
        WithdrawalGrant,
    },
    ArciumSignerAccount, ID, ID_CONST,
};
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::CallbackAccount;
use sha2::{Digest, Sha256};

#[queue_computation_accounts("init_agent_vault", client)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct InitAgentVault<'info> {
    #[account(mut)]
    pub client: Signer<'info>,

    #[account(
        constraint = vault_config.status == VAULT_STATUS_ACTIVE @ VaultError::VaultInactive,
    )]
    pub vault_config: Box<Account<'info, VaultConfig>>,

    #[account(
        constraint = arcium_config.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
    )]
    pub arcium_config: Box<Account<'info, ArciumConfig>>,

    #[account(
        init,
        payer = client,
        space = ClientVaultState::LEN,
        seeds = [
            b"client_vault_state",
            vault_config.key().as_ref(),
            client.key().as_ref(),
        ],
        bump,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        init_if_needed,
        space = 9,
        payer = client,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_INIT_AGENT_VAULT))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("init_agent_vault")]
#[derive(Accounts)]
pub struct InitAgentVaultCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_INIT_AGENT_VAULT))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by Arcium callback constraints.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by account constraint.
    pub instructions_sysvar: AccountInfo<'info>,

    #[account(
        mut,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_PENDING @ VaultError::InvalidArciumCallback,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,
}

#[init_computation_definition_accounts("init_agent_vault", payer)]
#[derive(Accounts)]
pub struct InitAgentVaultCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by the Arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: checked by the Arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: address lookup table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[queue_computation_accounts("apply_deposit", client)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct ApplyDeposit<'info> {
    #[account(mut)]
    pub client: Signer<'info>,

    #[account(
        constraint = vault_config.status == VAULT_STATUS_ACTIVE
            || vault_config.status == VAULT_STATUS_MIGRATING
            || vault_config.status == VAULT_STATUS_PAUSED
            @ VaultError::VaultInactive,
    )]
    pub vault_config: Box<Account<'info, VaultConfig>>,

    #[account(
        constraint = arcium_config.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
    )]
    pub arcium_config: Box<Account<'info, ArciumConfig>>,

    #[account(
        mut,
        constraint = client_vault_state.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
        constraint = client_vault_state.client == client.key() @ VaultError::Unauthorized,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_IDLE @ VaultError::ArciumStatePending,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        mut,
        constraint = deposit_credit.vault_config == vault_config.key() @ VaultError::InvalidDepositCredit,
        constraint = deposit_credit.client == client.key() @ VaultError::InvalidDepositCredit,
        constraint = deposit_credit.status == DEPOSIT_CREDIT_STATUS_PENDING @ VaultError::InvalidDepositCredit,
    )]
    pub deposit_credit: Box<Account<'info, DepositCredit>>,

    #[account(
        init_if_needed,
        space = 9,
        payer = client,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_APPLY_DEPOSIT))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("apply_deposit")]
#[derive(Accounts)]
pub struct ApplyDepositCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_APPLY_DEPOSIT))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by Arcium callback constraints.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by account constraint.
    pub instructions_sysvar: AccountInfo<'info>,

    #[account(
        mut,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_PENDING @ VaultError::InvalidArciumCallback,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        mut,
        constraint = deposit_credit.vault_config == client_vault_state.vault_config @ VaultError::InvalidDepositCredit,
        constraint = deposit_credit.client == client_vault_state.client @ VaultError::InvalidDepositCredit,
        constraint = deposit_credit.status == DEPOSIT_CREDIT_STATUS_PENDING @ VaultError::InvalidDepositCredit,
    )]
    pub deposit_credit: Box<Account<'info, DepositCredit>>,
}

#[init_computation_definition_accounts("apply_deposit", payer)]
#[derive(Accounts)]
pub struct ApplyDepositCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by the Arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: checked by the Arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: address lookup table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[queue_computation_accounts("settle_yield", client)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct SettleYield<'info> {
    #[account(mut)]
    pub client: Signer<'info>,

    pub vault_config: Box<Account<'info, VaultConfig>>,

    #[account(
        constraint = arcium_config.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
    )]
    pub arcium_config: Box<Account<'info, ArciumConfig>>,

    #[account(
        mut,
        constraint = client_vault_state.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
        constraint = client_vault_state.client == client.key() @ VaultError::Unauthorized,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_IDLE @ VaultError::ArciumStatePending,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        init_if_needed,
        space = 9,
        payer = client,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_SETTLE_YIELD))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("settle_yield")]
#[derive(Accounts)]
pub struct SettleYieldCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_SETTLE_YIELD))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by Arcium callback constraints.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by account constraint.
    pub instructions_sysvar: AccountInfo<'info>,

    #[account(
        mut,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_PENDING @ VaultError::InvalidArciumCallback,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,
}

#[init_computation_definition_accounts("settle_yield", payer)]
#[derive(Accounts)]
pub struct SettleYieldCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by the Arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: checked by the Arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: address lookup table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[queue_computation_accounts("owner_view", client)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct OwnerView<'info> {
    #[account(mut)]
    pub client: Signer<'info>,

    pub vault_config: Box<Account<'info, VaultConfig>>,

    #[account(
        constraint = arcium_config.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
    )]
    pub arcium_config: Box<Account<'info, ArciumConfig>>,

    #[account(
        mut,
        constraint = client_vault_state.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
        constraint = client_vault_state.client == client.key() @ VaultError::Unauthorized,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_IDLE @ VaultError::ArciumStatePending,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        init_if_needed,
        space = 9,
        payer = client,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_OWNER_VIEW))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("owner_view")]
#[derive(Accounts)]
pub struct OwnerViewCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_OWNER_VIEW))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by Arcium callback constraints.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by account constraint.
    pub instructions_sysvar: AccountInfo<'info>,

    #[account(
        mut,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_PENDING @ VaultError::InvalidArciumCallback,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,
}

#[init_computation_definition_accounts("owner_view", payer)]
#[derive(Accounts)]
pub struct OwnerViewCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by the Arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: checked by the Arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: address lookup table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[queue_computation_accounts("authorize_budget", client)]
#[derive(Accounts)]
#[instruction(computation_offset: u64, budget_id: u64)]
pub struct AuthorizeBudget<'info> {
    #[account(mut)]
    pub client: Signer<'info>,

    #[account(
        constraint = vault_config.status == VAULT_STATUS_ACTIVE @ VaultError::VaultInactive,
    )]
    pub vault_config: Box<Account<'info, VaultConfig>>,

    #[account(
        constraint = arcium_config.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
    )]
    pub arcium_config: Box<Account<'info, ArciumConfig>>,

    #[account(
        mut,
        constraint = client_vault_state.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
        constraint = client_vault_state.client == client.key() @ VaultError::Unauthorized,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_IDLE @ VaultError::ArciumStatePending,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        init,
        payer = client,
        space = BudgetGrant::LEN,
        seeds = [
            b"budget_grant",
            client_vault_state.key().as_ref(),
            &budget_id.to_le_bytes(),
        ],
        bump,
    )]
    pub budget_grant: Box<Account<'info, BudgetGrant>>,

    #[account(
        init_if_needed,
        space = 9,
        payer = client,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_AUTHORIZE_BUDGET))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("authorize_budget")]
#[derive(Accounts)]
pub struct AuthorizeBudgetCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_AUTHORIZE_BUDGET))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by Arcium callback constraints.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by account constraint.
    pub instructions_sysvar: AccountInfo<'info>,

    #[account(
        mut,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_PENDING @ VaultError::InvalidArciumCallback,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        mut,
        constraint = budget_grant.client_vault_state == client_vault_state.key() @ VaultError::InvalidBudgetGrant,
        constraint = budget_grant.client == client_vault_state.client @ VaultError::InvalidBudgetGrant,
        constraint = budget_grant.status == BUDGET_GRANT_STATUS_PENDING @ VaultError::InvalidBudgetGrant,
    )]
    pub budget_grant: Box<Account<'info, BudgetGrant>>,
}

#[init_computation_definition_accounts("authorize_budget", payer)]
#[derive(Accounts)]
pub struct AuthorizeBudgetCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by the Arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: checked by the Arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: address lookup table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[queue_computation_accounts("reconcile_budget", vault_signer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct ReconcileBudget<'info> {
    #[account(mut)]
    pub vault_signer: Signer<'info>,

    #[account(
        constraint = vault_config.vault_signer_pubkey == vault_signer.key() @ VaultError::InvalidVaultSigner,
        constraint = vault_config.status == VAULT_STATUS_ACTIVE
            || vault_config.status == VAULT_STATUS_MIGRATING
            || vault_config.status == VAULT_STATUS_PAUSED
            @ VaultError::VaultInactive,
    )]
    pub vault_config: Box<Account<'info, VaultConfig>>,

    #[account(
        constraint = arcium_config.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
    )]
    pub arcium_config: Box<Account<'info, ArciumConfig>>,

    #[account(
        mut,
        constraint = client_vault_state.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_IDLE @ VaultError::ArciumStatePending,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        mut,
        constraint = budget_grant.vault_config == vault_config.key() @ VaultError::InvalidBudgetGrant,
        constraint = budget_grant.client_vault_state == client_vault_state.key() @ VaultError::InvalidBudgetGrant,
        constraint = budget_grant.client == client_vault_state.client @ VaultError::InvalidBudgetGrant,
        constraint = budget_grant.status == BUDGET_GRANT_STATUS_READY @ VaultError::InvalidBudgetGrant,
    )]
    pub budget_grant: Box<Account<'info, BudgetGrant>>,

    #[account(
        init_if_needed,
        space = 9,
        payer = vault_signer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_RECONCILE_BUDGET))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("reconcile_budget")]
#[derive(Accounts)]
pub struct ReconcileBudgetCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_RECONCILE_BUDGET))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by Arcium callback constraints.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by account constraint.
    pub instructions_sysvar: AccountInfo<'info>,

    #[account(
        mut,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_PENDING @ VaultError::InvalidArciumCallback,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        mut,
        constraint = budget_grant.client_vault_state == client_vault_state.key() @ VaultError::InvalidBudgetGrant,
        constraint = budget_grant.client == client_vault_state.client @ VaultError::InvalidBudgetGrant,
        constraint = budget_grant.status == BUDGET_GRANT_STATUS_RECONCILING @ VaultError::InvalidBudgetGrant,
    )]
    pub budget_grant: Box<Account<'info, BudgetGrant>>,
}

#[init_computation_definition_accounts("reconcile_budget", payer)]
#[derive(Accounts)]
pub struct ReconcileBudgetCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by the Arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: checked by the Arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: address lookup table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[queue_computation_accounts("authorize_withdrawal", client)]
#[derive(Accounts)]
#[instruction(computation_offset: u64, withdrawal_id: u64)]
pub struct AuthorizeWithdrawal<'info> {
    #[account(mut)]
    pub client: Signer<'info>,

    #[account(
        constraint = vault_config.status == VAULT_STATUS_ACTIVE
            || vault_config.status == VAULT_STATUS_MIGRATING
            || vault_config.status == VAULT_STATUS_PAUSED
            @ VaultError::VaultInactive,
    )]
    pub vault_config: Box<Account<'info, VaultConfig>>,

    #[account(
        constraint = arcium_config.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
    )]
    pub arcium_config: Box<Account<'info, ArciumConfig>>,

    #[account(
        mut,
        constraint = client_vault_state.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
        constraint = client_vault_state.client == client.key() @ VaultError::Unauthorized,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_IDLE @ VaultError::ArciumStatePending,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        init,
        payer = client,
        space = WithdrawalGrant::LEN,
        seeds = [
            b"withdrawal_grant",
            client_vault_state.key().as_ref(),
            &withdrawal_id.to_le_bytes(),
        ],
        bump,
    )]
    pub withdrawal_grant: Box<Account<'info, WithdrawalGrant>>,

    #[account(
        init_if_needed,
        space = 9,
        payer = client,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_AUTHORIZE_WITHDRAWAL))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("authorize_withdrawal")]
#[derive(Accounts)]
pub struct AuthorizeWithdrawalCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_AUTHORIZE_WITHDRAWAL))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by Arcium callback constraints.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by account constraint.
    pub instructions_sysvar: AccountInfo<'info>,

    #[account(
        mut,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_PENDING @ VaultError::InvalidArciumCallback,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        mut,
        constraint = withdrawal_grant.client_vault_state == client_vault_state.key() @ VaultError::InvalidWithdrawalGrant,
        constraint = withdrawal_grant.client == client_vault_state.client @ VaultError::InvalidWithdrawalGrant,
        constraint = withdrawal_grant.status == WITHDRAWAL_GRANT_STATUS_PENDING @ VaultError::InvalidWithdrawalGrant,
    )]
    pub withdrawal_grant: Box<Account<'info, WithdrawalGrant>>,
}

#[init_computation_definition_accounts("authorize_withdrawal", payer)]
#[derive(Accounts)]
pub struct AuthorizeWithdrawalCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by the Arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: checked by the Arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: address lookup table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[queue_computation_accounts("reconcile_withdrawal", vault_signer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct ReconcileWithdrawal<'info> {
    #[account(mut)]
    pub vault_signer: Signer<'info>,

    #[account(
        constraint = vault_config.vault_signer_pubkey == vault_signer.key() @ VaultError::InvalidVaultSigner,
        constraint = vault_config.status == VAULT_STATUS_ACTIVE
            || vault_config.status == VAULT_STATUS_MIGRATING
            || vault_config.status == VAULT_STATUS_PAUSED
            @ VaultError::VaultInactive,
    )]
    pub vault_config: Box<Account<'info, VaultConfig>>,

    #[account(
        constraint = arcium_config.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
    )]
    pub arcium_config: Box<Account<'info, ArciumConfig>>,

    #[account(
        mut,
        constraint = client_vault_state.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_IDLE @ VaultError::ArciumStatePending,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        mut,
        constraint = withdrawal_grant.vault_config == vault_config.key() @ VaultError::InvalidWithdrawalGrant,
        constraint = withdrawal_grant.client_vault_state == client_vault_state.key() @ VaultError::InvalidWithdrawalGrant,
        constraint = withdrawal_grant.client == client_vault_state.client @ VaultError::InvalidWithdrawalGrant,
        constraint = withdrawal_grant.status == WITHDRAWAL_GRANT_STATUS_READY @ VaultError::InvalidWithdrawalGrant,
    )]
    pub withdrawal_grant: Box<Account<'info, WithdrawalGrant>>,

    #[account(
        init_if_needed,
        space = 9,
        payer = vault_signer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_RECONCILE_WITHDRAWAL))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("reconcile_withdrawal")]
#[derive(Accounts)]
pub struct ReconcileWithdrawalCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_RECONCILE_WITHDRAWAL))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by Arcium callback constraints.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by account constraint.
    pub instructions_sysvar: AccountInfo<'info>,

    #[account(
        mut,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_PENDING @ VaultError::InvalidArciumCallback,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        mut,
        constraint = withdrawal_grant.client_vault_state == client_vault_state.key() @ VaultError::InvalidWithdrawalGrant,
        constraint = withdrawal_grant.client == client_vault_state.client @ VaultError::InvalidWithdrawalGrant,
        constraint = withdrawal_grant.status == WITHDRAWAL_GRANT_STATUS_RECONCILING @ VaultError::InvalidWithdrawalGrant,
    )]
    pub withdrawal_grant: Box<Account<'info, WithdrawalGrant>>,
}

#[init_computation_definition_accounts("reconcile_withdrawal", payer)]
#[derive(Accounts)]
pub struct ReconcileWithdrawalCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by the Arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: checked by the Arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: address lookup table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[queue_computation_accounts("prepare_recovery_claim", client)]
#[derive(Accounts)]
#[instruction(computation_offset: u64, recovery_nonce: u64)]
pub struct PrepareRecoveryClaim<'info> {
    #[account(mut)]
    pub client: Signer<'info>,

    pub vault_config: Box<Account<'info, VaultConfig>>,

    #[account(
        constraint = arcium_config.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
    )]
    pub arcium_config: Box<Account<'info, ArciumConfig>>,

    #[account(
        mut,
        constraint = client_vault_state.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
        constraint = client_vault_state.client == client.key() @ VaultError::Unauthorized,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_IDLE @ VaultError::ArciumStatePending,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        init,
        payer = client,
        space = RecoveryClaim::LEN,
        seeds = [
            b"recovery_claim",
            client_vault_state.key().as_ref(),
            &recovery_nonce.to_le_bytes(),
        ],
        bump,
    )]
    pub recovery_claim: Box<Account<'info, RecoveryClaim>>,

    #[account(
        init_if_needed,
        space = 9,
        payer = client,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, VaultError::ClusterNotSet))]
    /// CHECK: checked by the Arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_PREPARE_RECOVERY_CLAIM))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("prepare_recovery_claim")]
#[derive(Accounts)]
pub struct PrepareRecoveryClaimCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_PREPARE_RECOVERY_CLAIM))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: checked by Arcium callback constraints.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, VaultError::ClusterNotSet))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by account constraint.
    pub instructions_sysvar: AccountInfo<'info>,

    #[account(
        mut,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_PENDING @ VaultError::InvalidArciumCallback,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        mut,
        constraint = recovery_claim.client_vault_state == client_vault_state.key() @ VaultError::InvalidRecoveryClaim,
        constraint = recovery_claim.client == client_vault_state.client @ VaultError::InvalidRecoveryClaim,
        constraint = recovery_claim.status == RECOVERY_CLAIM_STATUS_PENDING @ VaultError::InvalidRecoveryClaim,
    )]
    pub recovery_claim: Box<Account<'info, RecoveryClaim>>,
}

#[init_computation_definition_accounts("prepare_recovery_claim", payer)]
#[derive(Accounts)]
pub struct PrepareRecoveryClaimCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by the Arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: checked by the Arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: address lookup table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ArciumForceSettleFinalize<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,

    pub vault_config: Box<Account<'info, VaultConfig>>,

    #[account(
        mut,
        constraint = recovery_claim.vault_config == vault_config.key() @ VaultError::InvalidRecoveryClaim,
        constraint = recovery_claim.status == RECOVERY_CLAIM_STATUS_READY @ VaultError::InvalidRecoveryClaim,
    )]
    pub recovery_claim: Box<Account<'info, RecoveryClaim>>,

    #[account(mut, address = vault_config.vault_token_account)]
    pub vault_token_account: Box<Account<'info, TokenAccount>>,

    #[account(mut, address = recovery_claim.recipient_ata)]
    pub recipient_token_account: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CancelPendingArcium<'info> {
    pub authority: Signer<'info>,

    pub vault_config: Box<Account<'info, VaultConfig>>,

    #[account(
        mut,
        constraint = client_vault_state.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_PENDING @ VaultError::InvalidArciumCallback,
        constraint = authority.key() == vault_config.governance @ VaultError::Unauthorized,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,
}

#[derive(Accounts)]
pub struct CancelPendingBudget<'info> {
    pub authority: Signer<'info>,

    pub vault_config: Box<Account<'info, VaultConfig>>,

    #[account(
        mut,
        constraint = client_vault_state.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
        constraint = client_vault_state.status == CLIENT_VAULT_STATUS_PENDING @ VaultError::InvalidArciumCallback,
    )]
    pub client_vault_state: Box<Account<'info, ClientVaultState>>,

    #[account(
        mut,
        constraint = budget_grant.vault_config == vault_config.key() @ VaultError::InvalidBudgetGrant,
        constraint = budget_grant.client_vault_state == client_vault_state.key() @ VaultError::InvalidBudgetGrant,
        constraint = budget_grant.client == client_vault_state.client @ VaultError::InvalidBudgetGrant,
        constraint = budget_grant.status == BUDGET_GRANT_STATUS_PENDING
            || budget_grant.status == BUDGET_GRANT_STATUS_RECONCILING
            @ VaultError::InvalidBudgetGrant,
        constraint = authority.key() == client_vault_state.client
            || authority.key() == vault_config.vault_signer_pubkey
            || authority.key() == vault_config.governance
            @ VaultError::Unauthorized,
    )]
    pub budget_grant: Box<Account<'info, BudgetGrant>>,
}

pub fn init_init_agent_vault_comp_def_handler(ctx: Context<InitAgentVaultCompDef>) -> Result<()> {
    init_comp_def(ctx.accounts, None, None)
}

pub fn init_apply_deposit_comp_def_handler(ctx: Context<ApplyDepositCompDef>) -> Result<()> {
    init_comp_def(ctx.accounts, None, None)
}

pub fn init_settle_yield_comp_def_handler(ctx: Context<SettleYieldCompDef>) -> Result<()> {
    init_comp_def(ctx.accounts, None, None)
}

pub fn init_owner_view_comp_def_handler(ctx: Context<OwnerViewCompDef>) -> Result<()> {
    init_comp_def(ctx.accounts, None, None)
}

pub fn init_authorize_budget_comp_def_handler(ctx: Context<AuthorizeBudgetCompDef>) -> Result<()> {
    init_comp_def(ctx.accounts, None, None)
}

pub fn init_reconcile_budget_comp_def_handler(ctx: Context<ReconcileBudgetCompDef>) -> Result<()> {
    init_comp_def(ctx.accounts, None, None)
}

pub fn init_authorize_withdrawal_comp_def_handler(
    ctx: Context<AuthorizeWithdrawalCompDef>,
) -> Result<()> {
    init_comp_def(ctx.accounts, None, None)
}

pub fn init_reconcile_withdrawal_comp_def_handler(
    ctx: Context<ReconcileWithdrawalCompDef>,
) -> Result<()> {
    init_comp_def(ctx.accounts, None, None)
}

pub fn init_prepare_recovery_claim_comp_def_handler(
    ctx: Context<PrepareRecoveryClaimCompDef>,
) -> Result<()> {
    init_comp_def(ctx.accounts, None, None)
}

pub fn cancel_pending_arcium_handler(ctx: Context<CancelPendingArcium>) -> Result<()> {
    require_pending_timeout(&ctx.accounts.client_vault_state)?;
    ctx.accounts.client_vault_state.pending_offset = 0;
    ctx.accounts.client_vault_state.pending_started_at = 0;
    ctx.accounts.client_vault_state.status = CLIENT_VAULT_STATUS_IDLE;
    Ok(())
}

pub fn cancel_pending_budget_handler(ctx: Context<CancelPendingBudget>) -> Result<()> {
    require_pending_timeout(&ctx.accounts.client_vault_state)?;
    ctx.accounts.client_vault_state.pending_offset = 0;
    ctx.accounts.client_vault_state.pending_started_at = 0;
    ctx.accounts.client_vault_state.status = CLIENT_VAULT_STATUS_IDLE;

    let budget_grant = &mut ctx.accounts.budget_grant;
    budget_grant.status = if budget_grant.status == BUDGET_GRANT_STATUS_RECONCILING {
        BUDGET_GRANT_STATUS_READY
    } else {
        BUDGET_GRANT_STATUS_CANCELLED
    };

    Ok(())
}

pub fn init_agent_vault_handler(
    ctx: Context<InitAgentVault>,
    computation_offset: u64,
) -> Result<()> {
    require!(
        ctx.accounts.arcium_config.writes_enabled(),
        VaultError::InvalidArciumStatus
    );
    require!(
        ctx.accounts.arcium_program.key() == ctx.accounts.arcium_config.arcium_program_id,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mxe_account.key() == ctx.accounts.arcium_config.mxe_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.cluster_account.key() == ctx.accounts.arcium_config.cluster_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mempool_account.key() == ctx.accounts.arcium_config.mempool_account,
        VaultError::InvalidArciumConfig
    );

    let client_vault_state = &mut ctx.accounts.client_vault_state;
    client_vault_state.bump = ctx.bumps.client_vault_state;
    client_vault_state.vault_config = ctx.accounts.vault_config.key();
    client_vault_state.client = ctx.accounts.client.key();
    client_vault_state.status = CLIENT_VAULT_STATUS_PENDING;
    client_vault_state.state_version = 0;
    client_vault_state.pending_offset = computation_offset;
    client_vault_state.pending_started_at = Clock::get()?.unix_timestamp;
    client_vault_state.agent_vault_ciphertexts = [[0u8; 32]; AGENT_VAULT_SCALARS];
    client_vault_state.agent_vault_nonce = [0u8; 16];

    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
    let args = ArgBuilder::new()
        .plaintext_u128(ctx.accounts.arcium_config.current_yield_index_q64)
        .build();

    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![InitAgentVaultCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[CallbackAccount {
                pubkey: ctx.accounts.client_vault_state.key(),
                is_writable: true,
            }],
        )?],
        1,
        0,
    )
}

pub fn apply_deposit_handler(ctx: Context<ApplyDeposit>, computation_offset: u64) -> Result<()> {
    require!(
        ctx.accounts.arcium_config.writes_enabled(),
        VaultError::InvalidArciumStatus
    );
    require!(
        ctx.accounts.arcium_program.key() == ctx.accounts.arcium_config.arcium_program_id,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mxe_account.key() == ctx.accounts.arcium_config.mxe_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.cluster_account.key() == ctx.accounts.arcium_config.cluster_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mempool_account.key() == ctx.accounts.arcium_config.mempool_account,
        VaultError::InvalidArciumConfig
    );

    ctx.accounts.client_vault_state.status = CLIENT_VAULT_STATUS_PENDING;
    ctx.accounts.client_vault_state.pending_offset = computation_offset;
    ctx.accounts.client_vault_state.pending_started_at = Clock::get()?.unix_timestamp;

    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
    let args = append_agent_vault_arg(ArgBuilder::new(), &ctx.accounts.client_vault_state)
        .plaintext_u64(ctx.accounts.deposit_credit.amount)
        .plaintext_u128(ctx.accounts.arcium_config.current_yield_index_q64)
        .build();

    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![ApplyDepositCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[
                CallbackAccount {
                    pubkey: ctx.accounts.client_vault_state.key(),
                    is_writable: true,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.deposit_credit.key(),
                    is_writable: true,
                },
            ],
        )?],
        1,
        0,
    )
}

pub fn settle_yield_handler(ctx: Context<SettleYield>, computation_offset: u64) -> Result<()> {
    require!(
        ctx.accounts.arcium_config.writes_enabled(),
        VaultError::InvalidArciumStatus
    );
    require!(
        ctx.accounts.arcium_program.key() == ctx.accounts.arcium_config.arcium_program_id,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mxe_account.key() == ctx.accounts.arcium_config.mxe_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.cluster_account.key() == ctx.accounts.arcium_config.cluster_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mempool_account.key() == ctx.accounts.arcium_config.mempool_account,
        VaultError::InvalidArciumConfig
    );

    ctx.accounts.client_vault_state.status = CLIENT_VAULT_STATUS_PENDING;
    ctx.accounts.client_vault_state.pending_offset = computation_offset;
    ctx.accounts.client_vault_state.pending_started_at = Clock::get()?.unix_timestamp;

    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
    let args = append_agent_vault_arg(ArgBuilder::new(), &ctx.accounts.client_vault_state)
        .plaintext_u128(ctx.accounts.arcium_config.current_yield_index_q64)
        .build();

    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![SettleYieldCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[CallbackAccount {
                pubkey: ctx.accounts.client_vault_state.key(),
                is_writable: true,
            }],
        )?],
        1,
        0,
    )
}

pub fn owner_view_handler(
    ctx: Context<OwnerView>,
    computation_offset: u64,
    owner_x25519_pubkey: [u8; 32],
) -> Result<()> {
    require!(
        ctx.accounts.arcium_config.writes_enabled(),
        VaultError::InvalidArciumStatus
    );
    require!(
        ctx.accounts.arcium_program.key() == ctx.accounts.arcium_config.arcium_program_id,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mxe_account.key() == ctx.accounts.arcium_config.mxe_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.cluster_account.key() == ctx.accounts.arcium_config.cluster_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mempool_account.key() == ctx.accounts.arcium_config.mempool_account,
        VaultError::InvalidArciumConfig
    );

    ctx.accounts.client_vault_state.status = CLIENT_VAULT_STATUS_PENDING;
    ctx.accounts.client_vault_state.pending_offset = computation_offset;
    ctx.accounts.client_vault_state.pending_started_at = Clock::get()?.unix_timestamp;
    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
    let args = append_agent_vault_arg(ArgBuilder::new(), &ctx.accounts.client_vault_state)
        .x25519_pubkey(owner_x25519_pubkey)
        .plaintext_u128(ctx.accounts.arcium_config.current_yield_index_q64)
        .build();

    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![OwnerViewCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[CallbackAccount {
                pubkey: ctx.accounts.client_vault_state.key(),
                is_writable: true,
            }],
        )?],
        1,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn authorize_budget_handler(
    ctx: Context<AuthorizeBudget>,
    computation_offset: u64,
    budget_id: u64,
    request_nonce: u64,
    expires_at: i64,
    request_x25519_pubkey: [u8; 32],
    request_ciphertexts: [[u8; 32]; BUDGET_REQUEST_SCALARS],
    request_ciphertext_nonce: [u8; 16],
) -> Result<()> {
    require!(
        ctx.accounts.arcium_config.writes_enabled(),
        VaultError::InvalidArciumStatus
    );
    require!(expires_at > 0, VaultError::InvalidBudgetGrant);
    let clock = Clock::get()?;
    require!(
        expires_at > clock.unix_timestamp,
        VaultError::InvalidBudgetGrant
    );
    require!(
        ctx.accounts.arcium_program.key() == ctx.accounts.arcium_config.arcium_program_id,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mxe_account.key() == ctx.accounts.arcium_config.mxe_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.cluster_account.key() == ctx.accounts.arcium_config.cluster_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mempool_account.key() == ctx.accounts.arcium_config.mempool_account,
        VaultError::InvalidArciumConfig
    );

    let authorization_state_version = ctx
        .accounts
        .client_vault_state
        .state_version
        .checked_add(1)
        .ok_or(VaultError::ArithmeticOverflow)?;
    let expires_at_u64 = expires_at as u64;
    let (expected_domain_hash_lo, expected_domain_hash_hi) =
        split_domain_hash(compute_arcium_domain_hash(
            b"authorize_budget",
            ctx.accounts.vault_config.key(),
            &ctx.accounts.vault_config,
            &ctx.accounts.arcium_config,
        ));

    ctx.accounts.client_vault_state.status = CLIENT_VAULT_STATUS_PENDING;
    ctx.accounts.client_vault_state.pending_offset = computation_offset;
    ctx.accounts.client_vault_state.pending_started_at = clock.unix_timestamp;

    let budget_grant = &mut ctx.accounts.budget_grant;
    budget_grant.bump = ctx.bumps.budget_grant;
    budget_grant.vault_config = ctx.accounts.vault_config.key();
    budget_grant.client_vault_state = ctx.accounts.client_vault_state.key();
    budget_grant.client = ctx.accounts.client.key();
    budget_grant.budget_id = budget_id;
    budget_grant.request_nonce = request_nonce;
    budget_grant.status = BUDGET_GRANT_STATUS_PENDING;
    budget_grant.created_at = clock.unix_timestamp;
    budget_grant.expires_at = expires_at;
    budget_grant.state_version_at_authorization = 0;
    budget_grant.grant_state_ciphertexts = [[0u8; 32]; BUDGET_GRANT_STATE_SCALARS];
    budget_grant.grant_state_nonce = [0u8; 16];
    budget_grant.grant_ciphertexts = [[0u8; 32]; BUDGET_GRANT_SCALARS];
    budget_grant.grant_nonce = [0u8; 16];

    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
    let (vault_config_lo, vault_config_hi) = split_pubkey(ctx.accounts.vault_config.key());
    let (client_lo, client_hi) = split_pubkey(ctx.accounts.client.key());
    let (budget_grant_lo, budget_grant_hi) = split_pubkey(ctx.accounts.budget_grant.key());
    let args = append_budget_request_arg(
        append_agent_vault_arg(ArgBuilder::new(), &ctx.accounts.client_vault_state),
        request_x25519_pubkey,
        request_ciphertext_nonce,
        request_ciphertexts,
    )
    .x25519_pubkey(ctx.accounts.arcium_config.tee_x25519_pubkey)
    .plaintext_u128(ctx.accounts.arcium_config.current_yield_index_q64)
    .plaintext_u128(expected_domain_hash_lo)
    .plaintext_u128(expected_domain_hash_hi)
    .plaintext_u64(budget_id)
    .plaintext_u64(request_nonce)
    .plaintext_u64(expires_at_u64)
    .plaintext_u64(authorization_state_version)
    .plaintext_u128(vault_config_lo)
    .plaintext_u128(vault_config_hi)
    .plaintext_u128(client_lo)
    .plaintext_u128(client_hi)
    .plaintext_u128(budget_grant_lo)
    .plaintext_u128(budget_grant_hi)
    .build();

    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![AuthorizeBudgetCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[
                CallbackAccount {
                    pubkey: ctx.accounts.client_vault_state.key(),
                    is_writable: true,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.budget_grant.key(),
                    is_writable: true,
                },
            ],
        )?],
        1,
        0,
    )
}

pub fn reconcile_budget_handler(
    ctx: Context<ReconcileBudget>,
    computation_offset: u64,
    report_ciphertexts: [[u8; 32]; RECONCILE_REPORT_SCALARS],
    report_ciphertext_nonce: [u8; 16],
) -> Result<()> {
    require!(
        ctx.accounts.arcium_config.writes_enabled(),
        VaultError::InvalidArciumStatus
    );
    require!(
        ctx.accounts.arcium_program.key() == ctx.accounts.arcium_config.arcium_program_id,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mxe_account.key() == ctx.accounts.arcium_config.mxe_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.cluster_account.key() == ctx.accounts.arcium_config.cluster_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mempool_account.key() == ctx.accounts.arcium_config.mempool_account,
        VaultError::InvalidArciumConfig
    );

    let (expected_domain_hash_lo, expected_domain_hash_hi) =
        split_domain_hash(compute_arcium_domain_hash(
            b"reconcile_budget",
            ctx.accounts.vault_config.key(),
            &ctx.accounts.vault_config,
            &ctx.accounts.arcium_config,
        ));
    ctx.accounts.client_vault_state.status = CLIENT_VAULT_STATUS_PENDING;
    ctx.accounts.client_vault_state.pending_offset = computation_offset;
    ctx.accounts.client_vault_state.pending_started_at = Clock::get()?.unix_timestamp;
    ctx.accounts.budget_grant.status = BUDGET_GRANT_STATUS_RECONCILING;

    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
    let args = append_reconcile_report_arg(
        append_budget_grant_state_arg(
            append_agent_vault_arg(ArgBuilder::new(), &ctx.accounts.client_vault_state),
            &ctx.accounts.budget_grant,
        ),
        ctx.accounts.arcium_config.tee_x25519_pubkey,
        report_ciphertext_nonce,
        report_ciphertexts,
    )
    .plaintext_u128(expected_domain_hash_lo)
    .plaintext_u128(expected_domain_hash_hi)
    .plaintext_u64(ctx.accounts.budget_grant.budget_id)
    .plaintext_u64(ctx.accounts.budget_grant.request_nonce)
    .build();

    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![ReconcileBudgetCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[
                CallbackAccount {
                    pubkey: ctx.accounts.client_vault_state.key(),
                    is_writable: true,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.budget_grant.key(),
                    is_writable: true,
                },
            ],
        )?],
        1,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn authorize_withdrawal_handler(
    ctx: Context<AuthorizeWithdrawal>,
    computation_offset: u64,
    withdrawal_id: u64,
    expires_at: i64,
    recipient_ata: Pubkey,
    request_x25519_pubkey: [u8; 32],
    request_ciphertexts: [[u8; 32]; WITHDRAWAL_REQUEST_SCALARS],
    request_ciphertext_nonce: [u8; 16],
) -> Result<()> {
    require!(
        ctx.accounts.arcium_config.writes_enabled(),
        VaultError::InvalidArciumStatus
    );
    require!(expires_at > 0, VaultError::InvalidWithdrawalGrant);
    let clock = Clock::get()?;
    require!(
        expires_at > clock.unix_timestamp,
        VaultError::InvalidWithdrawalGrant
    );
    require!(
        ctx.accounts.arcium_program.key() == ctx.accounts.arcium_config.arcium_program_id,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mxe_account.key() == ctx.accounts.arcium_config.mxe_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.cluster_account.key() == ctx.accounts.arcium_config.cluster_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mempool_account.key() == ctx.accounts.arcium_config.mempool_account,
        VaultError::InvalidArciumConfig
    );

    let authorization_state_version = ctx
        .accounts
        .client_vault_state
        .state_version
        .checked_add(1)
        .ok_or(VaultError::ArithmeticOverflow)?;
    let expires_at_u64 = expires_at as u64;
    let (expected_domain_hash_lo, expected_domain_hash_hi) =
        split_domain_hash(compute_arcium_domain_hash(
            b"authorize_withdrawal",
            ctx.accounts.vault_config.key(),
            &ctx.accounts.vault_config,
            &ctx.accounts.arcium_config,
        ));
    let (vault_config_lo, vault_config_hi) = split_pubkey(ctx.accounts.vault_config.key());
    let (client_lo, client_hi) = split_pubkey(ctx.accounts.client.key());
    let (withdrawal_grant_lo, withdrawal_grant_hi) =
        split_pubkey(ctx.accounts.withdrawal_grant.key());
    let (recipient_lo, recipient_hi) = split_pubkey(recipient_ata);

    ctx.accounts.client_vault_state.status = CLIENT_VAULT_STATUS_PENDING;
    ctx.accounts.client_vault_state.pending_offset = computation_offset;
    ctx.accounts.client_vault_state.pending_started_at = clock.unix_timestamp;

    let withdrawal_grant = &mut ctx.accounts.withdrawal_grant;
    withdrawal_grant.bump = ctx.bumps.withdrawal_grant;
    withdrawal_grant.vault_config = ctx.accounts.vault_config.key();
    withdrawal_grant.client_vault_state = ctx.accounts.client_vault_state.key();
    withdrawal_grant.client = ctx.accounts.client.key();
    withdrawal_grant.withdrawal_id = withdrawal_id;
    withdrawal_grant.status = WITHDRAWAL_GRANT_STATUS_PENDING;
    withdrawal_grant.recipient_ata = recipient_ata;
    withdrawal_grant.expires_at = expires_at;
    withdrawal_grant.state_version_at_authorization = authorization_state_version;
    withdrawal_grant.grant_state_ciphertexts = [[0u8; 32]; WITHDRAWAL_GRANT_STATE_SCALARS];
    withdrawal_grant.grant_state_nonce = [0u8; 16];
    withdrawal_grant.grant_ciphertexts = [[0u8; 32]; WITHDRAWAL_GRANT_SCALARS];
    withdrawal_grant.grant_nonce = [0u8; 16];

    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
    let args = append_withdrawal_request_arg(
        append_agent_vault_arg(ArgBuilder::new(), &ctx.accounts.client_vault_state),
        request_x25519_pubkey,
        request_ciphertext_nonce,
        request_ciphertexts,
    )
    .x25519_pubkey(ctx.accounts.arcium_config.tee_x25519_pubkey)
    .plaintext_u128(ctx.accounts.arcium_config.current_yield_index_q64)
    .plaintext_u128(expected_domain_hash_lo)
    .plaintext_u128(expected_domain_hash_hi)
    .plaintext_u64(withdrawal_id)
    .plaintext_u64(expires_at_u64)
    .plaintext_u64(authorization_state_version)
    .plaintext_u128(vault_config_lo)
    .plaintext_u128(vault_config_hi)
    .plaintext_u128(client_lo)
    .plaintext_u128(client_hi)
    .plaintext_u128(withdrawal_grant_lo)
    .plaintext_u128(withdrawal_grant_hi)
    .plaintext_u128(recipient_lo)
    .plaintext_u128(recipient_hi)
    .build();

    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![AuthorizeWithdrawalCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[
                CallbackAccount {
                    pubkey: ctx.accounts.client_vault_state.key(),
                    is_writable: true,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.withdrawal_grant.key(),
                    is_writable: true,
                },
            ],
        )?],
        1,
        0,
    )
}

pub fn reconcile_withdrawal_handler(
    ctx: Context<ReconcileWithdrawal>,
    computation_offset: u64,
    report_ciphertexts: [[u8; 32]; WITHDRAWAL_REPORT_SCALARS],
    report_ciphertext_nonce: [u8; 16],
) -> Result<()> {
    require!(
        ctx.accounts.arcium_config.writes_enabled(),
        VaultError::InvalidArciumStatus
    );
    require!(
        ctx.accounts.arcium_program.key() == ctx.accounts.arcium_config.arcium_program_id,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mxe_account.key() == ctx.accounts.arcium_config.mxe_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.cluster_account.key() == ctx.accounts.arcium_config.cluster_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mempool_account.key() == ctx.accounts.arcium_config.mempool_account,
        VaultError::InvalidArciumConfig
    );

    let (expected_domain_hash_lo, expected_domain_hash_hi) =
        split_domain_hash(compute_arcium_domain_hash(
            b"reconcile_withdrawal",
            ctx.accounts.vault_config.key(),
            &ctx.accounts.vault_config,
            &ctx.accounts.arcium_config,
        ));
    ctx.accounts.client_vault_state.status = CLIENT_VAULT_STATUS_PENDING;
    ctx.accounts.client_vault_state.pending_offset = computation_offset;
    ctx.accounts.client_vault_state.pending_started_at = Clock::get()?.unix_timestamp;
    ctx.accounts.withdrawal_grant.status = WITHDRAWAL_GRANT_STATUS_RECONCILING;

    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
    let args = append_withdrawal_report_arg(
        append_withdrawal_grant_state_arg(
            append_agent_vault_arg(ArgBuilder::new(), &ctx.accounts.client_vault_state),
            &ctx.accounts.withdrawal_grant,
        ),
        ctx.accounts.arcium_config.tee_x25519_pubkey,
        report_ciphertext_nonce,
        report_ciphertexts,
    )
    .plaintext_u128(expected_domain_hash_lo)
    .plaintext_u128(expected_domain_hash_hi)
    .plaintext_u64(ctx.accounts.withdrawal_grant.withdrawal_id)
    .build();

    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![ReconcileWithdrawalCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[
                CallbackAccount {
                    pubkey: ctx.accounts.client_vault_state.key(),
                    is_writable: true,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.withdrawal_grant.key(),
                    is_writable: true,
                },
            ],
        )?],
        1,
        0,
    )
}

pub fn prepare_recovery_claim_handler(
    ctx: Context<PrepareRecoveryClaim>,
    computation_offset: u64,
    recovery_nonce: u64,
    recipient_ata: Pubkey,
) -> Result<()> {
    require!(
        ctx.accounts.arcium_config.writes_enabled(),
        VaultError::InvalidArciumStatus
    );
    require!(
        ctx.accounts.arcium_program.key() == ctx.accounts.arcium_config.arcium_program_id,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mxe_account.key() == ctx.accounts.arcium_config.mxe_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.cluster_account.key() == ctx.accounts.arcium_config.cluster_account,
        VaultError::InvalidArciumConfig
    );
    require!(
        ctx.accounts.mempool_account.key() == ctx.accounts.arcium_config.mempool_account,
        VaultError::InvalidArciumConfig
    );

    let clock = Clock::get()?;
    ctx.accounts.client_vault_state.status = CLIENT_VAULT_STATUS_PENDING;
    ctx.accounts.client_vault_state.pending_offset = computation_offset;
    ctx.accounts.client_vault_state.pending_started_at = clock.unix_timestamp;

    let recovery_claim = &mut ctx.accounts.recovery_claim;
    recovery_claim.bump = ctx.bumps.recovery_claim;
    recovery_claim.vault_config = ctx.accounts.vault_config.key();
    recovery_claim.client_vault_state = ctx.accounts.client_vault_state.key();
    recovery_claim.client = ctx.accounts.client.key();
    recovery_claim.recipient_ata = recipient_ata;
    recovery_claim.recovery_nonce = recovery_nonce;
    recovery_claim.status = RECOVERY_CLAIM_STATUS_PENDING;
    recovery_claim.free_balance_due = 0;
    recovery_claim.locked_balance_due = 0;
    recovery_claim.max_lock_expires_at = 0;
    recovery_claim.state_version = ctx.accounts.client_vault_state.state_version;
    recovery_claim.initiated_at = clock.unix_timestamp;
    recovery_claim.dispute_deadline = clock
        .unix_timestamp
        .checked_add(crate::constants::DISPUTE_WINDOW_SEC)
        .ok_or(VaultError::ArithmeticOverflow)?;

    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
    let args = append_agent_vault_arg(ArgBuilder::new(), &ctx.accounts.client_vault_state)
        .plaintext_u128(ctx.accounts.arcium_config.current_yield_index_q64)
        .build();

    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![PrepareRecoveryClaimCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[
                CallbackAccount {
                    pubkey: ctx.accounts.client_vault_state.key(),
                    is_writable: true,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.recovery_claim.key(),
                    is_writable: true,
                },
            ],
        )?],
        1,
        0,
    )
}

pub fn arcium_force_settle_finalize_handler(ctx: Context<ArciumForceSettleFinalize>) -> Result<()> {
    let clock = Clock::get()?;
    require!(
        clock.unix_timestamp > ctx.accounts.recovery_claim.dispute_deadline,
        VaultError::DisputeWindowActive
    );

    let free = ctx.accounts.recovery_claim.free_balance_due;
    let locked = if clock.unix_timestamp >= ctx.accounts.recovery_claim.max_lock_expires_at {
        ctx.accounts.recovery_claim.locked_balance_due
    } else {
        0
    };
    let claimable = free
        .checked_add(locked)
        .ok_or(VaultError::ArithmeticOverflow)?;

    if claimable == 0 {
        if ctx.accounts.recovery_claim.locked_balance_due == 0 {
            ctx.accounts.recovery_claim.status = RECOVERY_CLAIM_STATUS_FINALIZED;
        }
        return Ok(());
    }

    require!(
        ctx.accounts.vault_token_account.amount >= claimable,
        VaultError::VaultInsolvent
    );

    let vault = &ctx.accounts.vault_config;
    let governance_key = vault.governance.key();
    let vault_id_bytes = vault.vault_id.to_le_bytes();
    let bump = &[vault.bump];
    let signer_seeds: &[&[&[u8]]] = &[&[
        b"vault_config",
        governance_key.as_ref(),
        vault_id_bytes.as_ref(),
        bump,
    ]];

    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.vault_token_account.to_account_info(),
                to: ctx.accounts.recipient_token_account.to_account_info(),
                authority: ctx.accounts.vault_config.to_account_info(),
            },
            signer_seeds,
        ),
        claimable,
    )?;

    let recovery_claim = &mut ctx.accounts.recovery_claim;
    recovery_claim.free_balance_due = 0;
    if clock.unix_timestamp >= recovery_claim.max_lock_expires_at {
        recovery_claim.locked_balance_due = 0;
    }
    if recovery_claim.free_balance_due == 0 && recovery_claim.locked_balance_due == 0 {
        recovery_claim.status = RECOVERY_CLAIM_STATUS_FINALIZED;
    }

    Ok(())
}

pub fn init_agent_vault_callback_handler(
    ctx: Context<InitAgentVaultCallback>,
    output: SignedComputationOutputs<InitAgentVaultOutput>,
) -> Result<()> {
    let output = output
        .verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )
        .map_err(|_| VaultError::AbortedComputation)?;

    let pending_offset = ctx.accounts.client_vault_state.pending_offset;
    let expected_computation = derive_comp_pda!(
        pending_offset,
        ctx.accounts.mxe_account,
        VaultError::ClusterNotSet
    );
    write_agent_vault_state(
        ctx.accounts.client_vault_state.as_mut(),
        expected_computation,
        ctx.accounts.computation_account.key(),
        &output.field_0.ciphertexts,
        output.field_0.nonce,
    )
}

pub fn apply_deposit_callback_handler(
    ctx: Context<ApplyDepositCallback>,
    output: SignedComputationOutputs<ApplyDepositOutput>,
) -> Result<()> {
    require!(
        ctx.accounts.deposit_credit.status == DEPOSIT_CREDIT_STATUS_PENDING,
        VaultError::InvalidDepositCredit
    );

    let output = output
        .verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )
        .map_err(|_| VaultError::AbortedComputation)?;

    let pending_offset = ctx.accounts.client_vault_state.pending_offset;
    let expected_computation = derive_comp_pda!(
        pending_offset,
        ctx.accounts.mxe_account,
        VaultError::ClusterNotSet
    );
    if !output.field_0.field_1 {
        clear_pending_state(
            ctx.accounts.client_vault_state.as_mut(),
            expected_computation,
            ctx.accounts.computation_account.key(),
        )?;
        return Ok(());
    }

    write_agent_vault_state(
        ctx.accounts.client_vault_state.as_mut(),
        expected_computation,
        ctx.accounts.computation_account.key(),
        &output.field_0.field_0.ciphertexts,
        output.field_0.field_0.nonce,
    )?;

    let deposit_credit = &mut ctx.accounts.deposit_credit;
    deposit_credit.status = DEPOSIT_CREDIT_STATUS_APPLIED;
    deposit_credit.applied_state_version = ctx.accounts.client_vault_state.state_version;

    Ok(())
}

pub fn settle_yield_callback_handler(
    ctx: Context<SettleYieldCallback>,
    output: SignedComputationOutputs<SettleYieldOutput>,
) -> Result<()> {
    let output = output
        .verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )
        .map_err(|_| VaultError::AbortedComputation)?;

    let pending_offset = ctx.accounts.client_vault_state.pending_offset;
    let expected_computation = derive_comp_pda!(
        pending_offset,
        ctx.accounts.mxe_account,
        VaultError::ClusterNotSet
    );
    if !output.field_0.field_1 {
        clear_pending_state(
            ctx.accounts.client_vault_state.as_mut(),
            expected_computation,
            ctx.accounts.computation_account.key(),
        )?;
        return Ok(());
    }

    write_agent_vault_state(
        ctx.accounts.client_vault_state.as_mut(),
        expected_computation,
        ctx.accounts.computation_account.key(),
        &output.field_0.field_0.ciphertexts,
        output.field_0.field_0.nonce,
    )
}

pub fn owner_view_callback_handler(
    ctx: Context<OwnerViewCallback>,
    output: SignedComputationOutputs<OwnerViewOutput>,
) -> Result<()> {
    let output = output
        .verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )
        .map_err(|_| VaultError::AbortedComputation)?;
    let pending_offset = ctx.accounts.client_vault_state.pending_offset;
    let expected_computation = derive_comp_pda!(
        pending_offset,
        ctx.accounts.mxe_account,
        VaultError::ClusterNotSet
    );
    let state_version = ctx.accounts.client_vault_state.state_version;
    if !output.field_0.field_1 {
        clear_pending_state(
            ctx.accounts.client_vault_state.as_mut(),
            expected_computation,
            ctx.accounts.computation_account.key(),
        )?;
        return Ok(());
    }

    emit!(OwnerViewEvent {
        client: ctx.accounts.client_vault_state.client,
        state_version,
        ciphertexts: output.field_0.field_0.ciphertexts,
        nonce: output.field_0.field_0.nonce.to_le_bytes(),
    });

    clear_pending_state(
        ctx.accounts.client_vault_state.as_mut(),
        expected_computation,
        ctx.accounts.computation_account.key(),
    )?;

    Ok(())
}

pub fn authorize_budget_callback_handler(
    mut ctx: Context<AuthorizeBudgetCallback>,
    output: SignedComputationOutputs<AuthorizeBudgetOutput>,
) -> Result<()> {
    let output = output
        .verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )
        .map_err(|_| VaultError::AbortedComputation)?;

    finish_authorize_budget_callback(&mut ctx, &output)
}

#[inline(never)]
fn finish_authorize_budget_callback(
    ctx: &mut Context<AuthorizeBudgetCallback>,
    output: &AuthorizeBudgetOutput,
) -> Result<()> {
    let pending_offset = ctx.accounts.client_vault_state.pending_offset;
    let expected_computation = derive_comp_pda!(
        pending_offset,
        ctx.accounts.mxe_account,
        VaultError::ClusterNotSet
    );

    if !output.field_0.field_3 {
        clear_pending_state(
            ctx.accounts.client_vault_state.as_mut(),
            expected_computation,
            ctx.accounts.computation_account.key(),
        )?;
        ctx.accounts.budget_grant.status = BUDGET_GRANT_STATUS_CANCELLED;
        return Ok(());
    }

    write_agent_vault_state(
        ctx.accounts.client_vault_state.as_mut(),
        expected_computation,
        ctx.accounts.computation_account.key(),
        &output.field_0.field_0.ciphertexts,
        output.field_0.field_0.nonce,
    )?;

    let budget_grant = &mut ctx.accounts.budget_grant;
    budget_grant.grant_state_ciphertexts = output.field_0.field_1.ciphertexts;
    budget_grant.grant_state_nonce = output.field_0.field_1.nonce.to_le_bytes();
    budget_grant.grant_ciphertexts = output.field_0.field_2.ciphertexts;
    budget_grant.grant_nonce = output.field_0.field_2.nonce.to_le_bytes();
    budget_grant.state_version_at_authorization = ctx.accounts.client_vault_state.state_version;
    budget_grant.status = BUDGET_GRANT_STATUS_READY;

    Ok(())
}

pub fn reconcile_budget_callback_handler(
    ctx: Context<ReconcileBudgetCallback>,
    output: SignedComputationOutputs<ReconcileBudgetOutput>,
) -> Result<()> {
    let output = output
        .verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )
        .map_err(|_| VaultError::AbortedComputation)?;
    let pending_offset = ctx.accounts.client_vault_state.pending_offset;
    let expected_computation = derive_comp_pda!(
        pending_offset,
        ctx.accounts.mxe_account,
        VaultError::ClusterNotSet
    );

    if !output.field_0.field_2 {
        clear_pending_state(
            ctx.accounts.client_vault_state.as_mut(),
            expected_computation,
            ctx.accounts.computation_account.key(),
        )?;
        ctx.accounts.budget_grant.status = BUDGET_GRANT_STATUS_READY;
        return Ok(());
    }

    write_agent_vault_state(
        ctx.accounts.client_vault_state.as_mut(),
        expected_computation,
        ctx.accounts.computation_account.key(),
        &output.field_0.field_0.ciphertexts,
        output.field_0.field_0.nonce,
    )?;

    let budget_grant = &mut ctx.accounts.budget_grant;
    budget_grant.grant_state_ciphertexts = output.field_0.field_1.ciphertexts;
    budget_grant.grant_state_nonce = output.field_0.field_1.nonce.to_le_bytes();
    budget_grant.status = if output.field_0.field_3 {
        BUDGET_GRANT_STATUS_CLOSED
    } else {
        BUDGET_GRANT_STATUS_READY
    };

    Ok(())
}

pub fn authorize_withdrawal_callback_handler(
    mut ctx: Context<AuthorizeWithdrawalCallback>,
    output: SignedComputationOutputs<AuthorizeWithdrawalOutput>,
) -> Result<()> {
    let output = output
        .verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )
        .map_err(|_| VaultError::AbortedComputation)?;

    finish_authorize_withdrawal_callback(&mut ctx, &output)
}

#[inline(never)]
fn finish_authorize_withdrawal_callback(
    ctx: &mut Context<AuthorizeWithdrawalCallback>,
    output: &AuthorizeWithdrawalOutput,
) -> Result<()> {
    let pending_offset = ctx.accounts.client_vault_state.pending_offset;
    let expected_computation = derive_comp_pda!(
        pending_offset,
        ctx.accounts.mxe_account,
        VaultError::ClusterNotSet
    );

    if !output.field_0.field_3 {
        clear_pending_state(
            ctx.accounts.client_vault_state.as_mut(),
            expected_computation,
            ctx.accounts.computation_account.key(),
        )?;
        ctx.accounts.withdrawal_grant.status = WITHDRAWAL_GRANT_STATUS_CANCELLED;
        return Ok(());
    }

    write_agent_vault_state(
        ctx.accounts.client_vault_state.as_mut(),
        expected_computation,
        ctx.accounts.computation_account.key(),
        &output.field_0.field_0.ciphertexts,
        output.field_0.field_0.nonce,
    )?;

    let withdrawal_grant = &mut ctx.accounts.withdrawal_grant;
    withdrawal_grant.grant_state_ciphertexts = output.field_0.field_1.ciphertexts;
    withdrawal_grant.grant_state_nonce = output.field_0.field_1.nonce.to_le_bytes();
    withdrawal_grant.grant_ciphertexts = output.field_0.field_2.ciphertexts;
    withdrawal_grant.grant_nonce = output.field_0.field_2.nonce.to_le_bytes();
    withdrawal_grant.status = WITHDRAWAL_GRANT_STATUS_READY;

    Ok(())
}

pub fn reconcile_withdrawal_callback_handler(
    ctx: Context<ReconcileWithdrawalCallback>,
    output: SignedComputationOutputs<ReconcileWithdrawalOutput>,
) -> Result<()> {
    let output = output
        .verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )
        .map_err(|_| VaultError::AbortedComputation)?;
    let pending_offset = ctx.accounts.client_vault_state.pending_offset;
    let expected_computation = derive_comp_pda!(
        pending_offset,
        ctx.accounts.mxe_account,
        VaultError::ClusterNotSet
    );

    if !output.field_0.field_2 {
        clear_pending_state(
            ctx.accounts.client_vault_state.as_mut(),
            expected_computation,
            ctx.accounts.computation_account.key(),
        )?;
        ctx.accounts.withdrawal_grant.status = WITHDRAWAL_GRANT_STATUS_READY;
        return Ok(());
    }

    write_agent_vault_state(
        ctx.accounts.client_vault_state.as_mut(),
        expected_computation,
        ctx.accounts.computation_account.key(),
        &output.field_0.field_0.ciphertexts,
        output.field_0.field_0.nonce,
    )?;

    let withdrawal_grant = &mut ctx.accounts.withdrawal_grant;
    withdrawal_grant.grant_state_ciphertexts = output.field_0.field_1.ciphertexts;
    withdrawal_grant.grant_state_nonce = output.field_0.field_1.nonce.to_le_bytes();
    withdrawal_grant.status = if output.field_0.field_3 {
        WITHDRAWAL_GRANT_STATUS_CLOSED
    } else {
        WITHDRAWAL_GRANT_STATUS_READY
    };

    Ok(())
}

pub fn prepare_recovery_claim_callback_handler(
    ctx: Context<PrepareRecoveryClaimCallback>,
    output: SignedComputationOutputs<PrepareRecoveryClaimOutput>,
) -> Result<()> {
    let output = output
        .verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )
        .map_err(|_| VaultError::AbortedComputation)?;
    let pending_offset = ctx.accounts.client_vault_state.pending_offset;
    let expected_computation = derive_comp_pda!(
        pending_offset,
        ctx.accounts.mxe_account,
        VaultError::ClusterNotSet
    );

    if !output.field_0.field_4 {
        clear_pending_state(
            ctx.accounts.client_vault_state.as_mut(),
            expected_computation,
            ctx.accounts.computation_account.key(),
        )?;
        ctx.accounts.recovery_claim.status = RECOVERY_CLAIM_STATUS_CANCELLED;
        return Ok(());
    }

    require!(
        output.field_0.field_3 <= i64::MAX as u64,
        VaultError::ArithmeticOverflow
    );

    write_agent_vault_state(
        ctx.accounts.client_vault_state.as_mut(),
        expected_computation,
        ctx.accounts.computation_account.key(),
        &output.field_0.field_0.ciphertexts,
        output.field_0.field_0.nonce,
    )?;
    ctx.accounts.client_vault_state.status = CLIENT_VAULT_STATUS_CLOSED;

    let recovery_claim = &mut ctx.accounts.recovery_claim;
    recovery_claim.free_balance_due = output.field_0.field_1;
    recovery_claim.locked_balance_due = output.field_0.field_2;
    recovery_claim.max_lock_expires_at = output.field_0.field_3 as i64;
    recovery_claim.state_version = ctx.accounts.client_vault_state.state_version;
    recovery_claim.status = RECOVERY_CLAIM_STATUS_READY;

    Ok(())
}

fn append_agent_vault_arg(builder: ArgBuilder, state: &ClientVaultState) -> ArgBuilder {
    builder
        .plaintext_u128(u128::from_le_bytes(state.agent_vault_nonce))
        .encrypted_u64(state.agent_vault_ciphertexts[0])
        .encrypted_u64(state.agent_vault_ciphertexts[1])
        .encrypted_u64(state.agent_vault_ciphertexts[2])
        .encrypted_u64(state.agent_vault_ciphertexts[3])
        .encrypted_u64(state.agent_vault_ciphertexts[4])
        .encrypted_u64(state.agent_vault_ciphertexts[5])
        .encrypted_u64(state.agent_vault_ciphertexts[6])
        .encrypted_u128(state.agent_vault_ciphertexts[7])
}

fn append_budget_request_arg(
    builder: ArgBuilder,
    x25519_pubkey: [u8; 32],
    nonce: [u8; 16],
    ciphertexts: [[u8; 32]; BUDGET_REQUEST_SCALARS],
) -> ArgBuilder {
    builder
        .x25519_pubkey(x25519_pubkey)
        .plaintext_u128(u128::from_le_bytes(nonce))
        .encrypted_u128(ciphertexts[0])
        .encrypted_u128(ciphertexts[1])
        .encrypted_u64(ciphertexts[2])
        .encrypted_u64(ciphertexts[3])
        .encrypted_u64(ciphertexts[4])
        .encrypted_u64(ciphertexts[5])
}

fn append_budget_grant_state_arg(builder: ArgBuilder, grant: &BudgetGrant) -> ArgBuilder {
    builder
        .plaintext_u128(u128::from_le_bytes(grant.grant_state_nonce))
        .encrypted_u64(grant.grant_state_ciphertexts[0])
        .encrypted_u64(grant.grant_state_ciphertexts[1])
        .encrypted_u64(grant.grant_state_ciphertexts[2])
        .encrypted_u64(grant.grant_state_ciphertexts[3])
        .encrypted_u64(grant.grant_state_ciphertexts[4])
        .encrypted_u64(grant.grant_state_ciphertexts[5])
        .encrypted_u64(grant.grant_state_ciphertexts[6])
        .encrypted_u64(grant.grant_state_ciphertexts[7])
        .encrypted_u8(grant.grant_state_ciphertexts[8])
}

fn append_reconcile_report_arg(
    builder: ArgBuilder,
    x25519_pubkey: [u8; 32],
    nonce: [u8; 16],
    ciphertexts: [[u8; 32]; RECONCILE_REPORT_SCALARS],
) -> ArgBuilder {
    builder
        .x25519_pubkey(x25519_pubkey)
        .plaintext_u128(u128::from_le_bytes(nonce))
        .encrypted_u128(ciphertexts[0])
        .encrypted_u128(ciphertexts[1])
        .encrypted_u64(ciphertexts[2])
        .encrypted_u64(ciphertexts[3])
        .encrypted_u64(ciphertexts[4])
        .encrypted_u64(ciphertexts[5])
        .encrypted_u8(ciphertexts[6])
}

fn append_withdrawal_request_arg(
    builder: ArgBuilder,
    x25519_pubkey: [u8; 32],
    nonce: [u8; 16],
    ciphertexts: [[u8; 32]; WITHDRAWAL_REQUEST_SCALARS],
) -> ArgBuilder {
    builder
        .x25519_pubkey(x25519_pubkey)
        .plaintext_u128(u128::from_le_bytes(nonce))
        .encrypted_u128(ciphertexts[0])
        .encrypted_u128(ciphertexts[1])
        .encrypted_u64(ciphertexts[2])
        .encrypted_u64(ciphertexts[3])
        .encrypted_u64(ciphertexts[4])
}

fn append_withdrawal_grant_state_arg(builder: ArgBuilder, grant: &WithdrawalGrant) -> ArgBuilder {
    builder
        .plaintext_u128(u128::from_le_bytes(grant.grant_state_nonce))
        .encrypted_u64(grant.grant_state_ciphertexts[0])
        .encrypted_u64(grant.grant_state_ciphertexts[1])
        .encrypted_u64(grant.grant_state_ciphertexts[2])
        .encrypted_u64(grant.grant_state_ciphertexts[3])
        .encrypted_u64(grant.grant_state_ciphertexts[4])
        .encrypted_u64(grant.grant_state_ciphertexts[5])
        .encrypted_u8(grant.grant_state_ciphertexts[6])
}

fn append_withdrawal_report_arg(
    builder: ArgBuilder,
    x25519_pubkey: [u8; 32],
    nonce: [u8; 16],
    ciphertexts: [[u8; 32]; WITHDRAWAL_REPORT_SCALARS],
) -> ArgBuilder {
    builder
        .x25519_pubkey(x25519_pubkey)
        .plaintext_u128(u128::from_le_bytes(nonce))
        .encrypted_u128(ciphertexts[0])
        .encrypted_u128(ciphertexts[1])
        .encrypted_u64(ciphertexts[2])
        .encrypted_u64(ciphertexts[3])
        .encrypted_u8(ciphertexts[4])
}

fn split_domain_hash(hash: [u8; 32]) -> (u128, u128) {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&hash[..16]);
    hi.copy_from_slice(&hash[16..]);
    (u128::from_le_bytes(lo), u128::from_le_bytes(hi))
}

fn split_pubkey(pubkey: Pubkey) -> (u128, u128) {
    split_domain_hash(pubkey.to_bytes())
}

fn compute_arcium_domain_hash(
    instruction_kind: &[u8],
    vault_config_key: Pubkey,
    vault_config: &VaultConfig,
    arcium_config: &ArciumConfig,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"subly402:arcium-domain:v1");
    hasher.update(instruction_kind);
    hasher.update(ID.as_ref());
    hasher.update(vault_config_key.as_ref());
    hasher.update(vault_config.usdc_mint.as_ref());
    hasher.update(arcium_config.arcium_program_id.as_ref());
    hasher.update(arcium_config.mxe_account.as_ref());
    hasher.update(arcium_config.tee_x25519_pubkey);
    hasher.update(arcium_config.attestation_policy_hash);
    hasher.update(arcium_config.comp_def_version.to_le_bytes());
    hasher.finalize().into()
}

fn require_pending_timeout(state: &ClientVaultState) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    require!(
        state.pending_started_at > 0
            && now.saturating_sub(state.pending_started_at) >= ARCIUM_PENDING_TIMEOUT_SEC,
        VaultError::ArciumPendingTimeoutNotElapsed
    );
    Ok(())
}

fn write_agent_vault_state(
    state: &mut Account<ClientVaultState>,
    expected_computation: Pubkey,
    computation_account: Pubkey,
    ciphertexts: &[[u8; 32]; AGENT_VAULT_SCALARS],
    nonce: u128,
) -> Result<()> {
    require!(
        state.status == CLIENT_VAULT_STATUS_PENDING,
        VaultError::InvalidArciumCallback
    );

    require!(
        expected_computation == computation_account,
        VaultError::InvalidArciumCallback
    );

    state.agent_vault_ciphertexts = *ciphertexts;
    state.agent_vault_nonce = nonce.to_le_bytes();
    state.state_version = state
        .state_version
        .checked_add(1)
        .ok_or(VaultError::ArithmeticOverflow)?;
    state.pending_offset = 0;
    state.pending_started_at = 0;
    state.status = CLIENT_VAULT_STATUS_IDLE;

    Ok(())
}

fn clear_pending_state(
    state: &mut Account<ClientVaultState>,
    expected_computation: Pubkey,
    computation_account: Pubkey,
) -> Result<()> {
    require!(
        state.status == CLIENT_VAULT_STATUS_PENDING,
        VaultError::InvalidArciumCallback
    );
    require!(
        expected_computation == computation_account,
        VaultError::InvalidArciumCallback
    );

    state.pending_offset = 0;
    state.pending_started_at = 0;
    state.status = CLIENT_VAULT_STATUS_IDLE;

    Ok(())
}
#[event]
pub struct OwnerViewEvent {
    pub client: Pubkey,
    pub state_version: u64,
    pub ciphertexts: [[u8; 32]; AGENT_VAULT_SCALARS],
    pub nonce: [u8; 16],
}
