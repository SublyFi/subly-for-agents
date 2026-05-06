use anchor_lang::prelude::*;

use crate::constants::ARCIUM_STATUS_ENFORCED;
use crate::error::VaultError;
use crate::state::{ArciumConfig, VaultConfig};

#[derive(Accounts)]
pub struct UpdateArciumDeployment<'info> {
    #[account(mut)]
    pub governance: Signer<'info>,

    #[account(
        constraint = vault_config.governance == governance.key() @ VaultError::Unauthorized,
    )]
    pub vault_config: Account<'info, VaultConfig>,

    #[account(
        mut,
        seeds = [b"arcium_config", vault_config.key().as_ref()],
        bump = arcium_config.bump,
        constraint = arcium_config.vault_config == vault_config.key() @ VaultError::InvalidArciumConfig,
    )]
    pub arcium_config: Account<'info, ArciumConfig>,
}

pub fn handler(
    ctx: Context<UpdateArciumDeployment>,
    arcium_program_id: Pubkey,
    mxe_account: Pubkey,
    cluster_account: Pubkey,
    mempool_account: Pubkey,
    comp_def_version: u32,
    tee_x25519_pubkey: [u8; 32],
) -> Result<()> {
    require!(
        ctx.accounts.arcium_config.status != ARCIUM_STATUS_ENFORCED,
        VaultError::InvalidArciumStatus
    );

    let arcium_config = &mut ctx.accounts.arcium_config;
    arcium_config.arcium_program_id = arcium_program_id;
    arcium_config.mxe_account = mxe_account;
    arcium_config.cluster_account = cluster_account;
    arcium_config.mempool_account = mempool_account;
    arcium_config.comp_def_version = comp_def_version;
    arcium_config.tee_x25519_pubkey = tee_x25519_pubkey;
    arcium_config.attestation_policy_hash = ctx.accounts.vault_config.attestation_policy_hash;

    require!(
        !ArciumConfig::status_requires_deployment(arcium_config.status)
            || arcium_config.deployment_configured(),
        VaultError::InvalidArciumConfig
    );

    Ok(())
}
