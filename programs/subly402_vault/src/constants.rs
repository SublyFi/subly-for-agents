use arcium_anchor::comp_def_offset;

pub const MAX_SETTLEMENTS_PER_TX: usize = 20;
pub const MAX_ATOMIC_AUDITS_PER_TX: usize = 5;
pub const DISPUTE_WINDOW_SEC: i64 = 86400; // 24 hours
pub const ARCIUM_PENDING_TIMEOUT_SEC: i64 = 3600;

pub const VAULT_STATUS_ACTIVE: u8 = 0;
pub const VAULT_STATUS_PAUSED: u8 = 1;
pub const VAULT_STATUS_MIGRATING: u8 = 2;
pub const VAULT_STATUS_RETIRED: u8 = 3;

pub const ARCIUM_STATUS_DISABLED: u8 = 0;
pub const ARCIUM_STATUS_MIRROR: u8 = 1;
pub const ARCIUM_STATUS_ENFORCED: u8 = 2;
pub const ARCIUM_STATUS_PAUSED: u8 = 3;

pub const CLIENT_VAULT_STATUS_IDLE: u8 = 0;
pub const CLIENT_VAULT_STATUS_PENDING: u8 = 1;
pub const CLIENT_VAULT_STATUS_CLOSED: u8 = 2;

pub const DEPOSIT_CREDIT_STATUS_PENDING: u8 = 0;
pub const DEPOSIT_CREDIT_STATUS_APPLIED: u8 = 1;
pub const DEPOSIT_CREDIT_STATUS_CANCELLED: u8 = 2;

pub const BUDGET_GRANT_STATUS_PENDING: u8 = 0;
pub const BUDGET_GRANT_STATUS_READY: u8 = 1;
pub const BUDGET_GRANT_STATUS_RECONCILING: u8 = 2;
pub const BUDGET_GRANT_STATUS_CLOSED: u8 = 3;
pub const BUDGET_GRANT_STATUS_EXPIRED: u8 = 4;
pub const BUDGET_GRANT_STATUS_CANCELLED: u8 = 5;

pub const WITHDRAWAL_GRANT_STATUS_PENDING: u8 = 0;
pub const WITHDRAWAL_GRANT_STATUS_READY: u8 = 1;
pub const WITHDRAWAL_GRANT_STATUS_RECONCILING: u8 = 2;
pub const WITHDRAWAL_GRANT_STATUS_CLOSED: u8 = 3;
pub const WITHDRAWAL_GRANT_STATUS_EXPIRED: u8 = 4;
pub const WITHDRAWAL_GRANT_STATUS_CANCELLED: u8 = 5;

pub const YIELD_EPOCH_STATUS_OPEN: u8 = 0;
pub const YIELD_EPOCH_STATUS_CLOSED: u8 = 1;

pub const RECOVERY_CLAIM_STATUS_PENDING: u8 = 0;
pub const RECOVERY_CLAIM_STATUS_READY: u8 = 1;
pub const RECOVERY_CLAIM_STATUS_FINALIZED: u8 = 2;
pub const RECOVERY_CLAIM_STATUS_CANCELLED: u8 = 3;

pub const AGENT_VAULT_SCALARS: usize = 8;
pub const BUDGET_GRANT_STATE_SCALARS: usize = 9;
pub const BUDGET_GRANT_SCALARS: usize = 15;
pub const BUDGET_REQUEST_SCALARS: usize = 6;
pub const RECONCILE_REPORT_SCALARS: usize = 7;
pub const WITHDRAWAL_REQUEST_SCALARS: usize = 5;
pub const WITHDRAWAL_REPORT_SCALARS: usize = 5;
pub const WITHDRAWAL_GRANT_STATE_SCALARS: usize = 7;
pub const WITHDRAWAL_GRANT_SCALARS: usize = 15;

pub const COMP_DEF_OFFSET_INIT_AGENT_VAULT: u32 = comp_def_offset("init_agent_vault");
pub const COMP_DEF_OFFSET_APPLY_DEPOSIT: u32 = comp_def_offset("apply_deposit");
pub const COMP_DEF_OFFSET_SETTLE_YIELD: u32 = comp_def_offset("settle_yield");
pub const COMP_DEF_OFFSET_OWNER_VIEW: u32 = comp_def_offset("owner_view");
pub const COMP_DEF_OFFSET_AUTHORIZE_BUDGET: u32 = comp_def_offset("authorize_budget");
pub const COMP_DEF_OFFSET_RECONCILE_BUDGET: u32 = comp_def_offset("reconcile_budget");
pub const COMP_DEF_OFFSET_AUTHORIZE_WITHDRAWAL: u32 = comp_def_offset("authorize_withdrawal");
pub const COMP_DEF_OFFSET_RECONCILE_WITHDRAWAL: u32 = comp_def_offset("reconcile_withdrawal");
pub const COMP_DEF_OFFSET_PREPARE_RECOVERY_CLAIM: u32 = comp_def_offset("prepare_recovery_claim");
