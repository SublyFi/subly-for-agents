use arcis::*;

#[encrypted]
mod circuits {
    use arcis::*;

    #[derive(Copy, Clone)]
    pub struct AgentVault {
        pub free: u64,
        pub locked: u64,
        pub yield_earned: u64,
        pub spent: u64,
        pub withdrawn: u64,
        pub strategy_shares: u64,
        pub max_lock_expires_at: u64,
        pub yield_index_checkpoint_q64: u128,
    }

    #[derive(Copy, Clone)]
    pub struct AgentVaultView {
        pub free: u64,
        pub locked: u64,
        pub yield_earned: u64,
        pub spent: u64,
        pub withdrawn: u64,
        pub strategy_shares: u64,
        pub max_lock_expires_at: u64,
        pub yield_index_checkpoint_q64: u128,
    }

    #[derive(Copy, Clone)]
    pub struct BudgetRequest {
        pub domain_hash_lo: u128,
        pub domain_hash_hi: u128,
        pub budget_id: u64,
        pub request_nonce: u64,
        pub amount: u64,
        pub expires_at: u64,
    }

    #[derive(Copy, Clone)]
    pub struct BudgetGrantView {
        pub approved: u8,
        pub budget_id: u64,
        pub request_nonce: u64,
        pub amount: u64,
        pub remaining: u64,
        pub expires_at: u64,
        pub state_version: u64,
        pub domain_hash_lo: u128,
        pub domain_hash_hi: u128,
        pub vault_config_lo: u128,
        pub vault_config_hi: u128,
        pub client_lo: u128,
        pub client_hi: u128,
        pub budget_grant_lo: u128,
        pub budget_grant_hi: u128,
    }

    #[derive(Copy, Clone)]
    pub struct BudgetGrantState {
        pub budget_id: u64,
        pub request_nonce: u64,
        pub authorized: u64,
        pub remaining: u64,
        pub consumed: u64,
        pub refunded: u64,
        pub expires_at: u64,
        pub last_report_nonce: u64,
        pub status: u8,
    }

    #[derive(Copy, Clone)]
    pub struct ReconcileReport {
        pub domain_hash_lo: u128,
        pub domain_hash_hi: u128,
        pub budget_id: u64,
        pub request_nonce: u64,
        pub report_nonce: u64,
        pub consumed_delta: u64,
        pub refund_remaining: u8,
    }

    #[derive(Copy, Clone)]
    pub struct WithdrawalRequest {
        pub domain_hash_lo: u128,
        pub domain_hash_hi: u128,
        pub withdrawal_id: u64,
        pub amount: u64,
        pub expires_at: u64,
    }

    #[derive(Copy, Clone)]
    pub struct WithdrawalGrantState {
        pub withdrawal_id: u64,
        pub authorized: u64,
        pub withdrawn: u64,
        pub refunded: u64,
        pub expires_at: u64,
        pub state_version: u64,
        pub status: u8,
    }

    #[derive(Copy, Clone)]
    pub struct WithdrawalGrantView {
        pub approved: u8,
        pub withdrawal_id: u64,
        pub amount: u64,
        pub expires_at: u64,
        pub state_version: u64,
        pub domain_hash_lo: u128,
        pub domain_hash_hi: u128,
        pub vault_config_lo: u128,
        pub vault_config_hi: u128,
        pub client_lo: u128,
        pub client_hi: u128,
        pub withdrawal_grant_lo: u128,
        pub withdrawal_grant_hi: u128,
        pub recipient_lo: u128,
        pub recipient_hi: u128,
    }

    #[derive(Copy, Clone)]
    pub struct WithdrawalReport {
        pub domain_hash_lo: u128,
        pub domain_hash_hi: u128,
        pub withdrawal_id: u64,
        pub withdrawn_amount: u64,
        pub refund_remaining: u8,
    }

    const BUDGET_GRANT_STATUS_READY: u8 = 1;
    const BUDGET_GRANT_STATUS_CLOSED: u8 = 3;
    const WITHDRAWAL_GRANT_STATUS_READY: u8 = 1;
    const WITHDRAWAL_GRANT_STATUS_CLOSED: u8 = 3;

    fn q64_mul_u64(value: u64, delta_q64: u128) -> (u64, bool) {
        let high = (delta_q64 >> 64) as u64;
        let low = delta_q64 as u64;
        let high_product = (value as u128) * (high as u128);
        let low_product = ((value as u128) * (low as u128)) >> 64;
        let total = high_product + low_product;
        let ok = total <= u64::MAX as u128;

        (total as u64, ok)
    }

    fn settle_pending_yield(
        mut state: AgentVault,
        current_yield_index_q64: u128,
    ) -> (AgentVault, bool) {
        let mut ok = true;

        if current_yield_index_q64 > state.yield_index_checkpoint_q64 {
            let index_delta = current_yield_index_q64 - state.yield_index_checkpoint_q64;
            let (yield_delta, yield_ok) = q64_mul_u64(state.strategy_shares, index_delta);
            let next_free = (state.free as u128) + (yield_delta as u128);
            let next_yield_earned = (state.yield_earned as u128) + (yield_delta as u128);
            let can_add =
                yield_ok && next_free <= u64::MAX as u128 && next_yield_earned <= u64::MAX as u128;

            if can_add {
                state.free = next_free as u64;
                state.yield_earned = next_yield_earned as u64;
                state.yield_index_checkpoint_q64 = current_yield_index_q64;
            } else {
                ok = false;
            }
        }

        (state, ok)
    }

    #[instruction]
    pub fn init_agent_vault(current_yield_index_q64: u128) -> Enc<Mxe, AgentVault> {
        Mxe::get().from_arcis(AgentVault {
            free: 0,
            locked: 0,
            yield_earned: 0,
            spent: 0,
            withdrawn: 0,
            strategy_shares: 0,
            max_lock_expires_at: 0,
            yield_index_checkpoint_q64: current_yield_index_q64,
        })
    }

    #[instruction]
    pub fn apply_deposit(
        state_ctxt: Enc<Mxe, AgentVault>,
        amount: u64,
        current_yield_index_q64: u128,
    ) -> (Enc<Mxe, AgentVault>, bool) {
        let original_state = state_ctxt.to_arcis();
        let (mut state, yield_ok) = settle_pending_yield(original_state, current_yield_index_q64);
        let next_free = (state.free as u128) + (amount as u128);
        let next_strategy_shares = (state.strategy_shares as u128) + (amount as u128);
        let deposit_ok = next_free <= u64::MAX as u128 && next_strategy_shares <= u64::MAX as u128;
        let ok = yield_ok && deposit_ok;

        if ok {
            state.free = next_free as u64;
            state.strategy_shares = next_strategy_shares as u64;
        } else {
            state = original_state;
        }

        (state_ctxt.owner.from_arcis(state), ok.reveal())
    }

    #[instruction]
    pub fn settle_yield(
        state_ctxt: Enc<Mxe, AgentVault>,
        current_yield_index_q64: u128,
    ) -> (Enc<Mxe, AgentVault>, bool) {
        let (state, ok) = settle_pending_yield(state_ctxt.to_arcis(), current_yield_index_q64);
        (state_ctxt.owner.from_arcis(state), ok.reveal())
    }

    #[instruction]
    pub fn owner_view(
        state_ctxt: Enc<Mxe, AgentVault>,
        owner: Shared,
        current_yield_index_q64: u128,
    ) -> (Enc<Shared, AgentVaultView>, bool) {
        let (state, ok) = settle_pending_yield(state_ctxt.to_arcis(), current_yield_index_q64);

        (
            owner.from_arcis(AgentVaultView {
                free: state.free,
                locked: state.locked,
                yield_earned: state.yield_earned,
                spent: state.spent,
                withdrawn: state.withdrawn,
                strategy_shares: state.strategy_shares,
                max_lock_expires_at: state.max_lock_expires_at,
                yield_index_checkpoint_q64: state.yield_index_checkpoint_q64,
            }),
            ok.reveal(),
        )
    }

    #[instruction]
    pub fn authorize_budget(
        state_ctxt: Enc<Mxe, AgentVault>,
        request_ctxt: Enc<Shared, BudgetRequest>,
        tee: Shared,
        current_yield_index_q64: u128,
        expected_domain_hash_lo: u128,
        expected_domain_hash_hi: u128,
        public_budget_id: u64,
        public_request_nonce: u64,
        public_expires_at: u64,
        authorization_state_version: u64,
        vault_config_lo: u128,
        vault_config_hi: u128,
        client_lo: u128,
        client_hi: u128,
        budget_grant_lo: u128,
        budget_grant_hi: u128,
    ) -> (
        Enc<Mxe, AgentVault>,
        Enc<Mxe, BudgetGrantState>,
        Enc<Shared, BudgetGrantView>,
        bool,
    ) {
        let original_state = state_ctxt.to_arcis();
        let request = request_ctxt.to_arcis();
        let (mut state, yield_ok) = settle_pending_yield(original_state, current_yield_index_q64);

        let valid_request = request.domain_hash_lo == expected_domain_hash_lo
            && request.domain_hash_hi == expected_domain_hash_hi
            && request.budget_id == public_budget_id
            && request.request_nonce == public_request_nonce
            && request.expires_at == public_expires_at;
        let next_locked = (state.locked as u128) + (request.amount as u128);
        let can_lock = next_locked <= u64::MAX as u128;
        let approved = yield_ok
            && valid_request
            && request.amount > 0
            && state.free >= request.amount
            && can_lock
            && authorization_state_version > 0;

        let mut grant_state = BudgetGrantState {
            budget_id: public_budget_id,
            request_nonce: public_request_nonce,
            authorized: 0,
            remaining: 0,
            consumed: 0,
            refunded: 0,
            expires_at: public_expires_at,
            last_report_nonce: 0,
            status: BUDGET_GRANT_STATUS_CLOSED,
        };
        let mut grant_view = BudgetGrantView {
            approved: 0,
            budget_id: public_budget_id,
            request_nonce: public_request_nonce,
            amount: 0,
            remaining: 0,
            expires_at: public_expires_at,
            state_version: authorization_state_version,
            domain_hash_lo: expected_domain_hash_lo,
            domain_hash_hi: expected_domain_hash_hi,
            vault_config_lo,
            vault_config_hi,
            client_lo,
            client_hi,
            budget_grant_lo,
            budget_grant_hi,
        };

        if approved {
            state.free -= request.amount;
            state.locked = next_locked as u64;
            if request.expires_at > state.max_lock_expires_at {
                state.max_lock_expires_at = request.expires_at;
            }

            grant_state.authorized = request.amount;
            grant_state.remaining = request.amount;
            grant_state.expires_at = request.expires_at;
            grant_state.status = BUDGET_GRANT_STATUS_READY;

            grant_view.approved = 1;
            grant_view.amount = request.amount;
            grant_view.remaining = request.amount;
            grant_view.expires_at = request.expires_at;
        } else {
            state = original_state;
        }

        (
            state_ctxt.owner.from_arcis(state),
            Mxe::get().from_arcis(grant_state),
            tee.from_arcis(grant_view),
            approved.reveal(),
        )
    }

    #[instruction]
    pub fn reconcile_budget(
        state_ctxt: Enc<Mxe, AgentVault>,
        grant_state_ctxt: Enc<Mxe, BudgetGrantState>,
        report_ctxt: Enc<Shared, ReconcileReport>,
        expected_domain_hash_lo: u128,
        expected_domain_hash_hi: u128,
        public_budget_id: u64,
        public_request_nonce: u64,
    ) -> (Enc<Mxe, AgentVault>, Enc<Mxe, BudgetGrantState>, bool, bool) {
        let original_state = state_ctxt.to_arcis();
        let original_grant_state = grant_state_ctxt.to_arcis();
        let mut state = original_state;
        let mut grant_state = original_grant_state;
        let report = report_ctxt.to_arcis();

        let valid_report = report.domain_hash_lo == expected_domain_hash_lo
            && report.domain_hash_hi == expected_domain_hash_hi
            && report.budget_id == public_budget_id
            && report.request_nonce == public_request_nonce
            && report.budget_id == grant_state.budget_id
            && report.request_nonce == grant_state.request_nonce
            && report.report_nonce > grant_state.last_report_nonce
            && report.refund_remaining <= 1
            && grant_state.status == BUDGET_GRANT_STATUS_READY
            && report.consumed_delta <= grant_state.remaining;

        let mut refund = 0u64;
        if valid_report && report.refund_remaining == 1 {
            refund = grant_state.remaining - report.consumed_delta;
        }

        let debit = (report.consumed_delta as u128) + (refund as u128);
        let next_free = (state.free as u128) + (refund as u128);
        let next_spent = (state.spent as u128) + (report.consumed_delta as u128);
        let next_consumed = (grant_state.consumed as u128) + (report.consumed_delta as u128);
        let next_refunded = (grant_state.refunded as u128) + (refund as u128);
        let balances_ok = debit <= state.locked as u128
            && next_free <= u64::MAX as u128
            && next_spent <= u64::MAX as u128
            && next_consumed <= u64::MAX as u128
            && next_refunded <= u64::MAX as u128;
        let ok = valid_report && balances_ok;
        let mut closed = false;

        if ok {
            state.locked -= debit as u64;
            state.free = next_free as u64;
            state.spent = next_spent as u64;
            grant_state.remaining -= debit as u64;
            grant_state.consumed = next_consumed as u64;
            grant_state.refunded = next_refunded as u64;
            grant_state.last_report_nonce = report.report_nonce;

            if grant_state.remaining == 0 {
                grant_state.status = BUDGET_GRANT_STATUS_CLOSED;
                closed = true;
            }
        } else {
            state = original_state;
            grant_state = original_grant_state;
        }

        (
            state_ctxt.owner.from_arcis(state),
            grant_state_ctxt.owner.from_arcis(grant_state),
            ok.reveal(),
            closed.reveal(),
        )
    }

    #[instruction]
    pub fn authorize_withdrawal(
        state_ctxt: Enc<Mxe, AgentVault>,
        request_ctxt: Enc<Shared, WithdrawalRequest>,
        tee: Shared,
        current_yield_index_q64: u128,
        expected_domain_hash_lo: u128,
        expected_domain_hash_hi: u128,
        public_withdrawal_id: u64,
        public_expires_at: u64,
        authorization_state_version: u64,
        vault_config_lo: u128,
        vault_config_hi: u128,
        client_lo: u128,
        client_hi: u128,
        withdrawal_grant_lo: u128,
        withdrawal_grant_hi: u128,
        recipient_lo: u128,
        recipient_hi: u128,
    ) -> (
        Enc<Mxe, AgentVault>,
        Enc<Mxe, WithdrawalGrantState>,
        Enc<Shared, WithdrawalGrantView>,
        bool,
    ) {
        let original_state = state_ctxt.to_arcis();
        let request = request_ctxt.to_arcis();
        let (mut state, yield_ok) = settle_pending_yield(original_state, current_yield_index_q64);

        let valid_request = request.domain_hash_lo == expected_domain_hash_lo
            && request.domain_hash_hi == expected_domain_hash_hi
            && request.withdrawal_id == public_withdrawal_id
            && request.expires_at == public_expires_at;
        let next_locked = (state.locked as u128) + (request.amount as u128);
        let can_lock = next_locked <= u64::MAX as u128;
        let approved = yield_ok
            && valid_request
            && request.amount > 0
            && state.free >= request.amount
            && can_lock
            && authorization_state_version > 0;

        let mut grant_state = WithdrawalGrantState {
            withdrawal_id: public_withdrawal_id,
            authorized: 0,
            withdrawn: 0,
            refunded: 0,
            expires_at: public_expires_at,
            state_version: authorization_state_version,
            status: WITHDRAWAL_GRANT_STATUS_CLOSED,
        };
        let mut grant_view = WithdrawalGrantView {
            approved: 0,
            withdrawal_id: public_withdrawal_id,
            amount: 0,
            expires_at: public_expires_at,
            state_version: authorization_state_version,
            domain_hash_lo: expected_domain_hash_lo,
            domain_hash_hi: expected_domain_hash_hi,
            vault_config_lo,
            vault_config_hi,
            client_lo,
            client_hi,
            withdrawal_grant_lo,
            withdrawal_grant_hi,
            recipient_lo,
            recipient_hi,
        };

        if approved {
            state.free -= request.amount;
            state.locked = next_locked as u64;
            if request.expires_at > state.max_lock_expires_at {
                state.max_lock_expires_at = request.expires_at;
            }

            grant_state.authorized = request.amount;
            grant_state.expires_at = request.expires_at;
            grant_state.status = WITHDRAWAL_GRANT_STATUS_READY;

            grant_view.approved = 1;
            grant_view.amount = request.amount;
            grant_view.expires_at = request.expires_at;
        } else {
            state = original_state;
        }

        (
            state_ctxt.owner.from_arcis(state),
            Mxe::get().from_arcis(grant_state),
            tee.from_arcis(grant_view),
            approved.reveal(),
        )
    }

    #[instruction]
    pub fn reconcile_withdrawal(
        state_ctxt: Enc<Mxe, AgentVault>,
        grant_state_ctxt: Enc<Mxe, WithdrawalGrantState>,
        report_ctxt: Enc<Shared, WithdrawalReport>,
        expected_domain_hash_lo: u128,
        expected_domain_hash_hi: u128,
        public_withdrawal_id: u64,
    ) -> (
        Enc<Mxe, AgentVault>,
        Enc<Mxe, WithdrawalGrantState>,
        bool,
        bool,
    ) {
        let original_state = state_ctxt.to_arcis();
        let original_grant_state = grant_state_ctxt.to_arcis();
        let mut state = original_state;
        let mut grant_state = original_grant_state;
        let report = report_ctxt.to_arcis();

        let used = (grant_state.withdrawn as u128) + (grant_state.refunded as u128);
        let remaining_u128 = if (grant_state.authorized as u128) >= used {
            (grant_state.authorized as u128) - used
        } else {
            0
        };
        let valid_report = report.domain_hash_lo == expected_domain_hash_lo
            && report.domain_hash_hi == expected_domain_hash_hi
            && report.withdrawal_id == public_withdrawal_id
            && report.withdrawal_id == grant_state.withdrawal_id
            && report.refund_remaining <= 1
            && grant_state.status == WITHDRAWAL_GRANT_STATUS_READY
            && (grant_state.authorized as u128) >= used
            && (report.withdrawn_amount as u128) <= remaining_u128;

        let mut refund = 0u64;
        if valid_report && report.refund_remaining == 1 {
            refund = (remaining_u128 - report.withdrawn_amount as u128) as u64;
        }

        let debit = (report.withdrawn_amount as u128) + (refund as u128);
        let next_free = (state.free as u128) + (refund as u128);
        let next_withdrawn = (state.withdrawn as u128) + (report.withdrawn_amount as u128);
        let next_grant_withdrawn =
            (grant_state.withdrawn as u128) + (report.withdrawn_amount as u128);
        let next_refunded = (grant_state.refunded as u128) + (refund as u128);
        let balances_ok = debit <= state.locked as u128
            && next_free <= u64::MAX as u128
            && next_withdrawn <= u64::MAX as u128
            && next_grant_withdrawn <= u64::MAX as u128
            && next_refunded <= u64::MAX as u128;
        let ok = valid_report && balances_ok;
        let mut closed = false;

        if ok {
            state.locked -= debit as u64;
            state.free = next_free as u64;
            state.withdrawn = next_withdrawn as u64;
            grant_state.withdrawn = next_grant_withdrawn as u64;
            grant_state.refunded = next_refunded as u64;

            if grant_state.withdrawn + grant_state.refunded == grant_state.authorized {
                grant_state.status = WITHDRAWAL_GRANT_STATUS_CLOSED;
                closed = true;
            }
        } else {
            state = original_state;
            grant_state = original_grant_state;
        }

        (
            state_ctxt.owner.from_arcis(state),
            grant_state_ctxt.owner.from_arcis(grant_state),
            ok.reveal(),
            closed.reveal(),
        )
    }

    #[instruction]
    pub fn prepare_recovery_claim(
        state_ctxt: Enc<Mxe, AgentVault>,
        current_yield_index_q64: u128,
    ) -> (Enc<Mxe, AgentVault>, u64, u64, u64, bool) {
        let original_state = state_ctxt.to_arcis();
        let (mut state, ok) = settle_pending_yield(original_state, current_yield_index_q64);
        let free_due = state.free;
        let locked_due = state.locked;
        let max_lock_expires_at = state.max_lock_expires_at;

        if ok {
            state.free = 0;
            state.locked = 0;
        } else {
            state = original_state;
        }

        (
            state_ctxt.owner.from_arcis(state),
            free_due.reveal(),
            locked_due.reveal(),
            max_lock_expires_at.reveal(),
            ok.reveal(),
        )
    }
}
