use crate::ledger::{Key, LedgerState};

/// Result of committing a flow sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlowSandboxCommit {
    pub(crate) touched: Vec<(Key, Option<Vec<u8>>)>,
}

/// Transactional sandbox for trial liquidity execution.
///
/// This is not wired into Payment yet. It wraps `LedgerState`'s existing
/// begin/commit/discard machinery so future flow steps can trial mutations and
/// only commit the winning strand.
pub(crate) struct FlowSandbox<'a> {
    state: &'a mut LedgerState,
    active: bool,
}

impl<'a> FlowSandbox<'a> {
    pub(crate) fn begin(state: &'a mut LedgerState) -> Self {
        state.begin_tx();
        Self {
            state,
            active: true,
        }
    }

    pub(crate) fn state(&self) -> &LedgerState {
        self.state
    }

    pub(crate) fn state_mut(&mut self) -> &mut LedgerState {
        self.state
    }

    pub(crate) fn commit(mut self) -> FlowSandboxCommit {
        self.active = false;
        FlowSandboxCommit {
            touched: self.state.commit_tx(),
        }
    }

    pub(crate) fn discard(mut self) {
        self.active = false;
        self.state.discard_tx();
    }
}

impl Drop for FlowSandbox<'_> {
    fn drop(&mut self) {
        if self.active {
            self.state.discard_tx();
            self.active = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::AccountRoot;

    fn account(account_id: [u8; 20], balance: u64) -> AccountRoot {
        AccountRoot {
            account_id,
            balance,
            sequence: 1,
            owner_count: 0,
            flags: 0,
            regular_key: None,
            minted_nftokens: 0,
            first_nftoken_sequence: 0,
            burned_nftokens: 0,
            transfer_rate: 0,
            domain: Vec::new(),
            tick_size: 0,
            ticket_count: 0,
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        }
    }

    #[test]
    fn sandbox_discards_on_drop() {
        let id = [1u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(id, 10));
        {
            let mut sandbox = FlowSandbox::begin(&mut state);
            let mut acct = sandbox.state().get_account(&id).unwrap().clone();
            acct.balance = 20;
            sandbox.state_mut().insert_account(acct);
        }
        assert_eq!(state.get_account(&id).unwrap().balance, 10);
    }

    #[test]
    fn sandbox_commit_keeps_changes() {
        let id = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(id, 10));
        {
            let mut sandbox = FlowSandbox::begin(&mut state);
            let mut acct = sandbox.state().get_account(&id).unwrap().clone();
            acct.balance = 30;
            sandbox.state_mut().insert_account(acct);
            let _commit = sandbox.commit();
        }
        assert_eq!(state.get_account(&id).unwrap().balance, 30);
    }
}
