//! Ticket — IMPLEMENTED

use super::{balance_before_fee, owner_reserve_requirement, ApplyResult};
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

/// Apply TicketCreate: reserve sequence numbers for future out-of-order use.
pub(crate) fn apply_ticket_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    // Defensive duplicate of rippled TicketCreate::preflight. Live paths run
    // this before fee/sequence/auth, but apply_tx can be used directly in tests.
    let count = match tx.ticket_count {
        Some(c) if c > 0 && c <= 250 => c,
        _ => return ApplyResult::ClaimedCost("temINVALID_COUNT"),
    };

    if new_sender.ticket_count.saturating_add(count) > 250 {
        return ApplyResult::ClaimedCost("tecDIR_FULL");
    }

    let pre_fee_balance = balance_before_fee(new_sender.balance, tx.fee);
    let required = owner_reserve_requirement(state, new_sender.owner_count, count);
    if pre_fee_balance < required {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
    }

    // TicketCreate reserves from the current account Sequence after the
    // transaction machinery has consumed either the Sequence or Ticket.
    let first_ticket_seq = new_sender.sequence;
    for i in 0..count {
        let ticket_seq = first_ticket_seq.saturating_add(i);
        let ticket_key = crate::ledger::ticket::shamap_key(&tx.account, ticket_seq);
        let owner_node = directory::dir_add(state, &tx.account, ticket_key.0);
        let ticket = crate::ledger::Ticket {
            account: tx.account,
            sequence: ticket_seq,
            owner_node,
            previous_txn_id: [0u8; 32],
            previous_txn_lgrseq: 0,
            raw_sle: None,
        };
        state.insert_ticket(ticket);
        new_sender.owner_count += 1;
    }
    // TicketCreate is the only transaction that advances account Sequence by
    // more than the consumed sequence proxy.
    new_sender.sequence = first_ticket_seq.saturating_add(count);
    new_sender.ticket_count = new_sender.ticket_count.saturating_add(count);

    ApplyResult::Success
}
