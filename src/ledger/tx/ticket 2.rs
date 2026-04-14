//! Ticket — IMPLEMENTED

use crate::ledger::LedgerState;
use crate::ledger::directory;
use crate::transaction::ParsedTx;
use super::ApplyResult;

/// Apply TicketCreate: reserve sequence numbers for future out-of-order use.
pub(crate) fn apply_ticket_create(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    // TicketCount validation (rippled: TicketCreate.cpp preflight, temINVALID_COUNT)
    let count = match tx.ticket_count {
        Some(c) if c > 0 && c <= 250 => c,
        Some(_) => return ApplyResult::ClaimedCost("temINVALID_COUNT"),
        None => match tx.amount_drops {
            // Fallback to amount_drops for backward compatibility
            Some(d) if d > 0 && d <= 250 => d as u32,
            Some(_) => return ApplyResult::ClaimedCost("temINVALID_COUNT"),
            None => return ApplyResult::ClaimedCost("temINVALID_COUNT"),
        },
    };

    for i in 0..count {
        let ticket_seq = tx.sequence + i;
        let ticket_key = crate::ledger::ticket::shamap_key(&tx.account, ticket_seq);
        let owner_node = directory::dir_add(state, &tx.account, ticket_key.0);
        let ticket = crate::ledger::Ticket {
            account:  tx.account,
            sequence: ticket_seq,
            owner_node,
            previous_txn_id: [0u8; 32],
            previous_txn_lgrseq: 0,
            raw_sle: None,
        };
        state.insert_ticket(ticket);
        new_sender.owner_count += 1;
    }

    ApplyResult::Success
}
