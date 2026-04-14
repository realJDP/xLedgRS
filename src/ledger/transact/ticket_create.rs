use std::sync::Arc;
use crate::ledger::keylet;
use crate::ledger::sle::SLE;
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use super::{TER, TxHandler, check_reserve, owner_dir};

pub struct TicketCreateHandler;

impl TxHandler for TicketCreateHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        match tx.ticket_count {
            Some(count) if count >= 1 && count <= 250 => Ok(()),
            _ => Err(TER::Malformed("temINVALID_COUNT")),
        }
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let count = tx.ticket_count.unwrap();
        let sender_keylet = keylet::account(&tx.account);
        let sender_sle = match view.peek(&sender_keylet) {
            Some(s) => s,
            None => return TER::LocalFail("terNO_ACCOUNT"),
        };

        // Reserve check — sender must afford `count` more owned objects
        let balance = sender_sle.balance_xrp().unwrap_or(0);
        if let Err(ter) = check_reserve(balance, sender_sle.owner_count(), count, view.fees()) {
            return ter;
        }

        let sequence = sender_sle.sequence().unwrap_or(0);
        let mut sender = (*sender_sle).clone();

        // Create ticket SLEs
        for i in 0..count {
            let ticket_seq = sequence + 1 + i;
            let ticket_keylet = keylet::ticket(&tx.account, ticket_seq);
            let owner_node = owner_dir::dir_add(view, &tx.account, ticket_keylet.key.0);

            // Build ticket SLE binary
            let mut data = Vec::with_capacity(48);
            // LedgerEntryType = Ticket (0x0054)
            crate::ledger::meta::write_field_header(&mut data, 1, 1);
            data.extend_from_slice(&0x0054u16.to_be_bytes());
            // Flags = 0
            crate::ledger::meta::write_field_header(&mut data, 2, 2);
            data.extend_from_slice(&0u32.to_be_bytes());
            // TicketSequence
            crate::ledger::meta::write_field_header(&mut data, 2, 41);
            data.extend_from_slice(&ticket_seq.to_be_bytes());
            crate::ledger::meta::write_field_header(&mut data, 3, 4);
            data.extend_from_slice(&owner_node.to_be_bytes());
            // Account
            crate::ledger::meta::write_field_header(&mut data, 8, 1);
            crate::ledger::meta::encode_vl_length(&mut data, 20);
            data.extend_from_slice(&tx.account);

            let sle = SLE::new(
                ticket_keylet.key,
                crate::ledger::sle::LedgerEntryType::Ticket,
                data,
            );
            view.insert(Arc::new(sle));
        }

        // Bump owner count
        let oc = sender.owner_count();
        sender.set_owner_count(oc + count);

        // Update TicketCount on account
        let tc = sender.get_field_u32(2, 40).unwrap_or(0);
        sender.set_field_u32(2, 40, tc + count);

        view.update(Arc::new(sender));
        TER::Success
    }
}
