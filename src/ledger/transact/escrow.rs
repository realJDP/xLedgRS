use std::sync::Arc;
use crate::ledger::keylet;
use crate::ledger::sle::{SLE, LedgerEntryType};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use super::{TER, TecCode, TxHandler, check_reserve, owner_dir};

pub struct EscrowCreateHandler;

impl TxHandler for EscrowCreateHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        if tx.amount_drops.is_none() && tx.amount.is_none() {
            return Err(TER::Malformed("temBAD_AMOUNT"));
        }
        if tx.destination.is_none() {
            return Err(TER::Malformed("temDST_NEEDED"));
        }
        if tx.finish_after.is_none() && tx.cancel_after.is_none() {
            return Err(TER::Malformed("temBAD_EXPIRATION"));
        }
        Ok(())
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let dest_id = tx.destination.unwrap();
        let drops = tx.amount_drops.unwrap_or(0);
        if drops == 0 { return TER::Malformed("temBAD_AMOUNT"); }

        // Reserve check — sender must afford one more owned object
        let sender_keylet = keylet::account(&tx.account);
        let sender_sle = match view.peek(&sender_keylet) {
            Some(s) => s,
            None => return TER::LocalFail("terNO_ACCOUNT"),
        };
        let balance = sender_sle.balance_xrp().unwrap_or(0);
        if balance < drops {
            return TER::ClaimedCost(TecCode::Unfunded);
        }
        // Reserve: must afford current objects + 1 new escrow
        if let Err(ter) = check_reserve(balance - drops, sender_sle.owner_count(), 1, view.fees()) {
            return ter;
        }
        let mut sender = (*sender_sle).clone();
        sender.set_balance_xrp(balance - drops);

        // Bump owner count
        let oc = sender.owner_count();
        sender.set_owner_count(oc + 1);
        view.update(Arc::new(sender));

        let seq = tx.sequence;
        let escrow_keylet = keylet::escrow(&tx.account, seq);
        let owner_node = owner_dir::dir_add(view, &tx.account, escrow_keylet.key.0);
        let destination_node = if dest_id != tx.account {
            owner_dir::dir_add(view, &dest_id, escrow_keylet.key.0)
        } else {
            0
        };

        // Create escrow SLE
        let mut data = Vec::with_capacity(128);
        // LedgerEntryType = Escrow (0x0075)
        crate::ledger::meta::write_field_header(&mut data, 1, 1);
        data.extend_from_slice(&0x0075u16.to_be_bytes());
        // Flags = 0
        crate::ledger::meta::write_field_header(&mut data, 2, 2);
        data.extend_from_slice(&0u32.to_be_bytes());
        // Sequence
        crate::ledger::meta::write_field_header(&mut data, 2, 4);
        data.extend_from_slice(&seq.to_be_bytes());
        // FinishAfter (optional)
        if let Some(fa) = tx.finish_after {
            crate::ledger::meta::write_field_header(&mut data, 2, 37);
            data.extend_from_slice(&fa.to_be_bytes());
        }
        // CancelAfter (optional)
        if let Some(ca) = tx.cancel_after {
            crate::ledger::meta::write_field_header(&mut data, 2, 36);
            data.extend_from_slice(&ca.to_be_bytes());
        }
        crate::ledger::meta::write_field_header(&mut data, 3, 4);
        data.extend_from_slice(&owner_node.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 3, 9);
        data.extend_from_slice(&destination_node.to_be_bytes());
        // Amount (XRP)
        crate::ledger::meta::write_field_header(&mut data, 6, 1);
        let amt_wire = drops | 0x4000_0000_0000_0000;
        data.extend_from_slice(&amt_wire.to_be_bytes());
        // Account
        crate::ledger::meta::write_field_header(&mut data, 8, 1);
        crate::ledger::meta::encode_vl_length(&mut data, 20);
        data.extend_from_slice(&tx.account);
        // Destination
        crate::ledger::meta::write_field_header(&mut data, 8, 3);
        crate::ledger::meta::encode_vl_length(&mut data, 20);
        data.extend_from_slice(&dest_id);

        let sle = SLE::new(escrow_keylet.key, LedgerEntryType::Escrow, data);
        view.insert(Arc::new(sle));

        TER::Success
    }
}

pub struct EscrowFinishHandler;

impl TxHandler for EscrowFinishHandler {
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let owner = tx.owner.unwrap_or(tx.account);
        let seq = tx.offer_sequence.unwrap_or(tx.sequence);
        let escrow_keylet = keylet::escrow(&owner, seq);

        let escrow_sle = match view.peek(&escrow_keylet) {
            Some(s) => s,
            None => return TER::ClaimedCost(TecCode::NoEntry),
        };

        // Get amount from escrow SLE (sfAmount type=6, field=1)
        let drops = escrow_sle.get_field_xrp_drops(6, 1).unwrap_or(0);

        // Get destination from escrow SLE (sfDestination type=8, field=3)
        let dest_id = match escrow_sle.get_field_account(8, 3) {
            Some(d) => d,
            None => return TER::ClaimedCost(TecCode::NoEntry),
        };
        let owner_id = escrow_sle.account_id().unwrap_or(owner);

        // Credit destination
        let dest_keylet = keylet::account(&dest_id);
        match view.peek(&dest_keylet) {
            Some(dest_sle) => {
                let balance = dest_sle.balance_xrp().unwrap_or(0);
                let mut dest = (*dest_sle).clone();
                dest.set_balance_xrp(balance + drops);
                view.update(Arc::new(dest));
            }
            None => return TER::ClaimedCost(TecCode::NoDst),
        }

        owner_dir::dir_remove(view, &owner_id, &escrow_keylet.key.0);
        if dest_id != owner_id {
            owner_dir::dir_remove(view, &dest_id, &escrow_keylet.key.0);
        }

        // Remove escrow
        view.erase(&escrow_keylet.key);

        // Decrement owner's owner_count
        let owner_keylet = keylet::account(&owner_id);
        if let Some(owner_sle) = view.peek(&owner_keylet) {
            let mut o = (*owner_sle).clone();
            let oc = o.owner_count();
            o.set_owner_count(oc.saturating_sub(1));
            view.update(Arc::new(o));
        }

        TER::Success
    }
}

pub struct EscrowCancelHandler;

impl TxHandler for EscrowCancelHandler {
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let owner = tx.owner.unwrap_or(tx.account);
        let seq = tx.offer_sequence.unwrap_or(tx.sequence);
        let escrow_keylet = keylet::escrow(&owner, seq);

        let escrow_sle = match view.peek(&escrow_keylet) {
            Some(s) => s,
            None => return TER::ClaimedCost(TecCode::NoEntry),
        };

        let drops = escrow_sle.get_field_xrp_drops(6, 1).unwrap_or(0);
        let dest_id = escrow_sle.get_field_account(8, 3).unwrap_or(owner);

        // Refund to owner
        let owner_keylet = keylet::account(&owner);
        match view.peek(&owner_keylet) {
            Some(owner_sle) => {
                let balance = owner_sle.balance_xrp().unwrap_or(0);
                let mut o = (*owner_sle).clone();
                o.set_balance_xrp(balance + drops);
                let oc = o.owner_count();
                o.set_owner_count(oc.saturating_sub(1));
                view.update(Arc::new(o));
            }
            None => return TER::LocalFail("terNO_ACCOUNT"),
        }

        owner_dir::dir_remove(view, &owner, &escrow_keylet.key.0);
        if dest_id != owner {
            owner_dir::dir_remove(view, &dest_id, &escrow_keylet.key.0);
        }

        // Remove escrow
        view.erase(&escrow_keylet.key);

        TER::Success
    }
}
