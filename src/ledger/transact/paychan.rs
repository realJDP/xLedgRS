use super::{check_reserve, owner_dir, TecCode, TxHandler, TER};
use crate::ledger::keylet;
use crate::ledger::sle::{LedgerEntryType, SLE};
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use std::sync::Arc;

const TF_RENEW: u32 = 0x0001_0000;
const TF_CLOSE: u32 = 0x0002_0000;

pub struct PayChanCreateHandler;

impl TxHandler for PayChanCreateHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        if tx.destination.is_none() {
            return Err(TER::Malformed("temDST_NEEDED"));
        }
        if tx.amount_drops.is_none() {
            return Err(TER::Malformed("temBAD_AMOUNT"));
        }
        if tx.settle_delay.is_none() {
            return Err(TER::Malformed("temBAD_EXPIRATION"));
        }
        if tx.public_key.is_none() {
            return Err(TER::Malformed("temMALFORMED"));
        }
        Ok(())
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let dest_id = tx.destination.unwrap();
        let drops = tx.amount_drops.unwrap();
        let settle_delay = tx.settle_delay.unwrap();
        let pub_key = tx.public_key.as_ref().unwrap();

        // Debit sender
        let sender_keylet = keylet::account(&tx.account);
        let sender_sle = match view.peek(&sender_keylet) {
            Some(s) => s,
            None => return TER::LocalFail("terNO_ACCOUNT"),
        };
        let balance = sender_sle.balance_xrp().unwrap_or(0);
        if balance < drops {
            return TER::ClaimedCost(TecCode::Unfunded);
        }
        // Reserve check — sender must afford one more owned object after deduction
        if let Err(ter) = check_reserve(balance - drops, sender_sle.owner_count(), 1, view.fees()) {
            return ter;
        }
        let mut sender = (*sender_sle).clone();
        sender.set_balance_xrp(balance - drops);
        sender.set_owner_count(sender.owner_count() + 1);
        view.update(Arc::new(sender));

        let chan_keylet = keylet::paychan(&tx.account, &dest_id, tx.sequence);
        let owner_node = owner_dir::dir_add(view, &tx.account, chan_keylet.key.0);
        let destination_node = if dest_id != tx.account {
            owner_dir::dir_add(view, &dest_id, chan_keylet.key.0)
        } else {
            0
        };

        // Create paychan SLE
        let mut data = Vec::with_capacity(128);
        crate::ledger::meta::write_field_header(&mut data, 1, 1);
        data.extend_from_slice(&0x0078u16.to_be_bytes()); // PayChannel
        crate::ledger::meta::write_field_header(&mut data, 2, 2);
        data.extend_from_slice(&0u32.to_be_bytes()); // Flags
        crate::ledger::meta::write_field_header(&mut data, 2, 4);
        data.extend_from_slice(&tx.sequence.to_be_bytes()); // Sequence
        crate::ledger::meta::write_field_header(&mut data, 2, 39);
        data.extend_from_slice(&settle_delay.to_be_bytes()); // SettleDelay
        crate::ledger::meta::write_field_header(&mut data, 3, 4);
        data.extend_from_slice(&owner_node.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 3, 9);
        data.extend_from_slice(&destination_node.to_be_bytes());
        // Amount
        crate::ledger::meta::write_field_header(&mut data, 6, 1);
        data.extend_from_slice(&(drops | 0x4000_0000_0000_0000).to_be_bytes());
        // Balance = 0
        crate::ledger::meta::write_field_header(&mut data, 6, 2);
        data.extend_from_slice(&(0u64 | 0x4000_0000_0000_0000).to_be_bytes());
        // PublicKey (VL)
        crate::ledger::meta::write_field_header(&mut data, 7, 1);
        crate::ledger::meta::encode_vl_length(&mut data, pub_key.len());
        data.extend_from_slice(pub_key);
        // Account
        crate::ledger::meta::write_field_header(&mut data, 8, 1);
        crate::ledger::meta::encode_vl_length(&mut data, 20);
        data.extend_from_slice(&tx.account);
        // Destination
        crate::ledger::meta::write_field_header(&mut data, 8, 3);
        crate::ledger::meta::encode_vl_length(&mut data, 20);
        data.extend_from_slice(&dest_id);

        view.insert(Arc::new(SLE::new(
            chan_keylet.key,
            LedgerEntryType::PayChannel,
            data,
        )));

        TER::Success
    }
}

pub struct PayChanFundHandler;

impl TxHandler for PayChanFundHandler {
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let chan_id = match tx.channel {
            Some(id) => id,
            None => return TER::Malformed("temMALFORMED"),
        };
        let add_drops = match tx.amount_drops {
            Some(d) if d > 0 => d,
            _ => return TER::Malformed("temBAD_AMOUNT"),
        };

        // Look up channel
        let chan_keylet =
            keylet::Keylet::new(crate::ledger::Key(chan_id), LedgerEntryType::PayChannel);
        let chan_sle = match view.peek(&chan_keylet) {
            Some(s) => s,
            None => return TER::ClaimedCost(TecCode::NoEntry),
        };
        let src_id = chan_sle.account_id().unwrap_or([0u8; 20]);
        let dst_id = chan_sle.get_field_account(8, 3).unwrap_or([0u8; 20]);
        let expiration = chan_sle.get_field_u32(2, 10).unwrap_or(0);
        let cancel_after = chan_sle.get_field_u32(2, 36).unwrap_or(0);
        let close_time = view.info().close_time as u32;
        if (cancel_after != 0 && close_time >= cancel_after)
            || (expiration != 0 && close_time >= expiration)
        {
            return close_channel(view, &chan_keylet, &chan_sle);
        }
        if src_id != tx.account {
            return TER::ClaimedCost(TecCode::Generic("tecNO_PERMISSION"));
        }

        // Debit sender
        let sender_keylet = keylet::account(&tx.account);
        let sender_sle = match view.peek(&sender_keylet) {
            Some(s) => s,
            None => return TER::LocalFail("terNO_ACCOUNT"),
        };
        let balance = sender_sle.balance_xrp().unwrap_or(0);
        let reserve = view.fees().reserve_base
            + (sender_sle.owner_count() as u64).saturating_mul(view.fees().reserve_inc);
        if balance < reserve {
            return TER::ClaimedCost(TecCode::InsufficientReserve);
        }
        if balance < reserve.saturating_add(add_drops) {
            return TER::ClaimedCost(TecCode::Unfunded);
        }

        if view.read(&keylet::account(&dst_id)).is_none() {
            return TER::ClaimedCost(TecCode::NoDst);
        }

        let mut sender = (*sender_sle).clone();
        sender.set_balance_xrp(balance - add_drops);
        view.update(Arc::new(sender));

        // Increase channel amount
        let mut chan = (*chan_sle).clone();
        let current_amount = chan.get_field_xrp_drops(6, 1).unwrap_or(0);
        chan.set_field_xrp_drops(6, 1, current_amount + add_drops);

        // Update expiration if provided
        if let Some(exp) = tx.expiration {
            let settle_delay = chan.get_field_u32(2, 39).unwrap_or(0);
            let mut min_expiration = close_time.saturating_add(settle_delay);
            if expiration != 0 && expiration < min_expiration {
                min_expiration = expiration;
            }
            if exp < min_expiration {
                return TER::Malformed("temBAD_EXPIRATION");
            }
            chan.set_field_u32(2, 10, exp);
        }

        view.update(Arc::new(chan));
        TER::Success
    }
}

pub struct PayChanClaimHandler;

impl TxHandler for PayChanClaimHandler {
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let chan_id = match tx.channel {
            Some(id) => id,
            None => return TER::Malformed("temMALFORMED"),
        };

        let chan_keylet =
            keylet::Keylet::new(crate::ledger::Key(chan_id), LedgerEntryType::PayChannel);
        let chan_sle = match view.peek(&chan_keylet) {
            Some(s) => s,
            None => return TER::ClaimedCost(TecCode::NoTarget),
        };

        let mut chan = (*chan_sle).clone();

        // Get channel fields from binary SLE
        let chan_amount = chan.get_field_xrp_drops(6, 1).unwrap_or(0);
        let chan_balance = chan.get_field_xrp_drops(6, 2).unwrap_or(0);
        let settle_delay = chan.get_field_u32(2, 39).unwrap_or(0);
        let chan_expiration = chan.get_field_u32(2, 10).unwrap_or(0);
        let cancel_after = chan.get_field_u32(2, 36).unwrap_or(0);
        let dest_id = chan.get_field_account(8, 3).unwrap_or([0u8; 20]);
        let creator_id = chan.account_id().unwrap_or([0u8; 20]);
        let close_time = view.info().close_time as u32;

        if tx.flags & TF_RENEW != 0 && tx.flags & TF_CLOSE != 0 {
            return TER::Malformed("temMALFORMED");
        }
        if (cancel_after != 0 && close_time >= cancel_after)
            || (chan_expiration != 0 && close_time >= chan_expiration)
        {
            return close_channel(view, &chan_keylet, &chan);
        }
        if tx.account != creator_id && tx.account != dest_id {
            return TER::ClaimedCost(TecCode::Generic("tecNO_PERMISSION"));
        }

        // If claim amount provided, advance balance and credit destination
        if let Some(claimed_drops) = crate::transaction::parse::parsed_paychan_balance_drops(tx) {
            if claimed_drops > chan_amount {
                return TER::ClaimedCost(TecCode::Generic("tecUNFUNDED_PAYMENT"));
            }
            if claimed_drops <= chan_balance {
                return TER::ClaimedCost(TecCode::Generic("tecUNFUNDED_PAYMENT"));
            }
            if dest_id == tx.account && tx.paychan_sig.is_none() {
                return TER::Malformed("temBAD_SIGNATURE");
            }

            let delta = claimed_drops.saturating_sub(chan_balance);
            chan.set_field_xrp_drops(6, 2, claimed_drops); // update balance

            // Credit destination
            if delta > 0 {
                let dest_keylet = keylet::account(&dest_id);
                if let Some(dest_sle) = view.peek(&dest_keylet) {
                    let mut dest = (*dest_sle).clone();
                    let bal = dest.balance_xrp().unwrap_or(0);
                    dest.set_balance_xrp(bal + delta);
                    view.update(Arc::new(dest));
                }
            }
        } else if tx.paychan_sig.is_some() {
            return TER::Malformed("temMALFORMED");
        }

        if tx.flags & TF_RENEW != 0 {
            if creator_id != tx.account {
                return TER::ClaimedCost(TecCode::Generic("tecNO_PERMISSION"));
            }
            chan.remove_field(2, 10);
        }

        if tx.flags & TF_CLOSE != 0 {
            if dest_id == tx.account || chan.get_field_xrp_drops(6, 2).unwrap_or(0) >= chan_amount {
                return close_channel(view, &chan_keylet, &chan);
            }
            let settle_expiration = close_time.saturating_add(settle_delay);
            if chan_expiration == 0 || chan_expiration > settle_expiration {
                chan.set_field_u32(2, 10, settle_expiration);
            }
        }

        view.update(Arc::new(chan));
        TER::Success
    }
}

fn close_channel(view: &mut dyn ApplyView, chan_keylet: &keylet::Keylet, chan: &SLE) -> TER {
    let chan_amount = chan.get_field_xrp_drops(6, 1).unwrap_or(0);
    let chan_balance = chan.get_field_xrp_drops(6, 2).unwrap_or(0);
    let dest_id = chan.get_field_account(8, 3).unwrap_or([0u8; 20]);
    let creator_id = chan.account_id().unwrap_or([0u8; 20]);

    owner_dir::dir_remove(view, &creator_id, &chan_keylet.key.0);
    if dest_id != creator_id {
        owner_dir::dir_remove(view, &dest_id, &chan_keylet.key.0);
    }

    let creator_keylet = keylet::account(&creator_id);
    if let Some(creator_sle) = view.peek(&creator_keylet) {
        let mut creator = (*creator_sle).clone();
        let bal = creator.balance_xrp().unwrap_or(0);
        creator.set_balance_xrp(bal.saturating_add(chan_amount.saturating_sub(chan_balance)));
        creator.set_owner_count(creator.owner_count().saturating_sub(1));
        view.update(Arc::new(creator));
    }
    view.erase(&chan_keylet.key);
    TER::Success
}
