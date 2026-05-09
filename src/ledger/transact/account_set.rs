use super::{TecCode, TxHandler, TER};
use crate::ledger::account::{
    LSF_ALLOW_TRUST_LINE_CLAWBACK, LSF_ALLOW_TRUST_LINE_LOCKING, LSF_DEFAULT_RIPPLE,
    LSF_DEPOSIT_AUTH, LSF_DISABLE_MASTER, LSF_DISALLOW_XRP, LSF_GLOBAL_FREEZE, LSF_NO_FREEZE,
    LSF_REQUIRE_AUTH, LSF_REQUIRE_DEST_TAG,
};
use crate::ledger::keylet;
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use std::sync::Arc;

pub struct AccountSetHandler;

const LSF_AUTHORIZED_NFTOKEN_MINTER: u32 = 0x0200_0000;
const LSF_DISALLOW_INCOMING_NFTOKEN_OFFER: u32 = 0x0400_0000;
const LSF_DISALLOW_INCOMING_CHECK: u32 = 0x0800_0000;
const LSF_DISALLOW_INCOMING_PAYCHAN: u32 = 0x1000_0000;
const LSF_DISALLOW_INCOMING_TRUSTLINE: u32 = 0x2000_0000;
const ASF_REQUIRE_AUTH: u32 = 2;
const ASF_REQUIRE_DEST: u32 = 1;
const ASF_DISALLOW_XRP: u32 = 3;
const TF_REQUIRE_DEST_TAG: u32 = 0x0001_0000;
const TF_OPTIONAL_DEST_TAG: u32 = 0x0002_0000;
const TF_REQUIRE_AUTH: u32 = 0x0004_0000;
const TF_OPTIONAL_AUTH: u32 = 0x0008_0000;
const TF_DISALLOW_XRP: u32 = 0x0010_0000;
const TF_ALLOW_XRP: u32 = 0x0020_0000;

fn valid_account_set_flag(flag: u32) -> bool {
    matches!(flag, 1..=10 | 12..=17)
}

impl TxHandler for AccountSetHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        // Can't set and clear the same flag
        if let (Some(sf), Some(cf)) = (tx.set_flag, tx.clear_flag) {
            if sf == cf {
                return Err(TER::Malformed("temINVALID_FLAG"));
            }
        }
        if tx
            .set_flag
            .is_some_and(|flag| !valid_account_set_flag(flag))
            || tx
                .clear_flag
                .is_some_and(|flag| !valid_account_set_flag(flag))
        {
            return Err(TER::Malformed("temINVALID_FLAG"));
        }
        if legacy_flag_pair_conflicts(tx) {
            return Err(TER::Malformed("temINVALID_FLAG"));
        }
        if let Some(rate) = tx.transfer_rate {
            const QUALITY_ONE: u32 = 1_000_000_000;
            if rate != 0 && (rate < QUALITY_ONE || rate > 2 * QUALITY_ONE) {
                return Err(TER::Malformed("temBAD_TRANSFER_RATE"));
            }
        }
        if let Some(tick_size) = tx.tick_size {
            if tick_size != 0 && !(3..=16).contains(&tick_size) {
                return Err(TER::Malformed("temBAD_TICK_SIZE"));
            }
        }
        if tx.domain.as_ref().is_some_and(|domain| domain.len() > 256) {
            return Err(TER::LocalFail("telBAD_DOMAIN"));
        }
        Ok(())
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let sender_keylet = keylet::account(&tx.account);
        let sender_sle = match view.peek(&sender_keylet) {
            Some(s) => s,
            None => return TER::LocalFail("terNO_ACCOUNT"),
        };

        let mut sender = (*sender_sle).clone();
        let mut flags = sender.flags();

        if account_set_sets_require_auth(tx)
            && (flags & LSF_REQUIRE_AUTH) == 0
            && sender.owner_count() != 0
        {
            return TER::ClaimedCost(TecCode::OwnersFull);
        }
        if tx.clear_flag == Some(6) && (flags & LSF_NO_FREEZE) != 0 {
            return TER::ClaimedCost(TecCode::Generic("tecNO_PERMISSION"));
        }

        if legacy_flag_pair_conflicts(tx) {
            return TER::Malformed("temINVALID_FLAG");
        }

        if account_set_sets_require_auth(tx) {
            flags |= LSF_REQUIRE_AUTH;
        }
        if account_set_clears_require_auth(tx) {
            flags &= !LSF_REQUIRE_AUTH;
        }
        if account_set_sets_require_dest(tx) {
            flags |= LSF_REQUIRE_DEST_TAG;
        }
        if account_set_clears_require_dest(tx) {
            flags &= !LSF_REQUIRE_DEST_TAG;
        }
        if account_set_sets_disallow_xrp(tx) {
            flags |= LSF_DISALLOW_XRP;
        }
        if account_set_clears_disallow_xrp(tx) {
            flags &= !LSF_DISALLOW_XRP;
        }

        // SetFlag / ClearFlag
        if let Some(sf) = tx.set_flag {
            // Map AccountSet flags to ledger flags (matching rippled)
            let ledger_flag = account_set_flag_to_ledger(sf);
            if let Some(lf) = ledger_flag {
                flags |= lf;
            }
        }
        if let Some(cf) = tx.clear_flag {
            let ledger_flag = account_set_flag_to_ledger(cf);
            if let Some(lf) = ledger_flag {
                flags &= !lf;
            }
        }
        sender.set_flags(flags);

        // TransferRate
        if let Some(rate) = tx.transfer_rate {
            if rate == 0 || rate == 1_000_000_000 {
                sender.remove_field(2, 11); // remove TransferRate (= default)
            } else {
                sender.set_field_u32(2, 11, rate);
            }
        }

        // TickSize
        if let Some(ts) = tx.tick_size {
            if ts == 0 || ts == 16 {
                sender.remove_field(16, 16);
            } else {
                sender.set_field_raw_pub(16, 16, &[ts]);
            }
        }

        // Domain
        if let Some(ref domain) = tx.domain {
            if domain.is_empty() {
                sender.remove_field(7, 7); // remove Domain
            } else {
                sender.set_field_raw_pub(7, 7, domain); // VL type
            }
        }

        view.update(Arc::new(sender));
        TER::Success
    }
}

/// Map AccountSet flag numbers to ledger state flags (from rippled AccountSet.cpp).
pub fn account_set_flag_to_ledger(flag: u32) -> Option<u32> {
    match flag {
        1 => Some(LSF_REQUIRE_DEST_TAG),
        2 => Some(LSF_REQUIRE_AUTH),
        3 => Some(LSF_DISALLOW_XRP),
        4 => Some(LSF_DISABLE_MASTER),
        5 => None, // AccountTxnID is a field toggle, not an AccountRoot flag.
        6 => Some(LSF_NO_FREEZE),
        7 => Some(LSF_GLOBAL_FREEZE),
        8 => Some(LSF_DEFAULT_RIPPLE),
        9 => Some(LSF_DEPOSIT_AUTH),
        10 => Some(LSF_AUTHORIZED_NFTOKEN_MINTER),
        12 => Some(LSF_DISALLOW_INCOMING_NFTOKEN_OFFER),
        13 => Some(LSF_DISALLOW_INCOMING_CHECK),
        14 => Some(LSF_DISALLOW_INCOMING_PAYCHAN),
        15 => Some(LSF_DISALLOW_INCOMING_TRUSTLINE),
        16 => Some(LSF_ALLOW_TRUST_LINE_CLAWBACK),
        17 => Some(LSF_ALLOW_TRUST_LINE_LOCKING),
        _ => None,
    }
}

fn legacy_flag_pair_conflicts(tx: &ParsedTx) -> bool {
    account_set_sets_require_auth(tx) && account_set_clears_require_auth(tx)
        || account_set_sets_require_dest(tx) && account_set_clears_require_dest(tx)
        || account_set_sets_disallow_xrp(tx) && account_set_clears_disallow_xrp(tx)
}

fn account_set_sets_require_auth(tx: &ParsedTx) -> bool {
    (tx.flags & TF_REQUIRE_AUTH) != 0 || tx.set_flag == Some(ASF_REQUIRE_AUTH)
}

fn account_set_clears_require_auth(tx: &ParsedTx) -> bool {
    (tx.flags & TF_OPTIONAL_AUTH) != 0 || tx.clear_flag == Some(ASF_REQUIRE_AUTH)
}

fn account_set_sets_require_dest(tx: &ParsedTx) -> bool {
    (tx.flags & TF_REQUIRE_DEST_TAG) != 0 || tx.set_flag == Some(ASF_REQUIRE_DEST)
}

fn account_set_clears_require_dest(tx: &ParsedTx) -> bool {
    (tx.flags & TF_OPTIONAL_DEST_TAG) != 0 || tx.clear_flag == Some(ASF_REQUIRE_DEST)
}

fn account_set_sets_disallow_xrp(tx: &ParsedTx) -> bool {
    (tx.flags & TF_DISALLOW_XRP) != 0 || tx.set_flag == Some(ASF_DISALLOW_XRP)
}

fn account_set_clears_disallow_xrp(tx: &ParsedTx) -> bool {
    (tx.flags & TF_ALLOW_XRP) != 0 || tx.clear_flag == Some(ASF_DISALLOW_XRP)
}
