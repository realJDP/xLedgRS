use super::{TxHandler, TER};
use crate::ledger::keylet;
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use std::sync::Arc;

pub struct AccountSetHandler;

impl TxHandler for AccountSetHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        // Can't set and clear the same flag
        if let (Some(sf), Some(cf)) = (tx.set_flag, tx.clear_flag) {
            if sf == cf {
                return Err(TER::Malformed("temINVALID_FLAG"));
            }
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
            if ts == 0 {
                sender.remove_field(16, 8);
            } else {
                // TickSize is UInt8 (type=16, field=8)
                sender.set_field_raw_pub(16, 8, &[ts]);
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
        1 => Some(0x00010000),     // asfRequireDest -> lsfRequireDestTag
        2 => Some(0x00020000),     // asfRequireAuth -> lsfRequireAuth
        3 => Some(0x00040000),     // asfDisallowXRP -> lsfDisallowXRP
        4 => Some(0x00100000),     // asfDisableMaster -> lsfDisableMaster
        5 => Some(0x00200000),     // asfNoFreeze -> lsfNoFreeze (one-way!)
        6 => Some(0x00400000),     // asfGlobalFreeze -> lsfGlobalFreeze
        7 => Some(0x00800000),     // asfDefaultRipple -> lsfDefaultRipple
        8 => Some(0x01000000),     // asfDepositAuth -> lsfDepositAuth
        9 => Some(0x02000000),     // asfAuthorizedNFTokenMinter (not a simple flag)
        10 => Some(0x04000000),    // asfDisallowIncomingNFTokenOffer
        12 => Some(0x10000000),    // asfDisallowIncomingCheck
        13 => Some(0x20000000),    // asfDisallowIncomingPayChan
        14 => Some(0x40000000),    // asfDisallowIncomingTrustline
        15 => Some(0x80000000u32), // asfAllowTrustLineClawback
        _ => None,
    }
}
