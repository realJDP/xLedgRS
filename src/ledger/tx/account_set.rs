//! xLedgRS purpose: Account Set transaction engine logic for ledger replay.
//! AccountSet / SetRegularKey — IMPLEMENTED

use super::ApplyResult;
use crate::transaction::ParsedTx;

/// Map SetFlag/ClearFlag values to the corresponding lsf* account flag bit.
/// From rippled: AccountSet.cpp / LedgerFormats.h
fn account_flag_to_bit(flag: u32) -> u32 {
    match flag {
        1 => 0x00010000,  // asfRequireDest → lsfRequireDestTag
        2 => 0x00020000,  // asfRequireAuth → lsfRequireAuth
        3 => 0x00040000,  // asfDisallowXRP → lsfDisallowXRP
        4 => 0x00080000,  // asfDisableMaster → lsfDisableMaster
        5 => 0x00100000,  // asfAccountTxnID (no lsf bit — handled differently)
        6 => 0x00200000,  // asfNoFreeze → lsfNoFreeze
        7 => 0x00400000,  // asfGlobalFreeze → lsfGlobalFreeze
        8 => 0x00800000,  // asfDefaultRipple → lsfDefaultRipple
        9 => 0x01000000,  // asfDepositAuth → lsfDepositAuth
        10 => 0x02000000, // asfAuthorizedNFTokenMinter
        12 => 0x04000000, // asfDisallowIncomingNFTokenOffer
        13 => 0x08000000, // asfDisallowIncomingCheck
        14 => 0x10000000, // asfDisallowIncomingPayChan
        15 => 0x20000000, // asfDisallowIncomingTrustline
        16 => 0x40000000, // asfAllowTrustLineClawback
        _ => 0,
    }
}

/// Apply an AccountSet: modify account flags.
///
/// XRPL `AccountSet` uses `SetFlag` and `ClearFlag` fields. This handler
/// works directly with the resulting account flags.
pub(crate) fn apply_account_set(
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    // Validation (rippled: AccountSet.cpp preflight)

    // SetFlag == ClearFlag → temINVALID_FLAG
    if let (Some(sf), Some(cf)) = (tx.set_flag, tx.clear_flag) {
        if sf == cf {
            return ApplyResult::ClaimedCost("temINVALID_FLAG");
        }
    }

    // TransferRate validation
    if let Some(rate) = tx.transfer_rate {
        const QUALITY_ONE: u32 = 1_000_000_000;
        if rate != 0 && (rate < QUALITY_ONE || rate > 2 * QUALITY_ONE) {
            return ApplyResult::ClaimedCost("temBAD_TRANSFER_RATE");
        }
        new_sender.transfer_rate = rate;
    }

    // TickSize validation
    if let Some(tick) = tx.tick_size {
        if tick != 0 && (tick < 3 || tick > 15) {
            return ApplyResult::ClaimedCost("temBAD_TICK_SIZE");
        }
        new_sender.tick_size = tick;
    }

    // Domain validation
    if let Some(ref domain) = tx.domain {
        if domain.len() > 256 {
            return ApplyResult::ClaimedCost("telBAD_DOMAIN");
        }
        new_sender.domain = domain.clone();
    }

    // Apply SetFlag / ClearFlag to account flags
    // Flag values from rippled AccountSet.cpp / LedgerFormats.h
    if let Some(sf) = tx.set_flag {
        let flag_bit = account_flag_to_bit(sf);
        if flag_bit != 0 {
            new_sender.flags |= flag_bit;
        }
    }
    if let Some(cf) = tx.clear_flag {
        let flag_bit = account_flag_to_bit(cf);
        if flag_bit != 0 {
            new_sender.flags &= !flag_bit;
        }
    }

    ApplyResult::Success
}

/// Apply a SetRegularKey: authorize a secondary signing key.
pub(crate) fn apply_set_regular_key(
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    // Cannot set master key as regular key (rippled: SetRegularKey.cpp, temBAD_REGKEY)
    if let Some(rk) = tx.regular_key {
        if rk == tx.account {
            return ApplyResult::ClaimedCost("temBAD_REGKEY");
        }
    }
    new_sender.regular_key = tx.regular_key;
    ApplyResult::Success
}
