//! AccountSet / SetRegularKey — IMPLEMENTED

use super::ApplyResult;
use crate::ledger::account::{
    LSF_ALLOW_TRUST_LINE_CLAWBACK, LSF_ALLOW_TRUST_LINE_LOCKING, LSF_DEFAULT_RIPPLE,
    LSF_DEPOSIT_AUTH, LSF_DISABLE_MASTER, LSF_DISALLOW_INCOMING_TRUSTLINE, LSF_DISALLOW_XRP,
    LSF_GLOBAL_FREEZE, LSF_NO_FREEZE, LSF_PASSWORD_SPENT, LSF_REQUIRE_AUTH, LSF_REQUIRE_DEST_TAG,
};
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

const ASF_REQUIRE_AUTH: u32 = 2;
const ASF_DISABLE_MASTER: u32 = 4;
const ASF_NO_FREEZE: u32 = 6;
const ASF_GLOBAL_FREEZE: u32 = 7;
const ASF_AUTHORIZED_NFTOKEN_MINTER: u32 = 10;
const ASF_ALLOW_TRUST_LINE_CLAWBACK: u32 = 16;
const ASF_ALLOW_TRUST_LINE_LOCKING: u32 = 17;
const TF_REQUIRE_DEST_TAG: u32 = 0x0001_0000;
const TF_OPTIONAL_DEST_TAG: u32 = 0x0002_0000;
const TF_REQUIRE_AUTH: u32 = 0x0004_0000;
const TF_OPTIONAL_AUTH: u32 = 0x0008_0000;
const TF_DISALLOW_XRP: u32 = 0x0010_0000;
const TF_ALLOW_XRP: u32 = 0x0020_0000;
const TF_UNIVERSAL: u32 = 0xC000_0000;
const TF_ACCOUNT_SET_ALLOWED: u32 = TF_UNIVERSAL
    | TF_REQUIRE_DEST_TAG
    | TF_OPTIONAL_DEST_TAG
    | TF_REQUIRE_AUTH
    | TF_OPTIONAL_AUTH
    | TF_DISALLOW_XRP
    | TF_ALLOW_XRP;

pub(crate) fn valid_account_set_flag(flag: u32) -> bool {
    matches!(flag, 1..=10 | 12..=17)
}

pub(crate) fn account_set_flags_are_valid(flags: u32) -> bool {
    (flags & !TF_ACCOUNT_SET_ALLOWED) == 0
}

/// Map SetFlag/ClearFlag values to the corresponding lsf* account flag bit.
/// From rippled: AccountSet.cpp / LedgerFormats.h
fn account_flag_to_bit(flag: u32) -> u32 {
    match flag {
        1 => LSF_REQUIRE_DEST_TAG,
        2 => LSF_REQUIRE_AUTH,
        3 => LSF_DISALLOW_XRP,
        4 => LSF_DISABLE_MASTER,
        5 => 0, // asfAccountTxnID is not represented by an AccountRoot flag bit here.
        6 => LSF_NO_FREEZE,
        7 => LSF_GLOBAL_FREEZE,
        8 => LSF_DEFAULT_RIPPLE,
        9 => LSF_DEPOSIT_AUTH,
        10 => 0x02000000, // asfAuthorizedNFTokenMinter
        12 => 0x04000000, // asfDisallowIncomingNFTokenOffer
        13 => 0x08000000, // asfDisallowIncomingCheck
        14 => 0x10000000, // asfDisallowIncomingPayChan
        15 => LSF_DISALLOW_INCOMING_TRUSTLINE,
        16 => LSF_ALLOW_TRUST_LINE_CLAWBACK,
        17 => LSF_ALLOW_TRUST_LINE_LOCKING,
        _ => 0,
    }
}

/// Apply an AccountSet: modify account flags.
///
/// XRPL `AccountSet` uses `SetFlag` and `ClearFlag` fields. This handler
/// works directly with the resulting account flags.
pub(crate) fn apply_account_set(
    state: &LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    clawback_enabled: bool,
    token_escrow_enabled: bool,
) -> ApplyResult {
    // Validation (rippled: AccountSet.cpp preflight)
    if !account_set_flags_are_valid(tx.flags) {
        return ApplyResult::ClaimedCost("temINVALID_FLAG");
    }

    // SetFlag == ClearFlag → temINVALID_FLAG
    if let (Some(sf), Some(cf)) = (tx.set_flag, tx.clear_flag) {
        if sf == cf {
            return ApplyResult::ClaimedCost("temINVALID_FLAG");
        }
    }
    if tx
        .set_flag
        .is_some_and(|flag| !valid_account_set_flag(flag))
        || tx
            .clear_flag
            .is_some_and(|flag| !valid_account_set_flag(flag))
    {
        return ApplyResult::ClaimedCost("temINVALID_FLAG");
    }
    if !token_escrow_enabled
        && (tx.set_flag == Some(ASF_ALLOW_TRUST_LINE_LOCKING)
            || tx.clear_flag == Some(ASF_ALLOW_TRUST_LINE_LOCKING))
    {
        return ApplyResult::ClaimedCost("temDISABLED");
    }
    if account_set_sets_require_auth(tx)
        && (new_sender.flags & LSF_REQUIRE_AUTH) == 0
        && new_sender.owner_count != 0
    {
        return ApplyResult::ClaimedCost("tecOWNERS");
    }
    if tx.clear_flag == Some(ASF_NO_FREEZE) && (new_sender.flags & LSF_NO_FREEZE) != 0 {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if clawback_enabled
        && tx.set_flag == Some(ASF_ALLOW_TRUST_LINE_CLAWBACK)
        && (new_sender.flags & LSF_ALLOW_TRUST_LINE_CLAWBACK) == 0
        && (new_sender.flags & LSF_NO_FREEZE) != 0
    {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if clawback_enabled
        && tx.set_flag == Some(ASF_ALLOW_TRUST_LINE_CLAWBACK)
        && (new_sender.flags & LSF_ALLOW_TRUST_LINE_CLAWBACK) == 0
        && new_sender.owner_count != 0
    {
        return ApplyResult::ClaimedCost("tecOWNERS");
    }
    if clawback_enabled
        && tx.set_flag == Some(ASF_NO_FREEZE)
        && (new_sender.flags & LSF_ALLOW_TRUST_LINE_CLAWBACK) != 0
    {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if tx.set_flag == Some(ASF_AUTHORIZED_NFTOKEN_MINTER) && tx.nftoken_minter.is_none() {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    if tx.clear_flag == Some(ASF_AUTHORIZED_NFTOKEN_MINTER) && tx.nftoken_minter.is_some() {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    let signed_with_master = signed_with_master_key(tx);
    if tx.set_flag == Some(ASF_DISABLE_MASTER) && (new_sender.flags & LSF_DISABLE_MASTER) == 0 {
        if !signed_with_master {
            return ApplyResult::ClaimedCost("tecNEED_MASTER_KEY");
        }
        if new_sender.regular_key.is_none() && !signer_list_exists(state, &tx.account) {
            return ApplyResult::ClaimedCost("tecNO_ALTERNATIVE_KEY");
        }
    }
    if tx.set_flag == Some(ASF_NO_FREEZE)
        && !signed_with_master
        && (new_sender.flags & LSF_DISABLE_MASTER) == 0
    {
        return ApplyResult::ClaimedCost("tecNEED_MASTER_KEY");
    }

    // TransferRate validation
    if let Some(rate) = tx.transfer_rate {
        const QUALITY_ONE: u32 = 1_000_000_000;
        if rate != 0 && (rate < QUALITY_ONE || rate > 2 * QUALITY_ONE) {
            return ApplyResult::ClaimedCost("temBAD_TRANSFER_RATE");
        }
        new_sender.transfer_rate = if rate == QUALITY_ONE { 0 } else { rate };
    }

    // TickSize validation
    if let Some(tick) = tx.tick_size {
        if tick != 0 && (tick < 3 || tick > 16) {
            return ApplyResult::ClaimedCost("temBAD_TICK_SIZE");
        }
        new_sender.tick_size = if tick == 16 { 0 } else { tick };
    }

    // Domain validation
    if let Some(ref domain) = tx.domain {
        if domain.len() > 256 {
            return ApplyResult::ClaimedCost("telBAD_DOMAIN");
        }
        new_sender.domain = domain.clone();
    }

    if legacy_flag_pair_conflicts(tx) {
        return ApplyResult::ClaimedCost("temINVALID_FLAG");
    }

    if account_set_sets_require_auth(tx) {
        new_sender.flags |= LSF_REQUIRE_AUTH;
    }
    if account_set_clears_require_auth(tx) {
        new_sender.flags &= !LSF_REQUIRE_AUTH;
    }
    if account_set_sets_require_dest(tx) {
        new_sender.flags |= LSF_REQUIRE_DEST_TAG;
    }
    if account_set_clears_require_dest(tx) {
        new_sender.flags &= !LSF_REQUIRE_DEST_TAG;
    }
    if account_set_sets_disallow_xrp(tx) {
        new_sender.flags |= LSF_DISALLOW_XRP;
    }
    if account_set_clears_disallow_xrp(tx) {
        new_sender.flags &= !LSF_DISALLOW_XRP;
    }

    // Apply non-legacy SetFlag / ClearFlag to account flags.
    // Flag values from rippled AccountSet.cpp / LedgerFormats.h.
    if let Some(sf) = tx.set_flag {
        let flag_bit = account_flag_to_bit(sf);
        if flag_bit != 0
            && sf != ASF_GLOBAL_FREEZE
            && (sf != ASF_ALLOW_TRUST_LINE_CLAWBACK || clawback_enabled)
            && (sf != ASF_ALLOW_TRUST_LINE_LOCKING || token_escrow_enabled)
        {
            new_sender.flags |= flag_bit;
        }
    }
    if let Some(cf) = tx.clear_flag {
        let flag_bit = account_flag_to_bit(cf);
        if flag_bit != 0
            && cf != ASF_GLOBAL_FREEZE
            && cf != ASF_NO_FREEZE
            && cf != ASF_ALLOW_TRUST_LINE_CLAWBACK
            && (cf != ASF_ALLOW_TRUST_LINE_LOCKING || token_escrow_enabled)
        {
            new_sender.flags &= !flag_bit;
        }
    }
    if tx.set_flag == Some(ASF_GLOBAL_FREEZE) {
        new_sender.flags |= LSF_GLOBAL_FREEZE;
    } else if tx.clear_flag == Some(ASF_GLOBAL_FREEZE) && (new_sender.flags & LSF_NO_FREEZE) == 0 {
        new_sender.flags &= !LSF_GLOBAL_FREEZE;
    }

    // asfAccountTxnID is a special AccountSet switch: it toggles the
    // AccountRoot sfAccountTxnID field, not an lsf* flag bit.
    match (tx.set_flag, tx.clear_flag) {
        (Some(5), _) => new_sender.ensure_account_txn_id(),
        (_, Some(5)) => new_sender.clear_account_txn_id(),
        _ => {}
    }
    apply_accountset_optional_fields(tx, new_sender);

    ApplyResult::Success
}

pub(crate) fn legacy_flag_pair_conflicts(tx: &ParsedTx) -> bool {
    account_set_sets_require_auth(tx) && account_set_clears_require_auth(tx)
        || account_set_sets_require_dest(tx) && account_set_clears_require_dest(tx)
        || account_set_sets_disallow_xrp(tx) && account_set_clears_disallow_xrp(tx)
}

pub(crate) fn account_set_sets_require_auth(tx: &ParsedTx) -> bool {
    (tx.flags & TF_REQUIRE_AUTH) != 0 || tx.set_flag == Some(ASF_REQUIRE_AUTH)
}

fn account_set_clears_require_auth(tx: &ParsedTx) -> bool {
    (tx.flags & TF_OPTIONAL_AUTH) != 0 || tx.clear_flag == Some(ASF_REQUIRE_AUTH)
}

fn account_set_sets_require_dest(tx: &ParsedTx) -> bool {
    (tx.flags & TF_REQUIRE_DEST_TAG) != 0 || tx.set_flag == Some(1)
}

fn account_set_clears_require_dest(tx: &ParsedTx) -> bool {
    (tx.flags & TF_OPTIONAL_DEST_TAG) != 0 || tx.clear_flag == Some(1)
}

fn account_set_sets_disallow_xrp(tx: &ParsedTx) -> bool {
    (tx.flags & TF_DISALLOW_XRP) != 0 || tx.set_flag == Some(3)
}

fn account_set_clears_disallow_xrp(tx: &ParsedTx) -> bool {
    (tx.flags & TF_ALLOW_XRP) != 0 || tx.clear_flag == Some(3)
}

fn signed_with_master_key(tx: &ParsedTx) -> bool {
    if tx.signing_pubkey.is_empty() {
        return false;
    }
    crate::crypto::account_id(&tx.signing_pubkey) == tx.account
}

fn signer_list_exists(state: &LedgerState, account: &[u8; 20]) -> bool {
    let key = crate::ledger::keylet::signer_list(account).key;
    state.get_raw(&key).is_some()
        || state.get_raw_owned(&key).is_some()
        || state.get_committed_raw_owned(&key).is_some()
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|b| *b == 0)
}

fn valid_message_key(key: &[u8]) -> bool {
    if key.is_empty() {
        return true;
    }
    key.len() == 33 && matches!(key[0], 0x02 | 0x03 | 0xED)
}

pub(crate) fn accountset_message_key_is_valid(tx: &ParsedTx) -> bool {
    tx.message_key.as_deref().is_none_or(valid_message_key)
}

fn apply_accountset_optional_fields(tx: &ParsedTx, account: &mut crate::ledger::AccountRoot) {
    if let Some(hash) = tx.email_hash {
        if is_zero(&hash) {
            account.set_email_hash(None);
        } else {
            account.set_email_hash(Some(hash));
        }
    }
    if let Some(locator) = tx.wallet_locator {
        if is_zero(&locator) {
            account.set_wallet_locator(None);
        } else {
            account.set_wallet_locator(Some(locator));
        }
    }
    if let Some(ref key) = tx.message_key {
        if key.is_empty() {
            account.set_message_key(None);
        } else {
            account.set_message_key(Some(key));
        }
    }
    if tx.set_flag == Some(ASF_AUTHORIZED_NFTOKEN_MINTER) {
        if let Some(minter) = tx.nftoken_minter {
            account.set_nftoken_minter(Some(minter));
        }
    } else if tx.clear_flag == Some(ASF_AUTHORIZED_NFTOKEN_MINTER) {
        account.set_nftoken_minter(None);
    }
}

/// Apply a SetRegularKey: authorize a secondary signing key.
pub(crate) fn apply_set_regular_key(
    state: &LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    // Cannot set master key as regular key (rippled: SetRegularKey.cpp, temBAD_REGKEY)
    if let Some(rk) = tx.regular_key {
        if rk == tx.account {
            return ApplyResult::ClaimedCost("temBAD_REGKEY");
        }
    }
    if tx.regular_key.is_none()
        && (new_sender.flags & LSF_DISABLE_MASTER) != 0
        && !signer_list_exists(state, &tx.account)
    {
        return ApplyResult::ClaimedCost("tecNO_ALTERNATIVE_KEY");
    }
    if tx.signers.is_empty()
        && !tx.signing_pubkey.is_empty()
        && crate::crypto::account_id(&tx.signing_pubkey) == tx.account
        && (new_sender.flags & LSF_PASSWORD_SPENT) == 0
        && tx.fee < crate::ledger::read_fees(state).base
    {
        new_sender.flags |= LSF_PASSWORD_SPENT;
    }
    new_sender.regular_key = tx.regular_key;
    ApplyResult::Success
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::account::LSF_PASSWORD_SPENT;

    fn account() -> crate::ledger::AccountRoot {
        crate::ledger::AccountRoot {
            account_id: [1u8; 20],
            balance: 1_000_000,
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

    fn apply_for_test(
        tx: &ParsedTx,
        sender: &mut crate::ledger::AccountRoot,
        clawback_enabled: bool,
    ) -> ApplyResult {
        apply_account_set(&LedgerState::new(), tx, sender, clawback_enabled, true)
    }

    #[test]
    fn require_dest_sets_destination_tag_flag_not_password_spent() {
        let mut sender = account();
        let tx = ParsedTx {
            tx_type: 3,
            set_flag: Some(1),
            ..ParsedTx::default()
        };

        assert_eq!(apply_for_test(&tx, &mut sender, true), ApplyResult::Success);
        assert_eq!(sender.flags & LSF_REQUIRE_DEST_TAG, LSF_REQUIRE_DEST_TAG);
        assert_eq!(sender.flags & LSF_PASSWORD_SPENT, 0);
    }

    #[test]
    fn account_txn_id_flag_toggles_field_not_account_flags() {
        let mut sender = account();
        let original_flags = sender.flags;
        let tx = ParsedTx {
            tx_type: 3,
            set_flag: Some(5),
            ..ParsedTx::default()
        };

        assert_eq!(apply_for_test(&tx, &mut sender, true), ApplyResult::Success);
        assert_eq!(sender.flags, original_flags);
        assert_eq!(sender.account_txn_id(), Some([0u8; 32]));

        let clear_tx = ParsedTx {
            tx_type: 3,
            clear_flag: Some(5),
            ..ParsedTx::default()
        };

        assert_eq!(
            apply_for_test(&clear_tx, &mut sender, true),
            ApplyResult::Success
        );
        assert_eq!(sender.flags, original_flags);
        assert_eq!(sender.account_txn_id(), None);
    }

    #[test]
    fn existing_account_txn_id_is_not_reset_by_set_flag() {
        let mut sender = account();
        let existing = [0x44; 32];
        sender.set_account_txn_id(existing);
        let tx = ParsedTx {
            tx_type: 3,
            set_flag: Some(5),
            ..ParsedTx::default()
        };

        assert_eq!(apply_for_test(&tx, &mut sender, true), ApplyResult::Success);
        assert_eq!(sender.account_txn_id(), Some(existing));
    }

    #[test]
    fn require_auth_cannot_be_enabled_after_owned_objects_exist() {
        let mut sender = account();
        sender.owner_count = 1;
        let tx = ParsedTx {
            tx_type: 3,
            set_flag: Some(ASF_REQUIRE_AUTH),
            ..ParsedTx::default()
        };

        assert_eq!(
            apply_for_test(&tx, &mut sender, true),
            ApplyResult::ClaimedCost("tecOWNERS")
        );
        assert_eq!(sender.flags & LSF_REQUIRE_AUTH, 0);
    }

    #[test]
    fn no_freeze_and_clawback_are_one_way_account_flags() {
        let mut sender = account();
        sender.flags = LSF_NO_FREEZE | LSF_ALLOW_TRUST_LINE_CLAWBACK;

        let clear_no_freeze = ParsedTx {
            tx_type: 3,
            clear_flag: Some(ASF_NO_FREEZE),
            ..ParsedTx::default()
        };
        assert_eq!(
            apply_for_test(&clear_no_freeze, &mut sender, true),
            ApplyResult::ClaimedCost("tecNO_PERMISSION")
        );

        let clear_clawback = ParsedTx {
            tx_type: 3,
            clear_flag: Some(ASF_ALLOW_TRUST_LINE_CLAWBACK),
            ..ParsedTx::default()
        };
        assert_eq!(
            apply_for_test(&clear_clawback, &mut sender, true),
            ApplyResult::Success
        );
    }

    #[test]
    fn clawback_must_be_enabled_before_owned_objects_exist() {
        let mut sender = account();
        sender.owner_count = 1;
        let tx = ParsedTx {
            tx_type: 3,
            set_flag: Some(ASF_ALLOW_TRUST_LINE_CLAWBACK),
            ..ParsedTx::default()
        };

        assert_eq!(
            apply_for_test(&tx, &mut sender, true),
            ApplyResult::ClaimedCost("tecOWNERS")
        );
        assert_eq!(sender.flags & LSF_ALLOW_TRUST_LINE_CLAWBACK, 0);
    }
}
