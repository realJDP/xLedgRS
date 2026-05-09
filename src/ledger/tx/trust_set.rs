//! TrustSet — IMPLEMENTED

use super::ApplyResult;
use super::{balance_before_fee, load_existing_account, owner_reserve_requirement};
use crate::ledger::account::{
    LSF_DEFAULT_RIPPLE, LSF_DISALLOW_INCOMING_TRUSTLINE, LSF_NO_FREEZE, LSF_REQUIRE_AUTH,
};
use crate::ledger::directory;
use crate::ledger::ter;
use crate::ledger::trustline::{
    LSF_HIGH_AUTH, LSF_HIGH_DEEP_FREEZE, LSF_HIGH_FREEZE, LSF_HIGH_NO_RIPPLE, LSF_HIGH_RESERVE,
    LSF_LOW_AUTH, LSF_LOW_DEEP_FREEZE, LSF_LOW_FREEZE, LSF_LOW_NO_RIPPLE, LSF_LOW_RESERVE,
};
use crate::ledger::LedgerState;
use crate::transaction::amount::{Amount, Currency};
use crate::transaction::ParsedTx;

const TF_SET_AUTH: u32 = 0x0001_0000;
const TF_SET_NO_RIPPLE: u32 = 0x0002_0000;
const TF_CLEAR_NO_RIPPLE: u32 = 0x0004_0000;
const TF_SET_FREEZE: u32 = 0x0010_0000;
const TF_CLEAR_FREEZE: u32 = 0x0020_0000;
pub(crate) const TF_SET_DEEP_FREEZE: u32 = 0x0040_0000;
pub(crate) const TF_CLEAR_DEEP_FREEZE: u32 = 0x0080_0000;
const QUALITY_ONE: u32 = 1_000_000_000;

fn reserve_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        LSF_LOW_RESERVE
    } else if account == &tl.high_account {
        LSF_HIGH_RESERVE
    } else {
        panic!("account is not part of this trust line");
    }
}

fn auth_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        LSF_LOW_AUTH
    } else if account == &tl.high_account {
        LSF_HIGH_AUTH
    } else {
        panic!("account is not part of this trust line");
    }
}

fn no_ripple_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        LSF_LOW_NO_RIPPLE
    } else if account == &tl.high_account {
        LSF_HIGH_NO_RIPPLE
    } else {
        panic!("account is not part of this trust line");
    }
}

fn freeze_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        LSF_LOW_FREEZE
    } else if account == &tl.high_account {
        LSF_HIGH_FREEZE
    } else {
        panic!("account is not part of this trust line");
    }
}

fn deep_freeze_flag_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u32 {
    if account == &tl.low_account {
        LSF_LOW_DEEP_FREEZE
    } else if account == &tl.high_account {
        LSF_HIGH_DEEP_FREEZE
    } else {
        panic!("account is not part of this trust line");
    }
}

fn set_owner_node_for(tl: &mut crate::ledger::RippleState, account: &[u8; 20], node: u64) {
    if account == &tl.low_account {
        tl.low_node = node;
    } else if account == &tl.high_account {
        tl.high_node = node;
    } else {
        panic!("account is not part of this trust line");
    }
}

fn owner_node_for(tl: &crate::ledger::RippleState, account: &[u8; 20]) -> u64 {
    if account == &tl.low_account {
        tl.low_node
    } else if account == &tl.high_account {
        tl.high_node
    } else {
        0
    }
}

fn normalize_quality(quality: u32) -> u32 {
    if quality == QUALITY_ONE {
        0
    } else {
        quality
    }
}

fn apply_sender_qualities(
    tl: &mut crate::ledger::RippleState,
    account: &[u8; 20],
    quality_in: Option<u32>,
    quality_out: Option<u32>,
) {
    if account == &tl.low_account {
        if let Some(quality) = quality_in {
            tl.low_quality_in = normalize_quality(quality);
        }
        if let Some(quality) = quality_out {
            tl.low_quality_out = normalize_quality(quality);
        }
    } else if account == &tl.high_account {
        if let Some(quality) = quality_in {
            tl.high_quality_in = normalize_quality(quality);
        }
        if let Some(quality) = quality_out {
            tl.high_quality_out = normalize_quality(quality);
        }
    } else {
        panic!("account is not part of this trust line");
    }
}

fn side_requires_owner_reserve(
    tl: &crate::ledger::RippleState,
    account: &[u8; 20],
    account_flags: u32,
) -> bool {
    let default_ripple = (account_flags & LSF_DEFAULT_RIPPLE) != 0;
    if account == &tl.low_account {
        !tl.low_limit.is_zero()
            || tl.low_quality_in != 0
            || tl.low_quality_out != 0
            || ((tl.flags & LSF_LOW_NO_RIPPLE) == 0) != default_ripple
            || (tl.flags & LSF_LOW_FREEZE) != 0
            || tl.balance.mantissa > 0
    } else if account == &tl.high_account {
        !tl.high_limit.is_zero()
            || tl.high_quality_in != 0
            || tl.high_quality_out != 0
            || ((tl.flags & LSF_HIGH_NO_RIPPLE) == 0) != default_ripple
            || (tl.flags & LSF_HIGH_FREEZE) != 0
            || tl.balance.mantissa < 0
    } else {
        panic!("account is not part of this trust line");
    }
}

fn trustline_is_rippled_default(
    tl: &crate::ledger::RippleState,
    low_account_flags: u32,
    high_account_flags: u32,
) -> bool {
    tl.is_empty()
        && !side_requires_owner_reserve(tl, &tl.low_account, low_account_flags)
        && !side_requires_owner_reserve(tl, &tl.high_account, high_account_flags)
}

fn tx_sets_persistent_trustline_state(tx_flags: u32) -> bool {
    (tx_flags & (TF_SET_AUTH | TF_SET_NO_RIPPLE | TF_SET_FREEZE | TF_SET_DEEP_FREEZE)) != 0
}

pub(crate) fn preflight(tx: &ParsedTx, deep_freeze_enabled: bool) -> Result<(), ter::TxResult> {
    const TF_UNIVERSAL: u32 = 0xC000_0000;
    const TRUSTSET_FLAGS: u32 = TF_SET_AUTH
        | TF_SET_NO_RIPPLE
        | TF_CLEAR_NO_RIPPLE
        | TF_SET_FREEZE
        | TF_CLEAR_FREEZE
        | TF_SET_DEEP_FREEZE
        | TF_CLEAR_DEEP_FREEZE;

    if (tx.flags & !(TF_UNIVERSAL | TRUSTSET_FLAGS)) != 0 {
        return Err(ter::TEM_INVALID_FLAG);
    }
    if !deep_freeze_enabled && (tx.flags & (TF_SET_DEEP_FREEZE | TF_CLEAR_DEEP_FREEZE)) != 0 {
        return Err(ter::TEM_INVALID_FLAG);
    }

    let Some(limit_amount) = tx.limit_amount.as_ref() else {
        return Err(ter::TEM_BAD_LIMIT);
    };
    match limit_amount {
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            if currency.is_bad_currency() {
                return Err(ter::TEM_BAD_CURRENCY);
            }
            if value.is_negative() {
                return Err(ter::TEM_BAD_LIMIT);
            }
            if *issuer == [0u8; 20] {
                return Err(ter::TEM_DST_NEEDED);
            }
            Ok(())
        }
        Amount::Xrp(_) | Amount::Mpt(_) => Err(ter::TEM_BAD_LIMIT),
    }
}

fn trustline_reserve_create_requirement(state: &LedgerState, owner_count: u32) -> u64 {
    if owner_count < 2 {
        0
    } else {
        owner_reserve_requirement(state, owner_count, 1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PseudoAccountKind {
    Amm([u8; 32]),
    VaultOrLoanBroker,
}

fn account_pseudo_kind(account: &crate::ledger::account::AccountRoot) -> Option<PseudoAccountKind> {
    let raw = account.raw_sle.as_ref()?;
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    let mut found_unsupported_pseudo_field = false;
    for field in &parsed.fields {
        if field.type_code != 5 {
            continue;
        }
        match field.field_code {
            14 if field.data.len() == 32 => {
                let mut id = [0u8; 32];
                id.copy_from_slice(&field.data);
                return Some(PseudoAccountKind::Amm(id));
            }
            // sfVaultID and sfLoanBrokerID pseudo accounts may only receive
            // TrustSet updates to lines that already exist.
            35 | 37 if field.data.len() == 32 => return Some(PseudoAccountKind::VaultOrLoanBroker),
            14 | 35 | 37 => found_unsupported_pseudo_field = true,
            _ => {}
        }
    }
    if found_unsupported_pseudo_field {
        Some(PseudoAccountKind::VaultOrLoanBroker)
    } else {
        None
    }
}

fn amm_lp_token_balance(state: &LedgerState, amm_id: &[u8; 32]) -> Option<Amount> {
    let key = crate::ledger::keylet::amm_id(*amm_id).key;
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    let parsed = crate::ledger::meta::parse_sle(&raw)?;
    if parsed.entry_type != 0x0079 {
        return None;
    }
    let field = parsed
        .fields
        .iter()
        .find(|field| field.type_code == 6 && field.field_code == 31)?;
    Amount::from_bytes(&field.data)
        .ok()
        .map(|(amount, _)| amount)
}

fn check_amm_pseudo_trustline_create(
    state: &LedgerState,
    amm_id: &[u8; 32],
    currency: &Currency,
) -> Option<&'static str> {
    let Some(lp_balance) = amm_lp_token_balance(state, amm_id) else {
        return Some("tecINTERNAL");
    };
    let Amount::Iou {
        value,
        currency: lp_currency,
        ..
    } = lp_balance
    else {
        return Some("tecINTERNAL");
    };
    if value.is_zero() {
        return Some("tecAMM_EMPTY");
    }
    if &lp_currency != currency {
        return Some("tecNO_PERMISSION");
    }
    None
}

fn check_pseudo_account_trustset(
    state: &LedgerState,
    counterparty: &crate::ledger::account::AccountRoot,
    currency: &Currency,
    had_trustline: bool,
) -> Option<&'static str> {
    match account_pseudo_kind(counterparty) {
        Some(PseudoAccountKind::Amm(amm_id)) => {
            if had_trustline {
                None
            } else {
                check_amm_pseudo_trustline_create(state, &amm_id, currency)
            }
        }
        Some(PseudoAccountKind::VaultOrLoanBroker) => {
            if had_trustline {
                None
            } else {
                Some("tecNO_PERMISSION")
            }
        }
        None => None,
    }
}

fn apply_sender_trustline_flags(
    tl: &mut crate::ledger::RippleState,
    account: &[u8; 20],
    account_flags: u32,
    tx_flags: u32,
    deep_freeze_enabled: bool,
) -> Option<&'static str> {
    if (tx_flags & TF_SET_AUTH) != 0 {
        tl.flags |= auth_flag_for(tl, account);
    }

    let no_ripple = no_ripple_flag_for(tl, account);
    if (tx_flags & TF_SET_NO_RIPPLE) != 0 && (tx_flags & TF_CLEAR_NO_RIPPLE) == 0 {
        if tl.balance_for(account).mantissa < 0 {
            return Some("tecNO_PERMISSION");
        }
        tl.flags |= no_ripple;
    } else if (tx_flags & TF_CLEAR_NO_RIPPLE) != 0 && (tx_flags & TF_SET_NO_RIPPLE) == 0 {
        tl.flags &= !no_ripple;
    }

    let freeze = freeze_flag_for(tl, account);
    let deep_freeze = deep_freeze_flag_for(tl, account);
    let set_freeze = (tx_flags & TF_SET_FREEZE) != 0 && (tx_flags & TF_CLEAR_FREEZE) == 0;
    let clear_freeze = (tx_flags & TF_CLEAR_FREEZE) != 0 && (tx_flags & TF_SET_FREEZE) == 0;
    let set_deep_freeze =
        (tx_flags & TF_SET_DEEP_FREEZE) != 0 && (tx_flags & TF_CLEAR_DEEP_FREEZE) == 0;
    let clear_deep_freeze =
        (tx_flags & TF_CLEAR_DEEP_FREEZE) != 0 && (tx_flags & TF_SET_DEEP_FREEZE) == 0;

    if !deep_freeze_enabled && (tx_flags & (TF_SET_DEEP_FREEZE | TF_CLEAR_DEEP_FREEZE)) != 0 {
        return Some("temINVALID_FLAG");
    }

    if deep_freeze_enabled {
        if (account_flags & LSF_NO_FREEZE) != 0 && (set_freeze || set_deep_freeze) {
            return Some("tecNO_PERMISSION");
        }
        if (set_freeze || set_deep_freeze) && (clear_freeze || clear_deep_freeze) {
            return Some("tecNO_PERMISSION");
        }
        if set_deep_freeze && (tl.flags & freeze) == 0 && !set_freeze {
            return Some("tecNO_PERMISSION");
        }
        if clear_freeze && !clear_deep_freeze && (tl.flags & deep_freeze) != 0 {
            return Some("tecNO_PERMISSION");
        }
    }

    if set_freeze {
        tl.flags |= freeze;
    } else if clear_freeze {
        tl.flags &= !freeze;
    }
    if set_deep_freeze {
        tl.flags |= deep_freeze;
    } else if clear_deep_freeze {
        tl.flags &= !deep_freeze;
    }

    None
}

pub(crate) fn apply_trustset(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    deep_freeze_enabled: bool,
) -> ApplyResult {
    let limit = match &tx.limit_amount {
        Some(Amount::Iou {
            value,
            currency,
            issuer,
        }) => (value.clone(), currency.clone(), *issuer),
        _ => return ApplyResult::ClaimedCost("temBAD_LIMIT"),
    };
    let (limit_value, currency, counterparty) = limit;

    if currency.is_bad_currency() {
        return ApplyResult::ClaimedCost("temBAD_CURRENCY");
    }
    if limit_value.is_negative() {
        return ApplyResult::ClaimedCost("temBAD_LIMIT");
    }
    if counterparty == tx.account {
        return ApplyResult::ClaimedCost("temDST_IS_SRC");
    }
    if (tx.flags & TF_SET_AUTH) != 0 && (new_sender.flags & LSF_REQUIRE_AUTH) == 0 {
        return ApplyResult::ClaimedCost("tefNO_AUTH_REQUIRED");
    }
    let Some(counterparty_account) = load_existing_account(state, &counterparty) else {
        return ApplyResult::ClaimedCost("tecNO_DST");
    };
    let counterparty_flags = counterparty_account.flags;

    let key = crate::ledger::trustline::shamap_key(&tx.account, &counterparty, &currency);
    let requested_quality_in = tx.quality_in.map(normalize_quality);
    let requested_quality_out = tx.quality_out.map(normalize_quality);

    // Check typed map AND NuDB for existing trust line (hydration gap).
    let had_trustline = state.get_trustline(&key).is_some()
        || state.get_raw_owned(&key).is_some()
        || state.get_committed_raw_owned(&key).is_some();
    if !had_trustline {
        if (counterparty_flags & LSF_DISALLOW_INCOMING_TRUSTLINE) != 0 {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
    }
    if let Some(ter) =
        check_pseudo_account_trustset(state, &counterparty_account, &currency, had_trustline)
    {
        return ApplyResult::ClaimedCost(ter);
    }
    let mut tl = if let Some(existing) = state.get_trustline(&key) {
        existing.clone()
    } else if let Some(raw) = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))
    {
        if let Some(decoded) = crate::ledger::RippleState::decode_from_sle(&raw) {
            state.hydrate_trustline(decoded.clone());
            decoded
        } else {
            crate::ledger::RippleState::new(&tx.account, &counterparty, currency)
        }
    } else {
        // No existing trust line. If limit is zero, this is redundant.
        if limit_value.is_zero()
            && requested_quality_in.unwrap_or(0) == 0
            && requested_quality_out.unwrap_or(0) == 0
            && !tx_sets_persistent_trustline_state(tx.flags)
        {
            return ApplyResult::ClaimedCost("tecNO_LINE_REDUNDANT");
        }
        crate::ledger::RippleState::new(&tx.account, &counterparty, currency)
    };

    // Set the limit for the sender's side
    let reserve_flag = reserve_flag_for(&tl, &tx.account);
    let sender_reserved_before = (tl.flags & reserve_flag) != 0;
    let low_account_flags = if tl.low_account == tx.account {
        new_sender.flags
    } else {
        counterparty_flags
    };
    let high_account_flags = if tl.high_account == tx.account {
        new_sender.flags
    } else {
        counterparty_flags
    };
    if !had_trustline && (counterparty_flags & LSF_DEFAULT_RIPPLE) == 0 {
        tl.flags |= no_ripple_flag_for(&tl, &counterparty);
    }
    if !had_trustline
        && (new_sender.flags & LSF_DEFAULT_RIPPLE) == 0
        && (tx.flags & (TF_SET_NO_RIPPLE | TF_CLEAR_NO_RIPPLE)) == 0
        && (tx.flags & TF_SET_AUTH) != 0
        && limit_value.is_zero()
    {
        tl.flags |= no_ripple_flag_for(&tl, &tx.account);
    }
    tl.set_limit_for(&tx.account, limit_value);
    apply_sender_qualities(
        &mut tl,
        &tx.account,
        requested_quality_in,
        requested_quality_out,
    );
    if let Some(ter) = apply_sender_trustline_flags(
        &mut tl,
        &tx.account,
        new_sender.flags,
        tx.flags,
        deep_freeze_enabled,
    ) {
        return ApplyResult::ClaimedCost(ter);
    }
    let sender_reserved_after = side_requires_owner_reserve(&tl, &tx.account, new_sender.flags);
    let creates_trustline = !had_trustline;
    let sender_reserve_increases =
        creates_trustline || (!sender_reserved_before && sender_reserved_after);
    if sender_reserve_increases {
        // rippled's TrustSet reserve gate is special: the first two owned
        // objects may be trust lines without enforcing the incremental reserve.
        let pre_fee_balance = balance_before_fee(new_sender.balance, tx.fee);
        let required = trustline_reserve_create_requirement(state, new_sender.owner_count);
        if pre_fee_balance < required {
            return ApplyResult::ClaimedCost(if creates_trustline {
                "tecNO_LINE_INSUF_RESERVE"
            } else {
                "tecINSUF_RESERVE_LINE"
            });
        }
    }

    if trustline_is_rippled_default(&tl, low_account_flags, high_account_flags) && had_trustline {
        // Delete the trust line if both limits are zero and balance is zero
        // Remove from both accounts' owner directories (rippled RippleStateHelpers.cpp:283,290)
        directory::dir_remove_owner_page(
            state,
            &tx.account,
            owner_node_for(&tl, &tx.account),
            &key.0,
        );
        directory::dir_remove_owner_page(
            state,
            &counterparty,
            owner_node_for(&tl, &counterparty),
            &key.0,
        );
        state.remove_trustline(&key);
        // Owner reserve applies only on the side carrying the reserve flag.
        if sender_reserved_before {
            new_sender.owner_count = new_sender.owner_count.saturating_sub(1);
        }
        if let Some(peer) = state.get_account(&counterparty) {
            let mut peer = peer.clone();
            let peer_flag = reserve_flag_for(&tl, &counterparty);
            if (tl.flags & peer_flag) != 0 {
                peer.owner_count = peer.owner_count.saturating_sub(1);
            }
            state.insert_account(peer);
        }
    } else {
        if !had_trustline {
            // New trust line — add to BOTH accounts' owner directories
            // (rippled RippleStateHelpers.cpp:192,198)
            let sender_node = directory::dir_add(state, &tx.account, key.0);
            let counterparty_node = directory::dir_add(state, &counterparty, key.0);
            set_owner_node_for(&mut tl, &tx.account, sender_node);
            set_owner_node_for(&mut tl, &counterparty, counterparty_node);
            if let Some(peer) = load_existing_account(state, &counterparty) {
                // rippled's trustCreate peeks the peer AccountRoot; validated
                // metadata threads it even when only PreviousTxn fields change.
                let peer_key = crate::ledger::account::shamap_key(&counterparty);
                state.force_previous_txn_touch(&peer_key);
                state.insert_account(peer);
            }
        }

        if sender_reserved_before != sender_reserved_after {
            if sender_reserved_after {
                tl.flags |= reserve_flag;
                new_sender.owner_count += 1;
            } else {
                tl.flags &= !reserve_flag;
                new_sender.owner_count = new_sender.owner_count.saturating_sub(1);
            }
        } else if !had_trustline && !sender_reserved_after {
            // rippled's trustCreate always charges the transaction sender an
            // owner reserve for a newly created RippleState, even when the
            // only lasting reason for the line is authorization.
            tl.flags |= reserve_flag;
            new_sender.owner_count += 1;
        }
        state.insert_trustline(tl);
    }

    ApplyResult::Success
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::account::AccountRoot;
    use crate::transaction::amount::{IouValue, Issue};

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

    fn pseudo_account_with_hash_field(
        account_id: [u8; 20],
        field_code: u16,
        owner_id: [u8; 32],
    ) -> AccountRoot {
        let mut pseudo = account(account_id, 0);
        pseudo.sequence = 0;
        pseudo.flags = crate::ledger::account::LSF_DISABLE_MASTER
            | LSF_DEFAULT_RIPPLE
            | crate::ledger::account::LSF_DEPOSIT_AUTH;
        pseudo.raw_sle = Some(crate::ledger::meta::patch_sle(
            &pseudo.encode(),
            &[crate::ledger::meta::ParsedField {
                type_code: 5,
                field_code,
                data: owner_id.to_vec(),
            }],
            None,
            None,
            &[],
        ));
        pseudo
    }

    #[test]
    fn trustset_to_empty_amm_pseudo_returns_tec_amm_empty() {
        let sender = [1u8; 20];
        let issuer = [2u8; 20];
        let amm_account = [3u8; 20];
        let usd = Currency::from_code("USD").unwrap();
        let usd_issue = Issue::Iou {
            currency: usd.clone(),
            issuer,
        };
        let lp_currency = crate::ledger::tx::amm::amm_lp_currency(&Currency::xrp(), &usd);
        let amm_key = crate::ledger::tx::amm::amm_key(&Issue::Xrp, &usd_issue);

        let mut state = LedgerState::new();
        state.insert_account(account(sender, 100_000_000));
        state.insert_account(account(issuer, 100_000_000));
        let mut pseudo = account(amm_account, 0);
        pseudo.raw_sle = Some(crate::ledger::meta::patch_sle(
            &pseudo.encode(),
            &[crate::ledger::meta::ParsedField {
                type_code: 5,
                field_code: 14,
                data: amm_key.0.to_vec(),
            }],
            None,
            None,
            &[],
        ));
        state.insert_account(pseudo);

        let lp_balance = Amount::Iou {
            value: IouValue::ZERO,
            currency: lp_currency.clone(),
            issuer: amm_account,
        };
        state.insert_raw(
            amm_key,
            crate::ledger::meta::build_sle(
                0x0079,
                &[
                    crate::ledger::meta::ParsedField {
                        type_code: 8,
                        field_code: 1,
                        data: amm_account.to_vec(),
                    },
                    crate::ledger::meta::ParsedField {
                        type_code: 24,
                        field_code: 3,
                        data: Issue::Xrp.to_bytes(),
                    },
                    crate::ledger::meta::ParsedField {
                        type_code: 24,
                        field_code: 4,
                        data: usd_issue.to_bytes(),
                    },
                    crate::ledger::meta::ParsedField {
                        type_code: 6,
                        field_code: 31,
                        data: lp_balance.to_bytes(),
                    },
                ],
                None,
                None,
            ),
        );

        let mut new_sender = state.get_account(&sender).cloned().unwrap();
        let tx = ParsedTx {
            tx_type: 20,
            account: sender,
            sequence: 1,
            limit_amount: Some(Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: lp_currency,
                issuer: amm_account,
            }),
            ..ParsedTx::default()
        };

        assert_eq!(
            apply_trustset(&mut state, &tx, &mut new_sender, true),
            ApplyResult::ClaimedCost("tecAMM_EMPTY")
        );
    }

    #[test]
    fn trustset_new_line_to_vault_pseudo_returns_no_permission() {
        let sender = [1u8; 20];
        let vault_pseudo = [4u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(sender, 100_000_000));
        state.insert_account(pseudo_account_with_hash_field(vault_pseudo, 35, [9u8; 32]));

        let mut new_sender = state.get_account(&sender).cloned().unwrap();
        let tx = ParsedTx {
            tx_type: 20,
            account: sender,
            sequence: 1,
            limit_amount: Some(Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd,
                issuer: vault_pseudo,
            }),
            ..ParsedTx::default()
        };

        assert_eq!(
            apply_trustset(&mut state, &tx, &mut new_sender, true),
            ApplyResult::ClaimedCost("tecNO_PERMISSION")
        );
    }

    #[test]
    fn trustset_new_line_to_loan_broker_pseudo_returns_no_permission() {
        let sender = [1u8; 20];
        let broker_pseudo = [5u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(sender, 100_000_000));
        state.insert_account(pseudo_account_with_hash_field(broker_pseudo, 37, [8u8; 32]));

        let mut new_sender = state.get_account(&sender).cloned().unwrap();
        let tx = ParsedTx {
            tx_type: 20,
            account: sender,
            sequence: 1,
            limit_amount: Some(Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd,
                issuer: broker_pseudo,
            }),
            ..ParsedTx::default()
        };

        assert_eq!(
            apply_trustset(&mut state, &tx, &mut new_sender, true),
            ApplyResult::ClaimedCost("tecNO_PERMISSION")
        );
    }

    #[test]
    fn trustset_existing_line_to_vault_pseudo_can_be_modified() {
        let sender = [1u8; 20];
        let vault_pseudo = [4u8; 20];
        let usd = Currency::from_code("USD").unwrap();

        let mut state = LedgerState::new();
        state.insert_account(account(sender, 100_000_000));
        state.insert_account(account(vault_pseudo, 0));

        let mut new_sender = state.get_account(&sender).cloned().unwrap();
        let create = ParsedTx {
            tx_type: 20,
            account: sender,
            sequence: 1,
            limit_amount: Some(Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer: vault_pseudo,
            }),
            ..ParsedTx::default()
        };
        assert_eq!(
            apply_trustset(&mut state, &create, &mut new_sender, true),
            ApplyResult::Success
        );
        state.insert_account(new_sender);
        state.insert_account(pseudo_account_with_hash_field(vault_pseudo, 35, [9u8; 32]));

        let mut new_sender = state.get_account(&sender).cloned().unwrap();
        let modify = ParsedTx {
            tx_type: 20,
            account: sender,
            sequence: 2,
            limit_amount: Some(Amount::Iou {
                value: IouValue::from_f64(20.0),
                currency: usd,
                issuer: vault_pseudo,
            }),
            ..ParsedTx::default()
        };

        assert_eq!(
            apply_trustset(&mut state, &modify, &mut new_sender, true),
            ApplyResult::Success
        );
    }
}
