//! AMM — AMMClawback (31), AMMCreate (35), AMMDeposit (36), AMMWithdraw (37),
//!       AMMVote (38), AMMBid (39), AMMDelete (40).
//!
//! AMMCreate creates a pseudo-account + AMM SLE + LP token issuance.
//! AMMDelete removes AMM SLE + pseudo-account when LP token balance is 0.
//!
//! SHAMap key for AMM:
//!   SHA-512-half(0x0041 || min_issue.account || min_issue.currency ||
//!                          max_issue.account || max_issue.currency)
//!   namespace 'A' = 0x41
//!   Issues sorted by (currency, account) — matching rippled's Issue::operator<=>
//!
//! (rippled: AMMCreate.cpp, AMMDelete.cpp, AMMDeposit.cpp, AMMWithdraw.cpp,
//!  AMMVote.cpp, AMMBid.cpp, AMMClawback.cpp)

use crate::crypto::{ripemd160, sha256, sha512_first_half};
use crate::ledger::account::LSF_ALLOW_TRUST_LINE_CLAWBACK;
use crate::ledger::tx::TxContext;
use crate::ledger::{directory, AccountRoot, Key, LedgerState};
use crate::transaction::amount::{Amount, Currency, IouValue, Issue};
use crate::transaction::ParsedTx;
use num_bigint::{BigInt, BigUint, Sign};
use std::sync::LazyLock;

use super::asset_flow::{apply_amount_delta, AssetDelta};
use super::{balance_before_fee, owner_reserve_requirement, ApplyResult};

/// LedgerNameSpace::AMM = 'A' = 0x41.
const AMM_SPACE: [u8; 2] = [0x00, 0x41];

/// AMM entry type (ltAMM = 0x0079).
const LT_AMM: u16 = 0x0079;

/// Account flags for pseudo-accounts.
const LSF_DISABLE_MASTER: u32 = 0x00100000;
const LSF_DEFAULT_RIPPLE: u32 = 0x00800000;
const LSF_DEPOSIT_AUTH: u32 = 0x01000000;
const LSF_AMM_NODE: u32 = 0x01000000;
const TRADING_FEE_THRESHOLD: u16 = 1000;
const AUCTION_SLOT_SECONDS: u32 = 24 * 60 * 60;
const AUCTION_SLOT_TIME_INTERVALS: u64 = 20;
const AUCTION_SLOT_INTERVAL_SECONDS: u64 =
    AUCTION_SLOT_SECONDS as u64 / AUCTION_SLOT_TIME_INTERVALS;
const AUCTION_SLOT_FEE_SCALE_FACTOR: u32 = 100_000;
const AUCTION_SLOT_DISCOUNTED_FEE_FRACTION: u16 = 10;
const AUCTION_SLOT_MIN_FEE_FRACTION: u64 = 25;
const MAX_DELETABLE_AMM_TRUSTLINES: usize = 512;
const VOTE_MAX_SLOTS: usize = 8;
const VOTE_WEIGHT_SCALE_FACTOR: u32 = 100_000;
const TF_AMM_WITHDRAW_LP_TOKEN: u32 = 0x0001_0000;
const TF_AMM_WITHDRAW_ALL: u32 = 0x0002_0000;
const TF_AMM_ONE_ASSET_WITHDRAW_ALL: u32 = 0x0004_0000;
const TF_AMM_SINGLE_ASSET: u32 = 0x0008_0000;
const TF_AMM_TWO_ASSET: u32 = 0x0010_0000;
const TF_AMM_ONE_ASSET_LP_TOKEN: u32 = 0x0020_0000;
const TF_AMM_LIMIT_LP_TOKEN: u32 = 0x0040_0000;
const TF_AMM_TWO_ASSET_IF_EMPTY: u32 = 0x0080_0000;
const TF_CLAW_TWO_ASSETS: u32 = 0x0000_0001;

static FEATURE_FIX_AMM_CLAWBACK_ROUNDING: LazyLock<[u8; 32]> =
    LazyLock::new(|| super::amendment_hash("fixAMMClawbackRounding"));

#[cfg(test)]
static TEST_AMM_DELETE_LIMIT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn amm_delete_trustline_limit() -> usize {
    #[cfg(test)]
    {
        let limit = TEST_AMM_DELETE_LIMIT.load(std::sync::atomic::Ordering::SeqCst);
        if limit != 0 {
            return limit;
        }
    }
    MAX_DELETABLE_AMM_TRUSTLINES
}
const TF_AMM_DEPOSIT_MASK: u32 = TF_AMM_WITHDRAW_LP_TOKEN
    | TF_AMM_SINGLE_ASSET
    | TF_AMM_TWO_ASSET
    | TF_AMM_ONE_ASSET_LP_TOKEN
    | TF_AMM_LIMIT_LP_TOKEN
    | TF_AMM_TWO_ASSET_IF_EMPTY;
const TF_AMM_WITHDRAW_MASK: u32 = TF_AMM_WITHDRAW_LP_TOKEN
    | TF_AMM_WITHDRAW_ALL
    | TF_AMM_ONE_ASSET_WITHDRAW_ALL
    | TF_AMM_SINGLE_ASSET
    | TF_AMM_TWO_ASSET
    | TF_AMM_ONE_ASSET_LP_TOKEN
    | TF_AMM_LIMIT_LP_TOKEN;

/// Get the (account, currency) pair from an Issue for key derivation.
/// XRP: account=[0;20], currency=[0;20].
fn issue_parts(issue: &Issue) -> ([u8; 20], [u8; 20]) {
    match issue {
        Issue::Xrp => ([0u8; 20], [0u8; 20]),
        Issue::Iou { currency, issuer } => (*issuer, currency.code),
        Issue::Mpt(_) => ([0u8; 20], [0u8; 20]), // MPT AMM not supported yet
    }
}

/// Sort two issues for canonical AMM key derivation.
/// rippled sorts by (currency, account) with XRP account ignored.
fn sorted_issues<'a>(a: &'a Issue, b: &'a Issue) -> (&'a Issue, &'a Issue) {
    let (a_acct, a_cur) = issue_parts(a);
    let (b_acct, b_cur) = issue_parts(b);
    // Compare currency first, then account
    match a_cur.cmp(&b_cur) {
        std::cmp::Ordering::Less => (a, b),
        std::cmp::Ordering::Greater => (b, a),
        std::cmp::Ordering::Equal => {
            // Same currency — compare account (but XRP ignores account)
            if a_cur == [0u8; 20] {
                (a, b) // XRP — equivalent
            } else if a_acct <= b_acct {
                (a, b)
            } else {
                (b, a)
            }
        }
    }
}

#[allow(dead_code)]
fn issue_currency(issue: &Issue) -> Option<Currency> {
    match issue {
        Issue::Xrp => Some(Currency::xrp()),
        Issue::Iou { currency, .. } => Some(currency.clone()),
        Issue::Mpt(_) => None,
    }
}

fn invalid_amm_asset(issue: &Issue) -> Result<(), &'static str> {
    match issue {
        Issue::Iou { currency, .. } if currency.is_bad_currency() => Err("temBAD_CURRENCY"),
        // The local AMM model does not yet carry MPT pool accounting. Return
        // the same malformed-family result used for unsupported AMM tokens.
        Issue::Mpt(_) => Err("temBAD_AMM_TOKENS"),
        _ => Ok(()),
    }
}

fn invalid_amm_asset_pair(issue1: &Issue, issue2: &Issue) -> Result<(), &'static str> {
    if issue1 == issue2 {
        return Err("temBAD_AMM_TOKENS");
    }
    invalid_amm_asset(issue1)?;
    invalid_amm_asset(issue2)?;
    Ok(())
}

fn invalid_amm_amount(amount: &Amount) -> Result<(), &'static str> {
    let issue = issue_from_amount(amount).ok_or("temBAD_AMM_TOKENS")?;
    invalid_amm_asset(&issue)?;
    let positive = match amount {
        Amount::Xrp(drops) => *drops > 0,
        Amount::Iou { value, .. } => value.is_positive(),
        Amount::Mpt(_) => amount
            .mpt_parts()
            .map(|(value, _)| value > 0)
            .unwrap_or(false),
    };
    if !positive {
        return Err("temBAD_AMOUNT");
    }
    Ok(())
}

/// Derive the canonical AMM LP-token currency.
///
/// rippled uses `0x03 || SHA512Half(min(currency), max(currency))[0..19]`.
#[allow(dead_code)]
pub(crate) fn amm_lp_currency(currency1: &Currency, currency2: &Currency) -> Currency {
    let (min_currency, max_currency) = if currency1.code <= currency2.code {
        (currency1, currency2)
    } else {
        (currency2, currency1)
    };

    let mut payload = Vec::with_capacity(40);
    payload.extend_from_slice(&min_currency.code);
    payload.extend_from_slice(&max_currency.code);
    let hash = sha512_first_half(&payload);

    let mut code = [0u8; 20];
    code[0] = 0x03;
    code[1..20].copy_from_slice(&hash[..19]);
    Currency { code }
}

/// Derive the canonical AMM LP-token issue for an asset pair and AMM account.
#[allow(dead_code)]
pub(crate) fn amm_lp_issue(issue1: &Issue, issue2: &Issue, amm_account: [u8; 20]) -> Option<Issue> {
    Some(Issue::Iou {
        currency: amm_lp_currency(&issue_currency(issue1)?, &issue_currency(issue2)?),
        issuer: amm_account,
    })
}

/// Compute the AMM SHAMap key from two asset issues.
/// `SHA-512-Half(0x0041 || minIssue.account || minIssue.currency ||
///                         maxIssue.account || maxIssue.currency)`
pub(crate) fn amm_key(issue1: &Issue, issue2: &Issue) -> Key {
    let (min_i, max_i) = sorted_issues(issue1, issue2);
    let (min_acct, min_cur) = issue_parts(min_i);
    let (max_acct, max_cur) = issue_parts(max_i);

    let mut data = Vec::with_capacity(2 + 20 + 20 + 20 + 20);
    data.extend_from_slice(&AMM_SPACE);
    data.extend_from_slice(&min_acct);
    data.extend_from_slice(&min_cur);
    data.extend_from_slice(&max_acct);
    data.extend_from_slice(&max_cur);
    Key(sha512_first_half(&data))
}

/// Derive a pseudo-account address (same algorithm as vault/loan).
fn pseudo_account_address(
    state: &LedgerState,
    parent_hash: &[u8; 32],
    owner_key: &[u8; 32],
) -> Option<[u8; 20]> {
    for i in 0u16..256 {
        let mut input = Vec::with_capacity(2 + 32 + 32);
        input.extend_from_slice(&i.to_be_bytes());
        input.extend_from_slice(parent_hash);
        input.extend_from_slice(owner_key);
        let hash = sha512_first_half(&input);
        let addr = ripemd160(&sha256(&hash));
        if state.get_account(&addr).is_none() {
            return Some(addr);
        }
    }
    None
}

/// Build an AMM SLE.
fn build_amm_sle(
    pseudo_account: &[u8; 20],
    asset1: &Issue,
    asset2: &Issue,
    trading_fee: u16,
    owner_node: u64,
    pool1: i64,
    pool2: i64,
    lp_total: i64,
) -> Vec<u8> {
    use crate::ledger::meta::ParsedField;
    let (canonical_asset1, canonical_asset2) = sorted_issues(asset1, asset2);
    let mut fields = vec![
        // sfAccount (ACCOUNT=8, field=1) — pseudo-account
        ParsedField {
            type_code: 8,
            field_code: 1,
            data: pseudo_account.to_vec(),
        },
        // sfFlags (UINT32=2, field=2)
        ParsedField {
            type_code: 2,
            field_code: 2,
            data: 0u32.to_be_bytes().to_vec(),
        },
        // sfOwnerNode (UINT64=3, field=4)
        ParsedField {
            type_code: 3,
            field_code: 4,
            data: owner_node.to_be_bytes().to_vec(),
        },
        // sfTradingFee (UINT16=1, field=5)
        ParsedField {
            type_code: 1,
            field_code: 5,
            data: trading_fee.to_be_bytes().to_vec(),
        },
        // sfAsset (ISSUE=24, field=3)
        ParsedField {
            type_code: 24,
            field_code: 3,
            data: canonical_asset1.to_bytes(),
        },
        // sfAsset2 (ISSUE=24, field=4)
        ParsedField {
            type_code: 24,
            field_code: 4,
            data: canonical_asset2.to_bytes(),
        },
        // Pool balance tracking (NUMBER fields for simplified local model):
        // sfPool1 (NUMBER=9, field=10) — asset1 pool balance (drops for XRP)
        ParsedField {
            type_code: 9,
            field_code: 10,
            data: pool1.to_be_bytes().to_vec(),
        },
        // sfPool2 (NUMBER=9, field=11) — asset2 pool balance
        ParsedField {
            type_code: 9,
            field_code: 11,
            data: pool2.to_be_bytes().to_vec(),
        },
        // sfLPTotal (NUMBER=9, field=12) — total LP tokens outstanding
        ParsedField {
            type_code: 9,
            field_code: 12,
            data: lp_total.to_be_bytes().to_vec(),
        },
    ];
    if let Some(lp_balance) = lp_token_balance_amount(asset1, asset2, *pseudo_account, lp_total) {
        fields.push(ParsedField {
            // sfLPTokenBalance (AMOUNT=6, field=31)
            type_code: 6,
            field_code: 31,
            data: lp_balance.to_bytes(),
        });
    }
    crate::ledger::meta::build_sle(LT_AMM, &fields, None, None)
}

fn lp_token_balance_amount(
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
    lp_total: i64,
) -> Option<Amount> {
    let Issue::Iou { currency, issuer } = amm_lp_issue(asset1, asset2, amm_account)? else {
        return None;
    };
    Some(Amount::Iou {
        value: if lp_total <= 0 {
            IouValue::ZERO
        } else {
            iou_value_from_units(lp_total as u64)
        },
        currency,
        issuer,
    })
}

fn iou_value_from_units(units: u64) -> IouValue {
    if units == 0 {
        return IouValue::ZERO;
    }
    let mut mantissa = units as u128;
    let mut exponent = 0i32;
    while mantissa > 9_999_999_999_999_999u128 {
        mantissa /= 10;
        exponent += 1;
    }
    while mantissa < 1_000_000_000_000_000u128 {
        mantissa *= 10;
        exponent -= 1;
    }
    let mut value = IouValue {
        mantissa: mantissa as i64,
        exponent,
    };
    value.normalize();
    value
}

fn iou_value_floor_units(value: &IouValue) -> Option<u64> {
    if !value.is_positive() {
        return None;
    }
    let mantissa = value.mantissa as u128;
    let units = if value.exponent >= 0 {
        mantissa.checked_mul(10u128.checked_pow(value.exponent as u32)?)?
    } else {
        mantissa / 10u128.checked_pow((-value.exponent) as u32)?
    };
    u64::try_from(units).ok()
}

fn iou_value_floor_units_allow_zero(value: &IouValue) -> Option<u64> {
    if value.is_zero() {
        return Some(0);
    }
    iou_value_floor_units(value)
}

fn initialize_fee_auction_vote(
    raw: &[u8],
    creator: &[u8; 20],
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
    close_time: u64,
    trading_fee: u16,
) -> Vec<u8> {
    let vote_slots = build_vote_slots(&[VoteSlotInfo {
        account: *creator,
        trading_fee,
        vote_weight: VOTE_WEIGHT_SCALE_FACTOR,
    }]);
    let price = lp_token_amount_for_units(asset1, asset2, amm_account, 0).unwrap_or(Amount::Xrp(0));
    let auction_slot = build_auction_slot(
        creator,
        (close_time as u32).saturating_add(AUCTION_SLOT_SECONDS),
        trading_fee / AUCTION_SLOT_DISCOUNTED_FEE_FRACTION,
        &price,
    );
    let raw = crate::ledger::meta::patch_sle(
        raw,
        &[
            crate::ledger::meta::ParsedField {
                type_code: 15,
                field_code: 12,
                data: vote_slots,
            },
            crate::ledger::meta::ParsedField {
                type_code: 14,
                field_code: 26,
                data: auction_slot,
            },
        ],
        None,
        None,
        &[],
    );
    amm_patch_trading_fee(&raw, trading_fee)
}

fn amount_pool_units(amount: &Amount) -> Option<u64> {
    match amount {
        Amount::Xrp(drops) => Some(*drops),
        Amount::Iou { value, .. } => iou_value_floor_units(value),
        Amount::Mpt(_) => None,
    }
}

fn amount_pool_units_allow_zero(amount: &Amount) -> Option<u64> {
    match amount {
        Amount::Xrp(drops) => Some(*drops),
        Amount::Iou { value, .. } => iou_value_floor_units_allow_zero(value),
        Amount::Mpt(_) => None,
    }
}

fn issue_from_amount(amount: &Amount) -> Option<Issue> {
    match amount {
        Amount::Xrp(_) => Some(Issue::Xrp),
        Amount::Iou {
            currency, issuer, ..
        } => Some(Issue::Iou {
            currency: currency.clone(),
            issuer: *issuer,
        }),
        Amount::Mpt(raw) => {
            let (_, issuance) = Amount::Mpt(raw.clone()).mpt_parts()?;
            Some(Issue::Mpt(issuance))
        }
    }
}

fn amount_from_issue_units(issue: &Issue, units: u64) -> Option<Amount> {
    match issue {
        Issue::Xrp => Some(Amount::Xrp(units)),
        Issue::Iou { currency, issuer } => Some(Amount::Iou {
            value: iou_value_from_units(units),
            currency: currency.clone(),
            issuer: *issuer,
        }),
        Issue::Mpt(_) => None,
    }
}

fn lp_token_amount_for_units(
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
    units: u64,
) -> Option<Amount> {
    let Issue::Iou { currency, issuer } = amm_lp_issue(asset1, asset2, amm_account)? else {
        return None;
    };
    Some(Amount::Iou {
        value: iou_value_from_units(units),
        currency,
        issuer,
    })
}

fn transfer_amount_between_accounts_waiving_issuer_fee(
    state: &mut LedgerState,
    sender: &[u8; 20],
    receiver: &[u8; 20],
    amount: &Amount,
) -> bool {
    if sender == receiver {
        return true;
    }
    if let Amount::Iou { issuer, .. } = amount {
        if sender == issuer {
            return apply_amount_delta(state, receiver, AssetDelta::Credit, amount);
        }
        if receiver == issuer {
            return amm_can_debit_amount(state, sender, amount)
                && apply_amount_delta(state, sender, AssetDelta::Debit, amount);
        }
    }
    amm_can_debit_amount(state, sender, amount)
        && apply_amount_delta(state, sender, AssetDelta::Debit, amount)
        && apply_amount_delta(state, receiver, AssetDelta::Credit, amount)
}

fn transfer_lp_tokens(
    state: &mut LedgerState,
    sender: &[u8; 20],
    receiver: &[u8; 20],
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
    units: u64,
) -> bool {
    if units == 0 {
        return true;
    }
    let Some(amount) = lp_token_amount_for_units(asset1, asset2, amm_account, units) else {
        return false;
    };
    if !amm_can_debit_amount(state, sender, &amount)
        || !apply_amount_delta(state, sender, AssetDelta::Debit, &amount)
        || !apply_amount_delta(state, receiver, AssetDelta::Credit, &amount)
    {
        return false;
    }
    ensure_lp_token_trustline_lifecycle(state, receiver, asset1, asset2, amm_account)
}

fn issue_lp_tokens(
    state: &mut LedgerState,
    holder: &[u8; 20],
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
    units: u64,
) -> bool {
    match lp_token_amount_for_units(asset1, asset2, amm_account, units) {
        Some(amount) => {
            apply_amount_delta(state, holder, AssetDelta::Credit, &amount)
                && ensure_lp_token_trustline_lifecycle(state, holder, asset1, asset2, amm_account)
        }
        None => false,
    }
}

fn burn_lp_tokens(
    state: &mut LedgerState,
    holder: &[u8; 20],
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
    units: u64,
) -> bool {
    match lp_token_amount_for_units(asset1, asset2, amm_account, units) {
        Some(amount) => {
            amm_can_debit_amount(state, holder, &amount)
                && apply_amount_delta(state, holder, AssetDelta::Debit, &amount)
        }
        None => false,
    }
}

fn owner_dir_has_entry(state: &LedgerState, owner: &[u8; 20], key: &Key) -> bool {
    let root_key = directory::owner_dir_key(owner);
    let mut current_page_num = 0u64;
    let mut pages_seen = 0usize;
    loop {
        let page_key = directory::page_key(&root_key.0, current_page_num);
        let Some(page) = directory::load_directory_fresh(state, &page_key) else {
            return false;
        };
        if page.indexes.iter().any(|entry| entry == &key.0) {
            return true;
        }
        if page.index_next == 0 || page.index_next == current_page_num {
            return false;
        }
        current_page_num = page.index_next;
        pages_seen += 1;
        if pages_seen > MAX_DELETABLE_AMM_TRUSTLINES + 16 {
            return false;
        }
    }
}

fn ensure_amm_trustline_lifecycle(
    state: &mut LedgerState,
    amm_account: &[u8; 20],
    peer_account: &[u8; 20],
    currency: &Currency,
    mark_amm_node: bool,
) -> bool {
    let key = crate::ledger::trustline::shamap_key(amm_account, peer_account, currency);
    let Some(mut line) = state.get_trustline(&key).cloned().or_else(|| {
        state
            .get_raw_owned(&key)
            .or_else(|| state.get_committed_raw_owned(&key))
            .and_then(|raw| crate::ledger::RippleState::decode_from_sle(&raw))
    }) else {
        return false;
    };

    let amm_node = if owner_dir_has_entry(state, amm_account, &key) {
        if amm_account == &line.low_account {
            line.low_node
        } else {
            line.high_node
        }
    } else {
        directory::dir_add(state, amm_account, key.0)
    };
    if amm_account == &line.low_account {
        line.low_node = amm_node;
    } else if amm_account == &line.high_account {
        line.high_node = amm_node;
    } else {
        return false;
    }

    let peer_node = if owner_dir_has_entry(state, peer_account, &key) {
        if peer_account == &line.low_account {
            line.low_node
        } else {
            line.high_node
        }
    } else {
        directory::dir_add(state, peer_account, key.0)
    };
    let reserve_flag = reserve_flag_for_trustline_account(&line, peer_account);
    let had_reserve = (line.flags & reserve_flag) != 0;
    if peer_account == &line.low_account {
        line.low_node = peer_node;
    } else if peer_account == &line.high_account {
        line.high_node = peer_node;
    } else {
        return false;
    }

    if mark_amm_node {
        line.flags |= LSF_AMM_NODE;
    }
    if reserve_flag != 0 {
        line.flags |= reserve_flag;
    }
    state.insert_trustline(line);

    if reserve_flag != 0 && !had_reserve {
        if let Some(account) = state.get_account(peer_account) {
            let mut account = account.clone();
            account.owner_count = account.owner_count.saturating_add(1);
            state.insert_account(account);
        }
    }
    true
}

fn ensure_pool_asset_trustline_lifecycle(
    state: &mut LedgerState,
    amm_account: &[u8; 20],
    amount: &Amount,
) -> bool {
    let Amount::Iou {
        currency, issuer, ..
    } = amount
    else {
        return true;
    };
    ensure_amm_trustline_lifecycle(state, amm_account, issuer, currency, true)
}

fn ensure_lp_token_trustline_lifecycle(
    state: &mut LedgerState,
    holder: &[u8; 20],
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
) -> bool {
    if holder == &amm_account {
        return true;
    }
    let Some(Issue::Iou { currency, issuer }) = amm_lp_issue(asset1, asset2, amm_account) else {
        return false;
    };
    ensure_amm_trustline_lifecycle(state, &issuer, holder, &currency, false)
}

fn amm_can_debit_amount(state: &LedgerState, holder: &[u8; 20], amount: &Amount) -> bool {
    match amount {
        Amount::Xrp(drops) => state
            .get_account(holder)
            .map(|account| account.balance >= *drops)
            .unwrap_or(false),
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            if holder == issuer {
                return true;
            }
            let key = crate::ledger::trustline::shamap_key(holder, issuer, currency);
            let line = state.get_trustline(&key).cloned().or_else(|| {
                state
                    .get_raw_owned(&key)
                    .or_else(|| state.get_committed_raw_owned(&key))
                    .and_then(|raw| crate::ledger::RippleState::decode_from_sle(&raw))
            });
            line.map(|line| !line.balance_for(holder).sub(value).is_negative())
                .unwrap_or(false)
        }
        Amount::Mpt(_) => false,
    }
}

fn load_account_readonly(state: &LedgerState, account: &[u8; 20]) -> Option<AccountRoot> {
    state.get_account(account).cloned().or_else(|| {
        let key = crate::ledger::account::shamap_key(account);
        state
            .get_raw_owned(&key)
            .or_else(|| state.get_committed_raw_owned(&key))
            .and_then(|raw| AccountRoot::decode(&raw).ok())
    })
}

fn load_trustline_readonly(
    state: &LedgerState,
    account: &[u8; 20],
    issuer: &[u8; 20],
    currency: &Currency,
) -> Option<crate::ledger::RippleState> {
    let key = crate::ledger::trustline::shamap_key(account, issuer, currency);
    state.get_trustline(&key).cloned().or_else(|| {
        state
            .get_raw_owned(&key)
            .or_else(|| state.get_committed_raw_owned(&key))
            .and_then(|raw| crate::ledger::RippleState::decode_from_sle(&raw))
    })
}

fn trustline_auth_flag_for(holder: &[u8; 20], line: &crate::ledger::RippleState) -> Option<u32> {
    if holder == &line.low_account {
        Some(crate::ledger::trustline::LSF_LOW_AUTH)
    } else if holder == &line.high_account {
        Some(crate::ledger::trustline::LSF_HIGH_AUTH)
    } else {
        None
    }
}

fn trustline_frozen_by_issuer(line: &crate::ledger::RippleState, issuer: &[u8; 20]) -> bool {
    if issuer == &line.low_account {
        (line.flags & crate::ledger::trustline::LSF_LOW_FREEZE) != 0
    } else if issuer == &line.high_account {
        (line.flags & crate::ledger::trustline::LSF_HIGH_FREEZE) != 0
    } else {
        false
    }
}

fn trustline_deep_frozen(line: &crate::ledger::RippleState) -> bool {
    (line.flags
        & (crate::ledger::trustline::LSF_LOW_DEEP_FREEZE
            | crate::ledger::trustline::LSF_HIGH_DEEP_FREEZE))
        != 0
}

fn issue_require_auth_result(
    state: &LedgerState,
    holder: &[u8; 20],
    issue: &Issue,
) -> Result<(), &'static str> {
    let Issue::Iou { currency, issuer } = issue else {
        return Ok(());
    };
    if holder == issuer {
        return Ok(());
    }
    let Some(issuer_account) = load_account_readonly(state, issuer) else {
        return Err("tecNO_ISSUER");
    };
    if (issuer_account.flags & crate::ledger::account::LSF_REQUIRE_AUTH) == 0 {
        return Ok(());
    }
    let Some(line) = load_trustline_readonly(state, holder, issuer, currency) else {
        return Err("tecNO_LINE");
    };
    let Some(auth_flag) = trustline_auth_flag_for(holder, &line) else {
        return Err("tecNO_LINE");
    };
    if (line.flags & auth_flag) == 0 {
        return Err("tecNO_AUTH");
    }
    Ok(())
}

fn issue_global_frozen(state: &LedgerState, issue: &Issue) -> bool {
    let Issue::Iou { issuer, .. } = issue else {
        return false;
    };
    load_account_readonly(state, issuer)
        .map(|account| (account.flags & crate::ledger::account::LSF_GLOBAL_FREEZE) != 0)
        .unwrap_or(false)
}

fn issue_frozen_for_holder(state: &LedgerState, holder: &[u8; 20], issue: &Issue) -> bool {
    let Issue::Iou { currency, issuer } = issue else {
        return false;
    };
    if issue_global_frozen(state, issue) {
        return true;
    }
    if holder == issuer {
        return false;
    }
    load_trustline_readonly(state, holder, issuer, currency)
        .map(|line| trustline_frozen_by_issuer(&line, issuer) || trustline_deep_frozen(&line))
        .unwrap_or(false)
}

fn amm_check_asset_hold_allowed(
    state: &LedgerState,
    holder: &[u8; 20],
    issue: &Issue,
) -> Result<(), &'static str> {
    issue_require_auth_result(state, holder, issue)?;
    if issue_frozen_for_holder(state, holder, issue) {
        return Err("tecFROZEN");
    }
    Ok(())
}

fn amm_check_asset_not_frozen(
    state: &LedgerState,
    holder: &[u8; 20],
    issue: &Issue,
) -> Result<(), &'static str> {
    if issue_frozen_for_holder(state, holder, issue) {
        return Err("tecFROZEN");
    }
    Ok(())
}

fn amm_check_amount_hold_allowed(
    state: &LedgerState,
    holder: &[u8; 20],
    amount: &Amount,
) -> Result<(), &'static str> {
    let Some(issue) = issue_from_amount(amount) else {
        return Err("temBAD_AMM_TOKENS");
    };
    amm_check_asset_hold_allowed(state, holder, &issue)
}

fn amm_check_deposit_preclaim(
    state: &LedgerState,
    depositor: &[u8; 20],
    amm_account: &[u8; 20],
    asset1: &Issue,
    asset2: &Issue,
    deposit_amounts: &[Amount],
) -> Result<(), &'static str> {
    amm_check_asset_hold_allowed(state, depositor, asset1)?;
    amm_check_asset_hold_allowed(state, depositor, asset2)?;
    amm_check_asset_not_frozen(state, amm_account, asset1)?;
    amm_check_asset_not_frozen(state, amm_account, asset2)?;
    for amount in deposit_amounts {
        amm_check_amount_hold_allowed(state, depositor, amount)?;
        let issue = issue_from_amount(amount).ok_or("temBAD_AMM_TOKENS")?;
        amm_check_asset_not_frozen(state, amm_account, &issue)?;
        if !amm_can_debit_amount(state, depositor, amount) {
            return Err("tecUNFUNDED_AMM");
        }
    }
    Ok(())
}

fn amm_check_withdraw_preclaim(
    state: &LedgerState,
    withdrawer: &[u8; 20],
    amm_account: &[u8; 20],
    amount: &Amount,
    pool_units: u64,
) -> Result<(), &'static str> {
    if amount_pool_units(amount).is_some_and(|units| units > pool_units) {
        return Err("tecAMM_BALANCE");
    }
    let issue = issue_from_amount(amount).ok_or("temBAD_AMM_TOKENS")?;
    amm_check_asset_hold_allowed(state, withdrawer, &issue)?;
    amm_check_asset_not_frozen(state, amm_account, &issue)?;
    Ok(())
}

fn amm_pool_units_from_ledger(
    state: &mut LedgerState,
    pseudo_account: &[u8; 20],
    issue: &Issue,
) -> u64 {
    match issue {
        Issue::Xrp => state
            .get_account(pseudo_account)
            .map(|account| account.balance)
            .unwrap_or(0),
        Issue::Iou { currency, issuer } => {
            let key = crate::ledger::trustline::shamap_key(pseudo_account, issuer, currency);
            let line = state.get_trustline(&key).cloned().or_else(|| {
                state
                    .get_raw_owned(&key)
                    .or_else(|| state.get_committed_raw_owned(&key))
                    .and_then(|raw| crate::ledger::RippleState::decode_from_sle(&raw))
            });
            let Some(line) = line else { return 0 };
            iou_value_floor_units(&line.balance_for(pseudo_account)).unwrap_or(0)
        }
        Issue::Mpt(_) => 0,
    }
}

fn amm_pool_units(
    state: &mut LedgerState,
    amm_raw: &[u8],
    pseudo_account: &[u8; 20],
    asset1: &Issue,
    asset2: &Issue,
) -> (u64, u64) {
    let ledger1 = amm_pool_units_from_ledger(state, pseudo_account, asset1);
    let ledger2 = amm_pool_units_from_ledger(state, pseudo_account, asset2);
    let synthetic1 = amm_sle_number(amm_raw, 10).max(0) as u64;
    let synthetic2 = amm_sle_number(amm_raw, 11).max(0) as u64;
    (
        if ledger1 > 0 { ledger1 } else { synthetic1 },
        if ledger2 > 0 { ledger2 } else { synthetic2 },
    )
}

fn amm_lp_total_units(raw: &[u8]) -> u64 {
    amm_sle_lp_token_balance(raw)
        .as_ref()
        .and_then(amount_pool_units_allow_zero)
        .unwrap_or_else(|| amm_sle_number(raw, 12).max(0) as u64)
}

fn holder_lp_token_units(
    state: &LedgerState,
    holder: &[u8; 20],
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
) -> Option<u64> {
    let Issue::Iou { currency, issuer } = amm_lp_issue(asset1, asset2, amm_account)? else {
        return None;
    };
    let key = crate::ledger::trustline::shamap_key(holder, &issuer, &currency);
    let line = state.get_trustline(&key).cloned().or_else(|| {
        state
            .get_raw_owned(&key)
            .or_else(|| state.get_committed_raw_owned(&key))
            .and_then(|raw| crate::ledger::RippleState::decode_from_sle(&raw))
    })?;
    iou_value_floor_units(&line.balance_for(holder))
}

fn only_positive_lp_holder(
    state: &LedgerState,
    holder: &[u8; 20],
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
) -> bool {
    let Some(Issue::Iou { currency, issuer }) = amm_lp_issue(asset1, asset2, amm_account) else {
        return false;
    };
    let mut saw_holder = false;
    for (_, line) in state.iter_trustlines() {
        if line.currency != currency {
            continue;
        }
        if line.low_account != issuer && line.high_account != issuer {
            continue;
        }
        for account in [line.low_account, line.high_account] {
            if account == issuer {
                continue;
            }
            if !iou_value_floor_units(&line.balance_for(&account)).is_some_and(|units| units > 0) {
                continue;
            }
            if account != *holder {
                return false;
            }
            saw_holder = true;
        }
    }
    saw_holder
}

fn within_amm_clawback_lp_rounding_tolerance(holder_lp: u64, lp_total: u64) -> bool {
    if holder_lp == lp_total {
        return true;
    }
    let diff = holder_lp.abs_diff(lp_total) as u128;
    let max = holder_lp.max(lp_total) as u128;
    diff.saturating_mul(1000) < max
}

fn amm_clawback_adjusted_lp_total(
    state: &LedgerState,
    holder: &[u8; 20],
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
    holder_lp: u64,
    lp_total: u64,
) -> Result<u64, &'static str> {
    if !state.is_amendment_active(&*FEATURE_FIX_AMM_CLAWBACK_ROUNDING) {
        return Ok(lp_total);
    }
    if holder_lp == 0 {
        return Err("tecAMM_BALANCE");
    }
    if only_positive_lp_holder(state, holder, asset1, asset2, amm_account) {
        if within_amm_clawback_lp_rounding_tolerance(holder_lp, lp_total) {
            return Ok(holder_lp);
        }
        return Err("tecAMM_INVALID_TOKENS");
    }
    Ok(lp_total)
}

fn amm_withdraw_lp_burn_from_fields(
    lp_token_in: Option<&Amount>,
    amount_drops: Option<u64>,
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
) -> Result<u64, &'static str> {
    if let Some(lp_token_in) = lp_token_in {
        let Amount::Iou {
            value,
            currency,
            issuer,
        } = lp_token_in
        else {
            return Err("temBAD_AMM_TOKENS");
        };

        let Some(Issue::Iou {
            currency: expected_currency,
            issuer: expected_issuer,
        }) = amm_lp_issue(asset1, asset2, amm_account)
        else {
            return Err("temBAD_AMM_TOKENS");
        };

        if *currency != expected_currency || *issuer != expected_issuer {
            return Err("temBAD_AMM_TOKENS");
        }

        if let Some(units) = iou_value_floor_units(value) {
            return Ok(units);
        }

        return Err("temBAD_AMM_TOKENS");
    }

    let _ = amount_drops;
    Err("temMALFORMED")
}

fn lp_token_units_from_amount(
    amount: Option<&Amount>,
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
) -> Result<u64, &'static str> {
    let Some(amount) = amount else {
        return Err("temMALFORMED");
    };
    amm_withdraw_lp_burn_from_fields(Some(amount), None, asset1, asset2, amm_account)
}

fn lp_token_units_from_amount_allow_zero(
    amount: &Amount,
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
) -> Result<u64, &'static str> {
    let Amount::Iou {
        value,
        currency,
        issuer,
    } = amount
    else {
        return Err("temBAD_AMM_TOKENS");
    };
    let Some(Issue::Iou {
        currency: expected_currency,
        issuer: expected_issuer,
    }) = amm_lp_issue(asset1, asset2, amm_account)
    else {
        return Err("temBAD_AMM_TOKENS");
    };
    if *currency != expected_currency || *issuer != expected_issuer {
        return Err("temBAD_AMM_TOKENS");
    }
    iou_value_floor_units_allow_zero(value).ok_or("temBAD_AMM_TOKENS")
}

fn amount_matches_issue(amount: &Amount, issue: &Issue) -> bool {
    issue_from_amount(amount).as_ref() == Some(issue)
}

fn issue_issuer(issue: &Issue) -> Option<[u8; 20]> {
    match issue {
        Issue::Iou { issuer, .. } => Some(*issuer),
        _ => None,
    }
}

fn issuer_default_ripple_enabled(state: &LedgerState, issue: &Issue) -> bool {
    let Issue::Iou { issuer, .. } = issue else {
        return true;
    };
    state
        .get_account(issuer)
        .cloned()
        .or_else(|| {
            let key = crate::ledger::account::shamap_key(issuer);
            state
                .get_raw_owned(&key)
                .or_else(|| state.get_committed_raw_owned(&key))
                .and_then(|raw| AccountRoot::decode(&raw).ok())
        })
        .map(|account| (account.flags & LSF_DEFAULT_RIPPLE) != 0)
        .unwrap_or(true)
}

fn account_has_ammid(state: &LedgerState, account: &[u8; 20]) -> bool {
    let raw = state
        .get_account(account)
        .and_then(|account| account.raw_sle.clone())
        .or_else(|| {
            let key = crate::ledger::account::shamap_key(account);
            state
                .get_raw_owned(&key)
                .or_else(|| state.get_committed_raw_owned(&key))
        });
    let Some(raw) = raw else {
        return false;
    };
    crate::ledger::meta::parse_sle(&raw)
        .map(|sle| {
            sle.fields
                .iter()
                .any(|field| field.type_code == 5 && field.field_code == 14)
        })
        .unwrap_or(false)
}

fn issue_is_lp_token(state: &LedgerState, issue: &Issue) -> bool {
    issue_issuer(issue)
        .map(|issuer| account_has_ammid(state, &issuer))
        .unwrap_or(false)
}

fn ceil_div_u128(numerator: u128, denominator: u128) -> Option<u64> {
    if denominator == 0 {
        return None;
    }
    let value = numerator.saturating_add(denominator - 1) / denominator;
    u64::try_from(value).ok()
}

fn lp_from_two_asset_deposit(
    deposit1: u64,
    deposit2: u64,
    pool1: u64,
    pool2: u64,
    lp_total: u64,
) -> u64 {
    if lp_total == 0 {
        isqrt(deposit1 as u128 * deposit2 as u128)
    } else if pool1 == 0 || pool2 == 0 {
        0
    } else {
        let ratio1 = (deposit1 as u128 * lp_total as u128) / pool1 as u128;
        let ratio2 = (deposit2 as u128 * lp_total as u128) / pool2 as u128;
        ratio1.min(ratio2) as u64
    }
}

fn lp_from_single_asset_deposit(deposit: u64, pool: u64, lp_total: u64, tfee: u16) -> u64 {
    if pool == 0 || lp_total == 0 {
        return 0;
    }
    lp_tokens_out_for_single_asset(deposit, pool, lp_total, tfee).unwrap_or(0)
}

fn proportional_pool_in_for_lp(pool: u64, lp_out: u64, lp_total: u64) -> Option<u64> {
    ceil_div_u128(pool as u128 * lp_out as u128, lp_total as u128)
}

const AMM_FIXED_SCALE_U128: u128 = 1_000_000_000_000_000_000;

fn amm_fixed_scale() -> BigInt {
    BigInt::from(AMM_FIXED_SCALE_U128)
}

fn amm_fee_scaled(tfee: u16) -> BigInt {
    (BigInt::from(tfee) * amm_fixed_scale()) / BigInt::from(AUCTION_SLOT_FEE_SCALE_FACTOR)
}

fn amm_ratio_scaled(numerator: u64, denominator: u64) -> Option<BigInt> {
    if denominator == 0 {
        return None;
    }
    Some((BigInt::from(numerator) * amm_fixed_scale()) / BigInt::from(denominator))
}

fn amm_fixed_mul(a: &BigInt, b: &BigInt) -> BigInt {
    (a * b) / amm_fixed_scale()
}

fn amm_fixed_div(a: &BigInt, b: &BigInt) -> Option<BigInt> {
    if b == &BigInt::from(0u8) {
        return None;
    }
    Some((a * amm_fixed_scale()) / b)
}

fn amm_biguint_sqrt_floor(n: &BigUint) -> BigUint {
    if n <= &BigUint::from(1u8) {
        return n.clone();
    }
    let two = BigUint::from(2u8);
    let mut x0 = n.clone();
    let mut x1 = (&x0 + n / &x0) / &two;
    while x1 < x0 {
        x0 = x1;
        x1 = (&x0 + n / &x0) / &two;
    }
    x0
}

fn amm_fixed_sqrt(value: &BigInt) -> Option<BigInt> {
    if value.sign() == Sign::Minus {
        return None;
    }
    let n = value.to_biguint()? * BigUint::from(AMM_FIXED_SCALE_U128);
    Some(BigInt::from(amm_biguint_sqrt_floor(&n)))
}

fn amm_floor_scaled(base: u64, frac: &BigInt) -> Option<u64> {
    if frac.sign() != Sign::Plus {
        return None;
    }
    let value = (BigInt::from(base) * frac) / amm_fixed_scale();
    u64::try_from(value).ok()
}

fn amm_ceil_scaled(base: u64, frac: &BigInt) -> Option<u64> {
    if frac.sign() != Sign::Plus {
        return None;
    }
    let scale = amm_fixed_scale();
    let numerator = BigInt::from(base) * frac;
    let value = (&numerator + (&scale - 1u8)) / scale;
    u64::try_from(value).ok()
}

fn amm_single_asset_fee_terms(tfee: u16) -> Option<(BigInt, BigInt, BigInt)> {
    let scale = amm_fixed_scale();
    let fee = amm_fee_scaled(tfee);
    if fee >= scale {
        return None;
    }
    let f1 = &scale - &fee;
    let f2_num = &scale - (&fee / 2u8);
    let f2 = amm_fixed_div(&f2_num, &f1)?;
    Some((fee, f1, f2))
}

fn lp_tokens_out_for_single_asset(
    deposit: u64,
    pool: u64,
    lp_total: u64,
    tfee: u16,
) -> Option<u64> {
    if deposit == 0 || pool == 0 || lp_total == 0 {
        return None;
    }
    let scale = amm_fixed_scale();
    let (_, f1, f2) = amm_single_asset_fee_terms(tfee)?;
    let r = amm_ratio_scaled(deposit, pool)?;
    let f2_squared = amm_fixed_mul(&f2, &f2);
    let r_over_f1 = amm_fixed_div(&r, &f1)?;
    let root = amm_fixed_sqrt(&(f2_squared + r_over_f1))?;
    let c = root - f2;
    let frac = amm_fixed_div(&(r - &c), &(scale + c))?;
    amm_floor_scaled(lp_total, &frac)
}

fn single_asset_in_for_lp(pool: u64, lp_out: u64, lp_total: u64, tfee: u16) -> Option<u64> {
    if pool == 0 || lp_out == 0 || lp_total == 0 || lp_out >= lp_total {
        return None;
    }
    let mut high = 1u64;
    while lp_tokens_out_for_single_asset(high, pool, lp_total, tfee)? < lp_out {
        let next = high.saturating_mul(2);
        if next == high {
            return None;
        }
        high = next;
    }

    let mut low = 1u64;
    while low < high {
        let mid = low + (high - low) / 2;
        if lp_tokens_out_for_single_asset(mid, pool, lp_total, tfee)? >= lp_out {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    Some(low)
}

fn single_withdraw_lp_burn(withdraw: u64, pool: u64, lp_total: u64, tfee: u16) -> Option<u64> {
    if withdraw == 0 || pool == 0 || withdraw > pool || lp_total == 0 {
        return None;
    }
    let scale = amm_fixed_scale();
    let fee = amm_fee_scaled(tfee);
    let r = amm_ratio_scaled(withdraw, pool)?;
    let c = amm_fixed_mul(&r, &fee) + (&scale * 2u8) - fee;
    let discriminant = amm_fixed_mul(&c, &c) - (r * 4u8);
    let root = amm_fixed_sqrt(&discriminant)?;
    let frac = (c - root) / 2u8;
    amm_ceil_scaled(lp_total, &frac)
}

fn single_asset_out_for_lp(pool: u64, lp_burn: u64, lp_total: u64, tfee: u16) -> Option<u64> {
    if pool == 0 || lp_burn == 0 || lp_total == 0 || lp_burn > lp_total {
        return None;
    }
    let scale = amm_fixed_scale();
    let fee = amm_fee_scaled(tfee);
    let t1 = amm_ratio_scaled(lp_burn, lp_total)?;
    let denominator = amm_fixed_mul(&t1, &fee) - &scale;
    if denominator == BigInt::from(0u8) {
        return None;
    }
    let numerator = amm_fixed_mul(&t1, &t1) - amm_fixed_mul(&t1, &((&scale * 2u8) - fee));
    let frac = amm_fixed_div(&numerator, &denominator)?;
    amm_floor_scaled(pool, &frac)
}

fn validate_amm_withdraw_mode(tx: &ParsedTx) -> Result<u32, &'static str> {
    let submode = tx.flags & TF_AMM_WITHDRAW_MASK;
    if submode.count_ones() != 1 {
        return Err("temMALFORMED");
    }

    match submode {
        TF_AMM_WITHDRAW_LP_TOKEN => {
            if tx.lp_token_in.is_none()
                || tx.amount.is_some()
                || tx.amount2.is_some()
                || tx.eprice.is_some()
                || tx.amount_drops.is_some()
            {
                return Err("temMALFORMED");
            }
        }
        TF_AMM_WITHDRAW_ALL => {
            if tx.lp_token_in.is_some()
                || tx.amount.is_some()
                || tx.amount2.is_some()
                || tx.eprice.is_some()
                || tx.amount_drops.is_some()
            {
                return Err("temMALFORMED");
            }
        }
        TF_AMM_TWO_ASSET => {
            if tx.amount.is_none()
                || tx.amount2.is_none()
                || tx.lp_token_in.is_some()
                || tx.eprice.is_some()
                || tx.amount_drops.is_some()
            {
                return Err("temMALFORMED");
            }
        }
        TF_AMM_SINGLE_ASSET | TF_AMM_ONE_ASSET_WITHDRAW_ALL => {
            if tx.amount.is_none()
                || tx.amount2.is_some()
                || tx.lp_token_in.is_some()
                || tx.eprice.is_some()
                || tx.amount_drops.is_some()
            {
                return Err("temMALFORMED");
            }
        }
        TF_AMM_ONE_ASSET_LP_TOKEN | TF_AMM_LIMIT_LP_TOKEN => {
            if tx.amount.is_none()
                || tx.amount2.is_some()
                || (submode == TF_AMM_ONE_ASSET_LP_TOKEN && tx.lp_token_in.is_none())
                || (submode == TF_AMM_LIMIT_LP_TOKEN && tx.lp_token_in.is_some())
                || (submode == TF_AMM_ONE_ASSET_LP_TOKEN && tx.eprice.is_some())
                || (submode == TF_AMM_LIMIT_LP_TOKEN && tx.eprice.is_none())
                || tx.amount_drops.is_some()
            {
                return Err("temMALFORMED");
            }
        }
        _ => return Err("temMALFORMED"),
    }

    Ok(submode)
}

#[cfg(test)]
fn validate_amm_withdraw_lp_token_mode(tx: &ParsedTx) -> Result<(), &'static str> {
    match validate_amm_withdraw_mode(tx)? {
        TF_AMM_WITHDRAW_LP_TOKEN => Ok(()),
        _ => Err("temMALFORMED"),
    }
}

fn validate_amm_deposit_mode(tx: &ParsedTx) -> Result<u32, &'static str> {
    let submode = tx.flags & TF_AMM_DEPOSIT_MASK;
    if submode.count_ones() != 1 {
        return Err("temMALFORMED");
    }

    if tx.trading_fee.is_some() && submode != TF_AMM_TWO_ASSET_IF_EMPTY {
        return Err("temMALFORMED");
    }

    match submode {
        TF_AMM_TWO_ASSET | TF_AMM_TWO_ASSET_IF_EMPTY => {
            if tx.amount.is_none()
                || tx.amount2.is_none()
                || tx.eprice.is_some()
                || (submode == TF_AMM_TWO_ASSET_IF_EMPTY && tx.lp_token_out.is_some())
            {
                return Err("temMALFORMED");
            }
        }
        TF_AMM_SINGLE_ASSET => {
            if tx.amount.is_none() || tx.amount2.is_some() || tx.eprice.is_some() {
                return Err("temMALFORMED");
            }
        }
        TF_AMM_WITHDRAW_LP_TOKEN => {
            if tx.lp_token_out.is_none()
                || (tx.amount.is_some() != tx.amount2.is_some())
                || tx.eprice.is_some()
            {
                return Err("temMALFORMED");
            }
        }
        TF_AMM_ONE_ASSET_LP_TOKEN => {
            if tx.amount.is_none() || tx.amount2.is_some() || tx.lp_token_out.is_none() {
                return Err("temMALFORMED");
            }
        }
        TF_AMM_LIMIT_LP_TOKEN => {
            if tx.amount.is_none()
                || tx.amount2.is_some()
                || tx.lp_token_out.is_some()
                || tx.eprice.is_none()
            {
                return Err("temMALFORMED");
            }
        }
        _ => return Err("temMALFORMED"),
    }

    Ok(submode)
}

/// Read a NUMBER field from an AMM SLE.
fn amm_sle_number(raw: &[u8], field_code: u16) -> i64 {
    let parsed = match crate::ledger::meta::parse_sle(raw) {
        Some(p) => p,
        None => return 0,
    };
    for field in &parsed.fields {
        if field.type_code == 9 && field.field_code == field_code && field.data.len() == 8 {
            return i64::from_be_bytes(field.data[..8].try_into().unwrap());
        }
    }
    0
}

/// Patch a NUMBER field on an AMM SLE.
fn amm_patch_number(raw: &[u8], field_code: u16, value: i64) -> Vec<u8> {
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 9,
            field_code,
            data: value.to_be_bytes().to_vec(),
        }],
        None,
        None,
        &[],
    )
}

fn amm_patch_lp_token_balance(
    raw: &[u8],
    asset1: &Issue,
    asset2: &Issue,
    amm_account: [u8; 20],
    lp_total: i64,
) -> Vec<u8> {
    let Some(lp_balance) = lp_token_balance_amount(asset1, asset2, amm_account, lp_total) else {
        return raw.to_vec();
    };
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 6,
            field_code: 31,
            data: lp_balance.to_bytes(),
        }],
        None,
        None,
        &[],
    )
}

fn patch_account_ammid(raw: &[u8], amm_id: &[u8; 32]) -> Vec<u8> {
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            // sfAMMID (UINT256=5, field=14)
            type_code: 5,
            field_code: 14,
            data: amm_id.to_vec(),
        }],
        None,
        None,
        &[],
    )
}

#[allow(dead_code)]
fn amm_sle_auction_expiration(raw: &[u8]) -> Option<u32> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    let auction_slot = parsed
        .fields
        .iter()
        .find(|field| field.type_code == 14 && field.field_code == 26)?;
    let mut pos = 0usize;
    while pos < auction_slot.data.len() {
        let (tc, fc, new_pos) = crate::ledger::meta::read_field_header(&auction_slot.data, pos);
        if (tc, fc) == (14, 1) || new_pos > auction_slot.data.len() {
            break;
        }
        pos = new_pos;
        if (tc, fc) == (2, 10) && pos + 4 <= auction_slot.data.len() {
            return Some(u32::from_be_bytes(
                auction_slot.data[pos..pos + 4].try_into().unwrap(),
            ));
        }
        pos = crate::ledger::meta::skip_field_raw(&auction_slot.data, pos, tc);
    }
    None
}

#[derive(Debug, Clone)]
struct AuctionSlotInfo {
    account: Option<[u8; 20]>,
    expiration: u32,
    price: Amount,
    auth_accounts: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct VoteSlotInfo {
    account: [u8; 20],
    trading_fee: u16,
    vote_weight: u32,
}

fn build_auction_slot_with_auth(
    account: &[u8; 20],
    expiration: u32,
    discounted_fee: u16,
    price: &Amount,
    auth_accounts: Option<&[u8]>,
) -> Vec<u8> {
    let mut slot = Vec::new();
    if discounted_fee != 0 {
        crate::ledger::meta::write_field_header_pub(&mut slot, 1, 6); // sfDiscountedFee
        slot.extend_from_slice(&discounted_fee.to_be_bytes());
    }
    crate::ledger::meta::write_field_header_pub(&mut slot, 2, 10); // sfExpiration
    slot.extend_from_slice(&expiration.to_be_bytes());
    crate::ledger::meta::write_field_header_pub(&mut slot, 6, 28); // sfPrice
    slot.extend_from_slice(&price.to_bytes());
    crate::ledger::meta::write_field_header_pub(&mut slot, 8, 1); // sfAccount
    slot.push(20);
    slot.extend_from_slice(account);
    if let Some(auth_accounts) = auth_accounts {
        crate::ledger::meta::write_field_header_pub(&mut slot, 15, 25); // sfAuthAccounts
        slot.extend_from_slice(auth_accounts);
    }
    slot.push(0xE1); // OBJECT_END_MARKER
    slot
}

fn build_auction_slot(
    account: &[u8; 20],
    expiration: u32,
    discounted_fee: u16,
    price: &Amount,
) -> Vec<u8> {
    build_auction_slot_with_auth(account, expiration, discounted_fee, price, None)
}

fn build_auth_accounts_array(accounts: &[[u8; 20]]) -> Option<Vec<u8>> {
    if accounts.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for account in accounts {
        crate::ledger::meta::write_field_header_pub(&mut out, 14, 27); // sfAuthAccount
        crate::ledger::meta::write_field_header_pub(&mut out, 8, 1); // sfAccount
        out.push(20);
        out.extend_from_slice(account);
        out.push(0xE1); // OBJECT_END_MARKER
    }
    out.push(0xF1); // ARRAY_END_MARKER
    Some(out)
}

#[allow(dead_code)]
fn amm_patch_auction_slot(
    raw: &[u8],
    account: &[u8; 20],
    expiration: u32,
    discounted_fee: u16,
    price: &Amount,
) -> Vec<u8> {
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            // sfAuctionSlot (OBJECT=14, field=26)
            type_code: 14,
            field_code: 26,
            data: build_auction_slot(account, expiration, discounted_fee, price),
        }],
        None,
        None,
        &[],
    )
}

fn amm_patch_auction_slot_with_auth(
    raw: &[u8],
    account: &[u8; 20],
    expiration: u32,
    discounted_fee: u16,
    price: &Amount,
    auth_accounts: Option<&[u8]>,
) -> Vec<u8> {
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 14,
            field_code: 26,
            data: build_auction_slot_with_auth(
                account,
                expiration,
                discounted_fee,
                price,
                auth_accounts,
            ),
        }],
        None,
        None,
        &[],
    )
}

fn amm_sle_auction_info(raw: &[u8]) -> Option<AuctionSlotInfo> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    let auction_slot = parsed
        .fields
        .iter()
        .find(|field| field.type_code == 14 && field.field_code == 26)?;
    let mut account = None::<[u8; 20]>;
    let mut expiration = 0u32;
    let mut price = None::<Amount>;
    let mut auth_accounts = None::<Vec<u8>>;
    let mut pos = 0usize;
    while pos < auction_slot.data.len() {
        if auction_slot.data[pos] == 0xE1 {
            break;
        }
        let (tc, fc, new_pos) = crate::ledger::meta::read_field_header(&auction_slot.data, pos);
        if new_pos > auction_slot.data.len() {
            break;
        }
        pos = new_pos;
        match (tc, fc) {
            (2, 10) if pos + 4 <= auction_slot.data.len() => {
                expiration =
                    u32::from_be_bytes(auction_slot.data[pos..pos + 4].try_into().unwrap());
                pos += 4;
            }
            (6, 28) => {
                let end = crate::ledger::meta::skip_field_raw(&auction_slot.data, pos, tc);
                if end <= auction_slot.data.len() {
                    price = Amount::from_bytes(&auction_slot.data[pos..end])
                        .ok()
                        .map(|(amount, _)| amount);
                }
                pos = end;
            }
            (8, 1) => {
                let (len, consumed) =
                    crate::ledger::meta::decode_vl_length(&auction_slot.data, pos);
                pos += consumed;
                if len == 20 && pos + 20 <= auction_slot.data.len() {
                    let mut id = [0u8; 20];
                    id.copy_from_slice(&auction_slot.data[pos..pos + 20]);
                    account = Some(id);
                }
                pos = (pos + len).min(auction_slot.data.len());
            }
            (15, 25) => {
                let end = crate::ledger::meta::skip_field_raw(&auction_slot.data, pos, tc);
                if end <= auction_slot.data.len() {
                    auth_accounts = Some(auction_slot.data[pos..end].to_vec());
                }
                pos = end;
            }
            _ => {
                pos = crate::ledger::meta::skip_field_raw(&auction_slot.data, pos, tc);
            }
        }
    }
    Some(AuctionSlotInfo {
        account,
        expiration,
        price: price.unwrap_or(Amount::Xrp(0)),
        auth_accounts,
    })
}

fn amm_patch_auction_discounted_fee(raw: &[u8], discounted_fee: u16) -> Vec<u8> {
    let Some(info) = amm_sle_auction_info(raw) else {
        return raw.to_vec();
    };
    let Some(account) = info.account else {
        return raw.to_vec();
    };
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 14,
            field_code: 26,
            data: build_auction_slot_with_auth(
                &account,
                info.expiration,
                discounted_fee,
                &info.price,
                info.auth_accounts.as_deref(),
            ),
        }],
        None,
        None,
        &[],
    )
}

fn build_vote_entry(account: &[u8; 20], trading_fee: u16, vote_weight: u32) -> Vec<u8> {
    let mut entry = Vec::new();
    if trading_fee != 0 {
        crate::ledger::meta::write_field_header_pub(&mut entry, 1, 5); // sfTradingFee
        entry.extend_from_slice(&trading_fee.to_be_bytes());
    }
    crate::ledger::meta::write_field_header_pub(&mut entry, 2, 48); // sfVoteWeight
    entry.extend_from_slice(&vote_weight.to_be_bytes());
    crate::ledger::meta::write_field_header_pub(&mut entry, 8, 1); // sfAccount
    entry.push(20);
    entry.extend_from_slice(account);
    entry.push(0xE1); // OBJECT_END_MARKER
    entry
}

fn build_vote_slots(votes: &[VoteSlotInfo]) -> Vec<u8> {
    let mut slots = Vec::new();
    for vote in votes {
        crate::ledger::meta::write_field_header_pub(&mut slots, 14, 25); // sfVoteEntry
        slots.extend_from_slice(&build_vote_entry(
            &vote.account,
            vote.trading_fee,
            vote.vote_weight,
        ));
    }
    slots.push(0xF1); // ARRAY_END_MARKER
    slots
}

fn amm_sle_vote_slots(raw: &[u8]) -> Vec<VoteSlotInfo> {
    let Some(parsed) = crate::ledger::meta::parse_sle(raw) else {
        return Vec::new();
    };
    let Some(vote_slots) = parsed
        .fields
        .iter()
        .find(|field| field.type_code == 15 && field.field_code == 12)
    else {
        return Vec::new();
    };
    let mut votes = Vec::new();
    let mut pos = 0usize;
    while pos < vote_slots.data.len() {
        if vote_slots.data[pos] == 0xF1 {
            break;
        }
        let (tc, fc, new_pos) = crate::ledger::meta::read_field_header(&vote_slots.data, pos);
        if new_pos > vote_slots.data.len() {
            break;
        }
        pos = new_pos;
        if (tc, fc) != (14, 25) {
            pos = crate::ledger::meta::skip_field_raw(&vote_slots.data, pos, tc);
            continue;
        }

        let mut account = None::<[u8; 20]>;
        let mut trading_fee = 0u16;
        let mut vote_weight = 0u32;
        while pos < vote_slots.data.len() && vote_slots.data[pos] != 0xE1 {
            let (inner_tc, inner_fc, inner_pos) =
                crate::ledger::meta::read_field_header(&vote_slots.data, pos);
            if inner_pos > vote_slots.data.len() {
                break;
            }
            pos = inner_pos;
            match (inner_tc, inner_fc) {
                (1, 5) if pos + 2 <= vote_slots.data.len() => {
                    trading_fee =
                        u16::from_be_bytes(vote_slots.data[pos..pos + 2].try_into().unwrap());
                    pos += 2;
                }
                (2, 48) if pos + 4 <= vote_slots.data.len() => {
                    vote_weight =
                        u32::from_be_bytes(vote_slots.data[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                }
                (8, 1) => {
                    let (len, consumed) =
                        crate::ledger::meta::decode_vl_length(&vote_slots.data, pos);
                    pos += consumed;
                    if len == 20 && pos + 20 <= vote_slots.data.len() {
                        let mut id = [0u8; 20];
                        id.copy_from_slice(&vote_slots.data[pos..pos + 20]);
                        account = Some(id);
                    }
                    pos = (pos + len).min(vote_slots.data.len());
                }
                _ => {
                    pos = crate::ledger::meta::skip_field_raw(&vote_slots.data, pos, inner_tc);
                }
            }
        }
        if pos < vote_slots.data.len() && vote_slots.data[pos] == 0xE1 {
            pos += 1;
        }
        if let Some(account) = account {
            votes.push(VoteSlotInfo {
                account,
                trading_fee,
                vote_weight,
            });
        }
    }
    votes
}

fn amm_patch_vote_slots(raw: &[u8], votes: &[VoteSlotInfo]) -> Vec<u8> {
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 15,
            field_code: 12,
            data: build_vote_slots(votes),
        }],
        None,
        None,
        &[],
    )
}

fn vote_weight(lp_tokens: u64, lp_total: u64) -> u32 {
    if lp_total == 0 {
        return 0;
    }
    ((lp_tokens as u128 * VOTE_WEIGHT_SCALE_FACTOR as u128) / lp_total as u128) as u32
}

fn auction_time_slot(current: u64, slot: &AuctionSlotInfo) -> Option<u64> {
    if slot.expiration < AUCTION_SLOT_SECONDS {
        return None;
    }
    let start = slot.expiration as u64 - AUCTION_SLOT_SECONDS as u64;
    if current < start {
        return None;
    }
    let elapsed = current - start;
    if elapsed >= AUCTION_SLOT_SECONDS as u64 {
        return None;
    }
    Some(elapsed / AUCTION_SLOT_INTERVAL_SECONDS)
}

fn biguint_to_u64_saturating(value: BigUint) -> u64 {
    let digits = value.to_u64_digits();
    if digits.len() > 1 {
        u64::MAX
    } else {
        digits.first().copied().unwrap_or(0)
    }
}

fn auction_rebid_computed_price(purchased: u64, time_slot: u64, min_slot_price: u64) -> u64 {
    let uplift = BigUint::from(purchased) * BigUint::from(105u32);
    let base = if time_slot == 0 {
        uplift / BigUint::from(100u32)
    } else {
        let interval = BigUint::from(AUCTION_SLOT_TIME_INTERVALS);
        let used = BigUint::from(time_slot + 1);
        let denominator = interval.pow(60);
        let used_power = used.pow(60);
        if used_power >= denominator {
            BigUint::from(0u32)
        } else {
            uplift * (denominator.clone() - used_power) / (BigUint::from(100u32) * denominator)
        }
    };
    biguint_to_u64_saturating(base).saturating_add(min_slot_price)
}

fn auction_rebid_refund_units(purchased: u64, time_slot: u64) -> u64 {
    let remaining = AUCTION_SLOT_TIME_INTERVALS.saturating_sub(time_slot + 1);
    let refund = purchased as u128 * remaining as u128 / AUCTION_SLOT_TIME_INTERVALS as u128;
    refund.min(u64::MAX as u128) as u64
}

#[allow(dead_code)]
fn amm_sle_lp_token_balance(raw: &[u8]) -> Option<Amount> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    for field in &parsed.fields {
        if field.type_code == 6 && field.field_code == 31 {
            return Amount::from_bytes(&field.data)
                .ok()
                .map(|(amount, _)| amount);
        }
    }
    None
}

/// Integer square root (floor).
fn isqrt(n: u128) -> u64 {
    if n <= 1 {
        return n as u64;
    }
    let mut x = (n / 2) + 1;
    let mut y = (x + n / x) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x as u64
}

/// Extract sfAccount from an AMM SLE.
fn amm_sle_pseudo_id(raw: &[u8]) -> Option<[u8; 20]> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    for field in &parsed.fields {
        if field.type_code == 8 && field.field_code == 1 && field.data.len() == 20 {
            let mut id = [0u8; 20];
            id.copy_from_slice(&field.data);
            return Some(id);
        }
    }
    None
}

fn load_amm_raw(state: &LedgerState, key: &Key) -> Option<Vec<u8>> {
    state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))
}

fn sle_uint64(raw: &[u8], field_code: u16) -> u64 {
    let Some(parsed) = crate::ledger::meta::parse_sle(raw) else {
        return 0;
    };
    parsed
        .fields
        .iter()
        .find(|field| field.type_code == 3 && field.field_code == field_code)
        .and_then(|field| field.data.as_slice().try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AmmAccountDelete {
    Deleted,
    Incomplete,
}

fn reserve_flag_for_trustline_account(
    line: &crate::ledger::RippleState,
    account: &[u8; 20],
) -> u32 {
    if account == &line.low_account {
        crate::ledger::trustline::LSF_LOW_RESERVE
    } else if account == &line.high_account {
        crate::ledger::trustline::LSF_HIGH_RESERVE
    } else {
        0
    }
}

fn load_amm_owner_dir_entries(state: &LedgerState, pseudo_account: &[u8; 20]) -> Vec<Key> {
    let root_key = directory::owner_dir_key(pseudo_account);
    let mut entries = Vec::new();
    let mut current_page_num = 0u64;
    let mut pages_seen = 0usize;
    loop {
        let page_key = directory::page_key(&root_key.0, current_page_num);
        let Some(page) = directory::load_directory_fresh(state, &page_key) else {
            break;
        };
        entries.extend(page.indexes.iter().copied().map(Key));
        if page.index_next == 0 || page.index_next == current_page_num {
            break;
        }
        current_page_num = page.index_next;
        pages_seen += 1;
        if pages_seen > MAX_DELETABLE_AMM_TRUSTLINES + 16 {
            break;
        }
    }
    entries
}

fn load_trustline_for_delete(
    state: &mut LedgerState,
    key: &Key,
) -> Option<crate::ledger::RippleState> {
    if let Some(line) = state.get_trustline(key) {
        return Some(line.clone());
    }
    let raw = state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))?;
    let decoded = crate::ledger::RippleState::decode_from_sle(&raw)?;
    state.hydrate_trustline(decoded.clone());
    Some(decoded)
}

fn delete_amm_trustline(
    state: &mut LedgerState,
    pseudo_account: &[u8; 20],
    key: &Key,
) -> Result<(), &'static str> {
    let Some(line) = load_trustline_for_delete(state, key) else {
        return Err("tecINTERNAL");
    };
    if !line.balance.is_zero() {
        return Err("tecINTERNAL");
    }
    let amm_is_low = pseudo_account == &line.low_account;
    let amm_is_high = pseudo_account == &line.high_account;
    if amm_is_low == amm_is_high {
        return Err("terNO_AMM");
    }
    let other_account = if amm_is_low {
        line.high_account
    } else {
        line.low_account
    };
    if state.get_account(pseudo_account).is_none() || state.get_account(&other_account).is_none() {
        return Err("tecINTERNAL");
    }
    let target_is_amm = account_has_ammid(state, pseudo_account);
    let other_is_amm = account_has_ammid(state, &other_account);
    if target_is_amm && other_is_amm {
        return Err("tecINTERNAL");
    }
    if !target_is_amm && !other_is_amm {
        return Err("terNO_AMM");
    }
    let other_reserve_flag = reserve_flag_for_trustline_account(&line, &other_account);
    let other_reserved = (line.flags & other_reserve_flag) != 0;

    directory::dir_remove_owner_page(state, &line.low_account, line.low_node, &key.0);
    directory::dir_remove_owner_page(state, &line.high_account, line.high_node, &key.0);
    state.remove_trustline(key);

    if other_reserved {
        if let Some(account) = state.get_account(&other_account) {
            let mut account = account.clone();
            account.owner_count = account.owner_count.saturating_sub(1);
            state.insert_account(account);
        }
    }
    Ok(())
}

fn cleanup_amm_account_trustlines(
    state: &mut LedgerState,
    pseudo_account: &[u8; 20],
    amm_key: &Key,
    max_entries: usize,
) -> Result<AmmAccountDelete, &'static str> {
    let mut visited = 0usize;
    let mut skipped_amm = false;
    loop {
        let entries = load_amm_owner_dir_entries(state, pseudo_account);
        let mut next_trustline = None;
        for key in entries {
            if key == *amm_key {
                if !skipped_amm {
                    if visited >= max_entries {
                        return Ok(AmmAccountDelete::Incomplete);
                    }
                    visited += 1;
                    skipped_amm = true;
                }
                continue;
            }
            if visited >= max_entries {
                return Ok(AmmAccountDelete::Incomplete);
            }
            visited += 1;
            next_trustline = Some(key);
            break;
        }
        let Some(next_key) = next_trustline else {
            return Ok(AmmAccountDelete::Deleted);
        };
        delete_amm_trustline(state, pseudo_account, &next_key)?;
    }
}

fn delete_amm_account(
    state: &mut LedgerState,
    key: &Key,
    pseudo_account: &[u8; 20],
) -> Result<AmmAccountDelete, &'static str> {
    let cleanup =
        cleanup_amm_account_trustlines(state, pseudo_account, key, amm_delete_trustline_limit())?;
    if cleanup == AmmAccountDelete::Incomplete {
        return Ok(AmmAccountDelete::Incomplete);
    }
    let owner_node = load_amm_raw(state, key)
        .as_deref()
        .map(|raw| sle_uint64(raw, 4))
        .unwrap_or(0);
    if !directory::dir_remove_owner_page(state, pseudo_account, owner_node, &key.0) {
        return Err("tecINTERNAL");
    }
    state.remove_account(pseudo_account);
    state.remove_raw(key);
    Ok(AmmAccountDelete::Deleted)
}

fn patch_amm_empty_balances(
    raw: &[u8],
    asset1: &Issue,
    asset2: &Issue,
    pseudo_account: [u8; 20],
) -> Vec<u8> {
    let raw = amm_patch_number(raw, 10, 0);
    let raw = amm_patch_number(&raw, 11, 0);
    let raw = amm_patch_number(&raw, 12, 0);
    amm_patch_lp_token_balance(&raw, asset1, asset2, pseudo_account, 0)
}

fn remove_empty_amm(
    state: &mut LedgerState,
    key: &Key,
    pseudo_account: &[u8; 20],
) -> Result<AmmAccountDelete, &'static str> {
    delete_amm_account(state, key, pseudo_account)
}

// ── Transaction handlers ─────────────────────────────────────────────────────

/// Type 35: AMMCreate — create an AMM with two assets.
///
/// Creates: pseudo-account, AMM SLE with asset pair and trading fee.
/// The AMM SLE is owned by the pseudo-account. The creator pays the owner
/// reserve fee and may own the LP-token trust line, but does not own the AMM
/// ledger object itself.
///
/// (rippled: AMMCreate.cpp — doApply)
pub(crate) fn apply_amm_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
) -> ApplyResult {
    // 1. Validate two distinct assets. rippled derives these from
    // sfAmount/sfAmount2; AMMCreate does not carry sfAsset/sfAsset2.
    let amount_field = match tx.amount.as_ref() {
        Some(amount) => amount,
        None => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    let amount2_field = match tx.amount2.as_ref() {
        Some(amount) => amount,
        None => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    let asset1 = match issue_from_amount(amount_field) {
        Some(asset) => asset,
        None => return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS"),
    };
    let asset2 = match issue_from_amount(amount2_field) {
        Some(asset) => asset,
        None => return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS"),
    };
    if asset1 == asset2 {
        return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
    }
    if !issuer_default_ripple_enabled(state, &asset1)
        || !issuer_default_ripple_enabled(state, &asset2)
    {
        return ApplyResult::ClaimedCost("terNO_RIPPLE");
    }
    if issue_is_lp_token(state, &asset1) || issue_is_lp_token(state, &asset2) {
        return ApplyResult::ClaimedCost("tecAMM_INVALID_TOKENS");
    }

    // 2. Compute AMM key and check it doesn't already exist
    let akey = amm_key(&asset1, &asset2);
    if load_amm_raw(state, &akey).is_some() {
        return ApplyResult::ClaimedCost("tecDUPLICATE");
    }

    // 3. Validate AMMCreate's real transaction fields before mutating state.
    let trading_fee = match tx.trading_fee {
        Some(fee) if fee <= TRADING_FEE_THRESHOLD => fee,
        Some(_) => return ApplyResult::ClaimedCost("temBAD_FEE"),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let amount1 = match amount_pool_units(amount_field) {
        Some(value) if value > 0 => value,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    let amount2 = match amount_pool_units(amount2_field) {
        Some(value) if value > 0 => value,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    let lp_total = isqrt(amount1 as u128 * amount2 as u128);
    if lp_total == 0 {
        return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
    }
    let xrp_liquidity = [&tx.amount, &tx.amount2]
        .into_iter()
        .flatten()
        .filter_map(|amount| match amount {
            Amount::Xrp(drops) => Some(*drops),
            _ => None,
        })
        .sum::<u64>();
    let sender = match state.get_account(&tx.account) {
        Some(sender) => sender,
        None => return ApplyResult::ClaimedCost("tecNO_ACCOUNT"),
    };
    let pre_fee_balance = balance_before_fee(sender.balance, tx.fee);
    let owner_reserve = owner_reserve_requirement(state, sender.owner_count, 1);
    let xrp_liquid = pre_fee_balance.saturating_sub(owner_reserve);
    if xrp_liquid == 0 {
        return ApplyResult::ClaimedCost("tecINSUF_RESERVE_LINE");
    }
    if xrp_liquidity > xrp_liquid {
        return ApplyResult::ClaimedCost("tecUNFUNDED_AMM");
    }
    if !amm_can_debit_amount(state, &tx.account, amount_field)
        || !amm_can_debit_amount(state, &tx.account, amount2_field)
    {
        return ApplyResult::ClaimedCost("tecUNFUNDED_AMM");
    }
    if let Err(code) = amm_check_amount_hold_allowed(state, &tx.account, amount_field) {
        return ApplyResult::ClaimedCost(code);
    }
    if let Err(code) = amm_check_amount_hold_allowed(state, &tx.account, amount2_field) {
        return ApplyResult::ClaimedCost(code);
    }

    // 4. Derive pseudo-account
    let pseudo_id = match pseudo_account_address(state, &ctx.parent_hash, &akey.0) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("terADDRESS_COLLISION"),
    };

    // 5. Create pseudo-account
    let mut pseudo_account = AccountRoot {
        account_id: pseudo_id,
        balance: 0,
        sequence: 0,
        owner_count: 0,
        flags: LSF_DISABLE_MASTER | LSF_DEFAULT_RIPPLE | LSF_DEPOSIT_AUTH,
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
    };
    pseudo_account.raw_sle = Some(patch_account_ammid(&pseudo_account.encode(), &akey.0));
    state.insert_account(pseudo_account);

    // 6. Add AMM to pseudo-account's directory
    let owner_node = directory::dir_add(state, &pseudo_id, akey.0);

    // 7. Create AMM SLE using real AMM transaction fields.
    let amm_sle = build_amm_sle(
        &pseudo_id,
        &asset1,
        &asset2,
        trading_fee,
        owner_node,
        amount1 as i64,
        amount2 as i64,
        lp_total as i64,
    );
    let amm_sle = initialize_fee_auction_vote(
        &amm_sle,
        &tx.account,
        &asset1,
        &asset2,
        pseudo_id,
        ctx.close_time,
        trading_fee,
    );
    state.insert_raw(akey, amm_sle);

    // 8. Increment pseudo-account owner_count
    if let Some(pa) = state.get_account(&pseudo_id) {
        let mut pa = pa.clone();
        pa.owner_count += 1;
        state.insert_account(pa);
    }

    // 9. Move initial liquidity into the AMM pseudo-account. The synthetic
    // pool counters are still retained for the current simplified math, but
    // the ledger now also reflects the actual reserve balances.
    if !transfer_amount_between_accounts_waiving_issuer_fee(
        state,
        &tx.account,
        &pseudo_id,
        amount_field,
    ) || !transfer_amount_between_accounts_waiving_issuer_fee(
        state,
        &tx.account,
        &pseudo_id,
        amount2_field,
    ) {
        return ApplyResult::ClaimedCost("tecUNFUNDED_AMM");
    }
    if !ensure_pool_asset_trustline_lifecycle(state, &pseudo_id, amount_field)
        || !ensure_pool_asset_trustline_lifecycle(state, &pseudo_id, amount2_field)
    {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    }
    if !issue_lp_tokens(
        state,
        &tx.account,
        &asset1,
        &asset2,
        pseudo_id,
        lp_total as u64,
    ) {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    }

    ApplyResult::Success
}

/// Type 40: AMMDelete — delete an empty AMM.
///
/// Validates: LP token balance is 0 (empty pool).
/// Removes: AMM SLE, pseudo-account.
///
/// (rippled: AMMDelete.cpp — doApply)
pub(crate) fn apply_amm_delete(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    // 1. Find AMM — need both assets to compute key
    let asset1 = match &tx.asset {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let asset2 = match &tx.asset2 {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let akey = amm_key(&asset1, &asset2);
    let amm_raw = match load_amm_raw(state, &akey) {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("terNO_AMM"),
    };

    // 2. Get pseudo-account
    let pseudo_id = match amm_sle_pseudo_id(&amm_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 3. AMM must have no outstanding LP supply. rippled AMMDelete preclaim
    // keys emptiness off sfLPTokenBalance; zero-balance AMM trust lines are
    // cleaned below, possibly across multiple tecINCOMPLETE calls.
    let lp_total = amm_lp_total_units(&amm_raw);
    if lp_total != 0 {
        return ApplyResult::ClaimedCost("tecAMM_NOT_EMPTY");
    }
    match remove_empty_amm(state, &akey, &pseudo_id) {
        Ok(AmmAccountDelete::Deleted) => {}
        Ok(AmmAccountDelete::Incomplete) => {
            return ApplyResult::ClaimedCost("tecINCOMPLETE");
        }
        Err(code) => return ApplyResult::ClaimedCost(code),
    }

    ApplyResult::Success
}

/// Type 36: AMMDeposit — add liquidity to an AMM pool.
///
/// Simplified XRP + IOU model:
/// - First deposit: LP tokens = sqrt(xrp_drops * iou_value_scaled)
/// - Subsequent: LP tokens = proportional to smallest deposit ratio
/// - Transfer assets from depositor to pseudo-account
///
/// (rippled: AMMDeposit.cpp — doApply)
pub(crate) fn apply_amm_deposit(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    let submode = match validate_amm_deposit_mode(tx) {
        Ok(submode) => submode,
        Err(code) => return ApplyResult::ClaimedCost(code),
    };

    // 1. Find AMM
    let asset1 = match &tx.asset {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let asset2 = match &tx.asset2 {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    if let Err(code) = invalid_amm_asset_pair(&asset1, &asset2) {
        return ApplyResult::ClaimedCost(code);
    }

    let akey = amm_key(&asset1, &asset2);
    let amm_raw = match load_amm_raw(state, &akey) {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("terNO_AMM"),
    };

    let pseudo_id = match amm_sle_pseudo_id(&amm_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 2. Read current pool state
    let (pool1, pool2) = amm_pool_units(state, &amm_raw, &pseudo_id, &asset1, &asset2);
    let lp_total = amm_lp_total_units(&amm_raw);
    let trading_fee = amm_sle_trading_fee(&amm_raw);

    let mut deposit_amounts = Vec::<Amount>::new();
    let (deposit1, deposit2, lp_minted) = match submode {
        TF_AMM_TWO_ASSET | TF_AMM_TWO_ASSET_IF_EMPTY => {
            if submode == TF_AMM_TWO_ASSET_IF_EMPTY && lp_total != 0 {
                return ApplyResult::ClaimedCost("tecAMM_NOT_EMPTY");
            }
            let ledger_pool1 = amm_pool_units_from_ledger(state, &pseudo_id, &asset1);
            let ledger_pool2 = amm_pool_units_from_ledger(state, &pseudo_id, &asset2);
            if submode == TF_AMM_TWO_ASSET_IF_EMPTY && (ledger_pool1 != 0 || ledger_pool2 != 0) {
                return ApplyResult::ClaimedCost("tecINTERNAL");
            }
            let amount1 = tx.amount.as_ref().expect("validated Amount");
            let amount2 = tx.amount2.as_ref().expect("validated Amount2");
            if !amount_matches_issue(amount1, &asset1) || !amount_matches_issue(amount2, &asset2) {
                return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
            }
            let deposit1 = match amount_pool_units(amount1) {
                Some(d) if d > 0 => d,
                _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
            };
            let deposit2 = match amount_pool_units(amount2) {
                Some(d) if d > 0 => d,
                _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
            };
            deposit_amounts.push(amount1.clone());
            deposit_amounts.push(amount2.clone());
            (
                deposit1,
                deposit2,
                lp_from_two_asset_deposit(deposit1, deposit2, pool1, pool2, lp_total),
            )
        }
        TF_AMM_WITHDRAW_LP_TOKEN => {
            if lp_total == 0 {
                return ApplyResult::ClaimedCost("tecAMM_EMPTY");
            }
            let lp_out = match lp_token_units_from_amount(
                tx.lp_token_out.as_ref(),
                &asset1,
                &asset2,
                pseudo_id,
            ) {
                Ok(units) if units > 0 => units,
                Ok(_) => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
                Err(code) => return ApplyResult::ClaimedCost(code),
            };
            let Some(deposit1) = proportional_pool_in_for_lp(pool1, lp_out, lp_total) else {
                return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
            };
            let Some(deposit2) = proportional_pool_in_for_lp(pool2, lp_out, lp_total) else {
                return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
            };
            let Some(amount1) = amount_from_issue_units(&asset1, deposit1) else {
                return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
            };
            let Some(amount2) = amount_from_issue_units(&asset2, deposit2) else {
                return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
            };
            if let (Some(min1), Some(min2)) = (tx.amount.as_ref(), tx.amount2.as_ref()) {
                if !amount_matches_issue(min1, &asset1) || !amount_matches_issue(min2, &asset2) {
                    return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
                }
                let min1 = match amount_pool_units(min1) {
                    Some(units) => units,
                    None => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
                };
                let min2 = match amount_pool_units(min2) {
                    Some(units) => units,
                    None => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
                };
                if deposit1 < min1 || deposit2 < min2 {
                    return ApplyResult::ClaimedCost("tecAMM_FAILED");
                }
            }
            deposit_amounts.push(amount1);
            deposit_amounts.push(amount2);
            (deposit1, deposit2, lp_out)
        }
        TF_AMM_SINGLE_ASSET | TF_AMM_ONE_ASSET_LP_TOKEN | TF_AMM_LIMIT_LP_TOKEN => {
            if lp_total == 0 {
                return ApplyResult::ClaimedCost("tecAMM_EMPTY");
            }
            let amount = tx.amount.as_ref().expect("validated Amount");
            let deposit_units = match amount_pool_units(amount) {
                Some(d) if d > 0 => d,
                _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
            };
            let (is_asset1, pool) = if amount_matches_issue(amount, &asset1) {
                (true, pool1)
            } else if amount_matches_issue(amount, &asset2) {
                (false, pool2)
            } else {
                return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
            };
            let (actual_deposit_units, requested_lp) = match submode {
                TF_AMM_SINGLE_ASSET => (
                    deposit_units,
                    lp_from_single_asset_deposit(deposit_units, pool, lp_total, trading_fee),
                ),
                TF_AMM_ONE_ASSET_LP_TOKEN => {
                    let lp_out = match lp_token_units_from_amount(
                        tx.lp_token_out.as_ref(),
                        &asset1,
                        &asset2,
                        pseudo_id,
                    ) {
                        Ok(units) if units > 0 => units,
                        Ok(_) => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
                        Err(code) => return ApplyResult::ClaimedCost(code),
                    };
                    let Some(needed) = single_asset_in_for_lp(pool, lp_out, lp_total, trading_fee)
                    else {
                        return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
                    };
                    if needed > deposit_units {
                        return ApplyResult::ClaimedCost("tecAMM_FAILED");
                    }
                    (needed, lp_out)
                }
                TF_AMM_LIMIT_LP_TOKEN => (
                    deposit_units,
                    lp_from_single_asset_deposit(deposit_units, pool, lp_total, trading_fee),
                ),
                _ => unreachable!(),
            };
            if submode == TF_AMM_LIMIT_LP_TOKEN {
                let Some(eprice) = tx.eprice.as_ref() else {
                    return ApplyResult::ClaimedCost("temMALFORMED");
                };
                let Some(deposit_issue) = issue_from_amount(amount) else {
                    return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
                };
                if !amount_matches_issue(eprice, &deposit_issue) {
                    return ApplyResult::ClaimedCost("temBAD_AMOUNT");
                }
                let Some(eprice_units) = amount_pool_units(eprice) else {
                    return ApplyResult::ClaimedCost("temBAD_AMOUNT");
                };
                if eprice_units == 0
                    || (actual_deposit_units as u128)
                        > (eprice_units as u128).saturating_mul(requested_lp as u128)
                {
                    return ApplyResult::ClaimedCost("tecAMM_FAILED");
                }
            }
            let deposit_issue = issue_from_amount(amount).ok_or_else(|| "temBAD_AMM_TOKENS");
            let Ok(deposit_issue) = deposit_issue else {
                return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
            };
            let Some(actual_amount) = amount_from_issue_units(&deposit_issue, actual_deposit_units)
            else {
                return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
            };
            deposit_amounts.push(actual_amount);
            if is_asset1 {
                (actual_deposit_units, 0, requested_lp)
            } else {
                (0, actual_deposit_units, requested_lp)
            }
        }
        _ => unreachable!(),
    };

    if lp_minted == 0 {
        return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
    }
    if let Some(min_lp) = tx.lp_token_out.as_ref() {
        let min_units = match lp_token_units_from_amount(Some(min_lp), &asset1, &asset2, pseudo_id)
        {
            Ok(units) => units,
            Err(code) => return ApplyResult::ClaimedCost(code),
        };
        if lp_minted < min_units {
            return ApplyResult::ClaimedCost("tecAMM_FAILED");
        }
    }

    if let Err(code) = amm_check_deposit_preclaim(
        state,
        &tx.account,
        &pseudo_id,
        &asset1,
        &asset2,
        &deposit_amounts,
    ) {
        return ApplyResult::ClaimedCost(code);
    }

    // 3. Transfer reserve assets from depositor to pseudo-account.
    for amount in &deposit_amounts {
        if !transfer_amount_between_accounts_waiving_issuer_fee(
            state,
            &tx.account,
            &pseudo_id,
            amount,
        ) {
            return ApplyResult::ClaimedCost("tecUNFUNDED_AMM");
        }
        if !ensure_pool_asset_trustline_lifecycle(state, &pseudo_id, amount) {
            return ApplyResult::ClaimedCost("tecINTERNAL");
        }
    }
    if !issue_lp_tokens(state, &tx.account, &asset1, &asset2, pseudo_id, lp_minted) {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    }

    // 4. Update AMM pool balances and LP total.
    let amm_raw = amm_patch_number(&amm_raw, 10, (pool1 + deposit1) as i64);
    let amm_raw = amm_patch_number(&amm_raw, 11, (pool2 + deposit2) as i64);
    let new_lp_total = (lp_total + lp_minted) as i64;
    let amm_raw = amm_patch_number(&amm_raw, 12, new_lp_total);
    let amm_raw = amm_patch_lp_token_balance(&amm_raw, &asset1, &asset2, pseudo_id, new_lp_total);
    state.insert_raw(akey, amm_raw);

    ApplyResult::Success
}

/// Type 37: AMMWithdraw — remove liquidity from an AMM pool.
///
/// Burns LP tokens and returns underlying assets pro-rata.
///
/// (rippled: AMMWithdraw.cpp — doApply)
pub(crate) fn apply_amm_withdraw(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    let submode = match validate_amm_withdraw_mode(tx) {
        Ok(submode) => submode,
        Err(code) => return ApplyResult::ClaimedCost(code),
    };

    // 1. Find AMM
    let asset1 = match &tx.asset {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let asset2 = match &tx.asset2 {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    if let Err(code) = invalid_amm_asset_pair(&asset1, &asset2) {
        return ApplyResult::ClaimedCost(code);
    }

    let akey = amm_key(&asset1, &asset2);
    let amm_raw = match load_amm_raw(state, &akey) {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("terNO_AMM"),
    };

    let pseudo_id = match amm_sle_pseudo_id(&amm_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 2. Read current pool state.
    let (pool1, pool2) = amm_pool_units(state, &amm_raw, &pseudo_id, &asset1, &asset2);
    let lp_total = amm_lp_total_units(&amm_raw);
    let trading_fee = amm_sle_trading_fee(&amm_raw);

    if lp_total == 0 {
        return ApplyResult::ClaimedCost("tecAMM_EMPTY");
    }

    let (lp_burn, return1, return2) = match submode {
        TF_AMM_WITHDRAW_LP_TOKEN => {
            let lp_burn = match amm_withdraw_lp_burn_from_fields(
                tx.lp_token_in.as_ref(),
                tx.amount_drops,
                &asset1,
                &asset2,
                pseudo_id,
            ) {
                Ok(d) => d,
                Err(code) => return ApplyResult::ClaimedCost(code),
            };
            (
                lp_burn,
                ((lp_burn as u128 * pool1 as u128) / lp_total as u128) as u64,
                ((lp_burn as u128 * pool2 as u128) / lp_total as u128) as u64,
            )
        }
        TF_AMM_WITHDRAW_ALL => {
            let Some(lp_burn) =
                holder_lp_token_units(state, &tx.account, &asset1, &asset2, pseudo_id)
            else {
                return ApplyResult::ClaimedCost("tecAMM_BALANCE");
            };
            (
                lp_burn,
                ((lp_burn as u128 * pool1 as u128) / lp_total as u128) as u64,
                ((lp_burn as u128 * pool2 as u128) / lp_total as u128) as u64,
            )
        }
        TF_AMM_TWO_ASSET => {
            let amount1 = tx.amount.as_ref().expect("validated Amount");
            let amount2 = tx.amount2.as_ref().expect("validated Amount2");
            if !amount_matches_issue(amount1, &asset1) || !amount_matches_issue(amount2, &asset2) {
                return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
            }
            let return1 = match amount_pool_units(amount1) {
                Some(units) if units > 0 && units <= pool1 => units,
                _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
            };
            let return2 = match amount_pool_units(amount2) {
                Some(units) if units > 0 && units <= pool2 => units,
                _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
            };
            let burn1 = ceil_div_u128(return1 as u128 * lp_total as u128, pool1 as u128)
                .unwrap_or(u64::MAX);
            let burn2 = ceil_div_u128(return2 as u128 * lp_total as u128, pool2 as u128)
                .unwrap_or(u64::MAX);
            (burn1.max(burn2), return1, return2)
        }
        TF_AMM_SINGLE_ASSET => {
            let amount = tx.amount.as_ref().expect("validated Amount");
            let return_units = match amount_pool_units(amount) {
                Some(units) if units > 0 => units,
                _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
            };
            if amount_matches_issue(amount, &asset1) {
                if return_units > pool1 {
                    return ApplyResult::ClaimedCost("tecAMM_BALANCE");
                }
                let burn = single_withdraw_lp_burn(return_units, pool1, lp_total, trading_fee)
                    .unwrap_or(u64::MAX);
                (burn, return_units, 0)
            } else if amount_matches_issue(amount, &asset2) {
                if return_units > pool2 {
                    return ApplyResult::ClaimedCost("tecAMM_BALANCE");
                }
                let burn = single_withdraw_lp_burn(return_units, pool2, lp_total, trading_fee)
                    .unwrap_or(u64::MAX);
                (burn, 0, return_units)
            } else {
                return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
            }
        }
        TF_AMM_ONE_ASSET_LP_TOKEN => {
            let lp_burn = match amm_withdraw_lp_burn_from_fields(
                tx.lp_token_in.as_ref(),
                tx.amount_drops,
                &asset1,
                &asset2,
                pseudo_id,
            ) {
                Ok(d) if d > 0 => d,
                Ok(_) => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
                Err(code) => return ApplyResult::ClaimedCost(code),
            };
            let amount = tx.amount.as_ref().expect("validated Amount");
            let requested = match amount_pool_units(amount) {
                Some(units) if units > 0 => units,
                _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
            };
            if amount_matches_issue(amount, &asset1) {
                let max_out =
                    single_asset_out_for_lp(pool1, lp_burn, lp_total, trading_fee).unwrap_or(0);
                if requested > max_out {
                    return ApplyResult::ClaimedCost("tecAMM_FAILED");
                }
                (lp_burn, max_out, 0)
            } else if amount_matches_issue(amount, &asset2) {
                let max_out =
                    single_asset_out_for_lp(pool2, lp_burn, lp_total, trading_fee).unwrap_or(0);
                if requested > max_out {
                    return ApplyResult::ClaimedCost("tecAMM_FAILED");
                }
                (lp_burn, 0, max_out)
            } else {
                return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
            }
        }
        TF_AMM_LIMIT_LP_TOKEN => {
            let amount = tx.amount.as_ref().expect("validated Amount");
            let requested = match amount_pool_units(amount) {
                Some(units) if units > 0 => units,
                _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
            };
            let Some(eprice) = tx.eprice.as_ref() else {
                return ApplyResult::ClaimedCost("temMALFORMED");
            };
            let eprice_units =
                match lp_token_units_from_amount(Some(eprice), &asset1, &asset2, pseudo_id) {
                    Ok(units) if units > 0 => units,
                    Ok(_) => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
                    Err(_) => return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS"),
                };
            if amount_matches_issue(amount, &asset1) {
                if requested > pool1 {
                    return ApplyResult::ClaimedCost("tecAMM_BALANCE");
                }
                let burn = single_withdraw_lp_burn(requested, pool1, lp_total, trading_fee)
                    .unwrap_or(u64::MAX);
                if (burn as u128) > (eprice_units as u128).saturating_mul(requested as u128) {
                    return ApplyResult::ClaimedCost("tecAMM_FAILED");
                }
                (burn, requested, 0)
            } else if amount_matches_issue(amount, &asset2) {
                if requested > pool2 {
                    return ApplyResult::ClaimedCost("tecAMM_BALANCE");
                }
                let burn = single_withdraw_lp_burn(requested, pool2, lp_total, trading_fee)
                    .unwrap_or(u64::MAX);
                if (burn as u128) > (eprice_units as u128).saturating_mul(requested as u128) {
                    return ApplyResult::ClaimedCost("tecAMM_FAILED");
                }
                (burn, 0, requested)
            } else {
                return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
            }
        }
        TF_AMM_ONE_ASSET_WITHDRAW_ALL => {
            let Some(lp_burn) =
                holder_lp_token_units(state, &tx.account, &asset1, &asset2, pseudo_id)
            else {
                return ApplyResult::ClaimedCost("tecAMM_BALANCE");
            };
            let amount = tx.amount.as_ref().expect("validated Amount");
            if amount_matches_issue(amount, &asset1) {
                let out =
                    single_asset_out_for_lp(pool1, lp_burn, lp_total, trading_fee).unwrap_or(0);
                let requested_min = amount_pool_units(amount).unwrap_or(0);
                if out < requested_min {
                    return ApplyResult::ClaimedCost("tecAMM_FAILED");
                }
                (lp_burn, out, 0)
            } else if amount_matches_issue(amount, &asset2) {
                let out =
                    single_asset_out_for_lp(pool2, lp_burn, lp_total, trading_fee).unwrap_or(0);
                let requested_min = amount_pool_units(amount).unwrap_or(0);
                if out < requested_min {
                    return ApplyResult::ClaimedCost("tecAMM_FAILED");
                }
                (lp_burn, 0, out)
            } else {
                return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
            }
        }
        _ => unreachable!(),
    };

    if lp_burn == 0 || lp_burn > lp_total {
        return ApplyResult::ClaimedCost("tecAMM_BALANCE");
    }
    if tx.lp_token_in.is_some()
        && holder_lp_token_units(state, &tx.account, &asset1, &asset2, pseudo_id).unwrap_or(0)
            < lp_burn
    {
        return ApplyResult::ClaimedCost("tecAMM_INVALID_TOKENS");
    }
    if return1 > 0 {
        let Some(amount) = amount_from_issue_units(&asset1, return1) else {
            return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
        };
        if let Err(code) =
            amm_check_withdraw_preclaim(state, &tx.account, &pseudo_id, &amount, pool1)
        {
            return ApplyResult::ClaimedCost(code);
        }
    }
    if return2 > 0 {
        let Some(amount) = amount_from_issue_units(&asset2, return2) else {
            return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
        };
        if let Err(code) =
            amm_check_withdraw_preclaim(state, &tx.account, &pseudo_id, &amount, pool2)
        {
            return ApplyResult::ClaimedCost(code);
        }
    }
    if !burn_lp_tokens(state, &tx.account, &asset1, &asset2, pseudo_id, lp_burn) {
        return ApplyResult::ClaimedCost("tecAMM_BALANCE");
    }

    if return1 == 0 && return2 == 0 {
        return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
    }

    // 5. Transfer reserve assets from pseudo-account to withdrawer.
    if return1 > 0 {
        let Some(amount) = amount_from_issue_units(&asset1, return1) else {
            return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
        };
        if !transfer_amount_between_accounts_waiving_issuer_fee(
            state,
            &pseudo_id,
            &tx.account,
            &amount,
        ) {
            return ApplyResult::ClaimedCost("tecAMM_BALANCE");
        }
    }
    if return2 > 0 {
        let Some(amount) = amount_from_issue_units(&asset2, return2) else {
            return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
        };
        if !transfer_amount_between_accounts_waiving_issuer_fee(
            state,
            &pseudo_id,
            &tx.account,
            &amount,
        ) {
            return ApplyResult::ClaimedCost("tecAMM_BALANCE");
        }
    }

    // 6. Update AMM pool balances and LP total
    let new_lp_total = (lp_total - lp_burn) as i64;
    if new_lp_total == 0 {
        match remove_empty_amm(state, &akey, &pseudo_id) {
            Ok(AmmAccountDelete::Deleted) => {}
            Ok(AmmAccountDelete::Incomplete) => {
                let amm_raw = patch_amm_empty_balances(&amm_raw, &asset1, &asset2, pseudo_id);
                state.insert_raw(akey, amm_raw);
                return ApplyResult::ClaimedCost("tecINCOMPLETE");
            }
            Err(code) => return ApplyResult::ClaimedCost(code),
        }
        return ApplyResult::Success;
    }
    let amm_raw = amm_patch_number(&amm_raw, 10, (pool1 - return1) as i64);
    let amm_raw = amm_patch_number(&amm_raw, 11, (pool2 - return2) as i64);
    let amm_raw = amm_patch_number(&amm_raw, 12, new_lp_total);
    let amm_raw = amm_patch_lp_token_balance(&amm_raw, &asset1, &asset2, pseudo_id, new_lp_total);
    state.insert_raw(akey, amm_raw);

    ApplyResult::Success
}

/// Read sfTradingFee from an AMM SLE (UINT16, type=1 field=5).
#[allow(dead_code)]
fn amm_sle_trading_fee(raw: &[u8]) -> u16 {
    let parsed = match crate::ledger::meta::parse_sle(raw) {
        Some(p) => p,
        None => return 0,
    };
    for field in &parsed.fields {
        if field.type_code == 1 && field.field_code == 5 && field.data.len() == 2 {
            return u16::from_be_bytes(field.data[..2].try_into().unwrap());
        }
    }
    0
}

/// Patch sfTradingFee on an AMM SLE.
fn amm_patch_trading_fee(raw: &[u8], fee: u16) -> Vec<u8> {
    if fee == 0 {
        return crate::ledger::meta::patch_sle(raw, &[], None, None, &[(1, 5)]);
    }
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 1,
            field_code: 5,
            data: fee.to_be_bytes().to_vec(),
        }],
        None,
        None,
        &[],
    )
}

/// Type 38: AMMVote — vote on the AMM trading fee.
///
/// Each voter proposes a fee (0-1000 = 0-1%). VoteSlots retain up to eight
/// active LP voters and the AMM trading fee is the LP-token-weighted average.
///
/// (rippled: AMMVote.cpp — doApply)
pub(crate) fn apply_amm_vote(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    // 1. Run AMMVote preflight-equivalent checks before AMM lookup.
    let asset1 = match &tx.asset {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let asset2 = match &tx.asset2 {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    if let Err(code) = invalid_amm_asset_pair(&asset1, &asset2) {
        return ApplyResult::ClaimedCost(code);
    }
    let proposed_fee = match tx.trading_fee {
        Some(fee) if fee <= TRADING_FEE_THRESHOLD => fee,
        Some(_) => return ApplyResult::ClaimedCost("temBAD_FEE"),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    // 2. Find AMM
    let akey = amm_key(&asset1, &asset2);
    let amm_raw = match load_amm_raw(state, &akey) {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("terNO_AMM"),
    };
    let pseudo_id = match amm_sle_pseudo_id(&amm_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let lp_total = amm_lp_total_units(&amm_raw);
    if lp_total == 0 {
        return ApplyResult::ClaimedCost("tecAMM_EMPTY");
    }
    let lp_tokens_new = match holder_lp_token_units(state, &tx.account, &asset1, &asset2, pseudo_id)
    {
        Some(tokens) if tokens > 0 => tokens,
        _ => return ApplyResult::ClaimedCost("tecAMM_INVALID_TOKENS"),
    };

    #[derive(Clone)]
    struct ActiveVote {
        vote: VoteSlotInfo,
        lp_tokens: u64,
    }

    let mut active_votes = Vec::<ActiveVote>::new();
    let mut found_account = false;
    for vote in amm_sle_vote_slots(&amm_raw) {
        let Some(mut lp_tokens) =
            holder_lp_token_units(state, &vote.account, &asset1, &asset2, pseudo_id)
        else {
            continue;
        };
        if lp_tokens == 0 {
            continue;
        }
        let mut trading_fee = vote.trading_fee;
        if vote.account == tx.account {
            lp_tokens = lp_tokens_new;
            trading_fee = proposed_fee;
            found_account = true;
        }
        active_votes.push(ActiveVote {
            vote: VoteSlotInfo {
                account: vote.account,
                trading_fee,
                vote_weight: vote_weight(lp_tokens, lp_total),
            },
            lp_tokens,
        });
    }

    if !found_account {
        let new_vote = ActiveVote {
            vote: VoteSlotInfo {
                account: tx.account,
                trading_fee: proposed_fee,
                vote_weight: vote_weight(lp_tokens_new, lp_total),
            },
            lp_tokens: lp_tokens_new,
        };
        if active_votes.len() < VOTE_MAX_SLOTS {
            active_votes.push(new_vote);
        } else if let Some((min_pos, min_vote)) = active_votes
            .iter()
            .enumerate()
            .min_by(|(_, left), (_, right)| {
                left.lp_tokens
                    .cmp(&right.lp_tokens)
                    .then(left.vote.trading_fee.cmp(&right.vote.trading_fee))
                    .then(left.vote.account.cmp(&right.vote.account))
            })
            .map(|(idx, vote)| (idx, vote.clone()))
        {
            if lp_tokens_new > min_vote.lp_tokens
                || (lp_tokens_new == min_vote.lp_tokens && proposed_fee > min_vote.vote.trading_fee)
            {
                active_votes[min_pos] = new_vote;
            }
        }
    }

    let mut numerator = 0u128;
    let mut denominator = 0u128;
    let updated_votes = active_votes
        .into_iter()
        .map(|active| {
            numerator += active.vote.trading_fee as u128 * active.lp_tokens as u128;
            denominator += active.lp_tokens as u128;
            active.vote
        })
        .collect::<Vec<_>>();

    let new_fee = if denominator == 0 {
        0
    } else {
        (numerator / denominator).min(TRADING_FEE_THRESHOLD as u128) as u16
    };
    let amm_raw = amm_patch_vote_slots(&amm_raw, &updated_votes);
    let amm_raw = amm_patch_trading_fee(&amm_raw, new_fee);
    let amm_raw =
        amm_patch_auction_discounted_fee(&amm_raw, new_fee / AUCTION_SLOT_DISCOUNTED_FEE_FRACTION);
    state.insert_raw(akey, amm_raw);

    ApplyResult::Success
}

/// Type 39: AMMBid — bid for the AMM's auction slot.
///
/// The auction slot gives the holder a discounted trading fee for a time window.
/// Updates auction slot pricing, optional authorized accounts, previous-owner
/// refunds, and net LP-token burn following rippled's continuous auction shape.
///
/// (rippled: AMMBid.cpp — doApply)
pub(crate) fn apply_amm_bid(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
) -> ApplyResult {
    // AMMBid pays with LP tokens via sfBidMax/sfBidMin, never sfAmount.
    if tx.amount_drops.is_some()
        || tx.amount.is_some()
        || tx.amount2.is_some()
        || tx.lp_token_in.is_some()
        || tx.lp_token_out.is_some()
        || tx.eprice.is_some()
        || tx.trading_fee.is_some()
    {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    // 1. Find AMM
    let asset1 = match &tx.asset {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let asset2 = match &tx.asset2 {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    if let Err(code) = invalid_amm_asset_pair(&asset1, &asset2) {
        return ApplyResult::ClaimedCost(code);
    }
    for amount in [tx.bid_min.as_ref(), tx.bid_max.as_ref()]
        .into_iter()
        .flatten()
    {
        if let Err(code) = invalid_amm_amount(amount) {
            return ApplyResult::ClaimedCost(code);
        }
    }
    let auth_accounts = crate::transaction::parse::parsed_auth_accounts(tx);
    if auth_accounts.len() > 4 {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    for (idx, account) in auth_accounts.iter().enumerate() {
        if *account == tx.account || auth_accounts[..idx].contains(account) {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
    }

    let akey = amm_key(&asset1, &asset2);
    let amm_raw = match load_amm_raw(state, &akey) {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("terNO_AMM"),
    };

    let pseudo_id = match amm_sle_pseudo_id(&amm_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    for account in &auth_accounts {
        if state.get_account(account).is_none() {
            return ApplyResult::ClaimedCost("terNO_ACCOUNT");
        }
    }
    let auth_accounts = build_auth_accounts_array(&auth_accounts);

    let bid_min_units = match tx.bid_min.as_ref() {
        Some(amount) => {
            match lp_token_units_from_amount(Some(amount), &asset1, &asset2, pseudo_id) {
                Ok(units) if units > 0 => Some(units),
                Ok(_) => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
                Err(code) => return ApplyResult::ClaimedCost(code),
            }
        }
        None => None,
    };
    let bid_max_units = match tx.bid_max.as_ref() {
        Some(amount) => {
            match lp_token_units_from_amount(Some(amount), &asset1, &asset2, pseudo_id) {
                Ok(units) if units > 0 => Some(units),
                Ok(_) => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
                Err(code) => return ApplyResult::ClaimedCost(code),
            }
        }
        None => None,
    };
    if bid_min_units
        .zip(bid_max_units)
        .is_some_and(|(min, max)| min > max)
    {
        return ApplyResult::ClaimedCost("tecAMM_INVALID_TOKENS");
    }

    let lp_total = amm_lp_total_units(&amm_raw);
    if lp_total == 0 {
        return ApplyResult::ClaimedCost("tecAMM_EMPTY");
    }
    let lp_tokens = match holder_lp_token_units(state, &tx.account, &asset1, &asset2, pseudo_id) {
        Some(tokens) if tokens > 0 => tokens,
        _ => return ApplyResult::ClaimedCost("tecAMM_INVALID_TOKENS"),
    };
    for bid in [bid_min_units, bid_max_units].into_iter().flatten() {
        if bid > lp_tokens || bid >= lp_total {
            return ApplyResult::ClaimedCost("tecAMM_INVALID_TOKENS");
        }
    }

    let trading_fee = amm_sle_trading_fee(&amm_raw);
    let min_slot_price = ((lp_total as u128 * trading_fee as u128)
        / 100_000u128
        / AUCTION_SLOT_MIN_FEE_FRACTION as u128) as u64;
    let min_slot_price = if trading_fee > 0 {
        min_slot_price.max(1)
    } else {
        min_slot_price
    };

    let auction_info = amm_sle_auction_info(&amm_raw);
    let active_owner = auction_info.as_ref().and_then(|slot| {
        let owner = slot.account?;
        let time_slot = auction_time_slot(ctx.close_time, slot)?;
        if time_slot < AUCTION_SLOT_TIME_INTERVALS - 1 && state.get_account(&owner).is_some() {
            Some((owner, time_slot, slot))
        } else {
            None
        }
    });

    let (computed_price, refund_owner, refund_units) =
        if let Some((owner, time_slot, slot)) = active_owner {
            let purchased =
                lp_token_units_from_amount_allow_zero(&slot.price, &asset1, &asset2, pseudo_id)
                    .unwrap_or(0);
            let computed = auction_rebid_computed_price(purchased, time_slot, min_slot_price);
            let refund = auction_rebid_refund_units(purchased, time_slot);
            (computed, Some(owner), refund)
        } else {
            (min_slot_price, None, 0)
        };

    let pay_units = match (bid_min_units, bid_max_units) {
        (Some(min), Some(max)) => {
            if computed_price > max {
                return ApplyResult::ClaimedCost("tecAMM_FAILED");
            }
            computed_price.max(min)
        }
        (Some(min), None) => computed_price.max(min),
        (None, Some(max)) => {
            if computed_price > max {
                return ApplyResult::ClaimedCost("tecAMM_FAILED");
            }
            computed_price
        }
        (None, None) => computed_price,
    };
    if pay_units > lp_tokens || pay_units >= lp_total {
        return ApplyResult::ClaimedCost("tecAMM_INVALID_TOKENS");
    }
    if refund_units > pay_units {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    }
    if let Some(owner) = refund_owner {
        if !transfer_lp_tokens(
            state,
            &tx.account,
            &owner,
            &asset1,
            &asset2,
            pseudo_id,
            refund_units,
        ) {
            return ApplyResult::ClaimedCost("tecAMM_BALANCE");
        }
    }
    let burn_units = pay_units.saturating_sub(refund_units);
    if burn_units > 0
        && !burn_lp_tokens(state, &tx.account, &asset1, &asset2, pseudo_id, burn_units)
    {
        return ApplyResult::ClaimedCost("tecAMM_BALANCE");
    }

    let new_lp_total = (lp_total - burn_units) as i64;
    let discounted_fee = trading_fee / AUCTION_SLOT_DISCOUNTED_FEE_FRACTION;
    let expiration = (ctx.close_time as u32).saturating_add(AUCTION_SLOT_SECONDS);
    let Some(price) = lp_token_amount_for_units(&asset1, &asset2, pseudo_id, pay_units) else {
        return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
    };
    let amm_raw = amm_patch_number(&amm_raw, 12, new_lp_total);
    let amm_raw = amm_patch_lp_token_balance(&amm_raw, &asset1, &asset2, pseudo_id, new_lp_total);
    let amm_raw = amm_patch_auction_slot_with_auth(
        &amm_raw,
        &tx.account,
        expiration,
        discounted_fee,
        &price,
        auth_accounts.as_deref(),
    );
    state.insert_raw(akey, amm_raw);

    ApplyResult::Success
}

/// Type 31: AMMClawback — issuer recovers LP tokens from a holder.
///
/// The issuer of one of the AMM's assets claws back a holder's LP token balance,
/// burning the LP tokens and returning underlying assets to the issuer.
///
/// (rippled: AMMClawback.cpp — doApply)
pub(crate) fn apply_amm_clawback(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    let holder = match tx.holder {
        Some(holder) if holder != tx.account => holder,
        _ => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let asset1 = match &tx.asset {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let asset2 = match &tx.asset2 {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    if matches!(asset1, Issue::Xrp) || issue_issuer(&asset1) != Some(tx.account) {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    if (tx.flags & TF_CLAW_TWO_ASSETS) != 0 && issue_issuer(&asset2) != Some(tx.account) {
        return ApplyResult::ClaimedCost("temINVALID_FLAG");
    }
    if let Some(amount) = tx.amount.as_ref() {
        if !amount_matches_issue(amount, &asset1) {
            return ApplyResult::ClaimedCost("temBAD_AMOUNT");
        }
        match amount_pool_units(amount) {
            Some(units) if units > 0 => {}
            _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
        }
    }

    let Some(issuer_account) = state.get_account(&tx.account) else {
        return ApplyResult::ClaimedCost("terNO_ACCOUNT");
    };
    if state.get_account(&holder).is_none() {
        return ApplyResult::ClaimedCost("terNO_ACCOUNT");
    }

    let akey = amm_key(&asset1, &asset2);
    let amm_raw = match load_amm_raw(state, &akey) {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("terNO_AMM"),
    };

    if (issuer_account.flags & LSF_ALLOW_TRUST_LINE_CLAWBACK) == 0
        || (issuer_account.flags & crate::ledger::account::LSF_NO_FREEZE) != 0
    {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    let pseudo_id = match amm_sle_pseudo_id(&amm_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 2. Read current pool state
    let (pool1, pool2) = amm_pool_units(state, &amm_raw, &pseudo_id, &asset1, &asset2);
    let lp_total = amm_lp_total_units(&amm_raw);
    let holder_lp = match holder_lp_token_units(state, &holder, &asset1, &asset2, pseudo_id) {
        Some(units) if units > 0 => units,
        _ => return ApplyResult::ClaimedCost("tecAMM_BALANCE"),
    };
    let lp_total = match amm_clawback_adjusted_lp_total(
        state, &holder, &asset1, &asset2, pseudo_id, holder_lp, lp_total,
    ) {
        Ok(units) => units,
        Err(code) => return ApplyResult::ClaimedCost(code),
    };

    // 3. Claw all holder LP by default, or enough LP to remove the requested
    // issuer-asset Amount. This mirrors rippled's AMMClawback use of
    // AMMWithdraw helpers while preserving the local integer pool model.
    let requested_asset1_units = if let Some(amount) = tx.amount.as_ref() {
        let Some(requested_units) = amount_pool_units(amount) else {
            return ApplyResult::ClaimedCost("temBAD_AMOUNT");
        };
        Some(requested_units)
    } else {
        None
    };
    let lp_clawback = if let Some(requested_units) = requested_asset1_units {
        match ceil_div_u128(requested_units as u128 * lp_total as u128, pool1 as u128) {
            Some(units) if units > 0 => units.min(holder_lp),
            _ => return ApplyResult::ClaimedCost("tecAMM_BALANCE"),
        }
    } else {
        holder_lp
    };

    if lp_total == 0 || lp_clawback > lp_total {
        return ApplyResult::ClaimedCost("tecAMM_BALANCE");
    }

    // 4. Compute assets to return pro-rata (same as withdraw)
    let return1 = requested_asset1_units
        .unwrap_or_else(|| ((lp_clawback as u128 * pool1 as u128) / lp_total as u128) as u64)
        .min(pool1);
    let return2 = ((lp_clawback as u128 * pool2 as u128) / lp_total as u128) as u64;

    if !burn_lp_tokens(state, &holder, &asset1, &asset2, pseudo_id, lp_clawback) {
        return ApplyResult::ClaimedCost("tecAMM_BALANCE");
    }

    // 5. Transfer reserve portions from pseudo-account. The issuer always
    // claws the first asset. The paired asset returns to the holder unless
    // tfClawTwoAssets is set and both assets are issued by the same issuer.
    if return1 > 0 {
        let Some(amount) = amount_from_issue_units(&asset1, return1) else {
            return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
        };
        if !transfer_amount_between_accounts_waiving_issuer_fee(
            state,
            &pseudo_id,
            &tx.account,
            &amount,
        ) {
            return ApplyResult::ClaimedCost("tecAMM_BALANCE");
        }
    }
    if return2 > 0 {
        let Some(amount) = amount_from_issue_units(&asset2, return2) else {
            return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
        };
        let receiver = if (tx.flags & TF_CLAW_TWO_ASSETS) != 0 {
            tx.account
        } else {
            holder
        };
        if !transfer_amount_between_accounts_waiving_issuer_fee(
            state, &pseudo_id, &receiver, &amount,
        ) {
            return ApplyResult::ClaimedCost("tecAMM_BALANCE");
        }
    }

    // 6. Update AMM pool balances and LP total
    let new_lp_total = (lp_total - lp_clawback) as i64;
    if new_lp_total == 0 {
        match remove_empty_amm(state, &akey, &pseudo_id) {
            Ok(AmmAccountDelete::Deleted) => {}
            Ok(AmmAccountDelete::Incomplete) => {
                let amm_raw = patch_amm_empty_balances(&amm_raw, &asset1, &asset2, pseudo_id);
                state.insert_raw(akey, amm_raw);
            }
            Err(code) => return ApplyResult::ClaimedCost(code),
        }
        return ApplyResult::Success;
    }
    let amm_raw = amm_patch_number(&amm_raw, 10, (pool1 - return1) as i64);
    let amm_raw = amm_patch_number(&amm_raw, 11, (pool2 - return2) as i64);
    let amm_raw = amm_patch_number(&amm_raw, 12, new_lp_total);
    let amm_raw = amm_patch_lp_token_balance(&amm_raw, &asset1, &asset2, pseudo_id, new_lp_total);
    state.insert_raw(akey, amm_raw);

    ApplyResult::Success
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static AMM_DELETE_LIMIT_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn amm_delete_limit_test_lock() -> std::sync::MutexGuard<'static, ()> {
        AMM_DELETE_LIMIT_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("AMM delete limit test lock poisoned")
    }

    fn parsed_amm_withdraw_tx(
        flags: u32,
        lp_token_in: Option<Amount>,
        amount: Option<Amount>,
        amount2: Option<Amount>,
        eprice: Option<Amount>,
    ) -> ParsedTx {
        ParsedTx {
            tx_id: [0u8; 32],
            tx_type: 37,
            network_id: None,
            flags,
            sequence: 1,
            fee: 12,
            account: [1u8; 20],
            destination: None,
            destination_tag: None,
            amount_drops: None,
            amount,
            amount2,
            limit_amount: None,
            taker_pays: None,
            taker_gets: None,
            offer_sequence: None,
            finish_after: None,
            cancel_after: None,
            settle_delay: None,
            expiration: None,
            channel: None,
            public_key: None,
            deliver_min: None,
            bid_min: None,
            bid_max: None,
            lp_token_out: None,
            lp_token_in,
            eprice,
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            nftoken_broker_fee: None,
            uri: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            trading_fee: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            paychan_sig: None,
            owner: None,
            regular_key: None,
            nftoken_minter: None,
            issuer: None,
            subject: None,
            credential_type: None,
            oracle_document_id: None,
            oracle_last_update_time: None,
            oracle_price_data_series_raw: None,
            signer_quorum: None,
            signer_entries_raw: None,
            domain_id: None,
            ledger_fix_type: None,
            accepted_credentials_raw: None,
            authorize: None,
            unauthorize: None,
            delegate: None,
            account_txn_id: None,
            permissions_raw: None,
            did_document: None,
            did_data: None,
            holder: None,
            mptoken_issuance_id: None,
            set_flag: None,
            clear_flag: None,
            transfer_rate: None,
            quality_in: None,
            quality_out: None,
            tick_size: None,
            last_ledger_seq: None,
            ticket_count: None,
            ticket_sequence: None,
            domain: None,
            email_hash: None,
            wallet_locator: None,
            message_key: None,
            asset: Some(Issue::Xrp),
            asset2: Some(iou("USD", 7)),
            vault_id: None,
            loan_broker_id: None,
            loan_id: None,
            amendment: None,
            base_fee_field: None,
            reserve_base_field: None,
            reserve_increment_field: None,
            unl_modify_disabling: None,
            unl_modify_validator: None,
            signing_pubkey: vec![0x02; 33],
            signature: vec![],
            signing_hash: [0u8; 32],
            signing_payload: vec![],
            send_max: None,
            paths: vec![],
            signers: vec![],
        }
    }

    fn iou(currency_code: &str, issuer_byte: u8) -> Issue {
        Issue::Iou {
            currency: Currency::from_code(currency_code).expect("standard currency"),
            issuer: [issuer_byte; 20],
        }
    }

    fn account(id: [u8; 20], balance: u64, owner_count: u32) -> AccountRoot {
        AccountRoot {
            account_id: id,
            balance,
            sequence: 1,
            owner_count,
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

    fn make_amm_account(id: [u8; 20], amm_key: &Key, owner_count: u32) -> AccountRoot {
        let mut account = account(id, 0, owner_count);
        account.raw_sle = Some(patch_account_ammid(&account.encode(), &amm_key.0));
        account
    }

    fn zero_balance_amm_trustline(
        state: &mut LedgerState,
        amm_account: [u8; 20],
        holder: [u8; 20],
        currency_code: &str,
    ) -> Key {
        let currency = Currency::from_code(currency_code).expect("standard currency");
        let mut line = crate::ledger::RippleState::new(&amm_account, &holder, currency);
        line.flags |= reserve_flag_for_trustline_account(&line, &holder);
        let key = line.key();
        state.insert_trustline(line);
        directory::dir_add(state, &amm_account, key.0);
        directory::dir_add(state, &holder, key.0);
        key
    }

    fn amm_owned_trustline_count(state: &LedgerState, amm_account: &[u8; 20]) -> usize {
        state
            .iter_trustlines()
            .filter(|(_, line)| {
                line.low_account == *amm_account || line.high_account == *amm_account
            })
            .count()
    }

    #[test]
    fn amm_cleanup_batches_zero_balance_lp_trustlines() {
        let mut state = LedgerState::new();
        let amm_account = [9u8; 20];
        let holder1 = [1u8; 20];
        let holder2 = [2u8; 20];
        let amm_key = Key([0xAA; 32]);
        state.insert_account(make_amm_account(amm_account, &amm_key, 1));
        state.insert_account(account(holder1, 0, 1));
        state.insert_account(account(holder2, 0, 1));
        directory::dir_add(&mut state, &amm_account, amm_key.0);
        zero_balance_amm_trustline(&mut state, amm_account, holder1, "USD");
        zero_balance_amm_trustline(&mut state, amm_account, holder2, "EUR");
        let first_deletable_budget = load_amm_owner_dir_entries(&state, &amm_account)
            .into_iter()
            .position(|key| key != amm_key)
            .map(|pos| pos + 1)
            .expect("AMM directory has at least one trustline");

        let result = cleanup_amm_account_trustlines(
            &mut state,
            &amm_account,
            &amm_key,
            first_deletable_budget,
        )
        .expect("zero-balance AMM trustline cleanup succeeds");

        assert_eq!(result, AmmAccountDelete::Incomplete);
        assert_eq!(amm_owned_trustline_count(&state, &amm_account), 1);
        assert!(state.get_account(&amm_account).is_some());
    }

    #[test]
    fn amm_delete_tec_incomplete_commits_bounded_cleanup() {
        let _guard = amm_delete_limit_test_lock();
        TEST_AMM_DELETE_LIMIT.store(1, std::sync::atomic::Ordering::SeqCst);

        let mut state = LedgerState::new();
        let sender = [1u8; 20];
        let amm_account = [9u8; 20];
        let holder1 = [2u8; 20];
        let holder2 = [3u8; 20];
        let usd = iou("USD", 7);
        let amm_key = amm_key(&Issue::Xrp, &usd);
        let amm_raw = build_amm_sle(&amm_account, &Issue::Xrp, &usd, 30, 0, 0, 0, 0);
        state.insert_account(account(sender, 1_000_000, 0));
        state.insert_account(make_amm_account(amm_account, &amm_key, 1));
        state.insert_account(account(holder1, 0, 1));
        state.insert_account(account(holder2, 0, 1));
        state.insert_raw(amm_key, amm_raw);
        directory::dir_add(&mut state, &amm_account, amm_key.0);
        zero_balance_amm_trustline(&mut state, amm_account, holder1, "USD");
        zero_balance_amm_trustline(&mut state, amm_account, holder2, "EUR");

        let mut tx = ParsedTx {
            tx_type: 40,
            sequence: 1,
            fee: 10,
            account: sender,
            asset: Some(Issue::Xrp),
            asset2: Some(usd.clone()),
            ..ParsedTx::default()
        };

        let result = crate::ledger::tx::run_tx(
            &mut state,
            &tx,
            &crate::ledger::tx::TxContext::default(),
            crate::ledger::ter::ApplyFlags::VALIDATED_REPLAY,
        );
        assert_eq!(result.ter, crate::ledger::ter::TEC_INCOMPLETE);
        assert!(result.applied);
        assert_eq!(amm_owned_trustline_count(&state, &amm_account), 2);
        assert!(load_amm_raw(&state, &amm_key).is_some());

        TEST_AMM_DELETE_LIMIT.store(2, std::sync::atomic::Ordering::SeqCst);
        tx.sequence = 2;
        let result = crate::ledger::tx::run_tx(
            &mut state,
            &tx,
            &crate::ledger::tx::TxContext::default(),
            crate::ledger::ter::ApplyFlags::VALIDATED_REPLAY,
        );
        assert_eq!(result.ter, crate::ledger::ter::TEC_INCOMPLETE);
        assert!(result.applied);
        assert_eq!(amm_owned_trustline_count(&state, &amm_account), 1);
        assert!(load_amm_raw(&state, &amm_key).is_some());

        tx.sequence = 3;
        let result = crate::ledger::tx::run_tx(
            &mut state,
            &tx,
            &crate::ledger::tx::TxContext::default(),
            crate::ledger::ter::ApplyFlags::VALIDATED_REPLAY,
        );
        assert_eq!(result.ter, crate::ledger::ter::TES_SUCCESS);
        assert!(load_amm_raw(&state, &amm_key).is_none());
        assert!(state.get_account(&amm_account).is_none());
        assert_eq!(amm_owned_trustline_count(&state, &amm_account), 0);

        TEST_AMM_DELETE_LIMIT.store(0, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn amm_delete_account_removes_remaining_trustlines_and_lifecycle_entries() {
        let _guard = amm_delete_limit_test_lock();
        let mut state = LedgerState::new();
        let amm_account = [9u8; 20];
        let holder = [1u8; 20];
        let usd = iou("USD", 7);
        let amm_key = amm_key(&Issue::Xrp, &usd);
        let amm_raw = build_amm_sle(&amm_account, &Issue::Xrp, &usd, 30, 0, 0, 0, 0);
        state.insert_account(make_amm_account(amm_account, &amm_key, 1));
        state.insert_account(account(holder, 0, 1));
        state.insert_raw(amm_key, amm_raw);
        directory::dir_add(&mut state, &amm_account, amm_key.0);
        zero_balance_amm_trustline(&mut state, amm_account, holder, "USD");

        let result =
            delete_amm_account(&mut state, &amm_key, &amm_account).expect("AMM delete succeeds");

        assert_eq!(result, AmmAccountDelete::Deleted);
        assert!(state.get_account(&amm_account).is_none());
        assert!(load_amm_raw(&state, &amm_key).is_none());
        assert_eq!(amm_owned_trustline_count(&state, &amm_account), 0);
    }

    #[test]
    fn amm_pool_trustline_lifecycle_matches_bounded_delete_path() {
        let _guard = amm_delete_limit_test_lock();
        let mut state = LedgerState::new();
        let amm_account = [9u8; 20];
        let issuer = [7u8; 20];
        let usd = iou("USD", 7);
        let amm_key = amm_key(&Issue::Xrp, &usd);
        let amount = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer,
        };
        state.insert_account(make_amm_account(amm_account, &amm_key, 1));
        state.insert_account(account(issuer, 0, 0));
        state.insert_raw(
            amm_key,
            build_amm_sle(&amm_account, &Issue::Xrp, &usd, 30, 0, 0, 0, 0),
        );
        directory::dir_add(&mut state, &amm_account, amm_key.0);

        assert!(apply_amount_delta(
            &mut state,
            &amm_account,
            AssetDelta::Credit,
            &amount
        ));
        assert!(ensure_pool_asset_trustline_lifecycle(
            &mut state,
            &amm_account,
            &amount
        ));

        let key = crate::ledger::trustline::shamap_key(
            &amm_account,
            &issuer,
            &Currency::from_code("USD").unwrap(),
        );
        let line = state.get_trustline(&key).expect("AMM pool line exists");
        assert_ne!(line.flags & LSF_AMM_NODE, 0);
        assert_ne!(
            line.flags & reserve_flag_for_trustline_account(line, &issuer),
            0
        );
        assert!(owner_dir_has_entry(&state, &amm_account, &key));
        assert!(owner_dir_has_entry(&state, &issuer, &key));
        assert_eq!(state.get_account(&issuer).unwrap().owner_count, 1);

        let mut line = line.clone();
        line.balance = IouValue::ZERO;
        state.insert_trustline(line);
        let result =
            delete_amm_account(&mut state, &amm_key, &amm_account).expect("AMM delete succeeds");

        assert_eq!(result, AmmAccountDelete::Deleted);
        assert!(state.get_account(&amm_account).is_none());
        assert!(state.get_trustline(&key).is_none());
        assert_eq!(state.get_account(&issuer).unwrap().owner_count, 0);
    }

    #[test]
    fn amm_delete_trustline_requires_exactly_one_amm_account() {
        let mut state = LedgerState::new();
        let target = [9u8; 20];
        let peer = [1u8; 20];
        let key = Key([0xCC; 32]);
        let currency = Currency::from_code("USD").unwrap();
        let line = crate::ledger::RippleState::new(&target, &peer, currency);
        let line_key = line.key();

        state.insert_account(account(target, 0, 1));
        state.insert_account(account(peer, 0, 1));
        state.insert_trustline(line.clone());
        assert_eq!(
            delete_amm_trustline(&mut state, &target, &line_key),
            Err("terNO_AMM")
        );

        state.insert_account(make_amm_account(target, &key, 1));
        state.insert_account(make_amm_account(peer, &Key([0xDD; 32]), 1));
        state.insert_trustline(line);
        assert_eq!(
            delete_amm_trustline(&mut state, &target, &line_key),
            Err("tecINTERNAL")
        );
    }

    #[test]
    fn amm_lp_currency_is_symmetric_and_tagged() {
        let usd = Currency::from_code("USD").unwrap();
        let eur = Currency::from_code("EUR").unwrap();

        let lhs = amm_lp_currency(&usd, &eur);
        let rhs = amm_lp_currency(&eur, &usd);

        assert_eq!(lhs, rhs);
        assert_eq!(lhs.code[0], 0x03);
        assert_ne!(lhs.code[1..], [0u8; 19]);
    }

    #[test]
    fn amm_lp_currency_changes_with_pair() {
        let usd = Currency::from_code("USD").unwrap();
        let eur = Currency::from_code("EUR").unwrap();
        let jpy = Currency::from_code("JPY").unwrap();

        assert_ne!(amm_lp_currency(&usd, &eur), amm_lp_currency(&usd, &jpy));
    }

    #[test]
    fn amm_lp_issue_uses_amm_account_as_issuer() {
        let amm_account = [9u8; 20];
        let issue = amm_lp_issue(&Issue::Xrp, &iou("USD", 7), amm_account)
            .expect("XRP/IOU AMM can derive LP issue");

        match issue {
            Issue::Iou { currency, issuer } => {
                assert_eq!(currency.code[0], 0x03);
                assert_eq!(issuer, amm_account);
            }
            _ => panic!("LP token must be an IOU issue"),
        }
    }

    #[test]
    fn amm_lp_issue_rejects_mpt_until_supported() {
        assert_eq!(
            amm_lp_issue(&Issue::Mpt([1u8; 24]), &Issue::Xrp, [9u8; 20]),
            None
        );
    }

    #[test]
    fn amm_sle_carries_canonical_lp_token_balance() {
        let amm_account = [9u8; 20];
        let usd = iou("USD", 7);
        let raw = build_amm_sle(&amm_account, &Issue::Xrp, &usd, 30, 0, 1_000, 2_000, 1_414);

        let lp_balance = amm_sle_lp_token_balance(&raw).expect("sfLPTokenBalance present");
        match lp_balance {
            Amount::Iou {
                value,
                currency,
                issuer,
            } => {
                assert_eq!(value, IouValue::from_f64(1_414.0));
                assert_eq!(currency.code[0], 0x03);
                assert_eq!(issuer, amm_account);
            }
            _ => panic!("LP token balance must be an IOU amount"),
        }
    }

    #[test]
    fn amm_sle_stores_assets_in_canonical_order() {
        let amm_account = [9u8; 20];
        let usd = iou("USD", 7);
        let eur = iou("EUR", 8);
        let raw = build_amm_sle(&amm_account, &usd, &eur, 30, 0, 1_000, 2_000, 1_414);
        let parsed = crate::ledger::meta::parse_sle(&raw).expect("AMM SLE parses");
        let asset = parsed
            .fields
            .iter()
            .find(|field| field.type_code == 24 && field.field_code == 3)
            .and_then(|field| Issue::from_bytes(&field.data).map(|(issue, _)| issue))
            .expect("sfAsset is present");
        let asset2 = parsed
            .fields
            .iter()
            .find(|field| field.type_code == 24 && field.field_code == 4)
            .and_then(|field| Issue::from_bytes(&field.data).map(|(issue, _)| issue))
            .expect("sfAsset2 is present");

        assert_eq!(asset, eur);
        assert_eq!(asset2, usd);
    }

    #[test]
    fn amm_lp_token_balance_patch_preserves_canonical_issue() {
        let amm_account = [9u8; 20];
        let usd = iou("USD", 7);
        let raw = build_amm_sle(&amm_account, &Issue::Xrp, &usd, 30, 0, 1_000, 2_000, 1_414);
        let patched = amm_patch_lp_token_balance(&raw, &Issue::Xrp, &usd, amm_account, 2_000);

        let lp_balance = amm_sle_lp_token_balance(&patched).expect("sfLPTokenBalance present");
        match lp_balance {
            Amount::Iou { value, issuer, .. } => {
                assert_eq!(value, IouValue::from_f64(2_000.0));
                assert_eq!(issuer, amm_account);
            }
            _ => panic!("LP token balance must be an IOU amount"),
        }
    }

    #[test]
    fn amm_withdraw_prefers_canonical_lp_token_in_over_legacy_amount() {
        let amm_account = [9u8; 20];
        let usd = iou("USD", 7);
        let lp_token_in =
            lp_token_balance_amount(&Issue::Xrp, &usd, amm_account, 250).expect("LP issue");

        let burn = amm_withdraw_lp_burn_from_fields(
            Some(&lp_token_in),
            Some(999),
            &Issue::Xrp,
            &usd,
            amm_account,
        )
        .expect("canonical LPTokenIn is accepted");

        assert_eq!(burn, 250);
    }

    #[test]
    fn amm_withdraw_rejects_wrong_lp_token_issue() {
        let amm_account = [9u8; 20];
        let usd = iou("USD", 7);
        let eur = iou("EUR", 8);
        let wrong_lp_token =
            lp_token_balance_amount(&Issue::Xrp, &eur, amm_account, 250).expect("LP issue");

        let err = amm_withdraw_lp_burn_from_fields(
            Some(&wrong_lp_token),
            None,
            &Issue::Xrp,
            &usd,
            amm_account,
        )
        .expect_err("wrong AMM LP token issue must be rejected");

        assert_eq!(err, "temBAD_AMM_TOKENS");
    }

    #[test]
    fn amm_withdraw_rejects_lp_token_in_without_lp_token_flag() {
        let amm_account = [9u8; 20];
        let usd = iou("USD", 7);
        let lp_token_in =
            lp_token_balance_amount(&Issue::Xrp, &usd, amm_account, 250).expect("LP issue");
        let tx = parsed_amm_withdraw_tx(0, Some(lp_token_in), None, None, None);

        assert_eq!(
            validate_amm_withdraw_lp_token_mode(&tx),
            Err("temMALFORMED")
        );
    }

    #[test]
    fn amm_withdraw_lp_token_flag_requires_only_lp_token_in() {
        let amm_account = [9u8; 20];
        let usd = iou("USD", 7);
        let lp_token_in =
            lp_token_balance_amount(&Issue::Xrp, &usd, amm_account, 250).expect("LP issue");
        let missing_lp = parsed_amm_withdraw_tx(TF_AMM_WITHDRAW_LP_TOKEN, None, None, None, None);
        let mixed_amount = parsed_amm_withdraw_tx(
            TF_AMM_WITHDRAW_LP_TOKEN,
            Some(lp_token_in.clone()),
            Some(Amount::Xrp(1)),
            None,
            None,
        );
        let mixed_amount2 = parsed_amm_withdraw_tx(
            TF_AMM_WITHDRAW_LP_TOKEN,
            Some(lp_token_in.clone()),
            None,
            Some(Amount::Xrp(1)),
            None,
        );
        let mixed_eprice = parsed_amm_withdraw_tx(
            TF_AMM_WITHDRAW_LP_TOKEN,
            Some(lp_token_in.clone()),
            None,
            None,
            Some(Amount::Xrp(1)),
        );
        let clean = parsed_amm_withdraw_tx(
            TF_AMM_WITHDRAW_LP_TOKEN,
            Some(lp_token_in),
            None,
            None,
            None,
        );

        assert_eq!(
            validate_amm_withdraw_lp_token_mode(&missing_lp),
            Err("temMALFORMED")
        );
        assert_eq!(
            validate_amm_withdraw_lp_token_mode(&mixed_amount),
            Err("temMALFORMED")
        );
        assert_eq!(
            validate_amm_withdraw_lp_token_mode(&mixed_amount2),
            Err("temMALFORMED")
        );
        assert_eq!(
            validate_amm_withdraw_lp_token_mode(&mixed_eprice),
            Err("temMALFORMED")
        );
        assert_eq!(validate_amm_withdraw_lp_token_mode(&clean), Ok(()));
    }

    #[test]
    fn amm_two_asset_deposit_mints_lp_down_on_fractional_ratio() {
        assert_eq!(lp_from_two_asset_deposit(1, 2, 3, 7, 11), 3);
    }

    #[test]
    fn amm_lp_token_deposit_rounds_asset_inputs_up() {
        assert_eq!(proportional_pool_in_for_lp(10, 3, 7), Some(5));
        assert_eq!(proportional_pool_in_for_lp(11, 3, 7), Some(5));
    }

    #[test]
    fn amm_lp_token_withdraw_returns_assets_down() {
        let lp_burn = 3u64;
        let lp_total = 7u64;

        assert_eq!(lp_burn * 10 / lp_total, 4);
        assert_eq!(lp_burn * 11 / lp_total, 4);
    }

    #[test]
    fn amm_two_asset_withdraw_burns_lp_up() {
        let burn1 = ceil_div_u128(1 * 10, 3).expect("valid pool");
        let burn2 = ceil_div_u128(2 * 10, 7).expect("valid pool");

        assert_eq!(burn1.max(burn2), 4);
    }

    #[test]
    fn amm_single_asset_deposit_mints_lp_down() {
        assert_eq!(lp_tokens_out_for_single_asset(1, 3, 10, 0), Some(1));
    }

    #[test]
    fn amm_one_asset_lp_token_deposit_rounds_input_up() {
        assert_eq!(single_asset_in_for_lp(3, 1, 10, 0), Some(1));
    }

    #[test]
    fn amm_single_asset_withdraw_burns_lp_up() {
        assert_eq!(single_withdraw_lp_burn(1, 3, 10, 0), Some(2));
    }

    #[test]
    fn amm_one_asset_lp_token_withdraw_rounds_output_down() {
        assert_eq!(single_asset_out_for_lp(3, 2, 10, 0), Some(1));
    }

    #[test]
    fn amm_iou_pool_units_preserve_integer_exponents_without_f64() {
        let amount = Amount::Iou {
            value: IouValue {
                mantissa: 1_234_567_890_123_456,
                exponent: 3,
            },
            currency: Currency::from_code("USD").unwrap(),
            issuer: [7u8; 20],
        };

        assert_eq!(amount_pool_units(&amount), Some(1_234_567_890_123_456_000));
    }

    #[test]
    fn amm_iou_pool_units_floor_negative_exponent_without_f64() {
        let amount = Amount::Iou {
            value: IouValue {
                mantissa: 1_234_567_890_123_456,
                exponent: -3,
            },
            currency: Currency::from_code("USD").unwrap(),
            issuer: [7u8; 20],
        };

        assert_eq!(amount_pool_units(&amount), Some(1_234_567_890_123));
    }

    #[test]
    fn amm_lp_token_units_preserve_values_above_f64_exact_range() {
        let units = 9_007_199_254_740_993u64;
        let amm_account = [9u8; 20];
        let holder = [2u8; 20];
        let usd = iou("USD", 7);
        let lp_amount =
            lp_token_amount_for_units(&Issue::Xrp, &usd, amm_account, units).expect("LP amount");

        assert_eq!(
            lp_token_units_from_amount_allow_zero(&lp_amount, &Issue::Xrp, &usd, amm_account),
            Ok(units)
        );
        assert_eq!(
            amm_withdraw_lp_burn_from_fields(
                Some(&lp_amount),
                None,
                &Issue::Xrp,
                &usd,
                amm_account
            ),
            Ok(units)
        );

        let Issue::Iou { currency, issuer } =
            amm_lp_issue(&Issue::Xrp, &usd, amm_account).expect("LP issue")
        else {
            panic!("LP issue must be IOU");
        };
        let mut line = crate::ledger::RippleState::new(&holder, &issuer, currency);
        line.transfer(&issuer, &iou_value_from_units(units));
        let mut state = LedgerState::new();
        state.insert_trustline(line);

        assert_eq!(
            holder_lp_token_units(&state, &holder, &Issue::Xrp, &usd, amm_account),
            Some(units)
        );
    }

    #[test]
    fn amm_bid_rebid_price_uses_integer_auction_decay() {
        let purchased = 9_007_199_254_740_993u64;
        let min_slot_price = 7u64;
        let expected = ((purchased as u128 * 105u128) / 100u128) as u64 + min_slot_price;

        assert_eq!(
            auction_rebid_computed_price(purchased, 0, min_slot_price),
            expected
        );
    }

    #[test]
    fn amm_bid_refund_uses_exact_fraction_floor() {
        let purchased = 9_007_199_254_740_993u64;

        assert_eq!(
            auction_rebid_refund_units(purchased, 0),
            (purchased as u128 * 19u128 / 20u128) as u64
        );
    }

    fn iou_amount(issue: &Issue, units: u64) -> Amount {
        let Issue::Iou { currency, issuer } = issue else {
            panic!("test issue must be IOU");
        };
        Amount::Iou {
            value: iou_value_from_units(units),
            currency: currency.clone(),
            issuer: *issuer,
        }
    }

    fn parsed_amm_clawback_tx(
        issuer: [u8; 20],
        holder: [u8; 20],
        flags: u32,
        asset: Issue,
        asset2: Issue,
        amount: Option<Amount>,
    ) -> ParsedTx {
        ParsedTx {
            tx_type: 31,
            account: issuer,
            holder: Some(holder),
            flags,
            asset: Some(asset),
            asset2: Some(asset2),
            amount,
            ..ParsedTx::default()
        }
    }

    #[test]
    fn amm_clawback_checks_asset_shape_before_accounts() {
        let mut state = LedgerState::new();
        let tx = parsed_amm_clawback_tx([7u8; 20], [2u8; 20], 0, Issue::Xrp, iou("USD", 7), None);

        assert_eq!(
            apply_amm_clawback(&mut state, &tx),
            ApplyResult::ClaimedCost("temMALFORMED")
        );
    }

    #[test]
    fn amm_clawback_missing_amm_precedes_issuer_permission() {
        let mut state = LedgerState::new();
        let issuer = [7u8; 20];
        let holder = [2u8; 20];
        state.insert_account(account(issuer, 0, 0));
        state.insert_account(account(holder, 0, 0));
        let tx = parsed_amm_clawback_tx(issuer, holder, 0, iou("USD", 7), iou("EUR", 8), None);

        assert_eq!(
            apply_amm_clawback(&mut state, &tx),
            ApplyResult::ClaimedCost("terNO_AMM")
        );
    }

    fn seed_amm_clawback_rounding_state(
        lp_total: u64,
        holder_lp: u64,
    ) -> (LedgerState, ParsedTx, Issue, Issue, [u8; 20], [u8; 20]) {
        let issuer = [7u8; 20];
        let paired_issuer = [8u8; 20];
        let holder = [2u8; 20];
        let amm_account = [9u8; 20];
        let asset1 = iou("USD", 7);
        let asset2 = iou("EUR", 8);
        let amm_key = amm_key(&asset1, &asset2);
        let mut state = LedgerState::new();
        let mut issuer_account = account(issuer, 0, 0);
        issuer_account.flags |= LSF_ALLOW_TRUST_LINE_CLAWBACK;
        state.insert_account(issuer_account);
        state.insert_account(account(paired_issuer, 0, 0));
        state.insert_account(account(holder, 0, 0));
        state.insert_account(make_amm_account(amm_account, &amm_key, 1));
        state.insert_raw(
            amm_key,
            build_amm_sle(
                &amm_account,
                &asset1,
                &asset2,
                0,
                0,
                1_000,
                2_000,
                lp_total as i64,
            ),
        );
        directory::dir_add(&mut state, &amm_account, amm_key.0);
        assert!(apply_amount_delta(
            &mut state,
            &amm_account,
            AssetDelta::Credit,
            &iou_amount(&asset1, 1_000)
        ));
        assert!(apply_amount_delta(
            &mut state,
            &amm_account,
            AssetDelta::Credit,
            &iou_amount(&asset2, 2_000)
        ));
        assert!(issue_lp_tokens(
            &mut state,
            &holder,
            &asset1,
            &asset2,
            amm_account,
            holder_lp
        ));
        let tx = ParsedTx {
            tx_type: 31,
            account: issuer,
            holder: Some(holder),
            asset: Some(asset1.clone()),
            asset2: Some(asset2.clone()),
            amount: Some(iou_amount(&asset1, 500)),
            ..ParsedTx::default()
        };
        (state, tx, asset1, asset2, holder, amm_account)
    }

    #[test]
    fn amm_clawback_without_rounding_amendment_uses_sle_lp_total() {
        let (mut state, tx, asset1, asset2, holder, amm_account) =
            seed_amm_clawback_rounding_state(1_000, 1_001);

        assert_eq!(apply_amm_clawback(&mut state, &tx), ApplyResult::Success);

        assert_eq!(
            holder_lp_token_units(&state, &holder, &asset1, &asset2, amm_account),
            Some(501)
        );
    }

    #[test]
    fn amm_clawback_rounding_amendment_adjusts_last_lp_total() {
        let (mut state, tx, asset1, asset2, holder, amm_account) =
            seed_amm_clawback_rounding_state(1_000, 1_001);
        state.enable_amendment(*FEATURE_FIX_AMM_CLAWBACK_ROUNDING);

        assert_eq!(apply_amm_clawback(&mut state, &tx), ApplyResult::Success);

        assert_eq!(
            holder_lp_token_units(&state, &holder, &asset1, &asset2, amm_account),
            Some(500)
        );
        let amm_raw = load_amm_raw(&state, &amm_key(&asset1, &asset2)).expect("AMM remains open");
        assert_eq!(amm_lp_total_units(&amm_raw), 500);
        assert_eq!(amm_sle_number(&amm_raw, 10), 500);
        assert_eq!(amm_sle_number(&amm_raw, 11), 1000);
    }

    #[test]
    fn amm_clawback_rounding_amendment_rejects_far_last_lp_mismatch() {
        let (mut state, tx, _, _, _, _) = seed_amm_clawback_rounding_state(1_000, 1_100);
        state.enable_amendment(*FEATURE_FIX_AMM_CLAWBACK_ROUNDING);

        assert_eq!(
            apply_amm_clawback(&mut state, &tx),
            ApplyResult::ClaimedCost("tecAMM_INVALID_TOKENS")
        );
    }
}
