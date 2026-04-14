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

use crate::crypto::{sha512_first_half, sha256, ripemd160};
use crate::ledger::{directory, Key, LedgerState, AccountRoot};
use crate::ledger::tx::TxContext;
use crate::transaction::amount::Issue;
use crate::transaction::ParsedTx;

use super::ApplyResult;

/// LedgerNameSpace::AMM = 'A' = 0x41.
const AMM_SPACE: [u8; 2] = [0x00, 0x41];

/// AMM entry type (ltAMM = 0x0079).
const LT_AMM: u16 = 0x0079;

/// Account flags for pseudo-accounts.
const LSF_DISABLE_MASTER: u32 = 0x00100000;
const LSF_DEFAULT_RIPPLE: u32 = 0x00800000;
const LSF_DEPOSIT_AUTH: u32   = 0x01000000;

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

/// Compute the AMM SHAMap key from two asset issues.
/// `SHA-512-Half(0x0041 || minIssue.account || minIssue.currency ||
///                         maxIssue.account || maxIssue.currency)`
pub(super) fn amm_key(issue1: &Issue, issue2: &Issue) -> Key {
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
) -> Vec<u8> {
    use crate::ledger::meta::ParsedField;
    let fields = vec![
        // sfAccount (ACCOUNT=8, field=1) — pseudo-account
        ParsedField { type_code: 8, field_code: 1, data: pseudo_account.to_vec() },
        // sfFlags (UINT32=2, field=2)
        ParsedField { type_code: 2, field_code: 2, data: 0u32.to_be_bytes().to_vec() },
        // sfOwnerNode (UINT64=3, field=4)
        ParsedField { type_code: 3, field_code: 4, data: owner_node.to_be_bytes().to_vec() },
        // sfTradingFee (UINT16=1, field=2)
        ParsedField { type_code: 1, field_code: 2, data: trading_fee.to_be_bytes().to_vec() },
        // sfAsset (ISSUE=24, field=3)
        ParsedField { type_code: 24, field_code: 3, data: asset1.to_bytes() },
        // sfAsset2 (ISSUE=24, field=4)
        ParsedField { type_code: 24, field_code: 4, data: asset2.to_bytes() },
        // Pool balance tracking (NUMBER fields for simplified local model):
        // sfPool1 (NUMBER=9, field=10) — asset1 pool balance (drops for XRP)
        ParsedField { type_code: 9, field_code: 10, data: 0i64.to_be_bytes().to_vec() },
        // sfPool2 (NUMBER=9, field=11) — asset2 pool balance
        ParsedField { type_code: 9, field_code: 11, data: 0i64.to_be_bytes().to_vec() },
        // sfLPTotal (NUMBER=9, field=12) — total LP tokens outstanding
        ParsedField { type_code: 9, field_code: 12, data: 0i64.to_be_bytes().to_vec() },
    ];
    crate::ledger::meta::build_sle(LT_AMM, &fields, None, None)
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
            type_code: 9, field_code, data: value.to_be_bytes().to_vec(),
        }],
        None, None, &[],
    )
}

/// Integer square root (floor).
fn isqrt(n: u128) -> u64 {
    if n == 0 { return 0; }
    let mut x = (n as f64).sqrt() as u128;
    // Newton's method refinement for exact floor
    loop {
        let x1 = (x + n / x) / 2;
        if x1 >= x { break; }
        x = x1;
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

// ── Transaction handlers ─────────────────────────────────────────────────────

/// Type 35: AMMCreate — create an AMM with two assets.
///
/// Creates: pseudo-account, AMM SLE with asset pair and trading fee.
/// owner_count += 1 (for AMM on pseudo-account).
///
/// (rippled: AMMCreate.cpp — doApply)
pub(crate) fn apply_amm_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
) -> ApplyResult {
    // 1. Validate two distinct assets
    let asset1 = match &tx.asset {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS"),
    };
    let asset2 = match &tx.asset2 {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS"),
    };
    if asset1 == asset2 {
        return ApplyResult::ClaimedCost("temBAD_AMM_TOKENS");
    }

    // 2. Compute AMM key and check it doesn't already exist
    let akey = amm_key(&asset1, &asset2);
    if state.get_raw(&akey).is_some() {
        return ApplyResult::ClaimedCost("tecDUPLICATE");
    }

    // 3. Derive pseudo-account
    let pseudo_id = match pseudo_account_address(state, &ctx.parent_hash, &akey.0) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("terADDRESS_COLLISION"),
    };

    // 4. Create pseudo-account
    state.insert_account(AccountRoot {
        account_id: pseudo_id,
        balance: 0,
        sequence: 0,
        owner_count: 0,
        flags: LSF_DISABLE_MASTER | LSF_DEFAULT_RIPPLE | LSF_DEPOSIT_AUTH,
        regular_key: None,
        minted_nftokens: 0,
        burned_nftokens: 0,
        transfer_rate: 0,
        domain: Vec::new(),
        tick_size: 0,
        ticket_count: 0,
        previous_txn_id: [0u8; 32],
        previous_txn_lgr_seq: 0, raw_sle: None,
    });

    // 5. Add AMM to pseudo-account's directory
    let owner_node = directory::dir_add(state, &pseudo_id, akey.0);

    // 6. Create AMM SLE (trading_fee from tx.flags, simplified)
    let trading_fee = (tx.flags & 0xFFFF) as u16; // trading fee in lower 16 bits
    let amm_sle = build_amm_sle(&pseudo_id, &asset1, &asset2, trading_fee, owner_node);
    state.insert_raw(akey, amm_sle);

    // 7. Increment pseudo-account owner_count
    if let Some(pa) = state.get_account(&pseudo_id) {
        let mut pa = pa.clone();
        pa.owner_count += 1;
        state.insert_account(pa);
    }

    // 8. Update sender: owner_count += 1 (for the AMM)
    if let Some(sender) = state.get_account(&tx.account) {
        let mut sender = sender.clone();
        sender.owner_count += 1;
        state.insert_account(sender);
    }

    // NOTE: Full AMMCreate also transfers initial liquidity from creator to
    // pseudo-account and mints LP tokens. That requires Amount-level asset
    // transfer which we defer to the deposit path.

    ApplyResult::Success
}

/// Type 40: AMMDelete — delete an empty AMM.
///
/// Validates: LP token balance is 0 (empty pool).
/// Removes: AMM SLE, pseudo-account.
///
/// (rippled: AMMDelete.cpp — doApply)
pub(crate) fn apply_amm_delete(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
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
    let amm_raw = match state.get_raw(&akey) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("terNO_AMM"),
    };

    // 2. Get pseudo-account
    let pseudo_id = match amm_sle_pseudo_id(&amm_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 3. AMM must be empty: no pooled assets and no LP supply.
    let pool1 = amm_sle_number(&amm_raw, 10) as u64;
    let pool2 = amm_sle_number(&amm_raw, 11) as u64;
    let lp_total = amm_sle_number(&amm_raw, 12) as u64;
    if pool1 != 0 || pool2 != 0 || lp_total != 0 {
        return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
    }

    // 4. Remove AMM from pseudo-account's directory
    directory::dir_remove(state, &pseudo_id, &akey.0);

    // 5. Remove pseudo-account
    state.remove_account(&pseudo_id);

    // 6. Remove AMM SLE
    state.remove_raw(&akey);

    // 7. Decrement sender's owner_count
    if let Some(sender) = state.get_account(&tx.account) {
        let mut sender = sender.clone();
        sender.owner_count = sender.owner_count.saturating_sub(1);
        state.insert_account(sender);
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
pub(crate) fn apply_amm_deposit(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
    // 1. Find AMM
    let asset1 = match &tx.asset { Some(a) => a.clone(), None => return ApplyResult::ClaimedCost("temMALFORMED") };
    let asset2 = match &tx.asset2 { Some(a) => a.clone(), None => return ApplyResult::ClaimedCost("temMALFORMED") };
    let akey = amm_key(&asset1, &asset2);
    let amm_raw = match state.get_raw(&akey) { Some(d) => d.to_vec(), None => return ApplyResult::ClaimedCost("terNO_AMM") };

    let pseudo_id = match amm_sle_pseudo_id(&amm_raw) { Some(id) => id, None => return ApplyResult::ClaimedCost("tecINTERNAL") };

    // 2. Get deposit amounts (amount_drops for asset1/XRP, we'll use flags for asset2 amount)
    // Simplified: for XRP+IOU, amount_drops is the XRP deposit.
    // For the IOU side, we use a fixed 1:1 ratio for simplicity in first pass.
    let xrp_deposit = match tx.amount_drops {
        Some(d) if d > 0 => d,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    // IOU deposit amount — for simplicity, equal to XRP deposit scaled
    // In production this would come from a second Amount field
    let iou_deposit = xrp_deposit; // 1:1 simplified ratio

    // 3. Read current pool state
    let pool1 = amm_sle_number(&amm_raw, 10) as u64; // asset1 pool
    let pool2 = amm_sle_number(&amm_raw, 11) as u64; // asset2 pool
    let lp_total = amm_sle_number(&amm_raw, 12) as u64;

    // 4. Compute LP tokens to mint
    let lp_minted = if lp_total == 0 {
        // First deposit: LP = sqrt(asset1 * asset2)
        isqrt(xrp_deposit as u128 * iou_deposit as u128)
    } else {
        // Pro-rata: LP = min(deposit1/pool1, deposit2/pool2) * lp_total
        let ratio1 = (xrp_deposit as u128 * lp_total as u128) / pool1 as u128;
        let ratio2 = (iou_deposit as u128 * lp_total as u128) / pool2 as u128;
        ratio1.min(ratio2) as u64
    };

    if lp_minted == 0 {
        return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
    }

    // 5. Transfer XRP from depositor to pseudo-account
    if let Some(sender) = state.get_account(&tx.account) {
        let mut sender = sender.clone();
        if sender.balance < xrp_deposit {
            return ApplyResult::ClaimedCost("tecUNFUNDED_AMM");
        }
        sender.balance -= xrp_deposit;
        state.insert_account(sender);
    }
    if let Some(pa) = state.get_account(&pseudo_id) {
        let mut pa = pa.clone();
        pa.balance += xrp_deposit;
        state.insert_account(pa);
    }

    // 6. Update AMM pool balances and LP total
    let amm_raw = amm_patch_number(&amm_raw, 10, (pool1 + xrp_deposit) as i64);
    let amm_raw = amm_patch_number(&amm_raw, 11, (pool2 + iou_deposit) as i64);
    let amm_raw = amm_patch_number(&amm_raw, 12, (lp_total + lp_minted) as i64);
    state.insert_raw(akey, amm_raw);

    ApplyResult::Success
}

/// Type 37: AMMWithdraw — remove liquidity from an AMM pool.
///
/// Burns LP tokens and returns underlying assets pro-rata.
///
/// (rippled: AMMWithdraw.cpp — doApply)
pub(crate) fn apply_amm_withdraw(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
    // 1. Find AMM
    let asset1 = match &tx.asset { Some(a) => a.clone(), None => return ApplyResult::ClaimedCost("temMALFORMED") };
    let asset2 = match &tx.asset2 { Some(a) => a.clone(), None => return ApplyResult::ClaimedCost("temMALFORMED") };
    let akey = amm_key(&asset1, &asset2);
    let amm_raw = match state.get_raw(&akey) { Some(d) => d.to_vec(), None => return ApplyResult::ClaimedCost("terNO_AMM") };

    let pseudo_id = match amm_sle_pseudo_id(&amm_raw) { Some(id) => id, None => return ApplyResult::ClaimedCost("tecINTERNAL") };

    // 2. Get LP tokens to burn (passed as amount_drops)
    let lp_burn = match tx.amount_drops {
        Some(d) if d > 0 => d,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };

    // 3. Read current pool state
    let pool1 = amm_sle_number(&amm_raw, 10) as u64;
    let pool2 = amm_sle_number(&amm_raw, 11) as u64;
    let lp_total = amm_sle_number(&amm_raw, 12) as u64;

    if lp_total == 0 || lp_burn > lp_total {
        return ApplyResult::ClaimedCost("tecAMM_BALANCE");
    }

    // 4. Compute assets to return pro-rata
    let return1 = ((lp_burn as u128 * pool1 as u128) / lp_total as u128) as u64;
    let return2 = ((lp_burn as u128 * pool2 as u128) / lp_total as u128) as u64;

    if return1 == 0 && return2 == 0 {
        return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
    }

    // 5. Transfer XRP from pseudo-account to withdrawer
    if let Some(pa) = state.get_account(&pseudo_id) {
        let mut pa = pa.clone();
        pa.balance = pa.balance.saturating_sub(return1);
        state.insert_account(pa);
    }
    if let Some(sender) = state.get_account(&tx.account) {
        let mut sender = sender.clone();
        sender.balance += return1;
        state.insert_account(sender);
    }

    // 6. Update AMM pool balances and LP total
    let amm_raw = amm_patch_number(&amm_raw, 10, (pool1 - return1) as i64);
    let amm_raw = amm_patch_number(&amm_raw, 11, (pool2 - return2) as i64);
    let amm_raw = amm_patch_number(&amm_raw, 12, (lp_total - lp_burn) as i64);
    state.insert_raw(akey, amm_raw);

    ApplyResult::Success
}

/// Read sfTradingFee from an AMM SLE (UINT16, type=1 field=2).
#[allow(dead_code)]
fn amm_sle_trading_fee(raw: &[u8]) -> u16 {
    let parsed = match crate::ledger::meta::parse_sle(raw) {
        Some(p) => p,
        None => return 0,
    };
    for field in &parsed.fields {
        if field.type_code == 1 && field.field_code == 2 && field.data.len() == 2 {
            return u16::from_be_bytes(field.data[..2].try_into().unwrap());
        }
    }
    0
}

/// Patch sfTradingFee on an AMM SLE.
fn amm_patch_trading_fee(raw: &[u8], fee: u16) -> Vec<u8> {
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 1, field_code: 2, data: fee.to_be_bytes().to_vec(),
        }],
        None, None, &[],
    )
}

/// Type 38: AMMVote — vote on the AMM trading fee.
///
/// Each voter proposes a fee (0-1000 = 0-1%). The AMM's trading fee is
/// set to the proposed fee, weighted by the voter's LP token share.
/// Simplified: we apply the voter's proposed fee directly (single-voter model).
/// Full implementation would track up to 8 vote slots and compute weighted average.
///
/// (rippled: AMMVote.cpp — doApply)
pub(crate) fn apply_amm_vote(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
    // 1. Find AMM
    let asset1 = match &tx.asset { Some(a) => a.clone(), None => return ApplyResult::ClaimedCost("temMALFORMED") };
    let asset2 = match &tx.asset2 { Some(a) => a.clone(), None => return ApplyResult::ClaimedCost("temMALFORMED") };
    let akey = amm_key(&asset1, &asset2);
    let amm_raw = match state.get_raw(&akey) { Some(d) => d.to_vec(), None => return ApplyResult::ClaimedCost("terNO_AMM") };

    // 2. Get proposed trading fee from tx (sfTradingFee encoded in flags or dedicated field)
    // rippled passes TradingFee as a field; we use the lower 16 bits of flags as simplified parse
    let proposed_fee = (tx.flags & 0xFFFF) as u16;

    // Trading fee must be 0..=1000 (0-1% in basis points × 10)
    if proposed_fee > 1000 {
        return ApplyResult::ClaimedCost("temBAD_FEE");
    }

    // 3. Update the AMM's trading fee
    // Simplified: direct set. Full rippled tracks VoteSlots array with up to 8
    // voters and computes a weighted average based on each voter's LP holdings.
    let amm_raw = amm_patch_trading_fee(&amm_raw, proposed_fee);
    state.insert_raw(akey, amm_raw);

    ApplyResult::Success
}

/// Type 39: AMMBid — bid for the AMM's auction slot.
///
/// The auction slot gives the holder a discounted trading fee for a time window.
/// Simplified: update the AMM's auction slot fields.
/// Full implementation would handle: slot expiry, minimum bid, refunds to previous winner.
///
/// (rippled: AMMBid.cpp — doApply)
pub(crate) fn apply_amm_bid(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
    // 1. Find AMM
    let asset1 = match &tx.asset { Some(a) => a.clone(), None => return ApplyResult::ClaimedCost("temMALFORMED") };
    let asset2 = match &tx.asset2 { Some(a) => a.clone(), None => return ApplyResult::ClaimedCost("temMALFORMED") };
    let akey = amm_key(&asset1, &asset2);
    let amm_raw = match state.get_raw(&akey) { Some(d) => d.to_vec(), None => return ApplyResult::ClaimedCost("terNO_AMM") };

    // 2. Get bid amount (LP tokens to pay for the slot)
    let bid_amount = match tx.amount_drops {
        Some(d) if d > 0 => d,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };

    // 3. Burn the bid LP tokens from total supply
    let lp_total = amm_sle_number(&amm_raw, 12) as u64;
    if bid_amount > lp_total {
        return ApplyResult::ClaimedCost("tecAMM_BALANCE");
    }
    let amm_raw = amm_patch_number(&amm_raw, 12, (lp_total - bid_amount) as i64);
    state.insert_raw(akey, amm_raw);

    // NOTE: Full AMMBid also: creates/updates AuctionSlot object on the AMM SLE,
    // tracks slot expiry (24 intervals of 72 minutes), computes discounted fee,
    // refunds LP tokens to previous slot holder. Deferred to metadata/diff sync
    // for now since the SLE field layout is complex.

    ApplyResult::Success
}

/// Type 31: AMMClawback — issuer recovers LP tokens from a holder.
///
/// The issuer of one of the AMM's assets claws back a holder's LP token balance,
/// burning the LP tokens and returning underlying assets to the issuer.
///
/// (rippled: AMMClawback.cpp — doApply)
pub(crate) fn apply_amm_clawback(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
    // 1. Find AMM
    let asset1 = match &tx.asset { Some(a) => a.clone(), None => return ApplyResult::ClaimedCost("temMALFORMED") };
    let asset2 = match &tx.asset2 { Some(a) => a.clone(), None => return ApplyResult::ClaimedCost("temMALFORMED") };
    let akey = amm_key(&asset1, &asset2);
    let amm_raw = match state.get_raw(&akey) { Some(d) => d.to_vec(), None => return ApplyResult::ClaimedCost("terNO_AMM") };

    let pseudo_id = match amm_sle_pseudo_id(&amm_raw) { Some(id) => id, None => return ApplyResult::ClaimedCost("tecINTERNAL") };

    // 2. Get LP tokens to claw back (amount_drops)
    let lp_clawback = match tx.amount_drops {
        Some(d) if d > 0 => d,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };

    // 3. Read current pool state
    let pool1 = amm_sle_number(&amm_raw, 10) as u64;
    let pool2 = amm_sle_number(&amm_raw, 11) as u64;
    let lp_total = amm_sle_number(&amm_raw, 12) as u64;

    if lp_total == 0 || lp_clawback > lp_total {
        return ApplyResult::ClaimedCost("tecAMM_BALANCE");
    }

    // 4. Compute assets to return pro-rata (same as withdraw)
    let return1 = ((lp_clawback as u128 * pool1 as u128) / lp_total as u128) as u64;
    let return2 = ((lp_clawback as u128 * pool2 as u128) / lp_total as u128) as u64;

    // 5. Transfer XRP portion from pseudo-account to clawback issuer
    if return1 > 0 {
        if let Some(pa) = state.get_account(&pseudo_id) {
            let mut pa = pa.clone();
            pa.balance = pa.balance.saturating_sub(return1);
            state.insert_account(pa);
        }
        if let Some(sender) = state.get_account(&tx.account) {
            let mut sender = sender.clone();
            sender.balance += return1;
            state.insert_account(sender);
        }
    }

    // 6. Update AMM pool balances and LP total
    let amm_raw = amm_patch_number(&amm_raw, 10, (pool1 - return1) as i64);
    let amm_raw = amm_patch_number(&amm_raw, 11, (pool2 - return2) as i64);
    let amm_raw = amm_patch_number(&amm_raw, 12, (lp_total - lp_clawback) as i64);
    state.insert_raw(akey, amm_raw);

    ApplyResult::Success
}
