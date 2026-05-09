//! NFToken — IMPLEMENTED

use super::ApplyResult;
use crate::ledger::directory;
use crate::ledger::tx::asset_flow::{
    apply_amount_delta, transfer_rate_gross_debit_amount, AssetDelta,
};
use crate::ledger::LedgerState;
use crate::transaction::amount::{Amount, IouValue};
use crate::transaction::ParsedTx;

fn nft_offer_directory_root(offer: &crate::ledger::NFTokenOffer) -> crate::ledger::Key {
    directory::nft_offer_dir_key(&offer.nftoken_id, offer.is_sell())
}

fn remove_nft_offer_directories(
    state: &mut LedgerState,
    key: &crate::ledger::Key,
    offer: &crate::ledger::NFTokenOffer,
) {
    directory::dir_remove_root_page(
        state,
        &directory::owner_dir_key(&offer.account),
        offer.owner_node,
        &key.0,
    );
    directory::dir_remove_root_page(
        state,
        &nft_offer_directory_root(offer),
        offer.nft_offer_node,
        &key.0,
    );
}

pub(crate) fn apply_nftoken_mint(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    close_time: u64,
    pre_fee_balance: u64,
) -> ApplyResult {
    let taxon = tx.nftoken_taxon.unwrap_or(0);
    let transfer_fee = tx.transfer_fee_field.unwrap_or(0);
    let nft_flags = (tx.flags & 0xFFFF) as u16;

    // Transfer fee validation (rippled: NFTokenMint.cpp preflight)
    if transfer_fee > 50000 {
        return ApplyResult::ClaimedCost("temBAD_NFTOKEN_TRANSFER_FEE");
    }
    // Transfer fee requires tfTransferable flag
    if transfer_fee > 0 && (nft_flags & crate::ledger::nftoken::TF_TRANSFERABLE == 0) {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    if tx.issuer == Some(tx.account) {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    let issuer = tx.issuer.unwrap_or(tx.account);
    if tx.issuer.is_some() {
        let issuer_account = match state.get_account(&issuer) {
            Some(account) => account.clone(),
            None => return ApplyResult::ClaimedCost("tecNO_ISSUER"),
        };
        if issuer_account.nftoken_minter() != Some(tx.account) {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
    }

    if (tx.destination.is_some() || tx.expiration.is_some()) && tx.amount.is_none() {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    if tx.destination == Some(tx.account) {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    if tx.expiration == Some(0) {
        return ApplyResult::ClaimedCost("temBAD_EXPIRATION");
    }
    if tx
        .expiration
        .is_some_and(|expiration| (close_time as u32) >= expiration)
    {
        return ApplyResult::ClaimedCost("tecEXPIRED");
    }
    if tx.amount.is_some() && (nft_flags & crate::ledger::nftoken::TF_ONLY_XRP != 0) {
        if !matches!(tx.amount, Some(Amount::Xrp(_))) {
            return ApplyResult::ClaimedCost("temBAD_AMOUNT");
        }
    }
    if let Some(destination) = tx.destination {
        let destination_account = match state.get_account(&destination) {
            Some(account) => account,
            None => return ApplyResult::ClaimedCost("tecNO_DST"),
        };
        if (destination_account.flags & crate::ledger::account::LSF_DISALLOW_INCOMING_NFTOKEN_OFFER)
            != 0
        {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
    }

    let mut issuer_account_for_mint = if issuer == tx.account {
        new_sender.clone()
    } else {
        state
            .get_account(&issuer)
            .cloned()
            .unwrap_or_else(|| unreachable!("authorized minter preclaim loaded issuer"))
    };
    let minted_count = issuer_account_for_mint.minted_nftokens;
    let minted_next = match minted_count.checked_add(1) {
        Some(next) if next != 0 => next,
        _ => return ApplyResult::ClaimedCost("tecMAX_SEQUENCE_REACHED"),
    };
    if issuer_account_for_mint.first_nftoken_sequence == 0 {
        issuer_account_for_mint.first_nftoken_sequence = if tx.issuer.is_some() || tx.sequence == 0
        {
            issuer_account_for_mint.sequence
        } else {
            issuer_account_for_mint.sequence.saturating_sub(1)
        };
    }
    let token_sequence = match issuer_account_for_mint
        .first_nftoken_sequence
        .checked_add(minted_count)
    {
        Some(seq)
            if seq >= issuer_account_for_mint.first_nftoken_sequence
                && seq.checked_add(1).is_some() =>
        {
            seq
        }
        _ => return ApplyResult::ClaimedCost("tecMAX_SEQUENCE_REACHED"),
    };

    let nftoken_id = crate::ledger::nftoken::make_nftoken_id(
        nft_flags,
        transfer_fee,
        &issuer,
        taxon,
        token_sequence,
    );

    let owner_page_count_before = state.nft_page_count(&tx.account);

    // Insert via page-based store (also keeps flat store in sync)
    if let Err(code) = state.insert_nftoken_paged(&tx.account, nftoken_id, tx.uri.clone()) {
        return ApplyResult::ClaimedCost(code);
    }
    issuer_account_for_mint.minted_nftokens = minted_next;
    if issuer == tx.account {
        new_sender.minted_nftokens = issuer_account_for_mint.minted_nftokens;
        new_sender.first_nftoken_sequence = issuer_account_for_mint.first_nftoken_sequence;
    } else {
        state.insert_account(issuer_account_for_mint);
    }
    let owner_page_count_after = state.nft_page_count(&tx.account);
    new_sender.owner_count = owner_count_after_page_delta(
        new_sender.owner_count,
        owner_page_count_before,
        owner_page_count_after,
    );

    if tx.amount.is_some() {
        let fees = crate::ledger::fees::Fees::default();
        let required = fees.reserve_base + ((new_sender.owner_count as u64 + 1) * fees.reserve_inc);
        if pre_fee_balance < required {
            return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
        }
        let sequence = super::sequence_proxy(tx);
        let offer_key = crate::ledger::nftoken::offer_shamap_key(&tx.account, sequence);
        let owner_node = directory::dir_add(state, &tx.account, offer_key.0);
        let (_, nft_offer_node) =
            directory::dir_add_nft_offer(state, &nftoken_id, true, offer_key.0);
        state.insert_nft_offer(crate::ledger::NFTokenOffer {
            account: tx.account,
            sequence,
            nftoken_id,
            amount: tx.amount.clone().unwrap_or(Amount::Xrp(0)),
            destination: tx.destination,
            expiration: tx.expiration,
            flags: 0x0001,
            owner_node,
            nft_offer_node,
            previous_txn_id: [0u8; 32],
            previous_txn_lgrseq: 0,
            raw_sle: None,
        });
        new_sender.owner_count += 1;
    }

    ApplyResult::Success
}

fn amount_is_zero(amount: &Amount) -> bool {
    match amount {
        Amount::Xrp(drops) => *drops == 0,
        Amount::Iou { value, .. } => value.mantissa == 0,
        Amount::Mpt(raw) => raw.iter().all(|b| *b == 0),
    }
}

fn amount_issue_eq(a: &Amount, b: &Amount) -> bool {
    match (a, b) {
        (Amount::Xrp(_), Amount::Xrp(_)) => true,
        (
            Amount::Iou {
                currency: ac,
                issuer: ai,
                ..
            },
            Amount::Iou {
                currency: bc,
                issuer: bi,
                ..
            },
        ) => ac == bc && ai == bi,
        (Amount::Mpt(a), Amount::Mpt(b)) => a.get(8..32) == b.get(8..32),
        _ => false,
    }
}

fn amount_ge(a: &Amount, b: &Amount) -> bool {
    if !amount_issue_eq(a, b) {
        return false;
    }
    match (a, b) {
        (Amount::Xrp(a), Amount::Xrp(b)) => a >= b,
        (Amount::Iou { value: a, .. }, Amount::Iou { value: b, .. }) => a.to_f64() >= b.to_f64(),
        _ => false,
    }
}

fn amount_gt(a: &Amount, b: &Amount) -> bool {
    if !amount_issue_eq(a, b) {
        return false;
    }
    match (a, b) {
        (Amount::Xrp(a), Amount::Xrp(b)) => a > b,
        (Amount::Iou { value: a, .. }, Amount::Iou { value: b, .. }) => a.to_f64() > b.to_f64(),
        _ => false,
    }
}

fn amount_sub(a: &Amount, b: &Amount) -> Option<Amount> {
    if !amount_issue_eq(a, b) {
        return None;
    }
    match (a, b) {
        (Amount::Xrp(a), Amount::Xrp(b)) => a.checked_sub(*b).map(Amount::Xrp),
        (
            Amount::Iou {
                value: a,
                currency,
                issuer,
            },
            Amount::Iou { value: b, .. },
        ) => Some(Amount::Iou {
            value: IouValue::from_f64(a.to_f64() - b.to_f64()),
            currency: currency.clone(),
            issuer: *issuer,
        }),
        _ => None,
    }
}

fn nft_transfer_fee_cut(amount: &Amount, fee: u16) -> Amount {
    match amount {
        Amount::Xrp(drops) => Amount::Xrp((*drops as u128 * fee as u128 / 100_000u128) as u64),
        Amount::Iou {
            value,
            currency,
            issuer,
        } => Amount::Iou {
            value: value.mul_round(&nft_transfer_fee_rate(fee), false),
            currency: currency.clone(),
            issuer: *issuer,
        },
        Amount::Mpt(raw) => Amount::Mpt(raw.clone()),
    }
}

fn nft_transfer_fee_rate(fee: u16) -> IouValue {
    let mut value = IouValue {
        mantissa: fee as i64,
        exponent: -5,
    };
    value.normalize();
    value
}

fn amount_is_negative(amount: &Amount) -> bool {
    matches!(amount, Amount::Iou { value, .. } if value.is_negative())
}

fn load_trustline_for_nft(
    state: &mut LedgerState,
    holder: &[u8; 20],
    issuer: &[u8; 20],
    currency: &crate::transaction::amount::Currency,
) -> Option<crate::ledger::RippleState> {
    let key = crate::ledger::trustline::shamap_key(holder, issuer, currency);
    if let Some(line) = state.get_trustline(&key) {
        return Some(line.clone());
    }
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    let decoded = crate::ledger::RippleState::decode_from_sle(&raw)?;
    state.hydrate_trustline(decoded.clone());
    Some(decoded)
}

fn trustline_auth_flag_for(issuer: &[u8; 20], holder: &[u8; 20]) -> u32 {
    if issuer > holder {
        crate::ledger::trustline::LSF_HIGH_AUTH
    } else {
        crate::ledger::trustline::LSF_LOW_AUTH
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

fn trustline_has_deep_freeze(line: &crate::ledger::RippleState) -> bool {
    (line.flags
        & (crate::ledger::trustline::LSF_LOW_DEEP_FREEZE
            | crate::ledger::trustline::LSF_HIGH_DEEP_FREEZE))
        != 0
}

fn trustline_limit_for(line: &crate::ledger::RippleState, holder: &[u8; 20]) -> IouValue {
    if holder == &line.low_account {
        line.low_limit
    } else {
        line.high_limit
    }
}

fn check_trustline_authorized(
    state: &mut LedgerState,
    holder: &[u8; 20],
    issuer: &[u8; 20],
    currency: &crate::transaction::amount::Currency,
) -> Result<(), &'static str> {
    let Some(issuer_account) = state.get_account(issuer).cloned() else {
        return Err("tecNO_ISSUER");
    };
    if holder == issuer {
        return Ok(());
    }
    if (issuer_account.flags & crate::ledger::account::LSF_REQUIRE_AUTH) == 0 {
        return Ok(());
    }
    let Some(line) = load_trustline_for_nft(state, holder, issuer, currency) else {
        return Err("tecNO_LINE");
    };
    if (line.flags & trustline_auth_flag_for(issuer, holder)) == 0 {
        return Err("tecNO_AUTH");
    }
    Ok(())
}

fn check_trustline_deep_frozen(
    state: &mut LedgerState,
    holder: &[u8; 20],
    issuer: &[u8; 20],
    currency: &crate::transaction::amount::Currency,
) -> Result<(), &'static str> {
    if state.get_account(issuer).is_none() {
        return Err("tecNO_ISSUER");
    }
    if holder == issuer {
        return Ok(());
    }
    if let Some(line) = load_trustline_for_nft(state, holder, issuer, currency) {
        if trustline_has_deep_freeze(&line) {
            return Err("tecFROZEN");
        }
    }
    Ok(())
}

fn can_fund_amount(state: &mut LedgerState, account: &[u8; 20], amount: &Amount) -> bool {
    if amount_is_zero(amount) {
        return true;
    }
    match amount {
        Amount::Xrp(drops) => state
            .get_account(account)
            .map(|acct| acct.balance >= *drops)
            .unwrap_or(false),
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            if account == issuer {
                return true;
            }
            if state
                .get_account(issuer)
                .map(|issuer_acct| {
                    (issuer_acct.flags & crate::ledger::account::LSF_GLOBAL_FREEZE) != 0
                })
                .unwrap_or(true)
            {
                return false;
            }
            let Some(line) = load_trustline_for_nft(state, account, issuer, currency) else {
                return false;
            };
            if trustline_frozen_by_issuer(&line, issuer) || trustline_has_deep_freeze(&line) {
                return false;
            }
            super::flow::compare_iou_values(&line.balance_for(account), value)
                != std::cmp::Ordering::Less
        }
        Amount::Mpt(_) => super::mptoken::can_debit_mpt_amount(state, account, amount),
    }
}

fn check_iou_receiver(
    state: &mut LedgerState,
    account: &[u8; 20],
    amount: &Amount,
) -> Result<(), &'static str> {
    match amount {
        Amount::Xrp(_) => {
            if state.get_account(account).is_some() {
                Ok(())
            } else {
                Err("tecNO_DST")
            }
        }
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            check_trustline_authorized(state, account, issuer, currency)?;
            check_trustline_deep_frozen(state, account, issuer, currency)?;
            if account == issuer {
                return Ok(());
            }
            let Some(line) = load_trustline_for_nft(state, account, issuer, currency) else {
                return Ok(());
            };
            if trustline_frozen_by_issuer(&line, issuer) {
                return Err("tecFROZEN");
            }
            let spendable = trustline_limit_for(&line, account).sub(&line.balance_for(account));
            if super::flow::compare_iou_values(&spendable, value) == std::cmp::Ordering::Less {
                return Err("tecNO_LINE");
            }
            Ok(())
        }
        Amount::Mpt(_) => Ok(()),
    }
}

fn check_transfer_fee_receiver(
    state: &mut LedgerState,
    nft: &crate::ledger::NFToken,
    amount: &Amount,
) -> Result<(), &'static str> {
    let Amount::Iou {
        currency, issuer, ..
    } = amount
    else {
        return Ok(());
    };
    if nft.transfer_fee == 0 {
        return Ok(());
    }
    if state.get_account(&nft.issuer).is_none() {
        return Err("tecNO_ISSUER");
    }
    if nft.issuer != *issuer {
        let Some(line) = load_trustline_for_nft(state, &nft.issuer, issuer, currency) else {
            return Err("tecNO_LINE");
        };
        if trustline_frozen_by_issuer(&line, issuer) || trustline_has_deep_freeze(&line) {
            return Err("tecFROZEN");
        }
    }
    check_trustline_authorized(state, &nft.issuer, issuer, currency)?;
    check_trustline_deep_frozen(state, &nft.issuer, issuer, currency)?;
    Ok(())
}

fn pay_amount(
    state: &mut LedgerState,
    from: &[u8; 20],
    to: &[u8; 20],
    amount: &Amount,
) -> ApplyResult {
    if amount_is_zero(amount) {
        return ApplyResult::Success;
    }
    let debit = transfer_rate_gross_debit_amount(state, from, to, amount);
    if !apply_amount_delta(state, from, AssetDelta::Debit, &debit) {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
    }
    if !apply_amount_delta(state, to, AssetDelta::Credit, amount) {
        return ApplyResult::ClaimedCost("tecFAILED_PROCESSING");
    }
    ApplyResult::Success
}

fn remove_consumed_offer(
    state: &mut LedgerState,
    key: &crate::ledger::Key,
    offer: &crate::ledger::NFTokenOffer,
) {
    remove_nft_offer_directories(state, key, offer);
    state.remove_nft_offer(key);
    if let Some(acct) = state.get_account(&offer.account) {
        let mut acct = acct.clone();
        acct.owner_count = acct.owner_count.saturating_sub(1);
        state.insert_account(acct);
    }
}

fn owner_count_after_page_delta(
    owner_count: u32,
    page_count_before: usize,
    page_count_after: usize,
) -> u32 {
    match page_count_after.cmp(&page_count_before) {
        std::cmp::Ordering::Greater => {
            owner_count.saturating_add((page_count_after - page_count_before) as u32)
        }
        std::cmp::Ordering::Less => {
            owner_count.saturating_sub((page_count_before - page_count_after) as u32)
        }
        std::cmp::Ordering::Equal => owner_count,
    }
}

fn apply_nft_page_owner_count_delta(
    state: &mut LedgerState,
    owner: &[u8; 20],
    page_count_before: usize,
    page_count_after: usize,
) {
    if page_count_before == page_count_after {
        return;
    }
    if let Some(account) = state.get_account(owner) {
        let mut account = account.clone();
        account.owner_count =
            owner_count_after_page_delta(account.owner_count, page_count_before, page_count_after);
        state.insert_account(account);
    }
}

fn transfer_nft_owner(
    state: &mut LedgerState,
    nft: &crate::ledger::NFToken,
    buyer: &[u8; 20],
) -> Result<(), &'static str> {
    let uri = nft.uri.clone();
    let old_owner_page_count_before = state.nft_page_count(&nft.owner);
    let new_owner_page_count_before = state.nft_page_count(buyer);
    state.remove_nftoken_paged(&nft.owner, &nft.nftoken_id);
    let old_owner_page_count_after = state.nft_page_count(&nft.owner);
    state.insert_nftoken_paged(buyer, nft.nftoken_id, uri)?;
    let new_owner_page_count_after = state.nft_page_count(buyer);

    apply_nft_page_owner_count_delta(
        state,
        &nft.owner,
        old_owner_page_count_before,
        old_owner_page_count_after,
    );
    apply_nft_page_owner_count_delta(
        state,
        buyer,
        new_owner_page_count_before,
        new_owner_page_count_after,
    );
    Ok(())
}

fn check_buyer_reserve_after_transfer(
    state: &LedgerState,
    buyer: &[u8; 20],
    owner_count_before: u32,
) -> ApplyResult {
    let Some(account) = state.get_account(buyer) else {
        return ApplyResult::ClaimedCost("tecINTERNAL");
    };
    if account.owner_count > owner_count_before {
        let fees = crate::ledger::fees::Fees::default();
        let reserve = fees.reserve_base + account.owner_count as u64 * fees.reserve_inc;
        if account.balance < reserve {
            return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
        }
    }
    ApplyResult::Success
}

fn offer_is_expired(offer: &crate::ledger::NFTokenOffer, close_time: u64) -> bool {
    offer
        .expiration
        .is_some_and(|expiration| (close_time as u32) >= expiration)
}

fn delete_expired_accept_offers(
    state: &mut LedgerState,
    buy: Option<(&crate::ledger::Key, &crate::ledger::NFTokenOffer)>,
    sell: Option<(&crate::ledger::Key, &crate::ledger::NFTokenOffer)>,
    close_time: u64,
) -> bool {
    let mut found_expired = false;
    if let Some((key, offer)) = buy {
        if offer_is_expired(offer, close_time) {
            remove_consumed_offer(state, key, offer);
            found_expired = true;
        }
    }
    if let Some((key, offer)) = sell {
        if offer_is_expired(offer, close_time) {
            remove_consumed_offer(state, key, offer);
            found_expired = true;
        }
    }
    found_expired
}

fn check_nft_payment_preclaim(
    state: &mut LedgerState,
    payer: &[u8; 20],
    receiver: Option<&[u8; 20]>,
    amount: &Amount,
) -> ApplyResult {
    if amount_is_negative(amount) {
        return ApplyResult::ClaimedCost("temBAD_OFFER");
    }
    if !can_fund_amount(state, payer, amount) {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
    }
    if let Some(receiver) = receiver {
        if let Err(code) = check_iou_receiver(state, receiver, amount) {
            return ApplyResult::ClaimedCost(code);
        }
    }
    ApplyResult::Success
}

fn settle_nft_sale(
    state: &mut LedgerState,
    buyer: &[u8; 20],
    seller: &[u8; 20],
    nft: &crate::ledger::NFToken,
    amount: &Amount,
) -> ApplyResult {
    let mut seller_amount = amount.clone();
    if nft.transfer_fee != 0 && buyer != &nft.issuer && seller != &nft.issuer {
        let cut = nft_transfer_fee_cut(amount, nft.transfer_fee);
        if !amount_is_zero(&cut) {
            if let ApplyResult::ClaimedCost(code) = pay_amount(state, buyer, &nft.issuer, &cut) {
                return ApplyResult::ClaimedCost(code);
            }
            if let Some(remaining) = amount_sub(&seller_amount, &cut) {
                seller_amount = remaining;
            }
        }
    }
    pay_amount(state, buyer, seller, &seller_amount)
}

pub(crate) fn apply_nftoken_burn(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    let nftoken_id = match tx.nftoken_id {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let page_owner = tx.owner.unwrap_or(tx.account);
    let nft = match load_nftoken_for_owner(state, &page_owner, &nftoken_id) {
        Some(n) => n.clone(),
        None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
    };

    // The holder may always burn. The issuer may burn non-held tokens only
    // when the token's immutable ID flags include tfBurnable.
    let is_owner = tx.account == nft.owner;
    let is_issuer = tx.account == nft.issuer;
    if !is_owner && !(is_issuer && nft.flags & crate::ledger::nftoken::TF_BURNABLE != 0) {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    let owner_page_count_before = state.nft_page_count(&nft.owner);

    let mut sell_offer_keys: Vec<crate::ledger::Key> = state
        .iter_nft_offers()
        .filter(|(_, o)| o.nftoken_id == nftoken_id && o.is_sell())
        .map(|(k, _)| *k)
        .collect();
    let mut buy_offer_keys: Vec<crate::ledger::Key> = state
        .iter_nft_offers()
        .filter(|(_, o)| o.nftoken_id == nftoken_id && !o.is_sell())
        .map(|(k, _)| *k)
        .collect();
    sell_offer_keys.sort_by(|a, b| a.0.cmp(&b.0));
    buy_offer_keys.sort_by(|a, b| a.0.cmp(&b.0));

    for k in sell_offer_keys
        .iter()
        .chain(buy_offer_keys.iter())
        .take(500)
    {
        if let Some(off) = state.remove_nft_offer(k) {
            remove_nft_offer_directories(state, k, &off);
            if let Some(acct) = state.get_account(&off.account) {
                let mut acct = acct.clone();
                acct.owner_count = acct.owner_count.saturating_sub(1);
                state.insert_account(acct);
            }
        }
    }

    // Remove via page-based store (also removes from flat store)
    state.remove_nftoken_paged(&nft.owner, &nftoken_id);
    let owner_page_count_after = state.nft_page_count(&nft.owner);
    apply_nft_page_owner_count_delta(
        state,
        &nft.owner,
        owner_page_count_before,
        owner_page_count_after,
    );

    if let Some(issuer) = state.get_account(&nft.issuer) {
        let mut issuer = issuer.clone();
        issuer.burned_nftokens = issuer.burned_nftokens.saturating_add(1);
        state.insert_account(issuer);
    }

    ApplyResult::Success
}

/// Apply NFTokenCancelOffer: remove one or more NFToken offers from the ledger.
pub(crate) fn apply_nftoken_cancel_offer(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    let mut removed_any = false;

    for offer_hash in [tx.nft_sell_offer, tx.nft_buy_offer].iter().flatten() {
        let key = crate::ledger::Key(*offer_hash);
        if let Some(offer) = state.remove_nft_offer(&key) {
            remove_nft_offer_directories(state, &key, &offer);
            if let Some(owner_acct) = state.get_account(&offer.account) {
                let mut owner_acct = owner_acct.clone();
                owner_acct.owner_count = owner_acct.owner_count.saturating_sub(1);
                state.insert_account(owner_acct);
            }
            removed_any = true;
        }
    }

    if !removed_any {
        tracing::trace!(
            "NFTokenCancelOffer: no offers found via parsed fields, metadata will handle"
        );
    }

    ApplyResult::Success
}

pub(crate) fn apply_nftoken_create_offer(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let sequence = super::sequence_proxy(tx);
    let nftoken_id = match tx.nftoken_id {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let is_sell = (tx.flags & 0x0001) != 0;
    let expected_owner = if is_sell {
        tx.account
    } else {
        match tx.owner {
            Some(owner) => owner,
            None => return ApplyResult::ClaimedCost("temMALFORMED"),
        }
    };
    let nft = match load_nftoken_for_tx(state, &nftoken_id) {
        Some(nft) => nft,
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    if nft.owner != expected_owner {
        return ApplyResult::ClaimedCost("tecNO_ENTRY");
    }

    // Destination offers require the destination account to exist.
    // Without this guard, validated-replay parity breaks on tecNO_DST:
    // the local engine would create an offer that rippled only charged a fee for.
    if let Some(destination) = tx.destination {
        if state.get_account(&destination).is_none() {
            return ApplyResult::ClaimedCost("tecNO_DST");
        }
    }

    let amount = tx.amount.clone().unwrap_or(Amount::Xrp(0));

    // Reserve check: account must afford the new owner object.
    // rippled returns tecINSUFFICIENT_RESERVE if insufficient.
    let fees = crate::ledger::fees::Fees::default();
    let required = fees.reserve_base + ((new_sender.owner_count as u64 + 1) * fees.reserve_inc);
    if new_sender.balance < required {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
    }

    let offer_key = crate::ledger::nftoken::offer_shamap_key(&tx.account, sequence);
    let owner_node = directory::dir_add(state, &tx.account, offer_key.0);
    let (_, nft_offer_node) =
        directory::dir_add_nft_offer(state, &nftoken_id, is_sell, offer_key.0);
    let offer = crate::ledger::NFTokenOffer {
        account: tx.account,
        sequence,
        nftoken_id,
        amount,
        destination: tx.destination,
        expiration: tx.expiration,
        flags: tx.flags,
        owner_node,
        nft_offer_node,
        previous_txn_id: [0u8; 32],
        previous_txn_lgrseq: 0,
        raw_sle: None,
    };

    state.insert_nft_offer(offer);
    new_sender.owner_count += 1;

    ApplyResult::Success
}

fn load_nft_offer_for_tx(
    state: &mut LedgerState,
    key: &crate::ledger::Key,
) -> Option<crate::ledger::NFTokenOffer> {
    if let Some(offer) = state.get_nft_offer(key) {
        return Some(offer.clone());
    }

    let raw = state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))?;
    let offer = crate::ledger::NFTokenOffer::decode_from_sle(&raw)?;
    state.hydrate_nft_offer(offer.clone());
    Some(offer)
}

fn load_nftoken_for_owner(
    state: &LedgerState,
    owner: &[u8; 20],
    id: &[u8; 32],
) -> Option<crate::ledger::NFToken> {
    let page_token = state.get_nftoken_from_owner_pages(owner, id)?;
    let flags = u16::from_be_bytes([id[0], id[1]]);
    let transfer_fee = u16::from_be_bytes([id[2], id[3]]);
    let mut issuer = [0u8; 20];
    issuer.copy_from_slice(&id[4..24]);

    Some(crate::ledger::NFToken {
        nftoken_id: *id,
        owner: *owner,
        issuer,
        uri: page_token.uri.clone(),
        flags,
        transfer_fee,
        taxon: 0,
    })
}

fn load_nftoken_for_tx(state: &LedgerState, id: &[u8; 32]) -> Option<crate::ledger::NFToken> {
    if let Some(nft) = state.get_nftoken(id) {
        return Some(nft.clone());
    }

    let page_token = state.get_nftoken_from_pages(id)?;
    let owner = state.nftoken_page_owner(id)?;
    let flags = u16::from_be_bytes([id[0], id[1]]);
    let transfer_fee = u16::from_be_bytes([id[2], id[3]]);
    let mut issuer = [0u8; 20];
    issuer.copy_from_slice(&id[4..24]);

    Some(crate::ledger::NFToken {
        nftoken_id: *id,
        owner,
        issuer,
        uri: page_token.uri.clone(),
        flags,
        transfer_fee,
        taxon: 0,
    })
}

pub(crate) fn apply_nftoken_accept_offer(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    if tx.nft_buy_offer.is_none() && tx.nft_sell_offer.is_none() {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    if tx.nftoken_broker_fee.is_some()
        && (tx.nft_buy_offer.is_none() || tx.nft_sell_offer.is_none())
    {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    let buy_loaded = tx.nft_buy_offer.map(|hash| {
        let key = crate::ledger::Key(hash);
        load_nft_offer_for_tx(state, &key).map(|offer| (key, offer))
    });
    let sell_loaded = tx.nft_sell_offer.map(|hash| {
        let key = crate::ledger::Key(hash);
        load_nft_offer_for_tx(state, &key).map(|offer| (key, offer))
    });
    let buy = match buy_loaded {
        Some(Some(pair)) => Some(pair),
        Some(None) => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
        None => None,
    };
    let sell = match sell_loaded {
        Some(Some(pair)) => Some(pair),
        Some(None) => return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND"),
        None => None,
    };

    if let Some((_, offer)) = &buy {
        if offer.is_sell() {
            return ApplyResult::ClaimedCost("tecNFTOKEN_OFFER_TYPE_MISMATCH");
        }
        if offer.account == tx.account {
            return ApplyResult::ClaimedCost("tecCANT_ACCEPT_OWN_NFTOKEN_OFFER");
        }
    }
    if let Some((_, offer)) = &sell {
        if !offer.is_sell() {
            return ApplyResult::ClaimedCost("tecNFTOKEN_OFFER_TYPE_MISMATCH");
        }
        if offer.account == tx.account {
            return ApplyResult::ClaimedCost("tecCANT_ACCEPT_OWN_NFTOKEN_OFFER");
        }
    }

    match (buy, sell) {
        (Some((buy_key, buy)), Some((sell_key, sell))) => {
            if buy.nftoken_id != sell.nftoken_id || !amount_issue_eq(&buy.amount, &sell.amount) {
                return ApplyResult::ClaimedCost("tecNFTOKEN_BUY_SELL_MISMATCH");
            }
            if buy.account == sell.account {
                return ApplyResult::ClaimedCost("tecCANT_ACCEPT_OWN_NFTOKEN_OFFER");
            }
            if !amount_ge(&buy.amount, &sell.amount) {
                return ApplyResult::ClaimedCost("tecINSUFFICIENT_PAYMENT");
            }
            if buy.destination.is_some_and(|dest| dest != tx.account)
                || sell.destination.is_some_and(|dest| dest != tx.account)
            {
                return ApplyResult::ClaimedCost("tecNO_PERMISSION");
            }
            let broker_fee = tx.nftoken_broker_fee.clone().unwrap_or(Amount::Xrp(0));
            if !amount_is_zero(&broker_fee) && !amount_issue_eq(&broker_fee, &buy.amount) {
                return ApplyResult::ClaimedCost("tecNFTOKEN_BUY_SELL_MISMATCH");
            }
            if !amount_is_zero(&broker_fee) && !amount_gt(&buy.amount, &broker_fee) {
                return ApplyResult::ClaimedCost("tecINSUFFICIENT_PAYMENT");
            }
            let after_broker =
                amount_sub(&buy.amount, &broker_fee).unwrap_or_else(|| Amount::Xrp(0));
            if !amount_ge(&after_broker, &sell.amount) {
                return ApplyResult::ClaimedCost("tecINSUFFICIENT_PAYMENT");
            }
            let nft = match load_nftoken_for_tx(state, &sell.nftoken_id) {
                Some(nft) => nft,
                None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
            };
            if nft.owner != sell.account {
                return ApplyResult::ClaimedCost("tecNO_PERMISSION");
            }
            if !state.can_insert_nftoken_paged(&buy.account, &nft.nftoken_id) {
                return ApplyResult::ClaimedCost("tecNO_SUITABLE_NFTOKEN_PAGE");
            }
            if let ApplyResult::ClaimedCost(code) =
                check_nft_payment_preclaim(state, &buy.account, None, &buy.amount)
            {
                return ApplyResult::ClaimedCost(code);
            }
            if let Err(code) = check_iou_receiver(state, &buy.account, &buy.amount) {
                return ApplyResult::ClaimedCost(code);
            }
            if let Err(code) = check_iou_receiver(state, &sell.account, &sell.amount) {
                return ApplyResult::ClaimedCost(code);
            }
            if let Err(code) = check_transfer_fee_receiver(state, &nft, &after_broker) {
                return ApplyResult::ClaimedCost(code);
            }
            if !amount_is_zero(&broker_fee) {
                if let Err(code) = check_iou_receiver(state, &tx.account, &broker_fee) {
                    return ApplyResult::ClaimedCost(code);
                }
            }
            if delete_expired_accept_offers(
                state,
                Some((&buy_key, &buy)),
                Some((&sell_key, &sell)),
                close_time,
            ) {
                return ApplyResult::ClaimedCost("tecEXPIRED");
            }

            let buyer_owner_count_before = state
                .get_account(&buy.account)
                .map(|acct| acct.owner_count)
                .unwrap_or(0);
            remove_consumed_offer(state, &buy_key, &buy);
            remove_consumed_offer(state, &sell_key, &sell);
            if let ApplyResult::ClaimedCost(code) =
                pay_amount(state, &buy.account, &tx.account, &broker_fee)
            {
                return ApplyResult::ClaimedCost(code);
            }
            if let ApplyResult::ClaimedCost(code) =
                settle_nft_sale(state, &buy.account, &sell.account, &nft, &after_broker)
            {
                return ApplyResult::ClaimedCost(code);
            }
            if let Err(code) = transfer_nft_owner(state, &nft, &buy.account) {
                return ApplyResult::ClaimedCost(code);
            }
            if let ApplyResult::ClaimedCost(code) =
                check_buyer_reserve_after_transfer(state, &buy.account, buyer_owner_count_before)
            {
                return ApplyResult::ClaimedCost(code);
            }
            ApplyResult::Success
        }
        (None, Some((sell_key, sell))) => {
            if sell.destination.is_some_and(|dest| dest != tx.account) {
                return ApplyResult::ClaimedCost("tecNO_PERMISSION");
            }
            let nft = match load_nftoken_for_tx(state, &sell.nftoken_id) {
                Some(nft) => nft,
                None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
            };
            if nft.owner != sell.account {
                return ApplyResult::ClaimedCost("tecNO_PERMISSION");
            }
            if !state.can_insert_nftoken_paged(&tx.account, &nft.nftoken_id) {
                return ApplyResult::ClaimedCost("tecNO_SUITABLE_NFTOKEN_PAGE");
            }
            if let ApplyResult::ClaimedCost(code) =
                check_nft_payment_preclaim(state, &tx.account, Some(&sell.account), &sell.amount)
            {
                return ApplyResult::ClaimedCost(code);
            }
            if let Err(code) = check_iou_receiver(state, &tx.account, &sell.amount) {
                return ApplyResult::ClaimedCost(code);
            }
            if let Err(code) = check_transfer_fee_receiver(state, &nft, &sell.amount) {
                return ApplyResult::ClaimedCost(code);
            }
            if delete_expired_accept_offers(state, None, Some((&sell_key, &sell)), close_time) {
                return ApplyResult::ClaimedCost("tecEXPIRED");
            }

            let buyer_owner_count_before = state
                .get_account(&tx.account)
                .map(|acct| acct.owner_count)
                .unwrap_or(0);
            remove_consumed_offer(state, &sell_key, &sell);
            if let ApplyResult::ClaimedCost(code) =
                settle_nft_sale(state, &tx.account, &sell.account, &nft, &sell.amount)
            {
                return ApplyResult::ClaimedCost(code);
            }
            if let Err(code) = transfer_nft_owner(state, &nft, &tx.account) {
                return ApplyResult::ClaimedCost(code);
            }
            if let ApplyResult::ClaimedCost(code) =
                check_buyer_reserve_after_transfer(state, &tx.account, buyer_owner_count_before)
            {
                return ApplyResult::ClaimedCost(code);
            }
            ApplyResult::Success
        }
        (Some((buy_key, buy)), None) => {
            if buy.destination.is_some_and(|dest| dest != tx.account) {
                return ApplyResult::ClaimedCost("tecNO_PERMISSION");
            }
            let nft = match load_nftoken_for_tx(state, &buy.nftoken_id) {
                Some(nft) => nft,
                None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
            };
            if tx.account != nft.owner {
                return ApplyResult::ClaimedCost("tecNO_PERMISSION");
            }
            if !state.can_insert_nftoken_paged(&buy.account, &nft.nftoken_id) {
                return ApplyResult::ClaimedCost("tecNO_SUITABLE_NFTOKEN_PAGE");
            }
            if let ApplyResult::ClaimedCost(code) =
                check_nft_payment_preclaim(state, &buy.account, Some(&tx.account), &buy.amount)
            {
                return ApplyResult::ClaimedCost(code);
            }
            if let Err(code) = check_iou_receiver(state, &buy.account, &buy.amount) {
                return ApplyResult::ClaimedCost(code);
            }
            if let Err(code) = check_transfer_fee_receiver(state, &nft, &buy.amount) {
                return ApplyResult::ClaimedCost(code);
            }
            if delete_expired_accept_offers(state, Some((&buy_key, &buy)), None, close_time) {
                return ApplyResult::ClaimedCost("tecEXPIRED");
            }

            let buyer_owner_count_before = state
                .get_account(&buy.account)
                .map(|acct| acct.owner_count)
                .unwrap_or(0);
            remove_consumed_offer(state, &buy_key, &buy);
            if let ApplyResult::ClaimedCost(code) =
                settle_nft_sale(state, &buy.account, &tx.account, &nft, &buy.amount)
            {
                return ApplyResult::ClaimedCost(code);
            }
            if let Err(code) = transfer_nft_owner(state, &nft, &buy.account) {
                return ApplyResult::ClaimedCost(code);
            }
            if let ApplyResult::ClaimedCost(code) =
                check_buyer_reserve_after_transfer(state, &buy.account, buyer_owner_count_before)
            {
                return ApplyResult::ClaimedCost(code);
            }
            ApplyResult::Success
        }
        (None, None) => ApplyResult::ClaimedCost("temMALFORMED"),
    }
}
