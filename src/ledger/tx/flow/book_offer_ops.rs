//! Reusable offer lifecycle helpers for BookStep work.
//!
//! These helpers are intentionally small and side-effect free for now. OfferCreate
//! still owns live directory mutation until BookStep planning/apply tests prove the
//! shared path.

use super::offer_math::{ceil_in_strict_via_quality, ceil_out_strict_via_quality, compare_amounts};
use crate::ledger::offer::{
    amount_exponent, amount_is_zero, amount_to_i128, scale_amount, subtract_amount,
};
use crate::ledger::{directory, Key, LedgerState, Offer};
use crate::transaction::amount::Amount;

#[derive(Debug, Clone)]
pub(crate) struct OfferDeleteResult {
    pub(crate) offer: Offer,
    pub(crate) owner_removed: bool,
    pub(crate) book_removed: bool,
    pub(crate) additional_books_removed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OfferFillQuote {
    pub(crate) input: Amount,
    pub(crate) output: Amount,
}

pub(crate) fn quote_offer_for_desired_output(
    offer: &Offer,
    desired_output: &Amount,
    round_input_up: bool,
) -> Option<OfferFillQuote> {
    let (input, output) = ceil_out_strict_via_quality(
        &offer.taker_pays,
        &offer.taker_gets,
        desired_output,
        &offer.book_directory,
        round_input_up,
    );
    if amount_is_zero(&input) || amount_is_zero(&output) {
        return None;
    }
    Some(OfferFillQuote { input, output })
}

pub(crate) fn quote_offer_for_input_limit(
    offer: &Offer,
    input_limit: &Amount,
    round_output_up: bool,
) -> Option<OfferFillQuote> {
    let (input, output) = ceil_in_strict_via_quality(
        &offer.taker_pays,
        &offer.taker_gets,
        input_limit,
        &offer.book_directory,
        round_output_up,
    );
    if amount_is_zero(&input) || amount_is_zero(&output) {
        return None;
    }
    Some(OfferFillQuote { input, output })
}

pub(crate) fn quote_offer_create_crossing_fill(
    offer: &Offer,
    remaining_output: &Amount,
    taker_input_funds: &Amount,
    maker_output_funds: &Amount,
    is_sell: bool,
) -> Option<OfferFillQuote> {
    let wanted_output = amount_to_i128(remaining_output);
    let offer_output = amount_to_i128(&offer.taker_gets);
    let funded_input = amount_to_i128(taker_input_funds);
    let offer_input = amount_to_i128(&offer.taker_pays);

    if wanted_output <= 0 || offer_output <= 0 || funded_input <= 0 || offer_input <= 0 {
        return None;
    }

    let receive_ratio = normalize_ratio(
        wanted_output,
        amount_exponent(remaining_output),
        offer_output,
        amount_exponent(&offer.taker_gets),
    );
    let input_ratio = normalize_ratio(
        funded_input,
        amount_exponent(taker_input_funds),
        offer_input,
        amount_exponent(&offer.taker_pays),
    );
    let (mut fill_num, fill_den) = if is_sell {
        input_ratio
    } else {
        min_ratio(receive_ratio, input_ratio)
    };
    if fill_num > fill_den {
        fill_num = fill_den;
    }

    if is_sell {
        let input_limit = if fill_num >= fill_den {
            offer.taker_pays.clone()
        } else {
            scale_amount(&offer.taker_pays, fill_num, fill_den)
        };
        let mut quote = quote_offer_for_input_limit(offer, &input_limit, false)?;
        if compare_amounts(&quote.output, maker_output_funds) == std::cmp::Ordering::Greater {
            quote = quote_offer_for_desired_output(offer, maker_output_funds, true)?;
        }
        return Some(quote);
    }

    let max_offer_output =
        if compare_amounts(maker_output_funds, &offer.taker_gets) == std::cmp::Ordering::Less {
            maker_output_funds.clone()
        } else {
            offer.taker_gets.clone()
        };
    let desired_output =
        if compare_amounts(remaining_output, &max_offer_output) == std::cmp::Ordering::Greater {
            max_offer_output
        } else {
            remaining_output.clone()
        };
    let quote = quote_offer_for_desired_output(offer, &desired_output, true)?;
    if compare_amounts(&quote.input, taker_input_funds) != std::cmp::Ordering::Greater {
        Some(quote)
    } else {
        quote_offer_for_input_limit(offer, taker_input_funds, false)
    }
}

pub(crate) fn offer_fully_consumed_by_output(
    offer: &Offer,
    filled_output: &Amount,
    funded_output: &Amount,
) -> bool {
    compare_amounts(filled_output, &offer.taker_gets) != std::cmp::Ordering::Less
        || compare_amounts(filled_output, funded_output) != std::cmp::Ordering::Less
}

pub(crate) fn rewrite_partial_offer_after_output_fill(
    offer: &Offer,
    filled_output: &Amount,
) -> Option<Offer> {
    let new_gets = subtract_amount(&offer.taker_gets, filled_output);
    let (new_pays, _) = ceil_out_strict_via_quality(
        &offer.taker_pays,
        &offer.taker_gets,
        &new_gets,
        &offer.book_directory,
        true,
    );

    if amount_is_zero(&new_gets) || amount_is_zero(&new_pays) {
        return None;
    }

    let mut updated = offer.clone();
    updated.taker_gets = new_gets;
    updated.taker_pays = new_pays;
    updated.raw_sle = None;
    Some(updated)
}

pub(crate) fn offer_has_zero_amount(offer: &Offer) -> bool {
    amount_is_zero(&offer.taker_pays) || amount_is_zero(&offer.taker_gets)
}

pub(crate) fn offer_should_remove_tiny_reduced_quality(
    offer: &Offer,
    owner_funds: &Amount,
) -> bool {
    let in_is_xrp = matches!(offer.taker_pays, Amount::Xrp(_));
    let out_is_xrp = matches!(offer.taker_gets, Amount::Xrp(_));

    if out_is_xrp {
        return false;
    }
    if !in_is_xrp
        && compare_amounts(&offer.taker_pays, &offer.taker_gets) != std::cmp::Ordering::Less
    {
        return false;
    }

    let (effective_in, effective_out) = match &offer.taker_gets {
        Amount::Iou { issuer, .. } if offer.account != *issuer => {
            if compare_amounts(owner_funds, &offer.taker_gets) == std::cmp::Ordering::Less {
                let Some(quote) = quote_offer_for_desired_output(offer, owner_funds, false) else {
                    return true;
                };
                (quote.input, quote.output)
            } else {
                (offer.taker_pays.clone(), offer.taker_gets.clone())
            }
        }
        _ => (offer.taker_pays.clone(), offer.taker_gets.clone()),
    };

    if amount_is_zero(&effective_in) || amount_is_zero(&effective_out) {
        return true;
    }
    if amount_gt_min_positive(&effective_in) {
        return false;
    }

    let effective_quality = directory::offer_quality(&effective_out, &effective_in);
    effective_quality < stored_offer_quality(offer)
}

fn amount_gt_min_positive(amount: &Amount) -> bool {
    match amount {
        Amount::Xrp(drops) => *drops > 1,
        Amount::Iou { value, .. } => value.mantissa > 1_000_000_000_000_000 || value.exponent > -96,
        Amount::Mpt(_) => false,
    }
}

fn stored_offer_quality(offer: &Offer) -> u64 {
    if offer.book_directory != [0u8; 32] {
        let mut q = [0u8; 8];
        q.copy_from_slice(&offer.book_directory[24..32]);
        u64::from_be_bytes(q)
    } else {
        directory::offer_quality(&offer.taker_gets, &offer.taker_pays)
    }
}

/// Remove an offer and all directory references that rippled's `offerDelete`
/// would clear.
///
/// The caller owns `OwnerCount` adjustment because OfferCreate batches several
/// deltas before applying them, while OfferCancel updates immediately.
pub(crate) fn delete_offer_from_dirs(
    state: &mut LedgerState,
    key: &Key,
) -> Option<OfferDeleteResult> {
    hydrate_offer_if_needed(state, key);
    let offer = state.remove_offer(key)?;
    let offer_key = crate::ledger::offer::shamap_key(&offer.account, offer.sequence);
    let owner_root = directory::owner_dir_key(&offer.account);
    let owner_removed =
        directory::dir_remove_root_page(state, &owner_root, offer.owner_node, &offer_key.0);

    let mut book_removed = true;
    if offer.book_directory != [0u8; 32] {
        book_removed = directory::dir_remove_root_page(
            state,
            &Key(offer.book_directory),
            offer.book_node,
            &offer_key.0,
        );
    }

    let mut additional_books_removed = 0usize;
    for book_directory in &offer.additional_books {
        if directory::dir_remove_root(state, &Key(*book_directory), &offer_key.0) {
            additional_books_removed += 1;
        }
    }

    Some(OfferDeleteResult {
        offer,
        owner_removed,
        book_removed,
        additional_books_removed,
    })
}

fn hydrate_offer_if_needed(state: &mut LedgerState, key: &Key) {
    if state.get_offer(key).is_some() {
        return;
    }
    let raw = state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key));
    if let Some(raw) = raw {
        if let Some(decoded) = crate::ledger::Offer::decode_from_sle(&raw) {
            state.hydrate_offer(decoded);
        }
    }
}

fn normalize_ratio(num: i128, num_exp: i32, den: i128, den_exp: i32) -> (i128, i128) {
    if den <= 0 || num <= 0 {
        return (0, 1);
    }
    if num_exp == den_exp {
        return (num, den);
    }
    if num_exp > den_exp {
        let shift = (num_exp - den_exp).min(38) as u32;
        (num.saturating_mul(10i128.pow(shift)), den)
    } else {
        let shift = (den_exp - num_exp).min(38) as u32;
        (num, den.saturating_mul(10i128.pow(shift)))
    }
}

fn min_ratio(a: (i128, i128), b: (i128, i128)) -> (i128, i128) {
    let (an, ad) = a;
    let (bn, bd) = b;
    if an <= 0 || ad <= 0 {
        return (0, 1);
    }
    if bn <= 0 || bd <= 0 {
        return (0, 1);
    }
    match an.checked_mul(bd).zip(bn.checked_mul(ad)) {
        Some((lhs, rhs)) => {
            if lhs <= rhs {
                a
            } else {
                b
            }
        }
        None => {
            if an.saturating_mul(bd) <= bn.saturating_mul(ad) {
                a
            } else {
                b
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{directory, AccountRoot, BookKey, LedgerState};
    use crate::transaction::amount::{Currency, IouValue};

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

    fn usd(issuer: [u8; 20], value: f64) -> Amount {
        Amount::Iou {
            value: IouValue::from_f64(value),
            currency: Currency::from_code("USD").unwrap(),
            issuer,
        }
    }

    fn offer(pays: Amount, gets: Amount) -> Offer {
        let book_key = BookKey::from_amounts(&pays, &gets);
        let quality = directory::offer_quality(&gets, &pays);
        let book_directory = directory::book_dir_quality_key(&book_key, quality).0;
        Offer {
            account: [1u8; 20],
            sequence: 7,
            taker_pays: pays,
            taker_gets: gets,
            flags: 0,
            book_directory,
            book_node: 3,
            owner_node: 4,
            expiration: None,
            domain_id: None,
            additional_books: Vec::new(),
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: Some(vec![0xAA]),
        }
    }

    fn standing_offer_with_dirs(
        state: &mut LedgerState,
        account: [u8; 20],
        sequence: u32,
        pays: Amount,
        gets: Amount,
    ) -> Offer {
        let book_key = BookKey::from_amounts(&pays, &gets);
        let quality = directory::offer_quality(&gets, &pays);
        let key = crate::ledger::offer::shamap_key(&account, sequence);
        let owner_node = directory::dir_add(state, &account, key.0);
        let (book_directory, book_node) = directory::dir_add_book(state, &book_key, quality, key.0);
        let offer = Offer {
            account,
            sequence,
            taker_pays: pays,
            taker_gets: gets,
            flags: 0,
            book_directory: book_directory.0,
            book_node,
            owner_node,
            expiration: None,
            domain_id: None,
            additional_books: Vec::new(),
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        state.insert_offer(offer.clone());
        offer
    }

    #[test]
    fn partial_rewrite_preserves_stored_quality_and_metadata() {
        let issuer = [2u8; 20];
        let original = offer(Amount::Xrp(20), usd(issuer, 10.0));
        let updated =
            rewrite_partial_offer_after_output_fill(&original, &usd(issuer, 4.0)).unwrap();

        assert_eq!(updated.sequence, original.sequence);
        assert_eq!(updated.book_directory, original.book_directory);
        assert_eq!(updated.book_node, original.book_node);
        assert_eq!(updated.owner_node, original.owner_node);
        assert!(updated.raw_sle.is_none());
        assert_eq!(updated.taker_gets, usd(issuer, 6.0));
        assert_ne!(updated.taker_pays, original.taker_pays);
    }

    #[test]
    fn partial_rewrite_returns_none_for_zero_remainder() {
        let issuer = [2u8; 20];
        let original = offer(Amount::Xrp(20), usd(issuer, 10.0));

        assert!(rewrite_partial_offer_after_output_fill(&original, &usd(issuer, 10.0)).is_none());
    }

    #[test]
    fn consumed_helper_checks_offer_and_funded_output_caps() {
        let issuer = [2u8; 20];
        let original = offer(Amount::Xrp(20), usd(issuer, 10.0));

        assert!(offer_fully_consumed_by_output(
            &original,
            &usd(issuer, 5.0),
            &usd(issuer, 5.0)
        ));
        assert!(!offer_fully_consumed_by_output(
            &original,
            &usd(issuer, 4.0),
            &usd(issuer, 5.0)
        ));
    }

    #[test]
    fn quote_helpers_use_stored_quality() {
        let issuer = [2u8; 20];
        let original = offer(Amount::Xrp(20), usd(issuer, 10.0));

        let out_quote = quote_offer_for_desired_output(&original, &usd(issuer, 4.0), true).unwrap();
        assert_eq!(out_quote.input, Amount::Xrp(8));
        assert_eq!(out_quote.output, usd(issuer, 4.0));

        let in_quote = quote_offer_for_input_limit(&original, &Amount::Xrp(8), false).unwrap();
        assert_eq!(in_quote.input, Amount::Xrp(8));
        assert_eq!(in_quote.output, usd(issuer, 4.0));
    }

    #[test]
    fn offer_create_quote_caps_non_sell_by_remaining_output() {
        let issuer = [2u8; 20];
        let original = offer(Amount::Xrp(20), usd(issuer, 10.0));

        let quote = quote_offer_create_crossing_fill(
            &original,
            &usd(issuer, 4.0),
            &Amount::Xrp(20),
            &usd(issuer, 10.0),
            false,
        )
        .unwrap();

        assert_eq!(quote.input, Amount::Xrp(8));
        assert_eq!(quote.output, usd(issuer, 4.0));
    }

    #[test]
    fn offer_create_quote_caps_non_sell_by_taker_funds() {
        let issuer = [2u8; 20];
        let original = offer(Amount::Xrp(20), usd(issuer, 10.0));

        let quote = quote_offer_create_crossing_fill(
            &original,
            &usd(issuer, 10.0),
            &Amount::Xrp(8),
            &usd(issuer, 10.0),
            false,
        )
        .unwrap();

        assert_eq!(quote.input, Amount::Xrp(8));
        assert_eq!(quote.output, usd(issuer, 4.0));
    }

    #[test]
    fn offer_create_quote_sell_ignores_receive_floor_inside_quality_gate() {
        let issuer = [2u8; 20];
        let original = offer(Amount::Xrp(20), usd(issuer, 10.0));

        let quote = quote_offer_create_crossing_fill(
            &original,
            &usd(issuer, 1.0),
            &Amount::Xrp(20),
            &usd(issuer, 10.0),
            true,
        )
        .unwrap();

        assert_eq!(quote.input, Amount::Xrp(20));
        assert_eq!(quote.output, usd(issuer, 10.0));
    }

    #[test]
    fn offer_create_quote_sell_caps_by_maker_funds() {
        let issuer = [2u8; 20];
        let original = offer(Amount::Xrp(20), usd(issuer, 10.0));

        let quote = quote_offer_create_crossing_fill(
            &original,
            &usd(issuer, 1.0),
            &Amount::Xrp(20),
            &usd(issuer, 4.0),
            true,
        )
        .unwrap();

        assert_eq!(quote.input, Amount::Xrp(8));
        assert_eq!(quote.output, usd(issuer, 4.0));
    }

    #[test]
    fn delete_offer_from_dirs_removes_offer_and_directory_entries() {
        let owner = [9u8; 20];
        let issuer = [2u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(owner, 1_000));
        let offer =
            standing_offer_with_dirs(&mut state, owner, 3, Amount::Xrp(100), usd(issuer, 10.0));
        let key = offer.key();

        let deleted = delete_offer_from_dirs(&mut state, &key).expect("offer deleted");

        assert_eq!(deleted.offer.sequence, 3);
        assert!(deleted.owner_removed);
        assert!(deleted.book_removed);
        assert!(state.get_offer(&key).is_none());
        assert!(!directory::owner_dir_contains_entry(&state, &owner, &key.0));
    }
}
