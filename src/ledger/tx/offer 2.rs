//! Offer — IMPLEMENTED

use crate::ledger::LedgerState;
use crate::ledger::directory;
use crate::ledger::offer::{amount_exponent, amount_is_zero, amount_to_i128, rate_gte, scale_amount, subtract_amount, BookKey};
use crate::transaction::amount::Amount;
use crate::transaction::ParsedTx;
use super::ApplyResult;

/// Apply an OfferCreate: attempt to cross against the opposite book,
/// then place any unfilled remainder as a standing order.
pub(crate) fn apply_offer_create(
    state:      &mut LedgerState,
    tx:         &ParsedTx,
) -> ApplyResult {
    let mut owner_count_accounts: std::collections::BTreeSet<[u8; 20]> =
        std::collections::BTreeSet::new();
    owner_count_accounts.insert(tx.account);

    let mut remaining_pays = match &tx.taker_pays {
        Some(a) => a.clone(),
        None    => return ApplyResult::ClaimedCost("temBAD_OFFER"),
    };
    let mut remaining_gets = match &tx.taker_gets {
        Some(a) => a.clone(),
        None    => return ApplyResult::ClaimedCost("temBAD_OFFER"),
    };

    let offer_seq = tx.sequence;

    // Validate offer amounts are non-zero
    if amount_is_zero(&remaining_pays) || amount_is_zero(&remaining_gets) {
        return ApplyResult::ClaimedCost("temBAD_OFFER");
    }

    // ── Cross against the opposite book ──────────────────────────────────────
    let opposite_key = BookKey::from_amounts(&remaining_gets, &remaining_pays);
    let book_len = state.get_book(&opposite_key).map(|b| b.len()).unwrap_or(0);
    tracing::info!(
        "offer replay diag: acct={} seq={} opposite_book_len={} tx_type={} flags={}",
        hex::encode_upper(tx.account),
        tx.sequence,
        book_len,
        tx.tx_type,
        tx.flags,
    );

    // Collect crossing offer keys (can't mutate state while iterating)
    let crossing_keys: Vec<crate::ledger::Key> = state.get_book(&opposite_key)
        .map(|book| book.iter_by_quality().cloned().collect())
        .unwrap_or_default();
    tracing::info!(
        "offer replay diag: acct={} seq={} crossing_keys={}",
        hex::encode_upper(tx.account),
        tx.sequence,
        crossing_keys.len(),
    );

    let mut offers_to_remove = Vec::new();
    const MAX_CROSSING_STEPS: usize = 850; // matches rippled
    let mut steps = 0;

    for key in &crossing_keys {
        if steps >= MAX_CROSSING_STEPS { break; }
        steps += 1;
        let book_offer = match state.get_offer(key) {
            Some(o) => o.clone(),
            None    => continue,
        };
        owner_count_accounts.insert(book_offer.account);

        if amount_is_zero(&book_offer.taker_gets) { continue; }
        if amount_is_zero(&remaining_gets) { break; }
        // Don't cross our own offers (rippled: OfferCreate.cpp)
        if book_offer.account == tx.account { continue; }

        if !rate_gte(&book_offer.taker_gets, &book_offer.taker_pays,
                     &remaining_pays, &remaining_gets) {
            break; // not crossing
        }

        let we_want_i   = amount_to_i128(&remaining_pays);
        let they_give_i = amount_to_i128(&book_offer.taker_gets);
        let exp_want = amount_exponent(&remaining_pays);
        let exp_give = amount_exponent(&book_offer.taker_gets);

        if they_give_i <= 0 { continue; }

        // Normalize to same exponent for comparison
        let (want_norm, give_norm) = if exp_want == exp_give {
            (we_want_i, they_give_i)
        } else if exp_want > exp_give {
            let shift = (exp_want - exp_give).min(38) as u32;
            (we_want_i, they_give_i * 10i128.pow(shift))
        } else {
            let shift = (exp_give - exp_want).min(38) as u32;
            (we_want_i * 10i128.pow(shift), they_give_i)
        };

        // Fill ratio: min(want/give, 1)
        let (fill_num, fill_den) = if want_norm <= give_norm {
            (want_norm, give_norm)    // partial consume of book offer
        } else {
            (1i128, 1i128)            // consume entire book offer
        };

        let filled_receive = scale_amount(&book_offer.taker_gets, fill_num, fill_den);
        let filled_pay     = scale_amount(&book_offer.taker_pays, fill_num, fill_den);

        // Transfer assets between the two parties
        transfer_amount(state, &tx.account, true,  &filled_receive);
        transfer_amount(state, &tx.account, false, &filled_pay);
        transfer_amount(state, &book_offer.account, true,  &filled_pay);
        transfer_amount(state, &book_offer.account, false, &filled_receive);

        // Update our remaining want/give
        remaining_pays = subtract_amount(&remaining_pays, &filled_receive);
        remaining_gets = subtract_amount(&remaining_gets, &filled_pay);

        let fully_consumed = fill_num >= fill_den;
        if fully_consumed {
            offers_to_remove.push(*key);
        } else {
            state.remove_offer(key);
            let new_gets = subtract_amount(&book_offer.taker_gets, &filled_receive);
            let new_pays = subtract_amount(&book_offer.taker_pays, &filled_pay);
            if !amount_is_zero(&new_gets) && !amount_is_zero(&new_pays) {
                let mut updated = book_offer.clone();
                updated.taker_gets = new_gets;
                updated.taker_pays = new_pays;
                updated.raw_sle = None;
                state.insert_offer(updated);
            } else {
                // Offer fully consumed (remainder is zero) — remove from owner and book directories
                let offer_key = crate::ledger::offer::shamap_key(&book_offer.account, book_offer.sequence);
                let removed_owner = directory::dir_remove(state, &book_offer.account, &offer_key.0);
                if book_offer.book_directory != [0u8; 32] {
                    let removed_book = directory::dir_remove_root(
                        state,
                        &crate::ledger::Key(book_offer.book_directory),
                        &offer_key.0,
                    );
                    if !removed_owner || !removed_book {
                        let owner_still_has_entry =
                            directory::owner_dir_contains_entry(state, &book_offer.account, &offer_key.0);
                        tracing::warn!(
                            "offer replay remove miss (zero remainder): account={} seq={} owner_removed={} book_removed={} owner_has_entry={}",
                            hex::encode_upper(book_offer.account),
                            book_offer.sequence,
                            removed_owner,
                            removed_book,
                            owner_still_has_entry,
                        );
                    }
                } else if !removed_owner {
                    let owner_still_has_entry =
                        directory::owner_dir_contains_entry(state, &book_offer.account, &offer_key.0);
                    tracing::warn!(
                        "offer replay owner-dir remove miss (zero remainder): account={} seq={} owner_has_entry={}",
                        hex::encode_upper(book_offer.account),
                        book_offer.sequence,
                        owner_still_has_entry,
                    );
                }
            }
        }

        if amount_is_zero(&remaining_pays) {
            break;
        }
    }

    // Remove consumed offers and decrement their owners' counts
    for key in &offers_to_remove {
        if let Some(removed) = state.remove_offer(key) {
            // Remove from owner and book directories
            let offer_key = crate::ledger::offer::shamap_key(&removed.account, removed.sequence);
            let removed_owner = directory::dir_remove(state, &removed.account, &offer_key.0);
            if removed.book_directory != [0u8; 32] {
                let removed_book = directory::dir_remove_root(
                    state,
                    &crate::ledger::Key(removed.book_directory),
                    &offer_key.0,
                );
                if !removed_owner || !removed_book {
                    let owner_still_has_entry =
                        directory::owner_dir_contains_entry(state, &removed.account, &offer_key.0);
                    tracing::warn!(
                        "offer replay remove miss (consumed): account={} seq={} owner_removed={} book_removed={} owner_has_entry={}",
                        hex::encode_upper(removed.account),
                        removed.sequence,
                        removed_owner,
                        removed_book,
                        owner_still_has_entry,
                    );
                }
            } else if !removed_owner {
                let owner_still_has_entry =
                    directory::owner_dir_contains_entry(state, &removed.account, &offer_key.0);
                tracing::warn!(
                    "offer replay owner-dir remove miss (consumed): account={} seq={} owner_has_entry={}",
                    hex::encode_upper(removed.account),
                    removed.sequence,
                    owner_still_has_entry,
                );
            }
        }
    }

    // ── Place remainder as standing offer ────────────────────────────────────
    if !amount_is_zero(&remaining_pays) && !amount_is_zero(&remaining_gets) {
        let offer_key = crate::ledger::offer::shamap_key(&tx.account, offer_seq);
        let owner_node = directory::dir_add(state, &tx.account, offer_key.0);
        let book_key = BookKey::from_amounts(&remaining_pays, &remaining_gets);
        let book_quality = directory::offer_quality(&remaining_gets, &remaining_pays);
        let (book_directory, book_node) =
            directory::dir_add_book(state, &book_key, book_quality, offer_key.0);
        let offer = crate::ledger::Offer {
            account:    tx.account,
            sequence:   offer_seq,
            taker_pays: remaining_pays,
            taker_gets: remaining_gets,
            flags:      tx.flags,
            book_directory: book_directory.0, book_node, owner_node,
            expiration: None, domain_id: None, additional_books: Vec::new(),
            previous_txn_id: [0u8; 32], previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        state.insert_offer(offer);
    }

    for account in owner_count_accounts {
        if let Some(acct) = state.get_account(&account) {
            let mut updated = acct.clone();
            updated.owner_count = crate::ledger::directory::owner_dir_entry_count(state, &account) as u32;
            state.insert_account(updated);
        }
    }

    ApplyResult::Success
}

/// Transfer an amount to/from an account.
/// `receive = true` credits, `receive = false` debits.
fn transfer_amount(
    state:   &mut LedgerState,
    account: &[u8; 20],
    receive: bool,
    amount:  &Amount,
) {
    match amount {
        Amount::Xrp(drops) => {
            if let Some(acct) = state.get_account(account) {
                let mut acct = acct.clone();
                if receive {
                    acct.balance = acct.balance.saturating_add(*drops);
                } else {
                    acct.balance = acct.balance.saturating_sub(*drops);
                }
                state.insert_account(acct);
            }
        }
        Amount::Iou { value, currency, issuer } => {
            let key = crate::ledger::trustline::shamap_key(account, issuer, currency);
            let mut tl = if let Some(existing) = state.get_trustline(&key) {
                existing.clone()
            } else {
                crate::ledger::RippleState::new(account, issuer, currency.clone())
            };
            if receive {
                tl.transfer(issuer, value);
            } else {
                tl.transfer(account, value);
            }
            state.insert_trustline(tl);
        }
        Amount::Mpt(_) => {
            // MPT amounts not yet supported for balance transfers
        }
    }
}

/// Apply an OfferCancel: remove a standing offer from the DEX.
pub(crate) fn apply_offer_cancel(
    state:  &mut LedgerState,
    tx:     &ParsedTx,
) -> ApplyResult {
    let target_seq = match tx.offer_sequence {
        Some(s) => s,
        None    => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = crate::ledger::offer::shamap_key(&tx.account, target_seq);
    if let Some(_removed) = state.remove_offer(&key) {
        if !directory::dir_remove(state, &tx.account, &key.0) {
            let owner_still_has_entry =
                directory::owner_dir_contains_entry(state, &tx.account, &key.0);
            tracing::warn!(
                "offer cancel owner-dir remove miss: account={} seq={} owner_has_entry={}",
                hex::encode_upper(tx.account),
                target_seq,
                owner_still_has_entry,
            );
        }
    }

    if let Some(acct) = state.get_account(&tx.account) {
        let mut updated = acct.clone();
        updated.owner_count = crate::ledger::directory::owner_dir_entry_count(state, &tx.account) as u32;
        state.insert_account(updated);
    }

    ApplyResult::Success
}
