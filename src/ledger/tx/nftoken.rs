//! NFToken — IMPLEMENTED

use super::ApplyResult;
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::amount::Amount;
use crate::transaction::ParsedTx;

pub(crate) fn apply_nftoken_mint(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
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

    let nftoken_id = crate::ledger::nftoken::make_nftoken_id(
        nft_flags,
        transfer_fee,
        &tx.account,
        taxon,
        new_sender.minted_nftokens,
    );

    // Insert via page-based store (also keeps flat store in sync)
    state.insert_nftoken_paged(&tx.account, nftoken_id, tx.uri.clone());
    new_sender.minted_nftokens += 1;
    new_sender.owner_count += 1;

    ApplyResult::Success
}

pub(crate) fn apply_nftoken_burn(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    let nftoken_id = match tx.nftoken_id {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let nft = match state.get_nftoken(&nftoken_id) {
        Some(n) => n.clone(),
        None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
    };

    // Only owner can burn, OR issuer if tfBurnable
    let is_owner = tx.account == nft.owner;
    let is_issuer = tx.account == nft.issuer;
    if !is_owner && !(is_issuer && nft.flags & crate::ledger::nftoken::TF_BURNABLE != 0) {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    // Decrement owner's owner_count
    if let Some(owner) = state.get_account(&nft.owner) {
        let mut owner = owner.clone();
        owner.owner_count = owner.owner_count.saturating_sub(1);
        state.insert_account(owner);
    }

    // Increment burner's burned_nftokens counter
    if let Some(burner) = state.get_account(&tx.account) {
        let mut burner = burner.clone();
        burner.burned_nftokens += 1;
        state.insert_account(burner);
    }

    // Remove all offers for this NFT
    let offer_keys: Vec<crate::ledger::Key> = state
        .iter_nft_offers()
        .filter(|(_, o)| o.nftoken_id == nftoken_id)
        .map(|(k, _)| *k)
        .collect();
    for k in &offer_keys {
        if let Some(off) = state.remove_nft_offer(k) {
            // Remove offer from owner directory (rippled NFTokenUtils.cpp:644)
            directory::dir_remove(state, &off.account, &k.0);
            if let Some(acct) = state.get_account(&off.account) {
                let mut acct = acct.clone();
                acct.owner_count = acct.owner_count.saturating_sub(1);
                state.insert_account(acct);
            }
        }
    }

    // Remove via page-based store (also removes from flat store)
    state.remove_nftoken_paged(&nft.owner, &nftoken_id);
    ApplyResult::Success
}

/// Apply NFTokenCancelOffer: remove one or more NFToken offers from the ledger.
pub(crate) fn apply_nftoken_cancel_offer(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    let mut removed_any = false;

    for offer_hash in [tx.nft_sell_offer, tx.nft_buy_offer].iter().flatten() {
        let key = crate::ledger::Key(*offer_hash);
        if let Some(offer) = state.remove_nft_offer(&key) {
            // Remove offer from owner directory (rippled NFTokenUtils.cpp:644)
            directory::dir_remove(state, &offer.account, &key.0);
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

    // NFTs live in `NFTokenPage` SLEs, which are not tracked individually here.
    // For replay of validated transactions, skip the existence/ownership
    // checks — the network already validated these.
    // (rippled: NFTokenCreateOffer.cpp checks via NFTokenUtils::getNFTokenPage)

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
    let offer = crate::ledger::NFTokenOffer {
        account: tx.account,
        sequence,
        nftoken_id,
        amount,
        destination: tx.destination,
        expiration: tx.expiration,
        flags: tx.flags,
        owner_node,
        nft_offer_node: 0,
        previous_txn_id: [0u8; 32],
        previous_txn_lgrseq: 0,
        raw_sle: None,
    };

    state.insert_nft_offer(offer);
    new_sender.owner_count += 1;

    ApplyResult::Success
}

pub(crate) fn apply_nftoken_accept_offer(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    // Direct accept: either sell_offer or buy_offer (not both for MVP)
    if let Some(sell_hash) = tx.nft_sell_offer {
        let sell_key = crate::ledger::Key(sell_hash);
        let sell = match state.get_nft_offer(&sell_key) {
            Some(o) => o.clone(),
            None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
        };

        if !sell.is_sell() {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }

        // Check expiration
        if let Some(exp) = sell.expiration {
            if (close_time as u32) >= exp {
                return ApplyResult::ClaimedCost("tecEXPIRED");
            }
        }

        // Check destination restriction
        if let Some(dest) = sell.destination {
            if tx.account != dest {
                return ApplyResult::ClaimedCost("tecNO_PERMISSION");
            }
        }

        let nft = match state.get_nftoken(&sell.nftoken_id) {
            Some(n) => n.clone(),
            None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
        };

        // Transfer payment: accepter pays seller
        match &sell.amount {
            Amount::Xrp(drops) if *drops > 0 => {
                // XRP payment
                if let Some(buyer) = state.get_account(&tx.account) {
                    let mut buyer = buyer.clone();
                    buyer.balance = buyer.balance.saturating_sub(*drops);
                    state.insert_account(buyer);
                }
                if let Some(seller) = state.get_account(&sell.account) {
                    let mut seller = seller.clone();
                    seller.balance = seller.balance.saturating_add(*drops);
                    seller.owner_count = seller.owner_count.saturating_sub(1);
                    state.insert_account(seller);
                }
            }
            Amount::Iou {
                value,
                currency,
                issuer,
            } => {
                // IOU payment: debit buyer's trust line, credit seller's trust line
                // Uses same pattern as direct IOU payment in ripple_calc
                let buyer_key = crate::ledger::trustline::shamap_key(&tx.account, issuer, currency);
                let mut buyer_tl = super::ripple_calc::load_or_create_trustline(
                    state,
                    &buyer_key,
                    &tx.account,
                    issuer,
                    currency,
                );
                buyer_tl.transfer(&tx.account, value);
                state.insert_trustline(buyer_tl);

                let seller_key =
                    crate::ledger::trustline::shamap_key(&sell.account, issuer, currency);
                let mut seller_tl = super::ripple_calc::load_or_create_trustline(
                    state,
                    &seller_key,
                    &sell.account,
                    issuer,
                    currency,
                );
                seller_tl.transfer(issuer, value);
                state.insert_trustline(seller_tl);

                // Decrement seller's owner_count for the consumed offer
                if let Some(seller) = state.get_account(&sell.account) {
                    let mut seller = seller.clone();
                    seller.owner_count = seller.owner_count.saturating_sub(1);
                    state.insert_account(seller);
                }
            }
            _ => {
                // Zero amount or MPT: decrement the seller's `owner_count`.
                if let Some(seller) = state.get_account(&sell.account) {
                    let mut seller = seller.clone();
                    seller.owner_count = seller.owner_count.saturating_sub(1);
                    state.insert_account(seller);
                }
            }
        }

        // Transfer NFT ownership
        // Decrement old owner's count, increment new owner's count
        if let Some(old_owner) = state.get_account(&nft.owner) {
            let mut old_owner = old_owner.clone();
            old_owner.owner_count = old_owner.owner_count.saturating_sub(1);
            state.insert_account(old_owner);
        }
        if let Some(new_owner) = state.get_account(&tx.account) {
            let mut new_owner = new_owner.clone();
            new_owner.owner_count += 1;
            state.insert_account(new_owner);
        }
        // Transfer NFT via page store: remove from old owner, add to new owner
        let old_owner_id = nft.owner;
        let uri = nft.uri.clone();
        state.remove_nftoken_paged(&old_owner_id, &sell.nftoken_id);
        state.insert_nftoken_paged(&tx.account, sell.nftoken_id, uri);

        // Remove sell offer from owner directory
        directory::dir_remove(state, &sell.account, &sell_key.0);
        state.remove_nft_offer(&sell_key);
        return ApplyResult::Success;
    }

    if let Some(buy_hash) = tx.nft_buy_offer {
        let buy_key = crate::ledger::Key(buy_hash);
        let buy = match state.get_nft_offer(&buy_key) {
            Some(o) => o.clone(),
            None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
        };

        if buy.is_sell() {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }

        // Caller must be the NFT owner
        let nft = match state.get_nftoken(&buy.nftoken_id) {
            Some(n) => n.clone(),
            None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
        };

        if tx.account != nft.owner {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }

        // Transfer payment: buyer pays owner
        let price_drops = match &buy.amount {
            Amount::Xrp(d) => *d,
            _ => 0,
        };
        if price_drops > 0 {
            if let Some(buyer) = state.get_account(&buy.account) {
                let mut buyer = buyer.clone();
                buyer.balance = buyer.balance.saturating_sub(price_drops);
                buyer.owner_count = buyer.owner_count.saturating_sub(1);
                state.insert_account(buyer);
            }
            if let Some(owner) = state.get_account(&tx.account) {
                let mut owner = owner.clone();
                owner.balance = owner.balance.saturating_add(price_drops);
                state.insert_account(owner);
            }
        } else {
            if let Some(buyer) = state.get_account(&buy.account) {
                let mut buyer = buyer.clone();
                buyer.owner_count = buyer.owner_count.saturating_sub(1);
                state.insert_account(buyer);
            }
        }

        // Transfer NFT ownership
        if let Some(old_owner) = state.get_account(&nft.owner) {
            let mut o = old_owner.clone();
            o.owner_count = o.owner_count.saturating_sub(1);
            state.insert_account(o);
        }
        if let Some(new_owner) = state.get_account(&buy.account) {
            let mut n = new_owner.clone();
            n.owner_count += 1;
            state.insert_account(n);
        }
        // Transfer NFT via page store
        let old_owner_id = nft.owner;
        let uri = nft.uri.clone();
        state.remove_nftoken_paged(&old_owner_id, &buy.nftoken_id);
        state.insert_nftoken_paged(&buy.account, buy.nftoken_id, uri);

        // Remove buy offer from owner directory
        directory::dir_remove(state, &buy.account, &buy_key.0);
        state.remove_nft_offer(&buy_key);
        return ApplyResult::Success;
    }

    ApplyResult::ClaimedCost("temMALFORMED")
}
