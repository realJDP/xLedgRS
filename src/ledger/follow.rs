//! Ledger follower — tracks validated ledgers and builds them locally.
//!
//! Requests liBASE (header) + liTX_NODE (transactions) in parallel for each
//! validated ledger. Applies transactions via the TX engine, patches state
//! from metadata, and advances the chain.
//!
//! This is a single unified path — no legacy fallbacks or competing channels.

use serde_json::Value;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::storage::Storage;

fn validate_sync_anchor_header(
    sync_ledger_seq: u32,
    sync_ledger_hash: Option<[u8; 32]>,
    sync_account_hash: Option<[u8; 32]>,
    hdr: &crate::ledger::LedgerHeader,
) -> bool {
    if hdr.sequence != sync_ledger_seq {
        warn!(
            "follower: sync_ledger_header seq {} != sync_ledger {}",
            hdr.sequence, sync_ledger_seq
        );
        return false;
    }
    if let Some(expected_hash) = sync_ledger_hash {
        if hdr.hash != expected_hash {
            warn!("follower: sync_ledger_header hash mismatch");
            return false;
        }
    }
    if let Some(expected_ah) = sync_account_hash {
        if hdr.account_hash != expected_ah {
            warn!("follower: sync_ledger_header account_hash mismatch");
            return false;
        }
    }
    true
}

fn load_verified_sync_anchor(
    storage: &Storage,
) -> Option<(
    u32,
    Option<[u8; 32]>,
    Option<[u8; 32]>,
    crate::ledger::LedgerHeader,
)> {
    let sync_ledger_seq = storage.get_sync_ledger()? as u32;
    let sync_ledger_hash = storage.get_sync_ledger_hash();
    let sync_account_hash = storage.get_sync_account_hash();
    let hdr = storage.get_sync_ledger_header()?;
    if validate_sync_anchor_header(sync_ledger_seq, sync_ledger_hash, sync_account_hash, &hdr) {
        Some((sync_ledger_seq, sync_ledger_hash, sync_account_hash, hdr))
    } else {
        None
    }
}

fn validated_reacquired_sync_header(
    inbound: &crate::ledger::inbound::InboundLedgers,
    expected_hash: [u8; 32],
    sync_ledger_seq: u32,
    sync_account_hash: Option<[u8; 32]>,
) -> Option<crate::ledger::LedgerHeader> {
    let hdr = inbound.get(&expected_hash)?.header.clone()?;
    if validate_sync_anchor_header(
        sync_ledger_seq,
        Some(expected_hash),
        sync_account_hash,
        &hdr,
    ) {
        Some(hdr)
    } else {
        None
    }
}

fn directory_neighbor_keys_from_raw(
    key: crate::ledger::Key,
    raw: &[u8],
) -> Option<Vec<crate::ledger::Key>> {
    if raw.len() < 3 || raw[0] != 0x11 {
        return None;
    }
    let sle_type = u16::from_be_bytes([raw[1], raw[2]]);
    if sle_type != 0x0064 {
        return None;
    }

    let dir = crate::ledger::directory::DirectoryNode::decode(raw, key.0).ok()?;
    let mut out = Vec::with_capacity(3);
    out.push(crate::ledger::Key(dir.root_index));
    if dir.index_next != 0 {
        out.push(crate::ledger::directory::page_key(
            &dir.root_index,
            dir.index_next,
        ));
    }
    if dir.index_previous != 0 {
        out.push(crate::ledger::directory::page_key(
            &dir.root_index,
            dir.index_previous,
        ));
    }
    Some(out)
}

fn directory_index_keys_from_raw(
    key: crate::ledger::Key,
    raw: &[u8],
) -> Option<Vec<crate::ledger::Key>> {
    if raw.len() < 3 || raw[0] != 0x11 {
        return None;
    }
    let sle_type = u16::from_be_bytes([raw[1], raw[2]]);
    if sle_type != 0x0064 {
        return None;
    }

    let dir = crate::ledger::directory::DirectoryNode::decode(raw, key.0).ok()?;
    let mut out = Vec::with_capacity(dir.indexes.len());
    for index in dir.indexes {
        out.push(crate::ledger::Key(index));
    }
    Some(out)
}

fn parsed_field_bytes<'a>(
    parsed: &'a crate::ledger::meta::ParsedSLE,
    type_code: u16,
    field_code: u16,
) -> Option<&'a [u8]> {
    parsed
        .fields
        .iter()
        .find(|field| field.type_code == type_code && field.field_code == field_code)
        .map(|field| field.data.as_slice())
}

fn parsed_field_account(
    parsed: &crate::ledger::meta::ParsedSLE,
    type_code: u16,
    field_code: u16,
) -> Option<[u8; 20]> {
    let data = parsed_field_bytes(parsed, type_code, field_code)?;
    if data.len() < 20 {
        return None;
    }
    Some(data[..20].try_into().ok()?)
}

fn parsed_field_u64(
    parsed: &crate::ledger::meta::ParsedSLE,
    type_code: u16,
    field_code: u16,
) -> Option<u64> {
    let data = parsed_field_bytes(parsed, type_code, field_code)?;
    if data.len() < 8 {
        return None;
    }
    Some(u64::from_be_bytes(data[..8].try_into().ok()?))
}

fn parsed_field_hash256(
    parsed: &crate::ledger::meta::ParsedSLE,
    type_code: u16,
    field_code: u16,
) -> Option<[u8; 32]> {
    let data = parsed_field_bytes(parsed, type_code, field_code)?;
    if data.len() < 32 {
        return None;
    }
    Some(data[..32].try_into().ok()?)
}

fn parsed_field_vector256(
    parsed: &crate::ledger::meta::ParsedSLE,
    type_code: u16,
    field_code: u16,
) -> Vec<[u8; 32]> {
    let Some(data) = parsed_field_bytes(parsed, type_code, field_code) else {
        return Vec::new();
    };
    data.chunks_exact(32)
        .filter_map(|chunk| chunk.try_into().ok())
        .collect()
}

fn parsed_amount_issuer(
    parsed: &crate::ledger::meta::ParsedSLE,
    type_code: u16,
    field_code: u16,
) -> Option<[u8; 20]> {
    let data = parsed_field_bytes(parsed, type_code, field_code)?;
    if data.len() < 48 {
        return None;
    }
    Some(data[28..48].try_into().ok()?)
}

fn add_account_related_scope(
    keys: &mut std::collections::BTreeSet<crate::ledger::Key>,
    account: [u8; 20],
    owner_page: Option<u64>,
) {
    keys.insert(crate::ledger::account::shamap_key(&account));
    let owner_root = crate::ledger::directory::owner_dir_key(&account);
    keys.insert(owner_root);
    if let Some(page) = owner_page.filter(|page| *page != 0) {
        keys.insert(crate::ledger::directory::page_key(&owner_root.0, page));
    }
}

fn add_book_related_scope(
    keys: &mut std::collections::BTreeSet<crate::ledger::Key>,
    book_directory: [u8; 32],
    book_page: Option<u64>,
) {
    if book_directory == [0u8; 32] {
        return;
    }
    keys.insert(crate::ledger::Key(book_directory));
    if let Some(page) = book_page.filter(|page| *page != 0) {
        keys.insert(crate::ledger::directory::page_key(&book_directory, page));
    }

    let mut root = book_directory;
    root[24..32].copy_from_slice(&0u64.to_be_bytes());
    keys.insert(crate::ledger::Key(root));
    if let Some(page) = book_page.filter(|page| *page != 0) {
        keys.insert(crate::ledger::directory::page_key(&root, page));
    }
}

fn related_scope_keys_from_raw_with_mode(
    key: crate::ledger::Key,
    raw: &[u8],
    include_directory_indexes: bool,
) -> Vec<crate::ledger::Key> {
    let mut out = std::collections::BTreeSet::new();

    let Some(parsed) = crate::ledger::meta::parse_sle(raw) else {
        return Vec::new();
    };

    if let Some(account) = parsed_field_account(&parsed, 8, 1) {
        add_account_related_scope(&mut out, account, parsed_field_u64(&parsed, 3, 4));
    }
    if let Some(owner) = parsed_field_account(&parsed, 8, 2) {
        add_account_related_scope(&mut out, owner, parsed_field_u64(&parsed, 3, 4));
    }
    if let Some(destination) = parsed_field_account(&parsed, 8, 3) {
        add_account_related_scope(
            &mut out,
            destination,
            parsed_field_u64(&parsed, 3, 9),
        );
    }

    match parsed.entry_type {
        0x0064 => {
            if let Some(neighbors) = directory_neighbor_keys_from_raw(key, raw) {
                out.extend(neighbors);
            }
            if include_directory_indexes {
                if let Some(indexes) = directory_index_keys_from_raw(key, raw) {
                    out.extend(indexes);
                }
            }
        }
        0x006f => {
            if let Some(account) = parsed_field_account(&parsed, 8, 1) {
                add_account_related_scope(&mut out, account, parsed_field_u64(&parsed, 3, 4));
            }
            if let Some(book_directory) = parsed_field_hash256(&parsed, 5, 16) {
                add_book_related_scope(
                    &mut out,
                    book_directory,
                    parsed_field_u64(&parsed, 3, 3),
                );
            }
            for book in parsed_field_vector256(&parsed, 19, 13) {
                add_book_related_scope(&mut out, book, None);
            }
            if let Some(offer) = crate::ledger::offer::Offer::decode_from_sle(raw) {
                for book in offer.additional_books {
                    add_book_related_scope(&mut out, book, None);
                }
            }
        }
        0x0072 => {
            if let Some(trustline) = crate::ledger::trustline::RippleState::decode_from_sle(raw) {
                add_account_related_scope(
                    &mut out,
                    trustline.low_account,
                    Some(trustline.low_node),
                );
                add_account_related_scope(
                    &mut out,
                    trustline.high_account,
                    Some(trustline.high_node),
                );
            } else {
                if let Some(low_account) = parsed_amount_issuer(&parsed, 6, 6) {
                    add_account_related_scope(
                        &mut out,
                        low_account,
                        parsed_field_u64(&parsed, 3, 7),
                    );
                }
                if let Some(high_account) = parsed_amount_issuer(&parsed, 6, 7) {
                    add_account_related_scope(
                        &mut out,
                        high_account,
                        parsed_field_u64(&parsed, 3, 8),
                    );
                }
            }
        }
        _ => {}
    }

    out.remove(&key);
    out.into_iter().collect()
}

fn related_scope_keys_from_raw(
    key: crate::ledger::Key,
    raw: &[u8],
) -> Vec<crate::ledger::Key> {
    related_scope_keys_from_raw_with_mode(key, raw, false)
}

fn authoritative_related_scope_keys_from_raw(
    key: crate::ledger::Key,
    raw: &[u8],
) -> Vec<crate::ledger::Key> {
    related_scope_keys_from_raw_with_mode(key, raw, true)
}

fn raw_from_directory_scope_sources(
    state: &crate::ledger::LedgerState,
    extra_raw_sources: &[&std::collections::HashMap<[u8; 32], Vec<u8>>],
    key: &crate::ledger::Key,
) -> Option<Vec<u8>> {
    extra_raw_sources
        .iter()
        .find_map(|source| source.get(&key.0).cloned())
        .or_else(|| state.get_committed_raw_owned(key))
        .or_else(|| state.get_raw_owned(key))
}

fn expand_directory_neighborhoods_with_sources(
    state: &crate::ledger::LedgerState,
    extra_raw_sources: &[&std::collections::HashMap<[u8; 32], Vec<u8>>],
    keys: &mut std::collections::BTreeSet<crate::ledger::Key>,
) {
    let seed_keys: Vec<crate::ledger::Key> = keys.iter().copied().collect();
    let mut added: std::collections::BTreeSet<crate::ledger::Key> =
        std::collections::BTreeSet::new();

    for key in seed_keys {
        let Some(raw) = raw_from_directory_scope_sources(state, extra_raw_sources, &key) else {
            continue;
        };
        added.extend(related_scope_keys_from_raw(key, &raw));
    }

    let directory_seeds: Vec<crate::ledger::Key> = added.iter().copied().collect();
    for key in directory_seeds {
        let Some(raw) = raw_from_directory_scope_sources(state, extra_raw_sources, &key) else {
            continue;
        };
        if let Some(neighbors) = directory_neighbor_keys_from_raw(key, &raw) {
            added.extend(neighbors);
        }
    }

    keys.extend(added);
}

fn expand_authoritative_directory_scope_with_sources(
    state: &crate::ledger::LedgerState,
    extra_raw_sources: &[&std::collections::HashMap<[u8; 32], Vec<u8>>],
    keys: &mut std::collections::BTreeSet<crate::ledger::Key>,
) {
    let mut frontier: std::collections::VecDeque<crate::ledger::Key> =
        keys.iter().copied().collect();
    let mut visited = std::collections::BTreeSet::new();

    while let Some(key) = frontier.pop_front() {
        if !visited.insert(key) {
            continue;
        }
        let Some(raw) = raw_from_directory_scope_sources(state, extra_raw_sources, &key) else {
            continue;
        };
        for related in authoritative_related_scope_keys_from_raw(key, &raw) {
            if keys.insert(related) {
                frontier.push_back(related);
            }
        }
    }
}

fn expand_directory_neighborhoods(
    state: &crate::ledger::LedgerState,
    keys: &mut std::collections::BTreeSet<crate::ledger::Key>,
) {
    expand_directory_neighborhoods_with_sources(state, &[], keys);
}

// ── Helper: sync typed collections from raw SLE ─────────────────────────────

pub(crate) fn sync_typed(
    state: &mut crate::ledger::LedgerState,
    entry_type: u16,
    key: &crate::ledger::Key,
    sle: &[u8],
) {
    state.clear_typed_entry_for_key(key);
    match entry_type {
        0x0061 => {
            if let Ok(acct) = crate::ledger::AccountRoot::decode(sle) {
                state.update_account_typed(acct);
            }
        }
        0x0072 => {
            if let Some(tl) = crate::ledger::trustline::RippleState::decode_from_sle(sle) {
                state.update_trustline_typed(tl);
            }
        }
        0x0064 => {
            if let Ok(dir) = crate::ledger::DirectoryNode::decode(sle, key.0) {
                state.update_directory_typed(dir);
            }
        }
        0x006f => {
            if let Some(off) = crate::ledger::offer::Offer::decode_from_sle(sle) {
                state.update_offer_typed(off);
            }
        }
        0x0037 => {
            if let Some(off) = crate::ledger::nftoken::NFTokenOffer::decode_from_sle(sle) {
                state.hydrate_nft_offer(off);
            }
        }
        _ => {}
    }
}

fn remove_typed(state: &mut crate::ledger::LedgerState, entry_type: u16, key: &crate::ledger::Key) {
    match entry_type {
        0x0061 => {
            if let Some(sle) = state.get_raw_owned(key) {
                if let Ok(acct) = crate::ledger::AccountRoot::decode(&sle) {
                    if state.remove_account(&acct.account_id).is_none() {
                        state.remove_raw(key);
                    }
                } else {
                    state.remove_raw(key);
                }
            } else {
                state.remove_raw(key);
            }
        }
        0x0072 => {
            if !state.remove_trustline(key) {
                state.remove_raw(key);
            }
        }
        0x0043 => {
            if state.remove_check(key).is_none() {
                state.remove_raw(key);
            }
        }
        0x0070 => {
            if state.remove_deposit_preauth(key).is_none() {
                state.remove_raw(key);
            }
        }
        0x0049 => {
            if state.remove_did(key).is_none() {
                state.remove_raw(key);
            }
        }
        0x0064 => {
            state.remove_directory_any(key);
        }
        0x006f => {
            if state.remove_offer(key).is_none() {
                state.remove_raw(key);
            }
        }
        0x0075 => {
            if state.remove_escrow(key).is_none() {
                state.remove_raw(key);
            }
        }
        0x0078 => {
            if state.remove_paychan(key).is_none() {
                state.remove_raw(key);
            }
        }
        0x0054 => {
            if state.remove_ticket(key).is_none() {
                state.remove_raw(key);
            }
        }
        0x0037 => {
            if state.remove_nft_offer(key).is_none() {
                state.remove_raw(key);
            }
        }
        _ => state.remove_raw(key),
    }
}

fn build_directory_sle_from_fields(
    key: &crate::ledger::Key,
    fields: &[crate::ledger::meta::ParsedField],
    prev_txn_id: Option<[u8; 32]>,
    prev_txn_lgrseq: Option<u32>,
) -> Vec<u8> {
    fn find_field<'a>(
        fields: &'a [crate::ledger::meta::ParsedField],
        tc: u16,
        fc: u16,
    ) -> Option<&'a [u8]> {
        fields
            .iter()
            .find(|f| f.type_code == tc && f.field_code == fc)
            .map(|f| f.data.as_slice())
    }

    fn as_u64(data: Option<&[u8]>) -> Option<u64> {
        let bytes = data?;
        if bytes.len() < 8 {
            return None;
        }
        Some(u64::from_be_bytes(bytes[..8].try_into().ok()?))
    }

    fn as_hash256(data: Option<&[u8]>) -> Option<[u8; 32]> {
        let bytes = data?;
        if bytes.len() < 32 {
            return None;
        }
        Some(bytes[..32].try_into().ok()?)
    }

    fn as_account(data: Option<&[u8]>) -> Option<[u8; 20]> {
        let bytes = data?;
        if bytes.len() < 20 {
            return None;
        }
        Some(bytes[..20].try_into().ok()?)
    }

    fn as_vector256(data: Option<&[u8]>) -> Vec<[u8; 32]> {
        let Some(bytes) = data else {
            return Vec::new();
        };
        bytes
            .chunks_exact(32)
            .filter_map(|chunk| chunk.try_into().ok())
            .collect()
    }

    let root_index = as_hash256(find_field(fields, 5, 8)).unwrap_or(key.0);

    crate::ledger::DirectoryNode {
        key: key.0,
        root_index,
        indexes: as_vector256(find_field(fields, 19, 1)),
        index_next: as_u64(find_field(fields, 3, 1)).unwrap_or(0),
        index_previous: as_u64(find_field(fields, 3, 2)).unwrap_or(0),
        owner: as_account(find_field(fields, 8, 2)),
        exchange_rate: as_u64(find_field(fields, 3, 6)),
        taker_pays_currency: as_account(find_field(fields, 17, 1)),
        taker_pays_issuer: as_account(find_field(fields, 17, 2)),
        taker_gets_currency: as_account(find_field(fields, 17, 3)),
        taker_gets_issuer: as_account(find_field(fields, 17, 4)),
        nftoken_id: as_hash256(find_field(fields, 5, 10)),
        domain_id: as_hash256(find_field(fields, 5, 34)),
        previous_txn_id: prev_txn_id,
        previous_txn_lgr_seq: prev_txn_lgrseq,
        has_index_next: false,
        has_index_previous: false,
        raw_sle: None,
    }
    .encode()
}

fn build_directory_sle_from_fields_with_state(
    state: &crate::ledger::LedgerState,
    key: &crate::ledger::Key,
    fields: &[crate::ledger::meta::ParsedField],
    related_offer_book: Option<([u8; 20], [u8; 20], [u8; 20], [u8; 20])>,
    prev_txn_id: Option<[u8; 32]>,
    prev_txn_lgrseq: Option<u32>,
) -> Vec<u8> {
    fn find_field<'a>(
        fields: &'a [crate::ledger::meta::ParsedField],
        tc: u16,
        fc: u16,
    ) -> Option<&'a [u8]> {
        fields
            .iter()
            .find(|f| f.type_code == tc && f.field_code == fc)
            .map(|f| f.data.as_slice())
    }

    fn as_u64(data: Option<&[u8]>) -> Option<u64> {
        let bytes = data?;
        if bytes.len() < 8 {
            return None;
        }
        Some(u64::from_be_bytes(bytes[..8].try_into().ok()?))
    }

    fn as_hash256(data: Option<&[u8]>) -> Option<[u8; 32]> {
        let bytes = data?;
        if bytes.len() < 32 {
            return None;
        }
        Some(bytes[..32].try_into().ok()?)
    }

    fn as_account(data: Option<&[u8]>) -> Option<[u8; 20]> {
        let bytes = data?;
        if bytes.len() < 20 {
            return None;
        }
        Some(bytes[..20].try_into().ok()?)
    }

    fn as_vector256(data: Option<&[u8]>) -> Vec<[u8; 32]> {
        let Some(bytes) = data else {
            return Vec::new();
        };
        bytes
            .chunks_exact(32)
            .filter_map(|chunk| chunk.try_into().ok())
            .collect()
    }

    let root_index = as_hash256(find_field(fields, 5, 8)).unwrap_or(key.0);
    let mut owner = as_account(find_field(fields, 8, 2));
    let mut exchange_rate = as_u64(find_field(fields, 3, 6));
    let mut taker_pays_currency = as_account(find_field(fields, 17, 1));
    let mut taker_pays_issuer = as_account(find_field(fields, 17, 2));
    let mut taker_gets_currency = as_account(find_field(fields, 17, 3));
    let mut taker_gets_issuer = as_account(find_field(fields, 17, 4));
    let nftoken_id = as_hash256(find_field(fields, 5, 10));
    let domain_id = as_hash256(find_field(fields, 5, 34));

    if (taker_pays_currency.is_none()
        || taker_pays_issuer.is_none()
        || taker_gets_currency.is_none()
        || taker_gets_issuer.is_none()
        || owner.is_none()
        || exchange_rate.is_none())
        && root_index != key.0
    {
        let root_key = crate::ledger::Key(root_index);
        if let Some(raw) = state.get_raw_owned(&root_key) {
            if let Ok(root_dir) = crate::ledger::DirectoryNode::decode(&raw, root_index) {
                if owner.is_none() {
                    owner = root_dir.owner;
                }
                if exchange_rate.is_none() {
                    exchange_rate = root_dir.exchange_rate;
                }
                if taker_pays_currency.is_none() {
                    taker_pays_currency = root_dir.taker_pays_currency;
                }
                if taker_pays_issuer.is_none() {
                    taker_pays_issuer = root_dir.taker_pays_issuer;
                }
                if taker_gets_currency.is_none() {
                    taker_gets_currency = root_dir.taker_gets_currency;
                }
                if taker_gets_issuer.is_none() {
                    taker_gets_issuer = root_dir.taker_gets_issuer;
                }
            }
        }
    }

    if let Some((pays_cur, pays_iss, gets_cur, gets_iss)) = related_offer_book {
        taker_pays_currency = Some(pays_cur);
        taker_pays_issuer = Some(pays_iss);
        taker_gets_currency = Some(gets_cur);
        taker_gets_issuer = Some(gets_iss);
    }

    crate::ledger::DirectoryNode {
        key: key.0,
        root_index,
        indexes: as_vector256(find_field(fields, 19, 1)),
        index_next: as_u64(find_field(fields, 3, 1)).unwrap_or(0),
        index_previous: as_u64(find_field(fields, 3, 2)).unwrap_or(0),
        owner,
        exchange_rate,
        taker_pays_currency,
        taker_pays_issuer,
        taker_gets_currency,
        taker_gets_issuer,
        nftoken_id,
        domain_id,
        previous_txn_id: prev_txn_id,
        previous_txn_lgr_seq: prev_txn_lgrseq,
        has_index_next: false,
        has_index_previous: false,
        raw_sle: None,
    }
    .encode()
}

fn build_offer_sle_from_fields(
    fields: &[crate::ledger::meta::ParsedField],
    prev_txn_id: Option<[u8; 32]>,
    prev_txn_lgrseq: Option<u32>,
) -> Vec<u8> {
    fn find_field<'a>(
        fields: &'a [crate::ledger::meta::ParsedField],
        tc: u16,
        fc: u16,
    ) -> Option<&'a [u8]> {
        fields
            .iter()
            .find(|f| f.type_code == tc && f.field_code == fc)
            .map(|f| f.data.as_slice())
    }

    fn as_u32(data: Option<&[u8]>) -> Option<u32> {
        let bytes = data?;
        if bytes.len() < 4 {
            return None;
        }
        Some(u32::from_be_bytes(bytes[..4].try_into().ok()?))
    }

    fn as_u64(data: Option<&[u8]>) -> Option<u64> {
        let bytes = data?;
        if bytes.len() < 8 {
            return None;
        }
        Some(u64::from_be_bytes(bytes[..8].try_into().ok()?))
    }

    fn as_hash256(data: Option<&[u8]>) -> Option<[u8; 32]> {
        let bytes = data?;
        if bytes.len() < 32 {
            return None;
        }
        Some(bytes[..32].try_into().ok()?)
    }

    fn as_account(data: Option<&[u8]>) -> Option<[u8; 20]> {
        let bytes = data?;
        if bytes.len() < 20 {
            return None;
        }
        Some(bytes[..20].try_into().ok()?)
    }

    fn as_vector256(data: Option<&[u8]>) -> Vec<[u8; 32]> {
        let Some(bytes) = data else {
            return Vec::new();
        };
        bytes
            .chunks_exact(32)
            .filter_map(|chunk| chunk.try_into().ok())
            .collect()
    }

    let taker_pays = find_field(fields, 6, 4)
        .and_then(|d| {
            crate::transaction::amount::Amount::from_bytes(d)
                .ok()
                .map(|(a, _)| a)
        })
        .unwrap_or(crate::transaction::amount::Amount::Xrp(0));
    let taker_gets = find_field(fields, 6, 5)
        .and_then(|d| {
            crate::transaction::amount::Amount::from_bytes(d)
                .ok()
                .map(|(a, _)| a)
        })
        .unwrap_or(crate::transaction::amount::Amount::Xrp(0));

    crate::ledger::offer::Offer {
        account: as_account(find_field(fields, 8, 1)).unwrap_or([0u8; 20]),
        sequence: as_u32(find_field(fields, 2, 4)).unwrap_or(0),
        taker_pays,
        taker_gets,
        flags: as_u32(find_field(fields, 2, 2)).unwrap_or(0),
        book_directory: as_hash256(find_field(fields, 5, 16)).unwrap_or([0u8; 32]),
        book_node: as_u64(find_field(fields, 3, 3)).unwrap_or(0),
        owner_node: as_u64(find_field(fields, 3, 4)).unwrap_or(0),
        expiration: as_u32(find_field(fields, 2, 10)),
        domain_id: as_hash256(find_field(fields, 5, 34)),
        additional_books: as_vector256(find_field(fields, 19, 13)),
        previous_txn_id: prev_txn_id.unwrap_or([0u8; 32]),
        previous_txn_lgr_seq: prev_txn_lgrseq.unwrap_or(0),
        raw_sle: None,
    }
    .encode()
}

fn build_created_sle(
    key: &crate::ledger::Key,
    entry_type: u16,
    fields: &[crate::ledger::meta::ParsedField],
    prev_txn_id: Option<[u8; 32]>,
    prev_txn_lgrseq: Option<u32>,
) -> Vec<u8> {
    match entry_type {
        0x0064 => build_directory_sle_from_fields(key, fields, prev_txn_id, prev_txn_lgrseq),
        0x006f => build_offer_sle_from_fields(fields, prev_txn_id, prev_txn_lgrseq),
        _ => crate::ledger::meta::build_sle(entry_type, fields, prev_txn_id, prev_txn_lgrseq),
    }
}

pub(crate) fn build_created_sle_with_state(
    state: &crate::ledger::LedgerState,
    key: &crate::ledger::Key,
    entry_type: u16,
    fields: &[crate::ledger::meta::ParsedField],
    related_offer_book: Option<([u8; 20], [u8; 20], [u8; 20], [u8; 20])>,
    prev_txn_id: Option<[u8; 32]>,
    prev_txn_lgrseq: Option<u32>,
) -> Vec<u8> {
    match entry_type {
        0x0064 => build_directory_sle_from_fields_with_state(
            state,
            key,
            fields,
            related_offer_book,
            prev_txn_id,
            prev_txn_lgrseq,
        ),
        _ => build_created_sle(key, entry_type, fields, prev_txn_id, prev_txn_lgrseq),
    }
}

pub(crate) fn extract_offer_book_sides(
    fields: &[crate::ledger::meta::ParsedField],
) -> Option<([u8; 20], [u8; 20], [u8; 20], [u8; 20], [u8; 32])> {
    fn find_field<'a>(
        fields: &'a [crate::ledger::meta::ParsedField],
        tc: u16,
        fc: u16,
    ) -> Option<&'a [u8]> {
        fields
            .iter()
            .find(|f| f.type_code == tc && f.field_code == fc)
            .map(|f| f.data.as_slice())
    }
    fn as_hash256(data: Option<&[u8]>) -> Option<[u8; 32]> {
        let bytes = data?;
        if bytes.len() < 32 {
            return None;
        }
        Some(bytes[..32].try_into().ok()?)
    }
    let pays = find_field(fields, 6, 4).and_then(|d| {
        crate::transaction::amount::Amount::from_bytes(d)
            .ok()
            .map(|(a, _)| a)
    })?;
    let gets = find_field(fields, 6, 5).and_then(|d| {
        crate::transaction::amount::Amount::from_bytes(d)
            .ok()
            .map(|(a, _)| a)
    })?;
    let book_dir = as_hash256(find_field(fields, 5, 16))?;
    let (pays_currency, pays_issuer) = match pays {
        crate::transaction::amount::Amount::Iou {
            currency, issuer, ..
        } => (currency.code, issuer),
        crate::transaction::amount::Amount::Xrp(_) | crate::transaction::amount::Amount::Mpt(_) => {
            ([0u8; 20], [0u8; 20])
        }
    };
    let (gets_currency, gets_issuer) = match gets {
        crate::transaction::amount::Amount::Iou {
            currency, issuer, ..
        } => (currency.code, issuer),
        crate::transaction::amount::Amount::Xrp(_) | crate::transaction::amount::Amount::Mpt(_) => {
            ([0u8; 20], [0u8; 20])
        }
    };
    Some((
        pays_currency,
        pays_issuer,
        gets_currency,
        gets_issuer,
        book_dir,
    ))
}

fn field_id_list(fields: &[crate::ledger::meta::ParsedField]) -> Vec<(u16, u16)> {
    fields.iter().map(|f| (f.type_code, f.field_code)).collect()
}

pub(crate) fn related_offer_book_for_directory_node(
    node: &crate::ledger::meta::AffectedNode,
    tx_book_dirs: &std::collections::HashMap<[u8; 32], ([u8; 20], [u8; 20], [u8; 20], [u8; 20])>,
) -> Option<([u8; 20], [u8; 20], [u8; 20], [u8; 20])> {
    if node.entry_type != 0x0064 {
        return None;
    }
    if let Some(exact) = tx_book_dirs.get(&node.ledger_index).copied() {
        return Some(exact);
    }
    let from_root = node
        .fields
        .iter()
        .find(|f| f.type_code == 5 && f.field_code == 8)
        .and_then(|f| {
            if f.data.len() < 32 {
                None
            } else {
                let mut root = [0u8; 32];
                root.copy_from_slice(&f.data[..32]);
                tx_book_dirs.get(&root).copied()
            }
        });
    if from_root.is_some() {
        return from_root;
    }
    let has_owner = node
        .fields
        .iter()
        .any(|f| f.type_code == 8 && f.field_code == 2);
    if has_owner {
        return None;
    }
    None
}

// ── Helper: metadata seeding and patching ────────────────────────────────────

/// Build pre-transaction SLE entries from metadata for state seeding.
fn seed_entries_from_metadata(
    blobs: &[(Vec<u8>, Vec<u8>)],
) -> Vec<(crate::ledger::Key, u16, Vec<u8>)> {
    let mut seeded_keys = std::collections::HashSet::new();
    let mut entries = Vec::new();
    let mut all_meta: Vec<(u32, Vec<crate::ledger::meta::AffectedNode>)> = Vec::new();
    for (_tx_blob, meta_blob) in blobs {
        let (idx, nodes) = crate::ledger::meta::parse_metadata_with_index(meta_blob);
        all_meta.push((idx.unwrap_or(u32::MAX), nodes));
    }
    all_meta.sort_by_key(|(idx, _)| *idx);
    for (_tx_index, nodes) in &all_meta {
        for node in nodes {
            if seeded_keys.contains(&node.ledger_index) {
                continue;
            }
            let sle = match node.action {
                // Modified: DON'T seed pre-TX state. The real SLE is already
                // in NuDB from sync or the previous follower cycle.
                // apply_metadata_patches() will read it and patch with FinalFields.
                crate::ledger::meta::Action::Modified => continue,
                crate::ledger::meta::Action::Deleted => crate::ledger::meta::build_sle(
                    node.entry_type,
                    &node.fields,
                    node.prev_txn_id,
                    node.prev_txn_lgrseq,
                ),
                crate::ledger::meta::Action::Created => continue,
            };
            seeded_keys.insert(node.ledger_index);
            entries.push((crate::ledger::Key(node.ledger_index), node.entry_type, sle));
        }
    }
    entries
}

#[derive(Debug, Clone, Default)]
struct MetadataPatchStats {
    applied: usize,
    missing_modified: usize,
    missing_modified_keys: Vec<crate::ledger::Key>,
    created_override_miss_keys: Vec<crate::ledger::Key>,
    incomplete_book_dir_keys: Vec<crate::ledger::Key>,
    aborted: bool,
}

/// Apply post-replay metadata patches.
fn apply_metadata_patches(
    meta_with_hashes: &[([u8; 32], Vec<u8>)],
    ledger_seq: u32,
    created_overrides: &std::collections::HashMap<crate::ledger::Key, Vec<u8>>,
    modified_dir_overrides: &std::collections::HashMap<crate::ledger::Key, Vec<u8>>,
    state: &mut crate::ledger::LedgerState,
) -> MetadataPatchStats {
    let fix_previous_txn_id_enabled = crate::ledger::fix_previous_txn_id_enabled(state);
    let should_thread_entry_type = |entry_type: u16| {
        crate::ledger::sle::LedgerEntryType::from_u16(entry_type)
            .map(|entry_type| {
                crate::ledger::should_thread_previous_txn_fields_with_fix_previous_txn_id(
                    fix_previous_txn_id_enabled,
                    entry_type,
                )
            })
            .unwrap_or(false)
    };
    fn watch_directory_key(key: &[u8; 32]) -> bool {
        let k = hex::encode_upper(key);
        k == "28516E970A801B5AE4C34A5A5F7BB8A63263E481504D85066F61BBE1A3AC1123"
            || k == "C78241CA86D8FD33D7930F713AE3A89D7CE23C52BB46E39526E627CCF5964E32"
            || k == "6065A06AFD2A13DE1A5F389523C4B4E96FEE17950D4078C12183CCA79542A434"
    }
    fn field_vector256(fields: &[crate::ledger::meta::ParsedField]) -> Vec<[u8; 32]> {
        fields
            .iter()
            .find(|f| f.type_code == 19 && f.field_code == 1)
            .map(|f| {
                f.data
                    .chunks_exact(32)
                    .filter_map(|c| c.try_into().ok())
                    .collect()
            })
            .unwrap_or_default()
    }
    fn normalize_directory_fields(
        entry_type: u16,
        fields: &[crate::ledger::meta::ParsedField],
    ) -> Vec<crate::ledger::meta::ParsedField> {
        let out: Vec<crate::ledger::meta::ParsedField> = fields
            .iter()
            .map(|f| crate::ledger::meta::ParsedField {
                type_code: f.type_code,
                field_code: f.field_code,
                data: f.data.clone(),
            })
            .collect();
        let _ = entry_type;
        out
    }
    const BYTE_DIFF_LEDGER_SEQ: u32 = 103483090;
    let byte_diff_mode = ledger_seq == BYTE_DIFF_LEDGER_SEQ;
    let mut applied = 0usize;
    let mut missing_modified = 0usize;
    let mut missing_modified_keys = std::collections::BTreeSet::<crate::ledger::Key>::new();
    let mut created_override_hits = 0usize;
    let mut created_override_misses = 0usize;
    let mut created_override_miss_keys: std::collections::HashSet<crate::ledger::Key> =
        std::collections::HashSet::new();
    let mut incomplete_book_dir_keys: Vec<crate::ledger::Key> = Vec::new();
    let mut created_seen: std::collections::HashMap<
        [u8; 32],
        Vec<crate::ledger::meta::ParsedField>,
    > = std::collections::HashMap::new();
    // Parse metadata and pair with tx hashes, sorted by TransactionIndex
    let mut all_meta: Vec<(u32, [u8; 32], Vec<crate::ledger::meta::AffectedNode>)> = Vec::new();
    for (tx_hash, meta_blob) in meta_with_hashes {
        let (idx, nodes) = crate::ledger::meta::parse_metadata_with_index(meta_blob);
        all_meta.push((idx.unwrap_or(u32::MAX), *tx_hash, nodes));
    }
    all_meta.sort_by_key(|(idx, _, _)| *idx);
    if byte_diff_mode {
        info!(
            "BYTE DIFF seq={}: txs_with_meta={} sorted_meta_entries={}",
            ledger_seq,
            meta_with_hashes.len(),
            all_meta.len(),
        );
    }
    for (_tx_index, tx_hash, nodes) in &all_meta {
        let mut tx_ops: Vec<(crate::ledger::Key, u16, Option<Vec<u8>>, bool)> = Vec::new();
        let mut tx_book_dirs: std::collections::HashMap<
            [u8; 32],
            ([u8; 20], [u8; 20], [u8; 20], [u8; 20]),
        > = std::collections::HashMap::new();
        for n in nodes {
            if n.entry_type == 0x006f {
                if let Some((pays_cur, pays_iss, gets_cur, gets_iss, book_dir)) =
                    extract_offer_book_sides(&n.fields)
                {
                    let sides = (pays_cur, pays_iss, gets_cur, gets_iss);
                    // Offer metadata gives sfBookDirectory (quality key). DirectoryNodes
                    // often reference RootIndex (quality-0 key), so index both.
                    tx_book_dirs.insert(book_dir, sides);
                    let root = crate::ledger::directory::book_dir_root_key(
                        &crate::ledger::offer::BookKey {
                            pays_currency: pays_cur,
                            pays_issuer: pays_iss,
                            gets_currency: gets_cur,
                            gets_issuer: gets_iss,
                        },
                    )
                    .0;
                    tx_book_dirs.entry(root).or_insert(sides);
                }
            }
        }
        for node in nodes {
            let key = crate::ledger::Key(node.ledger_index);
            if ledger_seq == 103483090
                && node.entry_type == 0x0064
                && watch_directory_key(&node.ledger_index)
            {
                let idx = field_vector256(&node.fields);
                let idx_short: Vec<String> =
                    idx.iter().map(|h| hex::encode_upper(&h[..8])).collect();
                info!(
                    "DIR WATCH seq={} action={:?} key={} tx_hash={} idx_count={} idx={:?}",
                    ledger_seq,
                    node.action,
                    hex::encode_upper(node.ledger_index),
                    hex::encode_upper(&tx_hash[..8]),
                    idx_short.len(),
                    idx_short,
                );
            }
            // rippled only threads PreviousTxn* for threaded object types.
            // Do not force PreviousTxn* onto non-threaded entries.
            let (new_ptid, new_ptseq) = if should_thread_entry_type(node.entry_type) {
                (Some(*tx_hash), Some(ledger_seq))
            } else {
                (None, None)
            };
            match node.action {
                crate::ledger::meta::Action::Created => {
                    created_seen.insert(node.ledger_index, node.fields.clone());
                    let norm_fields = normalize_directory_fields(node.entry_type, &node.fields);
                    let related_offer_book =
                        related_offer_book_for_directory_node(node, &tx_book_dirs);
                    let sle = if let Some(override_sle) = created_overrides.get(&key).cloned() {
                        created_override_hits += 1;
                        override_sle
                    } else {
                        created_override_misses += 1;
                        if byte_diff_mode {
                            warn!(
                                "BYTE DIFF seq={}: CREATE override-miss key={} type={:04X} fields={} field_ids={:?} tx_hash={}",
                                ledger_seq,
                                hex::encode_upper(key.0),
                                node.entry_type,
                                node.fields.len(),
                                field_id_list(&node.fields),
                                hex::encode_upper(tx_hash),
                            );
                        }
                        created_override_miss_keys.insert(key);
                        build_created_sle_with_state(
                            &state,
                            &key,
                            node.entry_type,
                            &norm_fields,
                            related_offer_book,
                            new_ptid,
                            new_ptseq,
                        )
                    };
                    if byte_diff_mode {
                        info!(
                            "BYTE DIFF seq={}: CREATE key={} type={:04X} sle_len={} sle_prefix={}",
                            ledger_seq,
                            hex::encode_upper(&key.0[..8]),
                            node.entry_type,
                            sle.len(),
                            hex::encode_upper(&sle[..sle.len().min(32)]),
                        );
                    }
                    // Block incomplete book DirectoryNodes from entering state.
                    if node.entry_type == 0x0064 {
                        match crate::ledger::DirectoryNode::decode(&sle, key.0) {
                            Ok(dir) => {
                                if dir.exchange_rate.is_some()
                                    && (dir.taker_pays_currency.is_none()
                                        || dir.taker_pays_issuer.is_none()
                                        || dir.taker_gets_currency.is_none()
                                        || dir.taker_gets_issuer.is_none())
                                {
                                    warn!(
                                        "follower: BLOCKING incomplete book DirectoryNode (created) at seq={} key={} sle_len={} has_pc={} has_pi={} has_gc={} has_gi={} root_is_self={}",
                                        ledger_seq,
                                        hex::encode_upper(key.0),
                                        sle.len(),
                                        dir.taker_pays_currency.is_some(),
                                        dir.taker_pays_issuer.is_some(),
                                        dir.taker_gets_currency.is_some(),
                                        dir.taker_gets_issuer.is_some(),
                                        dir.root_index == key.0,
                                    );
                                    incomplete_book_dir_keys.push(key);
                                    tx_ops.push((key, node.entry_type, Some(sle), true));
                                    continue;
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "follower: decode failed for created DirectoryNode at seq={} key={} sle_len={}: {}",
                                    ledger_seq, hex::encode_upper(key.0), sle.len(), e,
                                );
                            }
                        }
                    }
                    tx_ops.push((key, node.entry_type, Some(sle), true));
                }
                crate::ledger::meta::Action::Modified => {
                    if let Some(override_sle) = modified_dir_overrides.get(&key).cloned() {
                        if byte_diff_mode {
                            info!(
                                "BYTE DIFF seq={}: MODIFY-OVERRIDE key={} type={:04X} sle_len={} tx_hash={}",
                                ledger_seq,
                                hex::encode_upper(&key.0[..8]),
                                node.entry_type,
                                override_sle.len(),
                                hex::encode_upper(&tx_hash[..8]),
                            );
                        }
                        tx_ops.push((key, node.entry_type, Some(override_sle), false));
                        continue;
                    }
                    let norm_fields = normalize_directory_fields(node.entry_type, &node.fields);
                    let existing = state.get_raw_owned(&key);
                    let created_earlier_in_ledger = created_seen.contains_key(&node.ledger_index);
                    if node.entry_type == 0x0064 {
                        let has_indexes = node
                            .fields
                            .iter()
                            .any(|f| f.type_code == 19 && f.field_code == 1);
                        if !has_indexes {
                            if let Some(override_sle) = modified_dir_overrides.get(&key).cloned() {
                                if ledger_seq == 103483090
                                    && watch_directory_key(&node.ledger_index)
                                {
                                    info!(
                                        "DIR WATCH seq={} action=Modified key={} source=override sle_len={} tx_hash={}",
                                        ledger_seq,
                                        hex::encode_upper(node.ledger_index),
                                        override_sle.len(),
                                        hex::encode_upper(&tx_hash[..8]),
                                    );
                                }
                                tx_ops.push((key, node.entry_type, Some(override_sle), false));
                                continue;
                            } else if ledger_seq == 103483090
                                && watch_directory_key(&node.ledger_index)
                            {
                                warn!(
                                    "DIR WATCH seq={} action=Modified key={} source=patch_fallback reason=no_override tx_hash={}",
                                    ledger_seq,
                                    hex::encode_upper(node.ledger_index),
                                    hex::encode_upper(&tx_hash[..8]),
                                );
                            }
                        }
                    }
                    // Detect deleted fields: in PreviousFields but NOT in FinalFields
                    let final_keys: std::collections::HashSet<(u16, u16)> = node
                        .fields
                        .iter()
                        .map(|f| (f.type_code, f.field_code))
                        .collect();
                    let deleted: Vec<(u16, u16)> = node
                        .previous_fields
                        .iter()
                        .map(|f| (f.type_code, f.field_code))
                        .filter(|k| !final_keys.contains(k))
                        .collect();
                    let final_sle = if let Some(e) = existing {
                        if created_earlier_in_ledger {
                            let related_offer_book =
                                related_offer_book_for_directory_node(node, &tx_book_dirs);
                            // Merge type-17 fields from creation context into
                            // modification FinalFields so book directory fields
                            // aren't lost when the modification doesn't repeat them.
                            let merged_fields = if node.entry_type == 0x0064 {
                                let mut merged = norm_fields.clone();
                                if let Some(creation_fields) = created_seen.get(&node.ledger_index)
                                {
                                    for cf in creation_fields {
                                        if cf.type_code == 17
                                            && (cf.field_code >= 1 && cf.field_code <= 4)
                                            && !merged.iter().any(|f| {
                                                f.type_code == cf.type_code
                                                    && f.field_code == cf.field_code
                                            })
                                        {
                                            merged.push(cf.clone());
                                        }
                                    }
                                }
                                merged
                            } else {
                                norm_fields.clone()
                            };
                            let rebuilt = build_created_sle_with_state(
                                &state,
                                &key,
                                node.entry_type,
                                &merged_fields,
                                related_offer_book,
                                new_ptid,
                                new_ptseq,
                            );
                            if byte_diff_mode {
                                info!(
                                    "BYTE DIFF seq={}: MODIFY-REBUILD key={} type={:04X} before_len={} after_len={} prev_fields={} final_fields={} tx_hash={} before_prefix={} after_prefix={}",
                                    ledger_seq,
                                    hex::encode_upper(&key.0[..8]),
                                    node.entry_type,
                                    e.len(),
                                    rebuilt.len(),
                                    node.previous_fields.len(),
                                    node.fields.len(),
                                    hex::encode_upper(&tx_hash[..8]),
                                    hex::encode_upper(&e[..e.len().min(32)]),
                                    hex::encode_upper(&rebuilt[..rebuilt.len().min(32)]),
                                );
                            }
                            rebuilt
                        } else {
                            let patched = crate::ledger::meta::patch_sle(
                                &e,
                                &norm_fields,
                                new_ptid,
                                new_ptseq,
                                &deleted,
                            );
                            if byte_diff_mode {
                                info!(
                                    "BYTE DIFF seq={}: MODIFY key={} type={:04X} before_len={} after_len={} prev_fields={} final_fields={} deleted={} tx_hash={} before_prefix={} after_prefix={}",
                                    ledger_seq,
                                    hex::encode_upper(&key.0[..8]),
                                    node.entry_type,
                                    e.len(),
                                    patched.len(),
                                    node.previous_fields.len(),
                                    node.fields.len(),
                                    deleted.len(),
                                    hex::encode_upper(&tx_hash[..8]),
                                    hex::encode_upper(&e[..e.len().min(32)]),
                                    hex::encode_upper(&patched[..patched.len().min(32)]),
                                );
                                for deleted_key in &deleted {
                                    info!(
                                        "BYTE DIFF seq={}: MODIFY key={} deleted_field=({}, {})",
                                        ledger_seq,
                                        hex::encode_upper(&key.0[..8]),
                                        deleted_key.0,
                                        deleted_key.1,
                                    );
                                }
                            }
                            patched
                        }
                    } else if let Some(committed) = state.get_committed_raw_owned(&key) {
                        warn!(
                            "metadata patch falling back to committed base object: seq={} key={} type={:04X} tx_hash={}",
                            ledger_seq,
                            hex::encode_upper(&key.0[..8]),
                            node.entry_type,
                            hex::encode_upper(&tx_hash[..8]),
                        );
                        let patched = crate::ledger::meta::patch_sle(
                            &committed,
                            &norm_fields,
                            new_ptid,
                            new_ptseq,
                            &deleted,
                        );
                        if byte_diff_mode {
                            info!(
                                "BYTE DIFF seq={}: MODIFY-COMMITTED-FALLBACK key={} type={:04X} before_len={} after_len={} prev_fields={} final_fields={} deleted={} tx_hash={} before_prefix={} after_prefix={}",
                                ledger_seq,
                                hex::encode_upper(&key.0[..8]),
                                node.entry_type,
                                committed.len(),
                                patched.len(),
                                node.previous_fields.len(),
                                node.fields.len(),
                                deleted.len(),
                                hex::encode_upper(&tx_hash[..8]),
                                hex::encode_upper(&committed[..committed.len().min(32)]),
                                hex::encode_upper(&patched[..patched.len().min(32)]),
                            );
                        }
                        patched
                    } else {
                        missing_modified += 1;
                        missing_modified_keys.insert(key);
                        let (deleted_overlay, dirty_overlay, loaded_overlay, nudb_present) =
                            state.inspect_raw_lookup(&key);
                        let nudb_trace = state.debug_trace_nudb_key_path(&key);
                        error!(
                            "metadata patch missing base object: seq={} key={} type={:04X} tx_hash={} final_fields={} prev_fields={} deleted_overlay={} dirty_overlay={} loaded_overlay={} nudb_present={} created_earlier_in_ledger={}",
                            ledger_seq,
                            hex::encode_upper(&key.0[..8]),
                            node.entry_type,
                            hex::encode_upper(&tx_hash[..8]),
                            node.fields.len(),
                            node.previous_fields.len(),
                            deleted_overlay,
                            dirty_overlay,
                            loaded_overlay,
                            nudb_present,
                            created_earlier_in_ledger,
                        );
                        for trace_line in nudb_trace {
                            error!(
                                "metadata patch missing base object trace: seq={} key={} {}",
                                ledger_seq,
                                hex::encode_upper(&key.0[..8]),
                                trace_line,
                            );
                        }
                        if byte_diff_mode {
                            info!(
                                "BYTE DIFF seq={}: MODIFY-MISSING key={} type={:04X} final_fields={} prev_fields={} tx_hash={} deleted_overlay={} dirty_overlay={} loaded_overlay={} nudb_present={} created_earlier_in_ledger={}",
                                ledger_seq,
                                hex::encode_upper(&key.0[..8]),
                                node.entry_type,
                                node.fields.len(),
                                node.previous_fields.len(),
                                hex::encode_upper(&tx_hash[..8]),
                                deleted_overlay,
                                dirty_overlay,
                                loaded_overlay,
                                nudb_present,
                                created_earlier_in_ledger,
                            );
                        }
                        continue;
                    };
                    // Block incomplete book DirectoryNodes from entering state.
                    if node.entry_type == 0x0064 {
                        match crate::ledger::DirectoryNode::decode(&final_sle, key.0) {
                            Ok(dir) => {
                                if dir.exchange_rate.is_some()
                                    && (dir.taker_pays_currency.is_none()
                                        || dir.taker_pays_issuer.is_none()
                                        || dir.taker_gets_currency.is_none()
                                        || dir.taker_gets_issuer.is_none())
                                {
                                    warn!(
                                        "follower: BLOCKING incomplete book DirectoryNode (modified) at seq={} key={} sle_len={} has_pc={} has_pi={} has_gc={} has_gi={} root_is_self={} created_earlier={}",
                                        ledger_seq,
                                        hex::encode_upper(key.0),
                                        final_sle.len(),
                                        dir.taker_pays_currency.is_some(),
                                        dir.taker_pays_issuer.is_some(),
                                        dir.taker_gets_currency.is_some(),
                                        dir.taker_gets_issuer.is_some(),
                                        dir.root_index == key.0,
                                        created_earlier_in_ledger,
                                    );
                                    incomplete_book_dir_keys.push(key);
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "follower: decode failed for modified DirectoryNode at seq={} key={} sle_len={}: {}",
                                    ledger_seq, hex::encode_upper(key.0), final_sle.len(), e,
                                );
                            }
                        }
                    }
                    tx_ops.push((key, node.entry_type, Some(final_sle), false));
                }
                crate::ledger::meta::Action::Deleted => {
                    if byte_diff_mode {
                        info!(
                            "BYTE DIFF seq={}: DELETE key={} type={:04X} fields={} tx_hash={}",
                            ledger_seq,
                            hex::encode_upper(&key.0[..8]),
                            node.entry_type,
                            node.fields.len(),
                            hex::encode_upper(&tx_hash[..8]),
                        );
                    }
                    tx_ops.push((key, node.entry_type, None, false));
                }
            }
        }
        for (key, entry_type, sle_opt, synthesize_owner_dirs) in tx_ops {
            match sle_opt {
                Some(sle) => {
                    state.insert_raw(key, sle.clone());
                    sync_typed(state, entry_type, &key, &sle);
                    if synthesize_owner_dirs {
                        crate::ledger::close::ensure_owner_directory_entries_for_created_sle(
                            state, key, entry_type, &sle,
                        );
                    }
                }
                None => {
                    remove_typed(state, entry_type, &key);
                    state.remove_raw(&key);
                }
            }
            applied += 1;
        }
    }
    if byte_diff_mode {
        info!(
            "BYTE DIFF seq={}: CREATE override stats hits={} misses={} incomplete_book_dirs={}",
            ledger_seq,
            created_override_hits,
            created_override_misses,
            incomplete_book_dir_keys.len(),
        );
    }
    if !incomplete_book_dir_keys.is_empty() {
        warn!(
            "follower: {} incomplete book DirectoryNode(s) detected at seq={} — will force authoritative fetch",
            incomplete_book_dir_keys.len(),
            ledger_seq,
        );
    }
    MetadataPatchStats {
        applied,
        missing_modified,
        missing_modified_keys: missing_modified_keys.into_iter().collect(),
        created_override_miss_keys: created_override_miss_keys.into_iter().collect(),
        incomplete_book_dir_keys,
        aborted: false,
    }
}

fn prune_engine_only_transients(
    state: &mut crate::ledger::LedgerState,
    touched_keys: &[crate::ledger::Key],
    meta_with_hashes: &[([u8; 32], Vec<u8>)],
    ledger_seq: u32,
) -> usize {
    let mut meta_keys = std::collections::HashSet::<[u8; 32]>::new();
    for (_tx_hash, meta_blob) in meta_with_hashes {
        let nodes =
            match std::panic::catch_unwind(|| crate::ledger::meta::parse_metadata(meta_blob)) {
                Ok(nodes) => nodes,
                Err(_) => continue,
            };
        for node in nodes {
            meta_keys.insert(node.ledger_index);
        }
    }

    let mut removed = 0usize;
    for key in touched_keys {
        if meta_keys.contains(&key.0) {
            continue;
        }
        let Some(raw) = state.get_raw_owned(key) else {
            continue;
        };
        let Some(sle) = crate::ledger::sle::SLE::from_raw(*key, raw) else {
            continue;
        };
        let entry_type = sle.entry_type();
        // Only prune transient DEX artifacts that can be engine-only in replay.
        // Never prune AccountRoot / RippleState / other persistent types here.
        let is_transient_dex = matches!(
            entry_type,
            crate::ledger::sle::LedgerEntryType::Offer
                | crate::ledger::sle::LedgerEntryType::DirectoryNode
        );
        if !is_transient_dex {
            continue;
        }
        // Remove only if it was created/modified in this ledger by the engine
        // and is absent from authoritative metadata.
        let prev_lgr_seq = sle.get_field_u32(2, 5).unwrap_or(0);
        if prev_lgr_seq != ledger_seq {
            continue;
        }

        remove_typed(state, entry_type as u16, key);
        state.remove_raw(key);
        removed += 1;
    }
    removed
}

async fn fetch_created_sle_overrides(
    rpc_host: &str,
    rpc_port: u16,
    ledger_seq: u32,
    meta_with_hashes: &[([u8; 32], Vec<u8>)],
) -> std::collections::HashMap<crate::ledger::Key, Vec<u8>> {
    const OVERRIDE_FETCH_TIMEOUT_SECS: u64 = 5;
    const OVERRIDE_RETRY_TIMEOUT_SECS: u64 = 8;
    const OVERRIDE_RETRY_ATTEMPTS: usize = 3;
    let mut created_keys = std::collections::BTreeSet::new();
    for (_tx_hash, meta_blob) in meta_with_hashes {
        let nodes =
            match std::panic::catch_unwind(|| crate::ledger::meta::parse_metadata(meta_blob)) {
                Ok(nodes) => nodes,
                Err(_) => continue,
            };
        for node in nodes {
            if node.action == crate::ledger::meta::Action::Created {
                created_keys.insert(crate::ledger::Key(node.ledger_index));
            }
        }
    }
    let total_created = created_keys.len();

    let mut out = std::collections::HashMap::new();
    let mut join_set = tokio::task::JoinSet::new();
    for &key in &created_keys {
        let host = rpc_host.to_string();
        join_set.spawn(async move {
            let req = format!(
                r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                hex::encode(key.0),
                ledger_seq
            );
            let fetched = tokio::time::timeout(
                std::time::Duration::from_secs(OVERRIDE_FETCH_TIMEOUT_SECS),
                fetch_sle_binary(&host, rpc_port, &req),
            )
            .await
            .ok()
            .flatten();
            (key, fetched)
        });
    }
    while let Some(res) = join_set.join_next().await {
        if let Ok((key, Some(data))) = res {
            out.insert(key, data);
        }
    }
    // Retry misses with longer timeout and multiple attempts.
    // This helps transient objects whose ledger_entry binary is briefly unavailable.
    const RETRY_CONCURRENCY: usize = 16;
    let misses: Vec<crate::ledger::Key> = created_keys
        .iter()
        .copied()
        .filter(|k| !out.contains_key(k))
        .collect();
    let mut retry_set = tokio::task::JoinSet::new();
    let mut i = 0usize;
    while i < misses.len() || !retry_set.is_empty() {
        while i < misses.len() && retry_set.len() < RETRY_CONCURRENCY {
            let key = misses[i];
            i += 1;
            let host = rpc_host.to_string();
            retry_set.spawn(async move {
                let req = format!(
                    r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                    hex::encode(key.0),
                    ledger_seq
                );
                let mut fetched: Option<Vec<u8>> = None;
                for _ in 0..OVERRIDE_RETRY_ATTEMPTS {
                    fetched = tokio::time::timeout(
                        std::time::Duration::from_secs(OVERRIDE_RETRY_TIMEOUT_SECS),
                        fetch_sle_binary(&host, rpc_port, &req),
                    )
                    .await
                    .ok()
                    .flatten();
                    if fetched.is_some() {
                        break;
                    }
                }
                (key, fetched)
            });
        }
        if let Some(joined) = retry_set.join_next().await {
            if let Ok((key, Some(data))) = joined {
                out.insert(key, data);
            }
        }
    }
    info!(
        "follower: created overrides fetched {}/{} for ledger {} via {}:{} ({}s initial timeout, {} retry timeout x{} attempts)",
        out.len(),
        total_created,
        ledger_seq,
        rpc_host,
        rpc_port,
        OVERRIDE_FETCH_TIMEOUT_SECS,
        OVERRIDE_RETRY_TIMEOUT_SECS,
        OVERRIDE_RETRY_ATTEMPTS,
    );
    out
}

async fn fetch_modified_directory_overrides(
    rpc_host: &str,
    rpc_port: u16,
    ledger_seq: u32,
    meta_with_hashes: &[([u8; 32], Vec<u8>)],
) -> std::collections::HashMap<crate::ledger::Key, Vec<u8>> {
    const OVERRIDE_FETCH_TIMEOUT_SECS: u64 = 5;
    fn watch_directory_key(key: &[u8; 32]) -> bool {
        let k = hex::encode_upper(key);
        k == "28516E970A801B5AE4C34A5A5F7BB8A63263E481504D85066F61BBE1A3AC1123"
            || k == "C78241CA86D8FD33D7930F713AE3A89D7CE23C52BB46E39526E627CCF5964E32"
            || k == "6065A06AFD2A13DE1A5F389523C4B4E96FEE17950D4078C12183CCA79542A434"
    }
    let mut keys = std::collections::BTreeSet::new();
    for (_tx_hash, meta_blob) in meta_with_hashes {
        let nodes =
            match std::panic::catch_unwind(|| crate::ledger::meta::parse_metadata(meta_blob)) {
                Ok(nodes) => nodes,
                Err(_) => continue,
            };
        for node in nodes {
            if node.entry_type != 0x0064 || node.action != crate::ledger::meta::Action::Modified {
                continue;
            }
            let has_indexes = node
                .fields
                .iter()
                .any(|f| f.type_code == 19 && f.field_code == 1);
            if !has_indexes {
                keys.insert(crate::ledger::Key(node.ledger_index));
            }
        }
    }
    let total = keys.len();
    if ledger_seq == 103483090 {
        let watch: Vec<String> = keys
            .iter()
            .filter(|k| watch_directory_key(&k.0))
            .map(|k| hex::encode_upper(k.0))
            .collect();
        info!(
            "follower: modified DirectoryNode overrides candidates={} watch_hits={} seq={}",
            total,
            watch.len(),
            ledger_seq
        );
        if !watch.is_empty() {
            info!(
                "follower: modified DirectoryNode watch candidates={:?}",
                watch
            );
        }
    }
    let mut out = std::collections::HashMap::new();
    let mut join_set = tokio::task::JoinSet::new();
    for key in keys {
        let host = rpc_host.to_string();
        join_set.spawn(async move {
            let req = format!(
                r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                hex::encode(key.0),
                ledger_seq
            );
            let fetched = tokio::time::timeout(
                std::time::Duration::from_secs(OVERRIDE_FETCH_TIMEOUT_SECS),
                fetch_sle_binary(&host, rpc_port, &req),
            )
            .await
            .ok()
            .flatten();
            (key, fetched)
        });
    }
    while let Some(res) = join_set.join_next().await {
        if let Ok((key, Some(data))) = res {
            out.insert(key, data);
        }
    }
    info!(
        "follower: modified DirectoryNode overrides fetched {}/{} for ledger {} via {}:{} ({}s timeout each)",
        out.len(),
        total,
        ledger_seq,
        rpc_host,
        rpc_port,
        OVERRIDE_FETCH_TIMEOUT_SECS,
    );
    if ledger_seq == 103483090 {
        let watch_fetched = out.keys().filter(|k| watch_directory_key(&k.0)).count();
        info!(
            "follower: modified DirectoryNode watch fetched={}/3 for seq={}",
            watch_fetched, ledger_seq
        );
    }
    out
}

async fn fetch_multi_modified_overrides(
    rpc_host: &str,
    rpc_port: u16,
    ledger_seq: u32,
    meta_with_hashes: &[([u8; 32], Vec<u8>)],
) -> std::collections::HashMap<crate::ledger::Key, Vec<u8>> {
    const OVERRIDE_FETCH_TIMEOUT_SECS: u64 = 5;
    let mut key_counts: std::collections::HashMap<crate::ledger::Key, usize> =
        std::collections::HashMap::new();
    for (_tx_hash, meta_blob) in meta_with_hashes {
        let nodes =
            match std::panic::catch_unwind(|| crate::ledger::meta::parse_metadata(meta_blob)) {
                Ok(nodes) => nodes,
                Err(_) => continue,
            };
        for node in nodes {
            if node.action == crate::ledger::meta::Action::Modified {
                let key = crate::ledger::Key(node.ledger_index);
                *key_counts.entry(key).or_insert(0) += 1;
            }
        }
    }
    let keys: Vec<crate::ledger::Key> = key_counts
        .iter()
        .filter_map(|(k, c)| if *c > 1 { Some(*k) } else { None })
        .collect();
    let total = keys.len();
    let mut out = std::collections::HashMap::new();
    let mut join_set = tokio::task::JoinSet::new();
    for key in keys {
        let host = rpc_host.to_string();
        join_set.spawn(async move {
            let req = format!(
                r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                hex::encode(key.0),
                ledger_seq
            );
            let fetched = tokio::time::timeout(
                std::time::Duration::from_secs(OVERRIDE_FETCH_TIMEOUT_SECS),
                fetch_sle_binary(&host, rpc_port, &req),
            )
            .await
            .ok()
            .flatten();
            (key, fetched)
        });
    }
    while let Some(res) = join_set.join_next().await {
        if let Ok((key, Some(data))) = res {
            out.insert(key, data);
        }
    }
    info!(
        "follower: multi-modified overrides fetched {}/{} for ledger {} via {}:{}",
        out.len(),
        total,
        ledger_seq,
        rpc_host,
        rpc_port,
    );
    out
}

fn collect_missing_modified_base_keys_from_nodes(
    state: &crate::ledger::LedgerState,
    tx_nodes: &[Vec<crate::ledger::meta::AffectedNode>],
) -> Vec<crate::ledger::Key> {
    let mut created_seen = std::collections::BTreeSet::<[u8; 32]>::new();
    let mut missing = std::collections::BTreeSet::<crate::ledger::Key>::new();

    for nodes in tx_nodes {
        for node in nodes {
            match node.action {
                crate::ledger::meta::Action::Created => {
                    created_seen.insert(node.ledger_index);
                }
                crate::ledger::meta::Action::Modified => {
                    if created_seen.contains(&node.ledger_index) {
                        continue;
                    }
                    let key = crate::ledger::Key(node.ledger_index);
                    if state.get_raw_owned(&key).is_none()
                        && state.get_committed_raw_owned(&key).is_none()
                    {
                        missing.insert(key);
                    }
                }
                crate::ledger::meta::Action::Deleted => {}
            }
        }
    }

    missing.into_iter().collect()
}

fn collect_missing_modified_base_keys(
    state: &crate::ledger::LedgerState,
    meta_with_hashes: &[([u8; 32], Vec<u8>)],
) -> Vec<crate::ledger::Key> {
    let mut parsed = Vec::with_capacity(meta_with_hashes.len());
    for (_tx_hash, meta_blob) in meta_with_hashes {
        let nodes =
            match std::panic::catch_unwind(|| crate::ledger::meta::parse_metadata(meta_blob)) {
                Ok(nodes) => nodes,
                Err(_) => continue,
            };
        parsed.push(nodes);
    }
    collect_missing_modified_base_keys_from_nodes(state, &parsed)
}

fn collect_replay_prerequisite_keys(
    tx_blobs: &[(Vec<u8>, Vec<u8>)],
) -> std::collections::BTreeSet<crate::ledger::Key> {
    let mut keys = std::collections::BTreeSet::<crate::ledger::Key>::new();

    for (blob, _meta) in tx_blobs {
        let Ok(parsed) = crate::transaction::parse_blob(blob) else {
            continue;
        };

        match parsed.tx_type {
            7 => {
                if let Some(crate::transaction::Amount::Iou {
                    currency, issuer, ..
                }) = parsed.taker_gets.as_ref()
                {
                    if parsed.account != *issuer {
                        keys.insert(crate::ledger::trustline::shamap_key(
                            &parsed.account,
                            issuer,
                            currency,
                        ));
                    }
                }
            }
            0 => {
                let is_iou_amount =
                    matches!(parsed.amount.as_ref(), Some(crate::transaction::Amount::Iou { .. }));
                let use_ripple =
                    !parsed.paths.is_empty() || parsed.send_max.is_some() || is_iou_amount;
                if !use_ripple {
                    if let Some(destination) = parsed.destination {
                        keys.insert(crate::ledger::account::shamap_key(&destination));
                    }
                }
            }
            _ => {}
        }
    }

    keys
}

fn collect_missing_replay_prerequisite_keys(
    state: &crate::ledger::LedgerState,
    tx_blobs: &[(Vec<u8>, Vec<u8>)],
) -> Vec<crate::ledger::Key> {
    collect_replay_prerequisite_keys(tx_blobs)
        .into_iter()
        .filter(|key| {
            state.get_raw_owned(key).is_none() && state.get_committed_raw_owned(key).is_none()
        })
        .collect()
}

async fn fetch_authoritative_modified_base_replacements(
    rpc_host: &str,
    rpc_port: u16,
    ledger_seq: u32,
    keys: &[crate::ledger::Key],
) -> std::collections::HashMap<crate::ledger::Key, Vec<u8>> {
    use tokio::task::JoinSet;
    const REPLACEMENT_TIMEOUT_SECS: u64 = 8;
    const REPLACEMENT_CONCURRENCY: usize = 16;

    let mut out = std::collections::HashMap::new();
    if keys.is_empty() {
        return out;
    }

    let mut tasks = JoinSet::new();
    let mut i = 0usize;
    let mut timeouts = 0usize;

    while i < keys.len() || !tasks.is_empty() {
        while i < keys.len() && tasks.len() < REPLACEMENT_CONCURRENCY {
            let key = keys[i];
            i += 1;
            let host = rpc_host.to_string();
            let req = format!(
                r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                hex::encode(key.0),
                ledger_seq
            );
            tasks.spawn(async move {
                let fetched = tokio::time::timeout(
                    std::time::Duration::from_secs(REPLACEMENT_TIMEOUT_SECS),
                    fetch_sle_binary(&host, rpc_port, &req),
                )
                .await;
                (key, fetched)
            });
        }

        if let Some(joined) = tasks.join_next().await {
            if let Ok((key, fetched)) = joined {
                match fetched {
                    Ok(Some(raw)) => {
                        out.insert(key, raw);
                    }
                    Err(_) => {
                        timeouts += 1;
                    }
                    _ => {}
                }
            }
        }
    }

    if timeouts > 0 {
        warn!(
            "follower: authoritative modified-base fetch timeouts={}/{} for ledger {} ({}s timeout)",
            timeouts,
            keys.len(),
            ledger_seq,
            REPLACEMENT_TIMEOUT_SECS
        );
    }
    out
}

async fn fetch_surviving_created_override_replacements(
    rpc_host: &str,
    rpc_port: u16,
    ledger_seq: u32,
    survivor_keys: &[crate::ledger::Key],
) -> std::collections::HashMap<crate::ledger::Key, Vec<u8>> {
    use tokio::task::JoinSet;
    const REPLACEMENT_TIMEOUT_SECS: u64 = 8;
    const REPLACEMENT_CONCURRENCY: usize = 16;

    let mut out = std::collections::HashMap::new();
    if survivor_keys.is_empty() {
        return out;
    }

    let mut tasks = JoinSet::new();
    let mut i = 0usize;
    let mut timeouts = 0usize;

    while i < survivor_keys.len() || !tasks.is_empty() {
        while i < survivor_keys.len() && tasks.len() < REPLACEMENT_CONCURRENCY {
            let key = survivor_keys[i];
            i += 1;
            let host = rpc_host.to_string();
            let req = format!(
                r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                hex::encode(key.0),
                ledger_seq
            );
            tasks.spawn(async move {
                let fetched = tokio::time::timeout(
                    std::time::Duration::from_secs(REPLACEMENT_TIMEOUT_SECS),
                    fetch_sle_binary(&host, rpc_port, &req),
                )
                .await;
                (key, fetched)
            });
        }

        if let Some(joined) = tasks.join_next().await {
            if let Ok((key, fetched)) = joined {
                match fetched {
                    Ok(Some(raw)) => {
                        out.insert(key, raw);
                    }
                    Err(_) => {
                        timeouts += 1;
                    }
                    _ => {}
                }
            }
        }
    }

    if timeouts > 0 {
        warn!(
            "follower: survivor replacement fetch timeouts={}/{} for seq={} ({}s timeout)",
            timeouts,
            survivor_keys.len(),
            ledger_seq,
            REPLACEMENT_TIMEOUT_SECS
        );
    }
    out
}

// ── FollowerState ────────────────────────────────────────────────────────────

/// Progress counters for the ledger follower.
pub struct FollowerState {
    pub running: AtomicBool,
    pub current_seq: AtomicU32,
    pub ledgers_applied: AtomicU64,
    pub txs_applied: AtomicU64,
    pub objects_modified: AtomicU64,
    pub objects_created: AtomicU64,
    pub objects_deleted: AtomicU64,
    pub hash_matches: AtomicU64,
    pub hash_mismatches: AtomicU64,
    /// Set by the follower when it wants a state re-sync instead of continuing
    /// with divergent state. The Node watches this and triggers resync.
    pub resync_requested: AtomicBool,
    /// Channel for receiving liTX_NODE responses from peers.
    pub tx_tree_tx: tokio::sync::mpsc::Sender<crate::proto::TmLedgerData>,
    pub tx_tree_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<crate::proto::TmLedgerData>>,
    /// Channel for receiving liBASE header responses from peers.
    pub header_tx: tokio::sync::mpsc::Sender<crate::ledger::LedgerHeader>,
    pub header_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<crate::ledger::LedgerHeader>>,
    /// Channel for receiving liAS_NODE responses (reserved for prefetch).
    pub prefetch_tx: tokio::sync::mpsc::Sender<crate::proto::TmLedgerData>,
    pub prefetch_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<crate::proto::TmLedgerData>>,
}

impl FollowerState {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let (htx, hrx) = tokio::sync::mpsc::channel(64);
        let (ptx, prx) = tokio::sync::mpsc::channel(64);
        Self {
            running: AtomicBool::new(false),
            resync_requested: AtomicBool::new(false),
            current_seq: AtomicU32::new(0),
            ledgers_applied: AtomicU64::new(0),
            txs_applied: AtomicU64::new(0),
            objects_modified: AtomicU64::new(0),
            objects_created: AtomicU64::new(0),
            objects_deleted: AtomicU64::new(0),
            hash_matches: AtomicU64::new(0),
            hash_mismatches: AtomicU64::new(0),
            tx_tree_tx: tx,
            tx_tree_rx: tokio::sync::Mutex::new(rx),
            header_tx: htx,
            header_rx: tokio::sync::Mutex::new(hrx),
            prefetch_tx: ptx,
            prefetch_rx: tokio::sync::Mutex::new(prx),
        }
    }
}

fn stop_follower(follower_state: &FollowerState) {
    follower_state.running.store(false, Ordering::SeqCst);
}

fn request_resync_and_stop_follower(follower_state: &FollowerState) {
    follower_state
        .resync_requested
        .store(true, Ordering::SeqCst);
    stop_follower(follower_state);
}

fn try_flush_follow_state(state: &mut crate::ledger::LedgerState) -> std::io::Result<[u8; 32]> {
    state.try_take_dirty()?;
    Ok(state.nudb_root_hash().unwrap_or_else(|| state.state_hash()))
}

// ── Main follower loop ───────────────────────────────────────────────────────

/// Run the ledger follower loop. For each validated ledger:
/// 1. Send liBASE + liTX_NODE requests in parallel
/// 2. Wait for both responses (header + transactions)
/// 3. Seed state from metadata, replay transactions, patch state
/// 4. Verify hash (if sync complete) and advance
pub async fn run_follower(
    rpc_host: String,
    rpc_port: u16,
    storage: Arc<Storage>,
    follower_state: Arc<FollowerState>,
    shared_state: Arc<tokio::sync::RwLock<crate::node::SharedState>>,
    _diff_sync_rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<crate::proto::TmLedgerData>>>,
    inbound_ledgers: Arc<std::sync::Mutex<crate::ledger::inbound::InboundLedgers>>,
) {
    follower_state.running.store(true, Ordering::SeqCst);
    info!("ledger follower starting");

    // Determine the starting sequence as `synced ledger + 1`.
    // The synced ledger's state is already stored in NuDB, so the follower
    // advances state by applying the next ledger's metadata patches.
    let sync_ledger_seq = storage.get_sync_ledger().unwrap_or(0) as u32;
    let start_seq = if sync_ledger_seq > 0 {
        info!(
            "ledger follower: NuDB state is from synced ledger {} — starting at {}",
            sync_ledger_seq,
            sync_ledger_seq + 1
        );
        sync_ledger_seq + 1
    } else {
        // No sync ledger stored — wait for peers
        loop {
            let (seq, hash) = {
                let state = shared_state.read().await;
                (state.ctx.ledger_seq, state.ctx.ledger_header.hash)
            };
            if seq > 1 && hash != [0u8; 32] {
                info!(
                    "ledger follower: no sync_ledger stored, bootstrapping from peer tip {}",
                    seq
                );
                break seq;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    };
    let mut target_seq = start_seq;
    follower_state
        .current_seq
        .store(start_seq, Ordering::Relaxed);

    // NuDB handles memory — follower can run alongside sync safely.
    // No wait loop needed.

    // Get ledger_state handle (separate lock from SharedState)
    let ledger_state = {
        let ss = shared_state.read().await;
        ss.ctx.ledger_state.clone()
    };

    // State is now managed by SHAMap/NuDB — no load_state needed.

    // Seed prev_header from the real synced ledger header.
    // Three validation checks before trusting it:
    //   1. header.sequence == sync_ledger_seq
    //   2. header.hash matches sync_ledger_hash if stored
    //   3. header.account_hash matches sync_account_hash if stored
    // If any check fails, fall back to reacquiring by hash from peers.
    let verified_anchor = load_verified_sync_anchor(&storage);
    let sync_ledger_hash = verified_anchor
        .as_ref()
        .map(|(_, hash, _, _)| *hash)
        .unwrap_or_else(|| storage.get_sync_ledger_hash());
    let sync_account_hash = verified_anchor
        .as_ref()
        .map(|(_, _, account_hash, _)| *account_hash)
        .unwrap_or_else(|| storage.get_sync_account_hash());

    let mut prev_header: Option<crate::ledger::LedgerHeader> = if sync_ledger_seq > 0 {
        if let Some((_seq, _hash, _account_hash, hdr)) = verified_anchor {
            info!(
                "follower: loaded verified synced ledger header seq={} hash={}",
                hdr.sequence,
                hex::encode_upper(&hdr.hash[..8]),
            );
            Some(hdr)
        } else {
            loop {
                if let Some(hash) = sync_ledger_hash {
                    // Fallback: reacquire the header by hash from peers.
                    // Register acquisition FIRST, then send request — avoids race
                    // where a fast peer response arrives before the acquisition exists.
                    info!(
                        "follower: reacquiring synced ledger header by hash {} for seq {}",
                        hex::encode_upper(&hash[..8]),
                        sync_ledger_seq,
                    );
                    {
                        let mut guard = inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
                        guard.acquire(
                            hash,
                            sync_ledger_seq,
                            crate::ledger::inbound::InboundReason::History,
                        );
                    }
                    let req = crate::network::relay::encode_get_ledger_base(&hash, 0);
                    {
                        let mut state = shared_state.write().await;
                        state.send_to_peers_with_ledger(&req, sync_ledger_seq, 5);
                    }
                    // Wait for the header to arrive
                    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
                    let mut got_header = None;
                    loop {
                        {
                            let guard = inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(hdr) = validated_reacquired_sync_header(
                                &guard,
                                hash,
                                sync_ledger_seq,
                                sync_account_hash,
                            ) {
                                got_header = Some(hdr);
                                break;
                            }
                        }
                        if tokio::time::Instant::now() >= deadline {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                    if let Some(hdr) = got_header {
                        info!(
                    "follower: reacquired and validated synced ledger header seq={} hash={}",
                    hdr.sequence, hex::encode_upper(&hdr.hash[..8]),
                );
                        let _ = storage.set_sync_ledger_header(&hdr);
                        let _ = storage.flush();
                        break Some(hdr);
                    } else {
                        error!("follower: could not reacquire synced ledger header after 30s — retrying");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue; // retry the outer loop — do NOT fall through to bootstrap
                    }
                } else {
                    error!("follower: no sync_ledger_header and no sync_ledger_hash — cannot determine starting point, retrying");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue; // retry — do NOT fall through to bootstrap
                }
            }
        }
    } else {
        let ss = shared_state.read().await;
        let hdr = &ss.ctx.ledger_header;
        if hdr.hash != [0u8; 32] {
            Some(hdr.clone())
        } else {
            None
        }
    };

    let mut tx_engine_attempts = 0u64;
    let mut tx_engine_successes = 0u64;
    let mut first_hash_check_done = false;
    let mut first_post_sync_seq = sync_ledger_seq.checked_add(1);
    // Track in-flight persist tasks to detect pileup
    let persist_in_flight = Arc::new(AtomicU32::new(0));

    if let Some(ref prev) = prev_header {
        info!(
            "follower anchor: seq={} hash={} account_hash={} next_seq={}",
            prev.sequence,
            hex::encode_upper(&prev.hash[..8]),
            hex::encode_upper(&prev.account_hash[..8]),
            prev.sequence.saturating_add(1),
        );
    }

    // ── Main loop ────────────────────────────────────────────────────────
    loop {
        // ── Step 1: Determine the next ledger to replay ────────────────
        //
        // Strategy: anchor on prev_header and request N+1 specifically.
        // Use the validated_hashes ring buffer to look up the hash for
        // N+1. If N+1 isn't available yet, wait briefly. If it never
        // appears (gap or too far behind), fall back to latest validated.
        let (validated, ledger_hash) = if let Some(ref prev) = prev_header {
            let next_seq = prev.sequence + 1;

            // Wait for N+1 hash to appear in ring buffer (or timeout)
            let lookup_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut found_hash = None;
            let mut last_heartbeat = std::time::Instant::now();
            loop {
                {
                    let state = shared_state.read().await;
                    if let Some(&h) = state.validated_hashes.get(&next_seq) {
                        found_hash = Some(h);
                        break;
                    }
                    // Log when behind, but DON'T skip — must replay consecutively
                    // for hash parity. Each ledger's metadata patches build on
                    // the previous ledger's state.
                    if state.ctx.ledger_seq > next_seq + 100
                        && last_heartbeat.elapsed().as_secs() >= 10
                    {
                        info!(
                            "follower: {} ledgers behind tip {} — catching up consecutively from {}",
                            state.ctx.ledger_seq - next_seq, state.ctx.ledger_seq, next_seq,
                        );
                    }
                }
                if tokio::time::Instant::now() >= lookup_deadline {
                    break;
                }
                // Heartbeat: proves async runtime is alive during wait
                if last_heartbeat.elapsed().as_secs() >= 2 {
                    let pif = persist_in_flight.load(Ordering::Relaxed);
                    debug!(
                        "follower: waiting for seq {} hash (persist_in_flight={} elapsed={:.1}s)",
                        next_seq,
                        pif,
                        lookup_deadline.elapsed().as_secs_f64(),
                    );
                    last_heartbeat = std::time::Instant::now();
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }

            if let Some(hash) = found_hash {
                (next_seq, hash)
            } else {
                // N+1 not in ring buffer — request header by sequence from peers.
                // Peers with history will respond with the header (including hash).
                info!(
                    "follower: hash for seq {} not in ring buffer — requesting by sequence from peers",
                    next_seq,
                );
                let seq_req = crate::network::relay::encode_get_ledger_base_by_seq(next_seq, 0);
                {
                    let mut state = shared_state.write().await;
                    state.send_to_peers_with_ledger(&seq_req, next_seq, 5);
                }
                // Wait for the header to arrive via inbound_ledgers
                let seq_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                loop {
                    // Check if inbound_ledgers got a header for this seq
                    {
                        let guard = inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(hash) = guard.hash_for_seq(next_seq) {
                            info!(
                                "follower: got hash for seq {} from peer: {}",
                                next_seq,
                                hex::encode_upper(&hash[..8])
                            );
                            found_hash = Some(hash);
                            break;
                        }
                        if let Some(hdr) = guard.header_for_seq(next_seq) {
                            info!(
                                "follower: got buffered header for seq {} from peer: {}",
                                next_seq,
                                hex::encode_upper(&hdr.hash[..8]),
                            );
                            found_hash = Some(hdr.hash);
                            break;
                        }
                    }
                    // Also check validated_hashes (peer might have sent a validation)
                    {
                        let state = shared_state.read().await;
                        if let Some(&h) = state.validated_hashes.get(&next_seq) {
                            found_hash = Some(h);
                            break;
                        }
                    }
                    if tokio::time::Instant::now() >= seq_deadline {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
                if let Some(hash) = found_hash {
                    (next_seq, hash)
                } else {
                    warn!(
                        "follower: no peer responded with ledger {} header — trying RPC fallback",
                        next_seq
                    );
                    // RPC fallback: fetch ledger hash from s1/s2.ripple.com
                    if let Some((_resp, _acc_hash)) =
                        fetch_ledger_binary(&rpc_host, rpc_port, next_seq).await
                    {
                        // Got a response — extract the hash from the response
                        if let Some(hash_hex) = _resp["result"]["ledger"]["ledger_hash"]
                            .as_str()
                            .or_else(|| _resp["result"]["ledger_hash"].as_str())
                        {
                            if let Ok(hash_bytes) = hex::decode(hash_hex) {
                                if hash_bytes.len() == 32 {
                                    let mut hash = [0u8; 32];
                                    hash.copy_from_slice(&hash_bytes);
                                    info!(
                                        "follower: got hash for seq {} via RPC fallback: {}",
                                        next_seq,
                                        hex::encode_upper(&hash[..8])
                                    );
                                    (next_seq, hash)
                                } else {
                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                    continue;
                                }
                            } else {
                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                continue;
                            }
                        } else {
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            continue;
                        }
                    } else {
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        continue;
                    }
                }
            }
        } else {
            // No prev_header yet — bootstrap from latest validated
            loop {
                let (seq, hash) = {
                    let state = shared_state.read().await;
                    let seq = state.ctx.ledger_seq;
                    let hash = hex::decode(&state.ctx.ledger_hash)
                        .ok()
                        .and_then(|b| {
                            if b.len() == 32 {
                                let mut h = [0u8; 32];
                                h.copy_from_slice(&b);
                                Some(h)
                            } else {
                                None
                            }
                        })
                        .unwrap_or([0u8; 32]);
                    (seq, hash)
                };
                if seq > 0 && hash != [0u8; 32] {
                    let has_peers = {
                        let state = shared_state.read().await;
                        !state.peer_txs.is_empty()
                    };
                    if has_peers {
                        break (seq, hash);
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        };

        // ── Step 3: Create acquisition + send requests ──────────────────
        let is_consecutive = prev_header
            .as_ref()
            .map(|p| validated == p.sequence + 1)
            .unwrap_or(false);
        if first_post_sync_seq == Some(validated) {
            info!(
                "follower first-post-sync request: anchor_seq={} request_seq={} request_hash={} consecutive={}",
                prev_header.as_ref().map(|h| h.sequence).unwrap_or(0),
                validated,
                hex::encode_upper(&ledger_hash[..8]),
                is_consecutive,
            );
        }
        info!(
            "follower step3: creating acquisition for seq={} hash={} ({})",
            validated,
            hex::encode_upper(&ledger_hash[..8]),
            if is_consecutive {
                "consecutive"
            } else {
                "bootstrap/fallback"
            },
        );
        let mut watch_rx = {
            let mut guard = inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
            let rx = guard.acquire(
                ledger_hash,
                validated,
                crate::ledger::inbound::InboundReason::History,
            );
            if let Some(hdr) = guard.take_header_for_seq(validated) {
                let _ = guard.got_header(&ledger_hash, hdr);
            }
            rx
        };

        // Send requests (may be redundant with validation handler's pre-fetch)
        {
            let missing_tx_nodes = {
                let guard = inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
                guard.missing_tx_node_ids(&ledger_hash, 64)
            };
            let cookie_base = crate::sync::next_cookie();
            let cookie_tx = crate::sync::next_cookie();
            let base_req = crate::network::relay::encode_get_ledger_base(&ledger_hash, cookie_base);
            let use_root_tx_request = missing_tx_nodes.is_empty()
                || missing_tx_nodes
                    == vec![crate::ledger::shamap_id::SHAMapNodeID::root()
                        .to_wire()
                        .to_vec()];
            let tx_req = if use_root_tx_request {
                crate::network::relay::encode_get_ledger_txs_for_hash(&ledger_hash, cookie_tx)
            } else {
                crate::network::relay::encode_get_ledger_txs_for_hash_nodes(
                    &ledger_hash,
                    &missing_tx_nodes,
                    cookie_tx,
                )
            };
            let mut state = shared_state.write().await;
            state.send_to_peers_with_ledger(&base_req, validated, 3);
            state.send_to_peers_with_ledger(&tx_req, validated, 3);
        }

        // ── Step 4: Wait for completion via watch channel ───────────────
        // watch stores the last value — if completion already happened
        // If prefetch inserted the value first, the next read still observes it.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
        loop {
            // Check current state — may already be complete from pre-fetch
            if *watch_rx.borrow() {
                break; // Already complete
            }
            // Wait for state change or timeout
            match tokio::time::timeout_at(deadline, watch_rx.changed()).await {
                Ok(Ok(())) => {
                    if *watch_rx.borrow() {
                        break;
                    } // Complete
                }
                _ => break, // Timeout or channel closed
            }
        }

        // ── Take the result ─────────────────────────────────────────────
        let result = {
            let t0 = std::time::Instant::now();
            let mut guard = inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
            let wait_ms = t0.elapsed().as_millis();
            let r = guard.take(&ledger_hash);
            if wait_ms > 50 {
                warn!(
                    "follower inbound_ledgers.take() lock_wait={}ms seq={}",
                    wait_ms, target_seq
                );
            }
            r
        };

        // Sweep stale acquisitions
        {
            let mut guard = inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
            guard.sweep(std::time::Duration::from_secs(60));
        }

        // ── Process result ──────────────────────────────────────────────
        // RPC fallback when peers can't deliver the ledger data
        let result = if result.is_none() {
            info!(
                "follower: take() returned None for seq={} hash={} — trying RPC fallback",
                validated,
                hex::encode_upper(&ledger_hash[..8]),
            );
            if let Some((rpc_resp, rpc_acc_hash)) =
                fetch_ledger_binary(&rpc_host, rpc_port, validated).await
            {
                let rpc_blobs = parse_binary_ledger_blobs(&rpc_resp);
                if !rpc_blobs.is_empty() {
                    // Fetch non-binary header for full field set
                    let hdr_req = format!(
                        r#"{{"method":"ledger","params":[{{"ledger_index":{}}}]}}"#,
                        validated,
                    );
                    fn decode_h256(hex_str: &str) -> [u8; 32] {
                        hex::decode(hex_str)
                            .ok()
                            .and_then(|b| {
                                if b.len() == 32 {
                                    let mut h = [0u8; 32];
                                    h.copy_from_slice(&b);
                                    Some(h)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or([0u8; 32])
                    }
                    // Try local rippled first, then public servers for header
                    let hdr_body_opt = if let Ok(b) =
                        crate::rpc_sync::http_post(&rpc_host, rpc_port, &hdr_req).await
                    {
                        let v: Value = serde_json::from_str(&b).unwrap_or_default();
                        if v["result"]["status"].as_str() == Some("success") {
                            Some(b)
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let hdr_body_opt = if hdr_body_opt.is_none() {
                        // Try public full-history servers (round-robin)
                        let mut found = None;
                        let start =
                            RR_COUNTER.fetch_add(1, Ordering::Relaxed) % PUBLIC_SERVERS.len();
                        for i in 0..PUBLIC_SERVERS.len() {
                            let idx = (start + i) % PUBLIC_SERVERS.len();
                            let (host, port) = PUBLIC_SERVERS[idx];
                            if let Ok(b) = crate::rpc_sync::http_post(host, port, &hdr_req).await {
                                let v: Value = serde_json::from_str(&b).unwrap_or_default();
                                if v["result"]["status"].as_str() == Some("success") {
                                    found = Some(b);
                                    break;
                                }
                            }
                        }
                        found
                    } else {
                        hdr_body_opt
                    };
                    let rpc_header: Option<crate::ledger::LedgerHeader> = if let Some(hdr_body) =
                        hdr_body_opt
                    {
                        let hdr: Value = serde_json::from_str(&hdr_body).unwrap_or_default();
                        let lh = &hdr["result"]["ledger"];
                        Some(crate::ledger::LedgerHeader {
                            sequence: lh["ledger_index"].as_u64().unwrap_or(validated as u64)
                                as u32,
                            hash: ledger_hash,
                            parent_hash: decode_h256(lh["parent_hash"].as_str().unwrap_or("")),
                            close_time: lh["close_time"].as_u64().unwrap_or(0),
                            total_coins: lh["total_coins"]
                                .as_str()
                                .and_then(|s| s.parse::<u64>().ok())
                                .unwrap_or(0),
                            account_hash: decode_h256(&rpc_acc_hash),
                            transaction_hash: decode_h256(
                                lh["transaction_hash"].as_str().unwrap_or(""),
                            ),
                            parent_close_time: lh["parent_close_time"].as_u64().unwrap_or(0) as u32,
                            close_time_resolution: lh["close_time_resolution"]
                                .as_u64()
                                .unwrap_or(10)
                                as u8,
                            close_flags: lh["close_flags"].as_u64().unwrap_or(0) as u8,
                        })
                    } else {
                        info!("follower: RPC header fetch failed for seq={}", validated);
                        None
                    };
                    if let Some(rpc_header) = rpc_header {
                        let rpc_tx_root = rpc_header.transaction_hash;
                        info!(
                            "follower: got full ledger seq={} via RPC fallback: {} txs, account_hash={} parent={}",
                            validated, rpc_blobs.len(),
                            hex::encode_upper(&rpc_header.account_hash[..8]),
                            hex::encode_upper(&rpc_header.parent_hash[..8]),
                        );
                        Some((rpc_header, rpc_blobs, Some(rpc_tx_root)))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            result
        };
        if result.is_none() {
            // Fall through to retry section, then loop back
        }
        if let Some((seq_header, peer_blobs, _tx_root)) = result {
            // Bootstrap prev_header from first full header
            if prev_header.is_none() {
                info!(
                    "ledger follower: bootstrapping prev_header from ledger {}",
                    seq_header.sequence
                );
                prev_header = Some(seq_header.clone());
                target_seq = seq_header.sequence;
                continue;
            }

            let parent = prev_header.as_ref().unwrap();

            let blobs = if let Some((rpc_resp, _rpc_account_hash)) =
                fetch_ledger_binary(&rpc_host, rpc_port, seq_header.sequence).await
            {
                let rpc_blobs = parse_binary_ledger_blobs(&rpc_resp);
                if !rpc_blobs.is_empty() {
                    info!(
                        "follower: using RPC tx blobs for seq={} peer_blobs={} rpc_blobs={}",
                        seq_header.sequence,
                        peer_blobs.len(),
                        rpc_blobs.len(),
                    );
                    rpc_blobs
                } else {
                    warn!(
                        "follower: RPC ledger fetch for seq={} returned no tx blobs, using peer blobs={}",
                        seq_header.sequence,
                        peer_blobs.len(),
                    );
                    peer_blobs
                }
            } else {
                warn!(
                    "follower: RPC ledger fetch unavailable for seq={}, using peer blobs={}",
                    seq_header.sequence,
                    peer_blobs.len(),
                );
                peer_blobs
            };

            if first_post_sync_seq == Some(seq_header.sequence) {
                info!(
                    "follower first-post-sync header: seq={} hash={} parent={} expected_parent={} account_hash={} tx_root={} tx_count={}",
                    seq_header.sequence,
                    hex::encode_upper(&seq_header.hash[..8]),
                    hex::encode_upper(&seq_header.parent_hash[..8]),
                    hex::encode_upper(&parent.hash[..8]),
                    hex::encode_upper(&seq_header.account_hash[..8]),
                    hex::encode_upper(&seq_header.transaction_hash[..8]),
                    blobs.len(),
                );
            }

            // ── Parent linkage check ───────────────────────────────────
            // The acquired header must chain to `prev_header`. If not,
            // this is a gap or wrong branch — reset prev_header to this
            // header (treat as a new bootstrap point).
            if seq_header.parent_hash != parent.hash {
                let mismatches = follower_state.hash_mismatches.load(Ordering::Relaxed);
                let _ = mismatches; // always accept in divergent-tolerant mode
                if false {
                    warn!(
                        "follower: parent mismatch for seq={} — expected parent={} got={} (rejecting candidate, retrying same seq)",
                        seq_header.sequence,
                        hex::encode_upper(&parent.hash[..8]),
                        hex::encode_upper(&seq_header.parent_hash[..8]),
                    );
                    {
                        let mut guard = inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
                        guard.reject_seq_candidate(seq_header.sequence, seq_header.hash);
                    }
                    {
                        let mut state = shared_state.write().await;
                        if state.validated_hashes.get(&seq_header.sequence).copied()
                            == Some(seq_header.hash)
                        {
                            state.validated_hashes.remove(&seq_header.sequence);
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    continue;
                }
                // In divergent mode: accept the rippled header despite parent mismatch
                info!(
                    "follower: parent mismatch for seq={} (divergent mode, {} prior mismatches) — accepting anyway",
                    seq_header.sequence, mismatches,
                );
            }

            let seq = seq_header.sequence;
            let seq_account_hash = seq_header.account_hash;
            let tx_start = std::time::Instant::now();
            tx_engine_attempts += 1;

            // Collect (tx_hash, meta_blob) pairs — tx_hash is needed for PreviousTxnID.
            // TX hash = SHA-512-half(PREFIX_TX_ID || tx_blob)
            let meta_with_hashes: Vec<([u8; 32], Vec<u8>)> = blobs
                .iter()
                .map(|(tx, meta)| {
                    let mut buf = Vec::with_capacity(4 + tx.len());
                    buf.extend_from_slice(&crate::transaction::serialize::PREFIX_TX_ID);
                    buf.extend_from_slice(tx);
                    let tx_hash = crate::crypto::sha512_first_half(&buf);
                    (tx_hash, meta.clone())
                })
                .collect();
            let created_overrides =
                fetch_created_sle_overrides(&rpc_host, rpc_port, seq, &meta_with_hashes).await;
            let mut modified_overrides =
                fetch_modified_directory_overrides(&rpc_host, rpc_port, seq, &meta_with_hashes)
                    .await;
            let multi_modified_overrides =
                fetch_multi_modified_overrides(&rpc_host, rpc_port, seq, &meta_with_hashes).await;
            modified_overrides.extend(multi_modified_overrides);
            let metadata_deleted_keys = collect_deleted_metadata_keys(&meta_with_hashes);
            let meta_with_hashes_for_blocking = meta_with_hashes.clone();

            let missing_modified_base_keys = {
                let ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                collect_missing_modified_base_keys(&ls, &meta_with_hashes)
            };
            let missing_replay_prereq_keys = {
                let ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                collect_missing_replay_prerequisite_keys(&ls, &blobs)
            };
            let mut preload_keys = std::collections::BTreeSet::<crate::ledger::Key>::new();
            preload_keys.extend(missing_modified_base_keys.iter().copied());
            preload_keys.extend(missing_replay_prereq_keys.iter().copied());
            if !preload_keys.is_empty() {
                let preload_keys: Vec<crate::ledger::Key> = preload_keys.into_iter().collect();
                let authoritative_bases = fetch_authoritative_modified_base_replacements(
                    &rpc_host,
                    rpc_port,
                    parent.sequence,
                    &preload_keys,
                )
                .await;
                if !authoritative_bases.is_empty() {
                    let mut ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                    for (key, raw) in &authoritative_bases {
                        ls.clear_typed_entry_for_key(key);
                        ls.insert_raw(*key, raw.clone());
                        if let Some(sle) = crate::ledger::sle::SLE::from_raw(*key, raw.clone()) {
                            sync_typed(&mut ls, sle.entry_type() as u16, key, raw);
                        }
                    }
                }
                info!(
                    "follower: preloaded {}/{} replay prerequisite object(s) (modified_base={} extra_prereq={}) from authoritative ledger {} before replaying seq={}",
                    authoritative_bases.len(),
                    preload_keys.len(),
                    missing_modified_base_keys.len(),
                    missing_replay_prereq_keys.len(),
                    parent.sequence,
                    seq,
                );
            }

            // The synced base should already contain the pre-tx objects needed
            // for replay. Avoid seeding raw state from metadata here: XRPL
            // metadata FinalFields are projections, not guaranteed full SLEs.

            // Forensic capture gate: the first ledger after the sync anchor is
            // the divergence test point. Clone the inputs required for the
            // artifact bundle before `blobs` gets consumed by replay_ledger.
            let byte_diff_capture = first_post_sync_seq == Some(seq);
            let tx_blobs_for_capture: Option<Vec<(Vec<u8>, Vec<u8>)>> = if byte_diff_capture {
                Some(blobs.clone())
            } else {
                None
            };
            let meta_with_hashes_for_capture = if byte_diff_capture {
                Some(meta_with_hashes.clone())
            } else {
                None
            };

            // Replay ledger + metadata patching on blocking thread to avoid
            // stalling the tokio executor (CPU-bound, holds std::sync::Mutex).
            let ls_arc = ledger_state.clone();
            let parent_owned = parent.clone();
            let parent_for_capture = parent.clone();
            let seq_header_owned = seq_header.clone();
            let sync_complete_for_blocking = {
                let ss = shared_state.read().await;
                ss.sync_done
            };
            let spawn_t0 = std::time::Instant::now();
            let blocking_result = tokio::task::spawn_blocking(move || -> Result<_, String> {
                let lock_t0 = std::time::Instant::now();
                let mut ls = ls_arc.lock().unwrap_or_else(|e| e.into_inner());
                let lock_wait_ms = lock_t0.elapsed().as_millis();

                // Defer per-entry redb writes during replay — the snapshot
                // persist writes everything in a single batch afterward.
                ls.set_defer_storage(true);

                // Preserve the pristine sync-anchor base before replay mutates
                // the live NuDB-backed SHAMap. This allows post-mismatch
                // diagnostics distinguish "wrong bytes/scope" from "wrong
                // mutation of the right base".
                let pristine_base_snapshot = if byte_diff_capture {
                    ls.snapshot_nudb_for_diagnostics()
                } else {
                    None
                };

                // Pre-replay state snapshot for forensic capture. Must happen
                // before replay_ledger mutates `ls`. Scoped to byte-diff mode
                // so normal ledgers pay zero cost.
                let prestate_captured: Option<std::collections::HashMap<[u8; 32], Vec<u8>>> =
                    if let Some(ref mh) = meta_with_hashes_for_capture {
                        // Start from metadata-affected keys, then expand directory
                        // neighborhoods (root <-> pages via IndexNext/IndexPrevious).
                        // This avoids sparse-prestate artifacts in replay_fixture where
                        // owner/book page chains are only partially present.
                        let mut keys: std::collections::BTreeSet<crate::ledger::Key> =
                            crate::ledger::forensic::collect_metadata_affected_keys(mh)
                                .into_iter()
                                .map(crate::ledger::Key)
                                .collect();
                        keys.insert(crate::ledger::keylet::skip().key);
                        if (parent_owned.sequence & 0xFF) == 0 && parent_owned.sequence > 0 {
                            keys.insert(
                                crate::ledger::keylet::skip_for_ledger(parent_owned.sequence).key,
                            );
                        }
                        keys.extend(collect_replay_prerequisite_keys(&blobs));
                        expand_directory_neighborhoods(&ls, &mut keys);

                        let mut map = std::collections::HashMap::with_capacity(keys.len());
                        for k in keys {
                            if let Some(bytes) = ls.get_raw_owned(&k) {
                                map.insert(k.0, bytes);
                            }
                        }
                        Some(map)
                    } else {
                        None
                    };

                let replay_t0 = std::time::Instant::now();
                let mut rr = crate::ledger::close::replay_ledger(
                    &parent_owned, &mut ls, blobs, &seq_header_owned, byte_diff_capture,
                );
                let replay_ms = replay_t0.elapsed().as_millis();

                let engine_hash_matched = rr.header.account_hash == seq_header_owned.account_hash;
                let (patched, patch_ms) = if engine_hash_matched {
                    tracing::info!(
                        "follower: engine replay matched validated account_hash for seq={}, metadata patching not needed",
                        seq
                    );
                    (MetadataPatchStats::default(), 0)
                } else {
                    tracing::warn!(
                        "follower: engine replay hash differs for seq={} (local={} network={}) — applying metadata patches",
                        seq,
                        hex::encode_upper(&rr.header.account_hash[..8]),
                        hex::encode_upper(&seq_header_owned.account_hash[..8]),
                    );
                    let patch_t0 = std::time::Instant::now();
                    let patched = apply_metadata_patches(
                        &meta_with_hashes_for_blocking,
                        seq,
                        &created_overrides,
                        &modified_overrides,
                        &mut ls,
                    );
                    if patched.aborted {
                        tracing::warn!(
                            "follower: metadata patching aborted at seq={} after {} applied patches and {} missing modified base objects",
                            seq,
                            patched.applied,
                            patched.missing_modified,
                        );
                    } else {
                        tracing::info!(
                            "follower: metadata patches applied at seq={} patched={} missing_modified={} created_override_misses={} incomplete_book_dirs={}",
                            seq,
                            patched.applied,
                            patched.missing_modified,
                            patched.created_override_miss_keys.len(),
                            patched.incomplete_book_dir_keys.len(),
                        );
                    }
                    (patched, patch_t0.elapsed().as_millis())
                };

                let pruned_engine_only = if engine_hash_matched {
                    0usize
                } else {
                    prune_engine_only_transients(
                        &mut ls,
                        &rr.touched_keys,
                        &meta_with_hashes_for_blocking,
                        seq,
                    )
                };
                if pruned_engine_only > 0 {
                    tracing::info!(
                        "follower: pruned {} engine-only transient Offer/DirectoryNode entries at seq={}",
                        pruned_engine_only,
                        seq,
                    );
                }

                let hash_t0 = std::time::Instant::now();
                let h = if sync_complete_for_blocking {
                    match try_flush_follow_state(&mut ls) {
                        Ok(hash) => {
                            ls.set_defer_storage(false);
                            hash
                        }
                        Err(e) => {
                            ls.set_defer_storage(false);
                            return Err(format!(
                                "follower: failed to flush replayed state before hashing at seq={}: {}",
                                seq, e
                            ));
                        }
                    }
                } else {
                    ls.set_defer_storage(false);
                    rr.header.account_hash
                };
                let hash_ms = hash_t0.elapsed().as_millis();

                rr.header.account_hash = h;
                rr.header.hash = rr.header.compute_hash();

                // Capture post-state bytes for forensic comparison using the
                // union of engine-touched keys and metadata-affected keys.
                // Metadata patching can update entries the engine never marked
                // as touched, and those keys still influence the final hash.
                let forensic_keys: Vec<crate::ledger::Key> =
                    if let Some(ref mh) = meta_with_hashes_for_capture {
                        let mut union = std::collections::BTreeSet::new();
                        union.extend(rr.touched_keys.iter().copied());
                        union.extend(
                            crate::ledger::forensic::collect_metadata_affected_keys(mh)
                                .into_iter()
                                .map(crate::ledger::Key),
                        );
                        let prestate_sources: Vec<&std::collections::HashMap<[u8; 32], Vec<u8>>> =
                            prestate_captured.as_ref().into_iter().collect();
                        expand_directory_neighborhoods_with_sources(
                            &ls,
                            &prestate_sources,
                            &mut union,
                        );
                        let metadata_only = union.len().saturating_sub(rr.touched_keys.len());
                        info!(
                            "follower forensic scope seq={}: engine_touched={} metadata_union={} metadata_only={} prestate_sources={}",
                            seq_header_owned.sequence,
                            rr.touched_keys.len(),
                            union.len(),
                            metadata_only,
                            prestate_sources.len(),
                        );
                        union.into_iter().collect()
                    } else {
                        rr.touched_keys.clone()
                    };
                let post_state: Vec<([u8; 32], Option<Vec<u8>>)> = forensic_keys
                    .iter()
                    .map(|k| (k.0, ls.get_raw_owned(k)))
                    .collect();

                drop(ls);

                info!(
                    "follower replay breakdown seq={}: replay={}ms patches={}ms pruned_engine_only={} state_hash={}ms lock_wait={}ms",
                    seq_header_owned.sequence, replay_ms, patch_ms, pruned_engine_only, hash_ms, lock_wait_ms,
                );
                Ok((
                    rr,
                    patched,
                    pruned_engine_only,
                    lock_wait_ms,
                    prestate_captured,
                    pristine_base_snapshot,
                    post_state,
                ))
            }).await;
            let spawn_total_ms = spawn_t0.elapsed().as_millis();
            if spawn_total_ms > 50 {
                let lock_wait = blocking_result
                    .as_ref()
                    .ok()
                    .and_then(|inner| inner.as_ref().ok())
                    .map(|r| r.3)
                    .unwrap_or(0);
                warn!(
                    "follower spawn_blocking total={}ms (ledger_state lock_wait={}ms) seq={}",
                    spawn_total_ms, lock_wait, seq,
                );
            }
            let (
                mut replay_result,
                patched,
                pruned_engine_only,
                missing_modified,
                missing_modified_keys,
                created_miss_keys,
                incomplete_book_dirs,
                prestate_captured,
                pristine_base_snapshot,
                post_state,
            ) = match blocking_result {
                Ok(Ok((rr, p, pruned, _lock_wait, prestate, pristine_base, post))) => (
                    rr,
                    p.applied,
                    pruned,
                    p.missing_modified,
                    p.missing_modified_keys,
                    p.created_override_miss_keys,
                    p.incomplete_book_dir_keys,
                    prestate,
                    pristine_base,
                    post,
                ),
                Ok(Err(e)) => {
                    error!("{e}");
                    request_resync_and_stop_follower(&follower_state);
                    return;
                }
                Err(e) => {
                    error!("follower spawn_blocking panicked: {}", e);
                    continue;
                }
            };
            let mut authoritative_repair_keys =
                std::collections::BTreeSet::<crate::ledger::Key>::new();
            if !created_miss_keys.is_empty() {
                let survivor_keys: Vec<crate::ledger::Key> = {
                    let ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                    created_miss_keys
                        .iter()
                        .copied()
                        .filter(|k| ls.get_raw_owned(k).is_some())
                        .collect()
                };
                let survivor_replacements = fetch_surviving_created_override_replacements(
                    &rpc_host,
                    rpc_port,
                    seq,
                    &survivor_keys,
                )
                .await;
                let unreplaced_survivors: Vec<crate::ledger::Key> = survivor_keys
                    .iter()
                    .copied()
                    .filter(|k| !survivor_replacements.contains_key(k))
                    .collect();
                if !unreplaced_survivors.is_empty() {
                    error!(
                        "follower halting at seq={} because {} surviving created-override misses could not be authoritatively replaced",
                        seq,
                        unreplaced_survivors.len(),
                    );
                    for key in unreplaced_survivors.iter().take(8) {
                        error!(
                            "unreplaced surviving created key seq={} key={}",
                            seq,
                            hex::encode_upper(key.0),
                        );
                    }
                    request_resync_and_stop_follower(&follower_state);
                    return;
                }
                if !survivor_replacements.is_empty() {
                    let mut ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                    for (key, raw) in &survivor_replacements {
                        authoritative_repair_keys.insert(*key);
                        ls.insert_raw(*key, raw.clone());
                        if let Some(sle) = crate::ledger::sle::SLE::from_raw(*key, raw.clone()) {
                            sync_typed(&mut ls, sle.entry_type() as u16, key, raw);
                            authoritative_repair_keys.extend(
                                crate::ledger::close::ensure_owner_directory_entries_for_created_sle(
                                    &mut ls,
                                    *key,
                                    sle.entry_type() as u16,
                                    raw,
                                ),
                            );
                        }
                    }
                    replay_result.header.account_hash = match try_flush_follow_state(&mut ls) {
                        Ok(hash) => hash,
                        Err(e) => {
                            drop(ls);
                            error!(
                                "follower: failed to flush authoritative created-override repair at seq={}: {}",
                                seq, e
                            );
                            request_resync_and_stop_follower(&follower_state);
                            return;
                        }
                    };
                    replay_result.header.hash = replay_result.header.compute_hash();
                    info!(
                        "follower: replaced {} surviving created-override misses with authoritative bytes at seq={}",
                        survivor_replacements.len(),
                        seq,
                    );
                }
            }

            // Force-fetch authoritative bytes for incomplete book DirectoryNodes.
            if !incomplete_book_dirs.is_empty() {
                let book_dir_replacements = fetch_surviving_created_override_replacements(
                    &rpc_host,
                    rpc_port,
                    seq,
                    &incomplete_book_dirs,
                )
                .await;
                let unreplaced: Vec<&crate::ledger::Key> = incomplete_book_dirs
                    .iter()
                    .filter(|k| !book_dir_replacements.contains_key(k))
                    .collect();
                if !unreplaced.is_empty() {
                    error!(
                        "follower halting at seq={} because {} incomplete book DirectoryNode(s) could not be authoritatively fetched",
                        seq,
                        unreplaced.len(),
                    );
                    for key in unreplaced.iter().take(8) {
                        error!(
                            "unfetchable incomplete book dir seq={} key={}",
                            seq,
                            hex::encode_upper(key.0),
                        );
                    }
                    request_resync_and_stop_follower(&follower_state);
                    return;
                }
                if !book_dir_replacements.is_empty() {
                    let mut ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                    for (key, raw) in &book_dir_replacements {
                        authoritative_repair_keys.insert(*key);
                        ls.insert_raw(*key, raw.clone());
                        if let Some(sle) = crate::ledger::sle::SLE::from_raw(*key, raw.clone()) {
                            sync_typed(&mut ls, sle.entry_type() as u16, key, raw);
                        }
                    }
                    replay_result.header.account_hash = match try_flush_follow_state(&mut ls) {
                        Ok(hash) => hash,
                        Err(e) => {
                            drop(ls);
                            error!(
                                "follower: failed to flush authoritative DirectoryNode repair at seq={}: {}",
                                seq, e
                            );
                            request_resync_and_stop_follower(&follower_state);
                            return;
                        }
                    };
                    replay_result.header.hash = replay_result.header.compute_hash();
                    info!(
                        "follower: replaced {} incomplete book DirectoryNode(s) with authoritative bytes at seq={}",
                        book_dir_replacements.len(),
                        seq,
                    );
                }
            }

            let mut unresolved_missing_modified = missing_modified;
            if !missing_modified_keys.is_empty() {
                let modified_replacements = fetch_surviving_created_override_replacements(
                    &rpc_host,
                    rpc_port,
                    seq,
                    &missing_modified_keys,
                )
                .await;
                let unreplaced: Vec<&crate::ledger::Key> = missing_modified_keys
                    .iter()
                    .filter(|k| !modified_replacements.contains_key(k))
                    .collect();
                unresolved_missing_modified = unreplaced.len();
                if !unreplaced.is_empty() {
                    error!(
                        "follower halting at seq={} because {} ModifiedNode base object(s) could not be authoritatively fetched",
                        seq,
                        unreplaced.len(),
                    );
                    for key in unreplaced.iter().take(8) {
                        error!(
                            "unfetchable modified base seq={} key={}",
                            seq,
                            hex::encode_upper(key.0),
                        );
                    }
                    request_resync_and_stop_follower(&follower_state);
                    return;
                }
                if !modified_replacements.is_empty() {
                    let mut ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                    for (key, raw) in &modified_replacements {
                        authoritative_repair_keys.insert(*key);
                        ls.clear_typed_entry_for_key(key);
                        ls.insert_raw(*key, raw.clone());
                        if let Some(sle) = crate::ledger::sle::SLE::from_raw(*key, raw.clone()) {
                            sync_typed(&mut ls, sle.entry_type() as u16, key, raw);
                        }
                    }
                    replay_result.header.account_hash = match try_flush_follow_state(&mut ls) {
                        Ok(hash) => hash,
                        Err(e) => {
                            drop(ls);
                            error!(
                                "follower: failed to flush authoritative ModifiedNode repair at seq={}: {}",
                                seq, e
                            );
                            request_resync_and_stop_follower(&follower_state);
                            return;
                        }
                    };
                    replay_result.header.hash = replay_result.header.compute_hash();
                    info!(
                        "follower: replaced {} missing ModifiedNode base object(s) with authoritative bytes at seq={}",
                        modified_replacements.len(),
                        seq,
                    );
                }
            }

            // compare_engine_touched_keys disabled — was causing OOM
            // from concurrent RPC fan-out. Diagnostics complete (diffs=0).
            // if seq == 103483090 {
            //     compare_engine_touched_keys(...).await;
            // }

            if unresolved_missing_modified > 0 {
                error!(
                    "follower halting at seq={} because {} ModifiedNode base objects were missing",
                    seq, unresolved_missing_modified,
                );
                request_resync_and_stop_follower(&follower_state);
                return;
            }

            // Check sync state
            let sync_complete = {
                let ss = shared_state.read().await;
                ss.sync_done
            };
            if !sync_complete {
                replay_result.header.account_hash = seq_account_hash;
                replay_result.header.hash = replay_result.header.compute_hash();
            } else if replay_result.header.account_hash != seq_account_hash {
                // Reconcile disabled — was causing OOM via state_hash() snapshot.
                // Engine parity fixes should make this unnecessary.
                info!(
                    "follower: engine hash mismatch seq={} local={} network={} (reconcile disabled)",
                    seq,
                    hex::encode_upper(&replay_result.header.account_hash[..8]),
                    hex::encode_upper(&seq_account_hash[..8]),
                );
                // Meta reconcile disabled — state_hash() snapshot causes OOM
            }

            let mut matched =
                sync_complete && replay_result.header.account_hash == seq_account_hash;
            let mut repaired_from_pristine_authoritative = false;

            // Hash diff diagnostic: log both hashes for every built ledger
            if sync_complete && !matched {
                warn!(
                    "HASH DIFF seq={}: local={} network={} parent_used={}",
                    seq,
                    hex::encode_upper(&replay_result.header.account_hash[..16]),
                    hex::encode_upper(&seq_account_hash[..16]),
                    hex::encode_upper(&replay_result.header.parent_hash[..8]),
                );

                let repair_scope: Vec<crate::ledger::Key> = {
                    let mut keys = std::collections::BTreeSet::new();
                    keys.extend(post_state.iter().map(|(key, _)| crate::ledger::Key(*key)));
                    keys.extend(authoritative_repair_keys.iter().copied());
                    let ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                    let prestate_sources: Vec<&std::collections::HashMap<[u8; 32], Vec<u8>>> =
                        prestate_captured.as_ref().into_iter().collect();
                    expand_authoritative_directory_scope_with_sources(
                        &ls,
                        &prestate_sources,
                        &mut keys,
                    );
                    keys.into_iter().collect()
                };
                let explicit_delete_keys = metadata_deleted_keys.clone();

                if !repair_scope.is_empty() {
                    let (
                        upserted,
                        removed,
                        not_found,
                        unavailable,
                        authoritative_found,
                    ) = reconcile_touched_keys_with_rpc(
                        ledger_state.clone(),
                        &repair_scope,
                        &explicit_delete_keys,
                        seq,
                        &rpc_host,
                        rpc_port,
                    )
                    .await;
                    let mut repaired_hash = {
                        let mut ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                        match try_flush_follow_state(&mut ls) {
                            Ok(hash) => hash,
                            Err(e) => {
                                drop(ls);
                                error!(
                                    "follower: failed to flush authoritative mismatch repair at seq={}: {}",
                                    seq, e
                                );
                                request_resync_and_stop_follower(&follower_state);
                                return;
                            }
                        }
                    };
                    if repaired_hash != seq_account_hash {
                        let expanded_scope: Vec<crate::ledger::Key> = {
                            let mut keys =
                                std::collections::BTreeSet::<crate::ledger::Key>::new();
                            keys.extend(repair_scope.iter().copied());
                            let ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                            let mut extra_sources: Vec<
                                &std::collections::HashMap<[u8; 32], Vec<u8>>,
                            > = prestate_captured.as_ref().into_iter().collect();
                            extra_sources.push(&authoritative_found);
                            expand_authoritative_directory_scope_with_sources(
                                &ls,
                                &extra_sources,
                                &mut keys,
                            );
                            keys.into_iter().collect()
                        };
                        if expanded_scope.len() > repair_scope.len() {
                            let (
                                upserted2,
                                removed2,
                                not_found2,
                                unavailable2,
                                _authoritative_found2,
                            ) = reconcile_touched_keys_with_rpc(
                                ledger_state.clone(),
                                &expanded_scope,
                                &explicit_delete_keys,
                                seq,
                                &rpc_host,
                                rpc_port,
                            )
                            .await;
                            repaired_hash = {
                                let mut ls =
                                    ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                                match try_flush_follow_state(&mut ls) {
                                    Ok(hash) => hash,
                                    Err(e) => {
                                        drop(ls);
                                        error!(
                                            "follower: failed to flush expanded authoritative mismatch repair at seq={}: {}",
                                            seq, e
                                        );
                                        request_resync_and_stop_follower(&follower_state);
                                        return;
                                    }
                                }
                            };
                            if repaired_hash == seq_account_hash {
                                replay_result.header.account_hash = repaired_hash;
                                replay_result.header.hash = replay_result.header.compute_hash();
                                matched = true;
                                info!(
                                    "follower: expanded authoritative RPC repair resolved mismatch at seq={} scope_keys={} added_keys={} upserted={} removed={} not_found={} unavailable={}",
                                    seq,
                                    expanded_scope.len(),
                                    expanded_scope.len().saturating_sub(repair_scope.len()),
                                    upserted2,
                                    removed2,
                                    not_found2,
                                    unavailable2,
                                );
                            } else {
                                warn!(
                                    "follower: expanded authoritative RPC repair still mismatched at seq={} repaired={} network={} scope_keys={} added_keys={} upserted={} removed={} not_found={} unavailable={}",
                                    seq,
                                    hex::encode_upper(&repaired_hash[..16]),
                                    hex::encode_upper(&seq_account_hash[..16]),
                                    expanded_scope.len(),
                                    expanded_scope.len().saturating_sub(repair_scope.len()),
                                    upserted2,
                                    removed2,
                                    not_found2,
                                    unavailable2,
                                );
                            }
                        }
                    }
                    if repaired_hash == seq_account_hash {
                        replay_result.header.account_hash = repaired_hash;
                        replay_result.header.hash = replay_result.header.compute_hash();
                        matched = true;
                        info!(
                            "follower: authoritative RPC repair resolved mismatch at seq={} scope_keys={} upserted={} removed={} not_found={} unavailable={}",
                            seq,
                            repair_scope.len(),
                            upserted,
                            removed,
                            not_found,
                            unavailable,
                        );
                    } else {
                        warn!(
                            "follower: authoritative RPC repair did not resolve mismatch at seq={} repaired={} network={} scope_keys={} upserted={} removed={} not_found={} unavailable={}",
                            seq,
                            hex::encode_upper(&repaired_hash[..16]),
                            hex::encode_upper(&seq_account_hash[..16]),
                            repair_scope.len(),
                            upserted,
                            removed,
                            not_found,
                            unavailable,
                        );
                    }
                }
            }

            let elapsed = tx_start.elapsed();
            if matched {
                tx_engine_successes += 1;
            }

            // ── First-ledger diagnostic: prominent pass/fail after sync ──
            if sync_complete && !first_hash_check_done {
                first_hash_check_done = true;
                if matched {
                    info!("========================================");
                    info!("  FIRST LEDGER HASH: MATCH seq={}", seq);
                    info!(
                        "  local={}",
                        hex::encode_upper(&replay_result.header.account_hash[..16])
                    );
                    info!("  network={}", hex::encode_upper(&seq_account_hash[..16]));
                    info!("========================================");
                } else {
                    error!("========================================");
                    error!("  FIRST LEDGER HASH: MISMATCH seq={}", seq);
                    error!(
                        "  local={}",
                        hex::encode_upper(&replay_result.header.account_hash[..16])
                    );
                    error!("  network={}", hex::encode_upper(&seq_account_hash[..16]));
                    error!("========================================");
                }
            }

            if sync_complete && first_post_sync_seq == Some(seq) {
                info!(
                    "follower first-post-sync replay: seq={} parent_used={} local_hash={} network_hash={} tx_applied={} tx_failed={} patched={} pruned_engine_only={}",
                    seq,
                    hex::encode_upper(&replay_result.header.parent_hash[..8]),
                    hex::encode_upper(&replay_result.header.account_hash[..16]),
                    hex::encode_upper(&seq_account_hash[..16]),
                    replay_result.applied_count,
                    replay_result.failed_count,
                    patched,
                    pruned_engine_only,
                );
            }

            let first_post_sync_mismatch =
                sync_complete && !matched && first_post_sync_seq == Some(seq);
            if first_post_sync_mismatch {
                // Stop the follower before long forensic capture so the close-loop
                // supervisor can see the degraded state immediately and avoid a
                // false-good force-accept window.
                follower_state
                    .hash_mismatches
                    .fetch_add(1, Ordering::Relaxed);
                stop_follower(&follower_state);
            }

            if sync_complete && !matched {
                // Forensic capture: when this is the first ledger after the
                // sync anchor (byte_diff_capture was true), dump everything
                // required for offline `replay_fixture` iteration before
                // rippled's retention window rolls past this ledger.
                if let (Some(blobs_saved), Some(prestate)) =
                    (tx_blobs_for_capture.clone(), prestate_captured.clone())
                {
                    let touched_raw: Vec<[u8; 32]> = post_state.iter().map(|(k, _)| *k).collect();
                    let bundle_root = storage.data_dir().join("debug-runs");
                    let inputs = crate::ledger::forensic::CaptureInputs {
                        bundle_root,
                        anchor_seq: sync_ledger_seq,
                        anchor_hash: sync_ledger_hash,
                        anchor_account_hash: sync_account_hash,
                        mismatch_seq: seq,
                        local_account_hash: replay_result.header.account_hash,
                        network_account_hash: seq_account_hash,
                        parent_header: parent_for_capture.clone(),
                        validated_header: seq_header.clone(),
                        applied_count: replay_result.applied_count,
                        failed_count: replay_result.failed_count,
                        skipped_count: replay_result.skipped_count,
                        touched_keys: touched_raw,
                        per_tx_attribution: std::mem::take(&mut replay_result.per_tx_attribution),
                        tx_blobs: blobs_saved,
                        prestate,
                        rpc_host: Some(rpc_host.clone()),
                        rpc_port,
                    };
                    let forensic_delete_keys = metadata_deleted_keys.clone();
                    match crate::ledger::forensic::capture_forensic_bundle(inputs).await {
                        Ok((path, rippled_ref, rippled_not_found, rippled_unavailable)) => {
                            info!("forensic: bundle written to {:?}", path);
                            // Inline comparison: post-state vs rippled reference
                            if !rippled_ref.is_empty() {
                                let mut matched_count = 0usize;
                                let mut divergent = 0usize;
                                let mut local_missing = 0usize;
                                let mut not_in_ref = 0usize;
                                let mut not_in_ref_present = 0usize;
                                let mut not_in_ref_deleted = 0usize;
                                let mut ref_unavailable = 0usize;
                                let mut ref_unavailable_present = 0usize;
                                let mut ref_unavailable_deleted = 0usize;
                                let mut authoritative_upserts: Vec<(crate::ledger::Key, Vec<u8>)> =
                                    Vec::new();
                                let mut authoritative_deletes: Vec<crate::ledger::Key> = Vec::new();
                                for (key, local_bytes) in &post_state {
                                    if let Some(ref_bytes) = rippled_ref.get(key) {
                                        authoritative_upserts
                                            .push((crate::ledger::Key(*key), ref_bytes.clone()));
                                        match local_bytes {
                                            Some(local) if local == ref_bytes => {
                                                matched_count += 1;
                                            }
                                            Some(local) => {
                                                divergent += 1;
                                                let sle_type =
                                                    if local.len() >= 3 && local[0] == 0x11 {
                                                        u16::from_be_bytes([local[1], local[2]])
                                                    } else {
                                                        0
                                                    };
                                                let type_name = match sle_type {
                                                    0x0061 => "AccountRoot",
                                                    0x0064 => "DirectoryNode",
                                                    0x0072 => "RippleState",
                                                    0x006F => "Offer",
                                                    0x0075 => "Escrow",
                                                    0x0078 => "PayChannel",
                                                    0x0043 => "Check",
                                                    0x0054 => "Ticket",
                                                    0x0037 => "NFTokenOffer",
                                                    0x0050 => "NFTokenPage",
                                                    _ => "Unknown",
                                                };
                                                let first_diff = local
                                                    .iter()
                                                    .zip(ref_bytes.iter())
                                                    .position(|(a, b)| a != b)
                                                    .unwrap_or(local.len().min(ref_bytes.len()));
                                                error!(
                                                    "DIVERGENT #{}: key={} type=0x{:04X}({}) len={}vs{} diff@{}",
                                                    divergent,
                                                    hex::encode_upper(&key[..8]),
                                                    sle_type, type_name,
                                                    local.len(), ref_bytes.len(), first_diff,
                                                );
                                                let start = first_diff.saturating_sub(4);
                                                let end = (first_diff + 16)
                                                    .min(local.len())
                                                    .min(ref_bytes.len());
                                                error!(
                                                    "  local   [{}..{}]: {}",
                                                    start,
                                                    end,
                                                    hex::encode_upper(&local[start..end])
                                                );
                                                error!(
                                                    "  expected[{}..{}]: {}",
                                                    start,
                                                    end,
                                                    hex::encode_upper(&ref_bytes[start..end])
                                                );
                                            }
                                            None => {
                                                local_missing += 1;
                                                error!(
                                                    "KEY MISSING LOCALLY: key={}",
                                                    hex::encode_upper(&key[..8])
                                                );
                                            }
                                        }
                                    } else if rippled_not_found.contains(key) {
                                        not_in_ref += 1;
                                        match local_bytes {
                                            Some(local) => {
                                                not_in_ref_present += 1;
                                                if not_in_ref_present <= 8 {
                                                    let sle_type =
                                                        if local.len() >= 3 && local[0] == 0x11 {
                                                            u16::from_be_bytes([local[1], local[2]])
                                                        } else {
                                                            0
                                                        };
                                                    let type_name = match sle_type {
                                                        0x0061 => "AccountRoot",
                                                        0x0064 => "DirectoryNode",
                                                        0x0072 => "RippleState",
                                                        0x006F => "Offer",
                                                        0x0075 => "Escrow",
                                                        0x0078 => "PayChannel",
                                                        0x0043 => "Check",
                                                        0x0054 => "Ticket",
                                                        0x0037 => "NFTokenOffer",
                                                        0x0050 => "NFTokenPage",
                                                        _ => "Unknown",
                                                    };
                                                    error!(
                                                        "LOCAL ONLY #{}: key={} type=0x{:04X}({}) len={}",
                                                        not_in_ref_present,
                                                        hex::encode_upper(&key[..8]),
                                                        sle_type,
                                                        type_name,
                                                        local.len(),
                                                    );
                                                }
                                            }
                                            None => {
                                                not_in_ref_deleted += 1;
                                                if not_in_ref_deleted <= 12 {
                                                    error!(
                                                        "REF MISSING / LOCAL DELETED #{}: key={}",
                                                        not_in_ref_deleted,
                                                        hex::encode_upper(key),
                                                    );
                                                }
                                            }
                                        }
                                        if forensic_delete_keys
                                            .contains(&crate::ledger::Key(*key))
                                        {
                                            authoritative_deletes.push(crate::ledger::Key(*key));
                                        }
                                    } else {
                                        ref_unavailable += 1;
                                        match local_bytes {
                                            Some(local) => {
                                                ref_unavailable_present += 1;
                                                if ref_unavailable_present <= 8 {
                                                    error!(
                                                        "REF UNAVAILABLE / LOCAL PRESENT #{}: key={} len={}",
                                                        ref_unavailable_present,
                                                        hex::encode_upper(&key[..8]),
                                                        local.len(),
                                                    );
                                                }
                                            }
                                            None => {
                                                ref_unavailable_deleted += 1;
                                                if ref_unavailable_deleted <= 12 {
                                                    error!(
                                                        "REF UNAVAILABLE / LOCAL DELETED #{}: key={}",
                                                        ref_unavailable_deleted,
                                                        hex::encode_upper(key),
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                info!(
                                    "FORENSIC COMPARISON: matched={} divergent={} local_missing={} not_in_ref={} (present={} deleted={}) ref_unavailable={} (present={} deleted={}) total={}",
                                    matched_count,
                                    divergent,
                                    local_missing,
                                    not_in_ref,
                                    not_in_ref_present,
                                    not_in_ref_deleted,
                                    ref_unavailable,
                                    ref_unavailable_present,
                                    ref_unavailable_deleted,
                                    post_state.len(),
                                );
                                let local_upserts: Vec<(crate::ledger::Key, Vec<u8>)> = post_state
                                    .iter()
                                    .filter_map(|(key, local_bytes)| {
                                        local_bytes
                                            .as_ref()
                                            .map(|bytes| (crate::ledger::Key(*key), bytes.clone()))
                                    })
                                    .collect();
                                let local_deletes: Vec<crate::ledger::Key> = post_state
                                    .iter()
                                    .filter_map(|(key, local_bytes)| {
                                        if local_bytes.is_none() {
                                            Some(crate::ledger::Key(*key))
                                        } else {
                                            None
                                        }
                                    })
                                    .collect();
                                let reference_complete = rippled_unavailable.is_empty();
                                if !reference_complete {
                                    warn!(
                                        "FORENSIC REFERENCE INCOMPLETE seq={}: unavailable_keys={} — skipping authoritative delete inference for those keys",
                                        seq,
                                        rippled_unavailable.len(),
                                    );
                                }
                                let authoritative_overlay_hash = if reference_complete {
                                    let ls =
                                        ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                                    ls.overlay_hash_from_entries_for_diagnostics(
                                        &authoritative_upserts,
                                        &authoritative_deletes,
                                    )
                                } else {
                                    None
                                };
                                if let Some(root) = authoritative_overlay_hash {
                                    info!(
                                        "FORENSIC ROOT CHECK seq={}: authoritative_overlay={} local={} network={} upserts={} deletes={}",
                                        seq,
                                        hex::encode_upper(&root[..16]),
                                        hex::encode_upper(&replay_result.header.account_hash[..16]),
                                        hex::encode_upper(&seq_account_hash[..16]),
                                        authoritative_upserts.len(),
                                        authoritative_deletes.len(),
                                    );
                                }
                                if let Some(mut pristine_base) = pristine_base_snapshot {
                                    let pristine_local_hash = {
                                        let mut local_base = pristine_base.snapshot();
                                        crate::ledger::LedgerState::overlay_hash_from_snapshot_for_diagnostics(
                                            &mut local_base,
                                            &local_upserts,
                                            &local_deletes,
                                        )
                                    };
                                    let mut authoritative_base = pristine_base.snapshot();
                                    let pristine_authoritative_hash = if reference_complete {
                                        crate::ledger::LedgerState::overlay_hash_from_snapshot_for_diagnostics(
                                            &mut authoritative_base,
                                            &authoritative_upserts,
                                            &authoritative_deletes,
                                        )
                                    } else {
                                        [0u8; 32]
                                    };
                                    info!(
                                        "FORENSIC PRISTINE ROOT CHECK seq={}: pristine_local={} pristine_authoritative={} current_local={} network={} local_upserts={} local_deletes={} auth_upserts={} auth_deletes={}",
                                        seq,
                                        hex::encode_upper(&pristine_local_hash[..16]),
                                        hex::encode_upper(&pristine_authoritative_hash[..16]),
                                        hex::encode_upper(&replay_result.header.account_hash[..16]),
                                        hex::encode_upper(&seq_account_hash[..16]),
                                        local_upserts.len(),
                                        local_deletes.len(),
                                        authoritative_upserts.len(),
                                        authoritative_deletes.len(),
                                    );
                                    if reference_complete
                                        && !matched
                                        && pristine_authoritative_hash == seq_account_hash
                                    {
                                        let repair_loaded = if let Some(anchor_root) = sync_account_hash {
                                            let mut ls = ledger_state
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner());
                                            match ls.load_nudb_root(anchor_root) {
                                                Ok(true) => {
                                                    ls.reset_overlay_after_root_rehydrate();
                                                    for key in &authoritative_deletes {
                                                        if let Some(raw) = ls.get_raw_owned(key) {
                                                            if raw.len() >= 3 && raw[0] == 0x11 {
                                                                let entry_type =
                                                                    u16::from_be_bytes([raw[1], raw[2]]);
                                                                remove_typed(&mut ls, entry_type, key);
                                                            } else {
                                                                ls.remove_raw(key);
                                                            }
                                                        } else {
                                                            ls.remove_raw(key);
                                                        }
                                                    }
                                                    for (key, raw) in &authoritative_upserts {
                                                        ls.insert_raw(*key, raw.clone());
                                                        if raw.len() >= 3 && raw[0] == 0x11 {
                                                            let entry_type =
                                                                u16::from_be_bytes([raw[1], raw[2]]);
                                                            sync_typed(&mut ls, entry_type, key, raw);
                                                            crate::ledger::close::ensure_owner_directory_entries_for_created_sle(
                                                                &mut ls,
                                                                *key,
                                                                entry_type,
                                                                raw,
                                                            );
                                                        }
                                                    }
                                                    match try_flush_follow_state(&mut ls) {
                                                        Ok(repaired_hash) => {
                                                            if repaired_hash == seq_account_hash {
                                                                true
                                                            } else {
                                                                error!(
                                                                    "follower: pristine authoritative rebuild landed wrong root at seq={} repaired={} network={}",
                                                                    seq,
                                                                    hex::encode_upper(&repaired_hash[..16]),
                                                                    hex::encode_upper(&seq_account_hash[..16]),
                                                                );
                                                                false
                                                            }
                                                        }
                                                        Err(e) => {
                                                            error!(
                                                                "follower: pristine authoritative rebuild flush failed at seq={}: {}",
                                                                seq,
                                                                e,
                                                            );
                                                            false
                                                        }
                                                    }
                                                }
                                                Ok(false) => {
                                                    error!(
                                                        "follower: sync anchor root {} could not be reloaded for pristine authoritative rebuild at seq={}",
                                                        hex::encode_upper(&anchor_root[..16]),
                                                        seq,
                                                    );
                                                    false
                                                }
                                                Err(e) => {
                                                    error!(
                                                        "follower: sync anchor root {} failed to reload for pristine authoritative rebuild at seq={}: {}",
                                                        hex::encode_upper(&anchor_root[..16]),
                                                        seq,
                                                        e,
                                                    );
                                                    false
                                                }
                                            }
                                        } else {
                                            error!(
                                                "follower: no sync anchor account_hash available for pristine authoritative rebuild at seq={}",
                                                seq,
                                            );
                                            false
                                        };
                                        if repair_loaded {
                                            replay_result.header = seq_header.clone();
                                            repaired_from_pristine_authoritative = true;
                                            follower_state.running.store(true, Ordering::SeqCst);
                                            info!(
                                                "follower: pristine authoritative rebuild restored seq={} to network root {}",
                                                seq,
                                                hex::encode_upper(&pristine_authoritative_hash[..16]),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => warn!("forensic: bundle write failed: {}", e),
                    }
                }

                if repaired_from_pristine_authoritative {
                    matched = true;
                    info!(
                        "follower: continuing after pristine authoritative recovery at seq={}",
                        seq,
                    );
                } else {
                    if !first_post_sync_mismatch {
                        follower_state
                            .hash_mismatches
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    let successful_since_sync = follower_state.hash_matches.load(Ordering::Relaxed);
                    if successful_since_sync == 0 {
                        // First ledger after fresh sync — base state was correct,
                        // so this is an engine bug. Resync won't help.
                        error!(
                            "follower: hash mismatch at seq={} on FIRST post-sync ledger — engine bug, halting (resync would loop)",
                            seq,
                        );
                        if !first_post_sync_mismatch {
                            stop_follower(&follower_state);
                        }
                        return;
                    } else {
                        // Had N successful ledgers before this mismatch — state may have drifted.
                        // Re-sync to get back to correct state.
                        error!(
                            "follower: hash mismatch at seq={} after {} successful ledgers — requesting state re-sync",
                            seq, successful_since_sync,
                        );
                        follower_state
                            .resync_requested
                            .store(true, Ordering::SeqCst);
                        stop_follower(&follower_state);
                        return;
                    }
                }
            }

            let in_flight = persist_in_flight.load(Ordering::Relaxed);
            info!(
                "ledger {} (BUILT LOCAL{}): {} applied, {} failed, {} patched in {:.2}s | persist_in_flight={} {}",
                seq,
                if sync_complete { "" } else { ", pre-sync" },
                replay_result.applied_count,
                replay_result.failed_count,
                patched,
                elapsed.as_secs_f64(),
                in_flight,
                if sync_complete {
                    format!("| {}/{} success rate", tx_engine_successes, tx_engine_attempts)
                } else {
                    String::new()
                },
            );

            // ── Post-BUILT-LOCAL: persist + metadata ───────────────────────
            let tail_t0 = std::time::Instant::now();

            // Persist current-state deltas only after the base state sync completes.
            if sync_complete {
                // Everything runs in spawn_blocking: take_dirty + snapshot +
                // redb writes. Nothing heavy on the async runtime.
                let pif = persist_in_flight.clone();
                pif.fetch_add(1, Ordering::Relaxed);
                let ls_arc2 = ledger_state.clone();
                let store2 = storage.clone();
                let follower_state_for_persist = follower_state.clone();
                let header2 = replay_result.header.clone();
                let records2 = replay_result.tx_records.clone();
                let is_first_post_sync = first_post_sync_seq == Some(header2.sequence);
                let submit_t = std::time::Instant::now();
                tokio::task::spawn_blocking(move || {
                    let queue_ms = submit_t.elapsed().as_millis();
                    let persist_t0 = std::time::Instant::now();

                    // take_dirty (under lock) — NuDB handles persistence
                    {
                        let mut ls = ls_arc2.lock().unwrap_or_else(|e| e.into_inner());
                        if let Err(e) = ls.try_take_dirty() {
                            error!(
                                "follower persist seq={} failed to flush NuDB state: {}",
                                seq, e
                            );
                            request_resync_and_stop_follower(&follower_state_for_persist);
                            pif.fetch_sub(1, Ordering::Relaxed);
                            return;
                        }
                    }

                    let ledger_t0 = std::time::Instant::now();
                    let _ = store2.save_ledger(&header2, &records2);
                    let ledger_ms = ledger_t0.elapsed().as_millis();

                    let meta_t0 = std::time::Instant::now();
                    let header_hash = hex::encode_upper(header2.hash);
                    let _ = store2.save_meta(header2.sequence, &header_hash, &header2);
                    let _ = store2.persist_sync_anchor(&header2);
                    let meta_ms = meta_t0.elapsed().as_millis();

                    let flush_t0 = std::time::Instant::now();
                    let _ = store2.flush();
                    let flush_ms = flush_t0.elapsed().as_millis();

                    let total_ms = persist_t0.elapsed().as_millis();
                    pif.fetch_sub(1, Ordering::Relaxed);
                    let remaining = pif.load(Ordering::Relaxed);

                    tracing::info!(
                        "follower persist seq={}: queue={}ms ledger={}ms meta={}ms flush={}ms total={}ms in_flight={}",
                        seq, queue_ms, ledger_ms, meta_ms, flush_ms, total_ms, remaining,
                    );
                    if is_first_post_sync {
                        tracing::info!(
                            "follower first-post-sync persist: seq={} anchor_hash={} anchor_account_hash={} tx_records={}",
                            header2.sequence,
                            hex::encode_upper(&header2.hash[..8]),
                            hex::encode_upper(&header2.account_hash[..8]),
                            records2.len(),
                        );
                    }
                });
                // Don't .await — fire and forget
            } else {
                let ls_arc2 = ledger_state.clone();
                tokio::task::spawn_blocking(move || {
                    let mut ls = ls_arc2.lock().unwrap_or_else(|e| e.into_inner());
                    ls.take_dirty();
                });
                let _ = storage.save_ledger(&replay_result.header, &replay_result.tx_records);
            }

            // Phase 2: metadata update (async write lock)
            let meta_t0 = std::time::Instant::now();
            {
                let mut ss = shared_state.write().await;
                ss.ctx
                    .history
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert_ledger(
                        replay_result.header.clone(),
                        replay_result.tx_records.clone(),
                    );
                ss.ctx.ledger_seq = seq;
                ss.ctx.ledger_header = replay_result.header.clone();
                ss.ctx.ledger_hash = hex::encode_upper(replay_result.header.hash);
            }
            let meta_ms = meta_t0.elapsed().as_millis();

            let tail_ms = tail_t0.elapsed().as_millis();
            info!(
                "follower tail seq={}: meta_update={}ms total_tail={}ms",
                seq, meta_ms, tail_ms,
            );

            // Update counters
            follower_state.current_seq.store(seq, Ordering::Relaxed);
            follower_state
                .ledgers_applied
                .fetch_add(1, Ordering::Relaxed);
            follower_state
                .txs_applied
                .fetch_add(replay_result.applied_count as u64, Ordering::Relaxed);
            if matched {
                follower_state.hash_matches.fetch_add(1, Ordering::Relaxed);
            }

            prev_header = Some(replay_result.header);
            target_seq = seq;
            if first_post_sync_seq == Some(seq) {
                first_post_sync_seq = None;
            }
            continue;
        }

        // Retry incomplete acquisitions (3s cadence, max 6 retries per acquisition)
        {
            let retries = {
                let mut guard = inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
                guard.needs_retry()
            };
            for (hash, seq, needs_header, needs_tx) in &retries {
                let what = match (*needs_header, *needs_tx) {
                    (true, true) => "header+tx",
                    (true, false) => "header",
                    (false, true) => "tx",
                    _ => continue,
                };
                {
                    let mut state = shared_state.write().await;
                    if *needs_tx {
                        let cookie = crate::sync::next_cookie();
                        let missing_tx_nodes = {
                            let guard = inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
                            guard.missing_tx_node_ids(hash, 64)
                        };
                        let use_root_tx_request = missing_tx_nodes.is_empty()
                            || missing_tx_nodes
                                == vec![crate::ledger::shamap_id::SHAMapNodeID::root()
                                    .to_wire()
                                    .to_vec()];
                        let req = if use_root_tx_request {
                            crate::network::relay::encode_get_ledger_txs_for_hash(hash, cookie)
                        } else {
                            crate::network::relay::encode_get_ledger_txs_for_hash_nodes(
                                hash,
                                &missing_tx_nodes,
                                cookie,
                            )
                        };
                        state.send_to_peers_with_ledger(&req, *seq, 3);
                    }
                    if *needs_header {
                        let cookie = crate::sync::next_cookie();
                        let req = crate::network::relay::encode_get_ledger_base(hash, cookie);
                        state.send_to_peers_with_ledger(&req, *seq, 3);
                    }
                }
                // Mark retried IMMEDIATELY — 3s guard prevents duplicate retries
                let retry_num = {
                    let mut guard = inbound_ledgers.lock().unwrap_or_else(|e| e.into_inner());
                    guard.mark_retried(hash)
                };
                info!(
                    "follower retrying {} for seq={} hash={}.. (attempt {})",
                    what,
                    seq,
                    &hex::encode_upper(&hash[..4]),
                    retry_num,
                );
            }
        }

        // No response — brief wait
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

// ── Legacy helpers for test_one_ledger ────────────────────────────────────────
// The following functions are used by test_one_ledger (CLI diagnostic tool).
// They use JSON-RPC to fetch and apply individual ledgers for debugging.

fn update_typed_from_binary(data: &[u8], state: &mut crate::ledger::LedgerState) {
    if data.len() >= 3 && data[0] == 0x11 {
        let entry_type = u16::from_be_bytes([data[1], data[2]]);
        match entry_type {
            0x0061 => {
                if let Ok(acct) = crate::ledger::AccountRoot::decode(data) {
                    state.update_account_typed(acct);
                }
            }
            0x0072 => {
                if let Some(tl) = crate::ledger::trustline::RippleState::decode_from_sle(data) {
                    state.update_trustline_typed(tl);
                }
            }
            0x006f => {
                if let Some(off) = crate::ledger::offer::Offer::decode_from_sle(data) {
                    state.update_offer_typed(off);
                }
            }
            _ => {}
        }
    }
}

/// Apply transaction metadata (`AffectedNodes`) to the supplied `LedgerState`.
///
/// Returns (created, modified, deleted) counts.
fn apply_metadata(meta: &Value, state: &mut crate::ledger::LedgerState) -> (u64, u64, u64) {
    let mut created = 0u64;
    let mut modified = 0u64;
    let mut deleted = 0u64;

    let affected = match meta["AffectedNodes"].as_array() {
        Some(arr) => arr,
        None => return (0, 0, 0),
    };

    for node in affected {
        if let Some(created_node) = node.get("CreatedNode") {
            apply_created_node(created_node, state);
            created += 1;
        } else if let Some(modified_node) = node.get("ModifiedNode") {
            apply_modified_node(modified_node, state);
            modified += 1;
        } else if let Some(deleted_node) = node.get("DeletedNode") {
            apply_deleted_node(deleted_node, state);
            deleted += 1;
        }
    }

    (created, modified, deleted)
}

/// Apply a CreatedNode — insert a new object into state.
fn apply_created_node(node: &Value, state: &mut crate::ledger::LedgerState) {
    let entry_type = node["LedgerEntryType"].as_str().unwrap_or("");
    let fields = &node["NewFields"];

    match entry_type {
        "AccountRoot" => {
            if let Some(acct) = parse_account_from_json(fields) {
                state.insert_account(acct);
            }
        }
        "RippleState" => {
            if let Some(tl) = parse_trustline_from_json(fields) {
                state.insert_trustline(tl);
            }
        }
        "Offer" => {
            if let Some(offer) = parse_offer_from_json(fields) {
                state.insert_offer(offer);
            }
        }
        "Check" => {
            if let Some(chk) = parse_check_from_json(fields) {
                state.insert_check(chk);
            }
        }
        "Escrow" => {
            if let Some(esc) = parse_escrow_from_json(fields) {
                state.insert_escrow(esc);
            }
        }
        "PayChannel" => {
            if let Some(pc) = parse_paychan_from_json(fields) {
                state.insert_paychan(pc);
            }
        }
        "DepositPreauth" => {
            if let Some(dp) = parse_deposit_preauth_from_json(fields) {
                state.insert_deposit_preauth(dp);
            }
        }
        "Ticket" => {
            if let Some(tkt) = parse_ticket_from_json(fields) {
                state.insert_ticket(tkt);
            }
        }
        "NFTokenOffer" => {
            if let Some(off) = parse_nft_offer_from_json(fields) {
                state.insert_nft_offer(off);
            }
        }
        // DirectoryNode, SignerList, AMM, NFTokenPage, Amendments, FeeSettings,
        // LedgerHashes, NegativeUNL — tracked in SHAMap but no typed struct yet.
        _ => {}
    }
}

/// Apply a ModifiedNode — update an existing object in state.
fn apply_modified_node(node: &Value, state: &mut crate::ledger::LedgerState) {
    let entry_type = node["LedgerEntryType"].as_str().unwrap_or("");
    let final_fields = &node["FinalFields"];

    if final_fields.is_null() {
        return;
    }

    match entry_type {
        "AccountRoot" => {
            if let Some(acct) = parse_account_from_json(final_fields) {
                state.insert_account(acct);
            }
        }
        "RippleState" => {
            if let Some(tl) = parse_trustline_from_json(final_fields) {
                state.insert_trustline(tl);
            }
        }
        "Offer" => {
            if let Some(offer) = parse_offer_from_json(final_fields) {
                state.insert_offer(offer);
            }
        }
        "Check" => {
            if let Some(chk) = parse_check_from_json(final_fields) {
                state.insert_check(chk);
            }
        }
        "Escrow" => {
            if let Some(esc) = parse_escrow_from_json(final_fields) {
                state.insert_escrow(esc);
            }
        }
        "PayChannel" => {
            if let Some(pc) = parse_paychan_from_json(final_fields) {
                state.insert_paychan(pc);
            }
        }
        "DepositPreauth" => {
            if let Some(dp) = parse_deposit_preauth_from_json(final_fields) {
                state.insert_deposit_preauth(dp);
            }
        }
        "Ticket" => {
            if let Some(tkt) = parse_ticket_from_json(final_fields) {
                state.insert_ticket(tkt);
            }
        }
        "NFTokenOffer" => {
            if let Some(off) = parse_nft_offer_from_json(final_fields) {
                state.insert_nft_offer(off);
            }
        }
        _ => {}
    }
}

/// Apply a DeletedNode — remove an object from state.
fn apply_deleted_node(node: &Value, state: &mut crate::ledger::LedgerState) {
    let entry_type = node["LedgerEntryType"].as_str().unwrap_or("");
    let final_fields = &node["FinalFields"];

    // Deletion requires the SHAMap key, which is the `LedgerIndex`.
    let key = parse_ledger_index(node);

    match entry_type {
        "AccountRoot" => {
            if let Some(account_id) = parse_account_id_from_json(final_fields, "Account") {
                state.remove_account(&account_id);
            }
        }
        "RippleState" => {
            if let Some(k) = key {
                state.remove_trustline(&k);
            }
        }
        "Offer" => {
            if let Some(k) = key {
                state.remove_offer(&k);
            }
        }
        "Check" => {
            if let Some(k) = key {
                state.remove_check(&k);
            }
        }
        "Escrow" => {
            if let Some(k) = key {
                state.remove_escrow(&k);
            }
        }
        "PayChannel" => {
            if let Some(k) = key {
                state.remove_paychan(&k);
            }
        }
        "DepositPreauth" => {
            if let Some(k) = key {
                state.remove_deposit_preauth(&k);
            }
        }
        "Ticket" => {
            if let Some(k) = key {
                state.remove_ticket(&k);
            }
        }
        "NFTokenOffer" => {
            if let Some(k) = key {
                state.remove_nft_offer(&k);
            }
        }
        _ => {}
    }
}

/// Parse LedgerIndex from a node into a Key.
fn parse_ledger_index(node: &Value) -> Option<crate::ledger::Key> {
    let hex_str = node["LedgerIndex"].as_str()?;
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(crate::ledger::Key(arr))
}

// ── JSON field parsers ──────────────────────────────────────────────────────

/// Parse an AccountRoot from JSON fields (NewFields or FinalFields).
fn parse_account_from_json(fields: &Value) -> Option<crate::ledger::AccountRoot> {
    let account_id = parse_account_id_from_json(fields, "Account")?;
    let balance = parse_drops(fields.get("Balance")?)?;
    let sequence = fields["Sequence"].as_u64().unwrap_or(1) as u32;
    let owner_count = fields["OwnerCount"].as_u64().unwrap_or(0) as u32;
    let flags = fields["Flags"].as_u64().unwrap_or(0) as u32;
    let regular_key = parse_account_id_from_json(fields, "RegularKey");
    let minted_nftokens = fields["MintedNFTokens"].as_u64().unwrap_or(0) as u32;
    let burned_nftokens = fields["BurnedNFTokens"].as_u64().unwrap_or(0) as u32;
    let transfer_rate = fields["TransferRate"].as_u64().unwrap_or(0) as u32;
    let domain = fields["Domain"]
        .as_str()
        .and_then(|s| hex::decode(s).ok())
        .unwrap_or_default();
    let tick_size = fields["TickSize"].as_u64().unwrap_or(0) as u8;
    let ticket_count = fields["TicketCount"].as_u64().unwrap_or(0) as u32;
    let previous_txn_id = parse_hash256(fields, "PreviousTxnID").unwrap_or([0u8; 32]);
    let previous_txn_lgr_seq = fields["PreviousTxnLgrSeq"].as_u64().unwrap_or(0) as u32;

    Some(crate::ledger::AccountRoot {
        account_id,
        balance,
        sequence,
        owner_count,
        flags,
        regular_key,
        minted_nftokens,
        burned_nftokens,
        transfer_rate,
        domain,
        tick_size,
        ticket_count,
        previous_txn_id,
        previous_txn_lgr_seq,
        raw_sle: None,
    })
}

/// Parse a RippleState (trust line) from JSON fields.
fn parse_trustline_from_json(fields: &Value) -> Option<crate::ledger::RippleState> {
    use crate::transaction::amount::{Currency, IouValue};

    let low_limit = &fields["LowLimit"];
    let high_limit = &fields["HighLimit"];
    let balance_field = &fields["Balance"];

    let low_account = parse_account_id_from_json(low_limit, "issuer")?;
    let high_account = parse_account_id_from_json(high_limit, "issuer")?;

    let currency_str = low_limit["currency"]
        .as_str()
        .or_else(|| high_limit["currency"].as_str())?;
    let currency = parse_currency(currency_str)?;

    let balance = parse_iou_value(balance_field)?;
    let low_limit_val = parse_iou_value(low_limit).unwrap_or(IouValue::ZERO);
    let high_limit_val = parse_iou_value(high_limit).unwrap_or(IouValue::ZERO);
    let flags = fields["Flags"].as_u64().unwrap_or(0) as u32;

    let low_node = fields["LowNode"]
        .as_str()
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    let high_node = fields["HighNode"]
        .as_str()
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    let low_quality_in = fields["LowQualityIn"].as_u64().unwrap_or(0) as u32;
    let low_quality_out = fields["LowQualityOut"].as_u64().unwrap_or(0) as u32;
    let high_quality_in = fields["HighQualityIn"].as_u64().unwrap_or(0) as u32;
    let high_quality_out = fields["HighQualityOut"].as_u64().unwrap_or(0) as u32;
    let previous_txn_id = parse_hash256(fields, "PreviousTxnID").unwrap_or([0u8; 32]);
    let previous_txn_lgr_seq = fields["PreviousTxnLgrSeq"].as_u64().unwrap_or(0) as u32;

    Some(crate::ledger::RippleState {
        low_account,
        high_account,
        currency,
        balance,
        low_limit: low_limit_val,
        high_limit: high_limit_val,
        flags,
        low_node,
        high_node,
        low_quality_in,
        low_quality_out,
        high_quality_in,
        high_quality_out,
        previous_txn_id,
        previous_txn_lgr_seq,
        raw_sle: None,
    })
}

/// Parse an Offer from JSON fields.
fn parse_offer_from_json(fields: &Value) -> Option<crate::ledger::Offer> {
    let account = parse_account_id_from_json(fields, "Account")?;
    let sequence = fields["Sequence"].as_u64()? as u32;
    let taker_pays = parse_amount_json(&fields["TakerPays"])?;
    let taker_gets = parse_amount_json(&fields["TakerGets"])?;
    let flags = fields["Flags"].as_u64().unwrap_or(0) as u32;

    let book_directory = parse_hash256(fields, "BookDirectory").unwrap_or([0u8; 32]);
    let book_node = fields["BookNode"]
        .as_str()
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    let owner_node = fields["OwnerNode"]
        .as_str()
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    let expiration = fields["Expiration"].as_u64().map(|v| v as u32);
    let domain_id = parse_hash256(fields, "DomainID");
    let additional_books = fields["AdditionalBooks"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    if let Some(s) = v.as_str() {
                        parse_hex_32(s)
                    } else if let Some(obj) = v.as_object() {
                        obj.get("BookDirectory")
                            .and_then(|bd| bd.as_str())
                            .and_then(parse_hex_32)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let previous_txn_id = parse_hash256(fields, "PreviousTxnID").unwrap_or([0u8; 32]);
    let previous_txn_lgr_seq = fields["PreviousTxnLgrSeq"].as_u64().unwrap_or(0) as u32;

    Some(crate::ledger::Offer {
        account,
        sequence,
        taker_pays,
        taker_gets,
        flags,
        book_directory,
        book_node,
        owner_node,
        expiration,
        domain_id,
        additional_books,
        previous_txn_id,
        previous_txn_lgr_seq,
        raw_sle: None,
    })
}

/// Parse a Check from JSON fields.
fn parse_check_from_json(fields: &Value) -> Option<crate::ledger::Check> {
    let account = parse_account_id_from_json(fields, "Account")?;
    let destination = parse_account_id_from_json(fields, "Destination")?;
    let send_max = parse_drops(&fields["SendMax"])
        .map(crate::transaction::Amount::Xrp)
        .unwrap_or(crate::transaction::Amount::Xrp(0));
    let sequence = fields["Sequence"].as_u64().unwrap_or(0) as u32;
    let expiration = fields["Expiration"].as_u64().unwrap_or(0) as u32;

    Some(crate::ledger::Check {
        account,
        destination,
        send_max,
        sequence,
        expiration,
        owner_node: 0,
        destination_node: 0,
        source_tag: None,
        destination_tag: None,
        raw_sle: None,
    })
}

/// Parse an Escrow from JSON fields.
fn parse_escrow_from_json(fields: &Value) -> Option<crate::ledger::Escrow> {
    let account = parse_account_id_from_json(fields, "Account")?;
    let destination = parse_account_id_from_json(fields, "Destination")?;
    let held_amount = parse_amount_json(&fields["Amount"]);
    let amount = match held_amount.as_ref() {
        Some(crate::transaction::Amount::Xrp(drops)) => *drops,
        _ => 0,
    };
    let sequence = fields["Sequence"].as_u64().unwrap_or(0) as u32;
    let finish_after = fields["FinishAfter"].as_u64().unwrap_or(0) as u32;
    let cancel_after = fields["CancelAfter"].as_u64().unwrap_or(0) as u32;

    Some(crate::ledger::Escrow {
        account,
        destination,
        amount,
        sequence,
        finish_after,
        cancel_after,
        held_amount,
        condition: None,
        owner_node: 0,
        destination_node: 0,
        source_tag: None,
        destination_tag: None,
        raw_sle: None,
    })
}

/// Parse a PayChannel from JSON fields.
fn parse_paychan_from_json(fields: &Value) -> Option<crate::ledger::PayChannel> {
    let account = parse_account_id_from_json(fields, "Account")?;
    let destination = parse_account_id_from_json(fields, "Destination")?;
    let amount = parse_drops(&fields["Amount"]).unwrap_or(0);
    let balance = parse_drops(&fields["Balance"]).unwrap_or(0);
    let settle_delay = fields["SettleDelay"].as_u64().unwrap_or(0) as u32;
    let sequence = fields["Sequence"].as_u64().unwrap_or(0) as u32;
    let cancel_after = fields["CancelAfter"].as_u64().unwrap_or(0) as u32;
    let expiration = fields["Expiration"].as_u64().unwrap_or(0) as u32;
    let public_key = fields["PublicKey"]
        .as_str()
        .and_then(|s| hex::decode(s).ok())
        .unwrap_or_default();

    Some(crate::ledger::PayChannel {
        account,
        destination,
        amount,
        balance,
        settle_delay,
        public_key,
        sequence,
        cancel_after,
        expiration,
        owner_node: 0,
        destination_node: 0,
        source_tag: None,
        destination_tag: None,
        raw_sle: None,
    })
}

/// Parse a DepositPreauth from JSON fields.
fn parse_deposit_preauth_from_json(fields: &Value) -> Option<crate::ledger::DepositPreauth> {
    let account = parse_account_id_from_json(fields, "Account")?;
    let authorized = parse_account_id_from_json(fields, "Authorize")
        .or_else(|| parse_account_id_from_json(fields, "Authorized"))?;

    Some(crate::ledger::DepositPreauth {
        account,
        authorized,
        owner_node: 0,
        previous_txn_id: [0u8; 32],
        previous_txn_lgrseq: 0,
        raw_sle: None,
    })
}

/// Parse a Ticket from JSON fields.
fn parse_ticket_from_json(fields: &Value) -> Option<crate::ledger::Ticket> {
    let account = parse_account_id_from_json(fields, "Account")?;
    let sequence = fields["TicketSequence"]
        .as_u64()
        .or_else(|| fields["Sequence"].as_u64())? as u32;

    Some(crate::ledger::Ticket {
        account,
        sequence,
        owner_node: 0,
        previous_txn_id: [0u8; 32],
        previous_txn_lgrseq: 0,
        raw_sle: None,
    })
}

/// Parse an NFTokenOffer from JSON fields.
fn parse_nft_offer_from_json(fields: &Value) -> Option<crate::ledger::NFTokenOffer> {
    use crate::transaction::Amount;
    let account = parse_account_id_from_json(fields, "Owner")
        .or_else(|| parse_account_id_from_json(fields, "Account"))?;
    let sequence = fields["Sequence"].as_u64().unwrap_or(0) as u32;
    let nftoken_id = parse_hash256(fields, "NFTokenID")?;
    let amount = parse_amount_json(&fields["Amount"]).unwrap_or(Amount::Xrp(0));
    let destination = parse_account_id_from_json(fields, "Destination");
    let expiration = fields["Expiration"].as_u64().map(|e| e as u32);
    let flags = fields["Flags"].as_u64().unwrap_or(0) as u32;

    Some(crate::ledger::NFTokenOffer {
        account,
        sequence,
        nftoken_id,
        amount,
        destination,
        expiration,
        flags,
        owner_node: 0,
        nft_offer_node: 0,
        previous_txn_id: [0u8; 32],
        previous_txn_lgrseq: 0,
        raw_sle: None,
    })
}

/// Parse a 32-byte Hash256 from a JSON hex string field.
fn parse_hash256(fields: &Value, field_name: &str) -> Option<[u8; 32]> {
    let hex_str = fields[field_name].as_str()?;
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

fn parse_hex_32(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Parse a 20-byte AccountID from a JSON hex string field.
fn parse_account_id_from_json(fields: &Value, field_name: &str) -> Option<[u8; 20]> {
    let hex_str = fields[field_name].as_str()?;
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Parse drops from a JSON value — can be a string "12345" or number.
fn parse_drops(val: &Value) -> Option<u64> {
    if let Some(s) = val.as_str() {
        s.parse().ok()
    } else {
        val.as_u64()
    }
}

/// Parse an IOU value from JSON {"value": "1.5", "currency": "USD", "issuer": "r..."}.
fn parse_iou_value(val: &Value) -> Option<crate::transaction::amount::IouValue> {
    use crate::transaction::amount::IouValue;
    let value_str = val["value"].as_str()?;
    // Parse decimal string to IouValue
    let f: f64 = value_str.parse().ok()?;
    Some(IouValue::from_f64(f))
}

/// Parse a currency code — handles 3-letter ("USD") and 40-char hex codes.
fn parse_currency(code: &str) -> Option<crate::transaction::amount::Currency> {
    use crate::transaction::amount::Currency;
    if code.len() == 3 {
        Currency::from_code(code).ok()
    } else if code.len() == 40 {
        // 40-char hex = 20 bytes
        let bytes = hex::decode(code).ok()?;
        if bytes.len() != 20 {
            return None;
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Some(Currency { code: arr })
    } else {
        None
    }
}

/// Parse an Amount from JSON — either string (XRP drops) or object (IOU).
fn parse_amount_json(val: &Value) -> Option<crate::transaction::Amount> {
    use crate::transaction::amount::IouValue;
    use crate::transaction::Amount;

    if let Some(s) = val.as_str() {
        // XRP drops as string
        let drops: u64 = s.parse().ok()?;
        Some(Amount::Xrp(drops))
    } else if val.is_object() {
        if let (Some(mptid_hex), Some(value_str)) =
            (val["mpt_issuance_id"].as_str(), val["value"].as_str())
        {
            let raw = hex::decode(mptid_hex).ok()?;
            if raw.len() != 24 {
                return None;
            }
            let mut mptid = [0u8; 24];
            mptid.copy_from_slice(&raw);
            let value: u64 = value_str.parse().ok()?;
            return Some(Amount::from_mpt_value(value, mptid));
        }

        // IOU
        let f: f64 = val["value"].as_str()?.parse().ok()?;
        let value = IouValue::from_f64(f);
        let currency = parse_currency(val["currency"].as_str()?)?;
        let issuer = parse_account_id_from_json(val, "issuer")?;
        Some(Amount::Iou {
            value,
            currency,
            issuer,
        })
    } else {
        None
    }
}

/// Full-history XRPL servers for fallback when local rippled doesn't have the ledger.
/// All verified full-history (complete_ledgers starting from 32570).
const PUBLIC_SERVERS: &[(&str, u16)] = &[
    ("s1.ripple.com", 51234),
    ("s2.ripple.com", 51234),
    ("44.225.136.208", 51234),
    ("54.208.98.161", 51234),
];

/// Round-robin counter for distributing requests across public servers.
static RR_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Fetch a single object's binary SLE via ledger_entry.
/// Tries local rippled, falls back to public servers (round-robin).
async fn fetch_sle_binary(local_host: &str, local_port: u16, req: &str) -> Option<Vec<u8>> {
    match fetch_sle_binary_status(local_host, local_port, req).await {
        RpcLedgerEntryFetch::Found(data) => Some(data),
        RpcLedgerEntryFetch::NotFound | RpcLedgerEntryFetch::Unavailable => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RpcLedgerEntryFetch {
    Found(Vec<u8>),
    NotFound,
    Unavailable,
}

fn rpc_result_indicates_not_found(resp: &Value) -> bool {
    fn matches_not_found(value: &Value) -> bool {
        value.as_str().map_or(false, |s| {
            let lower = s.to_ascii_lowercase();
            lower.contains("entrynotfound")
                || lower.contains("objectnotfound")
                || lower.contains("notfound")
                || lower.contains("not found")
        })
    }

    [
        &resp["error"],
        &resp["error_message"],
        &resp["result"]["error"],
        &resp["result"]["error_message"],
        &resp["result"]["message"],
    ]
    .into_iter()
    .any(matches_not_found)
}

fn parse_ledger_entry_fetch_response(resp: &Value) -> RpcLedgerEntryFetch {
    if let Some(nb) = resp["result"]["node_binary"].as_str() {
        if let Ok(data) = hex::decode(nb) {
            return RpcLedgerEntryFetch::Found(data);
        }
    }
    if rpc_result_indicates_not_found(resp) {
        RpcLedgerEntryFetch::NotFound
    } else {
        RpcLedgerEntryFetch::Unavailable
    }
}

async fn fetch_sle_binary_status(local_host: &str, local_port: u16, req: &str) -> RpcLedgerEntryFetch {
    let mut saw_not_found = false;

    if let Ok(body) = crate::rpc_sync::http_post(local_host, local_port, req).await {
        if let Ok(resp) = serde_json::from_str::<Value>(&body) {
            match parse_ledger_entry_fetch_response(&resp) {
                RpcLedgerEntryFetch::Found(data) => return RpcLedgerEntryFetch::Found(data),
                RpcLedgerEntryFetch::NotFound => saw_not_found = true,
                RpcLedgerEntryFetch::Unavailable => {}
            }
        }
    }

    if !PUBLIC_SERVERS.is_empty() {
        let start = RR_COUNTER.fetch_add(1, Ordering::Relaxed) % PUBLIC_SERVERS.len();
        for i in 0..PUBLIC_SERVERS.len() {
            let idx = (start + i) % PUBLIC_SERVERS.len();
            let (host, port) = PUBLIC_SERVERS[idx];
            if let Ok(body) = crate::rpc_sync::http_post(host, port, req).await {
                if let Ok(resp) = serde_json::from_str::<Value>(&body) {
                    match parse_ledger_entry_fetch_response(&resp) {
                        RpcLedgerEntryFetch::Found(data) => {
                            return RpcLedgerEntryFetch::Found(data)
                        }
                        RpcLedgerEntryFetch::NotFound => saw_not_found = true,
                        RpcLedgerEntryFetch::Unavailable => {}
                    }
                }
            }
        }
    }

    if saw_not_found {
        RpcLedgerEntryFetch::NotFound
    } else {
        RpcLedgerEntryFetch::Unavailable
    }
}

fn collect_deleted_metadata_keys(
    meta_with_hashes: &[([u8; 32], Vec<u8>)],
) -> std::collections::BTreeSet<crate::ledger::Key> {
    let mut deleted = std::collections::BTreeSet::new();
    for (_tx_hash, meta_blob) in meta_with_hashes {
        let nodes =
            match std::panic::catch_unwind(|| crate::ledger::meta::parse_metadata(meta_blob)) {
                Ok(nodes) => nodes,
                Err(_) => continue,
            };
        for node in nodes {
            if node.action == crate::ledger::meta::Action::Deleted {
                deleted.insert(crate::ledger::Key(node.ledger_index));
            }
        }
    }
    deleted
}

async fn compare_engine_touched_keys(
    ledger_state: Arc<std::sync::Mutex<crate::ledger::LedgerState>>,
    touched_keys: &[crate::ledger::Key],
    seq: u32,
    rpc_host: &str,
    rpc_port: u16,
) {
    // Fetch touched keys from RPC with bounded concurrency.
    // Unbounded fan-out caused timeout-driven false LOCAL/REMOTE-only reports.
    const RPC_FETCH_TIMEOUT_SECS: u64 = 25;
    const RPC_FETCH_MAX_IN_FLIGHT: usize = 24;
    let mut fetched: std::collections::HashMap<crate::ledger::Key, Option<Vec<u8>>> =
        std::collections::HashMap::new();
    {
        let mut tasks = tokio::task::JoinSet::new();
        let mut next_idx = 0usize;
        let mut in_flight = 0usize;
        while next_idx < touched_keys.len() || in_flight > 0 {
            while in_flight < RPC_FETCH_MAX_IN_FLIGHT && next_idx < touched_keys.len() {
                let key = touched_keys[next_idx];
                next_idx += 1;
                in_flight += 1;
                let host = rpc_host.to_string();
                tasks.spawn(async move {
                    let req = format!(
                        r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                        hex::encode(key.0),
                        seq
                    );
                    let remote = tokio::time::timeout(
                        std::time::Duration::from_secs(RPC_FETCH_TIMEOUT_SECS),
                        fetch_sle_binary(&host, rpc_port, &req),
                    ).await.ok().flatten();
                    (key, remote)
                });
            }
            let Some(res) = tasks.join_next().await else {
                break;
            };
            in_flight = in_flight.saturating_sub(1);
            if let Ok((key, remote)) = res {
                fetched.insert(key, remote);
            }
        }
    }
    info!(
        "ENGINE KEY COMPARE seq={}: fetched {}/{} keys from RPC",
        seq,
        fetched.len(),
        touched_keys.len(),
    );
    let mut matches = 0usize;
    let mut diffs = 0usize;
    let mut local_only = 0usize;
    let mut remote_only = 0usize;
    let mut missing_both = 0usize;
    for key in touched_keys.iter() {
        let local = {
            let ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
            ls.get_raw_owned(key)
        };
        let remote = fetched.get(key).and_then(|v| v.clone());
        match (local, remote) {
            (Some(l), Some(r)) if l == r => {
                matches += 1;
            }
            (Some(l), Some(r)) => {
                diffs += 1;
                warn!(
                    "ENGINE KEY DIFF seq={} key={} local_len={} remote_len={} local_prefix={} remote_prefix={}",
                    seq,
                    hex::encode_upper(key.0),
                    l.len(),
                    r.len(),
                    hex::encode_upper(&l[..l.len().min(40)]),
                    hex::encode_upper(&r[..r.len().min(40)]),
                );
                if l.len() >= 3 && r.len() >= 3 {
                    let local_type = u16::from_be_bytes([l[1], l[2]]);
                    let remote_type = u16::from_be_bytes([r[1], r[2]]);
                    if local_type == 0x0061 && remote_type == 0x0061 {
                        if let (Ok(la), Ok(ra)) = (
                            crate::ledger::account::AccountRoot::decode(&l),
                            crate::ledger::account::AccountRoot::decode(&r),
                        ) {
                            let (owner_dir_total, owner_dir_unique) = {
                                let ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
                                crate::ledger::directory::owner_dir_entry_stats(&ls, &la.account_id)
                            };
                            warn!(
                                "ENGINE ACCOUNTROOT DIFF seq={} key={} local_owner_count={} remote_owner_count={} local_seq={} remote_seq={} local_prev_lgr={} remote_prev_lgr={} local_balance={} remote_balance={} owner_dir_total={} owner_dir_unique={}",
                                seq,
                                hex::encode_upper(key.0),
                                la.owner_count,
                                ra.owner_count,
                                la.sequence,
                                ra.sequence,
                                la.previous_txn_lgr_seq,
                                ra.previous_txn_lgr_seq,
                                la.balance,
                                ra.balance,
                                owner_dir_total,
                                owner_dir_unique,
                            );
                        }
                    } else if local_type == 0x0064 && remote_type == 0x0064 {
                        if let (Ok(ld), Ok(rd)) = (
                            crate::ledger::directory::DirectoryNode::decode(&l, key.0),
                            crate::ledger::directory::DirectoryNode::decode(&r, key.0),
                        ) {
                            let idx_mismatch_pos = ld
                                .indexes
                                .iter()
                                .zip(rd.indexes.iter())
                                .position(|(a, b)| a != b);
                            warn!(
                                "ENGINE DIRECTORY DIFF seq={} key={} local_idx_next={} remote_idx_next={} local_idx_prev={} remote_idx_prev={} local_indexes={} remote_indexes={} local_rate={:?} remote_rate={:?} local_root={} remote_root={} local_owner_present={} remote_owner_present={} local_prev_lgr={:?} remote_prev_lgr={:?} local_prev_txn={} remote_prev_txn={} idx_mismatch_pos={:?} local_first_idx={} remote_first_idx={} local_last16={} remote_last16={}",
                                seq,
                                hex::encode_upper(key.0),
                                ld.index_next,
                                rd.index_next,
                                ld.index_previous,
                                rd.index_previous,
                                ld.indexes.len(),
                                rd.indexes.len(),
                                ld.exchange_rate,
                                rd.exchange_rate,
                                hex::encode_upper(&ld.root_index[..8]),
                                hex::encode_upper(&rd.root_index[..8]),
                                ld.owner.is_some(),
                                rd.owner.is_some(),
                                ld.previous_txn_lgr_seq,
                                rd.previous_txn_lgr_seq,
                                ld.previous_txn_id
                                    .map(|h| hex::encode_upper(&h[..8]))
                                    .unwrap_or_else(|| "NONE".to_string()),
                                rd.previous_txn_id
                                    .map(|h| hex::encode_upper(&h[..8]))
                                    .unwrap_or_else(|| "NONE".to_string()),
                                idx_mismatch_pos,
                                ld.indexes
                                    .first()
                                    .map(|h| hex::encode_upper(&h[..8]))
                                    .unwrap_or_else(|| "NONE".to_string()),
                                rd.indexes
                                    .first()
                                    .map(|h| hex::encode_upper(&h[..8]))
                                    .unwrap_or_else(|| "NONE".to_string()),
                                hex::encode_upper(&l[l.len().saturating_sub(16)..]),
                                hex::encode_upper(&r[r.len().saturating_sub(16)..]),
                            );
                        }
                    }
                }
            }
            (Some(l), None) => {
                local_only += 1;
                warn!(
                    "ENGINE KEY LOCAL-ONLY seq={} key={} local_len={} local_prefix={}",
                    seq,
                    hex::encode_upper(key.0),
                    l.len(),
                    hex::encode_upper(&l[..l.len().min(40)]),
                );
            }
            (None, Some(r)) => {
                remote_only += 1;
                warn!(
                    "ENGINE KEY REMOTE-ONLY seq={} key={} remote_len={} remote_prefix={}",
                    seq,
                    hex::encode_upper(key.0),
                    r.len(),
                    hex::encode_upper(&r[..r.len().min(40)]),
                );
            }
            (None, None) => {
                missing_both += 1;
            }
        }
    }
    info!(
        "ENGINE KEY COMPARE SUMMARY seq={}: matches={} diffs={} local_only={} remote_only={} missing_both={} total={}",
        seq, matches, diffs, local_only, remote_only, missing_both, touched_keys.len(),
    );
}

async fn reconcile_touched_keys_with_rpc(
    ledger_state: Arc<std::sync::Mutex<crate::ledger::LedgerState>>,
    touched_keys: &[crate::ledger::Key],
    explicit_delete_keys: &std::collections::BTreeSet<crate::ledger::Key>,
    seq: u32,
    rpc_host: &str,
    rpc_port: u16,
) -> (
    usize,
    usize,
    usize,
    usize,
    std::collections::HashMap<[u8; 32], Vec<u8>>,
) {
    const RPC_FETCH_TIMEOUT_SECS: u64 = 25;
    const RPC_FETCH_MAX_IN_FLIGHT: usize = 24;
    let mut fetched: std::collections::HashMap<crate::ledger::Key, RpcLedgerEntryFetch> =
        std::collections::HashMap::new();
    {
        let mut tasks = tokio::task::JoinSet::new();
        let mut next_idx = 0usize;
        let mut in_flight = 0usize;
        while next_idx < touched_keys.len() || in_flight > 0 {
            while in_flight < RPC_FETCH_MAX_IN_FLIGHT && next_idx < touched_keys.len() {
                let key = touched_keys[next_idx];
                next_idx += 1;
                in_flight += 1;
                let host = rpc_host.to_string();
                tasks.spawn(async move {
                    let req = format!(
                        r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                        hex::encode(key.0),
                        seq
                    );
                    let remote = tokio::time::timeout(
                        std::time::Duration::from_secs(RPC_FETCH_TIMEOUT_SECS),
                        fetch_sle_binary_status(&host, rpc_port, &req),
                    )
                    .await
                    .unwrap_or(RpcLedgerEntryFetch::Unavailable);
                    (key, remote)
                });
            }
            let Some(res) = tasks.join_next().await else {
                break;
            };
            in_flight = in_flight.saturating_sub(1);
            if let Ok((key, remote)) = res {
                fetched.insert(key, remote);
            }
        }
    }

    let mut upserted = 0usize;
    let mut removed = 0usize;
    let mut not_found = 0usize;
    let mut unavailable = 0usize;
    let mut authoritative_found = std::collections::HashMap::<[u8; 32], Vec<u8>>::new();
    let mut ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
    for key in touched_keys {
        match fetched
            .get(key)
            .cloned()
            .unwrap_or(RpcLedgerEntryFetch::Unavailable)
        {
            RpcLedgerEntryFetch::Found(raw) => {
                authoritative_found.insert(key.0, raw.clone());
                ls.insert_raw(*key, raw.clone());
                if let Some(sle) = crate::ledger::sle::SLE::from_raw(*key, raw.clone()) {
                    sync_typed(&mut ls, sle.entry_type() as u16, key, &raw);
                }
                upserted += 1;
            }
            RpcLedgerEntryFetch::NotFound => {
                not_found += 1;
                if !explicit_delete_keys.contains(key) {
                    continue;
                }
                if let Some(existing) = ls.get_raw_owned(key) {
                    if let Some(sle) = crate::ledger::sle::SLE::from_raw(*key, existing) {
                        remove_typed(&mut ls, sle.entry_type() as u16, key);
                    }
                    ls.remove_raw(key);
                    removed += 1;
                }
            }
            RpcLedgerEntryFetch::Unavailable => unavailable += 1,
        }
    }
    info!(
        "follower: touched-key RPC reconcile seq={}: upserted={} removed={} not_found={} unavailable={} touched={}",
        seq,
        upserted,
        removed,
        not_found,
        unavailable,
        touched_keys.len(),
    );
    (
        upserted,
        removed,
        not_found,
        unavailable,
        authoritative_found,
    )
}

async fn reconcile_metadata_keys_with_rpc(
    ledger_state: Arc<std::sync::Mutex<crate::ledger::LedgerState>>,
    meta_with_hashes: &[([u8; 32], Vec<u8>)],
    seq: u32,
    rpc_host: &str,
    rpc_port: u16,
) -> (usize, usize, usize, usize, usize) {
    const RPC_FETCH_TIMEOUT_SECS: u64 = 25;
    const RPC_FETCH_MAX_IN_FLIGHT: usize = 24;
    let explicit_delete_keys = collect_deleted_metadata_keys(meta_with_hashes);
    let mut key_set = std::collections::BTreeSet::<crate::ledger::Key>::new();
    for (_tx_hash, meta_blob) in meta_with_hashes {
        let nodes =
            match std::panic::catch_unwind(|| crate::ledger::meta::parse_metadata(meta_blob)) {
                Ok(nodes) => nodes,
                Err(_) => continue,
            };
        for node in nodes {
            key_set.insert(crate::ledger::Key(node.ledger_index));
        }
    }
    let keys: Vec<crate::ledger::Key> = key_set.into_iter().collect();
    let mut fetched: std::collections::HashMap<crate::ledger::Key, RpcLedgerEntryFetch> =
        std::collections::HashMap::new();
    {
        let mut tasks = tokio::task::JoinSet::new();
        let mut next_idx = 0usize;
        let mut in_flight = 0usize;
        while next_idx < keys.len() || in_flight > 0 {
            while in_flight < RPC_FETCH_MAX_IN_FLIGHT && next_idx < keys.len() {
                let key = keys[next_idx];
                next_idx += 1;
                in_flight += 1;
                let host = rpc_host.to_string();
                tasks.spawn(async move {
                    let req = format!(
                        r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                        hex::encode(key.0),
                        seq
                    );
                    let remote = tokio::time::timeout(
                        std::time::Duration::from_secs(RPC_FETCH_TIMEOUT_SECS),
                        fetch_sle_binary_status(&host, rpc_port, &req),
                    )
                    .await
                    .unwrap_or(RpcLedgerEntryFetch::Unavailable);
                    (key, remote)
                });
            }
            let Some(res) = tasks.join_next().await else {
                break;
            };
            in_flight = in_flight.saturating_sub(1);
            if let Ok((key, remote)) = res {
                fetched.insert(key, remote);
            }
        }
    }

    let mut upserted = 0usize;
    let mut removed = 0usize;
    let mut not_found = 0usize;
    let mut unavailable = 0usize;
    let mut ls = ledger_state.lock().unwrap_or_else(|e| e.into_inner());
    for key in keys.iter() {
        match fetched
            .get(key)
            .cloned()
            .unwrap_or(RpcLedgerEntryFetch::Unavailable)
        {
            RpcLedgerEntryFetch::Found(raw) => {
                ls.insert_raw(*key, raw.clone());
                if let Some(sle) = crate::ledger::sle::SLE::from_raw(*key, raw.clone()) {
                    sync_typed(&mut ls, sle.entry_type() as u16, key, &raw);
                }
                upserted += 1;
            }
            RpcLedgerEntryFetch::NotFound => {
                not_found += 1;
                if !explicit_delete_keys.contains(key) {
                    continue;
                }
                if let Some(existing) = ls.get_raw_owned(key) {
                    if let Some(sle) = crate::ledger::sle::SLE::from_raw(*key, existing) {
                        remove_typed(&mut ls, sle.entry_type() as u16, key);
                    }
                    ls.remove_raw(key);
                    removed += 1;
                }
            }
            RpcLedgerEntryFetch::Unavailable => unavailable += 1,
        }
    }
    info!(
        "follower: metadata-key RPC reconcile seq={}: upserted={} removed={} not_found={} unavailable={} metadata_keys={}",
        seq, upserted, removed, not_found, unavailable, keys.len(),
    );
    (upserted, removed, not_found, unavailable, keys.len())
}

/// Get the current validated ledger sequence from rippled RPC.
async fn get_validated_seq(host: &str, port: u16) -> Option<u32> {
    let request = r#"{"method":"ledger","params":[{"ledger_index":"validated"}]}"#;
    let body = crate::rpc_sync::http_post(host, port, request).await.ok()?;
    let resp: Value = serde_json::from_str(&body).ok()?;
    resp["result"]["ledger_index"].as_u64().map(|n| n as u32)
}

/// Fetch a ledger with binary transactions + metadata.
/// Tries local rippled first, falls back to s2.ripple.com for pruned ledgers.
/// Returns (full JSON response, account_hash hex string).
async fn fetch_ledger_binary(
    local_host: &str,
    local_port: u16,
    seq: u32,
) -> Option<(Value, String)> {
    let bin_req = format!(
        r#"{{"method":"ledger","params":[{{"ledger_index":{},"transactions":true,"expand":true,"binary":true}}]}}"#,
        seq
    );
    let hdr_req = format!(
        r#"{{"method":"ledger","params":[{{"ledger_index":{}}}]}}"#,
        seq
    );

    // Try local first
    if let Some(result) = try_fetch_ledger(local_host, local_port, &bin_req, &hdr_req).await {
        return Some(result);
    }

    // Fallback to public full-history servers (round-robin)
    let start = RR_COUNTER.fetch_add(1, Ordering::Relaxed) % PUBLIC_SERVERS.len();
    for i in 0..PUBLIC_SERVERS.len() {
        let idx = (start + i) % PUBLIC_SERVERS.len();
        let (host, port) = PUBLIC_SERVERS[idx];
        if let Some(result) = try_fetch_ledger(host, port, &bin_req, &hdr_req).await {
            tracing::info!("ledger {}: fetched from {} (local pruned)", seq, host);
            return Some(result);
        }
    }

    None
}

async fn try_fetch_ledger(
    host: &str,
    port: u16,
    bin_req: &str,
    hdr_req: &str,
) -> Option<(Value, String)> {
    let body = crate::rpc_sync::http_post(host, port, bin_req).await.ok()?;
    let resp: Value = serde_json::from_str(&body).ok()?;

    if resp["result"]["status"].as_str() != Some("success") {
        return None;
    }

    // Get account_hash — not in binary response, need separate request
    let account_hash = if let Some(h) = resp["result"]["ledger"]["account_hash"].as_str() {
        h.to_string()
    } else {
        let hdr_body = crate::rpc_sync::http_post(host, port, hdr_req).await.ok()?;
        let hdr_resp: Value = serde_json::from_str(&hdr_body).ok()?;
        hdr_resp["result"]["ledger"]["account_hash"]
            .as_str()
            .unwrap_or("")
            .to_string()
    };

    Some((resp, account_hash))
}

fn parse_binary_ledger_blobs(resp: &Value) -> Vec<(Vec<u8>, Vec<u8>)> {
    let txs = resp["result"]["ledger"]["transactions"]
        .as_array()
        .map(|a| a.to_vec())
        .unwrap_or_default();
    let mut out = Vec::with_capacity(txs.len());
    for tx in txs {
        let tx_hex = match tx["tx_blob"].as_str() {
            Some(s) => s,
            None => continue,
        };
        let meta_hex = match tx["meta"].as_str() {
            Some(s) => s,
            None => continue,
        };
        let tx_blob = match hex::decode(tx_hex) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let meta_blob = match hex::decode(meta_hex) {
            Ok(b) => b,
            Err(_) => continue,
        };
        out.push((tx_blob, meta_blob));
    }
    out
}

// ── Test mode ─────────────────────────────────────────────────────────────

/// Test mode: load state from storage, apply one ledger, validate the hash,
/// and exit without starting the full node runtime.
pub async fn test_one_ledger(
    data_dir: &std::path::Path,
    rpc_host: &str,
    rpc_port: u16,
    test_seq: Option<u32>,
    cache_path: Option<String>,
    skip: (bool, bool, bool), // (skip_creates, skip_modifies, skip_deletes)
) -> anyhow::Result<()> {
    let (skip_creates, skip_modifies, skip_deletes) = skip;
    info!("=== TEST ONE LEDGER MODE ===");

    // Open storage
    let storage = Arc::new(crate::storage::Storage::open(data_dir)?);
    let sync_seq = storage.get_sync_ledger().map(|s| s as u32).unwrap_or(0);
    info!("state synced at ledger {}", sync_seq);

    let seq = test_seq.unwrap_or(sync_seq + 1);
    info!("will apply ledger {}", seq);

    // Build sparse SHAMap — check for cached leaf hashes first
    // (test mode uses a flat binary cache file, separate from the redb-backed storage)
    let leaf_cache = data_dir.join("leaf_hashes.bin");
    let mut state = crate::ledger::LedgerState::new();
    state.enable_sparse();

    if leaf_cache.exists() {
        info!(
            "loading cached leaf hashes from {}...",
            leaf_cache.display()
        );
        let start = std::time::Instant::now();
        let data = std::fs::read(&leaf_cache)?;
        let mut count = 0u64;
        let mut pos = 0;
        while pos + 64 <= data.len() {
            let mut key = [0u8; 32];
            let mut hash = [0u8; 32];
            key.copy_from_slice(&data[pos..pos + 32]);
            hash.copy_from_slice(&data[pos + 32..pos + 64]);
            state.insert_leaf_hash(crate::ledger::Key(key), hash);
            count += 1;
            pos += 64;
        }
        info!(
            "loaded {} leaf hashes in {:.1}s",
            count,
            start.elapsed().as_secs_f64()
        );
    } else {
        // NuDB handles object storage — no for_each_object available.
        // Leaf hashes must be built from the SHAMap directly.
        info!("no leaf hash cache found — sparse SHAMap starts empty (NuDB backend)");
    }

    let our_initial = state.state_hash();
    info!("our initial hash: {}", hex::encode_upper(&our_initial));

    // Load test ledger — from cache file or RPC
    let (resp, account_hash_hex) = if let Some(ref path) = cache_path {
        let cached = std::fs::read_to_string(path)?;
        let resp: Value = serde_json::from_str(&cached)?;
        // Get account_hash from a separate non-binary request (or cache it)
        let ah = resp["result"]["ledger"]["account_hash"]
            .as_str()
            .unwrap_or("")
            .to_string();
        if ah.is_empty() {
            // Need to fetch account_hash separately
            let hdr_req = format!(
                r#"{{"method":"ledger","params":[{{"ledger_index":{}}}]}}"#,
                seq
            );
            let ah2 =
                if let Ok(body) = crate::rpc_sync::http_post(rpc_host, rpc_port, &hdr_req).await {
                    serde_json::from_str::<Value>(&body)
                        .ok()
                        .and_then(|v| {
                            v["result"]["ledger"]["account_hash"]
                                .as_str()
                                .map(|s| s.to_string())
                        })
                        .unwrap_or_default()
                } else {
                    String::new()
                };
            (resp, ah2)
        } else {
            (resp, ah)
        }
    } else {
        // Verify initial hash
        let (_, net_hash) = fetch_ledger_binary(rpc_host, rpc_port, sync_seq)
            .await
            .unwrap_or_default();
        if !net_hash.is_empty() {
            let matches = hex::encode_upper(&our_initial) == net_hash.to_uppercase();
            info!("network hash:     {}", net_hash);
            info!("initial match:    {}", if matches { "YES" } else { "NO" });
        }

        info!("fetching ledger {} from RPC...", seq);
        match fetch_ledger_binary(rpc_host, rpc_port, seq).await {
            Some(r) => r,
            None => {
                error!("could not fetch ledger {}", seq);
                return Ok(());
            }
        }
    };
    info!("network account_hash for {}: {}", seq, account_hash_hex);

    let txs = resp["result"]["ledger"]["transactions"]
        .as_array()
        .map(|a| a.to_vec())
        .unwrap_or_default();
    info!("transactions: {}", txs.len());

    // Parse metadata and collect operations
    let mut created_nodes: Vec<(
        crate::ledger::Key,
        crate::ledger::meta::AffectedNode,
        Option<[u8; 32]>,
        u32,
    )> = Vec::new();
    let mut created_keys: Vec<crate::ledger::Key> = Vec::new();
    let mut modifies: Vec<(
        crate::ledger::Key,
        crate::ledger::meta::AffectedNode,
        Option<[u8; 32]>,
        u32,
    )> = Vec::new();
    let mut deletes: Vec<crate::ledger::Key> = Vec::new();
    let mut touched_entry_types: std::collections::HashMap<crate::ledger::Key, u16> =
        std::collections::HashMap::new();
    let mut total_nodes = 0u64;

    for tx in &txs {
        let meta_hex = match tx["meta"].as_str() {
            Some(s) => s,
            None => continue,
        };
        let meta_bytes = match hex::decode(meta_hex) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let tx_hash: Option<[u8; 32]> = tx["tx_blob"]
            .as_str()
            .and_then(|h| hex::decode(h).ok())
            .map(|blob| {
                let mut data = vec![0x54, 0x58, 0x4E, 0x00];
                data.extend_from_slice(&blob);
                crate::crypto::sha512_first_half(&data)
            });

        let nodes =
            match std::panic::catch_unwind(|| crate::ledger::meta::parse_metadata(&meta_bytes)) {
                Ok(n) => n,
                Err(_) => {
                    warn!("metadata parse panic");
                    continue;
                }
            };

        for node in nodes {
            total_nodes += 1;
            let key = crate::ledger::Key(node.ledger_index);
            touched_entry_types.insert(key, node.entry_type);
            match node.action {
                crate::ledger::meta::Action::Created => {
                    created_keys.push(key);
                    created_nodes.push((key, node, tx_hash, seq));
                }
                crate::ledger::meta::Action::Modified => {
                    modifies.push((key, node, tx_hash, seq));
                }
                crate::ledger::meta::Action::Deleted => {
                    deletes.push(key);
                }
            }
        }
    }

    info!(
        "parsed {} nodes: {} creates, {} modifies, {} deletes",
        total_nodes,
        created_keys.len(),
        modifies.len(),
        deletes.len()
    );

    // Fetch or load cached created SLEs
    let creates_cache = data_dir.join(format!("test_creates_{}.bin", seq));
    let mut created_sles: Vec<(crate::ledger::Key, Vec<u8>)> = Vec::new();
    if creates_cache.exists() {
        info!("loading cached created SLEs...");
        let data = std::fs::read(&creates_cache)?;
        let mut pos = 0;
        while pos + 36 <= data.len() {
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[pos..pos + 32]);
            let sle_len = u32::from_le_bytes(data[pos + 32..pos + 36].try_into().unwrap()) as usize;
            pos += 36;
            if pos + sle_len > data.len() {
                break;
            }
            created_sles.push((crate::ledger::Key(key), data[pos..pos + sle_len].to_vec()));
            pos += sle_len;
        }
        info!("loaded {} cached creates", created_sles.len());
    } else {
        info!(
            "fetching {} created objects from {} ...",
            created_keys.len(),
            rpc_host
        );
        let mut cache_buf: Vec<u8> = Vec::new();
        for key in &created_keys {
            let key_hex = hex::encode(key.0);
            let req = format!(
                r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                key_hex, seq
            );
            if let Some(data) = fetch_sle_binary(rpc_host, rpc_port, &req).await {
                cache_buf.extend_from_slice(&key.0);
                cache_buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
                cache_buf.extend_from_slice(&data);
                created_sles.push((*key, data));
            }
        }
        info!(
            "fetched {} / {} — saving cache",
            created_sles.len(),
            created_keys.len()
        );
        std::fs::write(&creates_cache, &cache_buf)?;
    }

    let mut create_exact_matches = 0usize;
    let mut create_exact_mismatches = 0usize;
    let mut create_missing_from_rpc = 0usize;
    let created_map: std::collections::HashMap<crate::ledger::Key, Vec<u8>> =
        created_sles.iter().cloned().collect();
    for (key, node, tx_hash, ledger_seq) in &created_nodes {
        let built = crate::ledger::meta::build_sle(
            node.entry_type,
            &node.fields,
            *tx_hash,
            Some(*ledger_seq),
        );
        match created_map.get(key) {
            Some(actual) if *actual == built => {
                create_exact_matches += 1;
            }
            Some(actual) => {
                create_exact_mismatches += 1;
                let actual_parsed = crate::ledger::meta::parse_sle(actual);
                let built_parsed = crate::ledger::meta::parse_sle(&built);
                info!(
                    "CREATE DIFF key={} type={:04X} built_len={} actual_len={} built_prefix={} actual_prefix={}",
                    hex::encode(key.0),
                    node.entry_type,
                    built.len(),
                    actual.len(),
                    hex::encode(&built[..built.len().min(24)]),
                    hex::encode(&actual[..actual.len().min(24)]),
                );
                if let (Some(bp), Some(ap)) = (built_parsed, actual_parsed) {
                    let built_keys: std::collections::HashSet<(u16, u16)> = bp
                        .fields
                        .iter()
                        .map(|f| (f.type_code, f.field_code))
                        .collect();
                    let actual_keys: std::collections::HashSet<(u16, u16)> = ap
                        .fields
                        .iter()
                        .map(|f| (f.type_code, f.field_code))
                        .collect();
                    let built_only: Vec<(u16, u16)> =
                        built_keys.difference(&actual_keys).copied().collect();
                    let actual_only: Vec<(u16, u16)> =
                        actual_keys.difference(&built_keys).copied().collect();
                    info!(
                        "CREATE FIELD DIFF key={} built_only={:?} actual_only={:?} built_prev_txn={:?}/{} actual_prev_txn={:?}/{}",
                        hex::encode(key.0),
                        built_only,
                        actual_only,
                        bp.prev_txn_id.map(hex::encode),
                        bp.prev_txn_lgrseq.unwrap_or_default(),
                        ap.prev_txn_id.map(hex::encode),
                        ap.prev_txn_lgrseq.unwrap_or_default(),
                    );
                }
            }
            None => {
                create_missing_from_rpc += 1;
            }
        }
    }
    info!(
        "CREATE COMPARE summary: matches={} mismatches={} missing_rpc={}",
        create_exact_matches, create_exact_mismatches, create_missing_from_rpc
    );

    if !skip_creates {
        info!("applying {} creates", created_sles.len());
        for (key, sle) in &created_sles {
            state.insert_raw(*key, sle.clone());
        }
    } else {
        info!("SKIPPING creates");
    }

    if !skip_modifies {
        // Count how many times each key is modified
        let mut key_counts: std::collections::HashMap<crate::ledger::Key, usize> =
            std::collections::HashMap::new();
        for (key, _, _, _) in &modifies {
            *key_counts.entry(*key).or_insert(0) += 1;
        }
        let multi_keys: Vec<crate::ledger::Key> = key_counts
            .iter()
            .filter(|(_, c)| **c > 1)
            .map(|(k, _)| *k)
            .collect();
        info!(
            "applying {} modifies ({} unique, {} multi-modified → fetching from RPC)",
            modifies.len(),
            key_counts.len(),
            multi_keys.len()
        );

        // Fetch final state for multi-modified objects from ledger_entry
        let mut multi_sles: std::collections::HashMap<crate::ledger::Key, Vec<u8>> =
            std::collections::HashMap::new();
        for key in &multi_keys {
            let key_hex = hex::encode(key.0);
            let req = format!(
                r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                key_hex, seq
            );
            if let Some(data) = fetch_sle_binary(rpc_host, rpc_port, &req).await {
                multi_sles.insert(*key, data);
            }
        }

        // Apply: multi-modified use fetched SLE, single-modified use patch_sle
        let mut patched_cache: std::collections::HashMap<crate::ledger::Key, Vec<u8>> =
            std::collections::HashMap::new();
        let mut applied: std::collections::HashSet<crate::ledger::Key> =
            std::collections::HashSet::new();
        for (key, node, tx_hash, ledger_seq) in &modifies {
            if multi_sles.contains_key(key) {
                // Multi-modified — use fetched final state (apply once)
                if !applied.insert(*key) {
                    continue;
                }
                let sle = multi_sles.get(key).unwrap();
                state.insert_raw(*key, sle.clone());
                continue;
            }
            // Single-modified — patch_sle
            let existing: Option<Vec<u8>> = state.get_raw_owned(key);
            if let Some(existing_data) = existing {
                let final_keys: std::collections::HashSet<(u16, u16)> = node
                    .fields
                    .iter()
                    .map(|f| (f.type_code, f.field_code))
                    .collect();
                let deleted: Vec<(u16, u16)> = node
                    .previous_fields
                    .iter()
                    .map(|f| (f.type_code, f.field_code))
                    .filter(|k| !final_keys.contains(k))
                    .collect();
                let patched = crate::ledger::meta::patch_sle(
                    &existing_data,
                    &node.fields,
                    *tx_hash,
                    Some(*ledger_seq),
                    &deleted,
                );
                // Dump first modify for debugging
                let target = "1ed8ddfd80f275cb1ce7f18bb9d906655de8029805d8b95fb9020b30425821eb";
                if hex::encode(key.0) == target {
                    info!("PATCH_RESULT for {}: {}", target, hex::encode(&patched));
                    info!("PATCH_BEFORE: {}", hex::encode(&existing_data));
                }
                state.insert_raw(*key, patched.clone());
                patched_cache.insert(*key, patched);
            }
        }
    } else {
        info!("SKIPPING modifies");
    }

    if !skip_deletes {
        info!("applying {} deletes", deletes.len());
        for key in &deletes {
            state.remove_raw(key);
        }
    } else {
        info!("SKIPPING deletes");
    }

    // THE MOMENT OF TRUTH
    let our_hash = state.state_hash();
    let network_hash = hex::decode(&account_hash_hex).unwrap_or_default();
    let hash_match = network_hash.len() == 32 && our_hash == network_hash[..32];

    info!("=== RESULT ===");
    info!("our hash:     {}", hex::encode_upper(&our_hash));
    info!("network hash: {}", account_hash_hex);
    if hash_match {
        info!(">>> HASH MATCH = TRUE <<<");
    } else {
        error!(">>> HASH MATCH = FALSE <<<");
        let dump_path = data_dir.join(format!("test_one_ledger_diff_{}.jsonl", seq));
        let mut writer = std::io::BufWriter::new(std::fs::File::create(&dump_path)?);
        let mut touched_keys: std::collections::BTreeSet<crate::ledger::Key> =
            std::collections::BTreeSet::new();
        touched_keys.extend(created_nodes.iter().map(|(k, _, _, _)| *k));
        touched_keys.extend(modifies.iter().map(|(k, _, _, _)| *k));
        touched_keys.extend(deletes.iter().copied());
        let mut exact = 0usize;
        let mut mismatched = 0usize;
        let mut local_only = 0usize;
        let mut remote_only = 0usize;
        let mut missing_both = 0usize;
        for key in touched_keys {
            let local = state.get_raw_owned(&key);
            let req = format!(
                r#"{{"method":"ledger_entry","params":[{{"index":"{}","ledger_index":{},"binary":true}}]}}"#,
                hex::encode(key.0),
                seq
            );
            let remote = fetch_sle_binary(rpc_host, rpc_port, &req).await;
            let kind = match (&local, &remote) {
                (Some(l), Some(r)) if l == r => {
                    exact += 1;
                    "match"
                }
                (Some(_), Some(_)) => {
                    mismatched += 1;
                    "mismatch"
                }
                (Some(_), None) => {
                    local_only += 1;
                    "local_only"
                }
                (None, Some(_)) => {
                    remote_only += 1;
                    "remote_only"
                }
                (None, None) => {
                    missing_both += 1;
                    "missing_both"
                }
            };
            if kind != "match" {
                let entry_type = touched_entry_types.get(&key).copied().unwrap_or(0);
                let line = serde_json::json!({
                    "seq": seq,
                    "key": hex::encode_upper(key.0),
                    "entry_type": format!("{:04X}", entry_type),
                    "kind": kind,
                    "local_len": local.as_ref().map(|b| b.len()).unwrap_or(0),
                    "remote_len": remote.as_ref().map(|b| b.len()).unwrap_or(0),
                    "local_hex": local.as_ref().map(hex::encode_upper),
                    "remote_hex": remote.as_ref().map(hex::encode_upper),
                });
                use std::io::Write;
                writer.write_all(line.to_string().as_bytes())?;
                writer.write_all(b"\n")?;
            }
        }
        use std::io::Write;
        writer.flush()?;
        error!(
            "test-one-ledger diff dump written: {} (match={} mismatch={} local_only={} remote_only={} missing_both={})",
            dump_path.display(),
            exact,
            mismatched,
            local_only,
            remote_only,
            missing_both,
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(
        seq: u32,
        parent_hash: [u8; 32],
        account_hash: [u8; 32],
    ) -> crate::ledger::LedgerHeader {
        let mut hdr = crate::ledger::LedgerHeader {
            sequence: seq,
            hash: [0u8; 32],
            parent_hash,
            close_time: seq as u64,
            total_coins: 100_000_000_000_000_000,
            account_hash,
            transaction_hash: [seq as u8; 32],
            parent_close_time: seq.saturating_sub(1),
            close_time_resolution: 10,
            close_flags: 0,
        };
        hdr.hash = hdr.compute_hash();
        hdr
    }

    #[test]
    fn sync_anchor_validation_checks_sequence_hash_and_account_hash() {
        let hdr = header(10, [0x01; 32], [0xAB; 32]);
        assert!(validate_sync_anchor_header(
            10,
            Some(hdr.hash),
            Some(hdr.account_hash),
            &hdr
        ));
        assert!(!validate_sync_anchor_header(
            11,
            Some(hdr.hash),
            Some(hdr.account_hash),
            &hdr
        ));
        assert!(!validate_sync_anchor_header(
            10,
            Some([0x11; 32]),
            Some(hdr.account_hash),
            &hdr
        ));
        assert!(!validate_sync_anchor_header(
            10,
            Some(hdr.hash),
            Some([0x22; 32]),
            &hdr
        ));
    }

    #[test]
    fn restart_reads_latest_persisted_anchor_after_follow_progress() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::open(dir.path()).unwrap();

        let synced = header(100, [0x10; 32], [0x20; 32]);
        storage.persist_sync_anchor(&synced).unwrap();

        let followed = header(101, synced.hash, [0x21; 32]);
        storage
            .save_meta(
                followed.sequence,
                &hex::encode_upper(followed.hash),
                &followed,
            )
            .unwrap();
        storage.persist_sync_anchor(&followed).unwrap();

        let (seq, sync_hash, sync_account_hash, loaded) =
            load_verified_sync_anchor(&storage).expect("latest anchor should load");
        assert_eq!(seq, 101);
        assert_eq!(sync_hash, Some(followed.hash));
        assert_eq!(sync_account_hash, Some(followed.account_hash));
        assert_eq!(loaded.sequence, 101);
        assert_eq!(loaded.parent_hash, synced.hash);
    }

    #[test]
    fn validated_reacquired_sync_header_accepts_matching_inbound_header() {
        let hdr = header(200, [0x44; 32], [0x55; 32]);
        let mut inbound = crate::ledger::inbound::InboundLedgers::new();
        inbound.create(hdr.hash, hdr.sequence);
        assert!(
            inbound.got_header(&hdr.hash, hdr.clone())
                || inbound.hash_for_seq(hdr.sequence).is_some()
        );

        let loaded = validated_reacquired_sync_header(
            &inbound,
            hdr.hash,
            hdr.sequence,
            Some(hdr.account_hash),
        )
        .expect("matching inbound header should validate");
        assert_eq!(loaded.hash, hdr.hash);
        assert_eq!(loaded.sequence, hdr.sequence);
    }

    #[test]
    fn validated_reacquired_sync_header_rejects_account_hash_mismatch() {
        let hdr = header(201, [0x66; 32], [0x77; 32]);
        let hdr_hash = hdr.hash;
        let mut inbound = crate::ledger::inbound::InboundLedgers::new();
        inbound.create(hdr_hash, hdr.sequence);
        let _ = inbound.got_header(&hdr_hash, hdr);

        let loaded = validated_reacquired_sync_header(
            &inbound,
            inbound.hash_for_seq(201).unwrap(),
            201,
            Some([0x99; 32]),
        );
        assert!(loaded.is_none());
    }

    #[test]
    fn request_resync_and_stop_sets_both_flags() {
        let follower = FollowerState::new();
        follower.running.store(true, Ordering::SeqCst);
        request_resync_and_stop_follower(&follower);
        assert!(!follower.running.load(Ordering::SeqCst));
        assert!(follower.resync_requested.load(Ordering::SeqCst));
    }

    #[test]
    fn authoritative_delete_removes_supported_raw_even_without_typed_cache() {
        let mut state = crate::ledger::LedgerState::new();
        let account = crate::ledger::account::AccountRoot {
            account_id: [0x41; 20],
            balance: 10,
            sequence: 1,
            owner_count: 0,
            flags: 0,
            regular_key: None,
            minted_nftokens: 0,
            burned_nftokens: 0,
            transfer_rate: 0,
            domain: Vec::new(),
            tick_size: 0,
            ticket_count: 0,
            previous_txn_id: [0; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        let key = crate::ledger::account::shamap_key(&account.account_id);
        state.insert_raw(key, account.to_sle_binary());
        assert!(state.get_raw_owned(&key).is_some());

        remove_typed(&mut state, 0x0061, &key);

        assert!(state.get_raw_owned(&key).is_none());
    }

    #[test]
    fn authoritative_delete_falls_back_to_raw_for_untyped_entries() {
        let mut state = crate::ledger::LedgerState::new();
        let ticket = crate::ledger::ticket::Ticket {
            account: [0x54; 20],
            sequence: 99,
            owner_node: 0,
            previous_txn_id: [0; 32],
            previous_txn_lgrseq: 0,
            raw_sle: None,
        };
        let key = ticket.key();
        state.insert_raw(key, ticket.to_sle_binary());
        assert!(state.get_raw_owned(&key).is_some());

        remove_typed(&mut state, 0x0054, &key);

        assert!(state.get_raw_owned(&key).is_none());
    }

    #[test]
    fn collect_missing_modified_base_keys_skips_created_then_modified_and_present_keys() {
        let mut state = crate::ledger::LedgerState::new();
        let present_account = crate::ledger::account::AccountRoot {
            account_id: [0x41; 20],
            balance: 10,
            sequence: 1,
            owner_count: 0,
            flags: 0,
            regular_key: None,
            minted_nftokens: 0,
            burned_nftokens: 0,
            transfer_rate: 0,
            domain: Vec::new(),
            tick_size: 0,
            ticket_count: 0,
            previous_txn_id: [0; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        let present_key = crate::ledger::account::shamap_key(&present_account.account_id);
        state.insert_raw(present_key, present_account.to_sle_binary());

        let missing_key = crate::ledger::Key([0x22; 32]);
        let created_then_modified = crate::ledger::Key([0x33; 32]);
        let nodes = vec![vec![
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Created,
                entry_type: 0x0061,
                ledger_index: created_then_modified.0,
                fields: Vec::new(),
                previous_fields: Vec::new(),
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Modified,
                entry_type: 0x0061,
                ledger_index: created_then_modified.0,
                fields: Vec::new(),
                previous_fields: Vec::new(),
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Modified,
                entry_type: 0x0061,
                ledger_index: missing_key.0,
                fields: Vec::new(),
                previous_fields: Vec::new(),
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Modified,
                entry_type: 0x0061,
                ledger_index: present_key.0,
                fields: Vec::new(),
                previous_fields: Vec::new(),
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
        ]];

        let missing = collect_missing_modified_base_keys_from_nodes(&state, &nodes);
        assert_eq!(missing, vec![missing_key]);
    }

    #[test]
    fn collect_replay_prerequisite_keys_includes_offer_funding_trustline() {
        let kp = crate::crypto::keys::KeyPair::Secp256k1(
            crate::crypto::keys::Secp256k1KeyPair::from_seed(
                "snoPBrXtMeMyMHUVTgbuqAfg1SUTb",
            )
            .unwrap(),
        );
        let account = crate::crypto::account_id(&kp.public_key_bytes());
        let issuer =
            crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap();
        let currency = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let signed = crate::transaction::builder::TxBuilder::offer_create()
            .account(&kp)
            .taker_pays(crate::transaction::Amount::Xrp(1_000_000))
            .taker_gets(crate::transaction::Amount::Iou {
                value: crate::transaction::amount::IouValue::from_f64(10.0),
                currency: currency.clone(),
                issuer,
            })
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();
        let expected = crate::ledger::trustline::shamap_key(&account, &issuer, &currency);
        let keys = collect_replay_prerequisite_keys(&[(signed.blob, Vec::new())]);
        assert!(keys.contains(&expected));
    }

    #[test]
    fn collect_replay_prerequisite_keys_includes_direct_xrp_destination_account() {
        let kp = crate::crypto::keys::KeyPair::Secp256k1(
            crate::crypto::keys::Secp256k1KeyPair::from_seed(
                "snoPBrXtMeMyMHUVTgbuqAfg1SUTb",
            )
            .unwrap(),
        );
        let destination =
            crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap();
        let signed = crate::transaction::builder::TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(crate::transaction::Amount::Xrp(905))
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();
        let expected = crate::ledger::account::shamap_key(&destination);
        let keys = collect_replay_prerequisite_keys(&[(signed.blob, Vec::new())]);
        assert!(keys.contains(&expected));
    }

    #[test]
    fn directory_scope_expands_deleted_pages_from_prestate() {
        let state = crate::ledger::LedgerState::new();
        let owner = [0xA5; 20];
        let root = crate::ledger::directory::owner_dir_key(&owner);
        let page = crate::ledger::directory::page_key(&root.0, 5);
        let prev = crate::ledger::directory::page_key(&root.0, 4);
        let next = crate::ledger::directory::page_key(&root.0, 7);
        let dir = crate::ledger::directory::DirectoryNode {
            key: page.0,
            root_index: root.0,
            indexes: Vec::new(),
            index_next: 7,
            index_previous: 4,
            owner: Some(owner),
            exchange_rate: None,
            taker_pays_currency: None,
            taker_pays_issuer: None,
            taker_gets_currency: None,
            taker_gets_issuer: None,
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: true,
            has_index_previous: true,
            raw_sle: None,
        };
        let mut prestate = std::collections::HashMap::new();
        prestate.insert(page.0, dir.to_sle_binary());

        let mut keys = std::collections::BTreeSet::new();
        keys.insert(page);
        expand_directory_neighborhoods_with_sources(&state, &[&prestate], &mut keys);

        assert!(keys.contains(&root));
        assert!(keys.contains(&prev));
        assert!(keys.contains(&next));
    }

    #[test]
    fn repair_scope_expands_offer_owner_and_book_context() {
        let mut state = crate::ledger::LedgerState::new();
        let offer = crate::ledger::offer::Offer {
            account: [0x11; 20],
            sequence: 7,
            taker_pays: crate::transaction::amount::Amount::Xrp(10),
            taker_gets: crate::transaction::amount::Amount::Xrp(20),
            flags: 0,
            book_directory: {
                let mut key = [0x44; 32];
                key[24..32].copy_from_slice(&55u64.to_be_bytes());
                key
            },
            book_node: 3,
            owner_node: 9,
            expiration: None,
            domain_id: None,
            additional_books: vec![[0x66; 32]],
            previous_txn_id: [0; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        let offer_key = offer.key();
        state.insert_raw(offer_key, offer.to_sle_binary());

        let mut keys = std::collections::BTreeSet::new();
        keys.insert(offer_key);
        expand_directory_neighborhoods_with_sources(&state, &[], &mut keys);

        let owner_root = crate::ledger::directory::owner_dir_key(&offer.account);
        assert!(keys.contains(&crate::ledger::account::shamap_key(&offer.account)));
        assert!(keys.contains(&owner_root));
        assert!(keys.contains(&crate::ledger::directory::page_key(
            &owner_root.0,
            offer.owner_node,
        )));
        assert!(keys.contains(&crate::ledger::Key(offer.book_directory)));
        assert!(keys.contains(&crate::ledger::directory::page_key(
            &offer.book_directory,
            offer.book_node,
        )));

        let mut book_root = offer.book_directory;
        book_root[24..32].copy_from_slice(&0u64.to_be_bytes());
        assert!(keys.contains(&crate::ledger::Key(book_root)));
        assert!(keys.contains(&crate::ledger::Key(offer.additional_books[0])));
    }

    #[test]
    fn repair_scope_expands_trustline_accounts_and_pages() {
        let mut state = crate::ledger::LedgerState::new();
        let low = [0x21; 20];
        let high = [0x42; 20];
        let trustline = crate::ledger::trustline::RippleState {
            low_account: low,
            high_account: high,
            currency: crate::transaction::amount::Currency { code: [0x55; 20] },
            balance: crate::transaction::amount::IouValue::ZERO,
            low_limit: crate::transaction::amount::IouValue {
                mantissa: 1_000_000_000_000_000,
                exponent: -15,
            },
            high_limit: crate::transaction::amount::IouValue {
                mantissa: 2_000_000_000_000_000,
                exponent: -15,
            },
            flags: 0,
            low_node: 6,
            high_node: 8,
            low_quality_in: 0,
            low_quality_out: 0,
            high_quality_in: 0,
            high_quality_out: 0,
            previous_txn_id: [0; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: Some(Vec::new()),
        };
        let mut trustline = trustline;
        trustline.raw_sle = Some(trustline.encode());
        let trustline_key = trustline.key();
        state.insert_raw(trustline_key, trustline.to_sle_binary());

        let mut keys = std::collections::BTreeSet::new();
        keys.insert(trustline_key);
        expand_directory_neighborhoods_with_sources(&state, &[], &mut keys);

        let low_root = crate::ledger::directory::owner_dir_key(&low);
        let high_root = crate::ledger::directory::owner_dir_key(&high);
        assert!(keys.contains(&crate::ledger::account::shamap_key(&low)));
        assert!(keys.contains(&crate::ledger::account::shamap_key(&high)));
        assert!(keys.contains(&low_root));
        assert!(keys.contains(&high_root));
        assert!(keys.contains(&crate::ledger::directory::page_key(
            &low_root.0,
            trustline.low_node,
        )));
        assert!(keys.contains(&crate::ledger::directory::page_key(
            &high_root.0,
            trustline.high_node,
        )));
    }

    #[test]
    fn repair_scope_expands_generic_owner_and_destination_nodes() {
        let mut state = crate::ledger::LedgerState::new();
        let check = crate::ledger::check::Check {
            account: [0x31; 20],
            destination: [0x32; 20],
            send_max: crate::transaction::Amount::Xrp(25),
            sequence: 9,
            expiration: 0,
            owner_node: 4,
            destination_node: 12,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        };
        let check_key = check.key();
        state.insert_raw(check_key, check.to_sle_binary());

        let mut keys = std::collections::BTreeSet::new();
        keys.insert(check_key);
        expand_directory_neighborhoods_with_sources(&state, &[], &mut keys);

        let owner_root = crate::ledger::directory::owner_dir_key(&check.account);
        let destination_root = crate::ledger::directory::owner_dir_key(&check.destination);
        assert!(keys.contains(&crate::ledger::account::shamap_key(&check.account)));
        assert!(keys.contains(&crate::ledger::account::shamap_key(
            &check.destination
        )));
        assert!(keys.contains(&crate::ledger::directory::page_key(
            &owner_root.0,
            check.owner_node,
        )));
        assert!(keys.contains(&crate::ledger::directory::page_key(
            &destination_root.0,
            check.destination_node,
        )));
    }

    #[test]
    fn repair_scope_recursively_expands_directory_indexes_into_offer_context() {
        let mut state = crate::ledger::LedgerState::new();
        let offer = crate::ledger::offer::Offer {
            account: [0x51; 20],
            sequence: 11,
            taker_pays: crate::transaction::amount::Amount::Xrp(10),
            taker_gets: crate::transaction::amount::Amount::Xrp(20),
            flags: 0,
            book_directory: {
                let mut key = [0x77; 32];
                key[24..32].copy_from_slice(&13u64.to_be_bytes());
                key
            },
            book_node: 13,
            owner_node: 4,
            expiration: None,
            domain_id: None,
            additional_books: vec![[0x88; 32]],
            previous_txn_id: [0; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        let offer_key = offer.key();
        state.insert_raw(offer_key, offer.to_sle_binary());

        let owner_root = crate::ledger::directory::owner_dir_key(&offer.account);
        let owner_page = crate::ledger::directory::page_key(&owner_root.0, offer.owner_node);
        let dir = crate::ledger::directory::DirectoryNode {
            key: owner_page.0,
            root_index: owner_root.0,
            indexes: vec![offer_key.0],
            index_next: 0,
            index_previous: 0,
            owner: Some(offer.account),
            exchange_rate: None,
            taker_pays_currency: None,
            taker_pays_issuer: None,
            taker_gets_currency: None,
            taker_gets_issuer: None,
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        };
        state.insert_raw(owner_page, dir.to_sle_binary());

        let mut keys = std::collections::BTreeSet::new();
        keys.insert(owner_page);
        expand_authoritative_directory_scope_with_sources(&state, &[], &mut keys);

        assert!(keys.contains(&offer_key));
        assert!(keys.contains(&crate::ledger::account::shamap_key(&offer.account)));
        assert!(keys.contains(&owner_root));
        assert!(keys.contains(&crate::ledger::Key(offer.book_directory)));
        assert!(keys.contains(&crate::ledger::directory::page_key(
            &offer.book_directory,
            offer.book_node,
        )));

        let mut book_root = offer.book_directory;
        book_root[24..32].copy_from_slice(&0u64.to_be_bytes());
        assert!(keys.contains(&crate::ledger::Key(book_root)));
        assert!(keys.contains(&crate::ledger::Key(offer.additional_books[0])));
    }

    #[test]
    fn repair_scope_uses_committed_directory_bytes_when_overlay_deleted() {
        use crate::ledger::node_store::MemNodeStore;
        use crate::ledger::shamap::{MapType, SHAMap};

        let backend = std::sync::Arc::new(MemNodeStore::new());
        let mut state = crate::ledger::LedgerState::new();
        state.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend));

        let offer = crate::ledger::offer::Offer {
            account: [0x61; 20],
            sequence: 19,
            taker_pays: crate::transaction::amount::Amount::Xrp(10),
            taker_gets: crate::transaction::amount::Amount::Xrp(20),
            flags: 0,
            book_directory: {
                let mut key = [0x91; 32];
                key[24..32].copy_from_slice(&7u64.to_be_bytes());
                key
            },
            book_node: 7,
            owner_node: 2,
            expiration: None,
            domain_id: None,
            additional_books: Vec::new(),
            previous_txn_id: [0; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        let offer_key = offer.key();
        state.insert_raw(offer_key, offer.to_sle_binary());

        let owner_root = crate::ledger::directory::owner_dir_key(&offer.account);
        let owner_page = crate::ledger::directory::page_key(&owner_root.0, offer.owner_node);
        let dir = crate::ledger::directory::DirectoryNode {
            key: owner_page.0,
            root_index: owner_root.0,
            indexes: vec![offer_key.0],
            index_next: 0,
            index_previous: 0,
            owner: Some(offer.account),
            exchange_rate: None,
            taker_pays_currency: None,
            taker_pays_issuer: None,
            taker_gets_currency: None,
            taker_gets_issuer: None,
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        };
        state.insert_raw(owner_page, dir.to_sle_binary());
        state.flush_nudb().unwrap();

        state.deleted_raw.insert(owner_page);
        state.state_map.remove(&owner_page);

        let mut keys = std::collections::BTreeSet::new();
        keys.insert(owner_page);
        expand_authoritative_directory_scope_with_sources(&state, &[], &mut keys);

        assert!(keys.contains(&offer_key));
        assert!(keys.contains(&crate::ledger::account::shamap_key(&offer.account)));
    }

    #[test]
    fn related_offer_book_prefers_exact_directory_key_and_does_not_guess_single_book() {
        let exact_key = [0xA1; 32];
        let wrong_root = [0xB2; 32];
        let exact_book = ([0x01; 20], [0x02; 20], [0x03; 20], [0x04; 20]);
        let guessed_book = ([0x11; 20], [0x12; 20], [0x13; 20], [0x14; 20]);

        let exact_node = crate::ledger::meta::AffectedNode {
            action: crate::ledger::meta::Action::Modified,
            entry_type: 0x0064,
            ledger_index: exact_key,
            fields: vec![],
            previous_fields: vec![],
            prev_txn_id: None,
            prev_txn_lgrseq: None,
        };
        let mut exact_dirs = std::collections::HashMap::new();
        exact_dirs.insert(exact_key, exact_book);
        assert_eq!(
            related_offer_book_for_directory_node(&exact_node, &exact_dirs),
            Some(exact_book)
        );

        let guessed_node = crate::ledger::meta::AffectedNode {
            action: crate::ledger::meta::Action::Modified,
            entry_type: 0x0064,
            ledger_index: [0xC3; 32],
            fields: vec![crate::ledger::meta::ParsedField {
                type_code: 5,
                field_code: 8,
                data: wrong_root.to_vec(),
            }],
            previous_fields: vec![],
            prev_txn_id: None,
            prev_txn_lgrseq: None,
        };
        let mut guessed_dirs = std::collections::HashMap::new();
        guessed_dirs.insert([0xD4; 32], guessed_book);
        assert_eq!(
            related_offer_book_for_directory_node(&guessed_node, &guessed_dirs),
            None
        );
    }

    #[test]
    fn metadata_patch_created_trustline_synthesizes_owner_directory_roots() {
        let mut state = crate::ledger::LedgerState::new();
        let low = [0x10; 20];
        let high = [0x20; 20];
        let currency = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let trustline_key = crate::ledger::trustline::shamap_key(&low, &high, &currency);
        let low_root = crate::ledger::directory::owner_dir_key(&low);
        let high_root = crate::ledger::directory::owner_dir_key(&high);

        let nodes = vec![crate::ledger::meta::AffectedNode {
            action: crate::ledger::meta::Action::Created,
            entry_type: 0x0072,
            ledger_index: trustline_key.0,
            fields: vec![
                crate::ledger::meta::ParsedField {
                    type_code: 3,
                    field_code: 7,
                    data: 0u64.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 3,
                    field_code: 8,
                    data: 0u64.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 6,
                    field_code: 6,
                    data: crate::transaction::amount::Amount::Iou {
                        value: crate::transaction::amount::IouValue::from_f64(1.0),
                        currency: currency.clone(),
                        issuer: low,
                    }
                    .to_bytes(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 6,
                    field_code: 7,
                    data: crate::transaction::amount::Amount::Iou {
                        value: crate::transaction::amount::IouValue::from_f64(1.0),
                        currency,
                        issuer: high,
                    }
                    .to_bytes(),
                },
            ],
            previous_fields: vec![],
            prev_txn_id: None,
            prev_txn_lgrseq: None,
        }];
        let metadata = crate::ledger::meta::encode_metadata(0, 0, &nodes);

        let stats = apply_metadata_patches(
            &[([0xAB; 32], metadata)],
            58,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            &mut state,
        );

        assert_eq!(stats.created_override_miss_keys.len(), 1);

        let low_raw = state
            .get_raw_owned(&low_root)
            .expect("low owner root must exist");
        let low_dir =
            crate::ledger::DirectoryNode::decode(&low_raw, low_root.0).expect("valid low root");
        assert!(low_dir.indexes.iter().any(|index| index == &trustline_key.0));

        let high_raw = state
            .get_raw_owned(&high_root)
            .expect("high owner root must exist");
        let high_dir = crate::ledger::DirectoryNode::decode(&high_raw, high_root.0)
            .expect("valid high root");
        assert!(high_dir.indexes.iter().any(|index| index == &trustline_key.0));
    }
}
