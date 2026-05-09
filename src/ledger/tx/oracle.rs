//! Oracle transaction handlers — OracleSet (51) and OracleDelete (52).
//!
//! OracleSet creates or updates an Oracle SLE.  OracleDelete removes one.
//!
//! SHAMap key: SHA-512-half(0x0052 || AccountID || OracleDocumentID)
//!   namespace 'R' = 0x52  (from rippled Indexes.cpp LedgerNameSpace::ORACLE)

use crate::ledger::{directory, keylet, ter, Key, LedgerState};
use crate::transaction::parse::{parsed_oracle_asset_class, parsed_oracle_provider};
use crate::transaction::ParsedTx;

use super::{balance_before_fee, owner_reserve_requirement, ApplyResult};

const XRPL_EPOCH_OFFSET: u64 = 946_684_800;
const MAX_LAST_UPDATE_TIME_DELTA: u64 = 300;
const MAX_ORACLE_DATA_SERIES: usize = 10;
const MAX_ORACLE_PROVIDER: usize = 256;
const MAX_ORACLE_URI: usize = 256;
const MAX_ORACLE_ASSET_CLASS: usize = 16;
const MAX_ORACLE_SCALE: u8 = 20;

/// Compute the SHAMap key for an Oracle SLE.
/// `SHA-512-half(0x0052 || account_id || oracle_document_id)`
fn oracle_key(account: &[u8; 20], document_id: u32) -> Key {
    keylet::oracle(account, document_id).key
}

#[derive(Clone)]
struct PriceDataEntry {
    base: [u8; 20],
    quote: [u8; 20],
    raw: Vec<u8>,
    has_price: bool,
}

fn parse_price_data_entries(raw: &[u8]) -> Result<Vec<PriceDataEntry>, &'static str> {
    let mut pos = 0usize;
    let mut entries = Vec::new();

    while pos < raw.len() {
        if raw[pos] == 0xF1 {
            break;
        }
        let object_start = pos;
        let (type_code, field_code, new_pos) = crate::ledger::meta::read_field_header(raw, pos);
        if new_pos > raw.len() || type_code == 0 {
            return Err("temMALFORMED");
        }
        if type_code == 15 && field_code == 1 {
            break;
        }
        if type_code != 14 || field_code != 32 {
            return Err("temMALFORMED");
        }
        pos = new_pos;

        let mut base = None::<[u8; 20]>;
        let mut quote = None::<[u8; 20]>;
        let mut has_price = false;
        while pos < raw.len() && raw[pos] != 0xE1 {
            let (inner_type, inner_field, inner_pos) =
                crate::ledger::meta::read_field_header(raw, pos);
            if inner_pos > raw.len() || inner_type == 0 {
                return Err("temMALFORMED");
            }
            pos = inner_pos;
            let next = crate::ledger::meta::skip_field_raw(raw, pos, inner_type);
            if next < pos || next > raw.len() {
                return Err("temMALFORMED");
            }

            match (inner_type, inner_field) {
                (17, 1) if next == pos + 20 => {
                    let mut currency = [0u8; 20];
                    currency.copy_from_slice(&raw[pos..next]);
                    base = Some(currency);
                }
                (17, 2) if next == pos + 20 => {
                    let mut currency = [0u8; 20];
                    currency.copy_from_slice(&raw[pos..next]);
                    quote = Some(currency);
                }
                (3, 23) if next == pos + 8 => {
                    has_price = true;
                }
                (16, 4) if next == pos + 1 && raw[pos] > MAX_ORACLE_SCALE => {
                    return Err("temMALFORMED");
                }
                _ => {}
            }
            pos = next;
        }
        if pos >= raw.len() || raw[pos] != 0xE1 {
            return Err("temMALFORMED");
        }
        pos += 1;

        let (Some(base), Some(quote)) = (base, quote) else {
            return Err("temMALFORMED");
        };
        if base == quote {
            return Err("temMALFORMED");
        }
        entries.push(PriceDataEntry {
            base,
            quote,
            raw: raw[object_start..pos].to_vec(),
            has_price,
        });
    }

    Ok(entries)
}

fn sorted_price_data_series(entries: Vec<PriceDataEntry>) -> Vec<u8> {
    let mut entries = entries;
    entries.sort_by_key(|entry| (entry.base, entry.quote));
    let mut out = Vec::new();
    for entry in entries {
        out.extend_from_slice(&entry.raw);
    }
    out.push(0xF1);
    out
}

fn amendment_active(state: &LedgerState, name: &str) -> bool {
    state.is_amendment_active(&crate::crypto::sha512_first_half(name.as_bytes()))
}

fn price_oracle_order_enabled(state: &LedgerState) -> bool {
    amendment_active(state, "fixPriceOracleOrder")
}

fn include_keylet_fields_enabled(state: &LedgerState) -> bool {
    amendment_active(state, "fixIncludeKeyletFields")
}

fn price_data_count(raw: &[u8]) -> usize {
    parse_price_data_entries(raw)
        .map(|entries| entries.len())
        .unwrap_or(0)
}

fn price_data_reserve_slots(raw: &[u8]) -> u32 {
    if price_data_count(raw) > 5 {
        2
    } else {
        1
    }
}

fn stored_price_data_reserve_slots(raw: &[u8]) -> u32 {
    crate::ledger::meta::parse_sle(raw)
        .and_then(|sle| {
            sle.fields
                .into_iter()
                .find(|field| field.type_code == 15 && field.field_code == 24)
                .map(|field| price_data_reserve_slots(&field.data))
        })
        .unwrap_or(1)
}

fn stored_uint64(raw: &[u8], field_code: u16) -> u64 {
    crate::ledger::meta::parse_sle(raw)
        .and_then(|sle| {
            sle.fields
                .into_iter()
                .find(|field| field.type_code == 3 && field.field_code == field_code)
                .and_then(|field| field.data.as_slice().try_into().ok())
                .map(u64::from_be_bytes)
        })
        .unwrap_or(0)
}

fn stored_price_data_series(raw: &[u8]) -> Option<Vec<u8>> {
    crate::ledger::meta::parse_sle(raw).and_then(|sle| {
        sle.fields
            .into_iter()
            .find(|field| field.type_code == 15 && field.field_code == 24)
            .map(|field| field.data)
    })
}

fn stored_field(raw: &[u8], type_code: u16, field_code: u16) -> Option<Vec<u8>> {
    crate::ledger::meta::parse_sle(raw).and_then(|sle| {
        sle.fields
            .into_iter()
            .find(|field| field.type_code == type_code && field.field_code == field_code)
            .map(|field| field.data)
    })
}

fn valid_optional_vl(value: Option<&[u8]>, max: usize) -> bool {
    value.is_none_or(|bytes| !bytes.is_empty() && bytes.len() <= max)
}

pub(crate) fn preflight(tx: &ParsedTx) -> Result<(), ter::TxResult> {
    const TF_UNIVERSAL: u32 = 0xC000_0000;
    if (tx.flags & !TF_UNIVERSAL) != 0 {
        return Err(ter::TEM_INVALID_FLAG);
    }

    match tx.tx_type {
        51 => {
            if tx.oracle_document_id.is_none()
                || tx.oracle_last_update_time.is_none()
                || tx.oracle_price_data_series_raw.is_none()
            {
                return Err(ter::TEM_MALFORMED);
            }
            let series = tx
                .oracle_price_data_series_raw
                .as_deref()
                .unwrap_or_default();
            let count = price_data_count(series);
            if count == 0 {
                return Err(ter::TEM_ARRAY_EMPTY);
            }
            if count > MAX_ORACLE_DATA_SERIES {
                return Err(ter::TEM_ARRAY_TOO_LARGE);
            }
            if !valid_optional_vl(parsed_oracle_provider(tx).as_deref(), MAX_ORACLE_PROVIDER)
                || !valid_optional_vl(tx.uri.as_deref(), MAX_ORACLE_URI)
                || !valid_optional_vl(
                    parsed_oracle_asset_class(tx).as_deref(),
                    MAX_ORACLE_ASSET_CLASS,
                )
            {
                return Err(ter::TEM_MALFORMED);
            }
        }
        52 => {
            if tx.oracle_document_id.is_none() {
                return Err(ter::TEM_MALFORMED);
            }
        }
        _ => {}
    }

    Ok(())
}

fn valid_update_time(last_update_time: u32, close_time: u64) -> bool {
    let last = last_update_time as u64;
    if last < XRPL_EPOCH_OFFSET {
        return false;
    }
    if close_time == 0 {
        return true;
    }
    let close_unix = close_time.saturating_add(XRPL_EPOCH_OFFSET);
    last >= close_unix.saturating_sub(MAX_LAST_UPDATE_TIME_DELTA)
        && last <= close_unix.saturating_add(MAX_LAST_UPDATE_TIME_DELTA)
}

fn merge_price_data_series(
    existing: Option<&[u8]>,
    incoming: &[u8],
    sort_on_create: bool,
) -> Result<Vec<u8>, &'static str> {
    use std::collections::{BTreeMap, BTreeSet};

    let incoming_entries = parse_price_data_entries(incoming)?;
    if incoming_entries.is_empty() {
        return Err("temARRAY_EMPTY");
    }
    if incoming_entries.len() > MAX_ORACLE_DATA_SERIES {
        return Err("temARRAY_TOO_LARGE");
    }

    let mut seen = BTreeSet::<([u8; 20], [u8; 20])>::new();
    for entry in &incoming_entries {
        if !seen.insert((entry.base, entry.quote)) {
            return Err("temMALFORMED");
        }
    }

    let mut pairs = BTreeMap::<([u8; 20], [u8; 20]), PriceDataEntry>::new();
    if let Some(existing) = existing {
        for entry in parse_price_data_entries(existing)? {
            pairs.insert((entry.base, entry.quote), entry);
        }
        for entry in incoming_entries {
            let key = (entry.base, entry.quote);
            if entry.has_price {
                pairs.insert(key, entry);
            } else if pairs.remove(&key).is_none() {
                return Err("tecTOKEN_PAIR_NOT_FOUND");
            }
        }
    } else {
        for entry in incoming_entries {
            if !entry.has_price {
                return Err("temMALFORMED");
            }
            pairs.insert((entry.base, entry.quote), entry);
        }
    }

    if pairs.is_empty() {
        return Err("tecARRAY_EMPTY");
    }
    if pairs.len() > MAX_ORACLE_DATA_SERIES {
        return Err("tecARRAY_TOO_LARGE");
    }

    if existing.is_some() || sort_on_create {
        Ok(sorted_price_data_series(pairs.into_values().collect()))
    } else {
        Ok(incoming.to_vec())
    }
}

fn build_oracle_sle(
    account: &[u8; 20],
    document_id: Option<u32>,
    last_update_time: u32,
    price_data_series: &[u8],
    provider: Option<&[u8]>,
    uri: Option<&[u8]>,
    asset_class: Option<&[u8]>,
    owner_node: u64,
) -> Vec<u8> {
    let mut fields = vec![
        crate::ledger::meta::ParsedField {
            type_code: 2,
            field_code: 15,
            data: last_update_time.to_be_bytes().to_vec(),
        },
        crate::ledger::meta::ParsedField {
            type_code: 3,
            field_code: 4,
            data: owner_node.to_be_bytes().to_vec(),
        },
        crate::ledger::meta::ParsedField {
            type_code: 8,
            field_code: 2,
            data: account.to_vec(),
        },
        crate::ledger::meta::ParsedField {
            type_code: 15,
            field_code: 24,
            data: price_data_series.to_vec(),
        },
    ];

    if let Some(document_id) = document_id {
        fields.push(crate::ledger::meta::ParsedField {
            type_code: 2,
            field_code: 51,
            data: document_id.to_be_bytes().to_vec(),
        });
    }
    if let Some(provider) = provider {
        fields.push(crate::ledger::meta::ParsedField {
            type_code: 7,
            field_code: 29,
            data: provider.to_vec(),
        });
    }
    if let Some(uri) = uri {
        fields.push(crate::ledger::meta::ParsedField {
            type_code: 7,
            field_code: 5,
            data: uri.to_vec(),
        });
    }
    if let Some(asset_class) = asset_class {
        fields.push(crate::ledger::meta::ParsedField {
            type_code: 7,
            field_code: 28,
            data: asset_class.to_vec(),
        });
    }

    crate::ledger::meta::build_sle(0x0080, &fields, None, None)
}

/// Type 51: OracleSet — create or update an Oracle object.
///
/// On create: add to owner directory and increment owner_count by the Oracle
/// reserve slots. On update: adjust owner_count if the price series crosses
/// the five-entry reserve threshold.
///
pub(crate) fn apply_oracle_set(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    close_time: u64,
) -> ApplyResult {
    let doc_id = match tx.oracle_document_id {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let last_update_time = match tx.oracle_last_update_time {
        Some(t) => t,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let price_data_series = match tx.oracle_price_data_series_raw.as_deref() {
        Some(series) if !series.is_empty() => series,
        _ => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let provider = parsed_oracle_provider(tx);
    let asset_class = parsed_oracle_asset_class(tx);
    let sort_on_create = price_oracle_order_enabled(state);
    let include_document_id = include_keylet_fields_enabled(state);
    if !valid_update_time(last_update_time, close_time) {
        return ApplyResult::ClaimedCost("tecINVALID_UPDATE_TIME");
    }
    if !valid_optional_vl(provider.as_deref(), MAX_ORACLE_PROVIDER)
        || !valid_optional_vl(tx.uri.as_deref(), MAX_ORACLE_URI)
        || !valid_optional_vl(asset_class.as_deref(), MAX_ORACLE_ASSET_CLASS)
    {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    let key = oracle_key(&tx.account, doc_id);

    // Includes committed NuDB-backed raw SLEs while still honoring overlay
    // deletes, matching rippled's view.read/peek behavior for synced ledgers.
    let existing = state.get_raw_owned(&key);

    if let Some(existing) = existing {
        let old_series = match stored_price_data_series(&existing) {
            Some(series) => series,
            None => return ApplyResult::ClaimedCost("tecINTERNAL"),
        };
        if let Some(stored_time) = stored_field(&existing, 2, 15).and_then(|data| {
            (data.len() >= 4).then(|| u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
        }) {
            if last_update_time <= stored_time {
                return ApplyResult::ClaimedCost("tecINVALID_UPDATE_TIME");
            }
        }
        if provider
            .as_ref()
            .is_some_and(|value| stored_field(&existing, 7, 29).as_ref() != Some(value))
            || asset_class
                .as_ref()
                .is_some_and(|value| stored_field(&existing, 7, 28).as_ref() != Some(value))
        {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
        let new_series = match merge_price_data_series(Some(&old_series), price_data_series, true) {
            Ok(series) => series,
            Err(code) => return ApplyResult::ClaimedCost(code),
        };
        let old_slots = price_data_reserve_slots(&old_series);
        let new_slots = price_data_reserve_slots(&new_series);
        if new_slots > old_slots {
            let additional = new_slots.saturating_sub(old_slots);
            let required = owner_reserve_requirement(state, new_sender.owner_count, additional);
            if balance_before_fee(new_sender.balance, tx.fee) < required {
                return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
            }
        }
        if new_slots > old_slots {
            new_sender.owner_count = new_sender
                .owner_count
                .saturating_add(new_slots.saturating_sub(old_slots));
        } else if old_slots > new_slots {
            new_sender.owner_count = new_sender
                .owner_count
                .saturating_sub(old_slots.saturating_sub(new_slots));
        }

        let mut fields = vec![
            crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 15,
                data: last_update_time.to_be_bytes().to_vec(),
            },
            crate::ledger::meta::ParsedField {
                type_code: 15,
                field_code: 24,
                data: new_series,
            },
        ];
        if let Some(uri) = tx.uri.as_deref() {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 7,
                field_code: 5,
                data: uri.to_vec(),
            });
        }
        if let Some(provider) = provider.as_deref() {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 7,
                field_code: 29,
                data: provider.to_vec(),
            });
        }
        if let Some(asset_class) = asset_class.as_deref() {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 7,
                field_code: 28,
                data: asset_class.to_vec(),
            });
        }
        if include_document_id && stored_field(&existing, 2, 51).is_none() {
            fields.push(crate::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 51,
                data: doc_id.to_be_bytes().to_vec(),
            });
        }
        let updated = crate::ledger::meta::patch_sle(&existing, &fields, None, None, &[]);
        state.insert_raw(key, updated);
    } else {
        let Some(provider) = provider.as_deref() else {
            return ApplyResult::ClaimedCost("temMALFORMED");
        };
        let Some(asset_class) = asset_class.as_deref() else {
            return ApplyResult::ClaimedCost("temMALFORMED");
        };
        let new_series = match merge_price_data_series(None, price_data_series, sort_on_create) {
            Ok(series) => series,
            Err(code) => return ApplyResult::ClaimedCost(code),
        };
        let reserve_slots = price_data_reserve_slots(&new_series);
        let required = owner_reserve_requirement(state, new_sender.owner_count, reserve_slots);
        if balance_before_fee(new_sender.balance, tx.fee) < required {
            return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
        }
        let owner_node = directory::dir_add(state, &tx.account, key.0);
        new_sender.owner_count = new_sender.owner_count.saturating_add(reserve_slots);
        let raw = build_oracle_sle(
            &tx.account,
            include_document_id.then_some(doc_id),
            last_update_time,
            &new_series,
            Some(provider),
            tx.uri.as_deref(),
            Some(asset_class),
            owner_node,
        );
        state.insert_raw(key, raw);
    }

    ApplyResult::Success
}

/// Type 52: OracleDelete — remove an Oracle object.
///
/// Removes from owner directory, decrements owner_count.
pub(crate) fn apply_oracle_delete(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
) -> ApplyResult {
    let doc_id = match tx.oracle_document_id {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = oracle_key(&tx.account, doc_id);

    // Same committed-aware lookup as OracleSet; a synced object must be
    // deletable even when it has not been loaded into the raw overlay yet.
    let existing = match state.get_raw_owned(&key) {
        Some(raw) => raw,
        None => {
            return ApplyResult::ClaimedCost("tecNO_ENTRY");
        }
    };

    let reserve_slots = stored_price_data_reserve_slots(&existing);

    // Remove from owner directory.
    let removed =
        directory::dir_remove_owner_page(state, &tx.account, stored_uint64(&existing, 4), &key.0);

    if removed {
        new_sender.owner_count = new_sender.owner_count.saturating_sub(reserve_slots);
    }

    // Remove the raw SLE even if the owner directory was already repaired by
    // metadata replay; the object itself is the source of truth for existence.
    state.remove_raw(&key);

    ApplyResult::Success
}

#[cfg(test)]
mod tests {
    use super::*;

    fn currency(code: &str) -> [u8; 20] {
        let mut out = [0u8; 20];
        let bytes = code.as_bytes();
        out[12..12 + bytes.len()].copy_from_slice(bytes);
        out
    }

    fn price_entry(base: [u8; 20], quote: [u8; 20], price: Option<u64>) -> Vec<u8> {
        let mut out = Vec::new();
        crate::ledger::meta::write_field_header(&mut out, 14, 32);
        if let Some(price) = price {
            crate::ledger::meta::write_field_header(&mut out, 3, 23);
            out.extend_from_slice(&price.to_be_bytes());
            crate::ledger::meta::write_field_header(&mut out, 16, 4);
            out.push(0);
        }
        crate::ledger::meta::write_field_header(&mut out, 17, 1);
        out.extend_from_slice(&base);
        crate::ledger::meta::write_field_header(&mut out, 17, 2);
        out.extend_from_slice(&quote);
        crate::ledger::meta::write_field_header(&mut out, 14, 1);
        out
    }

    fn series(entries: Vec<Vec<u8>>) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in entries {
            out.extend_from_slice(&entry);
        }
        crate::ledger::meta::write_field_header(&mut out, 15, 1);
        out
    }

    #[test]
    fn oracle_series_merges_deletes_and_sorts_pairs() {
        let xrp = [0u8; 20];
        let usd = currency("USD");
        let eur = currency("EUR");
        let jpy = currency("JPY");
        let existing = series(vec![
            price_entry(xrp, usd, Some(100)),
            price_entry(xrp, eur, Some(200)),
        ]);
        let incoming = series(vec![
            price_entry(xrp, jpy, Some(300)),
            price_entry(xrp, usd, None),
        ]);

        let merged = merge_price_data_series(Some(&existing), &incoming, true).unwrap();
        let parsed = parse_price_data_entries(&merged).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!((parsed[0].base, parsed[0].quote), (xrp, eur));
        assert_eq!((parsed[1].base, parsed[1].quote), (xrp, jpy));
    }

    #[test]
    fn oracle_series_rejects_duplicate_or_unknown_delete_pairs() {
        let xrp = [0u8; 20];
        let usd = currency("USD");
        let duplicate = series(vec![
            price_entry(xrp, usd, Some(100)),
            price_entry(xrp, usd, Some(200)),
        ]);
        assert_eq!(
            merge_price_data_series(None, &duplicate, true),
            Err("temMALFORMED")
        );

        let existing = series(vec![price_entry(xrp, usd, Some(100))]);
        let missing_delete = series(vec![price_entry(xrp, currency("EUR"), None)]);
        assert_eq!(
            merge_price_data_series(Some(&existing), &missing_delete, true),
            Err("tecTOKEN_PAIR_NOT_FOUND")
        );
    }

    #[test]
    fn oracle_update_time_uses_xrpl_epoch_window() {
        assert!(!valid_update_time(XRPL_EPOCH_OFFSET as u32 - 1, 0));
        assert!(valid_update_time((XRPL_EPOCH_OFFSET + 1_000) as u32, 1_000));
        assert!(valid_update_time((XRPL_EPOCH_OFFSET + 1_300) as u32, 1_000));
        assert!(!valid_update_time(
            (XRPL_EPOCH_OFFSET + 1_301) as u32,
            1_000
        ));
    }
}
