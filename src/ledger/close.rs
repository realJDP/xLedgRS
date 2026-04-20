//! Ledger close — drain the transaction pool, apply all transactions,
//! and produce a new validated ledger.
//!
//! This is the core ledger-advancement step.  In a consensus-driven node
//! it is called after a round reaches the Accepted phase.
//!
//! Also provides `replay_ledger()` for follower mode: replay a validated
//! ledger's transactions in sfTransactionIndex order (matching rippled's
//! LedgerReplay path in BuildLedger.cpp).

use crate::crypto::sha512_first_half;
use crate::ledger::apply::TxContext;
use crate::ledger::history::TxRecord;
use crate::ledger::pool::TxPool;
use crate::ledger::sparse_shamap::SparseSHAMap;
use crate::ledger::ter::ApplyFlags;
use crate::ledger::tx::{classify_result, run_tx, ApplyOutcome};
use crate::ledger::{LedgerHeader, LedgerState};
use crate::transaction::parse_blob;
use tracing::{debug, info, warn};

/// Prefix for transaction tree leaf hashes: "SND\0" (0x534E4400).
/// This matches rippled's HashPrefix::txNode used for TX SHAMap leaves.
const PREFIX_TX_LEAF: [u8; 4] = [0x53, 0x4E, 0x44, 0x00];

/// Compute a TX tree leaf hash: SHA-512-Half(SND\0 + data + key).
pub(crate) fn tx_leaf_hash(data: &[u8], key: &[u8; 32]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(4 + data.len() + 32);
    payload.extend_from_slice(&PREFIX_TX_LEAF);
    payload.extend_from_slice(data);
    payload.extend_from_slice(key);
    sha512_first_half(&payload)
}

fn encode_tx_leaf_data(tx_blob: &[u8], meta_blob: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(tx_blob.len() + meta_blob.len() + 8);
    crate::transaction::serialize::encode_length(tx_blob.len(), &mut data);
    data.extend_from_slice(tx_blob);
    crate::transaction::serialize::encode_length(meta_blob.len(), &mut data);
    data.extend_from_slice(meta_blob);
    data
}

pub(crate) fn stamp_touched_previous_fields(
    state: &mut LedgerState,
    touched: &[(crate::ledger::Key, Option<Vec<u8>>)],
    tx_id: &[u8; 32],
    ledger_seq: u32,
) {
    for (key, before) in touched {
        let Some(raw) = state.get_raw_owned(key) else {
            continue;
        };
        // Only stamp PreviousTxnID when the object's content actually changed.
        // rippled skips keys where before == after in metadata generation;
        // stamping unchanged objects causes PreviousTxnID divergence.
        if let Some(before_data) = before {
            if *before_data == raw {
                continue; // content unchanged — don't stamp
            }
        }
        let Some(mut sle) = crate::ledger::sle::SLE::from_raw(*key, raw) else {
            continue;
        };
        if !crate::ledger::should_thread_previous_txn_fields(state, sle.entry_type()) {
            continue;
        }
        sle.set_previous_txn_id(tx_id);
        sle.set_previous_txn_lgr_seq(ledger_seq);
        let updated_raw = sle.into_data();
        state.insert_raw(*key, updated_raw.clone());

        match crate::ledger::sle::SLE::from_raw(*key, updated_raw.clone()).map(|s| s.entry_type()) {
            Some(crate::ledger::sle::LedgerEntryType::AccountRoot) => {
                if let Ok(mut acct) = crate::ledger::account::AccountRoot::decode(&updated_raw) {
                    acct.previous_txn_id = *tx_id;
                    acct.previous_txn_lgr_seq = ledger_seq;
                    acct.raw_sle = Some(updated_raw);
                    state.hydrate_account(acct);
                }
            }
            Some(crate::ledger::sle::LedgerEntryType::Offer) => {
                if let Some(mut off) = crate::ledger::Offer::decode_from_sle(&updated_raw) {
                    off.previous_txn_id = *tx_id;
                    off.previous_txn_lgr_seq = ledger_seq;
                    off.raw_sle = Some(updated_raw);
                    state.hydrate_offer(off);
                }
            }
            Some(crate::ledger::sle::LedgerEntryType::DirectoryNode) => {
                if let Ok(mut dir) = crate::ledger::DirectoryNode::decode(&updated_raw, key.0) {
                    dir.previous_txn_id = Some(*tx_id);
                    dir.previous_txn_lgr_seq = Some(ledger_seq);
                    dir.raw_sle = Some(updated_raw);
                    state.hydrate_directory(dir);
                }
            }
            Some(crate::ledger::sle::LedgerEntryType::RippleState) => {
                if let Some(mut tl) = crate::ledger::RippleState::decode_from_sle(&updated_raw) {
                    tl.previous_txn_id = *tx_id;
                    tl.previous_txn_lgr_seq = ledger_seq;
                    tl.raw_sle = Some(updated_raw);
                    state.hydrate_trustline(tl);
                }
            }
            _ => {}
        }
    }
}

fn result_code(result: &str) -> i32 {
    match result {
        "tesSUCCESS" => 0,
        "tecPATH_PARTIAL" => 101,
        "tecPATH_DRY" => 128,
        "tecNO_LINE" => 135,
        "tecNO_TARGET" => 138,
        "tecNO_PERMISSION" => 139,
        "tecNO_ENTRY" => 140,
        "tecINSUFFICIENT_RESERVE" => 141,
        "tecEXPIRED" => 148,
        "tecDUPLICATE" => 149,
        "tecHAS_OBLIGATIONS" => 151,
        "tecINSUFFICIENT_FUNDS" => 159,
        "tecEMPTY_DID" => 187,
        "terNO_ACCOUNT" => -96,
        "temMALFORMED" => -299,
        "temBAD_AMOUNT" => -298,
        "temBAD_EXPIRATION" => -296,
        "temBAD_LIMIT" => -293,
        "temBAD_OFFER" => -292,
        "temBAD_SIGNATURE" => -282,
        "temDST_NEEDED" => -278,
        other => {
            // Fall back to the comprehensive ter module mapping
            crate::ledger::ter::token_to_code(other)
                .map(|r| r.code())
                .unwrap_or_else(|| {
                    warn!(
                        "close_ledger: unknown TER {}, defaulting metadata code to 0",
                        other
                    );
                    0
                })
        }
    }
}

pub(crate) fn build_tx_metadata(
    state: &LedgerState,
    touched: &[(crate::ledger::Key, Option<Vec<u8>>)],
    tx_hash: [u8; 32],
    ledger_seq: u32,
    tx_index: u32,
    result: &str,
) -> Vec<u8> {
    let mut nodes = Vec::new();

    for (key, before_opt) in touched {
        let after_opt = state.get_raw_owned(key);
        if before_opt.as_ref() == after_opt.as_ref() {
            continue;
        }

        match (before_opt.as_deref(), after_opt.as_deref()) {
            (None, Some(after)) => {
                if let Some(parsed) = crate::ledger::meta::parse_sle(after) {
                    nodes.push(crate::ledger::meta::AffectedNode {
                        action: crate::ledger::meta::Action::Created,
                        entry_type: parsed.entry_type,
                        ledger_index: key.0,
                        fields: parsed.fields,
                        previous_fields: vec![],
                        prev_txn_id: Some(tx_hash),
                        prev_txn_lgrseq: Some(ledger_seq),
                    });
                }
            }
            (Some(before), None) => {
                if let Some(parsed) = crate::ledger::meta::parse_sle(before) {
                    nodes.push(crate::ledger::meta::AffectedNode {
                        action: crate::ledger::meta::Action::Deleted,
                        entry_type: parsed.entry_type,
                        ledger_index: key.0,
                        fields: parsed.fields,
                        previous_fields: vec![],
                        prev_txn_id: parsed.prev_txn_id.or(Some(tx_hash)),
                        prev_txn_lgrseq: parsed.prev_txn_lgrseq.or(Some(ledger_seq)),
                    });
                }
            }
            (Some(before), Some(after)) => {
                let Some(pre) = crate::ledger::meta::parse_sle(before) else {
                    continue;
                };
                let Some(post) = crate::ledger::meta::parse_sle(after) else {
                    continue;
                };
                let previous_fields =
                    crate::ledger::meta::diff_previous_fields(&pre.fields, &post.fields);
                if previous_fields.is_empty() && pre.fields == post.fields {
                    continue;
                }
                nodes.push(crate::ledger::meta::AffectedNode {
                    action: crate::ledger::meta::Action::Modified,
                    entry_type: post.entry_type,
                    ledger_index: key.0,
                    fields: post.fields,
                    previous_fields,
                    prev_txn_id: Some(tx_hash),
                    prev_txn_lgrseq: Some(ledger_seq),
                });
            }
            (None, None) => {}
        }
    }

    crate::ledger::meta::encode_metadata(result_code(result), tx_index, &nodes)
}

fn hydrate_replay_prestate(state: &mut LedgerState, replay_txs: &[ReplayTx]) {
    let mut hydrated_offers = 0usize;
    let mut offer_nodes_total = 0usize;
    let mut offer_nodes_modified = 0usize;
    let mut offer_nodes_deleted = 0usize;
    let mut offer_raw_missing = 0usize;
    let mut offer_decode_failed = 0usize;
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for rtx in replay_txs {
        let (_idx, nodes) = crate::ledger::meta::parse_metadata_with_index(&rtx.meta);
        for node in nodes {
            if node.entry_type == 0x006F {
                offer_nodes_total += 1;
                match node.action {
                    crate::ledger::meta::Action::Modified => offer_nodes_modified += 1,
                    crate::ledger::meta::Action::Deleted => offer_nodes_deleted += 1,
                    _ => {}
                }
            }
            if !matches!(
                node.action,
                crate::ledger::meta::Action::Modified | crate::ledger::meta::Action::Deleted
            ) {
                continue;
            }
            if !seen.insert(node.ledger_index) {
                continue;
            }
            let key = crate::ledger::Key(node.ledger_index);
            let Some(raw) = state.get_raw_owned(&key) else {
                if node.entry_type == 0x006F {
                    offer_raw_missing += 1;
                }
                continue;
            };
            match node.entry_type {
                0x0061 => {
                    if let Ok(acct) = crate::ledger::account::AccountRoot::decode(&raw) {
                        state.hydrate_account(acct);
                    }
                }
                0x0064 => {
                    if let Ok(dir) = crate::ledger::DirectoryNode::decode(&raw, key.0) {
                        state.hydrate_directory(dir);
                    }
                }
                0x006F => {
                    if let Some(offer) = crate::ledger::offer::Offer::decode_from_sle(&raw) {
                        state.hydrate_offer(offer);
                        hydrated_offers += 1;
                    } else {
                        offer_decode_failed += 1;
                    }
                }
                0x0072 => {
                    if let Some(tl) = crate::ledger::trustline::RippleState::decode_from_sle(&raw) {
                        state.hydrate_trustline(tl);
                    }
                }
                0x0037 => {
                    if let Some(off) = crate::ledger::nftoken::NFTokenOffer::decode_from_sle(&raw) {
                        state.insert_nft_offer(off);
                    }
                }
                _ => {}
            }
        }
    }
    info!(
        "replay_ledger prestate: offer_nodes_total={} offer_nodes_modified={} offer_nodes_deleted={} hydrated_offers={} offer_raw_missing={} offer_decode_failed={}",
        offer_nodes_total,
        offer_nodes_modified,
        offer_nodes_deleted,
        hydrated_offers,
        offer_raw_missing,
        offer_decode_failed,
    );
}

/// Round close_time to the nearest multiple of `close_time_resolution`.
///
/// rippled rounds the agreed close time to the current resolution so that
/// minor disagreements between validators are smoothed out.
fn round_close_time(close_time: u64, resolution: u8) -> u64 {
    if resolution == 0 {
        return close_time;
    }
    let res = resolution as u64;
    (close_time + res / 2) / res * res
}

const POSSIBLE_CLOSE_TIME_RESOLUTIONS: [u8; 6] = [10, 20, 30, 60, 90, 120];
const INCREASE_RESOLUTION_EVERY: u32 = 8;
const DECREASE_RESOLUTION_EVERY: u32 = 1;
const CLOSE_TIME_NO_CONSENSUS: u8 = 0x01;

fn next_close_time_resolution(
    previous_resolution: u8,
    previous_agree: bool,
    ledger_seq: u32,
) -> u8 {
    let Some(idx) = POSSIBLE_CLOSE_TIME_RESOLUTIONS
        .iter()
        .position(|res| *res == previous_resolution)
    else {
        return previous_resolution;
    };

    if !previous_agree && ledger_seq % DECREASE_RESOLUTION_EVERY == 0 {
        if let Some(next) = POSSIBLE_CLOSE_TIME_RESOLUTIONS.get(idx + 1) {
            return *next;
        }
    }

    if previous_agree && ledger_seq % INCREASE_RESOLUTION_EVERY == 0 && idx > 0 {
        return POSSIBLE_CLOSE_TIME_RESOLUTIONS[idx - 1];
    }

    previous_resolution
}

fn effective_close_time(close_time: u64, resolution: u8, prior_close_time: u64) -> u64 {
    if close_time == 0 {
        return 0;
    }

    let rounded = round_close_time(close_time, resolution);
    rounded.max(prior_close_time.saturating_add(1))
}

fn parse_skip_list_hashes(sle: &crate::ledger::sle::SLE) -> Vec<[u8; 32]> {
    let Some(raw) = sle.get_field_vl(19, 2).or_else(|| sle.get_field_vl(19, 1)) else {
        return Vec::new();
    };

    let mut hashes = Vec::with_capacity(raw.len() / 32);
    for chunk in raw.chunks_exact(32) {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(chunk);
        hashes.push(hash);
    }
    hashes
}

fn build_skip_list_sle(
    first_ledger_sequence: Option<u32>,
    hashes: &[[u8; 32]],
    last_seq: u32,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(3 + 5 + 5 + 3 + hashes.len() * 32);

    // LedgerHashes SLEs are raw-only objects in this codebase, so build
    // them directly with the canonical field order rippled serializes.
    crate::ledger::meta::write_field_header(&mut data, 1, 1);
    data.extend_from_slice(&0x0068u16.to_be_bytes());

    crate::ledger::meta::write_field_header(&mut data, 2, 2);
    data.extend_from_slice(&0u32.to_be_bytes());

    if let Some(first_seq) = first_ledger_sequence {
        crate::ledger::meta::write_field_header(&mut data, 2, 26);
        data.extend_from_slice(&first_seq.to_be_bytes());
    }

    crate::ledger::meta::write_field_header(&mut data, 2, 27);
    data.extend_from_slice(&last_seq.to_be_bytes());

    // Public/mainnet `LedgerHashes` uses `sfHashes` at `(19, 2)`. The parser
    // still reads the
    // older local (19, 1) encoding above so pre-fix ledgers can roll forward.
    crate::ledger::meta::write_field_header(&mut data, 19, 2);
    crate::ledger::meta::encode_vl_length(&mut data, hashes.len() * 32);
    for hash in hashes {
        data.extend_from_slice(hash);
    }

    data
}

fn update_skip_lists(state: &mut LedgerState, prev_seq: u32, parent_hash: &[u8; 32]) {
    use crate::ledger::keylet;

    if (prev_seq & 0xFF) == 0 && prev_seq > 0 {
        let long_kl = keylet::skip_for_ledger(prev_seq);
        let (first_seq, mut hashes) = state
            .get_raw_owned(&long_kl.key)
            .and_then(|raw| crate::ledger::sle::SLE::from_raw(long_kl.key, raw))
            .map(|sle| (sle.get_field_u32(2, 26), parse_skip_list_hashes(&sle)))
            .unwrap_or((None, Vec::new()));
        hashes.push(*parent_hash);
        state.insert_raw(
            long_kl.key,
            build_skip_list_sle(first_seq, &hashes, prev_seq),
        );
    }

    let short_kl = keylet::skip();
    let (first_seq, mut hashes) = state
        .get_raw_owned(&short_kl.key)
        .and_then(|raw| crate::ledger::sle::SLE::from_raw(short_kl.key, raw))
        .map(|sle| (sle.get_field_u32(2, 26), parse_skip_list_hashes(&sle)))
        .unwrap_or((None, Vec::new()));

    if hashes.len() == 256 {
        hashes.remove(0);
    }
    hashes.push(*parent_hash);

    state.insert_raw(
        short_kl.key,
        build_skip_list_sle(first_seq, &hashes, prev_seq),
    );
}

/// Outcome of closing one ledger.
#[derive(Debug)]
pub struct CloseResult {
    /// The new ledger header (sequence = prev + 1).
    pub header: LedgerHeader,
    /// Transactions that were included in this ledger (for history storage).
    pub tx_records: Vec<TxRecord>,
    /// Number of transactions applied (tesSUCCESS).
    pub applied_count: usize,
    /// Number of transactions that failed (fee claimed, not applied).
    pub failed_count: usize,
    /// Number of transactions that couldn't even be parsed/applied.
    pub skipped_count: usize,
}

/// rippled's multi-pass constants (BuildLedger.cpp).
const LEDGER_TOTAL_PASSES: usize = 3;
const LEDGER_RETRY_PASSES: usize = 1;

/// An entry in the canonical transaction set, sortable by (salted account, sequence, txid).
struct CanonicalEntry {
    /// Sort key: account padded to 32 bytes then XORed with salt.
    salted_account: [u8; 32],
    sequence: u32,
    hash: [u8; 32],
    blob: Vec<u8>,
}

impl CanonicalEntry {
    fn new(
        account: &[u8; 20],
        sequence: u32,
        hash: [u8; 32],
        blob: Vec<u8>,
        salt: &[u8; 32],
    ) -> Self {
        // rippled CanonicalTXSet::accountKey(): copy 20-byte account into first 20 bytes
        // of a 32-byte buffer (rest zero), then XOR with salt.
        let mut salted = [0u8; 32];
        salted[..20].copy_from_slice(account);
        for i in 0..32 {
            salted[i] ^= salt[i];
        }
        Self {
            salted_account: salted,
            sequence,
            hash,
            blob,
        }
    }
}

impl Ord for CanonicalEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.salted_account
            .cmp(&other.salted_account)
            .then(self.sequence.cmp(&other.sequence))
            .then(self.hash.cmp(&other.hash))
    }
}
impl PartialOrd for CanonicalEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for CanonicalEntry {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}
impl Eq for CanonicalEntry {}

/// Close the current ledger: drain the pool, apply transactions, build a new header.
///
/// Uses rippled's multi-pass model with `certainRetry` semantics and
/// canonical transaction ordering (CanonicalTXSet-compatible).
///
/// `prev` is the current (parent) ledger header.  `state` is the live
/// account state — it is mutated in-place.  `pool` is drained.
pub fn close_ledger(
    prev: &LedgerHeader,
    state: &mut LedgerState,
    pool: &mut TxPool,
    close_time: u64,
    have_close_time_consensus: bool,
) -> CloseResult {
    let entries = pool.drain_sorted();

    let new_seq = prev.sequence + 1;

    let mut applied_count = 0usize;
    let mut failed_count = 0usize;
    let mut skipped_count = 0usize;
    let mut fees_burned = 0u64;
    let mut tx_records = Vec::new();
    let mut next_tx_index = 0u32;
    let mut tx_map = SparseSHAMap::new();

    // ── Build handler context from parent header ──────────────────────────
    let tx_ctx = TxContext::from_parent(prev, close_time);

    // ── Compute salt for canonical ordering ──────────────────────────────
    // rippled uses the consensus transaction set hash as the CanonicalTXSet salt.
    // Derive it from all transaction hashes in the set.
    let salt: [u8; 32] = {
        let mut hasher_data = Vec::with_capacity(4 + entries.len() * 32);
        hasher_data.extend_from_slice(&[0x53, 0x4E, 0x44, 0x00]); // SND\0 prefix
        for e in &entries {
            hasher_data.extend_from_slice(&e.hash);
        }
        sha512_first_half(&hasher_data)
    };

    // ── Parse and build canonical set ────────────────────────────────────
    let mut txns: Vec<CanonicalEntry> = Vec::with_capacity(entries.len());
    for entry in entries {
        let parsed = match parse_blob(&entry.blob) {
            Ok(p) => p,
            Err(_) => {
                skipped_count += 1;
                continue;
            }
        };
        txns.push(CanonicalEntry::new(
            &parsed.account,
            parsed.sequence,
            entry.hash,
            entry.blob,
            &salt,
        ));
    }
    txns.sort();

    // ── Multi-pass apply (rippled BuildLedger.cpp:applyTransactions) ────
    let mut certain_retry = true;
    let mut failed_set: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    for pass in 0..LEDGER_TOTAL_PASSES {
        let flags = if certain_retry {
            ApplyFlags::RETRY
        } else {
            ApplyFlags::NONE
        };
        let mut changes = 0usize;

        let mut kept = Vec::new();

        for entry in txns {
            if failed_set.contains(&entry.hash) {
                continue;
            }

            let parsed = match parse_blob(&entry.blob) {
                Ok(p) => p,
                Err(_) => {
                    skipped_count += 1;
                    continue;
                }
            };

            let result = run_tx(state, &parsed, &tx_ctx, flags);

            match classify_result(&result) {
                ApplyOutcome::Success => {
                    // Transaction applied — record it
                    let result_str = result.ter.token();
                    if result.ter.is_tes_success() {
                        applied_count += 1;
                    } else {
                        failed_count += 1;
                    }
                    fees_burned += parsed.fee;

                    // Thread PreviousTxnID/PreviousTxnLgrSeq onto every
                    // modified object before building metadata, matching
                    // rippled's in-apply stamping and replay_ledger's
                    // post-apply behavior. Without this, close_ledger
                    // produced state that disagreed with replay_ledger on
                    // the same transaction set (see 2026-04-11 finding).
                    stamp_touched_previous_fields(state, &result.touched, &entry.hash, new_seq);

                    let meta = build_tx_metadata(
                        state,
                        &result.touched,
                        entry.hash,
                        new_seq,
                        next_tx_index,
                        result_str,
                    );
                    let leaf_data = encode_tx_leaf_data(&entry.blob, &meta);
                    let lh = tx_leaf_hash(&leaf_data, &entry.hash);
                    tx_map.insert(entry.hash, lh);

                    tx_records.push(TxRecord {
                        blob: entry.blob,
                        meta,
                        hash: entry.hash,
                        ledger_seq: new_seq,
                        tx_index: next_tx_index,
                        result: result_str.to_string(),
                    });
                    next_tx_index += 1;
                    changes += 1;
                }
                ApplyOutcome::Fail => {
                    // Permanent failure — remove from set
                    failed_set.insert(entry.hash);
                }
                ApplyOutcome::Retry => {
                    // Keep for next pass
                    kept.push(entry);
                }
            }
        }

        txns = kept;

        // A non-retry pass made no changes — stop
        if changes == 0 && !certain_retry {
            break;
        }

        // Stop retriable passes when no progress or past retry limit
        if changes == 0 || pass >= LEDGER_RETRY_PASSES {
            certain_retry = false;
        }
    }

    // Remaining txns that never applied are skipped
    skipped_count += txns.len();

    update_skip_lists(state, prev.sequence, &prev.hash);

    // Compute the transaction set hash from the SHAMap root.
    let transaction_hash = if tx_map.len() == 0 {
        [0u8; 32]
    } else {
        tx_map.root_hash()
    };

    let account_hash = state.state_hash();

    let resolution = next_close_time_resolution(
        prev.close_time_resolution,
        prev.close_flags & CLOSE_TIME_NO_CONSENSUS == 0,
        new_seq,
    );
    let effective_close_time = effective_close_time(close_time, resolution, prev.close_time);

    let header = LedgerHeader {
        sequence: new_seq,
        hash: [0u8; 32],
        parent_hash: prev.hash,
        close_time: effective_close_time,
        total_coins: prev.total_coins.saturating_sub(fees_burned),
        account_hash,
        transaction_hash,
        parent_close_time: prev.close_time as u32,
        close_time_resolution: resolution,
        close_flags: if have_close_time_consensus {
            0
        } else {
            CLOSE_TIME_NO_CONSENSUS
        },
    };

    let hash = header.compute_hash();
    let header = LedgerHeader { hash, ..header };

    CloseResult {
        header,
        tx_records,
        applied_count,
        failed_count,
        skipped_count,
    }
}

// ── Replay (follower mode) ────────────────────────────────────────────────────

/// Per-transaction touched-key attribution, populated only when replay_ledger
/// is called with byte_diff=true. Used by forensic capture to map a divergent
/// state key back to the transaction that produced it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxAttribution {
    pub tx_id: [u8; 32],
    pub tx_index: u32,
    pub tx_type: String,
    pub ter_token: String,
    pub created_keys: Vec<[u8; 32]>,
    pub modified_keys: Vec<[u8; 32]>,
}

/// Outcome of replaying one validated ledger.
#[derive(Debug)]
pub struct ReplayResult {
    /// The new ledger header (sequence = prev + 1).
    pub header: LedgerHeader,
    /// Transactions that were included in this ledger (for history storage).
    pub tx_records: Vec<TxRecord>,
    /// Number of transactions applied (tesSUCCESS).
    pub applied_count: usize,
    /// Number of transactions that failed (fee claimed, not applied).
    pub failed_count: usize,
    /// Number of transactions that couldn't even be parsed.
    pub skipped_count: usize,
    /// Unique keys touched by engine replay, in first-seen order.
    pub touched_keys: Vec<crate::ledger::Key>,
    /// Per-transaction touched-key attribution. Empty unless byte_diff=true.
    pub per_tx_attribution: Vec<TxAttribution>,
}

/// A raw transaction extracted from a liTX_NODE response, with its metadata.
struct ReplayTx {
    /// The raw transaction blob (without metadata).
    blob: Vec<u8>,
    /// The raw metadata blob.
    meta: Vec<u8>,
    /// Parsed authoritative metadata nodes for this transaction.
    nodes: Vec<crate::ledger::meta::AffectedNode>,
    /// sfTransactionIndex from the metadata (execution order).
    tx_index: u32,
    /// txID = SHA-512-Half(TXN\0 + blob).
    tx_id: [u8; 32],
}

#[derive(Default)]
struct DirectoryIndexDelta {
    add: std::collections::BTreeSet<[u8; 32]>,
    remove: std::collections::BTreeSet<[u8; 32]>,
}

fn sle_entry_type(sle: &[u8]) -> Option<u16> {
    if sle.len() >= 3 && sle[0] == 0x11 {
        Some(u16::from_be_bytes([sle[1], sle[2]]))
    } else {
        None
    }
}

fn restore_validated_replay_before(
    state: &mut LedgerState,
    key: &crate::ledger::Key,
    before: Option<&Vec<u8>>,
) {
    state.clear_typed_entry_for_key(key);
    match before {
        Some(bytes) => {
            state.insert_raw(*key, bytes.clone());
            if let Some(entry_type) = sle_entry_type(bytes) {
                crate::ledger::follow::sync_typed(state, entry_type, key, bytes);
            }
        }
        None => {
            state.remove_raw(key);
        }
    }
}

fn incomplete_book_directory(sle: &[u8], key: &crate::ledger::Key) -> bool {
    let Ok(dir) = crate::ledger::DirectoryNode::decode(sle, key.0) else {
        return false;
    };
    dir.exchange_rate.is_some()
        && (dir.taker_pays_currency.is_none()
            || dir.taker_pays_issuer.is_none()
            || dir.taker_gets_currency.is_none()
            || dir.taker_gets_issuer.is_none())
}

fn find_parsed_field<'a>(
    fields: &'a [crate::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|f| f.type_code == type_code && f.field_code == field_code)
        .map(|f| f.data.as_slice())
}

fn parsed_hash256(
    fields: &[crate::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<[u8; 32]> {
    let bytes = find_parsed_field(fields, type_code, field_code)?;
    (bytes.len() >= 32).then(|| bytes[..32].try_into().ok()).flatten()
}

fn parsed_account(
    fields: &[crate::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<[u8; 20]> {
    let bytes = find_parsed_field(fields, type_code, field_code)?;
    (bytes.len() >= 20).then(|| bytes[..20].try_into().ok()).flatten()
}

fn parsed_amount_issuer(
    fields: &[crate::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<[u8; 20]> {
    let bytes = find_parsed_field(fields, type_code, field_code)?;
    let (amount, _) = crate::transaction::amount::Amount::from_bytes(bytes).ok()?;
    match amount {
        crate::transaction::amount::Amount::Iou { issuer, .. } => Some(issuer),
        _ => None,
    }
}

fn parsed_u64(
    fields: &[crate::ledger::meta::ParsedField],
    type_code: u16,
    field_code: u16,
) -> Option<u64> {
    let bytes = find_parsed_field(fields, type_code, field_code)?;
    if bytes.len() < 8 {
        return None;
    }
    Some(u64::from_be_bytes(bytes[..8].try_into().ok()?))
}

fn offer_directory_pages(
    node: &crate::ledger::meta::AffectedNode,
) -> Option<[crate::ledger::Key; 2]> {
    if node.entry_type != 0x006f {
        return None;
    }
    let owner = parsed_account(&node.fields, 8, 1)?;
    let owner_node = parsed_u64(&node.fields, 3, 4).unwrap_or(0);
    let book_root = parsed_hash256(&node.fields, 5, 16)?;
    let book_node = parsed_u64(&node.fields, 3, 3).unwrap_or(0);
    let owner_root = crate::ledger::directory::owner_dir_key(&owner);
    Some([
        crate::ledger::directory::page_key(&book_root, book_node),
        crate::ledger::directory::page_key(&owner_root.0, owner_node),
    ])
}

fn offer_directory_pages_from_fields(
    fields: &[crate::ledger::meta::ParsedField],
) -> Option<[crate::ledger::Key; 2]> {
    let owner = parsed_account(fields, 8, 1)?;
    let owner_node = parsed_u64(fields, 3, 4).unwrap_or(0);
    let book_root = parsed_hash256(fields, 5, 16)?;
    let book_node = parsed_u64(fields, 3, 3).unwrap_or(0);
    let owner_root = crate::ledger::directory::owner_dir_key(&owner);
    Some([
        crate::ledger::directory::page_key(&book_root, book_node),
        crate::ledger::directory::page_key(&owner_root.0, owner_node),
    ])
}

fn modified_offer_directory_pages(
    node: &crate::ledger::meta::AffectedNode,
) -> Option<([crate::ledger::Key; 2], [crate::ledger::Key; 2])> {
    if node.entry_type != 0x006f || node.action != crate::ledger::meta::Action::Modified {
        return None;
    }

    let current = offer_directory_pages_from_fields(&node.fields)?;

    let prior_owner = parsed_account(&node.previous_fields, 8, 1)
        .or_else(|| parsed_account(&node.fields, 8, 1))?;
    let prior_owner_node = parsed_u64(&node.previous_fields, 3, 4)
        .or_else(|| parsed_u64(&node.fields, 3, 4))
        .unwrap_or(0);
    let prior_book_root = parsed_hash256(&node.previous_fields, 5, 16)
        .or_else(|| parsed_hash256(&node.fields, 5, 16))?;
    let prior_book_node = parsed_u64(&node.previous_fields, 3, 3)
        .or_else(|| parsed_u64(&node.fields, 3, 3))
        .unwrap_or(0);
    let prior_owner_root = crate::ledger::directory::owner_dir_key(&prior_owner);
    let prior = [
        crate::ledger::directory::page_key(&prior_book_root, prior_book_node),
        crate::ledger::directory::page_key(&prior_owner_root.0, prior_owner_node),
    ];

    Some((prior, current))
}

fn owner_directory_pages_from_fields(
    entry_type: u16,
    fields: &[crate::ledger::meta::ParsedField],
) -> Vec<crate::ledger::Key> {
    let mut pages = std::collections::BTreeSet::new();

    match entry_type {
        0x006f | 0x0043 | 0x0075 | 0x0078 | 0x0070 | 0x0054 | 0x0053 | 0x0049 => {
            if let Some(account) = parsed_account(fields, 8, 1) {
                let owner_node = parsed_u64(fields, 3, 4).unwrap_or(0);
                let owner_root = crate::ledger::directory::owner_dir_key(&account);
                pages.insert(crate::ledger::directory::page_key(&owner_root.0, owner_node));
            }
            if matches!(entry_type, 0x0043 | 0x0075 | 0x0078) {
                if let Some(destination) = parsed_account(fields, 8, 3) {
                    let destination_node = parsed_u64(fields, 3, 9).unwrap_or(0);
                    let destination_root = crate::ledger::directory::owner_dir_key(&destination);
                    pages.insert(crate::ledger::directory::page_key(
                        &destination_root.0,
                        destination_node,
                    ));
                }
            }
        }
        0x0037 => {
            if let Some(owner) = parsed_account(fields, 8, 2) {
                let owner_node = parsed_u64(fields, 3, 12).unwrap_or(0);
                let owner_root = crate::ledger::directory::owner_dir_key(&owner);
                pages.insert(crate::ledger::directory::page_key(&owner_root.0, owner_node));
            }
        }
        0x0072 => {
            if let Some(low_account) = parsed_amount_issuer(fields, 6, 6) {
                let low_node = parsed_u64(fields, 3, 7).unwrap_or(0);
                let low_root = crate::ledger::directory::owner_dir_key(&low_account);
                pages.insert(crate::ledger::directory::page_key(&low_root.0, low_node));
            }
            if let Some(high_account) = parsed_amount_issuer(fields, 6, 7) {
                let high_node = parsed_u64(fields, 3, 8).unwrap_or(0);
                let high_root = crate::ledger::directory::owner_dir_key(&high_account);
                pages.insert(crate::ledger::directory::page_key(&high_root.0, high_node));
            }
        }
        _ => {}
    }

    pages.into_iter().collect()
}

pub(crate) fn ensure_owner_directory_entries_for_created_sle(
    state: &mut LedgerState,
    key: crate::ledger::Key,
    entry_type: u16,
    sle: &[u8],
) -> Vec<crate::ledger::Key> {
    fn load_directory(
        state: &LedgerState,
        key: &crate::ledger::Key,
    ) -> Option<crate::ledger::directory::DirectoryNode> {
        state
            .get_raw_owned(key)
            .and_then(|raw| crate::ledger::directory::DirectoryNode::decode(&raw, key.0).ok())
            .or_else(|| state.get_directory(key).cloned())
    }

    let mut touched = std::collections::BTreeSet::new();

    let mut ensure_owner = |owner: [u8; 20], owner_node: u64| {
        let root = crate::ledger::directory::owner_dir_key(&owner);
        let target = crate::ledger::directory::page_key(&root.0, owner_node);
        if let Some(mut page) = load_directory(state, &target) {
            if !page.indexes.iter().any(|existing| existing == &key.0) {
                page.indexes.push(key.0);
                page.raw_sle = None;
                state.insert_directory(page);
                touched.insert(target);
            }
            if owner_node == 0 {
                touched.insert(root);
            }
            return;
        }

        if crate::ledger::directory::owner_dir_contains_entry(state, &owner, &key.0) {
            return;
        }

        let page = crate::ledger::directory::dir_add(state, &owner, key.0);
        touched.insert(root);
        if page != 0 {
            touched.insert(crate::ledger::directory::page_key(&root.0, page));
        }
    };

    match entry_type {
        0x006f => {
            if let Some(offer) = crate::ledger::offer::Offer::decode_from_sle(sle) {
                ensure_owner(offer.account, offer.owner_node);
            }
        }
        0x0072 => {
            if let Some(trustline) = crate::ledger::trustline::RippleState::decode_from_sle(sle) {
                ensure_owner(trustline.low_account, trustline.low_node);
                ensure_owner(trustline.high_account, trustline.high_node);
            }
        }
        _ => {}
    }

    touched.into_iter().collect()
}

fn fields_include_indexes(fields: &[crate::ledger::meta::ParsedField]) -> bool {
    fields.iter().any(|f| f.type_code == 19 && f.field_code == 1)
}

fn apply_directory_index_delta(
    key: &crate::ledger::Key,
    sle: Vec<u8>,
    fields: &[crate::ledger::meta::ParsedField],
    delta: Option<&DirectoryIndexDelta>,
) -> Vec<u8> {
    if fields_include_indexes(fields) {
        return sle;
    }
    let Some(delta) = delta else {
        return sle;
    };
    let Ok(mut dir) = crate::ledger::DirectoryNode::decode(&sle, key.0) else {
        return sle;
    };
    for remove in &delta.remove {
        dir.indexes.retain(|index| index != remove);
    }
    for add in &delta.add {
        if !dir.indexes.iter().any(|index| index == add) {
            dir.indexes.push(*add);
        }
    }
    dir.raw_sle = None;
    dir.encode()
}

fn apply_directory_book_context(
    key: &crate::ledger::Key,
    sle: Vec<u8>,
    related_offer_book: Option<([u8; 20], [u8; 20], [u8; 20], [u8; 20])>,
) -> Vec<u8> {
    let Some((pays_cur, pays_iss, gets_cur, gets_iss)) = related_offer_book else {
        return sle;
    };
    let Ok(mut dir) = crate::ledger::DirectoryNode::decode(&sle, key.0) else {
        return sle;
    };
    dir.taker_pays_currency = Some(pays_cur);
    dir.taker_pays_issuer = Some(pays_iss);
    dir.taker_gets_currency = Some(gets_cur);
    dir.taker_gets_issuer = Some(gets_iss);
    dir.encode()
}

fn apply_authoritative_validated_tx_metadata(
    state: &mut LedgerState,
    tx_hash: &[u8; 32],
    ledger_seq: u32,
    nodes: &[crate::ledger::meta::AffectedNode],
    local_touched: &[(crate::ledger::Key, Option<Vec<u8>>)],
) -> Vec<crate::ledger::Key> {
    let should_thread_entry_type = |entry_type: u16| {
        crate::ledger::sle::LedgerEntryType::from_u16(entry_type)
            .map(|entry_type| !matches!(entry_type, crate::ledger::sle::LedgerEntryType::LedgerHashes))
            .unwrap_or(false)
    };

    let metadata_keys: std::collections::HashSet<crate::ledger::Key> =
        nodes.iter().map(|node| crate::ledger::Key(node.ledger_index)).collect();
    let local_before: std::collections::HashMap<crate::ledger::Key, Option<Vec<u8>>> = local_touched
        .iter()
        .map(|(key, before)| (*key, before.clone()))
        .collect();

    for (key, before) in local_touched {
        if metadata_keys.contains(key) {
            continue;
        }
        restore_validated_replay_before(state, key, before.as_ref());
    }

    let mut tx_book_dirs: std::collections::HashMap<
        [u8; 32],
        ([u8; 20], [u8; 20], [u8; 20], [u8; 20]),
    > = std::collections::HashMap::new();
    for node in nodes {
        if node.entry_type != 0x006f {
            continue;
        }
        if let Some((pays_cur, pays_iss, gets_cur, gets_iss, book_dir)) =
            crate::ledger::follow::extract_offer_book_sides(&node.fields)
        {
            let sides = (pays_cur, pays_iss, gets_cur, gets_iss);
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
    let mut dir_index_deltas: std::collections::HashMap<crate::ledger::Key, DirectoryIndexDelta> =
        std::collections::HashMap::new();
    for node in nodes {
        let mut directory_pages = std::collections::BTreeSet::new();
        directory_pages.extend(owner_directory_pages_from_fields(node.entry_type, &node.fields));
        if let Some([book_page, owner_page]) = offer_directory_pages(node) {
            directory_pages.insert(book_page);
            directory_pages.insert(owner_page);
        }
        match node.action {
            crate::ledger::meta::Action::Created => {
                for page in directory_pages {
                    dir_index_deltas
                        .entry(page)
                        .or_default()
                        .add
                        .insert(node.ledger_index);
                }
            }
            crate::ledger::meta::Action::Deleted => {
                for page in directory_pages {
                    dir_index_deltas
                        .entry(page)
                        .or_default()
                        .remove
                        .insert(node.ledger_index);
                }
            }
            crate::ledger::meta::Action::Modified => {
                if let Some((before_pages, after_pages)) = modified_offer_directory_pages(node) {
                    for before in before_pages {
                        if !after_pages.iter().any(|page| page == &before) {
                            dir_index_deltas
                                .entry(before)
                                .or_default()
                                .remove
                                .insert(node.ledger_index);
                        }
                    }
                    for after in after_pages {
                        if !before_pages.iter().any(|page| page == &after) {
                            dir_index_deltas
                                .entry(after)
                                .or_default()
                                .add
                                .insert(node.ledger_index);
                        }
                    }
                }
            }
        }
    }

    let mut authoritative_keys = Vec::new();
    let created_nodes: Vec<crate::ledger::meta::AffectedNode> = nodes
        .iter()
        .filter(|node| node.action == crate::ledger::meta::Action::Created)
        .cloned()
        .collect();
    let other_nodes: Vec<&crate::ledger::meta::AffectedNode> = nodes
        .iter()
        .filter(|node| node.action != crate::ledger::meta::Action::Created)
        .collect();

    let mut pending_created = created_nodes;
    while !pending_created.is_empty() {
        let mut next_pending = Vec::new();
        let mut progressed = false;
        for node in pending_created {
            let key = crate::ledger::Key(node.ledger_index);
            authoritative_keys.push(key);
            let (new_ptid, new_ptseq) = if should_thread_entry_type(node.entry_type) {
                (Some(*tx_hash), Some(ledger_seq))
            } else {
                (None, None)
            };
            let related_offer_book = crate::ledger::follow::related_offer_book_for_directory_node(
                &node,
                &tx_book_dirs,
            );
            let sle = if node.entry_type == 0x0064 {
                crate::ledger::follow::build_created_sle_with_state(
                    state,
                    &key,
                    node.entry_type,
                    &node.fields,
                    related_offer_book,
                    new_ptid,
                    new_ptseq,
                )
            } else {
                crate::ledger::follow::build_created_sle_with_state(
                    state,
                    &key,
                    node.entry_type,
                    &node.fields,
                    related_offer_book,
                    new_ptid,
                    new_ptseq,
                )
            };
            let sle = if node.entry_type == 0x0064 {
                apply_directory_index_delta(
                    &key,
                    sle,
                    &node.fields,
                    dir_index_deltas.get(&key),
                    )
                } else {
                    sle
                };
            let sle = if node.entry_type == 0x0064 {
                apply_directory_book_context(&key, sle, related_offer_book)
            } else {
                sle
            };
            if node.entry_type == 0x0064
                && incomplete_book_directory(&sle, &key)
                && next_pending.len() + 1 < metadata_keys.len()
            {
                next_pending.push(node);
                continue;
            }

            state.insert_raw(key, sle.clone());
            crate::ledger::follow::sync_typed(state, node.entry_type, &key, &sle);
            authoritative_keys.extend(ensure_owner_directory_entries_for_created_sle(
                state,
                key,
                node.entry_type,
                &sle,
            ));
            progressed = true;
        }

        if !progressed {
            for node in next_pending {
                let key = crate::ledger::Key(node.ledger_index);
                let (new_ptid, new_ptseq) = if should_thread_entry_type(node.entry_type) {
                    (Some(*tx_hash), Some(ledger_seq))
                } else {
                    (None, None)
                };
                let related_offer_book =
                    crate::ledger::follow::related_offer_book_for_directory_node(
                        &node,
                        &tx_book_dirs,
                    );
                let sle = if node.entry_type == 0x0064 {
                    state
                        .get_raw_owned(&key)
                        .map(|local_raw| {
                            crate::ledger::meta::patch_sle(
                                &local_raw,
                                &node.fields,
                                new_ptid,
                                new_ptseq,
                                &[],
                            )
                        })
                        .unwrap_or_else(|| {
                            crate::ledger::follow::build_created_sle_with_state(
                                state,
                                &key,
                                node.entry_type,
                                &node.fields,
                                related_offer_book,
                                new_ptid,
                                new_ptseq,
                            )
                        })
                } else {
                    crate::ledger::follow::build_created_sle_with_state(
                        state,
                        &key,
                        node.entry_type,
                        &node.fields,
                        related_offer_book,
                        new_ptid,
                        new_ptseq,
                    )
                };
                let sle = if node.entry_type == 0x0064 {
                    apply_directory_index_delta(
                        &key,
                        sle,
                        &node.fields,
                        dir_index_deltas.get(&key),
                    )
                } else {
                    sle
                };
                state.insert_raw(key, sle.clone());
                crate::ledger::follow::sync_typed(state, node.entry_type, &key, &sle);
                authoritative_keys.extend(ensure_owner_directory_entries_for_created_sle(
                    state,
                    key,
                    node.entry_type,
                    &sle,
                ));
            }
            break;
        }
        pending_created = next_pending;
    }

    for node in other_nodes {
        let key = crate::ledger::Key(node.ledger_index);
        authoritative_keys.push(key);
        let (new_ptid, new_ptseq) = if should_thread_entry_type(node.entry_type) {
            (Some(*tx_hash), Some(ledger_seq))
        } else {
            (None, None)
        };

        match node.action {
            crate::ledger::meta::Action::Modified => {
                let final_keys: std::collections::HashSet<(u16, u16)> = node
                    .fields
                    .iter()
                    .map(|f| (f.type_code, f.field_code))
                    .collect();
                let deleted: Vec<(u16, u16)> = node
                    .previous_fields
                    .iter()
                    .map(|f| (f.type_code, f.field_code))
                    .filter(|field| !final_keys.contains(field))
                    .collect();

                let base = local_before
                    .get(&key)
                    .cloned()
                    .flatten()
                    .or_else(|| state.get_raw_owned(&key));
                let Some(base) = base else {
                    tracing::warn!(
                        "validated replay metadata: missing ModifiedNode base object for key={} tx_hash={}",
                        hex::encode_upper(&key.0[..8]),
                        hex::encode_upper(&tx_hash[..8]),
                    );
                    continue;
                };

                let patched = crate::ledger::meta::patch_sle(
                    &base,
                    &node.fields,
                    new_ptid,
                    new_ptseq,
                    &deleted,
                );
                let related_offer_book = crate::ledger::follow::related_offer_book_for_directory_node(
                    node,
                    &tx_book_dirs,
                );
                let patched = if node.entry_type == 0x0064 {
                    let patched = apply_directory_book_context(&key, patched, related_offer_book);
                    apply_directory_index_delta(
                        &key,
                        patched,
                        &node.fields,
                        dir_index_deltas.get(&key),
                    )
                } else {
                    patched
                };
                state.insert_raw(key, patched.clone());
                crate::ledger::follow::sync_typed(state, node.entry_type, &key, &patched);
            }
            crate::ledger::meta::Action::Deleted => {
                state.clear_typed_entry_for_key(&key);
                state.remove_raw(&key);
            }
            crate::ledger::meta::Action::Created => {}
        }
    }

    authoritative_keys
}

/// Replay a validated ledger's transactions against the current state.
///
/// Matches rippled's LedgerReplay path (BuildLedger.cpp:198-220):
///   - Transactions ordered by sfTransactionIndex (from metadata)
///   - Single pass, no retry (replay of already-validated transactions)
///   - Uses the validated header's close_time, total_coins, etc.
///
/// The caller provides raw tx+meta blobs extracted from liTX_NODE.
/// Parse each transaction, sort by `sfTransactionIndex`, apply via `apply_tx`,
/// and compute the resulting state hash for verification.
pub fn replay_ledger(
    prev: &LedgerHeader,
    state: &mut LedgerState,
    tx_blobs_with_meta: Vec<(Vec<u8>, Vec<u8>)>,
    validated_header: &LedgerHeader,
    byte_diff: bool,
) -> ReplayResult {
    let new_seq = prev.sequence + 1;
    const REPLAY_DIAG_SEQ: u32 = 103447365;
    let replay_diag = new_seq == REPLAY_DIAG_SEQ;
    let mut per_tx_attribution: Vec<TxAttribution> = Vec::new();

    // Replay depends on the authoritative amendment set from the seeded
    // prestate. Without rehydrating it here, validated replay can behave like
    // gated features (for example fixPreviousTxnID on DirectoryNodes) are
    // disabled even when the network ledger expects them.
    for amendment in crate::ledger::read_amendments(state) {
        state.enable_amendment(amendment);
    }

    // Parse all transactions, extract sfTransactionIndex, compute txID
    let mut replay_txs: Vec<ReplayTx> = Vec::new();
    let mut skipped_count = 0usize;
    let phase_t0 = std::time::Instant::now();

    for (blob, meta) in tx_blobs_with_meta {
        // Compute txID = SHA-512-Half(TXN\0 + blob)
        let tx_id = {
            let mut data = Vec::with_capacity(4 + blob.len());
            data.extend_from_slice(&crate::transaction::serialize::PREFIX_TX_ID);
            data.extend_from_slice(&blob);
            sha512_first_half(&data)
        };

        // Extract sfTransactionIndex from metadata
        let (tx_index_opt, nodes) = crate::ledger::meta::parse_metadata_with_index(&meta);
        let tx_index = match tx_index_opt {
            Some(idx) => idx,
            None => {
                warn!(
                    "replay_ledger: tx {} has no sfTransactionIndex, skipping",
                    hex::encode_upper(&tx_id[..4])
                );
                skipped_count += 1;
                continue;
            }
        };

        replay_txs.push(ReplayTx {
            blob,
            meta,
            nodes,
            tx_index,
            tx_id,
        });
    }

    // Sort by sfTransactionIndex — this is the execution order rippled used.
    // rippled's LedgerReplay stores orderedTxns_ as map<uint32_t, STTx>
    // which is naturally sorted by the uint32_t key (sfTransactionIndex).
    replay_txs.sort_by_key(|tx| tx.tx_index);
    hydrate_replay_prestate(state, &replay_txs);
    let parse_ms = phase_t0.elapsed().as_millis();
    let apply_t0 = std::time::Instant::now();

    let mut applied_count = 0usize;
    let mut failed_count = 0usize;
    let mut logged_failures = 0usize;
    let mut fees_burned = 0u64;
    let mut tx_records = Vec::new();
    let mut touched_keys = Vec::new();
    let mut touched_seen = std::collections::HashSet::new();

    // Build the TX SHAMap for transaction_hash computation
    let mut tx_map = SparseSHAMap::new();

    // Single pass through sorted transactions — matches rippled's replay path
    // (BuildLedger.cpp:216-218: no retry, retryAssured=false)
    for rtx in &replay_txs {
        let parsed = match parse_blob(&rtx.blob) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    "replay_ledger: failed to parse tx {}: {:?}",
                    hex::encode_upper(&rtx.tx_id[..4]),
                    e
                );
                skipped_count += 1;
                continue;
            }
        };

        let meta_summary = crate::ledger::meta::parse_metadata_summary(&rtx.meta);
        let replay_ctx = TxContext {
            validated_result: meta_summary.result,
            validated_delivered_amount: meta_summary.delivered_amount,
            ..TxContext::from_parent(prev, validated_header.close_time)
        };
        let result = run_tx(state, &parsed, &replay_ctx, ApplyFlags::VALIDATED_REPLAY);
        let outcome = classify_result(&result);
        let result_str = result.ter.token();

        let authoritative_keys = apply_authoritative_validated_tx_metadata(
            state,
            &rtx.tx_id,
            new_seq,
            &rtx.nodes,
            &result.touched,
        );

        // Per-tx attribution: during validated replay, use authoritative
        // metadata keys rather than the raw local engine touch set. This keeps
        // forensic bundles aligned with the real XRPL side effects even when
        // the local engine needed metadata reconciliation.
        if byte_diff {
            let created_keys: Vec<[u8; 32]> = rtx
                .nodes
                .iter()
                .filter(|node| node.action == crate::ledger::meta::Action::Created)
                .map(|node| node.ledger_index)
                .collect();
            let modified_keys: Vec<[u8; 32]> = rtx
                .nodes
                .iter()
                .filter(|node| node.action != crate::ledger::meta::Action::Created)
                .map(|node| node.ledger_index)
                .collect();
            per_tx_attribution.push(TxAttribution {
                tx_id: rtx.tx_id,
                tx_index: rtx.tx_index,
                tx_type: parsed.tx_type.to_string(),
                ter_token: result_str.to_string(),
                created_keys,
                modified_keys,
            });
        }

        match outcome {
            ApplyOutcome::Success => {
                for key in &authoritative_keys {
                    if touched_seen.insert(*key) {
                        touched_keys.push(*key);
                    }
                }
                if result.ter.is_tes_success() {
                    applied_count += 1;
                } else {
                    failed_count += 1;
                }
                if result.ter.is_tes_success() || result.ter.is_tec_claim() {
                    fees_burned += parsed.fee;
                }
            }
            ApplyOutcome::Fail => {
                if replay_diag && logged_failures < 12 {
                    warn!(
                        "replay_ledger: tx {} type={} seq={} acct={} failed with {}",
                        hex::encode_upper(&rtx.tx_id[..4]),
                        parsed.tx_type,
                        parsed.sequence,
                        hex::encode_upper(&parsed.account[..4]),
                        result_str,
                    );
                    logged_failures += 1;
                }
                warn!(
                    "replay_ledger: tx {} failed in engine replay with {}",
                    hex::encode_upper(&rtx.tx_id[..4]),
                    result_str,
                );
                failed_count += 1;
            }
            ApplyOutcome::Retry => {
                if replay_diag && logged_failures < 12 {
                    warn!(
                        "replay_ledger: tx {} type={} seq={} acct={} requested retry with {}",
                        hex::encode_upper(&rtx.tx_id[..4]),
                        parsed.tx_type,
                        parsed.sequence,
                        hex::encode_upper(&parsed.account[..4]),
                        result_str,
                    );
                    logged_failures += 1;
                }
                warn!(
                    "replay_ledger: tx {} asked for retry during validated replay with {}",
                    hex::encode_upper(&rtx.tx_id[..4]),
                    result_str,
                );
                failed_count += 1;
            }
        }

        // Insert into TX SHAMap for transaction_hash computation.
        // The leaf data is the raw wire format: VL(tx) + VL(meta).
        let leaf_data = {
            let mut d = Vec::new();
            crate::transaction::serialize::encode_length(rtx.blob.len(), &mut d);
            d.extend_from_slice(&rtx.blob);
            crate::transaction::serialize::encode_length(rtx.meta.len(), &mut d);
            d.extend_from_slice(&rtx.meta);
            d
        };
        let lh = tx_leaf_hash(&leaf_data, &rtx.tx_id);
        tx_map.insert(rtx.tx_id, lh);

        tx_records.push(TxRecord {
            blob: rtx.blob.clone(),
            meta: rtx.meta.clone(),
            hash: rtx.tx_id,
            ledger_seq: new_seq,
            tx_index: rtx.tx_index,
            result: result_str.to_string(),
        });
    }

    let apply_ms = apply_t0.elapsed().as_millis();

    // Compute the transaction set hash from the TX SHAMap root
    let txhash_t0 = std::time::Instant::now();
    let transaction_hash = if tx_map.len() == 0 {
        [0u8; 32]
    } else {
        tx_map.root_hash()
    };
    let txhash_ms = txhash_t0.elapsed().as_millis();

    update_skip_lists(state, prev.sequence, &prev.hash);
    let short_skip_key = crate::ledger::keylet::skip().key;
    if touched_seen.insert(short_skip_key) {
        touched_keys.push(short_skip_key);
    }
    if (prev.sequence & 0xFF) == 0 && prev.sequence > 0 {
        let long_skip_key = crate::ledger::keylet::skip_for_ledger(prev.sequence).key;
        if touched_seen.insert(long_skip_key) {
            touched_keys.push(long_skip_key);
        }
    }

    // Compute the new account-state root hash
    let acchash_t0 = std::time::Instant::now();
    let account_hash = state.state_hash();
    let acchash_ms = acchash_t0.elapsed().as_millis();

    // Build the header using validated close_time, close_time_resolution,
    // and close_flags from the network (rippled's replay path uses the
    // validated header's values directly — BuildLedger.cpp:211-213).
    //
    // `total_coins`: use the validated header's value directly. Replaying a
    // validated ledger provides the authoritative `total_coins`.
    // This avoids double-counting fees (apply_tx deducts from account
    // balance, so `total_coins` must not be reduced a second time).
    let header = LedgerHeader {
        sequence: new_seq,
        hash: [0u8; 32],
        parent_hash: prev.hash,
        close_time: validated_header.close_time,
        total_coins: validated_header.total_coins,
        account_hash,
        transaction_hash,
        parent_close_time: prev.close_time as u32,
        close_time_resolution: validated_header.close_time_resolution,
        close_flags: validated_header.close_flags,
    };

    let hash = header.compute_hash();
    let header = LedgerHeader { hash, ..header };

    // Diagnostic comparison between computed fees and the validated header delta.
    let computed_coins = prev.total_coins.saturating_sub(fees_burned);
    if computed_coins != validated_header.total_coins {
        debug!(
            "replay_ledger: fee tracking delta: computed_coins={} validated_coins={} diff={}",
            computed_coins,
            validated_header.total_coins,
            computed_coins as i128 - validated_header.total_coins as i128,
        );
    }

    info!(
        "replay_ledger: seq={} applied={} failed={} skipped={} fees_burned={} hash={} | parse={}ms apply={}ms tx_hash={}ms acc_hash={}ms",
        new_seq, applied_count, failed_count, skipped_count, fees_burned,
        hex::encode_upper(&header.hash[..8]),
        parse_ms, apply_ms, txhash_ms, acchash_ms,
    );

    ReplayResult {
        header,
        tx_records,
        applied_count,
        failed_count,
        skipped_count,
        touched_keys,
        per_tx_attribution,
    }
}

/// Extract transaction blobs (tx + metadata) from a liTX_NODE peer response.
///
/// The TX SHAMap wire format for each node:
///   - Inner nodes: 512 or 513 bytes, or MIN\0 (0x4D494E00) prefix → skip
///   - Leaf type 0x04 (wireTypeTransactionWithMeta):
///     body = VL(tx_blob) + VL(meta_blob) + 32-byte txID + 0x04
///   - Leaf type 0x00 (raw tx, no metadata) -> skip because metadata is required
///
/// Returns Vec<(tx_blob, meta_blob)> pairs.
pub fn extract_tx_blobs_from_tx_tree(
    nodes: &[crate::proto::TmLedgerNode],
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut results = Vec::new();

    for node in nodes {
        let data = &node.nodedata;
        if data.len() < 34 {
            continue;
        }

        let wire_type = data[data.len() - 1];
        if wire_type == 0x02 || wire_type == 0x03 {
            continue;
        }

        if wire_type != 0x04 {
            continue;
        } // only wireTypeTransactionWithMeta

        // Strip 32-byte txID + 1-byte wire type from the end
        let payload = &data[..data.len() - 33];
        if payload.is_empty() {
            continue;
        }

        // Decode: VL(tx_blob) + VL(meta_blob)
        let mut pos = 0;

        // Read VL-encoded tx_blob
        let (tx_len, vl_bytes) = crate::transaction::serialize::decode_length(&payload[pos..]);
        pos += vl_bytes;
        if tx_len == 0 || pos + tx_len > payload.len() {
            continue;
        }
        let tx_blob = payload[pos..pos + tx_len].to_vec();
        pos += tx_len;

        // Read VL-encoded meta_blob
        if pos >= payload.len() {
            continue;
        }
        let (meta_len, vl_bytes2) = crate::transaction::serialize::decode_length(&payload[pos..]);
        pos += vl_bytes2;
        if meta_len == 0 || pos + meta_len > payload.len() {
            continue;
        }
        let meta_blob = payload[pos..pos + meta_len].to_vec();

        results.push((tx_blob, meta_blob));
    }

    results
}

#[cfg(test)]
mod tx_tree_extract_tests {
    use super::extract_tx_blobs_from_tx_tree;

    #[test]
    fn extracts_transaction_leaf_even_when_node_is_513_bytes() {
        let tx_blob = vec![0xAA; 192];
        let meta_blob = vec![0xBB; 285];
        let tx_id = [0xCC; 32];

        let mut nodedata = Vec::new();
        crate::transaction::serialize::encode_length(tx_blob.len(), &mut nodedata);
        nodedata.extend_from_slice(&tx_blob);
        crate::transaction::serialize::encode_length(meta_blob.len(), &mut nodedata);
        nodedata.extend_from_slice(&meta_blob);
        nodedata.extend_from_slice(&tx_id);
        nodedata.push(0x04);

        assert_eq!(nodedata.len(), 513);

        let nodes = vec![crate::proto::TmLedgerNode {
            nodedata,
            nodeid: Some(vec![0u8; 33]),
        }];
        let blobs = extract_tx_blobs_from_tx_tree(&nodes);
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].0.len(), tx_blob.len());
        assert_eq!(blobs[0].1.len(), meta_blob.len());
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
    use crate::ledger::{AccountRoot, LedgerState};
    use crate::transaction::{builder::TxBuilder, Amount};

    fn genesis_kp() -> KeyPair {
        KeyPair::Secp256k1(Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap())
    }

    fn genesis_id() -> [u8; 20] {
        crate::crypto::account_id(&genesis_kp().public_key_bytes())
    }

    fn dest_id() -> [u8; 20] {
        crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap()
    }

    fn initial_state() -> (LedgerHeader, LedgerState) {
        let mut state = LedgerState::new();
        state.insert_account(AccountRoot {
            account_id: genesis_id(),
            balance: 100_000_000_000_000_000, // 100B XRP
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
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        });
        let header = LedgerHeader {
            sequence: 1,
            hash: [0xAA; 32],
            parent_hash: [0u8; 32],
            close_time: 0,
            total_coins: 100_000_000_000_000_000,
            account_hash: state.state_hash(),
            transaction_hash: [0u8; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        };
        (header, state)
    }

    fn submit_payment(pool: &mut TxPool, seq: u32, amount: u64) {
        let kp = genesis_kp();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(amount))
            .fee(12)
            .sequence(seq)
            .sign(&kp)
            .unwrap();
        let parsed = parse_blob(&signed.blob).unwrap();
        pool.insert(signed.hash, signed.blob, &parsed);
    }

    #[test]
    fn test_close_empty_ledger() {
        let (prev, mut state) = initial_state();
        let mut pool = TxPool::new();
        let result = close_ledger(&prev, &mut state, &mut pool, 1000, true);

        assert_eq!(result.header.sequence, 2);
        assert_eq!(result.header.parent_hash, prev.hash);
        assert_eq!(result.applied_count, 0);
        assert_eq!(result.header.transaction_hash, [0u8; 32]);
        assert_ne!(result.header.hash, [0u8; 32]); // header hash is computed
    }

    #[test]
    fn test_close_with_one_payment() {
        let (prev, mut state) = initial_state();
        let mut pool = TxPool::new();
        submit_payment(&mut pool, 1, 5_000_000);

        let result = close_ledger(&prev, &mut state, &mut pool, 1000, true);
        assert_eq!(result.applied_count, 1);
        assert_eq!(result.failed_count, 0);
        assert_eq!(result.header.sequence, 2);

        // Sender debited
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 100_000_000_000_000_000 - 5_000_000 - 12);
        assert_eq!(sender.sequence, 2);

        // Destination credited
        let dest = state.get_account(&dest_id()).unwrap();
        assert_eq!(dest.balance, 5_000_000);

        let (tx_index, nodes) =
            crate::ledger::meta::parse_metadata_with_index(&result.tx_records[0].meta);
        assert_eq!(tx_index, Some(0));
        assert!(!nodes.is_empty());
    }

    #[test]
    fn test_close_retries_sequence_chained_transactions() {
        let (prev, mut state) = initial_state();
        let mut pool = TxPool::new();
        submit_payment(&mut pool, 2, 3_000_000);
        submit_payment(&mut pool, 1, 2_000_000);

        let result = close_ledger(&prev, &mut state, &mut pool, 1000, true);
        assert_eq!(result.applied_count, 2);
        assert_eq!(result.skipped_count, 0);
        assert_eq!(result.tx_records.len(), 2);
        assert_eq!(result.tx_records[0].tx_index, 0);
        assert_eq!(result.tx_records[1].tx_index, 1);
        assert!(!result.tx_records[0].meta.is_empty());

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.sequence, 3);
    }

    #[test]
    fn test_close_multiple_txs_in_sequence() {
        let (prev, mut state) = initial_state();
        let mut pool = TxPool::new();
        submit_payment(&mut pool, 1, 1_000_000);
        submit_payment(&mut pool, 2, 2_000_000);
        submit_payment(&mut pool, 3, 3_000_000);

        let result = close_ledger(&prev, &mut state, &mut pool, 1000, true);
        assert_eq!(result.applied_count, 3);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.sequence, 4);
        assert_eq!(sender.balance, 100_000_000_000_000_000 - 6_000_000 - 36);
    }

    #[test]
    fn test_close_skips_wrong_sequence() {
        let (prev, mut state) = initial_state();
        let mut pool = TxPool::new();
        // Skip sequence 1 — submit only seq 2
        submit_payment(&mut pool, 2, 1_000_000);

        let result = close_ledger(&prev, &mut state, &mut pool, 1000, true);
        assert_eq!(result.applied_count, 0);
        assert_eq!(result.skipped_count, 1);

        // State unchanged
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.sequence, 1);
    }

    #[test]
    fn test_consecutive_closes() {
        let (prev, mut state) = initial_state();

        // Ledger 2: one tx
        let mut pool = TxPool::new();
        submit_payment(&mut pool, 1, 1_000_000);
        let close1 = close_ledger(&prev, &mut state, &mut pool, 1000, true);
        assert_eq!(close1.header.sequence, 2);

        // Ledger 3: another tx
        let mut pool = TxPool::new();
        submit_payment(&mut pool, 2, 2_000_000);
        let close2 = close_ledger(&close1.header, &mut state, &mut pool, 2000, true);
        assert_eq!(close2.header.sequence, 3);
        assert_eq!(close2.header.parent_hash, close1.header.hash);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.sequence, 3);
    }

    #[test]
    fn test_tx_hash_changes_with_different_txs() {
        let (prev, mut state1) = initial_state();
        let (_, mut state2) = initial_state();

        let mut pool1 = TxPool::new();
        submit_payment(&mut pool1, 1, 1_000_000);
        let close1 = close_ledger(&prev, &mut state1, &mut pool1, 1000, true);

        let mut pool2 = TxPool::new();
        submit_payment(&mut pool2, 1, 9_000_000); // different amount → different tx hash
        let close2 = close_ledger(&prev, &mut state2, &mut pool2, 1000, true);

        assert_ne!(
            close1.header.transaction_hash, close2.header.transaction_hash,
            "different tx sets must produce different tx hashes"
        );
    }

    #[test]
    fn test_header_hash_is_nonzero() {
        let (prev, mut state) = initial_state();
        let mut pool = TxPool::new();
        submit_payment(&mut pool, 1, 1_000_000);
        let result = close_ledger(&prev, &mut state, &mut pool, 1000, true);
        assert_ne!(result.header.hash, [0u8; 32]);
    }

    #[test]
    fn test_close_time_resolution_tightens_after_agreement() {
        assert_eq!(next_close_time_resolution(30, true, 8), 20);
        assert_eq!(next_close_time_resolution(20, true, 16), 10);
    }

    #[test]
    fn test_close_time_resolution_relaxes_after_disagreement() {
        assert_eq!(next_close_time_resolution(30, false, 2), 60);
        assert_eq!(next_close_time_resolution(90, false, 2), 120);
    }

    #[test]
    fn test_close_flags_set_when_no_consensus() {
        let (prev, mut state) = initial_state();
        let mut pool = TxPool::new();
        // Close with consensus → flags should be 0
        let r1 = close_ledger(&prev, &mut state, &mut pool, 1000, true);
        assert_eq!(r1.header.close_flags, 0);
        // Close without consensus → flags should have CLOSE_TIME_NO_CONSENSUS
        let mut pool2 = TxPool::new();
        let r2 = close_ledger(&r1.header, &mut state, &mut pool2, 2000, false);
        assert_eq!(
            r2.header.close_flags & CLOSE_TIME_NO_CONSENSUS,
            CLOSE_TIME_NO_CONSENSUS
        );
    }

    #[test]
    fn test_effective_close_time_advances_past_parent() {
        assert_eq!(effective_close_time(1000, 10, 1004), 1005);
        assert_eq!(effective_close_time(1015, 10, 1004), 1020);
    }

    // ── Multi-pass close loop tests ─────────────────────────────────────

    fn sign_payment_blob(seq: u32, amount: u64, fee: u64) -> (Vec<u8>, [u8; 32]) {
        let kp = genesis_kp();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(amount))
            .fee(fee)
            .sequence(seq)
            .sign(&kp)
            .unwrap();
        // txID = SHA-512-Half(TXN\0 + blob)
        let mut data = Vec::with_capacity(4 + signed.blob.len());
        data.extend_from_slice(&crate::transaction::serialize::PREFIX_TX_ID);
        data.extend_from_slice(&signed.blob);
        let hash = sha512_first_half(&data);
        (signed.blob, hash)
    }

    fn pool_with_txs(txs: Vec<(Vec<u8>, [u8; 32])>) -> TxPool {
        let mut pool = TxPool::new();
        for (blob, hash) in txs {
            let parsed = parse_blob(&blob).unwrap();
            pool.insert(hash, blob, &parsed);
        }
        pool
    }

    #[test]
    fn close_single_payment_applies() {
        let (header, mut state) = initial_state();
        let tx = sign_payment_blob(1, 1_000_000, 12);
        let mut pool = pool_with_txs(vec![tx]);

        let result = close_ledger(&header, &mut state, &mut pool, 100, true);
        assert_eq!(result.applied_count, 1);
        assert_eq!(result.failed_count, 0);
        assert_eq!(result.skipped_count, 0);
        assert_eq!(result.header.sequence, 2);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 100_000_000_000_000_000 - 1_000_000 - 12);
    }

    #[test]
    fn close_chained_txs_land_across_passes() {
        // Tx at seq=2 depends on seq=1 completing first.
        // In canonical ordering, seq=2 may come before seq=1.
        // Multi-pass should handle this: seq=1 applies, then seq=2 retries and applies.
        let (header, mut state) = initial_state();
        let tx1 = sign_payment_blob(1, 1_000_000, 12);
        let tx2 = sign_payment_blob(2, 2_000_000, 12);
        let mut pool = pool_with_txs(vec![tx1, tx2]);

        let result = close_ledger(&header, &mut state, &mut pool, 100, true);
        assert_eq!(result.applied_count, 2);
        assert_eq!(result.skipped_count, 0);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 100_000_000_000_000_000 - 3_000_000 - 24);
        assert_eq!(sender.sequence, 3);
    }

    #[test]
    fn close_wrong_sequence_not_applied_no_fee() {
        // Tx at seq=99 — account is at seq=1. Should be retried then skipped.
        let (header, mut state) = initial_state();
        let tx = sign_payment_blob(99, 1_000_000, 12);
        let mut pool = pool_with_txs(vec![tx]);

        let result = close_ledger(&header, &mut state, &mut pool, 100, true);
        assert_eq!(result.applied_count, 0);
        // Not applied — no fee consumed, no sequence bump
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 100_000_000_000_000_000);
        assert_eq!(sender.sequence, 1);
    }

    #[test]
    fn close_canonical_ordering_is_deterministic() {
        // Two different pool insertion orders should produce the same close result.
        let (header1, mut state1) = initial_state();
        let (header2, mut state2) = initial_state();

        let tx_a = sign_payment_blob(1, 1_000_000, 12);
        let tx_b = sign_payment_blob(2, 2_000_000, 15);

        // Order 1: a then b
        let mut pool1 = pool_with_txs(vec![tx_a.clone(), tx_b.clone()]);
        // Order 2: b then a
        let mut pool2 = pool_with_txs(vec![tx_b, tx_a]);

        let r1 = close_ledger(&header1, &mut state1, &mut pool1, 100, true);
        let r2 = close_ledger(&header2, &mut state2, &mut pool2, 100, true);

        // Both should produce the same ledger hash
        assert_eq!(r1.header.hash, r2.header.hash);
        assert_eq!(r1.applied_count, r2.applied_count);
    }

    #[test]
    fn close_fees_reduce_total_coins() {
        let (header, mut state) = initial_state();
        let tx = sign_payment_blob(1, 1_000_000, 100);
        let mut pool = pool_with_txs(vec![tx]);

        let result = close_ledger(&header, &mut state, &mut pool, 100, true);
        // Fee of 100 drops should be burned from total_coins
        assert_eq!(result.header.total_coins, header.total_coins - 100);
    }

    #[test]
    fn test_replay_ledger_fee_matches_close() {
        // Close a ledger with one payment, then replay it.
        // The replay must produce the same total_coins and hash as close.
        let (prev, mut close_state) = initial_state();
        let mut pool = TxPool::new();
        submit_payment(&mut pool, 1, 5_000_000);

        let close_result = close_ledger(&prev, &mut close_state, &mut pool, 1000, true);
        assert_eq!(close_result.applied_count, 1);

        // Extract tx blobs + metadata for replay
        let tx_blobs_with_meta: Vec<(Vec<u8>, Vec<u8>)> = close_result
            .tx_records
            .iter()
            .map(|r| (r.blob.clone(), r.meta.clone()))
            .collect();

        // Reset state to parent and replay
        let (_, mut replay_state) = initial_state();
        let replay_result = replay_ledger(
            &prev,
            &mut replay_state,
            tx_blobs_with_meta,
            &close_result.header,
            false,
        );

        // total_coins must match — this catches double-counting
        assert_eq!(
            replay_result.header.total_coins,
            close_result.header.total_coins,
            "replay total_coins={} != close total_coins={} (diff={})",
            replay_result.header.total_coins,
            close_result.header.total_coins,
            replay_result.header.total_coins as i128 - close_result.header.total_coins as i128,
        );

        // applied count should match
        assert_eq!(replay_result.applied_count, close_result.applied_count);

        // account_hash must match — close_ledger and replay_ledger must
        // produce byte-identical state for the same tx set. Previously this
        // silently diverged because close_ledger skipped the
        // stamp_touched_previous_fields post-apply step. See project memory
        // `project_close_vs_replay_hash_diverge` for the 2026-04-11 finding.
        assert_eq!(
            replay_result.header.account_hash,
            close_result.header.account_hash,
            "replay account_hash {} != close account_hash {}",
            hex::encode_upper(replay_result.header.account_hash),
            hex::encode_upper(close_result.header.account_hash),
        );
    }

    #[test]
    fn test_close_creates_short_skip_list() {
        let (prev, mut state) = initial_state();
        let mut pool = TxPool::new();

        let _result = close_ledger(&prev, &mut state, &mut pool, 1000, true);

        let key = crate::ledger::keylet::skip().key;
        let raw = state
            .get_raw_owned(&key)
            .expect("short skip list should exist");
        let sle = crate::ledger::sle::SLE::from_raw(key, raw).expect("valid skip list SLE");

        assert_eq!(sle.get_field_u32(2, 27), Some(prev.sequence));
        assert_eq!(sle.get_field_u32(2, 26), None);
        assert_eq!(sle.get_field_vl(19, 1), None);
        let hashes = parse_skip_list_hashes(&sle);
        assert_eq!(hashes, vec![prev.hash]);
    }

    #[test]
    fn test_close_migrates_legacy_short_skip_list_encoding() {
        let (prev, mut state) = initial_state();
        let short_key = crate::ledger::keylet::skip().key;

        let mut legacy = Vec::new();
        crate::ledger::meta::write_field_header(&mut legacy, 1, 1);
        legacy.extend_from_slice(&0x0068u16.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut legacy, 2, 2);
        legacy.extend_from_slice(&0u32.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut legacy, 2, 26);
        legacy.extend_from_slice(&1u32.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut legacy, 2, 27);
        legacy.extend_from_slice(&0u32.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut legacy, 19, 1);
        crate::ledger::meta::encode_vl_length(&mut legacy, 32);
        legacy.extend_from_slice(&[0x11; 32]);
        state.insert_raw(short_key, legacy);

        let mut pool = TxPool::new();
        let _result = close_ledger(&prev, &mut state, &mut pool, 1000, true);

        let raw = state
            .get_raw_owned(&short_key)
            .expect("short skip list should exist");
        let sle = crate::ledger::sle::SLE::from_raw(short_key, raw).expect("valid skip list SLE");

        assert_eq!(sle.get_field_u32(2, 26), Some(1));
        assert_eq!(sle.get_field_u32(2, 27), Some(prev.sequence));
        assert_eq!(sle.get_field_vl(19, 1), None);
        let hashes = parse_skip_list_hashes(&sle);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], [0x11; 32]);
        assert_eq!(hashes[1], prev.hash);
    }

    fn parsed_field(type_code: u16, field_code: u16, data: Vec<u8>) -> crate::ledger::meta::ParsedField {
        crate::ledger::meta::ParsedField {
            type_code,
            field_code,
            data,
        }
    }

    #[test]
    fn authoritative_replay_created_directory_adds_missing_offer_index() {
        let mut state = crate::ledger::LedgerState::new();
        let account = [0x11; 20];
        let book_root = {
            let mut key = [0x44; 32];
            key[24..32].copy_from_slice(&0u64.to_be_bytes());
            key
        };
        let dir_key = crate::ledger::Key(book_root);
        let dir = crate::ledger::DirectoryNode {
            key: dir_key.0,
            root_index: dir_key.0,
            indexes: Vec::new(),
            index_next: 0,
            index_previous: 0,
            owner: None,
            exchange_rate: Some(7),
            taker_pays_currency: Some([0xAA; 20]),
            taker_pays_issuer: Some([0xBB; 20]),
            taker_gets_currency: Some([0xCC; 20]),
            taker_gets_issuer: Some([0xDD; 20]),
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        };
        state.insert_raw(dir_key, dir.encode());

        let offer_key = crate::ledger::Key([0x99; 32]);
        let tx_hash = [0x77; 32];
        let nodes = vec![
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Created,
                entry_type: 0x006f,
                ledger_index: offer_key.0,
                fields: vec![
                    parsed_field(8, 1, account.to_vec()),
                    parsed_field(3, 4, 0u64.to_be_bytes().to_vec()),
                    parsed_field(5, 16, book_root.to_vec()),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Created,
                entry_type: 0x0064,
                ledger_index: dir_key.0,
                fields: vec![
                    parsed_field(3, 6, 7u64.to_be_bytes().to_vec()),
                    parsed_field(5, 8, book_root.to_vec()),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
        ];

        apply_authoritative_validated_tx_metadata(&mut state, &tx_hash, 55, &nodes, &[]);

        let raw = state.get_raw_owned(&dir_key).expect("directory must exist");
        let dir = crate::ledger::DirectoryNode::decode(&raw, dir_key.0).expect("valid directory");
        assert_eq!(dir.indexes, vec![offer_key.0]);
    }

    #[test]
    fn authoritative_replay_created_directory_rebuild_ignores_stale_local_book_fields() {
        let mut state = crate::ledger::LedgerState::new();
        let account = [0x31; 20];
        let pays_currency = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let gets_currency = crate::transaction::amount::Currency::from_code("EUR").unwrap();
        let book_root = {
            let mut key = [0x74; 32];
            key[24..32].copy_from_slice(&0u64.to_be_bytes());
            key
        };
        let dir_key = crate::ledger::Key(book_root);
        let stale_dir = crate::ledger::DirectoryNode {
            key: dir_key.0,
            root_index: dir_key.0,
            indexes: Vec::new(),
            index_next: 0,
            index_previous: 0,
            owner: None,
            exchange_rate: Some(7),
            taker_pays_currency: Some([0xEE; 20]),
            taker_pays_issuer: Some([0xED; 20]),
            taker_gets_currency: Some([0xEC; 20]),
            taker_gets_issuer: Some([0xEB; 20]),
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        };
        state.insert_raw(dir_key, stale_dir.encode());

        let offer_key = crate::ledger::Key([0x98; 32]);
        let tx_hash = [0x79; 32];
        let nodes = vec![
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Created,
                entry_type: 0x006f,
                ledger_index: offer_key.0,
                fields: vec![
                    parsed_field(8, 1, account.to_vec()),
                    parsed_field(3, 4, 0u64.to_be_bytes().to_vec()),
                    parsed_field(5, 16, book_root.to_vec()),
                    parsed_field(
                        6,
                        4,
                        crate::transaction::amount::Amount::Iou {
                            value: crate::transaction::amount::IouValue::from_f64(1.0),
                            currency: pays_currency.clone(),
                            issuer: [0x02; 20],
                        }
                        .to_bytes(),
                    ),
                    parsed_field(
                        6,
                        5,
                        crate::transaction::amount::Amount::Iou {
                            value: crate::transaction::amount::IouValue::from_f64(2.0),
                            currency: gets_currency.clone(),
                            issuer: [0x04; 20],
                        }
                        .to_bytes(),
                    ),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Created,
                entry_type: 0x0064,
                ledger_index: dir_key.0,
                fields: vec![
                    parsed_field(3, 6, 7u64.to_be_bytes().to_vec()),
                    parsed_field(5, 8, book_root.to_vec()),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
        ];

        apply_authoritative_validated_tx_metadata(&mut state, &tx_hash, 55, &nodes, &[]);

        let raw = state.get_raw_owned(&dir_key).expect("directory must exist");
        let dir = crate::ledger::DirectoryNode::decode(&raw, dir_key.0).expect("valid directory");
        assert_eq!(dir.taker_pays_currency, Some(pays_currency.code));
        assert_eq!(dir.taker_pays_issuer, Some([0x02; 20]));
        assert_eq!(dir.taker_gets_currency, Some(gets_currency.code));
        assert_eq!(dir.taker_gets_issuer, Some([0x04; 20]));
    }

    #[test]
    fn authoritative_replay_modified_directory_applies_offer_swap_delta() {
        let mut state = crate::ledger::LedgerState::new();
        let account = [0x22; 20];
        let book_root = {
            let mut key = [0x55; 32];
            key[24..32].copy_from_slice(&0u64.to_be_bytes());
            key
        };
        let dir_key = crate::ledger::Key(book_root);
        let deleted_offer = [0x10; 32];
        let created_offer = [0x20; 32];
        let dir = crate::ledger::DirectoryNode {
            key: dir_key.0,
            root_index: dir_key.0,
            indexes: vec![deleted_offer],
            index_next: 0,
            index_previous: 0,
            owner: None,
            exchange_rate: Some(9),
            taker_pays_currency: Some([0x01; 20]),
            taker_pays_issuer: Some([0x02; 20]),
            taker_gets_currency: Some([0x03; 20]),
            taker_gets_issuer: Some([0x04; 20]),
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        };
        state.insert_raw(dir_key, dir.encode());

        let tx_hash = [0x88; 32];
        let nodes = vec![
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Deleted,
                entry_type: 0x006f,
                ledger_index: deleted_offer,
                fields: vec![
                    parsed_field(8, 1, account.to_vec()),
                    parsed_field(3, 4, 0u64.to_be_bytes().to_vec()),
                    parsed_field(5, 16, book_root.to_vec()),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Created,
                entry_type: 0x006f,
                ledger_index: created_offer,
                fields: vec![
                    parsed_field(8, 1, account.to_vec()),
                    parsed_field(3, 4, 0u64.to_be_bytes().to_vec()),
                    parsed_field(5, 16, book_root.to_vec()),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Modified,
                entry_type: 0x0064,
                ledger_index: dir_key.0,
                fields: vec![
                    parsed_field(3, 6, 9u64.to_be_bytes().to_vec()),
                    parsed_field(5, 8, book_root.to_vec()),
                    parsed_field(17, 1, [0x01; 20].to_vec()),
                    parsed_field(17, 2, [0x02; 20].to_vec()),
                    parsed_field(17, 3, [0x03; 20].to_vec()),
                    parsed_field(17, 4, [0x04; 20].to_vec()),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
        ];

        apply_authoritative_validated_tx_metadata(&mut state, &tx_hash, 56, &nodes, &[]);

        let raw = state.get_raw_owned(&dir_key).expect("directory must exist");
        let dir = crate::ledger::DirectoryNode::decode(&raw, dir_key.0).expect("valid directory");
        assert_eq!(dir.indexes, vec![created_offer]);
    }

    #[test]
    fn authoritative_replay_modified_directory_overrides_stale_book_fields() {
        let mut state = crate::ledger::LedgerState::new();
        let account = [0x42; 20];
        let pays_currency = crate::transaction::amount::Currency::from_code("GBP").unwrap();
        let gets_currency = crate::transaction::amount::Currency::from_code("CAD").unwrap();
        let book_root = {
            let mut key = [0x84; 32];
            key[24..32].copy_from_slice(&0u64.to_be_bytes());
            key
        };
        let dir_key = crate::ledger::Key(book_root);
        let dir = crate::ledger::DirectoryNode {
            key: dir_key.0,
            root_index: dir_key.0,
            indexes: Vec::new(),
            index_next: 0,
            index_previous: 0,
            owner: None,
            exchange_rate: Some(9),
            taker_pays_currency: Some([0xEE; 20]),
            taker_pays_issuer: Some([0xED; 20]),
            taker_gets_currency: Some([0xEC; 20]),
            taker_gets_issuer: Some([0xEB; 20]),
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        };
        state.insert_raw(dir_key, dir.encode());

        let tx_hash = [0x89; 32];
        let nodes = vec![
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Created,
                entry_type: 0x006f,
                ledger_index: [0xC4; 32],
                fields: vec![
                    parsed_field(8, 1, account.to_vec()),
                    parsed_field(3, 4, 0u64.to_be_bytes().to_vec()),
                    parsed_field(5, 16, book_root.to_vec()),
                    parsed_field(
                        6,
                        4,
                        crate::transaction::amount::Amount::Iou {
                            value: crate::transaction::amount::IouValue::from_f64(3.0),
                            currency: pays_currency.clone(),
                            issuer: [0x02; 20],
                        }
                        .to_bytes(),
                    ),
                    parsed_field(
                        6,
                        5,
                        crate::transaction::amount::Amount::Iou {
                            value: crate::transaction::amount::IouValue::from_f64(4.0),
                            currency: gets_currency.clone(),
                            issuer: [0x04; 20],
                        }
                        .to_bytes(),
                    ),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Modified,
                entry_type: 0x0064,
                ledger_index: dir_key.0,
                fields: vec![
                    parsed_field(3, 6, 9u64.to_be_bytes().to_vec()),
                    parsed_field(5, 8, book_root.to_vec()),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
        ];

        apply_authoritative_validated_tx_metadata(&mut state, &tx_hash, 56, &nodes, &[]);

        let raw = state.get_raw_owned(&dir_key).expect("directory must exist");
        let dir = crate::ledger::DirectoryNode::decode(&raw, dir_key.0).expect("valid directory");
        assert_eq!(dir.taker_pays_currency, Some(pays_currency.code));
        assert_eq!(dir.taker_pays_issuer, Some([0x02; 20]));
        assert_eq!(dir.taker_gets_currency, Some(gets_currency.code));
        assert_eq!(dir.taker_gets_issuer, Some([0x04; 20]));
    }

    #[test]
    fn authoritative_replay_modified_directory_uses_pre_tx_base_before_live_raw() {
        let mut state = crate::ledger::LedgerState::new();
        let book_root = {
            let mut key = [0x94; 32];
            key[24..32].copy_from_slice(&0u64.to_be_bytes());
            key
        };
        let dir_key = crate::ledger::Key(book_root);
        let before_dir = crate::ledger::DirectoryNode {
            key: dir_key.0,
            root_index: dir_key.0,
            indexes: Vec::new(),
            index_next: 0,
            index_previous: 0,
            owner: None,
            exchange_rate: Some(9),
            taker_pays_currency: Some([0x01; 20]),
            taker_pays_issuer: Some([0x02; 20]),
            taker_gets_currency: Some([0x03; 20]),
            taker_gets_issuer: Some([0x04; 20]),
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        };
        let live_dir = crate::ledger::DirectoryNode {
            key: dir_key.0,
            root_index: dir_key.0,
            indexes: Vec::new(),
            index_next: 0,
            index_previous: 0,
            owner: None,
            exchange_rate: Some(9),
            taker_pays_currency: Some([0xEE; 20]),
            taker_pays_issuer: Some([0xED; 20]),
            taker_gets_currency: Some([0xEC; 20]),
            taker_gets_issuer: Some([0xEB; 20]),
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        };
        let before_raw = before_dir.encode();
        state.insert_raw(dir_key, live_dir.encode());

        let tx_hash = [0x99; 32];
        let nodes = vec![crate::ledger::meta::AffectedNode {
            action: crate::ledger::meta::Action::Modified,
            entry_type: 0x0064,
            ledger_index: dir_key.0,
            fields: vec![
                parsed_field(3, 6, 9u64.to_be_bytes().to_vec()),
                parsed_field(5, 8, book_root.to_vec()),
            ],
            previous_fields: vec![],
            prev_txn_id: None,
            prev_txn_lgrseq: None,
        }];

        apply_authoritative_validated_tx_metadata(
            &mut state,
            &tx_hash,
            57,
            &nodes,
            &[(dir_key, Some(before_raw))],
        );

        let raw = state.get_raw_owned(&dir_key).expect("directory must exist");
        let dir = crate::ledger::DirectoryNode::decode(&raw, dir_key.0).expect("valid directory");
        assert_eq!(dir.taker_pays_currency, Some([0x01; 20]));
        assert_eq!(dir.taker_pays_issuer, Some([0x02; 20]));
        assert_eq!(dir.taker_gets_currency, Some([0x03; 20]));
        assert_eq!(dir.taker_gets_issuer, Some([0x04; 20]));
    }

    #[test]
    fn authoritative_replay_created_trustline_adds_both_owner_directory_indexes() {
        let mut state = crate::ledger::LedgerState::new();
        let low = [0x10; 20];
        let high = [0x20; 20];
        let currency = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let trustline_key = crate::ledger::trustline::shamap_key(&low, &high, &currency);
        let low_root = crate::ledger::directory::owner_dir_key(&low);
        let high_root = crate::ledger::directory::owner_dir_key(&high);
        let low_page = crate::ledger::directory::page_key(&low_root.0, 2);
        let high_page = crate::ledger::directory::page_key(&high_root.0, 12);

        state.insert_raw(
            low_page,
            crate::ledger::DirectoryNode {
                key: low_page.0,
                root_index: low_root.0,
                indexes: Vec::new(),
                index_next: 0,
                index_previous: 0,
                owner: Some(low),
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
            }
            .encode(),
        );
        state.insert_raw(
            high_page,
            crate::ledger::DirectoryNode {
                key: high_page.0,
                root_index: high_root.0,
                indexes: Vec::new(),
                index_next: 0,
                index_previous: 12,
                owner: Some(high),
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
            }
            .encode(),
        );

        let tx_hash = [0xAB; 32];
        let nodes = vec![
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Created,
                entry_type: 0x0072,
                ledger_index: trustline_key.0,
                fields: vec![
                    parsed_field(3, 7, 2u64.to_be_bytes().to_vec()),
                    parsed_field(3, 8, 12u64.to_be_bytes().to_vec()),
                    parsed_field(
                        6,
                        6,
                        crate::transaction::amount::Amount::Iou {
                            value: crate::transaction::amount::IouValue::from_f64(1.0),
                            currency: currency.clone(),
                            issuer: low,
                        }
                        .to_bytes(),
                    ),
                    parsed_field(
                        6,
                        7,
                        crate::transaction::amount::Amount::Iou {
                            value: crate::transaction::amount::IouValue::from_f64(1.0),
                            currency: currency.clone(),
                            issuer: high,
                        }
                        .to_bytes(),
                    ),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Modified,
                entry_type: 0x0064,
                ledger_index: low_page.0,
                fields: vec![
                    parsed_field(5, 8, low_root.0.to_vec()),
                    parsed_field(8, 2, low.to_vec()),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Modified,
                entry_type: 0x0064,
                ledger_index: high_page.0,
                fields: vec![
                    parsed_field(5, 8, high_root.0.to_vec()),
                    parsed_field(8, 2, high.to_vec()),
                    parsed_field(3, 2, 12u64.to_be_bytes().to_vec()),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
        ];

        apply_authoritative_validated_tx_metadata(&mut state, &tx_hash, 58, &nodes, &[]);

        let low_raw = state.get_raw_owned(&low_page).expect("low directory must exist");
        let low_dir =
            crate::ledger::DirectoryNode::decode(&low_raw, low_page.0).expect("valid low dir");
        assert!(low_dir.indexes.iter().any(|index| index == &trustline_key.0));

        let high_raw = state.get_raw_owned(&high_page).expect("high directory must exist");
        let high_dir =
            crate::ledger::DirectoryNode::decode(&high_raw, high_page.0).expect("valid high dir");
        assert!(high_dir.indexes.iter().any(|index| index == &trustline_key.0));
    }

    #[test]
    fn authoritative_replay_modified_offer_page_move_removes_old_directory_index() {
        let mut state = crate::ledger::LedgerState::new();
        let owner = [0x33; 20];
        let book_root = {
            let mut key = [0x66; 32];
            key[24..32].copy_from_slice(&0u64.to_be_bytes());
            key
        };
        let old_dir_key = crate::ledger::Key(book_root);
        let new_dir_key = crate::ledger::directory::page_key(&book_root, 1);
        let offer_key = [0xC2; 32];

        let mut old_dir = crate::ledger::DirectoryNode {
            key: old_dir_key.0,
            root_index: old_dir_key.0,
            indexes: vec![offer_key],
            index_next: 1,
            index_previous: 0,
            owner: None,
            exchange_rate: Some(0x1122),
            taker_pays_currency: Some([0x01; 20]),
            taker_pays_issuer: Some([0x02; 20]),
            taker_gets_currency: Some([0x03; 20]),
            taker_gets_issuer: Some([0x04; 20]),
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: true,
            has_index_previous: false,
            raw_sle: None,
        };
        old_dir.raw_sle = Some(old_dir.encode());
        state.insert_raw(old_dir_key, old_dir.encode());

        let mut new_dir = crate::ledger::DirectoryNode {
            key: new_dir_key.0,
            root_index: old_dir_key.0,
            indexes: Vec::new(),
            index_next: 0,
            index_previous: 0,
            owner: None,
            exchange_rate: Some(0x1122),
            taker_pays_currency: Some([0x01; 20]),
            taker_pays_issuer: Some([0x02; 20]),
            taker_gets_currency: Some([0x03; 20]),
            taker_gets_issuer: Some([0x04; 20]),
            nftoken_id: None,
            domain_id: None,
            previous_txn_id: None,
            previous_txn_lgr_seq: None,
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        };
        new_dir.raw_sle = Some(new_dir.encode());
        state.insert_raw(new_dir_key, new_dir.encode());

        let tx_hash = [0x99; 32];
        let nodes = vec![
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Modified,
                entry_type: 0x006f,
                ledger_index: offer_key,
                fields: vec![
                    parsed_field(8, 1, owner.to_vec()),
                    parsed_field(3, 4, 0u64.to_be_bytes().to_vec()),
                    parsed_field(5, 16, book_root.to_vec()),
                    parsed_field(3, 3, 1u64.to_be_bytes().to_vec()),
                ],
                previous_fields: vec![parsed_field(3, 3, 0u64.to_be_bytes().to_vec())],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Modified,
                entry_type: 0x0064,
                ledger_index: old_dir_key.0,
                fields: vec![
                    parsed_field(3, 1, 1u64.to_be_bytes().to_vec()),
                    parsed_field(3, 6, 0x1122u64.to_be_bytes().to_vec()),
                    parsed_field(5, 8, book_root.to_vec()),
                    parsed_field(17, 1, vec![0x01; 20]),
                    parsed_field(17, 2, vec![0x02; 20]),
                    parsed_field(17, 3, vec![0x03; 20]),
                    parsed_field(17, 4, vec![0x04; 20]),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Modified,
                entry_type: 0x0064,
                ledger_index: new_dir_key.0,
                fields: vec![
                    parsed_field(3, 6, 0x1122u64.to_be_bytes().to_vec()),
                    parsed_field(5, 8, book_root.to_vec()),
                    parsed_field(17, 1, vec![0x01; 20]),
                    parsed_field(17, 2, vec![0x02; 20]),
                    parsed_field(17, 3, vec![0x03; 20]),
                    parsed_field(17, 4, vec![0x04; 20]),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
        ];

        apply_authoritative_validated_tx_metadata(&mut state, &tx_hash, 57, &nodes, &[]);

        let old_raw = state
            .get_raw_owned(&old_dir_key)
            .expect("old directory must exist");
        let old_dir =
            crate::ledger::DirectoryNode::decode(&old_raw, old_dir_key.0).expect("valid old dir");
        assert!(old_dir.indexes.is_empty());

        let new_raw = state
            .get_raw_owned(&new_dir_key)
            .expect("new directory must exist");
        let new_dir =
            crate::ledger::DirectoryNode::decode(&new_raw, new_dir_key.0).expect("valid new dir");
        assert_eq!(new_dir.indexes, vec![offer_key]);
    }

    #[test]
    fn authoritative_replay_deleted_ticket_removes_owner_directory_index() {
        let mut state = crate::ledger::LedgerState::new();
        let owner = [0x44; 20];
        let owner_root = crate::ledger::directory::owner_dir_key(&owner);
        let ticket_key = [0xAB; 32];

        let mut owner_dir = crate::ledger::DirectoryNode {
            key: owner_root.0,
            root_index: owner_root.0,
            indexes: vec![ticket_key],
            index_next: 0,
            index_previous: 0,
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
            has_index_next: false,
            has_index_previous: false,
            raw_sle: None,
        };
        owner_dir.raw_sle = Some(owner_dir.encode());
        state.insert_raw(owner_root, owner_dir.encode());

        let tx_hash = [0x55; 32];
        let nodes = vec![
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Deleted,
                entry_type: 0x0054,
                ledger_index: ticket_key,
                fields: vec![
                    parsed_field(8, 1, owner.to_vec()),
                    parsed_field(3, 4, 0u64.to_be_bytes().to_vec()),
                ],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
            crate::ledger::meta::AffectedNode {
                action: crate::ledger::meta::Action::Modified,
                entry_type: 0x0064,
                ledger_index: owner_root.0,
                fields: vec![parsed_field(5, 8, owner_root.0.to_vec())],
                previous_fields: vec![],
                prev_txn_id: None,
                prev_txn_lgrseq: None,
            },
        ];

        apply_authoritative_validated_tx_metadata(&mut state, &tx_hash, 58, &nodes, &[]);

        let raw = state
            .get_raw_owned(&owner_root)
            .expect("owner directory must exist");
        let dir =
            crate::ledger::DirectoryNode::decode(&raw, owner_root.0).expect("valid owner dir");
        assert!(dir.indexes.is_empty());
    }

    /// Diff the state_maps produced by close_ledger vs replay_ledger for
    /// the same Payment. Prints keys-only-in-A / keys-only-in-B / common
    /// keys with byte diffs, plus a hex side-by-side of the first common
    /// divergent key. Non-asserting — this is a localization tool.
    #[test]
    fn diag_close_vs_replay_state_diff() {
        use std::collections::BTreeMap;

        let (prev, mut close_state) = initial_state();
        let mut pool = TxPool::new();
        submit_payment(&mut pool, 1, 5_000_000);
        let close_result = close_ledger(&prev, &mut close_state, &mut pool, 1000, true);

        let tx_blobs: Vec<(Vec<u8>, Vec<u8>)> = close_result
            .tx_records
            .iter()
            .map(|r| (r.blob.clone(), r.meta.clone()))
            .collect();

        let (_, mut replay_state) = initial_state();
        let _replay_result = replay_ledger(
            &prev,
            &mut replay_state,
            tx_blobs,
            &close_result.header,
            false,
        );

        let close_map: BTreeMap<[u8; 32], Vec<u8>> = close_state
            .iter_raw_entries()
            .iter()
            .map(|(k, b)| (k.0, b.to_vec()))
            .collect();
        let replay_map: BTreeMap<[u8; 32], Vec<u8>> = replay_state
            .iter_raw_entries()
            .iter()
            .map(|(k, b)| (k.0, b.to_vec()))
            .collect();

        eprintln!("close state_map: {} entries", close_map.len());
        eprintln!("replay state_map: {} entries", replay_map.len());

        let only_close: Vec<&[u8; 32]> = close_map
            .keys()
            .filter(|k| !replay_map.contains_key(*k))
            .collect();
        let only_replay: Vec<&[u8; 32]> = replay_map
            .keys()
            .filter(|k| !close_map.contains_key(*k))
            .collect();
        let common_diff: Vec<(&[u8; 32], &Vec<u8>, &Vec<u8>)> = close_map
            .iter()
            .filter_map(|(k, a)| {
                replay_map
                    .get(k)
                    .and_then(|b| if a != b { Some((k, a, b)) } else { None })
            })
            .collect();

        eprintln!("only in close:  {}", only_close.len());
        for k in &only_close {
            eprintln!("  {}", hex::encode_upper(**k));
        }
        eprintln!("only in replay: {}", only_replay.len());
        for k in &only_replay {
            eprintln!("  {}", hex::encode_upper(**k));
        }
        eprintln!("common with byte diffs: {}", common_diff.len());
        for (k, a, b) in common_diff.iter().take(3) {
            eprintln!("  key {}", hex::encode_upper(**k));
            eprintln!("    close_len={} replay_len={}", a.len(), b.len());
            eprintln!("    close  = {}", hex::encode_upper(a));
            eprintln!("    replay = {}", hex::encode_upper(b));
            // Byte-level positional diff
            let min_len = a.len().min(b.len());
            let mut first_diff = None;
            for i in 0..min_len {
                if a[i] != b[i] {
                    first_diff = Some(i);
                    break;
                }
            }
            if let Some(pos) = first_diff {
                let end = (pos + 8).min(min_len);
                eprintln!(
                    "    first diff at byte {}: close={:02X} replay={:02X} (context close={} replay={})",
                    pos, a[pos], b[pos],
                    hex::encode_upper(&a[pos..end]),
                    hex::encode_upper(&b[pos..end]),
                );
            } else if a.len() != b.len() {
                eprintln!("    length differs but common prefix is identical");
            }
        }
    }

    /// Permanent diagnostic: prints close_ledger, replay_ledger (from
    /// initial_state), and replay_ledger (from insert_raw-seeded state)
    /// hashes for a single Payment. As of 2026-04-11, `close_hash` does
    /// NOT equal `ref_hash` / `harness_hash` — this is a pre-existing
    /// xLedgRS internal inconsistency (see project memory
    /// `project_close_vs_replay_hash_diverge`). Intentionally non-asserting
    /// so it serves as a regression canary: if someone unifies the two
    /// paths, the printed values will match.
    #[test]
    fn test_close_ledger_vs_replay_ledger_hash_divergence() {
        let (prev, mut close_state) = initial_state();

        // Snapshot pre-close state map via raw bytes (this is what the harness
        // will see in a forensic bundle).
        let prestate: std::collections::HashMap<[u8; 32], Vec<u8>> = close_state
            .iter_raw_entries()
            .iter()
            .map(|(k, b)| (k.0, b.to_vec()))
            .collect();

        let mut pool = TxPool::new();
        submit_payment(&mut pool, 1, 5_000_000);
        let close_result = close_ledger(&prev, &mut close_state, &mut pool, 1000, true);
        let close_hash = close_result.header.account_hash;

        let tx_blobs: Vec<(Vec<u8>, Vec<u8>)> = close_result
            .tx_records
            .iter()
            .map(|r| (r.blob.clone(), r.meta.clone()))
            .collect();

        // Path A: replay from initial_state (same insert_account seed)
        let (_, mut ref_state) = initial_state();
        let ref_result = replay_ledger(
            &prev,
            &mut ref_state,
            tx_blobs.clone(),
            &close_result.header,
            false,
        );
        let ref_hash = ref_result.header.account_hash;

        // Path B: replay from fresh state seeded only via insert_raw
        let mut harness_state = LedgerState::new();
        for (k, bytes) in &prestate {
            harness_state.insert_raw(crate::ledger::Key(*k), bytes.clone());
        }
        let harness_result = replay_ledger(
            &prev,
            &mut harness_state,
            tx_blobs,
            &close_result.header,
            false,
        );
        let harness_hash = harness_result.header.account_hash;

        eprintln!("close_hash   = {}", hex::encode_upper(close_hash));
        eprintln!("ref_hash     = {}", hex::encode_upper(ref_hash));
        eprintln!("harness_hash = {}", hex::encode_upper(harness_hash));
        eprintln!("prestate_keys= {}", prestate.len());
    }

    /// Synthetic Phase 1 validator: capture a forensic bundle from a close,
    /// reload it via the loader functions, and verify that running
    /// replay_ledger against the reloaded inputs reproduces the original
    /// account_hash. This exercises the full bundle I/O + replay_fixture
    /// seed path without touching the follower or a live rippled endpoint.
    #[test]
    fn test_forensic_bundle_round_trip() {
        use std::collections::HashMap;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let (prev, mut state) = initial_state();

            // Snapshot the full pre-close state map. For this synthetic test
            // it contains just the genesis account, so enumerating every leaf
            // is cheap. The live follower path collects only metadata-
            // affected keys, but the round-trip validator intentionally
            // exercise bundle I/O without worrying about key coverage.
            let prestate: HashMap<[u8; 32], Vec<u8>> = state
                .iter_raw_entries()
                .iter()
                .map(|(k, bytes)| (k.0, bytes.to_vec()))
                .collect();

            // Close a ledger with a single payment.
            let mut pool = TxPool::new();
            submit_payment(&mut pool, 1, 5_000_000);
            let close_result = close_ledger(&prev, &mut state, &mut pool, 1000, true);
            assert_eq!(close_result.applied_count, 1);

            // Extract tx blobs + metadata for the bundle.
            let tx_blobs: Vec<(Vec<u8>, Vec<u8>)> = close_result
                .tx_records
                .iter()
                .map(|r| (r.blob.clone(), r.meta.clone()))
                .collect();
            assert_eq!(tx_blobs.len(), 1);

            // Reference hash: replay_ledger against a fresh initial_state.
            // This is the ONLY valid ground truth for the harness path,
            // because close_ledger and replay_ledger currently produce
            // different account_hash for the same inputs (see project memory
            // `project_close_vs_replay_hash_diverge`). The harness uses
            // replay_ledger too, so comparing replay-vs-replay is the
            // correct invariant.
            let (_, mut ref_state) = initial_state();
            let ref_result = replay_ledger(
                &prev,
                &mut ref_state,
                tx_blobs.clone(),
                &close_result.header,
                false,
            );
            let expected_account_hash = ref_result.header.account_hash;

            // Capture a forensic bundle to a temp dir with no rippled endpoint.
            let tmp = tempfile::tempdir().unwrap();
            // Build the validated_header that replay_ledger expects: same as
            // close_result.header but with account_hash set to the reference
            // replay value (the one a live follower would see as the network
            // hash when rippled confirms the ledger).
            let mut validated_header_for_bundle = close_result.header.clone();
            validated_header_for_bundle.account_hash = expected_account_hash;

            let inputs = crate::ledger::forensic::CaptureInputs {
                bundle_root: tmp.path().to_path_buf(),
                anchor_seq: prev.sequence,
                anchor_hash: Some(prev.hash),
                anchor_account_hash: Some(prev.account_hash),
                mismatch_seq: close_result.header.sequence,
                local_account_hash: expected_account_hash,
                network_account_hash: expected_account_hash,
                parent_header: prev.clone(),
                validated_header: validated_header_for_bundle.clone(),
                applied_count: close_result.applied_count,
                failed_count: close_result.failed_count,
                skipped_count: close_result.skipped_count,
                touched_keys: Vec::new(),
                per_tx_attribution: Vec::new(),
                tx_blobs: tx_blobs.clone(),
                prestate: prestate.clone(),
                rpc_host: None,
                rpc_port: 0,
            };
            let (bundle_dir, _rippled_ref, _rippled_not_found, _rippled_unavailable) =
                crate::ledger::forensic::capture_forensic_bundle(inputs)
                    .await
                    .expect("capture_forensic_bundle must succeed");

            // Reload via the loader functions used by replay_fixture.
            use crate::ledger::forensic::loader;
            let artifact = loader::load_artifact(&bundle_dir).unwrap();
            let anchor_header = loader::load_anchor_header(&bundle_dir).unwrap();
            let validated_header = loader::load_validated_header(&bundle_dir).unwrap();
            let loaded_tx_blobs = loader::load_tx_blobs(&bundle_dir).unwrap();
            let loaded_prestate = loader::load_prestate(&bundle_dir).unwrap();
            let loaded_reference = loader::load_rippled_reference(&bundle_dir).unwrap();

            assert_eq!(artifact.anchor_seq, prev.sequence);
            assert_eq!(artifact.mismatch_seq, close_result.header.sequence);
            assert_eq!(artifact.tx_count, 1);
            assert_eq!(artifact.prestate_key_count, prestate.len());
            assert!(!artifact.rippled_reference_fetched);
            assert_eq!(loaded_reference.len(), 0);
            assert_eq!(anchor_header.hash, prev.hash);
            assert_eq!(validated_header.account_hash, expected_account_hash);
            assert_eq!(loaded_tx_blobs.len(), tx_blobs.len());
            assert_eq!(loaded_tx_blobs[0].0, tx_blobs[0].0);
            assert_eq!(loaded_tx_blobs[0].1, tx_blobs[0].1);
            assert_eq!(loaded_prestate.len(), prestate.len());
            for (k, v) in &prestate {
                assert_eq!(loaded_prestate.get(k), Some(v));
            }

            // Seed fresh state from reloaded prestate and replay.
            let mut replay_state = LedgerState::new();
            for (k, bytes) in &loaded_prestate {
                replay_state.insert_raw(crate::ledger::Key(*k), bytes.clone());
            }
            let replay_result = replay_ledger(
                &anchor_header,
                &mut replay_state,
                loaded_tx_blobs,
                &validated_header,
                true,
            );

            // The reloaded replay must reproduce the original close_ledger hash.
            assert_eq!(
                replay_result.header.account_hash,
                expected_account_hash,
                "round-trip replay account_hash {} differs from original {}",
                hex::encode_upper(replay_result.header.account_hash),
                hex::encode_upper(expected_account_hash),
            );
            assert_eq!(replay_result.applied_count, close_result.applied_count);
            // byte_diff=true must populate per_tx_attribution.
            assert!(!replay_result.per_tx_attribution.is_empty());
        });
    }
}
