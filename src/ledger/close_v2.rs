//! close_v2 — experimental ledger close using the view stack.
//!
//! Flow:
//!   1. Parent ClosedLedger (immutable, shared via Arc)
//!   2. OpenView wraps parent — reads fall through, writes buffered
//!   3. For each tx (canonical order, multi-pass retry):
//!      ApplyViewImpl wraps OpenView → handler → apply
//!   4. Snapshot parent SHAMap, apply OpenView changes → new state hash
//!   5. Build tx tree → tx hash
//!   6. Compute ledger header hash
//!
//! Modeled after parts of rippled's BuildLedger flow, but not the primary
//! runtime close path or a complete parity implementation.

use crate::crypto::sha512_first_half;
use crate::ledger::history::TxRecord;
use crate::ledger::ledger_core::ClosedLedger;
use crate::ledger::open_view::OpenView;
use crate::ledger::pool::TxPool;
use crate::ledger::sparse_shamap::SparseSHAMap;
use crate::ledger::transact;
use crate::ledger::views::{ApplyFlags, ReadView};
use crate::ledger::LedgerHeader;
use crate::transaction::parse_blob;
use std::sync::Arc;

const PREFIX_TX_LEAF: [u8; 4] = [0x53, 0x4E, 0x44, 0x00]; // SND\0

/// rippled constants from BuildLedger.cpp
const LEDGER_TOTAL_PASSES: usize = 3;
const LEDGER_RETRY_PASSES: usize = 1;

// ── Canonical ordering (matches rippled's CanonicalTXSet) ───────────────────

struct CanonicalEntry {
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
        // rippled: copy 20-byte account into 32-byte buffer, XOR with salt
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

// ── Close result ────────────────────────────────────────────────────────────

/// Outcome of closing a ledger via the view stack.
pub struct CloseResultV2 {
    pub header: LedgerHeader,
    pub tx_records: Vec<TxRecord>,
    pub applied_count: usize,
    pub failed_count: usize,
    pub skipped_count: usize,
    /// State changes from the OpenView — (key, action, sle_data).
    /// Used to sync LedgerState during the transition period.
    pub state_changes: Vec<(crate::ledger::Key, StateChangeAction, Option<Vec<u8>>)>,
}

#[derive(Debug, Clone, Copy)]
pub enum StateChangeAction {
    Insert,
    Replace,
    Erase,
}

// ── Close function ──────────────────────────────────────────────────────────

/// Close a ledger using the view stack, matching rippled's BuildLedger.
pub fn close_ledger_v2(
    parent: Arc<ClosedLedger>,
    pool: &mut TxPool,
    close_time: u64,
    have_close_time_consensus: bool,
) -> CloseResultV2 {
    let entries = pool.drain_sorted();
    let parent_info = parent.info();
    let new_seq = parent_info.seq + 1;

    // Salt for canonical ordering = hash of all tx hashes (matches rippled's consensus set hash)
    let salt: [u8; 32] = {
        let mut data = Vec::with_capacity(entries.len() * 32);
        for e in &entries {
            data.extend_from_slice(&e.hash);
        }
        if data.is_empty() {
            [0u8; 32]
        } else {
            sha512_first_half(&data)
        }
    };

    // Parse and build canonical set
    let mut txns: Vec<CanonicalEntry> = Vec::new();
    let mut skipped_count = 0usize;
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

    // Create OpenView wrapping parent
    let mut open = OpenView::new(parent.clone());
    open.info_mut().seq = new_seq;
    open.info_mut().close_time = close_time;

    let mut applied_count = 0usize;
    let mut failed_count = 0usize;
    let mut fees_burned = 0u64;
    let mut tx_records = Vec::new();
    let mut next_tx_index = 0u32;
    let mut tx_map = SparseSHAMap::new();

    // Multi-pass apply (rippled BuildLedger.cpp:applyTransactions)
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

            let tx_hash = entry.hash;
            let handler = transact::handler_for_type(parsed.tx_type);
            let result =
                transact::apply_transaction(&mut open, &parsed, &tx_hash, handler.as_ref(), flags);

            if result.ter.is_success() || result.ter.claims_fee() {
                // Applied — record it and accumulate burned fees
                fees_burned += parsed.fee;
                let result_str = if result.ter.is_success() {
                    applied_count += 1;
                    "tesSUCCESS"
                } else {
                    failed_count += 1;
                    "tecCLAIM"
                };

                // Build metadata from affected nodes
                let meta = if let Some(ref affected) = result.metadata {
                    build_metadata(affected, tx_hash, new_seq, next_tx_index, result_str)
                } else {
                    Vec::new()
                };

                // Build tx tree leaf
                let leaf_data = encode_tx_leaf(&entry.blob, &meta);
                let leaf_hash = tx_leaf_hash(&leaf_data, &tx_hash);
                tx_map.insert(tx_hash, leaf_hash);

                tx_records.push(TxRecord {
                    blob: entry.blob,
                    meta,
                    hash: tx_hash,
                    ledger_seq: new_seq,
                    tx_index: next_tx_index,
                    result: result_str.to_string(),
                });
                next_tx_index += 1;
                changes += 1;
            } else {
                // Check if permanent failure
                if is_permanent_failure(&result.ter) {
                    failed_set.insert(entry.hash);
                } else {
                    kept.push(entry); // Retry next pass
                }
            }
        }

        txns = kept;

        if changes == 0 && !certain_retry {
            break;
        }
        if changes == 0 || pass >= LEDGER_RETRY_PASSES {
            certain_retry = false;
        }
    }
    skipped_count += txns.len();

    // Update skip list SLE (matching rippled's Ledger::updateSkipList)
    update_skip_list(&mut open, parent_info.seq, &parent_info.hash);

    // Collect state changes for LedgerState sync
    let state_changes: Vec<(crate::ledger::Key, StateChangeAction, Option<Vec<u8>>)> = {
        use crate::ledger::state_table::RawAction;
        open.state_table()
            .iter()
            .map(|(key, (action, sle_opt))| {
                let act = match action {
                    RawAction::Insert => StateChangeAction::Insert,
                    RawAction::Replace => StateChangeAction::Replace,
                    RawAction::Erase => StateChangeAction::Erase,
                };
                let data = sle_opt.as_ref().map(|s| s.data().to_vec());
                (*key, act, data)
            })
            .collect()
    };

    // Compute state hash: snapshot parent SHAMap + apply OpenView changes
    let account_hash = {
        let mut new_state = parent.clone_state_map();
        open.apply_to_shamap(&mut new_state)
    };

    // Compute tx hash
    let transaction_hash = if tx_map.len() == 0 {
        [0u8; 32]
    } else {
        tx_map.root_hash()
    };

    // Close time logic (matching rippled)
    let prev_close_time = parent_info.close_time;
    let prev_resolution = parent_info.close_time_resolution;
    let resolution =
        next_close_time_resolution(prev_resolution, have_close_time_consensus, new_seq);
    let effective_time = effective_close_time(close_time, resolution, prev_close_time);
    let close_flags = if !have_close_time_consensus {
        0x01u8
    } else {
        0x00u8
    };

    // Build header
    let mut header = LedgerHeader {
        sequence: new_seq,
        total_coins: open.info().total_coins.saturating_sub(fees_burned),
        parent_hash: parent_info.hash,
        transaction_hash,
        account_hash,
        parent_close_time: prev_close_time as u32,
        close_time: effective_time,
        close_time_resolution: resolution,
        close_flags,
        hash: [0u8; 32],
    };
    header.hash = header.compute_hash();

    CloseResultV2 {
        header,
        tx_records,
        applied_count,
        failed_count,
        skipped_count,
        state_changes,
    }
}

/// Convert AffectedNodeInfo (from view stack) to AffectedNode (for metadata encoding)
/// and encode as binary metadata blob.
fn build_metadata(
    nodes: &[crate::ledger::apply_view_impl::AffectedNodeInfo],
    tx_hash: [u8; 32],
    ledger_seq: u32,
    tx_index: u32,
    result_str: &str,
) -> Vec<u8> {
    use crate::ledger::apply_view_impl::AffectedAction;
    use crate::ledger::meta::{encode_metadata, Action, AffectedNode};

    let mut meta_nodes = Vec::new();

    for node in nodes {
        let action = match node.action {
            AffectedAction::Created => Action::Created,
            AffectedAction::Modified => Action::Modified,
            AffectedAction::Deleted => Action::Deleted,
        };

        // Parse fields from the after SLE (for Created/Modified: the final state)
        let fields = if let Some(ref after) = node.after {
            crate::ledger::meta::parse_sle(after)
                .map(|p| p.fields)
                .unwrap_or_default()
        } else {
            vec![]
        };

        // Parse previous fields from before SLE (for Modified: diff with after)
        let previous_fields = if node.action == AffectedAction::Modified {
            if let (Some(ref before), Some(ref after)) = (&node.before, &node.after) {
                let pre = crate::ledger::meta::parse_sle(before)
                    .map(|p| p.fields)
                    .unwrap_or_default();
                let post = crate::ledger::meta::parse_sle(after)
                    .map(|p| p.fields)
                    .unwrap_or_default();
                crate::ledger::meta::diff_previous_fields(&pre, &post)
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        meta_nodes.push(AffectedNode {
            action,
            entry_type: node.entry_type as u16,
            ledger_index: node.key.0,
            fields,
            previous_fields,
            prev_txn_id: Some(tx_hash),
            prev_txn_lgrseq: Some(ledger_seq),
        });
    }

    let result_code = match result_str {
        "tesSUCCESS" => 0,
        "tecCLAIM" => 100,
        other => crate::ledger::ter::token_to_code(other)
            .map(|r| r.code())
            .unwrap_or(0),
    };
    encode_metadata(result_code, tx_index, &meta_nodes)
}

/// Update the skip list SLE, matching rippled's Ledger::updateSkipList().
///
/// Two skip lists:
/// 1. Short list (keylet::skip()): last 256 parent hashes, updated every ledger
/// 2. Long list (keylet::skip_for_ledger(seq)): flag ledger hashes, updated every 256 ledgers
fn update_skip_list(open: &mut OpenView, prev_seq: u32, parent_hash: &[u8; 32]) {
    use crate::ledger::keylet;
    use crate::ledger::sle::{LedgerEntryType, SLE};
    use crate::ledger::views::{RawView, ReadView};

    // ── Long skip list: every 256 ledgers ──
    if (prev_seq & 0xFF) == 0 && prev_seq > 0 {
        let long_kl = keylet::skip_for_ledger(prev_seq);
        let mut hashes = Vec::new();

        if let Some(existing) = open.read(&long_kl) {
            // Parse existing Vector256 (sfHashes type=19, field=1)
            if let Some(raw) = existing.find_field_raw(19, 1) {
                for chunk in raw.chunks_exact(32) {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(chunk);
                    hashes.push(h);
                }
            }
        }

        hashes.push(*parent_hash);

        // Build SLE binary
        let sle_data = build_skip_list_sle(&hashes, prev_seq);
        let sle = std::sync::Arc::new(SLE::new(
            long_kl.key,
            LedgerEntryType::LedgerHashes,
            sle_data,
        ));
        if hashes.len() == 1 {
            open.raw_insert(sle);
        } else {
            open.raw_replace(sle);
        }
    }

    // ── Short skip list: every ledger, last 256 hashes ──
    let short_kl = keylet::skip();
    let mut hashes = Vec::new();
    let mut exists = false;

    if let Some(existing) = open.read(&short_kl) {
        exists = true;
        if let Some(raw) = existing.find_field_raw(19, 1) {
            for chunk in raw.chunks_exact(32) {
                let mut h = [0u8; 32];
                h.copy_from_slice(chunk);
                hashes.push(h);
            }
        }
    }

    // Circular buffer: max 256 entries
    if hashes.len() == 256 {
        hashes.remove(0);
    }
    hashes.push(*parent_hash);

    let sle_data = build_skip_list_sle(&hashes, prev_seq);
    let sle = std::sync::Arc::new(SLE::new(
        short_kl.key,
        LedgerEntryType::LedgerHashes,
        sle_data,
    ));
    if exists {
        open.raw_replace(sle);
    } else {
        open.raw_insert(sle);
    }
}

/// Build binary SLE for a skip list entry.
/// Fields: sfLedgerEntryType(1,1), sfLastLedgerSequence(2,?), sfHashes(19,1)
fn build_skip_list_sle(hashes: &[[u8; 32]], last_seq: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity(3 + 5 + 3 + hashes.len() * 32);

    // sfLedgerEntryType = LedgerHashes (0x0068)
    crate::ledger::meta::write_field_header(&mut data, 1, 1);
    data.extend_from_slice(&0x0068u16.to_be_bytes());

    // sfFlags = 0 (required on all SLEs)
    crate::ledger::meta::write_field_header(&mut data, 2, 2);
    data.extend_from_slice(&0u32.to_be_bytes());

    // sfLastLedgerSequence (type=2, field=27)
    crate::ledger::meta::write_field_header(&mut data, 2, 27);
    data.extend_from_slice(&last_seq.to_be_bytes());

    // sfHashes (type=19 Vector256, field=1)
    crate::ledger::meta::write_field_header(&mut data, 19, 1);
    // VL-encoded: total_bytes = num_hashes * 32
    crate::ledger::meta::encode_vl_length(&mut data, hashes.len() * 32);
    for h in hashes {
        data.extend_from_slice(h);
    }

    data
}

fn is_permanent_failure(ter: &transact::TER) -> bool {
    matches!(
        ter,
        transact::TER::Malformed(_) | transact::TER::LocalFail(_)
    )
}

fn tx_leaf_hash(data: &[u8], key: &[u8; 32]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(4 + data.len() + 32);
    payload.extend_from_slice(&PREFIX_TX_LEAF);
    payload.extend_from_slice(data);
    payload.extend_from_slice(key);
    sha512_first_half(&payload)
}

fn encode_tx_leaf(tx_blob: &[u8], meta_blob: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(tx_blob.len() + meta_blob.len() + 8);
    crate::transaction::serialize::encode_length(tx_blob.len(), &mut data);
    data.extend_from_slice(tx_blob);
    crate::transaction::serialize::encode_length(meta_blob.len(), &mut data);
    data.extend_from_slice(meta_blob);
    data
}

// ── Close time helpers (matching rippled LedgerTiming.h) ────────────────────

const POSSIBLE_RESOLUTIONS: [u8; 6] = [10, 20, 30, 60, 90, 120];

fn next_close_time_resolution(prev: u8, agreed: bool, seq: u32) -> u8 {
    let Some(idx) = POSSIBLE_RESOLUTIONS.iter().position(|&r| r == prev) else {
        return prev;
    };
    if !agreed && seq % 1 == 0 {
        if let Some(&next) = POSSIBLE_RESOLUTIONS.get(idx + 1) {
            return next;
        }
    }
    if agreed && seq % 8 == 0 && idx > 0 {
        return POSSIBLE_RESOLUTIONS[idx - 1];
    }
    prev
}

fn effective_close_time(close_time: u64, resolution: u8, prior: u64) -> u64 {
    if close_time == 0 {
        return 0;
    }
    let res = resolution as u64;
    let rounded = if res > 0 {
        (close_time + res / 2) / res * res
    } else {
        close_time
    };
    rounded.max(prior + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ledger::keylet;

    #[test]
    fn test_skip_list_updated() {
        let parent = Arc::new(ClosedLedger::genesis());
        let mut pool = TxPool::new();
        let result = close_ledger_v2(parent, &mut pool, 1000, true);

        // The skip list should be in the state changes
        let skip_key = keylet::skip();
        let has_skip = result
            .state_changes
            .iter()
            .any(|(key, _, _)| *key == skip_key.key);
        assert!(has_skip, "skip list SLE should be created on first close");
    }

    #[test]
    fn test_close_v2_empty() {
        let parent = Arc::new(ClosedLedger::genesis());
        let mut pool = TxPool::new();
        let result = close_ledger_v2(parent, &mut pool, 1000, true);
        assert_eq!(result.header.sequence, 1);
        assert_eq!(result.applied_count, 0);
        assert_ne!(result.header.hash, [0u8; 32]); // hash computed
    }

    #[test]
    fn test_close_time_resolution() {
        assert_eq!(next_close_time_resolution(30, true, 8), 20); // improve
        assert_eq!(next_close_time_resolution(30, true, 7), 30); // not on boundary
        assert_eq!(next_close_time_resolution(30, false, 1), 60); // degrade
    }

    #[test]
    fn test_effective_close_time() {
        assert_eq!(effective_close_time(1005, 10, 1000), 1010); // round up
        assert_eq!(effective_close_time(1001, 10, 1000), 1001); // must be > prior
        assert_eq!(effective_close_time(0, 10, 1000), 0); // zero = no time
    }
}
