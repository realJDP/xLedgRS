//! Persistent storage for relational node data.
//!
//! rippled uses NuDB for content-addressed SHAMap nodes and SQLite for ledger
//! headers, transactions, and account_tx indexing. This module covers the
//! SQLite side; NuDB is managed by `NodeStore`.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use crate::ledger::history::TxRecord;
use crate::ledger::LedgerHeader;
use anyhow::Result;
use rusqlite::Connection;

/// Storage statistics for monitoring/display.
#[derive(Debug, Default, Clone, Copy)]
pub struct StorageStats {
    pub transactions: u64,
    pub ledgers: u64,
}

/// Persistent storage backed by SQLite.
pub struct Storage {
    /// Dedicated write connection — save_ledger, prune, checkpoint.
    sql_write: Mutex<Connection>,
    /// Dedicated read connection — queries don't block on writes (WAL mode).
    sql_read: Mutex<Connection>,
    path: PathBuf,
}

impl Storage {
    fn write_conn(&self) -> MutexGuard<'_, Connection> {
        self.sql_write.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn read_conn(&self) -> MutexGuard<'_, Connection> {
        self.sql_read.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Root directory containing the SQLite database file. The forensic capture
    /// path uses this to derive a `debug-runs` subdirectory.
    pub fn data_dir(&self) -> &Path {
        &self.path
    }
}

impl Storage {
    /// Open (or create) storage at the given directory path.
    pub fn open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)?;

        let sql_path = path.join("history.sqlite");
        let write_conn = Connection::open(&sql_path)?;
        write_conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ledgers (
                seq INTEGER PRIMARY KEY,
                hash TEXT NOT NULL,
                header BLOB NOT NULL,
                tx_hashes BLOB
            );
            CREATE TABLE IF NOT EXISTS txs (
                hash BLOB PRIMARY KEY,
                data BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS account_tx (
                account BLOB NOT NULL,
                ledger_seq INTEGER NOT NULL,
                tx_seq INTEGER NOT NULL,
                tx_hash BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_acctx ON account_tx(account, ledger_seq DESC, tx_seq DESC);
        ")?;

        let read_conn = Connection::open(&sql_path)?;
        read_conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA busy_timeout = 5000;
        ",
        )?;

        Ok(Self {
            sql_write: Mutex::new(write_conn),
            sql_read: Mutex::new(read_conn),
            path: path.to_path_buf(),
        })
    }

    // ── Meta / sync state ───────────────────────────────────────────────────

    /// Check if the database has existing state.
    pub fn has_state(&self) -> bool {
        self.get_meta("ledger_seq").is_some()
    }

    /// Check if a full state sync has completed previously.
    pub fn is_sync_complete(&self) -> bool {
        self.get_meta("sync_complete").is_some()
    }

    /// Mark state sync as complete.
    pub fn set_sync_complete(&self) -> Result<()> {
        self.save_meta_kv("sync_complete", b"1")
    }

    /// Clear the sync_complete flag to re-enter sync mode.
    pub fn clear_sync_complete(&self) -> Result<()> {
        let conn = self.write_conn();
        conn.execute(
            "DELETE FROM meta WHERE key = ?1",
            rusqlite::params!["sync_complete"],
        )?;
        Ok(())
    }

    /// Store the ledger sequence that the state was synced from.
    pub fn set_sync_ledger(&self, seq: u64) -> Result<()> {
        self.save_meta_kv("sync_ledger", &seq.to_le_bytes())
    }

    /// Get the ledger sequence that the state was synced from.
    pub fn get_sync_ledger(&self) -> Option<u64> {
        let val = self.get_meta("sync_ledger")?;
        if val.len() == 8 {
            Some(u64::from_le_bytes(val[..8].try_into().unwrap()))
        } else {
            None
        }
    }

    /// Store the full LedgerHeader from the synced ledger.
    pub fn set_sync_ledger_header(&self, header: &LedgerHeader) -> Result<()> {
        self.save_meta_kv("sync_ledger_header", &bincode::serialize(header)?)
    }

    /// Get the full LedgerHeader from the synced ledger.
    pub fn get_sync_ledger_header(&self) -> Option<LedgerHeader> {
        let val = self.get_meta("sync_ledger_header")?;
        bincode::deserialize(&val).ok()
    }

    /// Store the ledger hash from the synced ledger.
    pub fn set_sync_ledger_hash(&self, hash: &[u8; 32]) -> Result<()> {
        self.save_meta_kv("sync_ledger_hash", hash)
    }

    /// Get the ledger hash from the synced ledger.
    pub fn get_sync_ledger_hash(&self) -> Option<[u8; 32]> {
        let val = self.get_meta("sync_ledger_hash")?;
        val.try_into().ok()
    }

    /// Store the account state root hash from the synced ledger.
    pub fn set_sync_account_hash(&self, hash: &[u8; 32]) -> Result<()> {
        self.save_meta_kv("sync_account_hash", hash)
    }

    /// Get the account state root hash from the synced ledger.
    pub fn get_sync_account_hash(&self) -> Option<[u8; 32]> {
        let val = self.get_meta("sync_account_hash")?;
        val.try_into().ok()
    }

    /// Persist the current SHAMap leaf count for RPC and restart resume.
    pub fn save_leaf_count(&self, leaf_count: u64) -> Result<()> {
        self.save_meta_kv("leaf_count", &leaf_count.to_le_bytes())
    }

    /// Load the most recently saved SHAMap leaf count, if present.
    pub fn get_leaf_count(&self) -> Option<u64> {
        let val = self.get_meta("leaf_count")?;
        if val.len() >= 8 {
            Some(u64::from_le_bytes(val[..8].try_into().unwrap()))
        } else {
            None
        }
    }

    /// Clear completed-sync handoff metadata before starting a fresh sync.
    /// Partial progress counters are retained so a restarted acquisition can
    /// resume against already persisted NuDB nodes.
    pub fn clear_sync_handoff(&self) -> Result<()> {
        let mut conn = self.write_conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM meta WHERE key IN ('sync_complete', 'sync_ledger', 'sync_ledger_hash', 'sync_account_hash', 'sync_ledger_header')", [])?;
        tx.commit()?;
        Ok(())
    }

    /// Persist a ledger header as the durable resume anchor for follower startup.
    /// This advances after initial sync and after each durably persisted
    /// followed ledger so restart anchors from the latest on-disk state.
    pub fn persist_sync_anchor(&self, header: &LedgerHeader) -> Result<()> {
        let mut conn = self.write_conn();
        let tx = conn.transaction()?;
        Self::save_ledger_stub_on_conn(&tx, header)?;
        Self::persist_sync_anchor_on_conn(&tx, header)?;
        tx.commit()?;
        Ok(())
    }

    /// Save metadata (ledger_seq, header, etc.)
    pub fn save_meta(&self, seq: u32, hash: &str, header: &LedgerHeader) -> Result<()> {
        let mut conn = self.write_conn();
        let tx = conn.transaction()?;
        Self::save_meta_on_conn(&tx, seq, hash, header)?;
        tx.commit()?;
        Ok(())
    }

    /// Get metadata value by key.
    pub fn get_meta(&self, key: &str) -> Option<Vec<u8>> {
        let conn = self.read_conn();
        conn.query_row(
            "SELECT value FROM meta WHERE key = ?1",
            rusqlite::params![key],
            |row| row.get(0),
        )
        .ok()
    }

    /// Save a metadata value by key.
    pub fn save_meta_kv(&self, key: &str, value: &[u8]) -> Result<()> {
        let conn = self.write_conn();
        Self::save_meta_kv_on_conn(&conn, key, value)?;
        Ok(())
    }

    fn save_meta_kv_on_conn(conn: &Connection, key: &str, value: &[u8]) -> Result<()> {
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    fn save_meta_on_conn(
        conn: &Connection,
        seq: u32,
        hash: &str,
        header: &LedgerHeader,
    ) -> Result<()> {
        Self::save_meta_kv_on_conn(conn, "ledger_seq", &seq.to_be_bytes())?;
        Self::save_meta_kv_on_conn(conn, "ledger_hash", hash.as_bytes())?;
        Self::save_meta_kv_on_conn(conn, "ledger_header", &bincode::serialize(header)?)?;
        Ok(())
    }

    fn persist_sync_anchor_on_conn(conn: &Connection, header: &LedgerHeader) -> Result<()> {
        Self::save_meta_kv_on_conn(conn, "sync_ledger", &(header.sequence as u64).to_le_bytes())?;
        Self::save_meta_kv_on_conn(conn, "sync_ledger_hash", &header.hash)?;
        Self::save_meta_kv_on_conn(conn, "sync_account_hash", &header.account_hash)?;
        Self::save_meta_kv_on_conn(conn, "sync_ledger_header", &bincode::serialize(header)?)?;
        Self::save_meta_kv_on_conn(conn, "sync_complete", b"1")?;
        Ok(())
    }

    /// Load persisted peer reservations keyed by node public key.
    pub fn load_peer_reservations(&self) -> std::collections::BTreeMap<String, String> {
        self.get_meta("peer_reservations")
            .and_then(|bytes| bincode::deserialize(&bytes).ok())
            .unwrap_or_default()
    }

    /// Persist peer reservations keyed by node public key.
    pub fn save_peer_reservations(
        &self,
        reservations: &std::collections::BTreeMap<String, String>,
    ) -> Result<()> {
        self.save_meta_kv("peer_reservations", &bincode::serialize(reservations)?)
    }

    /// Load persisted peerfinder bootcache entries.
    pub fn load_peerfinder_bootcache(&self) -> Vec<crate::network::peerfinder::PeerfinderEntry> {
        self.get_meta("peerfinder_bootcache")
            .and_then(|bytes| bincode::deserialize(&bytes).ok())
            .unwrap_or_default()
    }

    /// Persist peerfinder bootcache entries.
    pub fn save_peerfinder_bootcache(
        &self,
        entries: &[crate::network::peerfinder::PeerfinderEntry],
    ) -> Result<()> {
        self.save_meta_kv("peerfinder_bootcache", &bincode::serialize(entries)?)
    }

    /// Load metadata.
    pub fn load_meta(&self) -> Result<(u32, String, LedgerHeader)> {
        let seq_bytes = self
            .get_meta("ledger_seq")
            .ok_or_else(|| anyhow::anyhow!("no ledger_seq in storage"))?;
        let seq = u32::from_be_bytes(
            seq_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid ledger_seq length"))?,
        );

        let hash = self
            .get_meta("ledger_hash")
            .map(|v| String::from_utf8_lossy(&v).to_string())
            .unwrap_or_default();

        let header_bytes = self
            .get_meta("ledger_header")
            .ok_or_else(|| anyhow::anyhow!("no ledger_header in storage"))?;
        let header: LedgerHeader = bincode::deserialize(&header_bytes)?;

        Ok((seq, hash, header))
    }

    // ── Transactions ────────────────────────────────────────────────────────

    /// Save a single transaction record.
    pub fn save_transaction(&self, rec: &TxRecord) -> Result<()> {
        let conn = self.write_conn();
        let data = bincode::serialize(rec)?;
        conn.execute(
            "INSERT OR REPLACE INTO txs (hash, data) VALUES (?1, ?2)",
            rusqlite::params![rec.hash.as_slice(), data],
        )?;
        Ok(())
    }

    /// Look up a transaction by its 32-byte hash.
    pub fn lookup_tx(&self, hash: &[u8; 32]) -> Option<TxRecord> {
        let conn = self.read_conn();
        let data: Vec<u8> = conn
            .query_row(
                "SELECT data FROM txs WHERE hash = ?1",
                rusqlite::params![hash.as_slice()],
                |row| row.get(0),
            )
            .ok()?;
        bincode::deserialize(&data).ok()
    }

    /// Look up a raw transaction blob by its 32-byte hash.
    pub fn lookup_raw_tx(&self, hash: &[u8]) -> Option<Vec<u8>> {
        if hash.len() != 32 {
            return None;
        }
        let key: &[u8; 32] = hash.try_into().ok()?;
        self.lookup_tx(key).map(|rec| rec.blob)
    }

    // ── Ledger history ──────────────────────────────────────────────────────

    /// Save a closed ledger and its transactions.
    pub fn save_ledger(&self, header: &LedgerHeader, tx_records: &[TxRecord]) -> Result<()> {
        let mut conn = self.write_conn();
        let tx = conn.transaction()?;
        Self::save_ledger_on_conn(&tx, header, tx_records)?;
        tx.commit()?;
        Ok(())
    }

    fn save_ledger_on_conn(
        conn: &Connection,
        header: &LedgerHeader,
        tx_records: &[TxRecord],
    ) -> Result<()> {
        let tx_hashes: Vec<[u8; 32]> = tx_records.iter().map(|r| r.hash).collect();
        let tx_hashes_blob = bincode::serialize(&tx_hashes)?;
        let header_blob = bincode::serialize(header)?;
        let hash_hex = hex::encode(header.hash);

        conn.execute(
            "INSERT OR REPLACE INTO ledgers (seq, hash, header, tx_hashes) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                header.sequence as i64,
                hash_hex,
                header_blob,
                tx_hashes_blob
            ],
        )?;

        // Save account_tx index
        for rec in tx_records {
            let accounts = extract_tx_accounts(&rec.blob);
            for acct in &accounts {
                let acct_hex = hex::encode(acct);
                let hash_hex_tx = hex::encode(rec.hash);
                conn.execute(
                    "INSERT OR IGNORE INTO account_tx (account, ledger_seq, tx_seq, tx_hash) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![acct_hex, rec.ledger_seq as i64, rec.tx_index as i64, hash_hex_tx],
                )?;
            }
        }

        // Save transaction records
        for rec in tx_records {
            let data = bincode::serialize(rec)?;
            conn.execute(
                "INSERT OR REPLACE INTO txs (hash, data) VALUES (?1, ?2)",
                rusqlite::params![rec.hash.as_slice(), data],
            )?;
        }

        Ok(())
    }

    fn save_ledger_stub_on_conn(conn: &Connection, header: &LedgerHeader) -> Result<()> {
        let tx_hashes_blob = bincode::serialize(&Vec::<[u8; 32]>::new())?;
        let header_blob = bincode::serialize(header)?;
        conn.execute(
            "INSERT OR IGNORE INTO ledgers (seq, hash, header, tx_hashes) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                header.sequence as i64,
                hex::encode(header.hash),
                header_blob,
                tx_hashes_blob,
            ],
        )?;
        Ok(())
    }

    /// Atomically persist a validated ledger's history row, durable resume
    /// metadata, and optionally the follower sync anchor.
    pub fn save_validated_checkpoint(
        &self,
        header: &LedgerHeader,
        tx_records: &[TxRecord],
        persist_sync_anchor: bool,
    ) -> Result<()> {
        let mut conn = self.write_conn();
        let tx = conn.transaction()?;
        Self::save_ledger_on_conn(&tx, header, tx_records)?;
        Self::save_meta_on_conn(
            &tx,
            header.sequence,
            &hex::encode_upper(header.hash),
            header,
        )?;
        if persist_sync_anchor {
            Self::persist_sync_anchor_on_conn(&tx, header)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Load ledger history into LedgerStore.
    pub fn load_history(&self) -> Result<crate::ledger::history::LedgerStore> {
        self.load_history_with_limit(Some(256))
    }

    /// Load ledger history into LedgerStore with a caller-provided in-memory limit.
    pub fn load_history_with_limit(
        &self,
        max_history: Option<u32>,
    ) -> Result<crate::ledger::history::LedgerStore> {
        let mut store = crate::ledger::history::LedgerStore::with_limit(max_history);

        let ledger_rows: Vec<(Vec<u8>, Option<Vec<u8>>)> = {
            let conn = self.read_conn();
            let mut stmt =
                conn.prepare("SELECT header, tx_hashes FROM ledgers ORDER BY seq ASC")?;
            let rows = stmt.query_map([], |row| {
                let header_blob: Vec<u8> = row.get(0)?;
                let tx_hashes_blob: Option<Vec<u8>> = row.get(1)?;
                Ok((header_blob, tx_hashes_blob))
            })?;
            rows.filter_map(|r| r.ok()).collect()
        };

        for (header_blob, tx_hashes_blob) in ledger_rows {
            let header: LedgerHeader = match bincode::deserialize(&header_blob) {
                Ok(h) => h,
                Err(_) => continue,
            };
            let tx_hashes: Vec<[u8; 32]> = tx_hashes_blob
                .and_then(|b| bincode::deserialize(&b).ok())
                .unwrap_or_default();

            let tx_records: Vec<TxRecord> =
                tx_hashes.iter().filter_map(|h| self.lookup_tx(h)).collect();

            store.insert_ledger(header, tx_records);
        }

        Ok(store)
    }

    /// Check whether all ledgers in the inclusive range are present.
    pub fn has_full_ledger_range(&self, min_seq: u32, max_seq: u32) -> bool {
        if min_seq > max_seq {
            return false;
        }
        let conn = self.read_conn();
        let row = conn.query_row(
            "SELECT MIN(seq), MAX(seq), COUNT(*) FROM ledgers WHERE seq >= ?1 AND seq <= ?2",
            rusqlite::params![min_seq as i64, max_seq as i64],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        );
        let Ok((min_found, max_found, count)) = row else {
            return false;
        };
        let expected = i64::from(max_seq) - i64::from(min_seq) + 1;
        min_found == Some(min_seq as i64) && max_found == Some(max_seq as i64) && count == expected
    }

    /// Prune ledger history older than `keep` ledgers from current sequence.
    pub fn prune_history(&self, current_seq: u32, keep: u32) -> Result<usize> {
        self.prune_history_to(current_seq, keep, None)
    }

    pub fn prune_history_to(
        &self,
        current_seq: u32,
        keep: u32,
        max_delete_seq: Option<u32>,
    ) -> Result<usize> {
        if current_seq <= keep {
            return Ok(0);
        }
        let mut cutoff = current_seq.saturating_sub(keep);
        if let Some(max_delete_seq) = max_delete_seq {
            cutoff = cutoff.min(max_delete_seq.saturating_add(1));
        }
        if cutoff == 0 {
            return Ok(0);
        }
        let cutoff = cutoff as i64;

        // Collect tx hashes to delete
        let protected_seq = self.get_sync_ledger().map(|seq| seq as i64);
        let pruned_hashes: Vec<[u8; 32]> = {
            let conn = self.read_conn();
            let mut stmt = conn.prepare(
                "SELECT tx_hashes FROM ledgers WHERE seq < ?1 AND (?2 IS NULL OR seq != ?2)",
            )?;
            let rows = stmt.query_map(rusqlite::params![cutoff, protected_seq], |row| {
                let tx_hashes_blob: Option<Vec<u8>> = row.get(0)?;
                Ok(tx_hashes_blob)
            })?;
            rows.filter_map(|r| r.ok())
                .flatten()
                .flat_map(|blob| bincode::deserialize::<Vec<[u8; 32]>>(&blob).unwrap_or_default())
                .collect()
        };

        let mut conn = self.write_conn();
        let tx = conn.transaction()?;
        let deleted = tx.execute(
            "DELETE FROM ledgers WHERE seq < ?1 AND (?2 IS NULL OR seq != ?2)",
            rusqlite::params![cutoff, protected_seq],
        )?;

        // Delete pruned transactions
        for hash in &pruned_hashes {
            tx.execute(
                "DELETE FROM txs WHERE hash = ?1",
                rusqlite::params![hash.as_slice()],
            )?;
        }

        // Delete pruned account_tx entries
        tx.execute(
            "DELETE FROM account_tx WHERE ledger_seq < ?1 AND (?2 IS NULL OR ledger_seq != ?2)",
            rusqlite::params![cutoff, protected_seq],
        )?;

        tx.commit()?;
        Ok(deleted)
    }

    pub fn prune_history_window(&self, min_seq: Option<u32>, max_seq: u32) -> Result<usize> {
        if max_seq == 0 || min_seq.is_some_and(|min| min > max_seq) {
            return Ok(0);
        }

        let protected_seq = self.get_sync_ledger().map(|seq| seq as i64);
        let pruned_hashes: Vec<[u8; 32]> = if let Some(min_seq) = min_seq {
            let conn = self.read_conn();
            let mut stmt =
                conn.prepare("SELECT tx_hashes FROM ledgers WHERE seq >= ?1 AND seq <= ?2 AND (?3 IS NULL OR seq != ?3)")?;
            let rows = stmt.query_map(
                rusqlite::params![min_seq as i64, max_seq as i64, protected_seq],
                |row| {
                    let tx_hashes_blob: Option<Vec<u8>> = row.get(0)?;
                    Ok(tx_hashes_blob)
                },
            )?;
            rows.filter_map(|r| r.ok())
                .flatten()
                .flat_map(|blob| bincode::deserialize::<Vec<[u8; 32]>>(&blob).unwrap_or_default())
                .collect()
        } else {
            let conn = self.read_conn();
            let mut stmt = conn.prepare(
                "SELECT tx_hashes FROM ledgers WHERE seq <= ?1 AND (?2 IS NULL OR seq != ?2)",
            )?;
            let rows = stmt.query_map(rusqlite::params![max_seq as i64, protected_seq], |row| {
                let tx_hashes_blob: Option<Vec<u8>> = row.get(0)?;
                Ok(tx_hashes_blob)
            })?;
            rows.filter_map(|r| r.ok())
                .flatten()
                .flat_map(|blob| bincode::deserialize::<Vec<[u8; 32]>>(&blob).unwrap_or_default())
                .collect()
        };

        let mut conn = self.write_conn();
        let tx = conn.transaction()?;
        let deleted = if let Some(min_seq) = min_seq {
            tx.execute(
                "DELETE FROM ledgers WHERE seq >= ?1 AND seq <= ?2 AND (?3 IS NULL OR seq != ?3)",
                rusqlite::params![min_seq as i64, max_seq as i64, protected_seq],
            )?
        } else {
            tx.execute(
                "DELETE FROM ledgers WHERE seq <= ?1 AND (?2 IS NULL OR seq != ?2)",
                rusqlite::params![max_seq as i64, protected_seq],
            )?
        };

        for hash in &pruned_hashes {
            tx.execute(
                "DELETE FROM txs WHERE hash = ?1",
                rusqlite::params![hash.as_slice()],
            )?;
        }

        if let Some(min_seq) = min_seq {
            tx.execute(
                "DELETE FROM account_tx WHERE ledger_seq >= ?1 AND ledger_seq <= ?2 AND (?3 IS NULL OR ledger_seq != ?3)",
                rusqlite::params![min_seq as i64, max_seq as i64, protected_seq],
            )?;
        } else {
            tx.execute(
                "DELETE FROM account_tx WHERE ledger_seq <= ?1 AND (?2 IS NULL OR ledger_seq != ?2)",
                rusqlite::params![max_seq as i64, protected_seq],
            )?;
        }

        tx.commit()?;
        Ok(deleted)
    }

    // ── Flush / stats ───────────────────────────────────────────────────────

    /// Flush all pending writes to disk (WAL checkpoint).
    pub fn flush(&self) -> Result<()> {
        let conn = self.write_conn();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Get storage statistics for display/monitoring.
    pub fn stats(&self) -> StorageStats {
        let conn = self.read_conn();
        let txs = conn
            .query_row("SELECT COUNT(*) FROM txs", [], |r| r.get(0))
            .unwrap_or(0u64);
        let ldg = conn
            .query_row("SELECT COUNT(*) FROM ledgers", [], |r| r.get(0))
            .unwrap_or(0u64);
        StorageStats {
            transactions: txs,
            ledgers: ldg,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(seq: u32) -> LedgerHeader {
        LedgerHeader {
            sequence: seq,
            hash: [seq as u8; 32],
            parent_hash: [0u8; 32],
            close_time: seq as u64,
            total_coins: 100_000_000_000_000_000,
            account_hash: [0u8; 32],
            transaction_hash: [0u8; 32],
            parent_close_time: 0,
            close_time_resolution: 10,
            close_flags: 0,
        }
    }

    fn tx_rec(hash_byte: u8, seq: u32) -> TxRecord {
        TxRecord {
            blob: vec![0x12, 0x00, hash_byte],
            meta: vec![],
            hash: [hash_byte; 32],
            ledger_seq: seq,
            tx_index: 0,
            result: "tesSUCCESS".into(),
        }
    }

    #[test]
    fn prune_history_removes_pruned_transactions_from_txs_table() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let h1 = header(1);
        let h2 = header(2);
        let t1 = tx_rec(0xA1, 1);
        let t2 = tx_rec(0xB2, 2);
        storage.save_ledger(&h1, std::slice::from_ref(&t1)).unwrap();
        storage.save_ledger(&h2, std::slice::from_ref(&t2)).unwrap();

        assert!(storage.lookup_tx(&t1.hash).is_some());
        assert!(storage.lookup_tx(&t2.hash).is_some());

        storage.prune_history(3, 1).unwrap();

        assert!(storage.lookup_tx(&t1.hash).is_none());
        assert!(storage.lookup_tx(&t2.hash).is_some());
    }

    #[test]
    fn prune_history_window_respects_requested_range() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let h1 = header(1);
        let h2 = header(2);
        let h3 = header(3);
        let t1 = tx_rec(0xA1, 1);
        let t2 = tx_rec(0xB2, 2);
        let t3 = tx_rec(0xC3, 3);
        storage.save_ledger(&h1, std::slice::from_ref(&t1)).unwrap();
        storage.save_ledger(&h2, std::slice::from_ref(&t2)).unwrap();
        storage.save_ledger(&h3, std::slice::from_ref(&t3)).unwrap();

        storage.prune_history_window(Some(2), 2).unwrap();

        assert!(storage.lookup_tx(&t1.hash).is_some());
        assert!(storage.lookup_tx(&t2.hash).is_none());
        assert!(storage.lookup_tx(&t3.hash).is_some());
        assert!(storage.has_full_ledger_range(1, 1));
        assert!(!storage.has_full_ledger_range(2, 2));
        assert!(storage.has_full_ledger_range(3, 3));
    }

    #[test]
    fn load_history_orders_ledgers_by_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let h2 = header(2);
        let h1 = header(1);
        storage.save_ledger(&h2, &[]).unwrap();
        storage.save_ledger(&h1, &[]).unwrap();

        let loaded = storage.load_history().unwrap();
        assert!(loaded.get_ledger(1).is_some());
        assert!(loaded.get_ledger(2).is_some());
        assert_eq!(loaded.complete_ledgers(), "1-2");
    }

    #[test]
    fn meta_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        assert!(!storage.has_state());
        let h = header(42);
        storage.save_meta(42, "abc123", &h).unwrap();
        assert!(storage.has_state());

        let (seq, hash, loaded) = storage.load_meta().unwrap();
        assert_eq!(seq, 42);
        assert_eq!(hash, "abc123");
        assert_eq!(loaded.sequence, 42);
    }

    #[test]
    fn sync_complete_flag() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        assert!(!storage.is_sync_complete());
        storage.set_sync_complete().unwrap();
        assert!(storage.is_sync_complete());
        storage.clear_sync_complete().unwrap();
        assert!(!storage.is_sync_complete());
    }

    #[test]
    fn clear_sync_handoff_removes_completed_anchor_but_keeps_partial_progress() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let header = header(123);

        storage.persist_sync_anchor(&header).unwrap();
        storage.save_leaf_count(42).unwrap();
        assert!(storage.is_sync_complete());
        assert_eq!(storage.get_sync_ledger(), Some(123));
        assert!(storage.get_sync_ledger_hash().is_some());
        assert!(storage.get_sync_account_hash().is_some());
        assert!(storage.get_sync_ledger_header().is_some());
        assert_eq!(storage.get_leaf_count(), Some(42));

        storage.clear_sync_handoff().unwrap();

        assert!(!storage.is_sync_complete());
        assert_eq!(storage.get_sync_ledger(), None);
        assert_eq!(storage.get_sync_ledger_hash(), None);
        assert_eq!(storage.get_sync_account_hash(), None);
        assert!(storage.get_sync_ledger_header().is_none());
        assert_eq!(storage.get_leaf_count(), Some(42));
    }

    #[test]
    fn validated_checkpoint_persists_history_meta_and_anchor_together() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let h = header(88);
        let tx = tx_rec(0x88, 88);

        storage
            .save_validated_checkpoint(&h, std::slice::from_ref(&tx), true)
            .unwrap();

        let (seq, hash, loaded) = storage.load_meta().unwrap();
        assert_eq!(seq, 88);
        assert_eq!(hash, hex::encode_upper(h.hash));
        assert_eq!(loaded.sequence, 88);
        assert!(storage.is_sync_complete());
        assert_eq!(storage.get_sync_ledger(), Some(88));
        assert_eq!(storage.get_sync_ledger_hash(), Some(h.hash));
        assert_eq!(storage.get_sync_account_hash(), Some(h.account_hash));
        assert_eq!(storage.get_sync_ledger_header().unwrap().sequence, 88);
        assert!(storage.has_full_ledger_range(88, 88));
        assert!(storage.lookup_tx(&tx.hash).is_some());
    }

    #[test]
    fn history_prune_preserves_durable_sync_anchor_row() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        for seq in 10..=12 {
            storage
                .save_ledger(&header(seq), std::slice::from_ref(&tx_rec(seq as u8, seq)))
                .unwrap();
        }
        storage.persist_sync_anchor(&header(11)).unwrap();

        let deleted = storage.prune_history_window(Some(10), 12).unwrap();

        assert_eq!(deleted, 2);
        assert!(!storage.has_full_ledger_range(10, 10));
        assert!(storage.has_full_ledger_range(11, 11));
        assert!(!storage.has_full_ledger_range(12, 12));
    }

    #[test]
    fn poisoned_sqlite_mutexes_recover_for_future_calls() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = storage.sql_write.lock().unwrap();
            panic!("poison write connection");
        }));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = storage.sql_read.lock().unwrap();
            panic!("poison read connection");
        }));

        storage.save_meta(7, "poison-ok", &header(7)).unwrap();
        let (seq, hash, hdr) = storage.load_meta().unwrap();
        assert_eq!(seq, 7);
        assert_eq!(hash, "poison-ok");
        assert_eq!(hdr.sequence, 7);

        storage.save_ledger(&header(7), &[]).unwrap();
        assert!(storage.has_full_ledger_range(7, 7));
        assert_eq!(storage.stats().ledgers, 1);
    }

    #[test]
    fn peer_reservations_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let mut reservations = std::collections::BTreeMap::new();
        reservations.insert("n9Example".to_string(), "vip".to_string());
        reservations.insert("n9Backup".to_string(), String::new());
        storage.save_peer_reservations(&reservations).unwrap();

        let loaded = storage.load_peer_reservations();
        assert_eq!(loaded, reservations);
    }

    #[test]
    fn peerfinder_bootcache_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let entries = vec![crate::network::peerfinder::PeerfinderEntry {
            address: "192.0.2.9:51235".parse().unwrap(),
            source: "peer".to_string(),
            fixed: false,
            last_seen_unix: 123,
            last_connected_unix: Some(456),
            success_count: 2,
            failure_count: 1,
            next_attempt_unix: 0,
        }];

        storage.save_peerfinder_bootcache(&entries).unwrap();
        let loaded = storage.load_peerfinder_bootcache();
        assert_eq!(loaded, entries);
    }
}

/// Extract sender (Account) and destination accounts from a raw tx blob.
fn extract_tx_accounts(blob: &[u8]) -> Vec<[u8; 20]> {
    let mut accounts = Vec::new();
    if let Ok(parsed) = crate::transaction::parse_blob(blob) {
        if parsed.account != [0u8; 20] {
            accounts.push(parsed.account);
        }
        if let Some(dest) = parsed.destination {
            if dest != [0u8; 20] && dest != parsed.account {
                accounts.push(dest);
            }
        }
    }
    accounts
}
