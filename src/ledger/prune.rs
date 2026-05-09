//! NuDB pruning — compact the NodeStore to only live objects.
//!
//! Walk the state tree from its root hash, copying all reachable nodes
//! to a new NuDB database. Delete the old one.
//!
//! Matches rippled's online_delete: create new DB, visitNodes, rotate.

use std::path::Path;
use std::sync::Arc;
use tracing::info;

use crate::ledger::node_store::{
    decode_node_object_kind, NodeObjectKind, NodeObjectType, NodeStore, NuDBNodeStore,
};

/// Result of a compaction.
#[derive(Debug)]
pub struct CompactResult {
    pub inner_nodes: u64,
    pub leaf_nodes: u64,
    pub total: u64,
}

fn walk_reachable<F>(
    store: &Arc<dyn NodeStore>,
    root_hash: [u8; 32],
    object_type: NodeObjectType,
    mut visitor: F,
) -> std::io::Result<CompactResult>
where
    F: FnMut([u8; 32], Vec<u8>) -> std::io::Result<()>,
{
    let mut inner_count = 0u64;
    let mut leaf_count = 0u64;
    let mut visited = std::collections::HashSet::new();
    let mut stack: Vec<[u8; 32]> = vec![root_hash];

    while let Some(hash) = stack.pop() {
        if hash == [0u8; 32] || !visited.insert(hash) {
            continue;
        }

        let data = match store.fetch(&hash)? {
            Some(d) => d,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("missing reachable node {}", hex::encode_upper(hash)),
                ));
            }
        };

        match decode_node_object_kind(object_type, &hash, &data) {
            Some(NodeObjectKind::Inner) => {
                inner_count += 1;
                for i in 0..16 {
                    let offset = i * 32;
                    let mut child_hash = [0u8; 32];
                    child_hash.copy_from_slice(&data[offset..offset + 32]);
                    if child_hash != [0u8; 32] {
                        stack.push(child_hash);
                    }
                }
            }
            Some(NodeObjectKind::Leaf) => {
                leaf_count += 1;
            }
            Some(NodeObjectKind::Ledger) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "reachable SHAMap node {} decoded as a ledger object",
                        hex::encode_upper(hash)
                    ),
                ));
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "reachable {:?} node {} failed typed/hash validation",
                        object_type,
                        hex::encode_upper(hash)
                    ),
                ));
            }
        }

        visitor(hash, data)?;

        let total = inner_count + leaf_count;
        if total % 500_000 == 0 && total > 0 {
            info!(
                "prune: visited {} reachable nodes ({} inner, {} leaf)",
                total, inner_count, leaf_count
            );
        }
    }

    Ok(CompactResult {
        inner_nodes: inner_count,
        leaf_nodes: leaf_count,
        total: inner_count + leaf_count,
    })
}

/// Walk the state tree from `root_hash`, copying all reachable nodes
/// from `source` to a new NuDB at `new_path`.
///
/// Inner nodes are 512 bytes (16 × 32-byte child hashes).
/// Everything else is a leaf node.
pub fn compact_nodestore(
    source: &Arc<dyn NodeStore>,
    root_hash: [u8; 32],
    new_path: &Path,
) -> std::io::Result<CompactResult> {
    compact_nodestore_typed(source, root_hash, NodeObjectType::AccountNode, new_path)
}

/// Walk a typed SHAMap tree from `root_hash`, copying all reachable nodes.
pub fn compact_nodestore_typed(
    source: &Arc<dyn NodeStore>,
    root_hash: [u8; 32],
    object_type: NodeObjectType,
    new_path: &Path,
) -> std::io::Result<CompactResult> {
    let target = Arc::new(NuDBNodeStore::open(new_path)?);
    let mut batch: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(1000);

    let result = walk_reachable(source, root_hash, object_type, |hash, data| {
        batch.push((hash, data));
        if batch.len() >= 1000 {
            target.store_batch(&batch)?;
            batch.clear();
        }
        Ok(())
    })?;

    // Flush remaining
    if !batch.is_empty() {
        target.store_batch(&batch)?;
    }
    target.flush_to_disk()?;

    info!(
        "prune: complete — {} nodes ({} inner, {} leaf)",
        result.total, result.inner_nodes, result.leaf_nodes
    );
    Ok(result)
}

/// Walk the in-memory SHAMap and collect known content hashes.
///
/// This is retained for diagnostics. Compaction must walk and validate the
/// persisted tree from the root so hash-only inner branches cannot lose their
/// descendants.
pub fn collect_live_leaf_hashes(state_map: &crate::ledger::shamap::SHAMap) -> Vec<[u8; 32]> {
    let mut hashes = Vec::new();
    collect_from_inner(&state_map.root, &mut hashes);
    hashes
}

fn collect_from_inner(node: &crate::ledger::shamap::InnerNode, hashes: &mut Vec<[u8; 32]>) {
    use crate::ledger::shamap::Node;
    for i in 0..16 {
        if let Some(ref child) = node.children[i] {
            match child.as_ref() {
                Node::Inner(inner) => collect_from_inner(inner, hashes),
                Node::Leaf(leaf) => {
                    if let Some(h) = leaf.cached_hash {
                        hashes.push(h);
                    }
                }
                Node::Stub { content_hash, .. } => {
                    hashes.push(*content_hash);
                }
            }
        } else if node.has_branch(i) {
            // Branch exists but child not in memory — the content hash
            // in child_hashes[i] points to either an inner or leaf in NuDB
            let h = node.child_hash(i);
            if h != [0u8; 32] {
                hashes.push(h);
            }
        }
    }
}

/// Compact using the in-memory SHAMap root hash.
///
/// The actual copy walks the persisted NodeStore from that root and validates
/// each reachable node. This intentionally fails if dirty in-memory nodes have
/// not been flushed yet, rather than producing an incomplete compacted DB.
pub fn compact_from_shamap(
    source: &Arc<dyn NodeStore>,
    state_map: &crate::ledger::shamap::SHAMap,
    new_path: &Path,
) -> std::io::Result<CompactResult> {
    let mut snapshot = state_map.clone();
    let root_hash = snapshot.root_hash();
    compact_nodestore(source, root_hash, new_path)
}

/// Verify that every node reachable from `root_hash` exists in `store`.
/// Returns the reachable node counts if verification succeeds.
pub fn verify_nodestore(
    store: &Arc<dyn NodeStore>,
    root_hash: [u8; 32],
) -> std::io::Result<CompactResult> {
    let result = walk_reachable(
        store,
        root_hash,
        NodeObjectType::AccountNode,
        |_hash, _data| Ok(()),
    )?;
    info!(
        "prune: verified {} reachable nodes ({} inner, {} leaf)",
        result.total, result.inner_nodes, result.leaf_nodes
    );
    Ok(result)
}

/// Move a verified compacted database into place and keep the previous store
/// as a rollback backup. Returns the backup directory path.
pub fn swap_compacted_nodestore(
    db_dir: &Path,
    compact_dir: &Path,
) -> std::io::Result<std::path::PathBuf> {
    if !compact_dir.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("compact directory {:?} does not exist", compact_dir),
        ));
    }
    if !db_dir.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("source directory {:?} does not exist", db_dir),
        ));
    }

    let parent = db_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("nodestore directory {:?} has no parent", db_dir),
        )
    })?;
    let stem = db_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid nodestore directory name {:?}", db_dir),
            )
        })?;

    let mut backup_dir = parent.join(format!("{stem}.backup"));
    if backup_dir.exists() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        backup_dir = parent.join(format!("{stem}.backup.{ts}"));
    }

    std::fs::rename(db_dir, &backup_dir)?;
    if let Err(e) = std::fs::rename(compact_dir, db_dir) {
        let _ = std::fs::rename(&backup_dir, db_dir);
        return Err(e);
    }

    Ok(backup_dir)
}

/// Compact the NodeStore in place: create new DB, copy live nodes, swap.
///
/// `source` is the current NodeStore.
/// `root_hash` is the current state tree root.
/// `db_dir` is the directory containing the NuDB files.
///
/// Creates `db_dir/compact/`, copies live nodes, then renames
/// old dir → `db_dir/old/`, new dir → `db_dir/` path.
pub fn compact_in_place(
    source: &Arc<dyn NodeStore>,
    root_hash: [u8; 32],
    db_dir: &Path,
) -> std::io::Result<CompactResult> {
    let compact_dir = db_dir.join("compact");
    if compact_dir.exists() {
        std::fs::remove_dir_all(&compact_dir)?;
    }

    let result = compact_nodestore(source, root_hash, &compact_dir)?;

    // Swap: rename current → old, compact → current
    let old_dir = db_dir.join("old");
    if old_dir.exists() {
        std::fs::remove_dir_all(&old_dir)?;
    }

    // The source NodeStore is still open, so the caller must drop it before
    // swapping directories. Leave the compacted directory in place and let the
    // caller perform the final swap.
    info!(
        "prune: compact database ready at {:?} ({} nodes). Caller must swap directories.",
        compact_dir, result.total,
    );

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::node_store::MemNodeStore;

    fn valid_leaf(data: &[u8], key_byte: u8) -> ([u8; 32], Vec<u8>) {
        let mut node = data.to_vec();
        node.extend_from_slice(&[key_byte; 32]);

        let mut prefixed = Vec::with_capacity(4 + node.len());
        prefixed.extend_from_slice(b"MLN\0");
        prefixed.extend_from_slice(&node);

        (crate::crypto::sha512_first_half(&prefixed), node)
    }

    fn valid_inner(children: &[[u8; 32]]) -> ([u8; 32], Vec<u8>) {
        let mut node = vec![0u8; 16 * 32];
        for (slot, child) in children.iter().enumerate() {
            let offset = slot * 32;
            node[offset..offset + 32].copy_from_slice(child);
        }

        let mut prefixed = Vec::with_capacity(4 + node.len());
        prefixed.extend_from_slice(b"MIN\0");
        prefixed.extend_from_slice(&node);

        (crate::crypto::sha512_first_half(&prefixed), node)
    }

    #[test]
    fn test_compact_empty() {
        let source = Arc::new(MemNodeStore::new()) as Arc<dyn NodeStore>;
        let tmp = tempfile::tempdir().unwrap();
        let result = compact_nodestore(&source, [0u8; 32], &tmp.path().join("out"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().total, 0);
    }

    #[test]
    fn test_compact_single_leaf() {
        let source = Arc::new(MemNodeStore::new()) as Arc<dyn NodeStore>;
        let (hash, data) = valid_leaf(b"leaf data", 0xAA);
        source.store(&hash, &data).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let result = compact_nodestore(&source, hash, &tmp.path().join("out")).unwrap();
        assert_eq!(result.leaf_nodes, 1);
        assert_eq!(result.inner_nodes, 0);
    }

    #[test]
    fn test_compact_inner_with_children() {
        let source = Arc::new(MemNodeStore::new()) as Arc<dyn NodeStore>;

        // Create two leaf nodes
        let (leaf1_hash, leaf1_data) = valid_leaf(b"leaf1", 0x11);
        let (leaf2_hash, leaf2_data) = valid_leaf(b"leaf2", 0x22);
        source.store(&leaf1_hash, &leaf1_data).unwrap();
        source.store(&leaf2_hash, &leaf2_data).unwrap();

        // Create inner node pointing to both leaves (slots 0 and 1)
        let (root_hash, inner_data) = valid_inner(&[leaf1_hash, leaf2_hash]);
        source.store(&root_hash, &inner_data).unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let result = compact_nodestore(&source, root_hash, &tmp.path().join("out")).unwrap();
        assert_eq!(result.inner_nodes, 1);
        assert_eq!(result.leaf_nodes, 2);
        assert_eq!(result.total, 3);
    }

    #[test]
    fn test_verify_nodestore_detects_all_reachable_nodes() {
        let source = Arc::new(MemNodeStore::new()) as Arc<dyn NodeStore>;
        let (leaf_hash, leaf_data) = valid_leaf(b"leaf", 0x33);
        source.store(&leaf_hash, &leaf_data).unwrap();
        let (root_hash, root_data) = valid_inner(&[leaf_hash]);
        source.store(&root_hash, &root_data).unwrap();

        let result = verify_nodestore(&source, root_hash).unwrap();
        assert_eq!(result.inner_nodes, 1);
        assert_eq!(result.leaf_nodes, 1);
        assert_eq!(result.total, 2);
    }

    #[test]
    fn test_compact_exact_512_byte_leaf_is_not_classified_as_inner() {
        let source = Arc::new(MemNodeStore::new()) as Arc<dyn NodeStore>;
        let (hash, data) = valid_leaf(&vec![0xAA; 480], 0x66);
        assert_eq!(data.len(), 16 * 32);
        source.store(&hash, &data).unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let result = compact_nodestore(&source, hash, &tmp.path().join("out")).unwrap();
        assert_eq!(result.inner_nodes, 0);
        assert_eq!(result.leaf_nodes, 1);
        assert_eq!(result.total, 1);
    }

    #[test]
    fn test_verify_rejects_wrong_typed_transaction_leaf() {
        let source = Arc::new(MemNodeStore::new()) as Arc<dyn NodeStore>;
        let key = [0x77; 32];
        let tx = b"tx-no-meta";
        let mut payload = Vec::with_capacity(4 + tx.len() + key.len());
        payload.extend_from_slice(b"TXN\0");
        payload.extend_from_slice(tx);
        payload.extend_from_slice(&key);
        let hash = crate::crypto::sha512_first_half(&payload);

        let mut data = tx.to_vec();
        data.extend_from_slice(&key);
        source.store(&hash, &data).unwrap();

        let err = verify_nodestore(&source, hash).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_compact_from_shamap_walks_reachable_descendants() {
        let backend = Arc::new(MemNodeStore::new()) as Arc<dyn NodeStore>;
        let mut map = crate::ledger::shamap::SHAMap::with_backend(
            crate::ledger::shamap::MapType::AccountState,
            backend.clone(),
        );
        map.insert(crate::ledger::shamap::Key([0x10; 32]), b"alpha".to_vec());
        map.insert(crate::ledger::shamap::Key([0x11; 32]), b"beta".to_vec());
        map.root_hash();
        map.flush_dirty().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let result = compact_from_shamap(&backend, &map, &tmp.path().join("out")).unwrap();
        assert!(
            result.total > result.leaf_nodes,
            "compaction from a SHAMap must preserve reachable inner nodes too",
        );
    }

    #[test]
    fn test_compact_deduplicates_repeated_child_hashes() {
        let source = Arc::new(MemNodeStore::new()) as Arc<dyn NodeStore>;
        let (leaf_hash, leaf_data) = valid_leaf(b"leaf", 0x55);
        source.store(&leaf_hash, &leaf_data).unwrap();

        let (root_hash, root_data) = valid_inner(&[leaf_hash, leaf_hash]);
        source.store(&root_hash, &root_data).unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let result = compact_nodestore(&source, root_hash, &tmp.path().join("out")).unwrap();
        assert_eq!(result.inner_nodes, 1);
        assert_eq!(result.leaf_nodes, 1);
        assert_eq!(result.total, 2);
    }
}
