//! xLedgRS purpose: Sparse Shamap support for XRPL ledger state and SHAMap logic.
//! Sparse SHAMap — inner nodes in RAM, leaf data on disk.
//!
//! Stores only the tree structure and hashes in memory (~500MB-1GB for 18.7M objects).
//! Leaf data lives in redb/SQLite storage and is read on demand.
//!
//! Leaf hash = SHA-512-half(MLN\0 + data + key)  — same as the full SHAMap
//! Inner hash = SHA-512-half(MIN\0 + child_hashes[0..16])

use crate::crypto::sha512_first_half;

const PREFIX_INNER: [u8; 4] = [0x4D, 0x49, 0x4E, 0x00]; // MIN\0
const PREFIX_LEAF: [u8; 4] = [0x4D, 0x4C, 0x4E, 0x00]; // MLN\0

/// Compute the leaf hash from raw SLE data and its 32-byte key.
pub fn leaf_hash(data: &[u8], key: &[u8; 32]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(4 + data.len() + 32);
    payload.extend_from_slice(&PREFIX_LEAF);
    payload.extend_from_slice(data);
    payload.extend_from_slice(key);
    sha512_first_half(&payload)
}

/// A sparse SHAMap that stores only hashes, not leaf data.
pub struct SparseSHAMap {
    root: InnerNode,
    count: usize,
}

struct InnerNode {
    children: [Child; 16],
    cached_hash: Option<[u8; 32]>,
}

enum Child {
    Empty,
    Leaf { key: [u8; 32], hash: [u8; 32] },
    Inner(Box<InnerNode>),
}

impl Default for Child {
    fn default() -> Self {
        Child::Empty
    }
}

impl InnerNode {
    fn new() -> Self {
        Self {
            children: Default::default(),
            cached_hash: None,
        }
    }

    fn invalidate(&mut self) {
        self.cached_hash = None;
    }

    fn hash(&mut self) -> [u8; 32] {
        if let Some(h) = self.cached_hash {
            return h;
        }
        let mut payload = Vec::with_capacity(4 + 16 * 32);
        payload.extend_from_slice(&PREFIX_INNER);
        for child in &mut self.children {
            let child_hash = match child {
                Child::Empty => [0u8; 32],
                Child::Leaf { hash, .. } => *hash,
                Child::Inner(inner) => inner.hash(),
            };
            payload.extend_from_slice(&child_hash);
        }
        let h = sha512_first_half(&payload);
        self.cached_hash = Some(h);
        h
    }
}

impl Default for InnerNode {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn nibble(key: &[u8; 32], depth: usize) -> usize {
    let byte = key[depth / 2];
    if depth % 2 == 0 {
        (byte >> 4) as usize
    } else {
        (byte & 0x0F) as usize
    }
}

impl SparseSHAMap {
    pub fn new() -> Self {
        Self {
            root: InnerNode::new(),
            count: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    /// Insert a leaf by its key and pre-computed hash.
    pub fn insert(&mut self, key: [u8; 32], hash: [u8; 32]) {
        let new = insert_recursive(&mut self.root, &key, hash, 0);
        if new {
            self.count += 1;
        }
    }

    /// Remove a leaf by key.
    pub fn remove(&mut self, key: &[u8; 32]) {
        if remove_recursive(&mut self.root, key, 0) {
            self.count -= 1;
        }
    }

    /// Look up the stored leaf hash for a key. Returns None if key not in tree.
    pub fn get_leaf_hash(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        let mut node = &self.root;
        for depth in 0..64 {
            let nib = nibble(key, depth);
            match &node.children[nib] {
                Child::Leaf { key: k, hash } if k == key => return Some(*hash),
                Child::Leaf { .. } => return None,
                Child::Inner(inner) => node = inner,
                Child::Empty => return None,
            }
        }
        None
    }

    /// Compute the root hash.
    pub fn root_hash(&mut self) -> [u8; 32] {
        self.root.hash()
    }

    /// Collect all leaf keys under a given nibble-prefix path.
    /// Used to enumerate leaves in a deleted subtree during diff sync.
    /// `nibbles` is a slice of nibble values (0-15), one per tree depth level.
    pub fn collect_keys_under_prefix(&self, nibbles: &[u8]) -> Vec<[u8; 32]> {
        let mut node = &self.root;
        for &nib in nibbles {
            match &node.children[nib as usize] {
                Child::Inner(inner) => node = inner,
                Child::Leaf { key, .. } => return vec![*key],
                Child::Empty => return vec![],
            }
        }
        let mut result = Vec::new();
        collect_leaves_recursive(node, &mut result);
        result
    }
}

fn collect_leaves_recursive(node: &InnerNode, out: &mut Vec<[u8; 32]>) {
    for child in &node.children {
        match child {
            Child::Empty => {}
            Child::Leaf { key, .. } => out.push(*key),
            Child::Inner(inner) => collect_leaves_recursive(inner, out),
        }
    }
}

fn insert_recursive(node: &mut InnerNode, key: &[u8; 32], hash: [u8; 32], depth: usize) -> bool {
    node.invalidate();
    let nib = nibble(key, depth);

    match &node.children[nib] {
        Child::Empty => {
            node.children[nib] = Child::Leaf { key: *key, hash };
            true
        }
        Child::Leaf { key: ek, .. } if ek == key => {
            // Update existing leaf
            node.children[nib] = Child::Leaf { key: *key, hash };
            false
        }
        Child::Leaf { .. } => {
            // Collision — extract existing, create inner, insert both
            let existing = std::mem::replace(&mut node.children[nib], Child::Empty);
            let (ek, eh) = match existing {
                Child::Leaf { key: k, hash: h } => (k, h),
                _ => unreachable!(),
            };
            let mut new_inner = Box::new(InnerNode::new());
            insert_recursive(&mut new_inner, &ek, eh, depth + 1);
            insert_recursive(&mut new_inner, key, hash, depth + 1);
            node.children[nib] = Child::Inner(new_inner);
            true
        }
        Child::Inner(_) => {
            if let Child::Inner(ref mut inner) = node.children[nib] {
                insert_recursive(inner, key, hash, depth + 1)
            } else {
                unreachable!()
            }
        }
    }
}

fn remove_recursive(node: &mut InnerNode, key: &[u8; 32], depth: usize) -> bool {
    node.invalidate();
    let nib = nibble(key, depth);

    match &node.children[nib] {
        Child::Empty => false,
        Child::Leaf { key: ek, .. } => {
            if ek == key {
                node.children[nib] = Child::Empty;
                true
            } else {
                false
            }
        }
        Child::Inner(_) => {
            let removed = if let Child::Inner(ref mut inner) = node.children[nib] {
                remove_recursive(inner, key, depth + 1)
            } else {
                false
            };
            if removed {
                // Collapse: if the inner node now has exactly one child and it's
                // a leaf, replace the inner node with that leaf. This matches
                // rippled's SHAMap behavior where single-child inner nodes are
                // collapsed to maintain correct hash computation.
                let should_collapse = if let Child::Inner(ref inner) = node.children[nib] {
                    let mut leaf_count = 0;
                    let mut inner_count = 0;
                    let mut sole_leaf = None;
                    for (_i, child) in inner.children.iter().enumerate() {
                        match child {
                            Child::Empty => {}
                            Child::Leaf { key: k, hash: h } => {
                                leaf_count += 1;
                                sole_leaf = Some((*k, *h));
                            }
                            Child::Inner(_) => {
                                inner_count += 1;
                            }
                        }
                    }
                    if leaf_count == 1 && inner_count == 0 {
                        sole_leaf
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some((k, h)) = should_collapse {
                    node.children[nib] = Child::Leaf { key: k, hash: h };
                }
            }
            removed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(val: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = val;
        k
    }

    fn test_data(val: u8) -> Vec<u8> {
        vec![val; 100]
    }

    #[test]
    fn test_empty_root_hash() {
        let mut map = SparseSHAMap::new();
        let hash = map.root_hash();
        // Empty inner node: SHA-512-half(MIN\0 + 16 * 32 zero bytes)
        assert_ne!(hash, [0u8; 32]); // not zero — has the prefix
    }

    #[test]
    fn test_insert_and_root_hash_changes() {
        let mut map = SparseSHAMap::new();
        let h1 = map.root_hash();
        let key = test_key(0xAB);
        let data = test_data(1);
        map.insert(key, leaf_hash(&data, &key));
        let h2 = map.root_hash();
        assert_ne!(h1, h2);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_same_hash_as_full_shamap() {
        // Verify sparse produces same root hash as the full SHAMap
        use crate::ledger::shamap::{Key, SHAMap};

        let mut full = SHAMap::new_state();
        let mut sparse = SparseSHAMap::new();

        for i in 0u8..50 {
            let mut k = [0u8; 32];
            k[0] = i;
            k[1] = i.wrapping_mul(7);
            let data = vec![i; 50 + i as usize];
            let lh = leaf_hash(&data, &k);

            full.insert(Key(k), data);
            sparse.insert(k, lh);
        }

        assert_eq!(full.root_hash(), sparse.root_hash());
    }

    #[test]
    fn test_remove() {
        let mut map = SparseSHAMap::new();
        let key = test_key(0x42);
        let data = test_data(2);
        map.insert(key, leaf_hash(&data, &key));
        assert_eq!(map.len(), 1);
        map.remove(&key);
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_update_leaf() {
        let mut map = SparseSHAMap::new();
        let key = test_key(0x42);
        map.insert(key, leaf_hash(&[1, 2, 3], &key));
        let h1 = map.root_hash();
        map.insert(key, leaf_hash(&[4, 5, 6], &key));
        let h2 = map.root_hash();
        assert_ne!(h1, h2);
        assert_eq!(map.len(), 1); // still 1, not 2
    }

    #[test]
    fn test_collision_split() {
        let mut map = SparseSHAMap::new();
        // Two keys with same first nibble
        let mut k1 = [0u8; 32];
        k1[0] = 0x10;
        let mut k2 = [0u8; 32];
        k2[0] = 0x11;
        map.insert(k1, leaf_hash(&[1], &k1));
        map.insert(k2, leaf_hash(&[2], &k2));
        assert_eq!(map.len(), 2);
    }
}
