//! SHAMapNodeID — position coordinate in the SHAMap tree.
//!
//! Encodes depth (0–64) + nibble path from root.
//! Used by the syncer to navigate the tree by position rather than by key.
//!
//! Wire format: 33 bytes = 32-byte path (masked to depth) + 1-byte depth.
//! Matches rippled's SHAMapNodeID exactly.

/// A position in the SHAMap tree: depth + path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SHAMapNodeID {
    /// Path from root — only the top `depth` nibbles are meaningful.
    /// Lower nibbles are zero-masked.
    id: [u8; 32],
    /// Tree depth (0 = root, max 64 for 32-byte keys × 2 nibbles/byte).
    depth: u8,
}

impl SHAMapNodeID {
    /// The root node (depth 0, all-zero path).
    pub fn root() -> Self {
        Self {
            id: [0u8; 32],
            depth: 0,
        }
    }

    /// Create from depth and path bytes.
    pub fn new(depth: u8, id: [u8; 32]) -> Self {
        let mut masked = id;
        // Zero-mask nibbles below depth
        mask_to_depth(&mut masked, depth);
        Self { id: masked, depth }
    }

    /// Create from a leaf key — depth 64 (full key).
    pub fn from_key(key: &[u8; 32]) -> Self {
        Self {
            id: *key,
            depth: 64,
        }
    }

    /// Deserialize from 33-byte wire format (32 path + 1 depth).
    pub fn from_wire(data: &[u8]) -> Option<Self> {
        if data.len() < 33 {
            return None;
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&data[..32]);
        let depth = data[32];
        if depth > 64 {
            return None;
        }
        Some(Self::new(depth, id))
    }

    /// Serialize to 33-byte wire format.
    pub fn to_wire(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[..32].copy_from_slice(&self.id);
        out[32] = self.depth;
        out
    }

    /// Tree depth (0 = root).
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// The path bytes.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Is this the root node?
    pub fn is_root(&self) -> bool {
        self.depth == 0
    }

    /// Which branch (0–15) to follow from this node toward `target`.
    /// Extracts the nibble at this node's depth from the target's path.
    pub fn select_branch(&self, target: &SHAMapNodeID) -> usize {
        nibble_at(&target.id, self.depth as usize)
    }

    /// Which branch to follow toward a leaf key.
    pub fn select_branch_for_key(&self, key: &[u8; 32]) -> usize {
        nibble_at(key, self.depth as usize)
    }

    /// Create the child node ID at the given branch (0–15).
    pub fn child_id(&self, branch: u8) -> Self {
        assert!(branch < 16);
        let mut child = self.id;
        let d = self.depth as usize;
        let byte_idx = d / 2;
        if byte_idx < 32 {
            if d % 2 == 0 {
                // Set upper nibble
                child[byte_idx] = (child[byte_idx] & 0x0F) | (branch << 4);
            } else {
                // Set lower nibble
                child[byte_idx] = (child[byte_idx] & 0xF0) | branch;
            }
        }
        Self {
            id: child,
            depth: self.depth + 1,
        }
    }
}

/// Extract nibble (0–15) at position `depth` from a 32-byte path.
fn nibble_at(data: &[u8; 32], depth: usize) -> usize {
    if depth >= 64 {
        return 0;
    }
    let byte = data[depth / 2];
    if depth % 2 == 0 {
        (byte >> 4) as usize
    } else {
        (byte & 0x0F) as usize
    }
}

/// Zero-mask all nibbles below `depth`.
fn mask_to_depth(data: &mut [u8; 32], depth: u8) {
    let d = depth as usize;
    let full_bytes = d / 2;
    if d % 2 == 1 && full_bytes < 32 {
        // Keep upper nibble, clear lower
        data[full_bytes] &= 0xF0;
    }
    // Clear all bytes after
    let start = if d % 2 == 0 {
        full_bytes
    } else {
        full_bytes + 1
    };
    for b in data.iter_mut().skip(start) {
        *b = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_zero() {
        let r = SHAMapNodeID::root();
        assert_eq!(r.depth(), 0);
        assert_eq!(r.id(), &[0u8; 32]);
        assert!(r.is_root());
    }

    #[test]
    fn child_id_sets_nibble() {
        let root = SHAMapNodeID::root();
        let child = root.child_id(0xA);
        assert_eq!(child.depth(), 1);
        assert_eq!(child.id()[0], 0xA0); // upper nibble = A, lower = 0

        let grandchild = child.child_id(0x5);
        assert_eq!(grandchild.depth(), 2);
        assert_eq!(grandchild.id()[0], 0xA5); // upper = A, lower = 5
    }

    #[test]
    fn select_branch_extracts_nibble() {
        let root = SHAMapNodeID::root();
        let mut target_id = [0u8; 32];
        target_id[0] = 0xBC;
        let target = SHAMapNodeID::new(2, target_id);

        assert_eq!(root.select_branch(&target), 0xB); // depth 0 → upper nibble
        let child = root.child_id(0xB);
        assert_eq!(child.select_branch(&target), 0xC); // depth 1 → lower nibble
    }

    #[test]
    fn wire_roundtrip() {
        let node = SHAMapNodeID::root().child_id(3).child_id(14).child_id(7);
        let wire = node.to_wire();
        let decoded = SHAMapNodeID::from_wire(&wire).unwrap();
        assert_eq!(decoded, node);
    }

    #[test]
    fn from_key_is_depth_64() {
        let key = [0xFF; 32];
        let node = SHAMapNodeID::from_key(&key);
        assert_eq!(node.depth(), 64);
        assert_eq!(node.id(), &key);
    }

    #[test]
    fn mask_clears_lower_nibbles() {
        let mut data = [0xFF; 32];
        mask_to_depth(&mut data, 3);
        assert_eq!(data[0], 0xFF); // nibbles 0,1 preserved
        assert_eq!(data[1], 0xF0); // nibble 2 preserved, nibble 3 cleared
        assert_eq!(data[2], 0x00); // rest cleared
    }

    #[test]
    fn select_branch_for_key() {
        let root = SHAMapNodeID::root();
        let key = [0xAB; 32];
        assert_eq!(root.select_branch_for_key(&key), 0xA);

        let child = root.child_id(0xA);
        assert_eq!(child.select_branch_for_key(&key), 0xB);
    }
}
