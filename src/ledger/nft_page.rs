//! NFTokenPage — page-based storage matching rippled's NFTokenPage SLE model.
//!
//! Each NFTokenPage holds up to 32 tokens, doubly-linked to adjacent pages.
//! Page key = owner(20 bytes) || (token_id & pageMask)(12 bytes) = 32 bytes.
//!
//! This module provides the page manipulation primitives: insert, remove,
//! split, merge. The actual SLE encoding uses the meta module's build_sle.
//!
//! Reference: rippled NFTokenUtils.cpp

use crate::ledger::Key;

/// Maximum NFTokens per page.
pub const MAX_TOKENS_PER_PAGE: usize = 32;

/// Page mask: low 96 bits (12 bytes) set to 0xFF.
const PAGE_MASK: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Compute the page key for an NFToken.
/// page_key = owner_prefix(20 bytes) || (token_id & pageMask)(12 bytes)
pub fn page_key_for_token(owner: &[u8; 20], token_id: &[u8; 32]) -> Key {
    let mut key = [0u8; 32];
    key[..20].copy_from_slice(owner);
    for i in 20..32 {
        key[i] = token_id[i] & PAGE_MASK[i];
    }
    Key(key)
}

/// Compute the minimum page key for an owner (all zeros in low 96 bits).
pub fn page_min(owner: &[u8; 20]) -> Key {
    let mut key = [0u8; 32];
    key[..20].copy_from_slice(owner);
    Key(key)
}

/// Compute the maximum page key for an owner (all ones in low 96 bits).
pub fn page_max(owner: &[u8; 20]) -> Key {
    let mut key = [0u8; 32];
    key[..20].copy_from_slice(owner);
    for i in 20..32 {
        key[i] = 0xFF;
    }
    Key(key)
}

/// An NFToken entry within a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageToken {
    pub nftoken_id: [u8; 32],
    pub uri: Option<Vec<u8>>,
}

/// Compare tokens for sorting: low 96 bits first, then full ID.
fn token_sort_key(id: &[u8; 32]) -> ([u8; 12], [u8; 32]) {
    let mut low96 = [0u8; 12];
    low96.copy_from_slice(&id[20..32]);
    (low96, *id)
}

impl Ord for PageToken {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        token_sort_key(&self.nftoken_id).cmp(&token_sort_key(&other.nftoken_id))
    }
}
impl PartialOrd for PageToken {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// An NFTokenPage — holds up to 32 tokens with optional prev/next links.
#[derive(Debug, Clone)]
pub struct NFTokenPage {
    pub key: Key,
    pub tokens: Vec<PageToken>,
    pub prev_page: Option<Key>,
    pub next_page: Option<Key>,
}

impl NFTokenPage {
    pub fn new(key: Key) -> Self {
        Self {
            key,
            tokens: Vec::new(),
            prev_page: None,
            next_page: None,
        }
    }

    /// Insert a token into this page, maintaining sorted order.
    /// Returns true if inserted, false if page is full.
    pub fn insert(&mut self, token: PageToken) -> bool {
        if self.tokens.len() >= MAX_TOKENS_PER_PAGE {
            return false;
        }
        let pos = self.tokens.binary_search(&token).unwrap_or_else(|p| p);
        self.tokens.insert(pos, token);
        true
    }

    /// Remove a token by ID. Returns the removed token or None.
    pub fn remove(&mut self, nftoken_id: &[u8; 32]) -> Option<PageToken> {
        if let Some(pos) = self.tokens.iter().position(|t| t.nftoken_id == *nftoken_id) {
            Some(self.tokens.remove(pos))
        } else {
            None
        }
    }

    /// Is this page empty?
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Number of tokens on this page.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Split this full page into two. Returns the new lower page.
    /// This page retains the upper half, matching rippled's NFTokenPage split
    /// where the newly-created page points to the existing page as next.
    pub fn split(&mut self) -> Option<NFTokenPage> {
        let mid = MAX_TOKENS_PER_PAGE / 2;
        let split_at = (mid..self.tokens.len())
            .find(|&i| self.tokens[i - 1].nftoken_id[20..32] != self.tokens[i].nftoken_id[20..32])
            .or_else(|| {
                (1..mid).rev().find(|&i| {
                    self.tokens[i - 1].nftoken_id[20..32] != self.tokens[i].nftoken_id[20..32]
                })
            })?;

        let upper_tokens: Vec<PageToken> = self.tokens.split_off(split_at);
        let lower_tokens = std::mem::replace(&mut self.tokens, upper_tokens);

        // New page key = boundary key derived from the first token retained in
        // the upper page. Tokens in the new lower page are strictly less than
        // this boundary.
        let new_key = if !self.tokens.is_empty() {
            let mut k = [0u8; 32];
            k[..20].copy_from_slice(&self.key.0[..20]); // same owner
            for i in 20..32 {
                k[i] = self.tokens[0].nftoken_id[i] & PAGE_MASK[i];
            }
            Key(k)
        } else {
            self.key // shouldn't happen
        };

        let mut new_page = NFTokenPage::new(new_key);
        new_page.tokens = lower_tokens;

        // Link: old previous -> new lower page -> existing upper page.
        new_page.prev_page = self.prev_page.take();
        new_page.next_page = Some(self.key);
        self.prev_page = Some(new_page.key);

        Some(new_page)
    }

    /// Can this page merge with another (combined size <= 32)?
    pub fn can_merge_with(&self, other: &NFTokenPage) -> bool {
        self.tokens.len() + other.tokens.len() <= MAX_TOKENS_PER_PAGE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token(id_byte: u8) -> PageToken {
        let mut id = [0u8; 32];
        id[31] = id_byte;
        PageToken {
            nftoken_id: id,
            uri: None,
        }
    }

    fn make_owner() -> [u8; 20] {
        [1u8; 20]
    }

    #[test]
    fn page_insert_maintains_order() {
        let mut page = NFTokenPage::new(page_max(&make_owner()));
        page.insert(make_token(3));
        page.insert(make_token(1));
        page.insert(make_token(2));

        assert_eq!(page.tokens[0].nftoken_id[31], 1);
        assert_eq!(page.tokens[1].nftoken_id[31], 2);
        assert_eq!(page.tokens[2].nftoken_id[31], 3);
    }

    #[test]
    fn page_insert_rejects_when_full() {
        let mut page = NFTokenPage::new(page_max(&make_owner()));
        for i in 0..MAX_TOKENS_PER_PAGE {
            assert!(page.insert(make_token(i as u8)));
        }
        assert!(!page.insert(make_token(99))); // 33rd token rejected
    }

    #[test]
    fn page_remove_by_id() {
        let mut page = NFTokenPage::new(page_max(&make_owner()));
        page.insert(make_token(1));
        page.insert(make_token(2));
        page.insert(make_token(3));

        let removed = page.remove(&make_token(2).nftoken_id);
        assert!(removed.is_some());
        assert_eq!(page.len(), 2);
        assert_eq!(page.tokens[0].nftoken_id[31], 1);
        assert_eq!(page.tokens[1].nftoken_id[31], 3);
    }

    #[test]
    fn page_split_at_midpoint() {
        let mut page = NFTokenPage::new(page_max(&make_owner()));
        for i in 0..MAX_TOKENS_PER_PAGE {
            page.insert(make_token(i as u8));
        }
        assert_eq!(page.len(), 32);

        let lower = page.split().expect("page has legal split");

        // Both halves should have tokens
        assert!(page.len() > 0);
        assert!(lower.len() > 0);
        assert_eq!(page.len() + lower.len(), 32);

        // Links should be set
        assert_eq!(lower.next_page, Some(page.key));
        assert_eq!(page.prev_page, Some(lower.key));
        assert!(lower.key < page.key);
    }

    #[test]
    fn page_split_rejects_all_equivalent_low96_tokens() {
        let mut page = NFTokenPage::new(page_max(&make_owner()));
        for i in 0..MAX_TOKENS_PER_PAGE {
            let mut token = make_token(7);
            token.nftoken_id[0] = i as u8;
            page.insert(token);
        }

        assert!(page.split().is_none());
        assert_eq!(page.len(), MAX_TOKENS_PER_PAGE);
    }

    #[test]
    fn page_key_derivation() {
        let owner = [0xAA; 20];
        let mut token_id = [0u8; 32];
        token_id[20..32].copy_from_slice(&[0x11; 12]);

        let pk = page_key_for_token(&owner, &token_id);
        // First 20 bytes = owner
        assert_eq!(&pk.0[..20], &owner);
        // Last 12 bytes = token low 96 bits masked
        assert_eq!(&pk.0[20..32], &[0x11; 12]);
    }

    #[test]
    fn page_min_max() {
        let owner = [0xBB; 20];
        let min = page_min(&owner);
        let max = page_max(&owner);

        assert_eq!(&min.0[..20], &owner);
        assert_eq!(&min.0[20..], &[0u8; 12]);
        assert_eq!(&max.0[..20], &owner);
        assert_eq!(&max.0[20..], &[0xFF; 12]);
    }
}
