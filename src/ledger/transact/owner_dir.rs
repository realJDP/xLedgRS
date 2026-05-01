//! xLedgRS purpose: Owner Dir legacy transactor for XRPL transaction apply.
use std::sync::Arc;

use crate::ledger::directory::{DirectoryNode, DIR_NODE_MAX_ENTRIES};
use crate::ledger::keylet::{self, Keylet};
use crate::ledger::sle::{LedgerEntryType, SLE};
use crate::ledger::views::{ApplyView, ReadView};

fn read_directory(view: &dyn ReadView, keylet: &Keylet) -> Option<DirectoryNode> {
    view.read(keylet)
        .and_then(|sle| DirectoryNode::decode(sle.data(), keylet.key.0).ok())
}

fn upsert_directory(view: &mut dyn ApplyView, mut dir: DirectoryNode) {
    dir.raw_sle = None;
    let keylet = Keylet::new(crate::ledger::Key(dir.key), LedgerEntryType::DirectoryNode);
    let sle = Arc::new(SLE::new(
        keylet.key,
        LedgerEntryType::DirectoryNode,
        dir.to_sle_binary(),
    ));
    if view.read(&keylet).is_some() {
        let _ = view.peek(&keylet);
        view.update(sle);
    } else {
        view.insert(sle);
    }
}

pub(crate) fn dir_add(view: &mut dyn ApplyView, owner: &[u8; 20], entry_key: [u8; 32]) -> u64 {
    let root_keylet = keylet::owner_dir(owner);

    if read_directory(view, &root_keylet).is_none() {
        let mut root = DirectoryNode::new_owner_root(owner);
        root.indexes.push(entry_key);
        upsert_directory(view, root);
        return 0;
    }

    let root = read_directory(view, &root_keylet).expect("root checked above");
    let last_page_num = root.index_previous;
    let last_keylet = keylet::dir_page(&root_keylet.key.0, last_page_num);
    let last = match read_directory(view, &last_keylet) {
        Some(dir) => dir,
        None => {
            let mut updated = root;
            updated.indexes.push(entry_key);
            upsert_directory(view, updated);
            return 0;
        }
    };

    if last.indexes.len() < DIR_NODE_MAX_ENTRIES {
        let mut updated = last;
        updated.indexes.push(entry_key);
        upsert_directory(view, updated);
        return last_page_num;
    }

    let new_page_num = if last_page_num == 0 {
        if root.index_next == 0 {
            1
        } else {
            let mut highest = root.index_next;
            loop {
                let page_keylet = keylet::dir_page(&root_keylet.key.0, highest);
                match read_directory(view, &page_keylet) {
                    Some(page) if page.index_next != 0 => highest = page.index_next,
                    _ => break,
                }
            }
            highest + 1
        }
    } else {
        last_page_num + 1
    };

    let mut new_page = DirectoryNode::new_page(&root_keylet.key.0, new_page_num, Some(*owner));
    new_page.indexes.push(entry_key);
    if new_page_num != 1 {
        new_page.index_previous = last_page_num;
    }

    if last_page_num == 0 {
        let mut root_updated = root;
        root_updated.index_next = new_page_num;
        root_updated.index_previous = new_page_num;
        upsert_directory(view, root_updated);
    } else {
        let mut old_last = last;
        old_last.index_next = new_page_num;
        upsert_directory(view, old_last);

        let mut root_updated = root;
        root_updated.index_previous = new_page_num;
        upsert_directory(view, root_updated);
    }

    upsert_directory(view, new_page);
    new_page_num
}

pub(crate) fn dir_remove(view: &mut dyn ApplyView, owner: &[u8; 20], entry_key: &[u8; 32]) -> bool {
    let root_keylet = keylet::owner_dir(owner);
    if read_directory(view, &root_keylet).is_none() {
        return false;
    }

    let mut current_page_num = 0u64;
    loop {
        let page_keylet = keylet::dir_page(&root_keylet.key.0, current_page_num);
        let page = match read_directory(view, &page_keylet) {
            Some(page) => page,
            None => return false,
        };

        if let Some(idx) = page.indexes.iter().position(|k| k == entry_key) {
            let mut updated = page.clone();
            updated.indexes.remove(idx);

            if !updated.indexes.is_empty() {
                upsert_directory(view, updated);
                return true;
            }

            if current_page_num == 0 {
                let next = page.index_next;
                let prev = page.index_previous;
                if next == 0 && prev == 0 {
                    view.erase(&page_keylet.key);
                    return true;
                }

                if next == prev && next != 0 {
                    let last_keylet = keylet::dir_page(&root_keylet.key.0, next);
                    if let Some(last) = read_directory(view, &last_keylet) {
                        if last.indexes.is_empty() {
                            updated.index_next = 0;
                            updated.index_previous = 0;
                            upsert_directory(view, updated);
                            view.erase(&last_keylet.key);
                            return true;
                        }
                    }
                }

                upsert_directory(view, updated);
                return true;
            }

            let prev_page_num = page.index_previous;
            let next_page_num = page.index_next;

            let prev_keylet = keylet::dir_page(&root_keylet.key.0, prev_page_num);
            if let Some(mut prev_page) = read_directory(view, &prev_keylet) {
                prev_page.index_next = next_page_num;
                upsert_directory(view, prev_page);
            }

            let next_keylet = keylet::dir_page(&root_keylet.key.0, next_page_num);
            if let Some(mut next_page) = read_directory(view, &next_keylet) {
                next_page.index_previous = prev_page_num;
                upsert_directory(view, next_page);
            }

            view.erase(&page_keylet.key);
            return true;
        }

        if page.index_next == 0 || page.index_next == current_page_num {
            return false;
        }
        current_page_num = page.index_next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::apply_view_impl::ApplyViewImpl;
    use crate::ledger::ledger_core::ClosedLedger;
    use crate::ledger::open_view::OpenView;
    use crate::ledger::views::ApplyFlags;

    fn entry(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn dir_add_creates_root_and_dir_remove_deletes_it() {
        let owner = [0xAB; 20];
        let base = ClosedLedger::genesis();
        let mut open = OpenView::new(Arc::new(base));
        let mut view = ApplyViewImpl::new(&mut open, ApplyFlags::NONE);

        assert_eq!(dir_add(&mut view, &owner, entry(1)), 0);

        let root = read_directory(&view, &keylet::owner_dir(&owner)).unwrap();
        assert_eq!(root.indexes, vec![entry(1)]);

        assert!(dir_remove(&mut view, &owner, &entry(1)));
        assert!(read_directory(&view, &keylet::owner_dir(&owner)).is_none());
    }

    #[test]
    fn dir_add_overflow_creates_page_one() {
        let owner = [0xCD; 20];
        let base = ClosedLedger::genesis();
        let mut open = OpenView::new(Arc::new(base));
        let mut view = ApplyViewImpl::new(&mut open, ApplyFlags::NONE);

        for n in 0..(DIR_NODE_MAX_ENTRIES as u8) {
            assert_eq!(dir_add(&mut view, &owner, entry(n)), 0);
        }

        let page = dir_add(&mut view, &owner, entry(99));
        assert_eq!(page, 1);

        let root = read_directory(&view, &keylet::owner_dir(&owner)).unwrap();
        assert_eq!(root.index_next, 1);
        assert_eq!(root.index_previous, 1);

        let page_one = read_directory(&view, &keylet::dir_page(&root.key, 1)).unwrap();
        assert_eq!(page_one.indexes, vec![entry(99)]);
    }

    #[test]
    fn dir_remove_overflow_page_resets_root_links() {
        let owner = [0xEF; 20];
        let base = ClosedLedger::genesis();
        let mut open = OpenView::new(Arc::new(base));
        let mut view = ApplyViewImpl::new(&mut open, ApplyFlags::NONE);

        for n in 0..(DIR_NODE_MAX_ENTRIES as u8) {
            assert_eq!(dir_add(&mut view, &owner, entry(n)), 0);
        }
        assert_eq!(dir_add(&mut view, &owner, entry(99)), 1);

        assert!(dir_remove(&mut view, &owner, &entry(99)));

        let root = read_directory(&view, &keylet::owner_dir(&owner)).unwrap();
        assert_eq!(root.index_next, 0);
        assert_eq!(root.index_previous, 0);
        assert!(read_directory(&view, &keylet::dir_page(&root.key, 1)).is_none());
    }
}
