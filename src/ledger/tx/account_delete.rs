//! AccountDelete — remove an account and transfer remaining XRP.

use super::ApplyResult;
use crate::ledger::account::{LSF_DEPOSIT_AUTH, LSF_PASSWORD_SPENT, LSF_REQUIRE_DEST_TAG};
use crate::ledger::{directory, Key, LedgerState};
use crate::transaction::ParsedTx;

const MAX_DELETABLE_DIR_ENTRIES: usize = 1000;

fn owner_dir_entries(state: &LedgerState, account: &[u8; 20]) -> Vec<Key> {
    let root = directory::owner_dir_key(account);
    let Some(_) = directory::load_directory_fresh(state, &root) else {
        return Vec::new();
    };

    let mut entries = Vec::new();
    let mut page_num = 0u64;
    loop {
        let page_key = directory::page_key(&root.0, page_num);
        let Some(page) = directory::load_directory_fresh(state, &page_key) else {
            break;
        };

        entries.extend(page.indexes.into_iter().map(Key));

        if page.index_next == 0 || page.index_next == page_num {
            break;
        }
        page_num = page.index_next;
    }
    entries
}

fn load_owned_sle(state: &LedgerState, key: &Key) -> Option<Vec<u8>> {
    state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))
}

fn non_obligation_deletable(entry_type: u16) -> bool {
    matches!(
        entry_type,
        0x006F | // Offer
        0x0053 | // SignerList
        0x0054 | // Ticket
        0x0070 | // DepositPreauth
        0x0037 | // NFTokenOffer
        0x0049 | // DID
        0x0080 | // Oracle
        0x0081 | // Credential
        0x0083 // Delegate
    )
}

fn validate_deletable_owned_objects(state: &LedgerState, account: &[u8; 20]) -> ApplyResult {
    let mut deletable_count = 0usize;
    for key in owner_dir_entries(state, account) {
        let Some(raw) = load_owned_sle(state, &key) else {
            return ApplyResult::ClaimedCost("tefBAD_LEDGER");
        };
        let Some(parsed) = crate::ledger::meta::parse_sle(&raw) else {
            return ApplyResult::ClaimedCost("tefBAD_LEDGER");
        };

        if !non_obligation_deletable(parsed.entry_type) {
            return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
        }

        deletable_count += 1;
        if deletable_count > MAX_DELETABLE_DIR_ENTRIES {
            return ApplyResult::ClaimedCost("tefTOO_BIG");
        }
    }

    ApplyResult::Success
}

fn parsed_account(
    fields: &[crate::ledger::meta::ParsedField],
    field_code: u16,
) -> Option<[u8; 20]> {
    fields.iter().find_map(|field| {
        (field.type_code == 8 && field.field_code == field_code && field.data.len() == 20).then(
            || {
                let mut account = [0u8; 20];
                account.copy_from_slice(&field.data);
                account
            },
        )
    })
}

fn parsed_hash256(
    fields: &[crate::ledger::meta::ParsedField],
    field_code: u16,
) -> Option<[u8; 32]> {
    fields.iter().find_map(|field| {
        (field.type_code == 5 && field.field_code == field_code && field.data.len() == 32).then(
            || {
                let mut value = [0u8; 32];
                value.copy_from_slice(&field.data);
                value
            },
        )
    })
}

fn parsed_u32(fields: &[crate::ledger::meta::ParsedField], field_code: u16) -> Option<u32> {
    fields.iter().find_map(|field| {
        if field.type_code == 2 && field.field_code == field_code && field.data.len() >= 4 {
            Some(u32::from_be_bytes(field.data[..4].try_into().ok()?))
        } else {
            None
        }
    })
}

fn parsed_u64(fields: &[crate::ledger::meta::ParsedField], field_code: u16) -> Option<u64> {
    fields.iter().find_map(|field| {
        if field.type_code == 3 && field.field_code == field_code && field.data.len() >= 8 {
            Some(u64::from_be_bytes(field.data[..8].try_into().ok()?))
        } else {
            None
        }
    })
}

fn parsed_flags(fields: &[crate::ledger::meta::ParsedField]) -> u32 {
    parsed_u32(fields, 2).unwrap_or(0)
}

fn account_raw_u32(
    state: &LedgerState,
    account: &crate::ledger::AccountRoot,
    field_code: u16,
) -> Option<u32> {
    let raw = account.raw_sle.clone().or_else(|| {
        let key = crate::ledger::account::shamap_key(&account.account_id);
        state
            .get_raw_owned(&key)
            .or_else(|| state.get_committed_raw_owned(&key))
    })?;
    let parsed = crate::ledger::meta::parse_sle(&raw)?;
    parsed_u32(&parsed.fields, field_code)
}

fn remove_from_owner_dir(state: &mut LedgerState, owner: &[u8; 20], key: &Key, owner_node: u64) {
    let root = directory::owner_dir_key(owner);
    directory::dir_remove_root_page(state, &root, owner_node, &key.0);
}

fn remove_offer_books(
    state: &mut LedgerState,
    key: &Key,
    fields: &[crate::ledger::meta::ParsedField],
) {
    if let Some(book_directory) = parsed_hash256(fields, 16) {
        let book_node = parsed_u64(fields, 3).unwrap_or(0);
        let root = Key(book_directory);
        if !directory::dir_remove_root_page(state, &root, book_node, &key.0) {
            directory::dir_remove_root(state, &root, &key.0);
        }
    }

    if let Some(additional_books) = fields
        .iter()
        .find(|field| field.type_code == 15 && field.field_code == 13)
    {
        for (book_directory, book_node) in
            crate::ledger::offer::additional_book_entries_from_payload(&additional_books.data)
        {
            let root = Key(book_directory);
            if !directory::dir_remove_root_page(state, &root, book_node, &key.0) {
                directory::dir_remove_root(state, &root, &key.0);
            }
        }
    }
}

fn decrement_existing_owner_count(state: &mut LedgerState, account: &[u8; 20]) {
    if let Some(mut owner) = state.get_account(account).cloned() {
        owner.owner_count = owner.owner_count.saturating_sub(1);
        state.insert_account(owner);
    }
}

fn delete_credential(
    state: &mut LedgerState,
    key: &Key,
    fields: &[crate::ledger::meta::ParsedField],
) {
    let accepted = (parsed_flags(fields) & super::credential::LSF_ACCEPTED) != 0;
    let issuer = parsed_account(fields, 4);
    let subject = parsed_account(fields, 24);
    let (Some(issuer), Some(subject)) = (issuer, subject) else {
        state.remove_raw(key);
        return;
    };

    let issuer_node = parsed_u64(fields, 27).unwrap_or(0);
    let subject_node = parsed_u64(fields, 28).unwrap_or(0);

    directory::dir_remove_owner_page(state, &issuer, issuer_node, &key.0);
    if !accepted || subject == issuer {
        decrement_existing_owner_count(state, &issuer);
    }

    if subject != issuer {
        directory::dir_remove_owner_page(state, &subject, subject_node, &key.0);
        if accepted {
            decrement_existing_owner_count(state, &subject);
        }
    }

    state.remove_raw(key);
}

fn delete_owned_entry(
    state: &mut LedgerState,
    account: &[u8; 20],
    key: &Key,
    raw: &[u8],
) -> ApplyResult {
    let Some(parsed) = crate::ledger::meta::parse_sle(raw) else {
        return ApplyResult::ClaimedCost("tefBAD_LEDGER");
    };

    let owner_node = match parsed.entry_type {
        0x0037 => parsed_u64(&parsed.fields, 12).unwrap_or(0), // NFTokenOffer::OwnerNode
        _ => parsed_u64(&parsed.fields, 4).unwrap_or(0),
    };

    match parsed.entry_type {
        0x006F => {
            remove_from_owner_dir(state, account, key, owner_node);
            remove_offer_books(state, key, &parsed.fields);
            state.remove_offer(key);
            state.remove_raw(key);
        }
        0x0081 => delete_credential(state, key, &parsed.fields),
        _ => {
            remove_from_owner_dir(state, account, key, owner_node);
            match parsed.entry_type {
                0x0070 => {
                    state.remove_deposit_preauth(key);
                }
                0x0049 => {
                    state.remove_did(key);
                }
                0x0054 => {
                    state.remove_ticket(key);
                }
                0x0037 => {
                    state.remove_nft_offer(key);
                }
                _ => {}
            }
            state.remove_raw(key);
        }
    }

    ApplyResult::Success
}

fn cleanup_on_account_delete(state: &mut LedgerState, account: &[u8; 20]) -> ApplyResult {
    let entries = owner_dir_entries(state, account);
    for key in entries {
        let Some(raw) = load_owned_sle(state, &key) else {
            return ApplyResult::ClaimedCost("tefBAD_LEDGER");
        };
        let result = delete_owned_entry(state, account, &key, &raw);
        if result != ApplyResult::Success {
            return result;
        }
    }

    let owner_root = directory::owner_dir_key(account);
    if directory::owner_dir_entry_count(state, account) == 0 {
        state.remove_directory_any(&owner_root);
    }
    if directory::load_directory_fresh(state, &owner_root).is_some() {
        return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
    }

    ApplyResult::Success
}

pub(crate) fn apply_account_delete(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    ctx: &super::TxContext,
) -> ApplyResult {
    let destination = match tx.destination {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temDST_NEEDED"),
    };

    if destination == tx.account {
        return ApplyResult::ClaimedCost("temDST_IS_SRC");
    }

    if let Some(code) = super::credential::check_credential_id_fields(tx) {
        return ApplyResult::ClaimedCost(code);
    }

    let transfer = new_sender.balance;
    let existing_destination = match super::load_existing_account(state, &destination) {
        Some(account) => account,
        None => return ApplyResult::ClaimedCost("tecNO_DST"),
    };
    if (existing_destination.flags & LSF_REQUIRE_DEST_TAG) != 0 && tx.destination_tag.is_none() {
        return ApplyResult::ClaimedCost("tecDST_TAG_NEEDED");
    }
    if let Err(code) = super::credential::validate_credential_ids(state, &tx.account, tx) {
        return ApplyResult::ClaimedCost(code);
    }
    let has_credential_ids = crate::transaction::parse::parsed_credential_ids_present(tx);
    if (existing_destination.flags & LSF_DEPOSIT_AUTH) != 0 && !has_credential_ids {
        let preauth_key = crate::ledger::deposit_preauth::shamap_key(&destination, &tx.account);
        if !state.has_deposit_preauth(&preauth_key)
            && state.get_raw_owned(&preauth_key).is_none()
            && state.get_committed_raw_owned(&preauth_key).is_none()
        {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
    }

    if new_sender.minted_nftokens != new_sender.burned_nftokens {
        return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
    }
    if state.nft_page_count(&tx.account) > 0 {
        return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
    }

    let account_sequence = if tx.sequence != 0 {
        new_sender.sequence.saturating_sub(1)
    } else {
        new_sender.sequence
    };
    if ctx.ledger_seq > 0 && account_sequence.saturating_add(255) > ctx.ledger_seq {
        return ApplyResult::ClaimedCost("tecTOO_SOON");
    }
    let first_nft_sequence = account_raw_u32(state, new_sender, 50).unwrap_or(0);
    let next_nft_sequence = first_nft_sequence.wrapping_add(new_sender.minted_nftokens);
    if ctx.ledger_seq > 0 && next_nft_sequence.wrapping_add(255) > ctx.ledger_seq {
        return ApplyResult::ClaimedCost("tecTOO_SOON");
    }

    let result = validate_deletable_owned_objects(state, &tx.account);
    if result != ApplyResult::Success {
        return result;
    }

    if has_credential_ids {
        if super::credential::remove_expired_credential_ids(state, tx, ctx.close_time) {
            return ApplyResult::ClaimedCost("tecEXPIRED");
        }
        if (existing_destination.flags & LSF_DEPOSIT_AUTH) != 0 {
            match super::credential::credential_deposit_preauth_authorized(
                state,
                &destination,
                &tx.account,
                tx,
                ctx.close_time,
            ) {
                Ok(true) => {}
                Ok(false) => return ApplyResult::ClaimedCost("tecNO_PERMISSION"),
                Err(code) => return ApplyResult::ClaimedCost(code),
            }
        }
    }

    let result = cleanup_on_account_delete(state, &tx.account);
    if result != ApplyResult::Success {
        return result;
    }

    new_sender.balance = 0;

    let mut dest = existing_destination;
    dest.balance = dest.balance.saturating_add(transfer);
    if transfer > 0 {
        dest.flags &= !LSF_PASSWORD_SPENT;
    }
    state.insert_account(dest);

    state.remove_account(&tx.account);
    ApplyResult::Success
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::AccountRoot;

    fn account(id: [u8; 20], balance: u64, sequence: u32, owner_count: u32) -> AccountRoot {
        AccountRoot {
            account_id: id,
            balance,
            sequence,
            owner_count,
            flags: 0,
            regular_key: None,
            minted_nftokens: 0,
            first_nftoken_sequence: 0,
            burned_nftokens: 0,
            transfer_rate: 0,
            domain: Vec::new(),
            tick_size: 0,
            ticket_count: 0,
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        }
    }

    fn account_delete_tx(source: [u8; 20], destination: [u8; 20]) -> ParsedTx {
        ParsedTx {
            tx_type: 21,
            account: source,
            destination: Some(destination),
            ..ParsedTx::default()
        }
    }

    fn deposit_preauth_sle(account: [u8; 20], authorized: [u8; 20]) -> Vec<u8> {
        crate::ledger::meta::build_sle(
            0x0070,
            &[
                crate::ledger::meta::ParsedField {
                    type_code: 8,
                    field_code: 1,
                    data: account.to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 8,
                    field_code: 5,
                    data: authorized.to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 3,
                    field_code: 4,
                    data: 0u64.to_be_bytes().to_vec(),
                },
            ],
            None,
            None,
        )
    }

    fn account_sle_with_first_nft_sequence(
        id: [u8; 20],
        balance: u64,
        sequence: u32,
        owner_count: u32,
        minted_nftokens: u32,
        burned_nftokens: u32,
        first_nft_sequence: u32,
    ) -> Vec<u8> {
        crate::ledger::meta::build_sle(
            0x0061,
            &[
                crate::ledger::meta::ParsedField {
                    type_code: 2,
                    field_code: 4,
                    data: sequence.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 2,
                    field_code: 13,
                    data: owner_count.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 2,
                    field_code: 43,
                    data: minted_nftokens.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 2,
                    field_code: 44,
                    data: burned_nftokens.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 2,
                    field_code: 50,
                    data: first_nft_sequence.to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 6,
                    field_code: 2,
                    data: (0x4000_0000_0000_0000u64 | balance).to_be_bytes().to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 8,
                    field_code: 1,
                    data: id.to_vec(),
                },
            ],
            None,
            None,
        )
    }

    fn ripple_state_sle(low: [u8; 20], high: [u8; 20]) -> Vec<u8> {
        crate::ledger::meta::build_sle(
            0x0072,
            &[
                crate::ledger::meta::ParsedField {
                    type_code: 8,
                    field_code: 1,
                    data: low.to_vec(),
                },
                crate::ledger::meta::ParsedField {
                    type_code: 8,
                    field_code: 2,
                    data: high.to_vec(),
                },
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
            ],
            None,
            None,
        )
    }

    #[test]
    fn account_delete_auto_cleans_deposit_preauth_owner_entry() {
        let source = [1u8; 20];
        let destination = [2u8; 20];
        let authorized = [3u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(source, 1_000, 1, 1));
        state.insert_account(account(destination, 50, 1, 0));

        let owned_key = Key([9u8; 32]);
        directory::dir_add(&mut state, &source, owned_key.0);
        state.insert_raw(owned_key, deposit_preauth_sle(source, authorized));

        let tx = account_delete_tx(source, destination);
        let mut new_sender = state.get_account(&source).unwrap().clone();
        let ctx = super::super::TxContext {
            ledger_seq: 300,
            ..super::super::TxContext::default()
        };

        assert_eq!(
            apply_account_delete(&mut state, &tx, &mut new_sender, &ctx),
            ApplyResult::Success
        );
        assert!(state.get_account(&source).is_none());
        assert_eq!(state.get_account(&destination).unwrap().balance, 1_050);
        assert!(state.get_raw_owned(&owned_key).is_none());
        assert!(
            directory::load_directory_fresh(&state, &directory::owner_dir_key(&source)).is_none()
        );
    }

    #[test]
    fn account_delete_rejects_owner_directory_obligation() {
        let source = [4u8; 20];
        let destination = [5u8; 20];
        let mut state = LedgerState::new();
        state.insert_account(account(source, 1_000, 1, 1));
        state.insert_account(account(destination, 50, 1, 0));

        let owned_key = Key([8u8; 32]);
        directory::dir_add(&mut state, &source, owned_key.0);
        state.insert_raw(owned_key, ripple_state_sle(source, destination));

        let tx = account_delete_tx(source, destination);
        let mut new_sender = state.get_account(&source).unwrap().clone();
        let ctx = super::super::TxContext {
            ledger_seq: 300,
            ..super::super::TxContext::default()
        };

        assert_eq!(
            apply_account_delete(&mut state, &tx, &mut new_sender, &ctx),
            ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS")
        );
        assert!(state.get_account(&source).is_some());
        assert!(state.get_raw_owned(&owned_key).is_some());
    }

    #[test]
    fn account_delete_rejects_recent_nft_sequence_window_from_raw_account() {
        let source = [6u8; 20];
        let destination = [7u8; 20];
        let mut state = LedgerState::new();
        let mut source_account = account(source, 1_000, 1, 0);
        source_account.minted_nftokens = 1;
        source_account.burned_nftokens = 1;
        source_account.raw_sle = Some(account_sle_with_first_nft_sequence(
            source, 1_000, 1, 0, 1, 1, 300,
        ));
        state.insert_account(source_account);
        state.insert_account(account(destination, 50, 1, 0));

        let tx = account_delete_tx(source, destination);
        let mut new_sender = state.get_account(&source).unwrap().clone();
        let ctx = super::super::TxContext {
            ledger_seq: 500,
            ..super::super::TxContext::default()
        };

        assert_eq!(
            apply_account_delete(&mut state, &tx, &mut new_sender, &ctx),
            ApplyResult::ClaimedCost("tecTOO_SOON")
        );
        assert!(state.get_account(&source).is_some());
        assert_eq!(state.get_account(&destination).unwrap().balance, 50);
    }
}
