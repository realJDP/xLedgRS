//! Mainnet Credential SLE node-field parity regressions.

use xrpl::crypto::keys::{KeyPair, Secp256k1KeyPair};
use xrpl::ledger::directory;
use xrpl::ledger::ter::ApplyFlags;
use xrpl::ledger::tx::{run_tx, TxContext};
use xrpl::ledger::{AccountRoot, LedgerState};
use xrpl::transaction::{builder::TxBuilder, parse_blob, ParsedTx};

const XRP: u64 = 1_000_000;
const BASE_FEE: u64 = 10;
const LSF_ACCEPTED: u32 = 0x0001_0000;

fn pctx(close_time: u64) -> TxContext {
    TxContext {
        close_time,
        ..TxContext::default()
    }
}

fn keypair(seed_byte: u8) -> KeyPair {
    KeyPair::Secp256k1(Secp256k1KeyPair::from_seed_entropy(&[seed_byte; 16]))
}

fn account_id(kp: &KeyPair) -> [u8; 20] {
    xrpl::crypto::account_id(&kp.public_key_bytes())
}

fn account(account_id: [u8; 20], owner_count: u32) -> AccountRoot {
    AccountRoot {
        account_id,
        balance: 100_000 * XRP,
        sequence: 1,
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

fn enable_credentials(state: &mut LedgerState) {
    state.enable_amendment(xrpl::crypto::sha512_first_half(b"Credentials"));
}

fn fill_owner_root_page(state: &mut LedgerState, owner: &[u8; 20], tag: u8) {
    for n in 0..directory::DIR_NODE_MAX_ENTRIES {
        let mut entry = [tag; 32];
        entry[31] = n as u8;
        assert_eq!(directory::dir_add(state, owner, entry), 0);
    }
}

fn signed_credential_create(
    kp: &KeyPair,
    seq: u32,
    subject: [u8; 20],
    credential_type: &[u8],
) -> ParsedTx {
    parse_blob(
        &TxBuilder::credential_create()
            .account(kp)
            .subject(subject)
            .credential_type(credential_type.to_vec())
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_credential_accept(
    kp: &KeyPair,
    seq: u32,
    issuer: [u8; 20],
    credential_type: &[u8],
) -> ParsedTx {
    parse_blob(
        &TxBuilder::credential_accept()
            .account(kp)
            .issuer(issuer)
            .credential_type(credential_type.to_vec())
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_credential_delete(
    kp: &KeyPair,
    seq: u32,
    subject: [u8; 20],
    issuer: [u8; 20],
    credential_type: &[u8],
) -> ParsedTx {
    parse_blob(
        &TxBuilder::credential_delete()
            .account(kp)
            .subject(subject)
            .issuer(issuer)
            .credential_type(credential_type.to_vec())
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn sle_u32_field(raw: &[u8], field_code: u16) -> u32 {
    let parsed = xrpl::ledger::meta::parse_sle(raw).expect("valid SLE");
    parsed
        .fields
        .iter()
        .find(|field| field.type_code == 2 && field.field_code == field_code)
        .map(|field| u32::from_be_bytes(field.data[..4].try_into().unwrap()))
        .unwrap_or(0)
}

fn sle_u64_field(raw: &[u8], field_code: u16) -> Option<u64> {
    let parsed = xrpl::ledger::meta::parse_sle(raw)?;
    parsed
        .fields
        .iter()
        .find(|field| field.type_code == 3 && field.field_code == field_code)
        .map(|field| u64::from_be_bytes(field.data[..8].try_into().unwrap()))
}

#[test]
fn non_self_issued_credential_stores_actual_owner_dir_pages_and_deletes_cleanly() {
    let issuer = keypair(0x11);
    let subject = keypair(0x22);
    let issuer_id = account_id(&issuer);
    let subject_id = account_id(&subject);
    let credential_type = b"KYC-PAGE";
    let mut state = LedgerState::new();
    enable_credentials(&mut state);
    state.insert_account(account(issuer_id, directory::DIR_NODE_MAX_ENTRIES as u32));
    state.insert_account(account(subject_id, directory::DIR_NODE_MAX_ENTRIES as u32));
    fill_owner_root_page(&mut state, &issuer_id, 0xA1);
    fill_owner_root_page(&mut state, &subject_id, 0xB2);

    let create = signed_credential_create(&issuer, 1, subject_id, credential_type);
    let result = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "credential create failed: {}",
        result.ter
    );

    let key = xrpl::ledger::keylet::credential(&subject_id, &issuer_id, credential_type).key;
    let raw = state.get_raw(&key).expect("credential SLE");
    assert_eq!(sle_u32_field(raw, 2), 0);
    assert_eq!(sle_u64_field(raw, 27), Some(1));
    assert_eq!(sle_u64_field(raw, 28), Some(1));
    assert_eq!(
        directory::owner_dir_page_for_entry(&state, &issuer_id, &key.0),
        Some(1)
    );
    assert_eq!(
        directory::owner_dir_page_for_entry(&state, &subject_id, &key.0),
        Some(1)
    );
    assert_eq!(
        state.get_account(&issuer_id).unwrap().owner_count,
        directory::DIR_NODE_MAX_ENTRIES as u32 + 1
    );
    assert_eq!(
        state.get_account(&subject_id).unwrap().owner_count,
        directory::DIR_NODE_MAX_ENTRIES as u32
    );

    let accept = signed_credential_accept(&subject, 1, issuer_id, credential_type);
    let result = run_tx(&mut state, &accept, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "credential accept failed: {}",
        result.ter
    );
    let raw = state.get_raw(&key).expect("accepted credential SLE");
    assert_eq!(sle_u32_field(raw, 2), LSF_ACCEPTED);
    assert_eq!(sle_u64_field(raw, 27), Some(1));
    assert_eq!(sle_u64_field(raw, 28), Some(1));
    assert_eq!(
        state.get_account(&issuer_id).unwrap().owner_count,
        directory::DIR_NODE_MAX_ENTRIES as u32
    );
    assert_eq!(
        state.get_account(&subject_id).unwrap().owner_count,
        directory::DIR_NODE_MAX_ENTRIES as u32 + 1
    );

    let delete = signed_credential_delete(&subject, 2, subject_id, issuer_id, credential_type);
    let result = run_tx(&mut state, &delete, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "credential delete failed: {}",
        result.ter
    );
    assert!(state.get_raw(&key).is_none());
    assert!(!directory::owner_dir_contains_entry(
        &state, &issuer_id, &key.0
    ));
    assert!(!directory::owner_dir_contains_entry(
        &state,
        &subject_id,
        &key.0
    ));
    assert_eq!(
        state.get_account(&issuer_id).unwrap().owner_count,
        directory::DIR_NODE_MAX_ENTRIES as u32
    );
    assert_eq!(
        state.get_account(&subject_id).unwrap().owner_count,
        directory::DIR_NODE_MAX_ENTRIES as u32
    );
}

#[test]
fn self_issued_credential_stores_issuer_page_only_and_delete_restores_owner_count() {
    let issuer = keypair(0x33);
    let issuer_id = account_id(&issuer);
    let credential_type = b"SELF-PAGE";
    let mut state = LedgerState::new();
    enable_credentials(&mut state);
    state.insert_account(account(issuer_id, directory::DIR_NODE_MAX_ENTRIES as u32));
    fill_owner_root_page(&mut state, &issuer_id, 0xC3);

    let create = signed_credential_create(&issuer, 1, issuer_id, credential_type);
    let result = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "self-issued create failed: {}",
        result.ter
    );

    let key = xrpl::ledger::keylet::credential(&issuer_id, &issuer_id, credential_type).key;
    let raw = state.get_raw(&key).expect("self-issued credential SLE");
    assert_eq!(sle_u32_field(raw, 2), LSF_ACCEPTED);
    assert_eq!(sle_u64_field(raw, 27), Some(1));
    assert_eq!(sle_u64_field(raw, 28), None);
    assert_eq!(
        directory::owner_dir_page_for_entry(&state, &issuer_id, &key.0),
        Some(1)
    );
    assert_eq!(
        state.get_account(&issuer_id).unwrap().owner_count,
        directory::DIR_NODE_MAX_ENTRIES as u32 + 1
    );

    let delete = signed_credential_delete(&issuer, 2, issuer_id, issuer_id, credential_type);
    let result = run_tx(&mut state, &delete, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "self-issued delete failed: {}",
        result.ter
    );
    assert!(state.get_raw(&key).is_none());
    assert!(!directory::owner_dir_contains_entry(
        &state, &issuer_id, &key.0
    ));
    assert_eq!(
        state.get_account(&issuer_id).unwrap().owner_count,
        directory::DIR_NODE_MAX_ENTRIES as u32
    );
}
