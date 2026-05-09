use xrpl::crypto::keys::{KeyPair, Secp256k1KeyPair};
use xrpl::ledger::directory::owner_dir_contains_entry;
use xrpl::ledger::ter::{self, ApplyFlags};
use xrpl::ledger::tx::{run_tx, TxContext};
use xrpl::ledger::{AccountRoot, LedgerState};
use xrpl::transaction::{builder::TxBuilder, parse_blob, Amount};

const XRP: u64 = 1_000_000;
const BASE_FEE: u64 = 10;

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

fn account_addr(kp: &KeyPair) -> String {
    xrpl::crypto::base58::encode_account(&account_id(kp))
}

fn account(account_id: [u8; 20], balance_xrp: u64) -> AccountRoot {
    AccountRoot {
        account_id,
        balance: balance_xrp * XRP,
        sequence: 1,
        owner_count: 0,
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

fn fund(state: &mut LedgerState, kp: &KeyPair, balance_xrp: u64) {
    state.insert_account(account(account_id(kp), balance_xrp));
}

fn parse_signed(signed: xrpl::transaction::builder::SignedTx) -> xrpl::transaction::ParsedTx {
    parse_blob(&signed.blob).unwrap()
}

fn setup_state() -> (LedgerState, KeyPair, KeyPair) {
    let mut state = LedgerState::new();
    let owner = keypair(15);
    let destination = keypair(25);
    fund(&mut state, &owner, 5_000);
    fund(&mut state, &destination, 5_000);
    (state, owner, destination)
}

fn create_escrow(
    state: &mut LedgerState,
    owner: &KeyPair,
    destination: &KeyPair,
    cancel_after: Option<u32>,
) {
    let mut builder = TxBuilder::escrow_create()
        .account(owner)
        .destination(&account_addr(destination))
        .unwrap()
        .amount(Amount::Xrp(1_000 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .finish_after(200);
    if let Some(cancel_after) = cancel_after {
        builder = builder.cancel_after(cancel_after);
    }
    let result = run_tx(
        state,
        &parse_signed(builder.sign(owner).unwrap()),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(
        result.ter.is_tes_success(),
        "escrow setup failed: {}",
        result.ter
    );
}

fn cancel_tx(owner: &KeyPair, sequence: u32) -> xrpl::transaction::ParsedTx {
    parse_signed(
        TxBuilder::escrow_cancel()
            .account(owner)
            .owner(account_id(owner))
            .offer_sequence(1)
            .fee(BASE_FEE)
            .sequence(sequence)
            .sign(owner)
            .unwrap(),
    )
}

#[test]
fn cancel_without_cancel_after_is_tec_no_permission() {
    let (mut state, owner, destination) = setup_state();
    create_escrow(&mut state, &owner, &destination, None);
    let escrow_key = xrpl::ledger::escrow::shamap_key(&account_id(&owner), 1);

    let result = run_tx(
        &mut state,
        &cancel_tx(&owner, 2),
        &pctx(1_000),
        ApplyFlags::NONE,
    );

    assert_eq!(result.ter, ter::TEC_NO_PERMISSION);
    assert!(result.applied, "tecNO_PERMISSION claims the cancel fee");
    assert!(state.get_escrow(&escrow_key).is_some());
    let owner_root = state.get_account(&account_id(&owner)).unwrap();
    assert_eq!(owner_root.sequence, 3);
    assert_eq!(owner_root.owner_count, 1);
}

#[test]
fn cancel_at_cancel_after_is_still_too_early() {
    let (mut state, owner, destination) = setup_state();
    create_escrow(&mut state, &owner, &destination, Some(300));
    let escrow_key = xrpl::ledger::escrow::shamap_key(&account_id(&owner), 1);

    let result = run_tx(
        &mut state,
        &cancel_tx(&owner, 2),
        &pctx(300),
        ApplyFlags::NONE,
    );

    assert_eq!(result.ter, ter::TEC_NO_PERMISSION);
    assert!(state.get_escrow(&escrow_key).is_some());
    assert_eq!(
        state.get_account(&account_id(&owner)).unwrap().owner_count,
        1
    );
}

#[test]
fn cancel_after_expiry_returns_xrp_to_owner() {
    let (mut state, owner, destination) = setup_state();
    create_escrow(&mut state, &owner, &destination, Some(300));
    let owner_after_create = state.get_account(&account_id(&owner)).unwrap().balance;

    let result = run_tx(
        &mut state,
        &cancel_tx(&owner, 2),
        &pctx(301),
        ApplyFlags::NONE,
    );

    assert_eq!(result.ter, ter::TES_SUCCESS);
    assert_eq!(
        state.get_account(&account_id(&owner)).unwrap().balance,
        owner_after_create + 1_000 * XRP - BASE_FEE
    );
}

#[test]
fn successful_cancel_removes_sle_and_owner_directory_entries() {
    let (mut state, owner, destination) = setup_state();
    create_escrow(&mut state, &owner, &destination, Some(300));
    let owner_id = account_id(&owner);
    let destination_id = account_id(&destination);
    let escrow_key = xrpl::ledger::escrow::shamap_key(&owner_id, 1);

    assert!(owner_dir_contains_entry(&state, &owner_id, &escrow_key.0));
    assert!(owner_dir_contains_entry(
        &state,
        &destination_id,
        &escrow_key.0
    ));

    let result = run_tx(
        &mut state,
        &cancel_tx(&owner, 2),
        &pctx(301),
        ApplyFlags::NONE,
    );

    assert_eq!(result.ter, ter::TES_SUCCESS);
    assert!(state.get_escrow(&escrow_key).is_none());
    assert!(!owner_dir_contains_entry(&state, &owner_id, &escrow_key.0));
    assert!(!owner_dir_contains_entry(
        &state,
        &destination_id,
        &escrow_key.0
    ));
    assert_eq!(state.get_account(&owner_id).unwrap().owner_count, 0);
}
