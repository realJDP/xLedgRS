use xrpl::crypto::keys::{KeyPair, Secp256k1KeyPair};
use xrpl::ledger::ter::{self, ApplyFlags};
use xrpl::ledger::tx::{run_tx, TxContext};
use xrpl::ledger::{AccountRoot, LedgerState};
use xrpl::transaction::builder::TxBuilder;
use xrpl::transaction::parse::ParsedTx;
use xrpl::transaction::{parse_blob, Amount};

const XRP: u64 = 1_000_000;
const BASE_FEE: u64 = 10;
const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;
const LSF_DEPOSIT_AUTH: u32 = 0x0100_0000;
const LSF_MPT_CAN_TRANSFER: u32 = 0x0000_0020;

fn pctx(close_time: u64) -> TxContext {
    TxContext {
        close_time,
        ..TxContext::default()
    }
}

fn kp_alice() -> KeyPair {
    KeyPair::Secp256k1(Secp256k1KeyPair::from_seed_entropy(&[1u8; 16]))
}

fn kp_bob() -> KeyPair {
    KeyPair::Secp256k1(Secp256k1KeyPair::from_seed_entropy(&[99u8; 16]))
}

fn kp_carol() -> KeyPair {
    KeyPair::Secp256k1(Secp256k1KeyPair::from_seed_entropy(&[42u8; 16]))
}

fn account_id(kp: &KeyPair) -> [u8; 20] {
    xrpl::crypto::account_id(&kp.public_key_bytes())
}

fn make_account(account_id: [u8; 20], balance: u64) -> AccountRoot {
    AccountRoot {
        account_id,
        balance,
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

fn enable_mainnet_mpt_amendments(state: &mut LedgerState) {
    for name in ["MPTokensV1", "Credentials"] {
        state.enable_amendment(xrpl::crypto::sha512_first_half(name.as_bytes()));
    }
}

fn fund(state: &mut LedgerState, kp: &KeyPair, balance_xrp: u64) {
    enable_mainnet_mpt_amendments(state);
    state.insert_account(make_account(account_id(kp), balance_xrp * XRP));
}

fn make_mptid(seq: u32, account: &[u8; 20]) -> [u8; 24] {
    let mut id = [0u8; 24];
    id[0..4].copy_from_slice(&seq.to_be_bytes());
    id[4..24].copy_from_slice(account);
    id
}

fn mpt_issuance_key_for(mptid: &[u8; 24]) -> xrpl::ledger::Key {
    let mut data = Vec::with_capacity(26);
    data.extend_from_slice(&[0x00, 0x7E]);
    data.extend_from_slice(mptid);
    xrpl::ledger::Key(xrpl::crypto::sha512_first_half(&data))
}

fn mpt_holder_key_for(mptid: &[u8; 24], holder: &[u8; 20]) -> xrpl::ledger::Key {
    let issuance_key = mpt_issuance_key_for(mptid);
    let mut data = Vec::with_capacity(54);
    data.extend_from_slice(&[0x00, 0x74]);
    data.extend_from_slice(&issuance_key.0);
    data.extend_from_slice(holder);
    xrpl::ledger::Key(xrpl::crypto::sha512_first_half(&data))
}

fn sle_u64(raw: &[u8], field_code: u16) -> u64 {
    xrpl::ledger::meta::parse_sle(raw)
        .and_then(|sle| {
            sle.fields.into_iter().find_map(|field| {
                (field.type_code == 3 && field.field_code == field_code && field.data.len() >= 8)
                    .then(|| {
                        u64::from_be_bytes([
                            field.data[0],
                            field.data[1],
                            field.data[2],
                            field.data[3],
                            field.data[4],
                            field.data[5],
                            field.data[6],
                            field.data[7],
                        ])
                    })
            })
        })
        .unwrap_or(0)
}

fn signed_mpt_create(
    kp: &KeyPair,
    seq: u32,
    flags: u32,
    maximum_amount: u64,
    transfer_fee: Option<u16>,
) -> ParsedTx {
    let mut builder = TxBuilder::mptoken_issuance_create()
        .account(kp)
        .flags(flags)
        .maximum_amount(maximum_amount)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(transfer_fee) = transfer_fee {
        builder = builder.transfer_fee_field(transfer_fee);
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_mpt_authorize(
    kp: &KeyPair,
    seq: u32,
    mptid: [u8; 24],
    holder: Option<[u8; 20]>,
) -> ParsedTx {
    let mut builder = TxBuilder::mptoken_authorize()
        .account(kp)
        .mptoken_issuance_id(mptid)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(holder) = holder {
        builder = builder.holder(holder);
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_mpt_payment(
    kp: &KeyPair,
    seq: u32,
    destination: [u8; 20],
    amount: Amount,
    send_max: Option<Amount>,
    deliver_min: Option<Amount>,
    flags: u32,
) -> ParsedTx {
    let mut builder = TxBuilder::payment()
        .account(kp)
        .destination_account(destination)
        .amount(amount)
        .flags(flags)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(send_max) = send_max {
        builder = builder.send_max(send_max);
    }
    if let Some(deliver_min) = deliver_min {
        builder = builder.deliver_min(deliver_min);
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_deposit_preauth_authorize(kp: &KeyPair, seq: u32, authorized: [u8; 20]) -> ParsedTx {
    parse_blob(
        &TxBuilder::deposit_preauth()
            .account(kp)
            .authorize(authorized)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_set_deposit_auth(kp: &KeyPair, seq: u32) -> ParsedTx {
    parse_blob(
        &TxBuilder::account_set()
            .account(kp)
            .set_flag(9)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn setup_transfer_fee_holders(
    state: &mut LedgerState,
    transfer_fee: u16,
) -> ([u8; 24], KeyPair, KeyPair, KeyPair) {
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(state, &alice, 5_000);
    fund(state, &bob, 5_000);
    fund(state, &carol, 5_000);

    let create = signed_mpt_create(&alice, 1, LSF_MPT_CAN_TRANSFER, 10_000, Some(transfer_fee));
    assert!(run_tx(state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &account_id(&alice));
    for kp in [&bob, &carol] {
        let authorize = signed_mpt_authorize(kp, 1, mptid, None);
        assert!(run_tx(state, &authorize, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success());
    }

    let issue_to_bob = signed_mpt_payment(
        &alice,
        2,
        account_id(&bob),
        Amount::from_mpt_value(1_000, mptid),
        None,
        None,
        0,
    );
    assert!(run_tx(state, &issue_to_bob, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    (mptid, alice, bob, carol)
}

#[test]
fn mpt_direct_payment_enforces_deposit_auth() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let set_deposit_auth = signed_set_deposit_auth(&bob, 1);
    assert!(
        run_tx(&mut state, &set_deposit_auth, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );
    assert_ne!(
        state.get_account(&account_id(&bob)).unwrap().flags & LSF_DEPOSIT_AUTH,
        0
    );

    let create = signed_mpt_create(&alice, 1, 0, 1_000, None);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    let mptid = make_mptid(1, &account_id(&alice));

    let holder = signed_mpt_authorize(&bob, 2, mptid, None);
    assert!(run_tx(&mut state, &holder, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let blocked = signed_mpt_payment(
        &alice,
        2,
        account_id(&bob),
        Amount::from_mpt_value(100, mptid),
        None,
        None,
        0,
    );
    let r = run_tx(&mut state, &blocked, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_PERMISSION);

    let bob_token = state
        .get_raw(&mpt_holder_key_for(&mptid, &account_id(&bob)))
        .unwrap()
        .to_vec();
    assert_eq!(sle_u64(&bob_token, 26), 0);

    let preauth = signed_deposit_preauth_authorize(&bob, 3, account_id(&alice));
    assert!(run_tx(&mut state, &preauth, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let allowed = signed_mpt_payment(
        &alice,
        3,
        account_id(&bob),
        Amount::from_mpt_value(100, mptid),
        None,
        None,
        0,
    );
    let r = run_tx(&mut state, &allowed, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "preauthorized MPT payment: {}",
        r.ter
    );

    let bob_token = state
        .get_raw(&mpt_holder_key_for(&mptid, &account_id(&bob)))
        .unwrap()
        .to_vec();
    assert_eq!(sle_u64(&bob_token, 26), 100);
}

#[test]
fn mpt_transfer_fee_uses_sendmax_and_partial_delivery() {
    let mut state = LedgerState::new();
    let (mptid, _alice, bob, carol) = setup_transfer_fee_holders(&mut state, 10_000);

    let no_sendmax = signed_mpt_payment(
        &bob,
        2,
        account_id(&carol),
        Amount::from_mpt_value(100, mptid),
        None,
        None,
        0,
    );
    assert_eq!(
        run_tx(&mut state, &no_sendmax, &pctx(100), ApplyFlags::NONE).ter,
        ter::TEC_PATH_PARTIAL
    );

    let short_sendmax = signed_mpt_payment(
        &bob,
        3,
        account_id(&carol),
        Amount::from_mpt_value(100, mptid),
        Some(Amount::from_mpt_value(109, mptid)),
        None,
        0,
    );
    assert_eq!(
        run_tx(&mut state, &short_sendmax, &pctx(100), ApplyFlags::NONE).ter,
        ter::TEC_PATH_PARTIAL
    );

    let exact_sendmax = signed_mpt_payment(
        &bob,
        4,
        account_id(&carol),
        Amount::from_mpt_value(100, mptid),
        Some(Amount::from_mpt_value(110, mptid)),
        None,
        0,
    );
    assert!(
        run_tx(&mut state, &exact_sendmax, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let partial = signed_mpt_payment(
        &bob,
        5,
        account_id(&carol),
        Amount::from_mpt_value(100, mptid),
        Some(Amount::from_mpt_value(90, mptid)),
        None,
        TF_PARTIAL_PAYMENT,
    );
    assert!(run_tx(&mut state, &partial, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let bob_token = state
        .get_raw(&mpt_holder_key_for(&mptid, &account_id(&bob)))
        .unwrap()
        .to_vec();
    let carol_token = state
        .get_raw(&mpt_holder_key_for(&mptid, &account_id(&carol)))
        .unwrap()
        .to_vec();
    let issuance = state
        .get_raw(&mpt_issuance_key_for(&mptid))
        .unwrap()
        .to_vec();

    assert_eq!(sle_u64(&bob_token, 26), 800);
    assert_eq!(sle_u64(&carol_token, 26), 182);
    assert_eq!(sle_u64(&issuance, 25), 982);
}

#[test]
fn mpt_holder_to_holder_without_can_transfer_is_no_auth() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);
    fund(&mut state, &carol, 5_000);

    let create = signed_mpt_create(&alice, 1, 0, 1_000, None);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    let mptid = make_mptid(1, &account_id(&alice));

    for kp in [&bob, &carol] {
        let authorize = signed_mpt_authorize(kp, 1, mptid, None);
        assert!(run_tx(&mut state, &authorize, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success());
    }

    let issue_to_bob = signed_mpt_payment(
        &alice,
        2,
        account_id(&bob),
        Amount::from_mpt_value(100, mptid),
        None,
        None,
        0,
    );
    assert!(
        run_tx(&mut state, &issue_to_bob, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let blocked = signed_mpt_payment(
        &bob,
        2,
        account_id(&carol),
        Amount::from_mpt_value(10, mptid),
        None,
        None,
        0,
    );
    assert_eq!(
        run_tx(&mut state, &blocked, &pctx(100), ApplyFlags::NONE).ter,
        ter::TEC_NO_AUTH
    );
}

#[test]
fn mpt_delivermin_rejects_partial_below_minimum() {
    let mut state = LedgerState::new();
    let (mptid, alice, bob, _carol) = setup_transfer_fee_holders(&mut state, 0);

    let below_min = signed_mpt_payment(
        &bob,
        2,
        account_id(&alice),
        Amount::from_mpt_value(100, mptid),
        Some(Amount::from_mpt_value(99, mptid)),
        Some(Amount::from_mpt_value(100, mptid)),
        TF_PARTIAL_PAYMENT,
    );
    assert_eq!(
        run_tx(&mut state, &below_min, &pctx(100), ApplyFlags::NONE).ter,
        ter::TEC_PATH_PARTIAL
    );

    let meets_min = signed_mpt_payment(
        &bob,
        3,
        account_id(&alice),
        Amount::from_mpt_value(100, mptid),
        Some(Amount::from_mpt_value(99, mptid)),
        Some(Amount::from_mpt_value(99, mptid)),
        TF_PARTIAL_PAYMENT,
    );
    assert!(run_tx(&mut state, &meets_min, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let bob_token = state
        .get_raw(&mpt_holder_key_for(&mptid, &account_id(&bob)))
        .unwrap()
        .to_vec();
    let issuance = state
        .get_raw(&mpt_issuance_key_for(&mptid))
        .unwrap()
        .to_vec();
    assert_eq!(sle_u64(&bob_token, 26), 901);
    assert_eq!(sle_u64(&issuance, 25), 901);
}
