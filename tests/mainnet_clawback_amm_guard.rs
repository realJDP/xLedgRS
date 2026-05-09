use xrpl::crypto::keys::{KeyPair, Secp256k1KeyPair};
use xrpl::ledger::account::{LSF_DEFAULT_RIPPLE, LSF_DEPOSIT_AUTH, LSF_DISABLE_MASTER};
use xrpl::ledger::ter::{self, ApplyFlags};
use xrpl::ledger::tx::{run_tx, TxContext};
use xrpl::ledger::{AccountRoot, LedgerState};
use xrpl::transaction::amount::{Amount, Currency, IouValue};
use xrpl::transaction::builder::TxBuilder;
use xrpl::transaction::parse::ParsedTx;
use xrpl::transaction::parse_blob;

const XRP: u64 = 1_000_000;
const BASE_FEE: u64 = 10;

fn kp_alice() -> KeyPair {
    KeyPair::Secp256k1(Secp256k1KeyPair::from_seed_entropy(&[1u8; 16]))
}

fn alice_id() -> [u8; 20] {
    xrpl::crypto::account_id(&kp_alice().public_key_bytes())
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

fn enable_amendments(state: &mut LedgerState, names: &[&str]) {
    for name in names {
        state.enable_amendment(xrpl::crypto::sha512_first_half(name.as_bytes()));
    }
}

fn fund(state: &mut LedgerState, kp: &KeyPair, balance_xrp: u64) {
    let id = xrpl::crypto::account_id(&kp.public_key_bytes());
    state.insert_account(make_account(id, balance_xrp * XRP));
}

fn insert_amm_pseudo_account(state: &mut LedgerState, account_id: [u8; 20]) {
    let mut account = make_account(account_id, 100 * XRP);
    account.sequence = 0;
    account.flags = LSF_DISABLE_MASTER | LSF_DEFAULT_RIPPLE | LSF_DEPOSIT_AUTH;
    account.raw_sle = Some(xrpl::ledger::meta::patch_sle(
        &account.encode(),
        &[xrpl::ledger::meta::ParsedField {
            type_code: 5,
            field_code: 14,
            data: [0xA5; 32].to_vec(),
        }],
        None,
        None,
        &[],
    ));
    state.insert_account(account);
}

fn make_mptid(seq: u32, account: &[u8; 20]) -> [u8; 24] {
    let mut id = [0u8; 24];
    id[0..4].copy_from_slice(&seq.to_be_bytes());
    id[4..24].copy_from_slice(account);
    id
}

fn signed_iou_clawback(kp: &KeyPair, seq: u32, holder: [u8; 20]) -> ParsedTx {
    parse_blob(
        &TxBuilder::clawback()
            .account(kp)
            .amount(Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: Currency::from_code("USD").unwrap(),
                issuer: holder,
            })
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_iou_clawback_with_holder_field(
    kp: &KeyPair,
    seq: u32,
    amount_holder: [u8; 20],
    holder_field: [u8; 20],
) -> ParsedTx {
    parse_blob(
        &TxBuilder::clawback()
            .account(kp)
            .holder(holder_field)
            .amount(Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: Currency::from_code("USD").unwrap(),
                issuer: amount_holder,
            })
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_mpt_clawback(kp: &KeyPair, seq: u32, holder: [u8; 20], mptid: [u8; 24]) -> ParsedTx {
    parse_blob(
        &TxBuilder::clawback()
            .account(kp)
            .holder(holder)
            .amount(Amount::from_mpt_value(5, mptid))
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

#[test]
fn iou_clawback_to_amm_pseudo_holder_returns_tec_amm_account() {
    let mut state = LedgerState::new();
    enable_amendments(&mut state, &["Clawback", "AMM"]);
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let amm_holder = [0xB0; 20];
    insert_amm_pseudo_account(&mut state, amm_holder);

    let tx = signed_iou_clawback(&alice, 1, amm_holder);
    let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

    assert_eq!(result.ter, ter::TEC_AMM_ACCOUNT);
}

#[test]
fn iou_clawback_with_holder_field_is_malformed() {
    let mut state = LedgerState::new();
    enable_amendments(&mut state, &["Clawback"]);
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let amount_holder = [0xB3; 20];
    let holder_field = [0xB4; 20];
    state.insert_account(make_account(amount_holder, 100 * XRP));
    state.insert_account(make_account(holder_field, 100 * XRP));

    let tx = signed_iou_clawback_with_holder_field(&alice, 1, amount_holder, holder_field);
    let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

    assert_eq!(result.ter, ter::TEM_MALFORMED);
}

#[test]
fn mpt_clawback_to_amm_pseudo_holder_returns_tec_amm_account() {
    let mut state = LedgerState::new();
    enable_amendments(&mut state, &["Clawback", "MPTokensV1", "AMM"]);
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let amm_holder = [0xB1; 20];
    insert_amm_pseudo_account(&mut state, amm_holder);
    let mptid = make_mptid(1, &alice_id());

    let tx = signed_mpt_clawback(&alice, 1, amm_holder, mptid);
    let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

    assert_eq!(result.ter, ter::TEC_AMM_ACCOUNT);
}

#[test]
fn mpt_clawback_to_non_amm_pseudo_holder_returns_tec_pseudo_account() {
    let mut state = LedgerState::new();
    enable_amendments(&mut state, &["Clawback", "MPTokensV1"]);
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let pseudo_holder = [0xB2; 20];
    let mut account = make_account(pseudo_holder, 100 * XRP);
    account.sequence = 0;
    account.flags = LSF_DISABLE_MASTER | LSF_DEFAULT_RIPPLE | LSF_DEPOSIT_AUTH;
    state.insert_account(account);

    let mptid = make_mptid(1, &alice_id());
    let tx = signed_mpt_clawback(&alice, 1, pseudo_holder, mptid);
    let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

    assert_eq!(result.ter, ter::TEC_PSEUDO_ACCOUNT);
}
