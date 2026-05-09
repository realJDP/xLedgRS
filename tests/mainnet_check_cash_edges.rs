use xrpl::crypto::keys::{KeyPair, Secp256k1KeyPair};
use xrpl::ledger::check;
use xrpl::ledger::ter::{self, ApplyFlags};
use xrpl::ledger::tx::{run_tx, TxContext};
use xrpl::ledger::{AccountRoot, LedgerState};
use xrpl::transaction::amount::{Currency, IouValue};
use xrpl::transaction::{builder::TxBuilder, parse_blob, Amount};

const XRP: u64 = 1_000_000;
const BASE_FEE: u64 = 10;

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

fn bob_addr() -> String {
    xrpl::crypto::base58::encode_account(&account_id(&kp_bob()))
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

fn fund(state: &mut LedgerState, kp: &KeyPair, balance_xrp: u64) {
    let id = account_id(kp);
    state.insert_account(make_account(id, balance_xrp * XRP));
}

fn iou_usd(value: f64, issuer: [u8; 20]) -> Amount {
    Amount::Iou {
        value: IouValue::from_f64(value),
        currency: Currency::from_code("USD").unwrap(),
        issuer,
    }
}

#[test]
fn check_cash_xrp_exact_shortfall_returns_tec_unfunded_payment() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let alice_id = account_id(&alice);
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);

    let create = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let create_result = run_tx(
        &mut state,
        &parse_blob(&create.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(create_result.ter.is_tes_success());

    let mut creator = state.get_account(&alice_id).unwrap().clone();
    creator.balance = 80 * XRP;
    state.insert_account(creator);

    let cash = TxBuilder::check_cash()
        .account(&bob)
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .check_id(check::shamap_key(&alice_id, 1).0)
        .sign(&bob)
        .unwrap();
    let result = run_tx(
        &mut state,
        &parse_blob(&cash.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    assert_eq!(result.ter, ter::TEC_UNFUNDED_PAYMENT);
    assert!(result.applied);
    assert!(state.get_check(&check::shamap_key(&alice_id, 1)).is_some());
}

#[test]
fn check_cash_iou_deliver_min_with_200_percent_transfer_rate_uses_half_max_target() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    let alice_id = account_id(&alice);
    let bob_id = account_id(&bob);
    let carol_id = account_id(&carol);
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);
    fund(&mut state, &carol, 300);

    let mut issuer = state.get_account(&carol_id).unwrap().clone();
    issuer.transfer_rate = 2_000_000_000;
    state.insert_account(issuer);

    let usd = Currency::from_code("USD").unwrap();
    let trust = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(100.0, carol_id))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let trust_result = run_tx(
        &mut state,
        &parse_blob(&trust.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(trust_result.ter.is_tes_success());

    let alice_line_key = xrpl::ledger::trustline::shamap_key(&alice_id, &carol_id, &usd);
    let mut line = state.get_trustline(&alice_line_key).unwrap().clone();
    line.transfer(&carol_id, &IouValue::from_f64(50.0));
    state.insert_trustline(line);

    let create = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(50.0, carol_id))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let create_result = run_tx(
        &mut state,
        &parse_blob(&create.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(create_result.ter.is_tes_success());

    let cash = TxBuilder::check_cash()
        .account(&bob)
        .deliver_min(iou_usd(20.0, carol_id))
        .fee(BASE_FEE)
        .sequence(1)
        .check_id(check::shamap_key(&alice_id, 2).0)
        .sign(&bob)
        .unwrap();
    let cash_result = run_tx(
        &mut state,
        &parse_blob(&cash.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(cash_result.ter.is_tes_success(), "{}", cash_result.ter);

    let alice_line = state.get_trustline(&alice_line_key).unwrap();
    assert_eq!(alice_line.balance_for(&alice_id), IouValue::ZERO);

    let bob_line_key = xrpl::ledger::trustline::shamap_key(&bob_id, &carol_id, &usd);
    let bob_line = state.get_trustline(&bob_line_key).unwrap();
    assert_eq!(bob_line.balance_for(&bob_id), IouValue::from_f64(25.0));
    assert!(state.get_check(&check::shamap_key(&alice_id, 2)).is_none());
}
