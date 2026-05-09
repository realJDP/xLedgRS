//! Worker 5 Flow/BookStep parity regressions.
//!
//! These cover active-mainnet rippled behavior where BookStep evaluates offer
//! expiration against the ledger close time before a payment can consume CLOB
//! liquidity. xLedgRSv2Beta currently routes some default book payment planners
//! with close_time=0, so these tests expose that gap without changing engine
//! code outside Worker 5 ownership.

use xrpl::crypto::keys::{KeyPair, Secp256k1KeyPair};
use xrpl::ledger::ter::{self, ApplyFlags};
use xrpl::ledger::tx::{run_tx, TxContext};
use xrpl::ledger::{AccountRoot, LedgerState};
use xrpl::transaction::amount::{Currency, IouValue};
use xrpl::transaction::{builder::TxBuilder, parse_blob, Amount};

const XRP: u64 = 1_000_000;
const BASE_FEE: u64 = 10;
const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;

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
    state.insert_account(make_account(account_id(kp), balance_xrp * XRP));
}

fn usd(units: f64, issuer: [u8; 20]) -> Amount {
    Amount::Iou {
        value: IouValue::from_f64(units),
        currency: Currency::from_code("USD").unwrap(),
        issuer,
    }
}

fn parse_signed(signed: xrpl::transaction::builder::SignedTx) -> xrpl::transaction::ParsedTx {
    parse_blob(&signed.blob).unwrap()
}

fn prepare_expired_xrp_to_usd_book() -> (LedgerState, KeyPair, KeyPair, KeyPair) {
    let mut state = LedgerState::new();
    let sender = keypair(11);
    let destination = keypair(22);
    let issuer = keypair(33);

    fund(&mut state, &sender, 10_000);
    fund(&mut state, &destination, 10_000);
    fund(&mut state, &issuer, 10_000);

    let trust = TxBuilder::trust_set()
        .account(&destination)
        .limit_amount(usd(1_000.0, account_id(&issuer)))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&destination)
        .unwrap();
    let trust_result = run_tx(
        &mut state,
        &parse_signed(trust),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(
        trust_result.ter.is_tes_success(),
        "destination trustline setup failed: {}",
        trust_result.ter
    );

    let expired_offer = TxBuilder::offer_create()
        .account(&issuer)
        .taker_pays(Amount::Xrp(20 * XRP))
        .taker_gets(usd(10.0, account_id(&issuer)))
        .expiration(150)
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&issuer)
        .unwrap();
    let offer_result = run_tx(
        &mut state,
        &parse_signed(expired_offer),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(
        offer_result.ter.is_tes_success(),
        "expired-offer fixture setup failed: {}",
        offer_result.ter
    );

    (state, sender, destination, issuer)
}

#[test]
fn default_book_payment_ignores_expired_offer_gap() {
    let (mut state, sender, destination, issuer) = prepare_expired_xrp_to_usd_book();

    let payment = TxBuilder::payment()
        .account(&sender)
        .destination(&account_addr(&destination))
        .unwrap()
        .amount(usd(10.0, account_id(&issuer)))
        .send_max(Amount::Xrp(20 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&sender)
        .unwrap();
    let result = run_tx(
        &mut state,
        &parse_signed(payment),
        &pctx(200),
        ApplyFlags::NONE,
    );

    assert_eq!(
        result.ter,
        ter::TEC_PATH_DRY,
        "rippled BookStep treats the only offer as expired at close_time=200"
    );
}

#[test]
fn default_book_partial_payment_ignores_expired_offer_gap() {
    let (mut state, sender, destination, issuer) = prepare_expired_xrp_to_usd_book();

    let payment = TxBuilder::payment()
        .account(&sender)
        .destination(&account_addr(&destination))
        .unwrap()
        .amount(usd(10.0, account_id(&issuer)))
        .send_max(Amount::Xrp(20 * XRP))
        .deliver_min(usd(5.0, account_id(&issuer)))
        .flags(TF_PARTIAL_PAYMENT)
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&sender)
        .unwrap();
    let result = run_tx(
        &mut state,
        &parse_signed(payment),
        &pctx(200),
        ApplyFlags::NONE,
    );

    assert_eq!(
        result.ter,
        ter::TEC_PATH_DRY,
        "rippled partial Payment cannot satisfy DeliverMin from expired CLOB liquidity"
    );
}
