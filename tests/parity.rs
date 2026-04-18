//! Parity tests — verify xLedgRS behavior matches rippled's expected outcomes.
//!
//! Fixtures are derived from rippled's jtx and app test suites.
//!
//! Each test encodes a specific scenario from rippled's C++ tests and verifies
//! that xLedgRS produces the same TER code, balance, sequence, and owner count.

use xrpl::crypto::keys::{KeyPair, Secp256k1KeyPair};
use xrpl::ledger::ter::{self, ApplyFlags};
use xrpl::ledger::tx::{classify_result, run_tx, ApplyOutcome, TxContext};
use xrpl::ledger::{AccountRoot, LedgerState};
use xrpl::transaction::parse::ParsedTx;
use xrpl::transaction::{builder::TxBuilder, parse_blob, Amount};

fn pctx(close_time: u64) -> TxContext {
    TxContext {
        close_time,
        ..TxContext::default()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const XRP: u64 = 1_000_000; // 1 XRP in drops
const BASE_FEE: u64 = 10; // rippled default base fee

fn kp_alice() -> KeyPair {
    KeyPair::Secp256k1(Secp256k1KeyPair::from_seed_entropy(&[1u8; 16]))
}

fn kp_bob() -> KeyPair {
    KeyPair::Secp256k1(Secp256k1KeyPair::from_seed_entropy(&[99u8; 16]))
}

fn kp_carol() -> KeyPair {
    KeyPair::Secp256k1(Secp256k1KeyPair::from_seed_entropy(&[42u8; 16]))
}

fn alice_id() -> [u8; 20] {
    xrpl::crypto::account_id(&kp_alice().public_key_bytes())
}
fn bob_id() -> [u8; 20] {
    xrpl::crypto::account_id(&kp_bob().public_key_bytes())
}
fn carol_id() -> [u8; 20] {
    xrpl::crypto::account_id(&kp_carol().public_key_bytes())
}
fn bob_addr() -> String {
    xrpl::crypto::base58::encode_account(&bob_id())
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
    let id = xrpl::crypto::account_id(&kp.public_key_bytes());
    state.insert_account(make_account(id, balance_xrp * XRP));
}

// ── Payment parity ───────────────────────────────────────────────────────────

#[test]
fn payment_xrp_basic() {
    // rippled: alice(10000 XRP) pays bob(10000 XRP) 100 XRP, fee=10 drops
    // Expected: tesSUCCESS, alice = 9900 XRP - 10 drops, bob = 10100 XRP
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "expected tesSUCCESS, got {}",
        result.ter
    );
    assert!(result.applied);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, 10_000 * XRP - 100 * XRP - BASE_FEE);
    assert_eq!(a.sequence, 2);

    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.balance, 10_000 * XRP + 100 * XRP);
}

#[test]
fn payment_creates_destination() {
    // rippled: payment to non-existent account creates it
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);
    // Bob does NOT exist yet

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(1_000 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(result.ter.is_tes_success());

    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.balance, 1_000 * XRP);
    assert_eq!(b.sequence, 1); // new account starts at seq 1
}

#[test]
fn payment_no_account_returns_ter() {
    // rippled: payment from non-existent account → terNO_ACCOUNT
    // Fee and sequence must NOT be consumed
    let mut state = LedgerState::new();
    let alice = kp_alice();

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TER_NO_ACCOUNT);
    assert!(!result.applied);
    assert!(state.get_account(&alice_id()).is_none());
}

#[test]
fn payment_wrong_sequence_returns_ter_pre_seq() {
    // rippled: wrong sequence → terPRE_SEQ, no fee/seq consumed
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(99) // wrong
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TER_PRE_SEQ);
    assert!(!result.applied);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, 10_000 * XRP); // unchanged
    assert_eq!(a.sequence, 1); // unchanged
}

#[test]
fn payment_insufficient_fee_returns_ter() {
    // rippled: balance < fee → terINSUF_FEE_B
    let mut state = LedgerState::new();
    let alice = kp_alice();
    state.insert_account(make_account(alice_id(), 5)); // only 5 drops

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(1))
        .fee(BASE_FEE) // 10 drops > 5 drops balance
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TER_INSUF_FEE_B);
    assert!(!result.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().balance, 5);
}

#[test]
fn payment_sequence_increments() {
    // rippled: successful tx bumps sequence by 1
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    for seq in 1..=3 {
        let signed = TxBuilder::payment()
            .account(&alice)
            .destination(&bob_addr())
            .unwrap()
            .amount(Amount::Xrp(100 * XRP))
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(&alice)
            .unwrap();
        let tx = parse_blob(&signed.blob).unwrap();
        let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
        assert!(
            result.ter.is_tes_success(),
            "tx seq={} failed: {}",
            seq,
            result.ter
        );
    }

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.sequence, 4);
    assert_eq!(a.balance, 10_000 * XRP - 300 * XRP - 3 * BASE_FEE);
}

// ── Escrow parity ────────────────────────────────────────────────────────────

#[test]
fn escrow_create_locks_xrp() {
    // rippled: alice creates 1000 XRP escrow to bob
    // Expected: tesSUCCESS, alice balance -= 1000 XRP + fee, owner_count = 1
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let signed = TxBuilder::escrow_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(1_000 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .finish_after(200) // finish_after > close_time
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "escrow create failed: {}",
        result.ter
    );

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, 5_000 * XRP - 1_000 * XRP - BASE_FEE);
    assert_eq!(a.owner_count, 1);
    assert_eq!(a.sequence, 2);

    // Bob's balance unchanged
    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.balance, 5_000 * XRP);
}

#[test]
fn escrow_finish_releases_xrp() {
    // rippled: after time elapses, finish releases XRP to destination
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    // Create escrow at close_time=100, finish_after=200
    let signed = TxBuilder::escrow_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(1_000 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .finish_after(200)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();
    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(result.ter.is_tes_success());

    // Finish at close_time=300 (after finish_after=200)
    let signed = TxBuilder::escrow_finish()
        .account(&bob)
        .fee(BASE_FEE)
        .sequence(1)
        .offer_sequence(1) // escrow sequence
        .sign(&bob)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    // run_tx needs the owner field set to alice's account
    // The escrow_finish handler looks up by owner+sequence
    let mut tx = tx;
    tx.owner = Some(alice_id());

    let result = run_tx(&mut state, &tx, &pctx(300), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "escrow finish failed: {}",
        result.ter
    );

    // Bob should have received the 1000 XRP
    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.balance, 5_000 * XRP + 1_000 * XRP - BASE_FEE);
}

// ── Retry/classification parity ──────────────────────────────────────────────

#[test]
fn ter_result_classified_as_retry() {
    // terPRE_SEQ should be classified as Retry in close loop
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(99) // wrong sequence
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(classify_result(&result), ApplyOutcome::Retry);
}

#[test]
fn ter_no_account_classified_as_retry() {
    // terNO_ACCOUNT should be classified as Retry
    let mut state = LedgerState::new();
    let alice = kp_alice();

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(classify_result(&result), ApplyOutcome::Retry);
}

// ── TrustSet parity ──────────────────────────────────────────────────────────

fn iou_usd(limit: f64, issuer_id: [u8; 20]) -> Amount {
    use xrpl::transaction::amount::{Currency, IouValue};
    Amount::Iou {
        value: IouValue::from_f64(limit),
        currency: Currency::from_code("USD").unwrap(),
        issuer: issuer_id,
    }
}

#[test]
fn trustset_creates_trust_line() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(1000.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "trustset failed: {}",
        result.ter
    );

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.sequence, 2);
    assert_eq!(a.owner_count, 1);

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    assert!(state
        .get_trustline_for(&alice_id(), &bob_id(), &usd)
        .is_some());
}

#[test]
fn trustset_zero_limit_removes_trust_line() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(1000.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(0.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();
    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "trustset zero failed: {}",
        result.ter
    );

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 0);

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    assert!(state
        .get_trustline_for(&alice_id(), &bob_id(), &usd)
        .is_none());
}

// ── OfferCreate / OfferCancel parity ─────────────────────────────────────────

#[test]
fn offer_create_places_offer() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(10_000.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let signed = TxBuilder::offer_create()
        .account(&alice)
        .taker_pays(iou_usd(50.0, bob_id()))
        .taker_gets(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "offer create failed: {}",
        result.ter
    );

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.sequence, 3);
    assert_eq!(a.owner_count, 2);
}

#[test]
fn offer_cancel_removes_offer() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(10_000.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let signed = TxBuilder::offer_create()
        .account(&alice)
        .taker_pays(iou_usd(50.0, bob_id()))
        .taker_gets(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);

    let signed = TxBuilder::offer_cancel()
        .account(&alice)
        .offer_sequence(2)
        .fee(BASE_FEE)
        .sequence(3)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "offer cancel failed: {}",
        result.ter
    );

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.sequence, 4);
    assert_eq!(a.owner_count, 1);
}

// ── Check parity ─────────────────────────────────────────────────────────────

#[test]
fn check_create_increases_owner_count() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);

    let signed = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(10 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "check create failed: {}",
        result.ter
    );

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 1);
    assert_eq!(a.balance, 300 * XRP - BASE_FEE);

    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.balance, 300 * XRP);
}

// ── PayChan parity ───────────────────────────────────────────────────────────

#[test]
fn paychan_create_locks_xrp() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let signed = TxBuilder::paychan_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(1_000 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .settle_delay(86400)
        .public_key_field(kp_alice().public_key_bytes())
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "paychan create failed: {}",
        result.ter
    );

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, 5_000 * XRP - 1_000 * XRP - BASE_FEE);
    assert_eq!(a.owner_count, 1);
    assert_eq!(a.sequence, 2);
}

// ── Offer crossing parity ────────────────────────────────────────────────────

#[test]
fn offer_crossing_full_fill() {
    // Alice places offer: sell 100 XRP, buy 50 USD(bob)
    // Carol places crossing offer: sell 50 USD(bob), buy 100 XRP
    // Both should fully fill, neither should have a standing offer after.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);
    fund(&mut state, &carol, 5_000);

    // Alice trust line to bob (issuer) for USD
    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(10_000.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    // Carol trust line to bob for USD
    let signed = TxBuilder::trust_set()
        .account(&carol)
        .limit_amount(iou_usd(10_000.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&carol)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    // Credit Carol with 50 USD by updating the issuer trust line directly.
    // The issuer side does not require a self-referential trust line.
    {
        let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
        let key = xrpl::ledger::trustline::shamap_key(&carol_id(), &bob_id(), &usd);
        if let Some(tl) = state.get_trustline(&key) {
            let mut tl = tl.clone();
            // Seed the balance through the trust-line helper so the low/high
            // side is resolved by the ledger model rather than by test logic.
            tl.transfer(
                &bob_id(),
                &xrpl::transaction::amount::IouValue::from_f64(50.0),
            );
            state.insert_trustline(tl);
        }
    }

    // Alice places offer: sell 100 XRP, buy 50 USD
    let signed = TxBuilder::offer_create()
        .account(&alice)
        .taker_pays(iou_usd(50.0, bob_id()))
        .taker_gets(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success(), "alice offer failed: {}", r.ter);

    let alice_pre = state.get_account(&alice_id()).unwrap().clone();

    // Carol places crossing offer: sell 50 USD, buy 100 XRP
    let signed = TxBuilder::offer_create()
        .account(&carol)
        .taker_pays(Amount::Xrp(100 * XRP))
        .taker_gets(iou_usd(50.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&carol)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(
        r.ter.is_tes_success(),
        "carol crossing offer failed: {}",
        r.ter
    );

    // After crossing: Alice gave 100 XRP, received 50 USD
    // Carol gave 50 USD, received 100 XRP
    let a = state.get_account(&alice_id()).unwrap();
    assert!(
        a.balance < alice_pre.balance,
        "alice should have less XRP after crossing"
    );

    let c = state.get_account(&carol_id()).unwrap();
    assert!(
        c.balance > 5_000 * XRP - 2 * BASE_FEE,
        "carol should have gained XRP"
    );
}

// ── Escrow edge cases ────────────────────────────────────────────────────────

#[test]
fn escrow_finish_too_early_fails() {
    // rippled: finishing before finish_after → tecNO_PERMISSION
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    // Create escrow with finish_after=500
    let signed = TxBuilder::escrow_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(1_000 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .finish_after(500)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    // Try to finish at close_time=200 (before finish_after=500)
    let signed = TxBuilder::escrow_finish()
        .account(&bob)
        .fee(BASE_FEE)
        .sequence(1)
        .offer_sequence(1)
        .sign(&bob)
        .unwrap();
    let mut tx = parse_blob(&signed.blob).unwrap();
    tx.owner = Some(alice_id());

    let result = run_tx(&mut state, &tx, &pctx(200), ApplyFlags::NONE);
    // Should fail — too early
    assert!(
        result.ter.is_tec_claim() || result.ter.token().contains("PERMISSION"),
        "expected failure for early finish, got {}",
        result.ter
    );

    // Alice's escrow should still exist, balance unchanged
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 1);
}

#[test]
fn escrow_cancel_after_expiry() {
    // rippled: cancel is allowed after cancel_after time
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    // Create escrow with cancel_after=300, finish_after=200
    let signed = TxBuilder::escrow_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(1_000 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .finish_after(200)
        .cancel_after(300)
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success());

    let alice_after_create = state.get_account(&alice_id()).unwrap().balance;

    // Cancel at close_time=400 (after cancel_after=300)
    let signed = TxBuilder::escrow_cancel()
        .account(&alice)
        .fee(BASE_FEE)
        .sequence(2)
        .offer_sequence(1)
        .sign(&alice)
        .unwrap();
    let mut tx = parse_blob(&signed.blob).unwrap();
    tx.owner = Some(alice_id());

    let result = run_tx(&mut state, &tx, &pctx(400), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "escrow cancel failed: {}",
        result.ter
    );

    // XRP should be returned to alice (minus fees)
    let a = state.get_account(&alice_id()).unwrap();
    assert!(
        a.balance > alice_after_create,
        "alice should have gotten XRP back"
    );
    assert_eq!(a.owner_count, 0);
}

// ── Close-level multi-tx parity ──────────────────────────────────────────────

#[test]
fn close_multi_tx_fee_burn_and_ordering() {
    // Close a ledger with 3 txs from the same sender, verify:
    // - all apply in sequence order
    // - total fee burn matches sum of fees
    // - header total_coins decreases
    use xrpl::ledger::close::close_ledger;
    use xrpl::ledger::pool::TxPool;

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let prev = xrpl::ledger::LedgerHeader {
        sequence: 1,
        hash: [0xAA; 32],
        parent_hash: [0u8; 32],
        close_time: 0,
        total_coins: 20_000 * XRP, // alice + bob
        account_hash: state.state_hash(),
        transaction_hash: [0u8; 32],
        parent_close_time: 0,
        close_time_resolution: 10,
        close_flags: 0,
    };

    let mut pool = TxPool::new();
    for seq in 1..=3 {
        let signed = TxBuilder::payment()
            .account(&alice)
            .destination(&bob_addr())
            .unwrap()
            .amount(Amount::Xrp(100 * XRP))
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(&alice)
            .unwrap();
        let mut data = Vec::with_capacity(4 + signed.blob.len());
        data.extend_from_slice(&[0x54, 0x58, 0x4E, 0x00]); // TXN\0
        data.extend_from_slice(&signed.blob);
        let hash = xrpl::crypto::sha512_first_half(&data);
        let parsed = parse_blob(&signed.blob).unwrap();
        pool.insert(hash, signed.blob, &parsed);
    }

    let result = close_ledger(&prev, &mut state, &mut pool, 100, true);

    assert_eq!(result.applied_count, 3);
    assert_eq!(result.failed_count, 0);
    assert_eq!(result.skipped_count, 0);
    assert_eq!(result.header.sequence, 2);

    // Total coins should decrease by 3 fees
    assert_eq!(result.header.total_coins, 20_000 * XRP - 3 * BASE_FEE);

    // Alice sent 300 XRP + 3 fees
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, 10_000 * XRP - 300 * XRP - 3 * BASE_FEE);
    assert_eq!(a.sequence, 4);

    // Bob received 300 XRP
    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.balance, 10_000 * XRP + 300 * XRP);
}

#[test]
fn close_skips_unfunded_tx() {
    // Tx at wrong sequence should not apply; remaining sequence gap means skip
    use xrpl::ledger::close::close_ledger;
    use xrpl::ledger::pool::TxPool;

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let prev = xrpl::ledger::LedgerHeader {
        sequence: 1,
        hash: [0xAA; 32],
        parent_hash: [0u8; 32],
        close_time: 0,
        total_coins: 20_000 * XRP,
        account_hash: state.state_hash(),
        transaction_hash: [0u8; 32],
        parent_close_time: 0,
        close_time_resolution: 10,
        close_flags: 0,
    };

    let mut pool = TxPool::new();
    // Only seq=5 (wrong, account at seq=1) — should be retried then skipped
    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(5)
        .sign(&alice)
        .unwrap();
    let mut data = Vec::with_capacity(4 + signed.blob.len());
    data.extend_from_slice(&[0x54, 0x58, 0x4E, 0x00]);
    data.extend_from_slice(&signed.blob);
    let hash = xrpl::crypto::sha512_first_half(&data);
    let parsed = parse_blob(&signed.blob).unwrap();
    pool.insert(hash, signed.blob, &parsed);

    let result = close_ledger(&prev, &mut state, &mut pool, 100, true);

    assert_eq!(result.applied_count, 0);
    // Should be skipped (retried but never matched)
    assert!(result.skipped_count > 0 || result.failed_count > 0);

    // Balances unchanged
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        10_000 * XRP
    );
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

// ── Offer depth ──────────────────────────────────────────────────────────────

#[test]
fn offer_no_cross_places_standing() {
    // An unmatched offer should remain as a standing offer.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    // Trust line for USD
    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(10_000.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    // Place offer — no counterparty, no crossing
    let signed = TxBuilder::offer_create()
        .account(&alice)
        .taker_pays(iou_usd(50.0, bob_id()))
        .taker_gets(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success());

    // XRP balance unchanged (offer doesn't lock XRP for IOUs)
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, 5_000 * XRP - 2 * BASE_FEE); // just fees
    assert_eq!(a.owner_count, 2); // trust line + offer
}

#[test]
fn offer_partial_cross() {
    // Alice offers to sell 200 XRP for 100 USD
    // Carol only has 25 USD → partial fill
    // Alice should have 75 USD remaining want, standing offer placed
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);
    fund(&mut state, &carol, 5_000);

    // Trust lines
    for (kp, seq) in [(&alice, 1u32), (&carol, 1u32)] {
        let signed = TxBuilder::trust_set()
            .account(kp)
            .limit_amount(iou_usd(10_000.0, bob_id()))
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap();
        run_tx(
            &mut state,
            &parse_blob(&signed.blob).unwrap(),
            &pctx(100),
            ApplyFlags::NONE,
        );
    }

    // Give Carol 25 USD
    {
        let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
        let key = xrpl::ledger::trustline::shamap_key(&carol_id(), &bob_id(), &usd);
        if let Some(tl) = state.get_trustline(&key) {
            let mut tl = tl.clone();
            tl.transfer(
                &bob_id(),
                &xrpl::transaction::amount::IouValue::from_f64(25.0),
            );
            state.insert_trustline(tl);
        }
    }

    // Alice places offer: sell 200 XRP, buy 100 USD
    let signed = TxBuilder::offer_create()
        .account(&alice)
        .taker_pays(iou_usd(100.0, bob_id()))
        .taker_gets(Amount::Xrp(200 * XRP))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let alice_pre = state.get_account(&alice_id()).unwrap().balance;

    // Carol places crossing offer: sell 25 USD, buy 50 XRP (matching rate)
    let signed = TxBuilder::offer_create()
        .account(&carol)
        .taker_pays(Amount::Xrp(50 * XRP))
        .taker_gets(iou_usd(25.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&carol)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success(), "partial cross failed: {}", r.ter);

    // Carol should have gained 50 XRP (partial fill of Alice's offer)
    let c = state.get_account(&carol_id()).unwrap();
    assert!(
        c.balance > 5_000 * XRP - 2 * BASE_FEE,
        "carol should have more XRP"
    );

    // Alice should have lost 50 XRP and her offer should still be standing (partially filled)
    let a = state.get_account(&alice_id()).unwrap();
    assert!(
        a.balance < alice_pre,
        "alice should have less XRP after partial cross"
    );
    // Alice still owns trust line + remaining offer
    assert!(
        a.owner_count >= 2,
        "alice should still own trust line + partial offer"
    );
}

// ── Check depth ──────────────────────────────────────────────────────────────

#[test]
fn check_cash_transfers_xrp() {
    // Alice creates check, Bob cashes it → XRP moves from Alice to Bob
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);

    // Create check
    let signed = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(10 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    // Bob cashes — needs owner and offer_sequence to find the check
    let signed = TxBuilder::check_cash()
        .account(&bob)
        .amount(Amount::Xrp(10 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .offer_sequence(1) // check sequence
        .sign(&bob)
        .unwrap();
    let mut tx = parse_blob(&signed.blob).unwrap();
    tx.owner = Some(alice_id()); // check was created by alice

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "check cash failed: {}", r.ter);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, 300 * XRP - 10 * XRP - BASE_FEE);
    assert_eq!(a.owner_count, 0); // check removed

    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.balance, 300 * XRP + 10 * XRP - BASE_FEE);
}

#[test]
fn check_cancel_by_creator() {
    // Alice creates check, Alice cancels it → check removed, no XRP moved
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);

    // Create check
    let signed = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(10 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);

    // Alice cancels
    let signed = TxBuilder::check_cancel()
        .account(&alice)
        .fee(BASE_FEE)
        .sequence(2)
        .offer_sequence(1)
        .sign(&alice)
        .unwrap();
    let mut tx = parse_blob(&signed.blob).unwrap();
    tx.owner = Some(alice_id());

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "check cancel failed: {}", r.ter);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 0);
    assert_eq!(a.balance, 300 * XRP - 2 * BASE_FEE); // only fees
}

#[test]
fn check_cash_insufficient_funds() {
    // Alice creates check for 100 XRP but only has 50 XRP
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 50); // only 50 XRP
    fund(&mut state, &bob, 300);

    let signed = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    // Bob tries to cash 100 XRP but Alice only has ~50 XRP
    let signed = TxBuilder::check_cash()
        .account(&bob)
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .offer_sequence(1)
        .sign(&bob)
        .unwrap();
    let mut tx = parse_blob(&signed.blob).unwrap();
    tx.owner = Some(alice_id());

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    // Should fail — Alice can't cover the check
    assert!(r.ter.is_tec_claim(), "expected tec failure, got {}", r.ter);
}

// ── PayChan depth ────────────────────────────────────────────────────────────

#[test]
fn paychan_fund_adds_xrp() {
    // Alice creates channel, then funds it with more XRP
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    // Create channel with 500 XRP
    let signed = TxBuilder::paychan_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(500 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .settle_delay(86400)
        .public_key_field(kp_alice().public_key_bytes())
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let alice_after_create = state.get_account(&alice_id()).unwrap().balance;

    // Compute channel hash (PayChan key = SHA-512-Half(0x0078 || account || sequence))
    let chan_key = xrpl::ledger::paychan::shamap_key(&alice_id(), &bob_id(), 1);

    // Fund channel with 200 more XRP
    let signed = TxBuilder::paychan_fund()
        .account(&alice)
        .channel(chan_key.0)
        .amount(Amount::Xrp(200 * XRP))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success(), "paychan fund failed: {}", r.ter);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, alice_after_create - 200 * XRP - BASE_FEE);

    // Channel should now have 700 XRP total
    let pc = state.get_paychan(&chan_key).unwrap();
    assert_eq!(pc.amount, 700 * XRP);
}

#[test]
fn paychan_fund_wrong_owner_fails() {
    // Bob tries to fund Alice's channel → tecNO_PERMISSION
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    // Create channel
    let signed = TxBuilder::paychan_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(500 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .settle_delay(86400)
        .public_key_field(kp_alice().public_key_bytes())
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let chan_key = xrpl::ledger::paychan::shamap_key(&alice_id(), &bob_id(), 1);

    // Bob tries to fund
    let signed = TxBuilder::paychan_fund()
        .account(&bob)
        .channel(chan_key.0)
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&bob)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tec_claim(), "expected tec, got {}", r.ter);

    // Bob's balance should only lose fee (tec claims fee)
    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.balance, 5_000 * XRP - BASE_FEE);
}

// ── Vault parity (stubs — ignored until implementation ready) ────────────────
//
// Field mapping from rippled (for VaultCreate implementation):
//   Vault SLE (ltVAULT = 0x0084):
//     sfOwner        = (ACCOUNT=8,  field=2)    — vault owner
//     sfAccount      = (ACCOUNT=8,  field=1)    — pseudo-account address
//     sfSequence     = (UINT32=2,   field=4)    — create tx sequence
//     sfAsset        = (ISSUE=24,   field=3)    — held asset type
//     sfAssetsTotal  = (NUMBER=9,   field=4)    — total assets (0 initially)
//     sfAssetsAvail  = (NUMBER=9,   field=2)    — available assets (0 initially)
//     sfShareMPTID   = (UINT192=21, field=2)    — share issuance MPTID (24 bytes)
//     sfWithdrawPol  = (UINT8=16,   field=20)   — withdrawal policy
//     sfScale        = (UINT8=16,   field=4)    — 0 for XRP/MPT, 6 for IOUs
//     sfFlags        = (UINT32=2,   field=2)    — vault flags
//     sfOwnerNode    = (UINT64=3,   field=4)    — directory page
//
//   Vault namespace = 'V' = 0x56
//   Vault key = SHA-512-Half(0x0056 || owner || sequence)
//
//   Pseudo-account derivation:
//     for i in 0..256:
//       hash = SHA-512-Half(i_u16_be || parent_hash || vault_key)
//       addr = RIPEMD160(SHA256(hash))
//       if no collision: return addr
//     Requires parent_hash — handler context must be extended.
//
//   VaultCreate creates:
//     1. Vault SLE
//     2. Pseudo-account (AccountRoot, seq=0, flags=DisableMaster|DefaultRipple|DepositAuth)
//     3. MPTokenIssuance for shares (owned by pseudo-account, seq=1)
//     4. Owner's MPToken for shares
//     5. Directory entries, owner_count += 2

#[test]
fn vault_create_basic() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = mpt_tx(65, alice_id(), 1, BASE_FEE); // tx_type 65 = VaultCreate
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "vault create failed: {}", r.ter);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 2);
    assert_eq!(a.sequence, 2);
    assert_eq!(a.balance, 5_000 * XRP - BASE_FEE);

    // Vault SLE should exist
    let vkey = test_vault_key(&alice_id(), 1);
    assert!(state.get_raw(&vkey).is_some(), "vault SLE should exist");

    // Pseudo-account should have been created
    assert!(state.account_count() >= 2, "pseudo-account should exist");
}

#[test]
fn vault_delete_empty() {
    // Create a vault, then delete it. All objects removed, owner_count back to 0.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Create vault at sequence 1
    let create_tx = mpt_tx(65, alice_id(), 1, BASE_FEE);
    let r = run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "vault create failed: {}", r.ter);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);

    let vkey = test_vault_key(&alice_id(), 1);
    assert!(state.get_raw(&vkey).is_some());

    // Delete vault at sequence 2
    let mut delete_tx = mpt_tx(67, alice_id(), 2, BASE_FEE);
    delete_tx.vault_id = Some(vkey.0);

    let r = run_tx(&mut state, &delete_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "vault delete failed: {}", r.ter);

    // Vault SLE should be gone
    assert!(
        state.get_raw(&vkey).is_none(),
        "vault SLE should be removed"
    );

    // Owner count back to 0
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 0);
    assert_eq!(a.sequence, 3);

    // Only alice's account should remain (pseudo-account removed)
    assert_eq!(state.account_count(), 1, "only alice should remain");
}

#[test]
fn vault_deposit_xrp() {
    // Deposit XRP into a vault. First deposit: shares = drops (1:1 at scale=0).
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Create vault
    let create_tx = mpt_tx(65, alice_id(), 1, BASE_FEE);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let balance_after_create = state.get_account(&alice_id()).unwrap().balance;

    // Deposit 100 XRP
    let mut deposit_tx = mpt_tx(68, alice_id(), 2, BASE_FEE); // type 68 = VaultDeposit
    deposit_tx.vault_id = Some(vkey.0);
    deposit_tx.amount_drops = Some(100 * XRP);

    let r = run_tx(&mut state, &deposit_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "vault deposit failed: {}", r.ter);

    // Alice lost 100 XRP + fee
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, balance_after_create - 100 * XRP - BASE_FEE);

    // The vault pseudo-account should exist after the deposit.
    // Account count is used here because the pseudo-account address is not
    // exposed through the test harness.
    assert!(state.account_count() >= 2);
}

#[test]
fn vault_withdraw_xrp() {
    // Deposit then withdraw. Should get XRP back.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Create vault
    let create_tx = mpt_tx(65, alice_id(), 1, BASE_FEE);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    // Deposit 100 XRP
    let mut deposit_tx = mpt_tx(68, alice_id(), 2, BASE_FEE);
    deposit_tx.vault_id = Some(vkey.0);
    deposit_tx.amount_drops = Some(100 * XRP);
    run_tx(&mut state, &deposit_tx, &pctx(100), ApplyFlags::NONE);

    let balance_after_deposit = state.get_account(&alice_id()).unwrap().balance;

    // Withdraw 100 XRP worth of shares (shares = drops at scale=0)
    let mut withdraw_tx = mpt_tx(69, alice_id(), 3, BASE_FEE); // type 69 = VaultWithdraw
    withdraw_tx.vault_id = Some(vkey.0);
    withdraw_tx.amount_drops = Some(100 * XRP); // shares to burn

    let r = run_tx(&mut state, &withdraw_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "vault withdraw failed: {}", r.ter);

    // Alice got 100 XRP back minus fee
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, balance_after_deposit + 100 * XRP - BASE_FEE);
}

#[test]
fn vault_delete_nonempty_fails() {
    // Create vault, deposit, try to delete → should fail
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Create vault
    let create_tx = mpt_tx(65, alice_id(), 1, BASE_FEE);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    // Deposit 100 XRP
    let mut deposit_tx = mpt_tx(68, alice_id(), 2, BASE_FEE);
    deposit_tx.vault_id = Some(vkey.0);
    deposit_tx.amount_drops = Some(100 * XRP);
    run_tx(&mut state, &deposit_tx, &pctx(100), ApplyFlags::NONE);

    // Try to delete — should fail (non-empty)
    let mut delete_tx = mpt_tx(67, alice_id(), 3, BASE_FEE);
    delete_tx.vault_id = Some(vkey.0);
    let r = run_tx(&mut state, &delete_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_HAS_OBLIGATIONS,
        "expected tecHAS_OBLIGATIONS, got {}",
        r.ter
    );
}

#[test]
fn vault_second_deposit_pro_rata() {
    // First deposit: 100 XRP → 100 shares (1:1 at scale=0).
    // Second deposit: 50 XRP → 50 shares (pro-rata: 100 shares * 50 / 100 = 50).
    // After both: assetsTotal=150, shares=150.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create_tx = mpt_tx(65, alice_id(), 1, BASE_FEE);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    // First deposit: 100 XRP
    let mut d1 = mpt_tx(68, alice_id(), 2, BASE_FEE);
    d1.vault_id = Some(vkey.0);
    d1.amount_drops = Some(100 * XRP);
    let r = run_tx(&mut state, &d1, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success());

    let balance_after_d1 = state.get_account(&alice_id()).unwrap().balance;

    // Second deposit: 50 XRP
    let mut d2 = mpt_tx(68, alice_id(), 3, BASE_FEE);
    d2.vault_id = Some(vkey.0);
    d2.amount_drops = Some(50 * XRP);
    let r = run_tx(&mut state, &d2, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "second deposit failed: {}", r.ter);

    // Alice lost 50 XRP + fee more
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, balance_after_d1 - 50 * XRP - BASE_FEE);
}

#[test]
fn vault_partial_withdraw() {
    // Deposit 200 XRP, withdraw 80 XRP worth of shares.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create_tx = mpt_tx(65, alice_id(), 1, BASE_FEE);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let mut dep = mpt_tx(68, alice_id(), 2, BASE_FEE);
    dep.vault_id = Some(vkey.0);
    dep.amount_drops = Some(200 * XRP);
    run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);

    let balance_after_dep = state.get_account(&alice_id()).unwrap().balance;

    // Withdraw 80 shares (= 80 XRP at 1:1 for first deposit)
    let mut wd = mpt_tx(69, alice_id(), 3, BASE_FEE);
    wd.vault_id = Some(vkey.0);
    wd.amount_drops = Some(80 * XRP);
    let r = run_tx(&mut state, &wd, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "partial withdraw failed: {}", r.ter);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, balance_after_dep + 80 * XRP - BASE_FEE);
}

#[test]
fn vault_over_withdraw_fails() {
    // Deposit 100, try to withdraw 200 → tecINSUFFICIENT_FUNDS
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create_tx = mpt_tx(65, alice_id(), 1, BASE_FEE);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let mut dep = mpt_tx(68, alice_id(), 2, BASE_FEE);
    dep.vault_id = Some(vkey.0);
    dep.amount_drops = Some(100 * XRP);
    run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);

    // Try to withdraw 200 shares — only 100 exist
    let mut wd = mpt_tx(69, alice_id(), 3, BASE_FEE);
    wd.vault_id = Some(vkey.0);
    wd.amount_drops = Some(200 * XRP);
    let r = run_tx(&mut state, &wd, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tec_claim(), "expected tec failure, got {}", r.ter);
}

#[test]
fn vault_withdraw_to_empty_then_delete() {
    // Deposit 100, withdraw 100, then delete succeeds.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create_tx = mpt_tx(65, alice_id(), 1, BASE_FEE);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    // Deposit
    let mut dep = mpt_tx(68, alice_id(), 2, BASE_FEE);
    dep.vault_id = Some(vkey.0);
    dep.amount_drops = Some(100 * XRP);
    run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);

    // Full withdraw
    let mut wd = mpt_tx(69, alice_id(), 3, BASE_FEE);
    wd.vault_id = Some(vkey.0);
    wd.amount_drops = Some(100 * XRP);
    let r = run_tx(&mut state, &wd, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "full withdraw failed: {}", r.ter);

    // Delete should now succeed
    let mut del = mpt_tx(67, alice_id(), 4, BASE_FEE);
    del.vault_id = Some(vkey.0);
    let r = run_tx(&mut state, &del, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "delete after full withdraw failed: {}",
        r.ter
    );

    assert!(state.get_raw(&vkey).is_none());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}

// ── Loan parity ──────────────────────────────────────────────────────────────

/// Compute LoanBroker SHAMap key: SHA-512-Half(0x006C || owner || sequence).
fn test_loan_broker_key(owner: &[u8; 20], sequence: u32) -> xrpl::ledger::Key {
    let mut data = Vec::with_capacity(26);
    data.extend_from_slice(&[0x00, 0x6C]); // 'l' namespace
    data.extend_from_slice(owner);
    data.extend_from_slice(&sequence.to_be_bytes());
    xrpl::ledger::Key(xrpl::crypto::sha512_first_half(&data))
}

#[test]
fn loan_broker_create_basic() {
    // LoanBrokerSet requires a vault. Create vault first, then broker.
    // owner_count: +2 (vault) +2 (broker) = 4
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Create vault at seq=1
    let create_vault = mpt_tx(65, alice_id(), 1, BASE_FEE);
    run_tx(&mut state, &create_vault, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);

    // Create loan broker at seq=2, linked to vault
    let mut broker_tx = mpt_tx(74, alice_id(), 2, BASE_FEE); // type 74 = LoanBrokerSet
    broker_tx.vault_id = Some(vkey.0);
    let r = run_tx(&mut state, &broker_tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "loan broker create failed: {}",
        r.ter
    );

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 4); // vault(2) + broker(2)
    assert_eq!(a.sequence, 3);

    // LoanBroker SLE should exist
    let bkey = test_loan_broker_key(&alice_id(), 2);
    assert!(state.get_raw(&bkey).is_some(), "broker SLE should exist");

    // Pseudo-account for broker should exist (total: alice + vault pseudo + broker pseudo)
    assert!(state.account_count() >= 3);
}

#[test]
fn loan_broker_delete_empty() {
    // Create vault + broker, then delete broker.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Create vault
    let create_vault = mpt_tx(65, alice_id(), 1, BASE_FEE);
    run_tx(&mut state, &create_vault, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    // Create broker
    let mut broker_tx = mpt_tx(74, alice_id(), 2, BASE_FEE);
    broker_tx.vault_id = Some(vkey.0);
    run_tx(&mut state, &broker_tx, &pctx(100), ApplyFlags::NONE);
    let bkey = test_loan_broker_key(&alice_id(), 2);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 4);

    // Delete broker
    let mut delete_tx = mpt_tx(75, alice_id(), 3, BASE_FEE); // type 75 = LoanBrokerDelete
    delete_tx.vault_id = Some(bkey.0); // broker ID passed as vault_id
    let r = run_tx(&mut state, &delete_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "broker delete failed: {}", r.ter);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 2); // only vault remains

    // Broker SLE should be gone
    assert!(state.get_raw(&bkey).is_none());
}

#[test]
fn loan_broker_create_no_vault_fails() {
    // LoanBrokerSet without a valid vault → tecNO_ENTRY
    let mut state = LedgerState::new();
    fund(&mut state, &kp_alice(), 5_000);

    let mut broker_tx = mpt_tx(74, alice_id(), 1, BASE_FEE);
    broker_tx.vault_id = Some([0xAA; 32]); // nonexistent vault
    let r = run_tx(&mut state, &broker_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_NO_ENTRY,
        "expected tecNO_ENTRY, got {}",
        r.ter
    );
}

/// Helper: set up vault + deposit + broker, return (vkey, bkey).
fn setup_vault_and_broker(state: &mut LedgerState) -> (xrpl::ledger::Key, xrpl::ledger::Key) {
    let create_vault = mpt_tx(65, alice_id(), 1, BASE_FEE);
    run_tx(state, &create_vault, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let mut dep = mpt_tx(68, alice_id(), 2, BASE_FEE);
    dep.vault_id = Some(vkey.0);
    dep.amount_drops = Some(1_000 * XRP);
    run_tx(state, &dep, &pctx(100), ApplyFlags::NONE);

    let mut broker_tx = mpt_tx(74, alice_id(), 3, BASE_FEE);
    broker_tx.vault_id = Some(vkey.0);
    run_tx(state, &broker_tx, &pctx(100), ApplyFlags::NONE);
    let bkey = test_loan_broker_key(&alice_id(), 3);

    (vkey, bkey)
}

/// Compute Loan SHAMap key: SHA-512-Half(0x004C || brokerKey || loanSequence).
fn test_loan_key(broker_key: &[u8; 32], loan_seq: u32) -> xrpl::ledger::Key {
    let mut data = Vec::with_capacity(38);
    data.extend_from_slice(&[0x00, 0x4C]); // 'L' namespace
    data.extend_from_slice(broker_key);
    data.extend_from_slice(&loan_seq.to_be_bytes());
    xrpl::ledger::Key(xrpl::crypto::sha512_first_half(&data))
}

#[test]
fn loan_create_basic() {
    // Create vault → broker → loan. Loan SLE should exist, borrower gets principal.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 5_000);

    // Create vault and deposit 1000 XRP (so there's principal to lend)
    let create_vault = mpt_tx(65, alice_id(), 1, BASE_FEE);
    run_tx(&mut state, &create_vault, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let mut dep = mpt_tx(68, alice_id(), 2, BASE_FEE);
    dep.vault_id = Some(vkey.0);
    dep.amount_drops = Some(1_000 * XRP);
    run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);

    // Create broker linked to vault
    let mut broker_tx = mpt_tx(74, alice_id(), 3, BASE_FEE);
    broker_tx.vault_id = Some(vkey.0);
    run_tx(&mut state, &broker_tx, &pctx(100), ApplyFlags::NONE);
    let bkey = test_loan_broker_key(&alice_id(), 3);

    let bob_balance_before = state.get_account(&bob_id()).unwrap().balance;

    // Bob creates a loan for 100 XRP principal
    let mut loan_tx = mpt_tx(80, bob_id(), 1, BASE_FEE); // type 80 = LoanSet
    loan_tx.vault_id = Some(bkey.0); // broker ID passed as vault_id
    loan_tx.amount_drops = Some(100 * XRP); // principal requested

    let r = run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "loan create failed: {}", r.ter);

    // Bob should have received 100 XRP
    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.balance, bob_balance_before + 100 * XRP - BASE_FEE);
    assert!(b.owner_count >= 1, "bob should own the loan");

    // Loan SLE should exist
    let lkey = test_loan_key(&bkey.0, 1); // first loan sequence = 1
    assert!(state.get_raw(&lkey).is_some(), "loan SLE should exist");
}

#[test]
fn loan_repay_basic() {
    // Create loan for 100 XRP, repay 100 XRP. Principal should be zero.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 5_000);

    let (_vkey, bkey) = setup_vault_and_broker(&mut state);

    // Bob creates loan for 100 XRP
    let mut loan_tx = mpt_tx(80, bob_id(), 1, BASE_FEE);
    loan_tx.vault_id = Some(bkey.0);
    loan_tx.amount_drops = Some(100 * XRP);
    run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    let lkey = test_loan_key(&bkey.0, 1);

    let bob_balance_after_loan = state.get_account(&bob_id()).unwrap().balance;

    // Bob repays 100 XRP
    let mut pay_tx = mpt_tx(84, bob_id(), 2, BASE_FEE); // type 84 = LoanPay
    pay_tx.vault_id = Some(lkey.0); // loan ID
    pay_tx.amount_drops = Some(100 * XRP);

    let r = run_tx(&mut state, &pay_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "loan repay failed: {}", r.ter);

    // Bob lost 100 XRP + fee
    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.balance, bob_balance_after_loan - 100 * XRP - BASE_FEE);
}

#[test]
fn loan_partial_repay() {
    // Create loan for 200 XRP, repay 80. Principal should be 120.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 5_000);

    let (_vkey, bkey) = setup_vault_and_broker(&mut state);

    let mut loan_tx = mpt_tx(80, bob_id(), 1, BASE_FEE);
    loan_tx.vault_id = Some(bkey.0);
    loan_tx.amount_drops = Some(200 * XRP);
    run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    let lkey = test_loan_key(&bkey.0, 1);

    let bob_balance = state.get_account(&bob_id()).unwrap().balance;

    // Repay 80 XRP
    let mut pay_tx = mpt_tx(84, bob_id(), 2, BASE_FEE);
    pay_tx.vault_id = Some(lkey.0);
    pay_tx.amount_drops = Some(80 * XRP);
    let r = run_tx(&mut state, &pay_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "partial repay failed: {}", r.ter);

    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.balance, bob_balance - 80 * XRP - BASE_FEE);

    // Loan should still exist (not fully repaid)
    assert!(state.get_raw(&lkey).is_some());
}

#[test]
fn loan_over_repay_fails() {
    // Create loan for 100 XRP, try to repay 200. Should fail.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 5_000);

    let (_vkey, bkey) = setup_vault_and_broker(&mut state);

    let mut loan_tx = mpt_tx(80, bob_id(), 1, BASE_FEE);
    loan_tx.vault_id = Some(bkey.0);
    loan_tx.amount_drops = Some(100 * XRP);
    run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    let lkey = test_loan_key(&bkey.0, 1);

    // Try to repay 200 XRP (more than principal)
    let mut pay_tx = mpt_tx(84, bob_id(), 2, BASE_FEE);
    pay_tx.vault_id = Some(lkey.0);
    pay_tx.amount_drops = Some(200 * XRP);
    let r = run_tx(&mut state, &pay_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tec_claim(), "expected tec failure, got {}", r.ter);
}

#[test]
fn loan_delete_active_fails() {
    // Create loan, don't repay, try to delete. Should fail.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 5_000);

    let (_vkey, bkey) = setup_vault_and_broker(&mut state);

    let mut loan_tx = mpt_tx(80, bob_id(), 1, BASE_FEE);
    loan_tx.vault_id = Some(bkey.0);
    loan_tx.amount_drops = Some(100 * XRP);
    run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    let lkey = test_loan_key(&bkey.0, 1);

    // Try to delete active loan
    let mut del_tx = mpt_tx(81, bob_id(), 2, BASE_FEE); // type 81 = LoanDelete
    del_tx.vault_id = Some(lkey.0);
    let r = run_tx(&mut state, &del_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_HAS_OBLIGATIONS,
        "expected tecHAS_OBLIGATIONS, got {}",
        r.ter
    );
}

#[test]
fn loan_repay_to_zero_then_delete() {
    // Full lifecycle: create → repay fully → delete loan
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 5_000);

    let (_vkey, bkey) = setup_vault_and_broker(&mut state);

    // Create loan
    let mut loan_tx = mpt_tx(80, bob_id(), 1, BASE_FEE);
    loan_tx.vault_id = Some(bkey.0);
    loan_tx.amount_drops = Some(100 * XRP);
    run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    let lkey = test_loan_key(&bkey.0, 1);

    assert!(state.get_account(&bob_id()).unwrap().owner_count >= 1);

    // Full repayment
    let mut pay_tx = mpt_tx(84, bob_id(), 2, BASE_FEE);
    pay_tx.vault_id = Some(lkey.0);
    pay_tx.amount_drops = Some(100 * XRP);
    run_tx(&mut state, &pay_tx, &pctx(100), ApplyFlags::NONE);

    // Delete loan
    let mut del_tx = mpt_tx(81, bob_id(), 3, BASE_FEE);
    del_tx.vault_id = Some(lkey.0);
    let r = run_tx(&mut state, &del_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "loan delete failed: {}", r.ter);

    // Loan SLE gone
    assert!(state.get_raw(&lkey).is_none());

    // Bob's owner_count should have decreased
    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.owner_count, 0);
}

#[test]
fn loan_create_no_broker_fails() {
    // LoanSet without a valid broker → tecNO_ENTRY
    let mut state = LedgerState::new();
    let bob = kp_bob();
    fund(&mut state, &bob, 5_000);

    let mut loan_tx = mpt_tx(80, bob_id(), 1, BASE_FEE);
    loan_tx.vault_id = Some([0xBB; 32]); // nonexistent broker
    loan_tx.amount_drops = Some(100 * XRP);

    let r = run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_NO_ENTRY,
        "expected tecNO_ENTRY, got {}",
        r.ter
    );
}

// ── AMM parity ───────────────────────────────────────────────────────────────
//
// AMM key derivation: SHA-512-Half(0x0041 || min_issue.account || min_issue.currency
//                                          || max_issue.account || max_issue.currency)
// Assets sorted lexicographically. For XRP: account=[0;20], currency=[0;20].
//
// AMM creates: pseudo-account, AMM SLE, LP tokens, trustlines, order books.
// LP token initial mint: sqrt(asset1 * asset2).
// owner_count += 1 on pseudo-account.

/// Compute AMM key locally for testing (same as amm.rs).
fn test_amm_key(
    issue1: &xrpl::transaction::amount::Issue,
    issue2: &xrpl::transaction::amount::Issue,
) -> xrpl::ledger::Key {
    // Sort issues by (currency, account) for canonical ordering
    fn parts(i: &xrpl::transaction::amount::Issue) -> ([u8; 20], [u8; 20]) {
        match i {
            xrpl::transaction::amount::Issue::Xrp => ([0u8; 20], [0u8; 20]),
            xrpl::transaction::amount::Issue::Iou { currency, issuer } => (*issuer, currency.code),
            xrpl::transaction::amount::Issue::Mpt(_) => ([0u8; 20], [0u8; 20]),
        }
    }
    let (a_acct, a_cur) = parts(issue1);
    let (b_acct, b_cur) = parts(issue2);
    let (min_acct, min_cur, max_acct, max_cur) = match a_cur.cmp(&b_cur) {
        std::cmp::Ordering::Less => (a_acct, a_cur, b_acct, b_cur),
        std::cmp::Ordering::Greater => (b_acct, b_cur, a_acct, a_cur),
        std::cmp::Ordering::Equal => {
            if a_acct <= b_acct {
                (a_acct, a_cur, b_acct, b_cur)
            } else {
                (b_acct, b_cur, a_acct, a_cur)
            }
        }
    };
    let mut data = Vec::with_capacity(82);
    data.extend_from_slice(&[0x00, 0x41]);
    data.extend_from_slice(&min_acct);
    data.extend_from_slice(&min_cur);
    data.extend_from_slice(&max_acct);
    data.extend_from_slice(&max_cur);
    xrpl::ledger::Key(xrpl::crypto::sha512_first_half(&data))
}

#[test]
fn amm_create_basic() {
    // AMMCreate with XRP + USD(bob) → tesSUCCESS
    use xrpl::transaction::amount::{Currency, Issue};

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let xrp_issue = Issue::Xrp;
    let usd_issue = Issue::Iou {
        currency: Currency::from_code("USD").unwrap(),
        issuer: bob_id(),
    };

    let mut tx = mpt_tx(35, alice_id(), 1, BASE_FEE); // type 35 = AMMCreate
    tx.asset = Some(xrp_issue.clone());
    tx.asset2 = Some(usd_issue.clone());

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm create failed: {}", r.ter);

    // AMM SLE should exist
    let akey = test_amm_key(&xrp_issue, &usd_issue);
    assert!(state.get_raw(&akey).is_some(), "AMM SLE should exist");

    // Pseudo-account should exist
    assert!(state.account_count() >= 3, "pseudo-account should exist");

    // Owner count increased
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 1);
    assert_eq!(a.sequence, 2);
}

#[test]
fn amm_create_same_asset_fails() {
    use xrpl::transaction::amount::Issue;

    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let mut tx = mpt_tx(35, alice_id(), 1, BASE_FEE);
    tx.asset = Some(Issue::Xrp);
    tx.asset2 = Some(Issue::Xrp); // same asset!

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tec_claim() || r.ter.token().contains("BAD_AMM"),
        "expected failure for same asset pair, got {}",
        r.ter
    );
}

#[test]
fn amm_create_duplicate_fails() {
    use xrpl::transaction::amount::{Currency, Issue};

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let xrp = Issue::Xrp;
    let usd = Issue::Iou {
        currency: Currency::from_code("USD").unwrap(),
        issuer: bob_id(),
    };

    // First create succeeds
    let mut tx = mpt_tx(35, alice_id(), 1, BASE_FEE);
    tx.asset = Some(xrp.clone());
    tx.asset2 = Some(usd.clone());
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    // Second create with same pair → tecDUPLICATE
    let mut tx2 = mpt_tx(35, alice_id(), 2, BASE_FEE);
    tx2.asset = Some(xrp.clone());
    tx2.asset2 = Some(usd.clone());
    let r = run_tx(&mut state, &tx2, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_DUPLICATE,
        "expected tecDUPLICATE, got {}",
        r.ter
    );
}

#[test]
fn amm_delete_empty() {
    use xrpl::transaction::amount::{Currency, Issue};

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let xrp = Issue::Xrp;
    let usd = Issue::Iou {
        currency: Currency::from_code("USD").unwrap(),
        issuer: bob_id(),
    };

    // Create AMM
    let mut tx = mpt_tx(35, alice_id(), 1, BASE_FEE);
    tx.asset = Some(xrp.clone());
    tx.asset2 = Some(usd.clone());
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let akey = test_amm_key(&xrp, &usd);
    assert!(state.get_raw(&akey).is_some());

    // Delete AMM (empty, no deposits)
    let mut del = mpt_tx(40, alice_id(), 2, BASE_FEE); // type 40 = AMMDelete
    del.asset = Some(xrp.clone());
    del.asset2 = Some(usd.clone());
    let r = run_tx(&mut state, &del, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm delete failed: {}", r.ter);

    // AMM SLE should be gone
    assert!(state.get_raw(&akey).is_none(), "AMM SLE should be removed");

    // Owner count back to 0
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 0);
}

#[test]
fn amm_delete_nonempty_fails() {
    use xrpl::transaction::amount::{Currency, Issue};

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let xrp = Issue::Xrp;
    let usd = Issue::Iou {
        currency: Currency::from_code("USD").unwrap(),
        issuer: bob_id(),
    };

    let mut create = mpt_tx(35, alice_id(), 1, BASE_FEE);
    create.asset = Some(xrp.clone());
    create.asset2 = Some(usd.clone());
    let r = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm create failed: {}", r.ter);

    let mut deposit = mpt_tx(36, alice_id(), 2, BASE_FEE);
    deposit.asset = Some(xrp.clone());
    deposit.asset2 = Some(usd.clone());
    deposit.amount_drops = Some(100 * XRP);
    let r = run_tx(&mut state, &deposit, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm deposit failed: {}", r.ter);

    let akey = test_amm_key(&xrp, &usd);
    assert!(
        state.get_raw(&akey).is_some(),
        "AMM SLE should exist before delete"
    );

    let mut del = mpt_tx(40, alice_id(), 3, BASE_FEE);
    del.asset = Some(xrp.clone());
    del.asset2 = Some(usd.clone());
    let r = run_tx(&mut state, &del, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter.to_string(),
        "tecHAS_OBLIGATIONS",
        "expected tecHAS_OBLIGATIONS, got {}",
        r.ter
    );

    assert!(
        state.get_raw(&akey).is_some(),
        "AMM SLE should remain after failed delete"
    );
}

#[test]
fn amm_deposit_basic() {
    // Deposit XRP into AMM pool, LP tokens minted.
    use xrpl::transaction::amount::{Currency, Issue};

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let xrp = Issue::Xrp;
    let usd = Issue::Iou {
        currency: Currency::from_code("USD").unwrap(),
        issuer: bob_id(),
    };

    // Create AMM
    let mut tx = mpt_tx(35, alice_id(), 1, BASE_FEE);
    tx.asset = Some(xrp.clone());
    tx.asset2 = Some(usd.clone());
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let balance_before = state.get_account(&alice_id()).unwrap().balance;

    // Deposit 100 XRP
    let mut dep = mpt_tx(36, alice_id(), 2, BASE_FEE); // type 36 = AMMDeposit
    dep.asset = Some(xrp.clone());
    dep.asset2 = Some(usd.clone());
    dep.amount_drops = Some(100 * XRP);

    let r = run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm deposit failed: {}", r.ter);

    // Alice lost 100 XRP + fee
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, balance_before - 100 * XRP - BASE_FEE);
}

#[test]
fn amm_withdraw_basic() {
    // Deposit then withdraw from AMM pool.
    use xrpl::transaction::amount::{Currency, Issue};

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let xrp = Issue::Xrp;
    let usd = Issue::Iou {
        currency: Currency::from_code("USD").unwrap(),
        issuer: bob_id(),
    };

    // Create + deposit
    let mut tx = mpt_tx(35, alice_id(), 1, BASE_FEE);
    tx.asset = Some(xrp.clone());
    tx.asset2 = Some(usd.clone());
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let mut dep = mpt_tx(36, alice_id(), 2, BASE_FEE);
    dep.asset = Some(xrp.clone());
    dep.asset2 = Some(usd.clone());
    dep.amount_drops = Some(100 * XRP);
    run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);

    let balance_after_dep = state.get_account(&alice_id()).unwrap().balance;

    // Withdraw all LP tokens (first deposit: LP = sqrt(100M * 100M) = 100M = 100 XRP in drops)
    // isqrt(100_000_000 * 100_000_000) = 100_000_000
    let mut wd = mpt_tx(37, alice_id(), 3, BASE_FEE); // type 37 = AMMWithdraw
    wd.asset = Some(xrp.clone());
    wd.asset2 = Some(usd.clone());
    wd.amount_drops = Some(100 * XRP); // burn all LP tokens

    let r = run_tx(&mut state, &wd, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm withdraw failed: {}", r.ter);

    // Alice got 100 XRP back minus fee
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, balance_after_dep + 100 * XRP - BASE_FEE);
}

#[test]
fn amm_withdraw_too_much_fails() {
    use xrpl::transaction::amount::{Currency, Issue};

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let xrp = Issue::Xrp;
    let usd = Issue::Iou {
        currency: Currency::from_code("USD").unwrap(),
        issuer: bob_id(),
    };

    // Create + deposit 100 XRP
    let mut tx = mpt_tx(35, alice_id(), 1, BASE_FEE);
    tx.asset = Some(xrp.clone());
    tx.asset2 = Some(usd.clone());
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let mut dep = mpt_tx(36, alice_id(), 2, BASE_FEE);
    dep.asset = Some(xrp.clone());
    dep.asset2 = Some(usd.clone());
    dep.amount_drops = Some(100 * XRP);
    run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);

    // Try to withdraw 200 LP tokens (only 100 exist)
    let mut wd = mpt_tx(37, alice_id(), 3, BASE_FEE);
    wd.asset = Some(xrp.clone());
    wd.asset2 = Some(usd.clone());
    wd.amount_drops = Some(200 * XRP);

    let r = run_tx(&mut state, &wd, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tec_claim(), "expected tec failure, got {}", r.ter);
}

// ── NFToken page-model parity ─────────────────────────────────────────────────

#[test]
fn nft_page_mint_creates_page() {
    // Minting an NFT should create an NFTokenPage SLE for the owner.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mut tx = mpt_tx(25, alice_id(), 1, BASE_FEE);
    tx.nftoken_taxon = Some(1);
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "mint failed: {}", r.ter);

    // Verify the NFT exists in the flat store
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.minted_nftokens, 1);
    assert_eq!(a.owner_count, 1);
}

#[test]
fn nft_page_mint_multiple_same_page() {
    // Multiple NFTs from the same owner should fit on one page (up to 32).
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    for seq in 1..=5u32 {
        let mut tx = mpt_tx(25, alice_id(), seq, BASE_FEE);
        tx.nftoken_taxon = Some(1);
        let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
        assert!(r.ter.is_tes_success(), "mint {} failed: {}", seq, r.ter);
    }

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.minted_nftokens, 5);
    assert_eq!(a.owner_count, 5);
}

#[test]
fn nft_page_burn_removes_from_page() {
    // Burn should remove the NFT and decrement owner_count.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Mint 3 NFTs
    for seq in 1..=3u32 {
        let mut tx = mpt_tx(25, alice_id(), seq, BASE_FEE);
        tx.nftoken_taxon = Some(1);
        run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    }
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 3);

    // Find and burn the first NFT
    let nft_id = {
        let mut found = None;
        for (id, _) in state.iter_nftokens() {
            found = Some(*id);
            break;
        }
        found.unwrap()
    };

    let mut burn_tx = mpt_tx(26, alice_id(), 4, BASE_FEE);
    burn_tx.nftoken_id = Some(nft_id);
    let r = run_tx(&mut state, &burn_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "burn failed: {}", r.ter);

    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);
    assert_eq!(state.get_account(&alice_id()).unwrap().burned_nftokens, 1);
}

#[test]
fn nft_page_burn_all_cleans_up() {
    // Burning all NFTs should leave owner_count at 0.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Mint 2
    for seq in 1..=2u32 {
        let mut tx = mpt_tx(25, alice_id(), seq, BASE_FEE);
        tx.nftoken_taxon = Some(1);
        run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    }

    // Burn all
    let ids: Vec<[u8; 32]> = state.iter_nftokens().map(|(id, _)| *id).collect();
    for (i, nft_id) in ids.iter().enumerate() {
        let mut burn_tx = mpt_tx(26, alice_id(), 3 + i as u32, BASE_FEE);
        burn_tx.nftoken_id = Some(*nft_id);
        let r = run_tx(&mut state, &burn_tx, &pctx(100), ApplyFlags::NONE);
        assert!(r.ter.is_tes_success(), "burn {} failed: {}", i, r.ter);
    }

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 0);
    assert_eq!(a.burned_nftokens, 2);
}

#[test]
fn nft_page_split_on_overflow() {
    // Mint 33 NFTs — should trigger a page split at 32.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 50_000);

    for seq in 1..=33u32 {
        let mut tx = mpt_tx(25, alice_id(), seq, BASE_FEE);
        tx.nftoken_taxon = Some(1);
        let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
        assert!(r.ter.is_tes_success(), "mint {} failed: {}", seq, r.ter);
    }

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.minted_nftokens, 33);
    assert_eq!(a.owner_count, 33);
}

#[test]
fn nft_page_burn_after_split() {
    // Mint 33 (triggers split), then burn one. Should work correctly.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 50_000);

    for seq in 1..=33u32 {
        let mut tx = mpt_tx(25, alice_id(), seq, BASE_FEE);
        tx.nftoken_taxon = Some(1);
        run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    }

    // Find and burn one NFT
    let nft_id = {
        let mut found = None;
        for (id, _) in state.iter_nftokens() {
            found = Some(*id);
            break;
        }
        found.unwrap()
    };

    let mut burn_tx = mpt_tx(26, alice_id(), 34, BASE_FEE);
    burn_tx.nftoken_id = Some(nft_id);
    let r = run_tx(&mut state, &burn_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "burn after split failed: {}", r.ter);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 32);
    assert_eq!(a.burned_nftokens, 1);
}

#[test]
fn nft_page_sle_exists_in_shamap() {
    // After minting, the page SLE should exist in state_map at the correct key.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mut tx = mpt_tx(25, alice_id(), 1, BASE_FEE);
    tx.nftoken_taxon = Some(1);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    // The page key should be owner(20) || pageMask-masked low bits
    // For the first mint, the page should be at page_max (all 0xFF in low 12)
    let max_key = xrpl::ledger::nft_page::page_max(&alice_id());
    let raw = state.get_raw(&max_key);
    assert!(
        raw.is_some(),
        "page SLE should exist in state_map at page_max key"
    );
}

#[test]
fn nft_page_split_creates_two_sles() {
    // Mint 33 NFTs. Should create 2 page SLEs after split.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 50_000);

    for seq in 1..=33u32 {
        let mut tx = mpt_tx(25, alice_id(), seq, BASE_FEE);
        tx.nftoken_taxon = Some(1);
        run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    }

    // Count page SLEs for alice in the BTreeMap
    let page_count = state.nft_page_count(&alice_id());
    assert!(
        page_count >= 2,
        "should have at least 2 pages after split, got {}",
        page_count
    );

    // Both pages should have SLEs in state_map
    let mut sle_count = 0;
    for (key, _page) in state.iter_nft_pages_for(&alice_id()) {
        if state.get_raw(&key).is_some() {
            sle_count += 1;
        }
    }
    assert!(
        sle_count >= 2,
        "should have at least 2 page SLEs in state_map"
    );
}

#[test]
fn nft_page_empty_page_deleted_from_shamap() {
    // Mint 1 NFT, burn it. The page SLE should be removed from state_map.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mut tx = mpt_tx(25, alice_id(), 1, BASE_FEE);
    tx.nftoken_taxon = Some(1);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let max_key = xrpl::ledger::nft_page::page_max(&alice_id());
    assert!(
        state.get_raw(&max_key).is_some(),
        "page should exist after mint"
    );

    // Find and burn the NFT
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();
    let mut burn_tx = mpt_tx(26, alice_id(), 2, BASE_FEE);
    burn_tx.nftoken_id = Some(nft_id);
    run_tx(&mut state, &burn_tx, &pctx(100), ApplyFlags::NONE);

    // Page should be gone from state_map
    assert!(
        state.get_raw(&max_key).is_none(),
        "empty page SLE should be deleted"
    );
    assert_eq!(state.nft_page_count(&alice_id()), 0);
}

#[test]
fn nft_page_transfer_moves_between_owners() {
    // Mint NFT for alice, create sell offer, bob accepts.
    // NFT should move from alice's page to bob's page.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    // Alice mints
    let mut mint = mpt_tx(25, alice_id(), 1, BASE_FEE);
    mint.nftoken_taxon = Some(1);
    run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    assert_eq!(state.nft_page_count(&alice_id()), 1);
    assert_eq!(state.nft_page_count(&bob_id()), 0);

    // Alice creates sell offer (free transfer)
    let mut offer_tx = mpt_tx(27, alice_id(), 2, BASE_FEE); // type 27 = NFTokenCreateOffer
    offer_tx.nftoken_id = Some(nft_id);
    offer_tx.amount = Some(Amount::Xrp(0)); // free
    offer_tx.flags = 0x0001; // tfSellNFToken
    run_tx(&mut state, &offer_tx, &pctx(100), ApplyFlags::NONE);

    // Find the offer key
    let offer_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 2);

    // Bob accepts
    let mut accept_tx = mpt_tx(29, bob_id(), 1, BASE_FEE); // type 29 = NFTokenAcceptOffer
    accept_tx.nft_sell_offer = Some(offer_key.0);
    let r = run_tx(&mut state, &accept_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "accept failed: {}", r.ter);

    // Alice's page should be empty/gone, bob's should have 1
    assert_eq!(
        state.nft_page_count(&alice_id()),
        0,
        "alice should have no pages"
    );
    assert!(
        state.nft_page_count(&bob_id()) >= 1,
        "bob should have a page"
    );
}

#[test]
fn nft_page_merge_on_removal() {
    // Mint 33 (split into 2 pages), burn enough to trigger merge back to 1.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 100_000);

    // Mint 33 → 2 pages
    for seq in 1..=33u32 {
        let mut tx = mpt_tx(25, alice_id(), seq, BASE_FEE);
        tx.nftoken_taxon = Some(1);
        run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    }
    assert!(
        state.nft_page_count(&alice_id()) >= 2,
        "should have 2+ pages after 33 mints"
    );

    // Burn tokens until the owner returns to 32 or fewer entries, which
    // should trigger a page merge.
    let ids: Vec<[u8; 32]> = state
        .iter_nftokens()
        .filter(|(_, nft)| nft.owner == alice_id())
        .map(|(id, _)| *id)
        .take(17) // burn 17, leaving 16
        .collect();

    for (i, nft_id) in ids.iter().enumerate() {
        let mut burn_tx = mpt_tx(26, alice_id(), 34 + i as u32, BASE_FEE);
        burn_tx.nftoken_id = Some(*nft_id);
        let r = run_tx(&mut state, &burn_tx, &pctx(100), ApplyFlags::NONE);
        assert!(r.ter.is_tes_success(), "burn {} failed: {}", i, r.ter);
    }

    // Should have merged back to 1 page (16 tokens fits on one page)
    let page_count = state.nft_page_count(&alice_id());
    assert_eq!(
        page_count, 1,
        "should have merged to 1 page, got {}",
        page_count
    );
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 16);
}

// ── NFToken behavioral parity ─────────────────────────────────────────────────
//
// NOTE: xLedgRS uses flat NFT storage (one SHAMap entry per token), not rippled's
// page-based model (32 tokens per NFTokenPage with split/merge logic). This means
// state-tree hashes will NOT match rippled for NFT-heavy ledgers. Transaction
// behavior (TER codes, owner counts, balances) IS tested here.
// Page-based storage is a future state-hash parity task.

#[test]
fn nft_mint_basic() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mut tx = mpt_tx(25, alice_id(), 1, BASE_FEE); // type 25 = NFTokenMint
    tx.nftoken_taxon = Some(42);

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "nft mint failed: {}", r.ter);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 1);
    assert_eq!(a.minted_nftokens, 1);
    assert_eq!(a.sequence, 2);
}

#[test]
fn nft_mint_multiple() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    for seq in 1..=3 {
        let mut tx = mpt_tx(25, alice_id(), seq, BASE_FEE);
        tx.nftoken_taxon = Some(1);
        let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
        assert!(r.ter.is_tes_success(), "mint {} failed: {}", seq, r.ter);
    }

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 3);
    assert_eq!(a.minted_nftokens, 3);
}

#[test]
fn nft_burn_reduces_owner_count() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Mint
    let mut mint_tx = mpt_tx(25, alice_id(), 1, BASE_FEE);
    mint_tx.nftoken_taxon = Some(1);
    run_tx(&mut state, &mint_tx, &pctx(100), ApplyFlags::NONE);

    // Find the NFT ID
    let nft_id = {
        let mut found = None;
        for (id, _nft) in state.iter_nftokens() {
            found = Some(*id);
            break;
        }
        found.expect("should have minted an NFT")
    };

    // Burn
    let mut burn_tx = mpt_tx(26, alice_id(), 2, BASE_FEE); // type 26 = NFTokenBurn
    burn_tx.nftoken_id = Some(nft_id);

    let r = run_tx(&mut state, &burn_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "nft burn failed: {}", r.ter);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 0);
    assert_eq!(a.burned_nftokens, 1);
}

#[test]
fn nft_burn_nonexistent_fails() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mut burn_tx = mpt_tx(26, alice_id(), 1, BASE_FEE);
    burn_tx.nftoken_id = Some([0xAA; 32]);

    let r = run_tx(&mut state, &burn_tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tec_claim(),
        "expected tec for nonexistent NFT, got {}",
        r.ter
    );
}

// Historical object-versioning tests were removed with the old object-history
// storage model. The current storage layer persists validated ledgers in SQLite
// plus SHAMap nodes in NuDB, so these API-shape tests no longer apply.

// ── MPT parity ───────────────────────────────────────────────────────────────

/// Build a minimal ParsedTx for MPT operations.
fn mpt_tx(tx_type: u16, account: [u8; 20], seq: u32, fee: u64) -> ParsedTx {
    ParsedTx {
        tx_type,
        account,
        sequence: seq,
        fee,
        flags: 0,
        amount_drops: None,
        destination: None,
        amount: None,
        limit_amount: None,
        taker_pays: None,
        taker_gets: None,
        deliver_min: None,
        offer_sequence: None,
        finish_after: None,
        cancel_after: None,
        settle_delay: None,
        expiration: None,
        set_flag: None,
        clear_flag: None,
        transfer_rate: None,
        tick_size: None,
        last_ledger_seq: None,
        ticket_count: None,
        ticket_sequence: None,
        domain: None,
        channel: None,
        public_key: None,
        paychan_sig: None,
        nftoken_id: None,
        nft_sell_offer: None,
        nft_buy_offer: None,
        uri: None,
        did_document: None,
        did_data: None,
        nftoken_taxon: None,
        transfer_fee_field: None,
        asset_scale: None,
        maximum_amount: None,
        mutable_flags: None,
        mptoken_metadata: None,
        owner: None,
        regular_key: None,
        issuer: None,
        subject: None,
        credential_type: None,
        oracle_document_id: None,
        signer_quorum: None,
        signer_entries_raw: None,
        domain_id: None,
        ledger_fix_type: None,
        accepted_credentials_raw: None,
        authorize: None,
        permissions_raw: None,
        holder: None,
        mptoken_issuance_id: None,
        asset: None,
        asset2: None,
        vault_id: None,
        amendment: None,
        base_fee_field: None,
        reserve_base_field: None,
        reserve_increment_field: None,
        unl_modify_disabling: None,
        unl_modify_validator: None,
        send_max: None,
        paths: Vec::new(),
        signing_pubkey: vec![0x02; 33],
        signature: vec![0; 64],
        signing_hash: [0u8; 32],
        signing_payload: vec![],
        signers: Vec::new(),
    }
}

/// Compute Vault SHAMap key locally: SHA-512-Half(0x0056 || account || sequence).
fn test_vault_key(owner: &[u8; 20], sequence: u32) -> xrpl::ledger::Key {
    let mut data = Vec::with_capacity(26);
    data.extend_from_slice(&[0x00, 0x56]); // 'V' namespace
    data.extend_from_slice(owner);
    data.extend_from_slice(&sequence.to_be_bytes());
    xrpl::ledger::Key(xrpl::crypto::sha512_first_half(&data))
}

/// Construct MPTID from sequence + account (4 + 20 = 24 bytes).
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

fn sle_flags(raw: &[u8]) -> u32 {
    xrpl::ledger::meta::parse_sle(raw)
        .and_then(|sle| {
            sle.fields.into_iter().find_map(|field| {
                (field.type_code == 2 && field.field_code == 2 && field.data.len() >= 4).then(
                    || {
                        u32::from_be_bytes([
                            field.data[0],
                            field.data[1],
                            field.data[2],
                            field.data[3],
                        ])
                    },
                )
            })
        })
        .unwrap_or(0)
}

#[test]
fn mpt_issuance_create_basic() {
    // rippled: MPTokenIssuanceCreate → tesSUCCESS, owner_count +1
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mut tx = mpt_tx(54, alice_id(), 1, BASE_FEE); // type 54 = MPTokenIssuanceCreate
    tx.maximum_amount = Some(100);
    tx.asset_scale = Some(0);

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "mpt issuance create failed: {}",
        r.ter
    );

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 1);
    assert_eq!(a.sequence, 2);
    assert_eq!(a.balance, 5_000 * XRP - BASE_FEE);

    // Issuance SLE should exist in raw state
    let mptid = make_mptid(1, &alice_id());
    let key = {
        let mut data = Vec::with_capacity(26);
        data.extend_from_slice(&[0x00, 0x7E]);
        data.extend_from_slice(&mptid);
        xrpl::ledger::Key(xrpl::crypto::sha512_first_half(&data))
    };
    assert!(state.get_raw(&key).is_some(), "issuance SLE should exist");
}

#[test]
fn mpt_issuance_destroy_basic() {
    // rippled: create then destroy → owner_count back to 0
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Create
    let mut tx = mpt_tx(54, alice_id(), 1, BASE_FEE);
    tx.maximum_amount = Some(100);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    // Destroy
    let mptid = make_mptid(1, &alice_id());
    let mut tx = mpt_tx(55, alice_id(), 2, BASE_FEE); // type 55 = MPTokenIssuanceDestroy
    tx.mptoken_issuance_id = Some(mptid);

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "mpt issuance destroy failed: {}",
        r.ter
    );

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 0);
    assert_eq!(a.sequence, 3);
}

#[test]
fn mpt_issuance_destroy_nonexistent() {
    // rippled: destroy non-existent → tecOBJECT_NOT_FOUND (or tecNO_ENTRY)
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let fake_mptid = make_mptid(99, &alice_id());
    let mut tx = mpt_tx(55, alice_id(), 1, BASE_FEE);
    tx.mptoken_issuance_id = Some(fake_mptid);

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    // Should fail — issuance doesn't exist
    assert!(
        !r.ter.is_tes_success(),
        "expected failure for nonexistent issuance"
    );
}

#[test]
fn mpt_authorize_holder_creates_mptoken() {
    // rippled: holder (bob) authorizes → creates MPToken SLE, owner_count +1
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    // Alice creates issuance
    let mut tx = mpt_tx(54, alice_id(), 1, BASE_FEE);
    tx.maximum_amount = Some(1000);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let mptid = make_mptid(1, &alice_id());

    // Bob creates MPToken (holder authorize, no holder field)
    let mut tx = mpt_tx(57, bob_id(), 1, BASE_FEE); // type 57 = MPTokenAuthorize
    tx.mptoken_issuance_id = Some(mptid);
    // No holder field → holder path (bob is creating his own MPToken)

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "mpt authorize (holder create) failed: {}",
        r.ter
    );

    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.owner_count, 1);
    assert_eq!(b.sequence, 2);
}

#[test]
fn mpt_authorize_duplicate_fails() {
    // rippled: duplicate MPToken creation → tecDUPLICATE
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    // Create issuance
    let mut tx = mpt_tx(54, alice_id(), 1, BASE_FEE);
    tx.maximum_amount = Some(1000);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let mptid = make_mptid(1, &alice_id());

    // Bob creates MPToken (first time)
    let mut tx = mpt_tx(57, bob_id(), 1, BASE_FEE);
    tx.mptoken_issuance_id = Some(mptid);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    // Bob tries to create again → tecDUPLICATE
    let mut tx = mpt_tx(57, bob_id(), 2, BASE_FEE);
    tx.mptoken_issuance_id = Some(mptid);
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_DUPLICATE,
        "expected tecDUPLICATE, got {}",
        r.ter
    );
}

#[test]
fn mpt_authorize_holder_destroys_mptoken() {
    // rippled: holder destroys MPToken with tfMPTUnauthorize → owner_count -1
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    // Create issuance + holder MPToken
    let mut tx = mpt_tx(54, alice_id(), 1, BASE_FEE);
    tx.maximum_amount = Some(1000);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let mptid = make_mptid(1, &alice_id());

    let mut tx = mpt_tx(57, bob_id(), 1, BASE_FEE);
    tx.mptoken_issuance_id = Some(mptid);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 1);

    // Destroy with tfMPTUnauthorize (0x01)
    let mut tx = mpt_tx(57, bob_id(), 2, BASE_FEE);
    tx.mptoken_issuance_id = Some(mptid);
    tx.flags = 0x0000_0001; // tfMPTUnauthorize

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "mpt unauthorize failed: {}", r.ter);

    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.owner_count, 0);
}

#[test]
fn mpt_issuance_set_modifies_flags() {
    // rippled: MPTokenIssuanceSet can modify mutable fields
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Create issuance with metadata
    let mut tx = mpt_tx(54, alice_id(), 1, BASE_FEE);
    tx.maximum_amount = Some(1000);
    tx.mptoken_metadata = Some(b"initial".to_vec());
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let mptid = make_mptid(1, &alice_id());

    // Set: update metadata
    let mut tx = mpt_tx(56, alice_id(), 2, BASE_FEE); // type 56 = MPTokenIssuanceSet
    tx.mptoken_issuance_id = Some(mptid);
    tx.mptoken_metadata = Some(b"updated".to_vec());

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "mpt issuance set failed: {}", r.ter);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.sequence, 3);
    // owner_count should be unchanged (set doesn't change ownership)
    assert_eq!(a.owner_count, 1);
}

#[test]
fn mpt_issuance_set_nonexistent_fails() {
    // rippled: set on nonexistent issuance → tecNO_ENTRY
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let fake_mptid = make_mptid(99, &alice_id());
    let mut tx = mpt_tx(56, alice_id(), 1, BASE_FEE);
    tx.mptoken_issuance_id = Some(fake_mptid);
    tx.mptoken_metadata = Some(b"test".to_vec());

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_NO_ENTRY,
        "expected tecNO_ENTRY, got {}",
        r.ter
    );
}

#[test]
fn mpt_full_lifecycle() {
    // Create issuance → holder authorizes → holder destroys → issuer destroys issuance
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    // 1. Alice creates issuance
    let mut tx = mpt_tx(54, alice_id(), 1, BASE_FEE);
    tx.maximum_amount = Some(1000);
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);

    let mptid = make_mptid(1, &alice_id());

    // 2. Bob creates MPToken
    let mut tx = mpt_tx(57, bob_id(), 1, BASE_FEE);
    tx.mptoken_issuance_id = Some(mptid);
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success());
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 1);

    // 3. Bob destroys MPToken
    let mut tx = mpt_tx(57, bob_id(), 2, BASE_FEE);
    tx.mptoken_issuance_id = Some(mptid);
    tx.flags = 0x01; // tfMPTUnauthorize
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success());
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 0);

    // 4. Alice destroys issuance (no holders remaining)
    let mut tx = mpt_tx(55, alice_id(), 2, BASE_FEE);
    tx.mptoken_issuance_id = Some(mptid);
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}

#[test]
fn mpt_payment_direct_creates_holder_and_tracks_outstanding() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mut create = mpt_tx(54, alice_id(), 1, BASE_FEE);
    create.maximum_amount = Some(1_000);
    let r = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "issuance create failed: {}", r.ter);

    let mptid = make_mptid(1, &alice_id());
    let mut payment = mpt_tx(0, alice_id(), 2, BASE_FEE);
    payment.destination = Some(bob_id());
    payment.amount = Some(Amount::from_mpt_value(100, mptid));
    let r = run_tx(&mut state, &payment, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "direct mpt payment failed: {}",
        r.ter
    );

    let issuance = state
        .get_raw(&mpt_issuance_key_for(&mptid))
        .unwrap()
        .to_vec();
    assert_eq!(
        sle_u64(&issuance, 4),
        100,
        "outstanding should increase when issuer pays holder"
    );

    let bob_token = state
        .get_raw(&mpt_holder_key_for(&mptid, &bob_id()))
        .unwrap()
        .to_vec();
    assert_eq!(
        sle_u64(&bob_token, 26),
        100,
        "destination holder should receive mpt balance"
    );
    assert_eq!(
        state.get_account(&bob_id()).unwrap().owner_count,
        1,
        "payment should auto-create bob's MPToken entry"
    );
}

#[test]
fn mpt_payment_secondary_sale_charges_transfer_fee() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);
    fund(&mut state, &carol, 5_000);

    let mut create = mpt_tx(54, alice_id(), 1, BASE_FEE);
    create.flags = 0x0000_0020; // tfMPTCanTransfer
    create.transfer_fee_field = Some(5_000); // 5.000%
    create.maximum_amount = Some(1_000);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());

    let mut issue_to_bob = mpt_tx(0, alice_id(), 2, BASE_FEE);
    issue_to_bob.destination = Some(bob_id());
    issue_to_bob.amount = Some(Amount::from_mpt_value(200, mptid));
    assert!(
        run_tx(&mut state, &issue_to_bob, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let mut bob_to_carol = mpt_tx(0, bob_id(), 1, BASE_FEE);
    bob_to_carol.destination = Some(carol_id());
    bob_to_carol.amount = Some(Amount::from_mpt_value(100, mptid));
    let r = run_tx(&mut state, &bob_to_carol, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "secondary transfer failed: {}",
        r.ter
    );

    let issuance = state
        .get_raw(&mpt_issuance_key_for(&mptid))
        .unwrap()
        .to_vec();
    let bob_token = state
        .get_raw(&mpt_holder_key_for(&mptid, &bob_id()))
        .unwrap()
        .to_vec();
    let carol_token = state
        .get_raw(&mpt_holder_key_for(&mptid, &carol_id()))
        .unwrap()
        .to_vec();

    assert_eq!(
        sle_u64(&bob_token, 26),
        95,
        "sender should pay delivered amount plus 5% fee"
    );
    assert_eq!(
        sle_u64(&carol_token, 26),
        100,
        "recipient should receive the full delivered amount"
    );
    assert_eq!(
        sle_u64(&issuance, 4),
        195,
        "secondary transfer fee should reduce outstanding by the issuer-collected fee"
    );
}

#[test]
fn mpt_payment_require_auth_blocks_unauthorized_recipient() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mut create = mpt_tx(54, alice_id(), 1, BASE_FEE);
    create.flags = 0x0000_0004; // tfMPTRequireAuth
    create.maximum_amount = Some(1_000);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());

    let mut holder_create = mpt_tx(57, bob_id(), 1, BASE_FEE);
    holder_create.mptoken_issuance_id = Some(mptid);
    assert!(
        run_tx(&mut state, &holder_create, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let mut payment = mpt_tx(0, alice_id(), 2, BASE_FEE);
    payment.destination = Some(bob_id());
    payment.amount = Some(Amount::from_mpt_value(50, mptid));
    let r = run_tx(&mut state, &payment, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_NO_AUTH,
        "unauthorized holder should not receive MPT"
    );

    let bob_token = state
        .get_raw(&mpt_holder_key_for(&mptid, &bob_id()))
        .unwrap()
        .to_vec();
    assert_eq!(
        sle_u64(&bob_token, 26),
        0,
        "failed payment must not credit destination"
    );
}

#[test]
fn mpt_clawback_reduces_holder_and_outstanding() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mut create = mpt_tx(54, alice_id(), 1, BASE_FEE);
    create.flags = 0x0000_0040; // tfMPTCanClawback
    create.maximum_amount = Some(1_000);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());
    let mut payment = mpt_tx(0, alice_id(), 2, BASE_FEE);
    payment.destination = Some(bob_id());
    payment.amount = Some(Amount::from_mpt_value(150, mptid));
    assert!(run_tx(&mut state, &payment, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mut clawback = mpt_tx(30, alice_id(), 3, BASE_FEE);
    clawback.amount = Some(Amount::from_mpt_value(60, mptid));
    clawback.holder = Some(bob_id());
    let r = run_tx(&mut state, &clawback, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "mpt clawback failed: {}", r.ter);

    let issuance = state
        .get_raw(&mpt_issuance_key_for(&mptid))
        .unwrap()
        .to_vec();
    let bob_token = state
        .get_raw(&mpt_holder_key_for(&mptid, &bob_id()))
        .unwrap()
        .to_vec();
    assert_eq!(sle_u64(&bob_token, 26), 90);
    assert_eq!(sle_u64(&issuance, 4), 90);
}

#[test]
fn mpt_authorize_holder_cannot_destroy_nonzero_balance() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mut create = mpt_tx(54, alice_id(), 1, BASE_FEE);
    create.maximum_amount = Some(1_000);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());
    let mut payment = mpt_tx(0, alice_id(), 2, BASE_FEE);
    payment.destination = Some(bob_id());
    payment.amount = Some(Amount::from_mpt_value(10, mptid));
    assert!(run_tx(&mut state, &payment, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mut unauthorize = mpt_tx(57, bob_id(), 1, BASE_FEE);
    unauthorize.mptoken_issuance_id = Some(mptid);
    unauthorize.flags = 0x0000_0001; // tfMPTUnauthorize
    let r = run_tx(&mut state, &unauthorize, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, xrpl::ledger::ter::TEC_HAS_OBLIGATIONS);
}

#[test]
fn mpt_issuance_destroy_with_outstanding_fails() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mut create = mpt_tx(54, alice_id(), 1, BASE_FEE);
    create.maximum_amount = Some(1_000);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());
    let mut payment = mpt_tx(0, alice_id(), 2, BASE_FEE);
    payment.destination = Some(bob_id());
    payment.amount = Some(Amount::from_mpt_value(10, mptid));
    assert!(run_tx(&mut state, &payment, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mut destroy = mpt_tx(55, alice_id(), 3, BASE_FEE);
    destroy.mptoken_issuance_id = Some(mptid);
    let r = run_tx(&mut state, &destroy, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, xrpl::ledger::ter::TEC_HAS_OBLIGATIONS);
}

#[test]
fn mpt_global_lock_blocks_secondary_transfer_but_allows_return_to_issuer() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);
    fund(&mut state, &carol, 5_000);

    let mut create = mpt_tx(54, alice_id(), 1, BASE_FEE);
    create.flags = 0x0000_0022; // tfMPTCanLock | tfMPTCanTransfer
    create.maximum_amount = Some(1_000);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());
    let mut issue_to_bob = mpt_tx(0, alice_id(), 2, BASE_FEE);
    issue_to_bob.destination = Some(bob_id());
    issue_to_bob.amount = Some(Amount::from_mpt_value(100, mptid));
    assert!(
        run_tx(&mut state, &issue_to_bob, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let mut lock = mpt_tx(56, alice_id(), 3, BASE_FEE);
    lock.mptoken_issuance_id = Some(mptid);
    lock.flags = 0x0000_0001; // tfMPTLock
    assert!(run_tx(&mut state, &lock, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let issuance = state
        .get_raw(&mpt_issuance_key_for(&mptid))
        .unwrap()
        .to_vec();
    assert_ne!(
        sle_flags(&issuance) & 0x0000_0001,
        0,
        "global lock should set issuance locked flag"
    );

    let mut blocked = mpt_tx(0, bob_id(), 1, BASE_FEE);
    blocked.destination = Some(carol_id());
    blocked.amount = Some(Amount::from_mpt_value(10, mptid));
    let r = run_tx(&mut state, &blocked, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, xrpl::ledger::ter::TEC_LOCKED);

    let mut return_to_issuer = mpt_tx(0, bob_id(), 2, BASE_FEE);
    return_to_issuer.destination = Some(alice_id());
    return_to_issuer.amount = Some(Amount::from_mpt_value(10, mptid));
    let r = run_tx(&mut state, &return_to_issuer, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "locked holder should still be able to return value to issuer"
    );

    let issuance = state
        .get_raw(&mpt_issuance_key_for(&mptid))
        .unwrap()
        .to_vec();
    let bob_token = state
        .get_raw(&mpt_holder_key_for(&mptid, &bob_id()))
        .unwrap()
        .to_vec();
    assert_eq!(sle_u64(&bob_token, 26), 90);
    assert_eq!(sle_u64(&issuance, 4), 90);
}

// ── TER validation parity ─────────────────────────────────────────────────────

#[test]
fn ter_payment_self_payment_rejected() {
    // rippled: Payment to self → temREDUNDANT
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let alice_addr_str = xrpl::crypto::base58::encode_account(&alice_id());
    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&alice_addr_str)
        .unwrap()
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        !r.ter.is_tes_success(),
        "self-payment should fail, got {}",
        r.ter
    );
}

#[test]
fn ter_nft_mint_bad_transfer_fee() {
    // rippled: NFTokenMint with transfer_fee > 50000 → temBAD_NFTOKEN_TRANSFER_FEE
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mut tx = mpt_tx(25, alice_id(), 1, BASE_FEE);
    tx.nftoken_taxon = Some(1);
    tx.transfer_fee_field = Some(60000); // > 50000 max
    tx.flags = 0x0008; // tfTransferable

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        !r.ter.is_tes_success(),
        "bad transfer fee should fail, got {}",
        r.ter
    );
}

#[test]
fn ter_nft_mint_transfer_fee_without_transferable() {
    // rippled: Transfer fee > 0 without tfTransferable → temMALFORMED
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mut tx = mpt_tx(25, alice_id(), 1, BASE_FEE);
    tx.nftoken_taxon = Some(1);
    tx.transfer_fee_field = Some(100);
    tx.flags = 0; // no tfTransferable

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        !r.ter.is_tes_success(),
        "fee without transferable flag should fail, got {}",
        r.ter
    );
}

#[test]
fn ter_set_regular_key_self_rejected() {
    // rippled: SetRegularKey with key == account → temBAD_REGKEY
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mut tx = mpt_tx(5, alice_id(), 1, BASE_FEE); // type 5 = SetRegularKey
    tx.regular_key = Some(alice_id()); // self

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        !r.ter.is_tes_success(),
        "regular key == account should fail, got {}",
        r.ter
    );
}

#[test]
fn ter_account_set_bad_transfer_rate() {
    // rippled: TransferRate < QUALITY_ONE (1B) → temBAD_TRANSFER_RATE
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mut tx = mpt_tx(3, alice_id(), 1, BASE_FEE); // type 3 = AccountSet
    tx.transfer_rate = Some(500_000_000); // < 1_000_000_000

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        !r.ter.is_tes_success(),
        "bad transfer rate should fail, got {}",
        r.ter
    );
}

#[test]
fn ter_account_set_bad_tick_size() {
    // rippled: TickSize not in [3, 15] → temBAD_TICK_SIZE
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mut tx = mpt_tx(3, alice_id(), 1, BASE_FEE);
    tx.tick_size = Some(1); // < 3

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        !r.ter.is_tes_success(),
        "bad tick size should fail, got {}",
        r.ter
    );
}

#[test]
fn ter_account_set_conflicting_flags() {
    // rippled: SetFlag == ClearFlag → temINVALID_FLAG
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mut tx = mpt_tx(3, alice_id(), 1, BASE_FEE);
    tx.set_flag = Some(7);
    tx.clear_flag = Some(7); // same as set

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        !r.ter.is_tes_success(),
        "conflicting flags should fail, got {}",
        r.ter
    );
}

// ── Multi-ledger replay tests ────────────────────────────────────────────────

use xrpl::ledger::close::{close_ledger, CloseResult};
use xrpl::ledger::pool::TxPool;
use xrpl::ledger::LedgerHeader;

fn pool_payment(pool: &mut TxPool, kp: &KeyPair, dest_addr: &str, amount: u64, fee: u64, seq: u32) {
    let signed = TxBuilder::payment()
        .account(kp)
        .destination(dest_addr)
        .unwrap()
        .amount(Amount::Xrp(amount))
        .fee(fee)
        .sequence(seq)
        .sign(kp)
        .unwrap();
    let mut data = Vec::with_capacity(4 + signed.blob.len());
    data.extend_from_slice(&[0x54, 0x58, 0x4E, 0x00]);
    data.extend_from_slice(&signed.blob);
    let hash = xrpl::crypto::sha512_first_half(&data);
    let parsed = parse_blob(&signed.blob).unwrap();
    pool.insert(hash, signed.blob, &parsed);
}

fn do_close(
    prev: &LedgerHeader,
    state: &mut LedgerState,
    pool: &mut TxPool,
    ct: u64,
) -> CloseResult {
    close_ledger(prev, state, pool, ct, true)
}

#[test]
fn replay_payment_chain_across_closes() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 1_000);

    let mut header = LedgerHeader {
        sequence: 1,
        hash: [0xAA; 32],
        parent_hash: [0u8; 32],
        close_time: 0,
        total_coins: 11_000 * XRP,
        account_hash: state.state_hash(),
        transaction_hash: [0u8; 32],
        parent_close_time: 0,
        close_time_resolution: 10,
        close_flags: 0,
    };

    for ledger in 1..=3u32 {
        let mut pool = TxPool::new();
        pool_payment(&mut pool, &alice, &bob_addr(), 100 * XRP, BASE_FEE, ledger);
        let result = do_close(&header, &mut state, &mut pool, ledger as u64 * 100);
        assert_eq!(
            result.applied_count,
            1,
            "ledger {} should apply 1 tx",
            ledger + 1
        );
        header = result.header;
    }

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, 10_000 * XRP - 300 * XRP - 3 * BASE_FEE);
    assert_eq!(a.sequence, 4);
    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.balance, 1_000 * XRP + 300 * XRP);
    assert_eq!(header.total_coins, 11_000 * XRP - 3 * BASE_FEE);
}

#[test]
fn replay_offer_create_then_cancel() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    // Trust line first
    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(10_000.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(0),
        ApplyFlags::NONE,
    );

    let header = LedgerHeader {
        sequence: 1,
        hash: [0xBB; 32],
        parent_hash: [0u8; 32],
        close_time: 0,
        total_coins: 10_000 * XRP,
        account_hash: state.state_hash(),
        transaction_hash: [0u8; 32],
        parent_close_time: 0,
        close_time_resolution: 10,
        close_flags: 0,
    };

    // Ledger 2: place offer
    {
        let mut pool = TxPool::new();
        let signed = TxBuilder::offer_create()
            .account(&alice)
            .taker_pays(iou_usd(50.0, bob_id()))
            .taker_gets(Amount::Xrp(100 * XRP))
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap();
        let mut d = Vec::with_capacity(4 + signed.blob.len());
        d.extend_from_slice(&[0x54, 0x58, 0x4E, 0x00]);
        d.extend_from_slice(&signed.blob);
        pool.insert(
            xrpl::crypto::sha512_first_half(&d),
            signed.blob.clone(),
            &parse_blob(&signed.blob).unwrap(),
        );
        let r = do_close(&header, &mut state, &mut pool, 200);
        assert_eq!(r.applied_count, 1);
    }
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);

    // Ledger 3: cancel offer
    {
        let mut pool = TxPool::new();
        let signed = TxBuilder::offer_cancel()
            .account(&alice)
            .offer_sequence(2)
            .fee(BASE_FEE)
            .sequence(3)
            .sign(&alice)
            .unwrap();
        let mut d = Vec::with_capacity(4 + signed.blob.len());
        d.extend_from_slice(&[0x54, 0x58, 0x4E, 0x00]);
        d.extend_from_slice(&signed.blob);
        pool.insert(
            xrpl::crypto::sha512_first_half(&d),
            signed.blob.clone(),
            &parse_blob(&signed.blob).unwrap(),
        );
        let r = do_close(&header, &mut state, &mut pool, 300);
        assert_eq!(r.applied_count, 1);
    }
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 4);
}

#[test]
fn replay_vault_lifecycle() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let header = LedgerHeader {
        sequence: 1,
        hash: [0xCC; 32],
        parent_hash: [0u8; 32],
        close_time: 0,
        total_coins: 10_000 * XRP,
        account_hash: state.state_hash(),
        transaction_hash: [0u8; 32],
        parent_close_time: 0,
        close_time_resolution: 10,
        close_flags: 0,
    };
    let ctx = |h: &LedgerHeader, ct: u64| TxContext::from_parent(h, ct);
    let vkey = test_vault_key(&alice_id(), 1);

    // Create → deposit → withdraw → delete
    let r = run_tx(
        &mut state,
        &mpt_tx(65, alice_id(), 1, BASE_FEE),
        &ctx(&header, 200),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);

    let mut dep = mpt_tx(68, alice_id(), 2, BASE_FEE);
    dep.vault_id = Some(vkey.0);
    dep.amount_drops = Some(500 * XRP);
    assert!(
        run_tx(&mut state, &dep, &ctx(&header, 300), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let mut wd = mpt_tx(69, alice_id(), 3, BASE_FEE);
    wd.vault_id = Some(vkey.0);
    wd.amount_drops = Some(500 * XRP);
    assert!(
        run_tx(&mut state, &wd, &ctx(&header, 400), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let mut del = mpt_tx(67, alice_id(), 4, BASE_FEE);
    del.vault_id = Some(vkey.0);
    assert!(
        run_tx(&mut state, &del, &ctx(&header, 500), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );
    assert!(state.get_raw(&vkey).is_none());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}

#[test]
fn replay_loan_lifecycle() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 5_000);

    let header = LedgerHeader {
        sequence: 1,
        hash: [0xDD; 32],
        parent_hash: [0u8; 32],
        close_time: 0,
        total_coins: 15_000 * XRP,
        account_hash: state.state_hash(),
        transaction_hash: [0u8; 32],
        parent_close_time: 0,
        close_time_resolution: 10,
        close_flags: 0,
    };
    let ctx = |ct: u64| TxContext::from_parent(&header, ct);

    // Vault + deposit + broker
    assert!(run_tx(
        &mut state,
        &mpt_tx(65, alice_id(), 1, BASE_FEE),
        &ctx(100),
        ApplyFlags::NONE
    )
    .ter
    .is_tes_success());
    let vkey = test_vault_key(&alice_id(), 1);
    let mut dep = mpt_tx(68, alice_id(), 2, BASE_FEE);
    dep.vault_id = Some(vkey.0);
    dep.amount_drops = Some(1_000 * XRP);
    assert!(run_tx(&mut state, &dep, &ctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    let mut bt = mpt_tx(74, alice_id(), 3, BASE_FEE);
    bt.vault_id = Some(vkey.0);
    assert!(run_tx(&mut state, &bt, &ctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    let bkey = test_loan_broker_key(&alice_id(), 3);

    // Bob: loan → repay → delete
    let mut lt = mpt_tx(80, bob_id(), 1, BASE_FEE);
    lt.vault_id = Some(bkey.0);
    lt.amount_drops = Some(100 * XRP);
    assert!(run_tx(&mut state, &lt, &ctx(200), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    let lkey = test_loan_key(&bkey.0, 1);

    let mut pay = mpt_tx(84, bob_id(), 2, BASE_FEE);
    pay.vault_id = Some(lkey.0);
    pay.amount_drops = Some(100 * XRP);
    assert!(run_tx(&mut state, &pay, &ctx(300), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mut dl = mpt_tx(81, bob_id(), 3, BASE_FEE);
    dl.vault_id = Some(lkey.0);
    assert!(run_tx(&mut state, &dl, &ctx(400), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    assert!(state.get_raw(&lkey).is_none());
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 0);

    // Alice: delete broker
    let mut db = mpt_tx(75, alice_id(), 4, BASE_FEE);
    db.vault_id = Some(bkey.0);
    assert!(run_tx(&mut state, &db, &ctx(500), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    assert!(state.get_raw(&bkey).is_none());
}

#[test]
fn replay_amm_lifecycle() {
    use xrpl::transaction::amount::{Currency, Issue};

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let xrp = Issue::Xrp;
    let usd = Issue::Iou {
        currency: Currency::from_code("USD").unwrap(),
        issuer: bob_id(),
    };
    let akey = test_amm_key(&xrp, &usd);

    let header = LedgerHeader {
        sequence: 1,
        hash: [0xEE; 32],
        parent_hash: [0u8; 32],
        close_time: 0,
        total_coins: 20_000 * XRP,
        account_hash: state.state_hash(),
        transaction_hash: [0u8; 32],
        parent_close_time: 0,
        close_time_resolution: 10,
        close_flags: 0,
    };
    let ctx = |ct: u64| TxContext::from_parent(&header, ct);

    // Create → deposit → withdraw → delete
    let mut tx = mpt_tx(35, alice_id(), 1, BASE_FEE);
    tx.asset = Some(xrp.clone());
    tx.asset2 = Some(usd.clone());
    assert!(run_tx(&mut state, &tx, &ctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mut dep = mpt_tx(36, alice_id(), 2, BASE_FEE);
    dep.asset = Some(xrp.clone());
    dep.asset2 = Some(usd.clone());
    dep.amount_drops = Some(200 * XRP);
    assert!(run_tx(&mut state, &dep, &ctx(200), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let bal = state.get_account(&alice_id()).unwrap().balance;
    let mut wd = mpt_tx(37, alice_id(), 3, BASE_FEE);
    wd.asset = Some(xrp.clone());
    wd.asset2 = Some(usd.clone());
    wd.amount_drops = Some(200 * XRP);
    assert!(run_tx(&mut state, &wd, &ctx(300), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        bal + 200 * XRP - BASE_FEE
    );

    let mut del = mpt_tx(40, alice_id(), 4, BASE_FEE);
    del.asset = Some(xrp.clone());
    del.asset2 = Some(usd.clone());
    assert!(run_tx(&mut state, &del, &ctx(400), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    assert!(state.get_raw(&akey).is_none());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}
