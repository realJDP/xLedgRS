//! Parity tests — verify xLedgRSv2Beta behavior matches rippled's expected outcomes.
//!
//! Fixtures are derived from rippled's jtx and app test suites.
//!
//! Each test encodes a specific scenario from rippled's C++ tests and verifies
//! that xLedgRSv2Beta produces the same TER code, balance, sequence, and owner count.

use xrpl::crypto::keys::{KeyPair, Secp256k1KeyPair};
use xrpl::ledger::check;
use xrpl::ledger::node_store::MemNodeStore;
use xrpl::ledger::ter::{self, ApplyFlags};
use xrpl::ledger::tx::{classify_result, run_tx, ApplyOutcome, TxContext};
use xrpl::ledger::{AccountRoot, LedgerState, MapType, SHAMap};
use xrpl::transaction::amount::{Currency, IouValue};
use xrpl::transaction::parse::ParsedTx;
use xrpl::transaction::{builder::TxBuilder, parse_blob, Amount, PathStep};

fn pctx(close_time: u64) -> TxContext {
    TxContext {
        close_time,
        ..TxContext::default()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const XRP: u64 = 1_000_000; // 1 XRP in drops
const BASE_FEE: u64 = 10; // rippled default base fee
const OWNER_RESERVE_FEE: u64 = 200_000; // current mainnet reserve increment
const LSF_DEFAULT_RIPPLE: u32 = 0x0080_0000;
const LSF_PASSWORD_SPENT: u32 = 0x0001_0000;
const LSF_REQUIRE_DEST_TAG: u32 = 0x0002_0000;
const LSF_REQUIRE_AUTH: u32 = 0x0004_0000;
const LSF_DISABLE_MASTER: u32 = 0x0010_0000;
const LSF_DISALLOW_XRP: u32 = 0x0008_0000;
const LSF_NO_FREEZE: u32 = 0x0020_0000;
const LSF_GLOBAL_FREEZE: u32 = 0x0040_0000;
const LSF_DEPOSIT_AUTH: u32 = 0x0100_0000;
const LSF_ALLOW_TRUST_LINE_CLAWBACK: u32 = 0x8000_0000;
const LSF_DISALLOW_INCOMING_TRUSTLINE: u32 = 0x2000_0000;
const LSF_ALLOW_TRUST_LINE_LOCKING: u32 = 0x4000_0000;
const LSF_LOW_FREEZE: u32 = 0x0040_0000;
const LSF_HIGH_FREEZE: u32 = 0x0080_0000;
const LSF_LOW_NO_RIPPLE: u32 = 0x0010_0000;
const LSF_HIGH_NO_RIPPLE: u32 = 0x0020_0000;
const LSF_LOAN_DEFAULT: u32 = 0x0001_0000;
const LSF_LOAN_IMPAIRED: u32 = 0x0002_0000;
const TF_REQUIRE_DEST_TAG: u32 = 0x0001_0000;
const TF_OPTIONAL_DEST_TAG: u32 = 0x0002_0000;
const TF_REQUIRE_AUTH: u32 = 0x0004_0000;
const TF_OPTIONAL_AUTH: u32 = 0x0008_0000;
const TF_DISALLOW_XRP: u32 = 0x0010_0000;
const TF_ALLOW_XRP: u32 = 0x0020_0000;
const TF_LOAN_DEFAULT: u32 = 0x0001_0000;
const TF_LOAN_IMPAIR: u32 = 0x0002_0000;
const TF_LOAN_UNIMPAIR: u32 = 0x0004_0000;
const TF_PAYCHAN_RENEW: u32 = 0x0001_0000;
const TF_PAYCHAN_CLOSE: u32 = 0x0002_0000;

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

fn signed_mpt_create(
    kp: &KeyPair,
    seq: u32,
    flags: u32,
    maximum_amount: Option<u64>,
    asset_scale: Option<u8>,
    transfer_fee: Option<u16>,
    metadata: Option<&[u8]>,
) -> ParsedTx {
    let mut builder = TxBuilder::mptoken_issuance_create()
        .account(kp)
        .flags(flags)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(maximum_amount) = maximum_amount {
        builder = builder.maximum_amount(maximum_amount);
    }
    if let Some(asset_scale) = asset_scale {
        builder = builder.asset_scale(asset_scale);
    }
    if let Some(transfer_fee) = transfer_fee {
        builder = builder.transfer_fee_field(transfer_fee);
    }
    if let Some(metadata) = metadata {
        builder = builder.mptoken_metadata(metadata.to_vec());
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_mpt_destroy(kp: &KeyPair, seq: u32, mptid: [u8; 24]) -> ParsedTx {
    parse_blob(
        &TxBuilder::mptoken_issuance_destroy()
            .account(kp)
            .mptoken_issuance_id(mptid)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_mpt_set(
    kp: &KeyPair,
    seq: u32,
    mptid: [u8; 24],
    flags: u32,
    metadata: Option<&[u8]>,
    holder: Option<[u8; 20]>,
) -> ParsedTx {
    let mut builder = TxBuilder::mptoken_issuance_set()
        .account(kp)
        .mptoken_issuance_id(mptid)
        .flags(flags)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(metadata) = metadata {
        builder = builder.mptoken_metadata(metadata.to_vec());
    }
    if let Some(holder) = holder {
        builder = builder.holder(holder);
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_mpt_set_transfer_fee(
    kp: &KeyPair,
    seq: u32,
    mptid: [u8; 24],
    transfer_fee: u16,
    holder: Option<[u8; 20]>,
) -> ParsedTx {
    let mut builder = TxBuilder::mptoken_issuance_set()
        .account(kp)
        .mptoken_issuance_id(mptid)
        .transfer_fee_field(transfer_fee)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(holder) = holder {
        builder = builder.holder(holder);
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_mpt_authorize(
    kp: &KeyPair,
    seq: u32,
    mptid: [u8; 24],
    flags: u32,
    holder: Option<[u8; 20]>,
) -> ParsedTx {
    let mut builder = TxBuilder::mptoken_authorize()
        .account(kp)
        .mptoken_issuance_id(mptid)
        .flags(flags)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(holder) = holder {
        builder = builder.holder(holder);
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_mpt_payment(kp: &KeyPair, seq: u32, destination: [u8; 20], amount: Amount) -> ParsedTx {
    parse_blob(
        &TxBuilder::payment()
            .account(kp)
            .destination_account(destination)
            .amount(amount)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_mpt_payment_sendmax(
    kp: &KeyPair,
    seq: u32,
    destination: [u8; 20],
    amount: Amount,
    send_max: Amount,
) -> ParsedTx {
    parse_blob(
        &TxBuilder::payment()
            .account(kp)
            .destination_account(destination)
            .amount(amount)
            .send_max(send_max)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
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

fn signed_deposit_preauth_unauthorize(kp: &KeyPair, seq: u32, authorized: [u8; 20]) -> ParsedTx {
    parse_blob(
        &TxBuilder::deposit_preauth()
            .account(kp)
            .unauthorize(authorized)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn deposit_preauth_credentials_raw(credentials: &[([u8; 20], &[u8])]) -> Vec<u8> {
    let mut raw = Vec::new();
    for (issuer, credential_type) in credentials {
        xrpl::ledger::meta::write_field_header_pub(&mut raw, 14, 33); // sfCredential
        xrpl::ledger::meta::write_field_header_pub(&mut raw, 8, 4); // sfIssuer
        xrpl::transaction::serialize::encode_length(20, &mut raw);
        raw.extend_from_slice(issuer);
        xrpl::ledger::meta::write_field_header_pub(&mut raw, 7, 31); // sfCredentialType
        xrpl::transaction::serialize::encode_length(credential_type.len(), &mut raw);
        raw.extend_from_slice(credential_type);
        raw.push(0xE1);
    }
    raw.push(0xF1);
    raw
}

fn signed_mpt_clawback(kp: &KeyPair, seq: u32, holder: [u8; 20], amount: Amount) -> ParsedTx {
    parse_blob(
        &TxBuilder::clawback()
            .account(kp)
            .holder(holder)
            .amount(amount)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_vault_create(kp: &KeyPair, seq: u32) -> ParsedTx {
    parse_blob(
        &TxBuilder::vault_create()
            .account(kp)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_vault_create_with_asset(
    kp: &KeyPair,
    seq: u32,
    asset: xrpl::transaction::amount::Issue,
) -> ParsedTx {
    parse_blob(
        &TxBuilder::vault_create()
            .account(kp)
            .asset(asset)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_vault_delete(kp: &KeyPair, seq: u32, vault_id: [u8; 32]) -> ParsedTx {
    parse_blob(
        &TxBuilder::vault_delete()
            .account(kp)
            .vault_id(vault_id)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_vault_deposit(kp: &KeyPair, seq: u32, vault_id: [u8; 32], drops: u64) -> ParsedTx {
    parse_blob(
        &TxBuilder::vault_deposit()
            .account(kp)
            .vault_id(vault_id)
            .amount(Amount::Xrp(drops))
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_vault_withdraw(kp: &KeyPair, seq: u32, vault_id: [u8; 32], shares: u64) -> ParsedTx {
    parse_blob(
        &TxBuilder::vault_withdraw()
            .account(kp)
            .vault_id(vault_id)
            .amount(Amount::Xrp(shares))
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_vault_set(
    kp: &KeyPair,
    seq: u32,
    vault_id: [u8; 32],
    assets_maximum: Option<i64>,
    data: Option<Vec<u8>>,
    domain_id: Option<[u8; 32]>,
) -> ParsedTx {
    let mut builder = TxBuilder::vault_set()
        .account(kp)
        .vault_id(vault_id)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(maximum) = assets_maximum {
        builder = builder.assets_maximum(maximum);
    }
    if let Some(data) = data {
        builder = builder.data(data);
    }
    if let Some(domain_id) = domain_id {
        builder = builder.domain_id(domain_id);
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_vault_clawback(
    kp: &KeyPair,
    seq: u32,
    vault_id: [u8; 32],
    holder: [u8; 20],
    amount: Option<Amount>,
) -> ParsedTx {
    let mut builder = TxBuilder::vault_clawback()
        .account(kp)
        .vault_id(vault_id)
        .holder(holder)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(amount) = amount {
        builder = builder.amount(amount);
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_loan_broker_set(kp: &KeyPair, seq: u32, vault_id: [u8; 32]) -> ParsedTx {
    parse_blob(
        &TxBuilder::loan_broker_set()
            .account(kp)
            .vault_id(vault_id)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_loan_broker_delete(kp: &KeyPair, seq: u32, broker_id: [u8; 32]) -> ParsedTx {
    parse_blob(
        &TxBuilder::loan_broker_delete()
            .account(kp)
            .loan_broker_id(broker_id)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_loan_set(kp: &KeyPair, seq: u32, broker_id: [u8; 32], principal: u64) -> ParsedTx {
    parse_blob(
        &TxBuilder::loan_set()
            .account(kp)
            .loan_broker_id(broker_id)
            .amount(Amount::Xrp(principal))
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_loan_delete(kp: &KeyPair, seq: u32, loan_id: [u8; 32]) -> ParsedTx {
    parse_blob(
        &TxBuilder::loan_delete()
            .account(kp)
            .loan_id(loan_id)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_loan_pay(kp: &KeyPair, seq: u32, loan_id: [u8; 32], amount: u64) -> ParsedTx {
    parse_blob(
        &TxBuilder::loan_pay()
            .account(kp)
            .loan_id(loan_id)
            .amount(Amount::Xrp(amount))
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_loan_cover_deposit(kp: &KeyPair, seq: u32, broker_id: [u8; 32], amount: u64) -> ParsedTx {
    parse_blob(
        &TxBuilder::loan_broker_cover_deposit()
            .account(kp)
            .loan_broker_id(broker_id)
            .amount(Amount::Xrp(amount))
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_loan_cover_withdraw(
    kp: &KeyPair,
    seq: u32,
    broker_id: [u8; 32],
    amount: u64,
    destination: Option<[u8; 20]>,
) -> ParsedTx {
    let mut builder = TxBuilder::loan_broker_cover_withdraw()
        .account(kp)
        .loan_broker_id(broker_id)
        .amount(Amount::Xrp(amount))
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(destination) = destination {
        builder = builder.destination_account(destination);
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_loan_cover_clawback(
    kp: &KeyPair,
    seq: u32,
    broker_id: Option<[u8; 32]>,
    amount: Option<u64>,
) -> ParsedTx {
    let mut builder = TxBuilder::loan_broker_cover_clawback()
        .account(kp)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(broker_id) = broker_id {
        builder = builder.loan_broker_id(broker_id);
    }
    if let Some(amount) = amount {
        builder = builder.amount(Amount::Xrp(amount));
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_loan_manage(kp: &KeyPair, seq: u32, loan_id: [u8; 32], flags: u32) -> ParsedTx {
    parse_blob(
        &TxBuilder::loan_manage()
            .account(kp)
            .loan_id(loan_id)
            .flags(flags)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_nft_mint(kp: &KeyPair, seq: u32, taxon: u32) -> ParsedTx {
    parse_blob(
        &TxBuilder::nftoken_mint()
            .account(kp)
            .nftoken_taxon(taxon)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_nft_mint_flags(kp: &KeyPair, seq: u32, taxon: u32, flags: u32) -> ParsedTx {
    parse_blob(
        &TxBuilder::nftoken_mint()
            .account(kp)
            .nftoken_taxon(taxon)
            .flags(flags)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_nft_burn(kp: &KeyPair, seq: u32, nftoken_id: [u8; 32]) -> ParsedTx {
    parse_blob(
        &TxBuilder::nftoken_burn()
            .account(kp)
            .nftoken_id(nftoken_id)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_nft_burn_owner(
    kp: &KeyPair,
    seq: u32,
    nftoken_id: [u8; 32],
    owner: [u8; 20],
) -> ParsedTx {
    parse_blob(
        &TxBuilder::nftoken_burn()
            .account(kp)
            .owner(owner)
            .nftoken_id(nftoken_id)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_nft_sell_offer(kp: &KeyPair, seq: u32, nftoken_id: [u8; 32], amount: Amount) -> ParsedTx {
    parse_blob(
        &TxBuilder::nftoken_create_offer()
            .account(kp)
            .nftoken_id(nftoken_id)
            .amount(amount)
            .flags(0x0001)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_nft_accept_sell(kp: &KeyPair, seq: u32, offer_id: [u8; 32]) -> ParsedTx {
    parse_blob(
        &TxBuilder::nftoken_accept_offer()
            .account(kp)
            .nft_sell_offer(offer_id)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_nft_accept_buy(kp: &KeyPair, seq: u32, offer_id: [u8; 32]) -> ParsedTx {
    parse_blob(
        &TxBuilder::nftoken_accept_offer()
            .account(kp)
            .nft_buy_offer(offer_id)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

const TF_AMM_WITHDRAW_LP_TOKEN: u32 = 0x0001_0000;
const TF_AMM_TWO_ASSET: u32 = 0x0010_0000;

fn signed_amm_create(
    kp: &KeyPair,
    seq: u32,
    amount: Amount,
    amount2: Amount,
    trading_fee: u16,
) -> ParsedTx {
    parse_blob(
        &TxBuilder::amm_create()
            .account(kp)
            .amount(amount)
            .amount2(amount2)
            .trading_fee(trading_fee)
            .fee(OWNER_RESERVE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_amm_deposit(
    kp: &KeyPair,
    seq: u32,
    asset: xrpl::transaction::amount::Issue,
    asset2: xrpl::transaction::amount::Issue,
    amount: Amount,
    amount2: Amount,
) -> ParsedTx {
    parse_blob(
        &TxBuilder::amm_deposit()
            .account(kp)
            .asset(asset)
            .asset2(asset2)
            .amount(amount)
            .amount2(amount2)
            .flags(TF_AMM_TWO_ASSET)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_amm_withdraw_lp(
    kp: &KeyPair,
    seq: u32,
    asset: xrpl::transaction::amount::Issue,
    asset2: xrpl::transaction::amount::Issue,
    lp_token_in: Amount,
) -> ParsedTx {
    parse_blob(
        &TxBuilder::amm_withdraw()
            .account(kp)
            .asset(asset)
            .asset2(asset2)
            .lp_token_in(lp_token_in)
            .flags(TF_AMM_WITHDRAW_LP_TOKEN)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_amm_delete(
    kp: &KeyPair,
    seq: u32,
    asset: xrpl::transaction::amount::Issue,
    asset2: xrpl::transaction::amount::Issue,
) -> ParsedTx {
    parse_blob(
        &TxBuilder::amm_delete()
            .account(kp)
            .asset(asset)
            .asset2(asset2)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_amm_vote(
    kp: &KeyPair,
    seq: u32,
    asset: xrpl::transaction::amount::Issue,
    asset2: xrpl::transaction::amount::Issue,
    trading_fee: u16,
) -> ParsedTx {
    parse_blob(
        &TxBuilder::amm_vote()
            .account(kp)
            .asset(asset)
            .asset2(asset2)
            .trading_fee(trading_fee)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_amm_bid(
    kp: &KeyPair,
    seq: u32,
    asset: xrpl::transaction::amount::Issue,
    asset2: xrpl::transaction::amount::Issue,
    bid_min: Option<Amount>,
    bid_max: Option<Amount>,
) -> ParsedTx {
    let mut builder = TxBuilder::amm_bid()
        .account(kp)
        .asset(asset)
        .asset2(asset2)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(bid_min) = bid_min {
        builder = builder.bid_min(bid_min);
    }
    if let Some(bid_max) = bid_max {
        builder = builder.bid_max(bid_max);
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn paychan_claim_signature(kp: &KeyPair, channel: [u8; 32], amount: u64) -> Vec<u8> {
    let mut payload = xrpl::ledger::paychan::PREFIX_CLAIM.to_vec();
    payload.extend_from_slice(&channel);
    payload.extend_from_slice(&amount.to_be_bytes());
    kp.sign(&payload)
}

fn signed_paychan_claim(
    kp: &KeyPair,
    seq: u32,
    channel: [u8; 32],
    flags: u32,
    balance: Option<u64>,
    amount: Option<u64>,
    public_key: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
) -> ParsedTx {
    let mut builder = TxBuilder::paychan_claim()
        .account(kp)
        .channel(channel)
        .flags(flags)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(balance) = balance {
        builder = builder.balance(Amount::Xrp(balance));
    }
    if let Some(amount) = amount {
        builder = builder.amount(Amount::Xrp(amount));
    }
    if let Some(public_key) = public_key {
        builder = builder.public_key_field(public_key);
    }
    if let Some(signature) = signature {
        builder = builder.signature_field(signature);
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_ticket_create(kp: &KeyPair, seq: u32, count: u32) -> ParsedTx {
    parse_blob(
        &TxBuilder::ticket_create()
            .account(kp)
            .ticket_count(count)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
}

fn signed_credential_create(
    kp: &KeyPair,
    seq: u32,
    subject: Option<[u8; 20]>,
    credential_type: Option<&[u8]>,
    expiration: Option<u32>,
    uri: Option<&[u8]>,
    flags: u32,
) -> ParsedTx {
    let mut builder = TxBuilder::credential_create()
        .account(kp)
        .flags(flags)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(subject) = subject {
        builder = builder.subject(subject);
    }
    if let Some(credential_type) = credential_type {
        builder = builder.credential_type(credential_type.to_vec());
    }
    if let Some(expiration) = expiration {
        builder = builder.expiration(expiration);
    }
    if let Some(uri) = uri {
        builder = builder.uri(uri.to_vec());
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_credential_accept(
    kp: &KeyPair,
    seq: u32,
    issuer: Option<[u8; 20]>,
    credential_type: Option<&[u8]>,
    flags: u32,
) -> ParsedTx {
    let mut builder = TxBuilder::credential_accept()
        .account(kp)
        .flags(flags)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(issuer) = issuer {
        builder = builder.issuer(issuer);
    }
    if let Some(credential_type) = credential_type {
        builder = builder.credential_type(credential_type.to_vec());
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_credential_delete(
    kp: &KeyPair,
    seq: u32,
    subject: Option<[u8; 20]>,
    issuer: Option<[u8; 20]>,
    credential_type: Option<&[u8]>,
    flags: u32,
) -> ParsedTx {
    let mut builder = TxBuilder::credential_delete()
        .account(kp)
        .flags(flags)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(subject) = subject {
        builder = builder.subject(subject);
    }
    if let Some(issuer) = issuer {
        builder = builder.issuer(issuer);
    }
    if let Some(credential_type) = credential_type {
        builder = builder.credential_type(credential_type.to_vec());
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_did_set(
    kp: &KeyPair,
    seq: u32,
    uri: Option<&[u8]>,
    document: Option<&[u8]>,
    data: Option<&[u8]>,
    flags: u32,
) -> ParsedTx {
    let mut builder = TxBuilder::did_set()
        .account(kp)
        .flags(flags)
        .fee(BASE_FEE)
        .sequence(seq);
    if let Some(uri) = uri {
        builder = builder.uri(uri.to_vec());
    }
    if let Some(document) = document {
        builder = builder.did_document(document.to_vec());
    }
    if let Some(data) = data {
        builder = builder.data(data.to_vec());
    }
    parse_blob(&builder.sign(kp).unwrap().blob).unwrap()
}

fn signed_did_delete(kp: &KeyPair, seq: u32, flags: u32) -> ParsedTx {
    parse_blob(
        &TxBuilder::did_delete()
            .account(kp)
            .flags(flags)
            .fee(BASE_FEE)
            .sequence(seq)
            .sign(kp)
            .unwrap()
            .blob,
    )
    .unwrap()
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
    enable_parity_amendments(state);
    let id = xrpl::crypto::account_id(&kp.public_key_bytes());
    state.insert_account(make_account(id, balance_xrp * XRP));
}

fn signer_entries_raw(entries: &[([u8; 20], u16)]) -> Vec<u8> {
    let mut raw = Vec::new();
    for (account, weight) in entries {
        raw.push(0xE4); // sfSignerEntry
        raw.push(0x13); // sfSignerWeight
        raw.extend_from_slice(&weight.to_be_bytes());
        raw.push(0x81); // sfAccount
        xrpl::transaction::serialize::encode_length(20, &mut raw);
        raw.extend_from_slice(account);
        raw.push(0xE1);
    }
    raw.push(0xF1);
    raw
}

fn enable_default_ripple(state: &mut LedgerState, account_id: [u8; 20]) {
    let mut account = state
        .get_account(&account_id)
        .cloned()
        .expect("account exists");
    account.flags |= LSF_DEFAULT_RIPPLE;
    state.insert_account(account);
}

fn enable_parity_amendments(state: &mut LedgerState) {
    for name in [
        "AMM",
        "AMMClawback",
        "Clawback",
        "DID",
        "MPTokensV1",
        "PriceOracle",
        "Credentials",
        "SingleAssetVault",
        "LendingProtocol",
        "TokenEscrow",
        "DynamicMPT",
        "PermissionedDEX",
    ] {
        state.enable_amendment(xrpl::crypto::sha512_first_half(name.as_bytes()));
    }
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
fn payment_domain_id_requires_permissioned_dex() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    state.insert_account(make_account(alice_id(), 10_000 * XRP));
    state.insert_account(make_account(bob_id(), 10_000 * XRP));

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(100 * XRP))
        .domain_id([0x44; 32])
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEM_DISABLED);
    assert!(!result.applied);
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, 10_000 * XRP);
    assert_eq!(a.sequence, 1);
    assert_eq!(state.get_account(&bob_id()).unwrap().balance, 10_000 * XRP);
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
fn payment_iou_missing_destination_is_tec_no_dst() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);
    assert!(state.get_account(&bob_id()).is_none());

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEC_NO_DST);
    assert!(result.applied, "tecNO_DST claims fee only");
    assert!(state.get_account(&bob_id()).is_none());
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 2);
}

#[test]
fn payment_xrp_partial_missing_destination_is_tel_no_dst_partial() {
    const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let carol = kp_carol();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &carol, 10_000);
    assert!(state.get_account(&bob_id()).is_none());

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(20 * XRP))
        .send_max(iou_usd(25.0, carol_id()))
        .flags(TF_PARTIAL_PAYMENT)
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEL_NO_DST_PARTIAL);
    assert!(!result.applied);
    assert!(state.get_account(&bob_id()).is_none());
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

#[test]
fn payment_xrp_missing_destination_below_reserve_is_tec_no_dst_insuf_xrp() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let carol = kp_carol();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &carol, 10_000);
    assert!(state.get_account(&bob_id()).is_none());

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(1))
        .send_max(iou_usd(25.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEC_NO_DST_INSUF_XRP);
    assert!(result.applied, "tecNO_DST_INSUF_XRP claims fee only");
    assert!(state.get_account(&bob_id()).is_none());
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 2);
}

#[test]
fn payment_path_count_limit_is_tel_bad_path_count() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);
    fund(&mut state, &carol, 10_000);

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let mut tx = parse_blob(&signed.blob).unwrap();
    tx.paths = vec![
        vec![PathStep {
            account: Some(carol_id()),
            currency: None,
            issuer: None,
        }];
        7
    ];

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEL_BAD_PATH_COUNT);
    assert!(!result.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

#[test]
fn payment_path_length_limit_is_tel_bad_path_count() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);
    fund(&mut state, &carol, 10_000);

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let mut tx = parse_blob(&signed.blob).unwrap();
    tx.paths = vec![vec![
        PathStep {
            account: Some(carol_id()),
            currency: None,
            issuer: None,
        };
        9
    ]];

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEL_BAD_PATH_COUNT);
    assert!(!result.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

#[test]
fn payment_bad_currency_destination_is_tem_bad_currency() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_bad_currency(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEM_BAD_CURRENCY);
    assert!(!result.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

#[test]
fn payment_bad_currency_sendmax_is_tem_bad_currency() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let signed = TxBuilder::payment()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(20 * XRP))
        .send_max(iou_bad_currency(25.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEM_BAD_CURRENCY);
    assert!(!result.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

#[test]
fn payment_malformed_preflight_errors_do_not_claim_fee_or_sequence() {
    const TF_PARTIAL_PAYMENT: u32 = 0x0002_0000;

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let cases = [
        (
            TxBuilder::payment()
                .account(&alice)
                .destination(&bob_addr())
                .unwrap()
                .amount(Amount::Xrp(100 * XRP))
                .flags(0x0008_0000)
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_INVALID_FLAG,
        ),
        (
            TxBuilder::payment()
                .account(&alice)
                .amount(Amount::Xrp(100 * XRP))
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_DST_NEEDED,
        ),
        (
            TxBuilder::payment()
                .account(&alice)
                .destination_account(alice_id())
                .amount(Amount::Xrp(100 * XRP))
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_REDUNDANT,
        ),
        (
            TxBuilder::payment()
                .account(&alice)
                .destination(&bob_addr())
                .unwrap()
                .amount(Amount::Xrp(100 * XRP))
                .send_max(Amount::Xrp(100 * XRP))
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_BAD_SEND_XRP_MAX,
        ),
        (
            TxBuilder::payment()
                .account(&alice)
                .destination(&bob_addr())
                .unwrap()
                .amount(Amount::Xrp(100 * XRP))
                .flags(TF_PARTIAL_PAYMENT)
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_BAD_SEND_XRP_PARTIAL,
        ),
        (
            TxBuilder::payment()
                .account(&alice)
                .destination(&bob_addr())
                .unwrap()
                .amount(Amount::Xrp(100 * XRP))
                .deliver_min(Amount::Xrp(50 * XRP))
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_BAD_AMOUNT,
        ),
    ];

    for (blob, expected) in cases {
        let result = run_tx(
            &mut state,
            &parse_blob(&blob).unwrap(),
            &pctx(100),
            ApplyFlags::NONE,
        );
        assert_eq!(result.ter, expected);
        assert!(!result.applied);
        let account = state.get_account(&alice_id()).unwrap();
        assert_eq!(account.sequence, 1);
        assert_eq!(account.balance, 5_000 * XRP);
        assert_eq!(account.owner_count, 0);
    }
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

// ── DepositPreauth / DepositAuth parity ─────────────────────────────────────

#[test]
fn deposit_preauth_authorize_duplicate_and_unauthorize_match_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let auth = signed_deposit_preauth_authorize(&alice, 1, bob_id());
    let r = run_tx(&mut state, &auth, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "DepositPreauth failed: {}", r.ter);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);
    assert!(
        state.has_deposit_preauth(&xrpl::ledger::deposit_preauth::shamap_key(
            &alice_id(),
            &bob_id()
        ))
    );

    let dup = signed_deposit_preauth_authorize(&alice, 2, bob_id());
    let r = run_tx(&mut state, &dup, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_DUPLICATE);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);

    let unauth = signed_deposit_preauth_unauthorize(&alice, 3, bob_id());
    let r = run_tx(&mut state, &unauth, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "Deposit unauthorize failed: {}",
        r.ter
    );
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
    assert!(
        !state.has_deposit_preauth(&xrpl::ledger::deposit_preauth::shamap_key(
            &alice_id(),
            &bob_id()
        ))
    );

    let missing = signed_deposit_preauth_unauthorize(&alice, 4, bob_id());
    let r = run_tx(&mut state, &missing, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_ENTRY);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}

#[test]
fn deposit_preauth_authorize_self_is_tem_but_unauthorize_self_is_tec_no_entry() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let self_auth = signed_deposit_preauth_authorize(&alice, 1, alice_id());
    let r = run_tx(&mut state, &self_auth, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_CANNOT_PREAUTH_SELF);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);

    let self_unauth = signed_deposit_preauth_unauthorize(&alice, 1, alice_id());
    let r = run_tx(&mut state, &self_unauth, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_ENTRY);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 2);
}

#[test]
fn deposit_preauth_deposit_auth_gate_for_payments_matches_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let require_deposit_auth = TxBuilder::account_set()
        .account(&bob)
        .set_flag(9)
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&bob)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&require_deposit_auth.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success(), "AccountSet failed: {}", r.ter);
    assert_ne!(
        state.get_account(&bob_id()).unwrap().flags & LSF_DEPOSIT_AUTH,
        0
    );

    let blocked = signed_mpt_payment(&alice, 1, bob_id(), Amount::Xrp(100 * XRP));
    let r = run_tx(&mut state, &blocked, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_PERMISSION);

    let auth = signed_deposit_preauth_authorize(&bob, 2, alice_id());
    let r = run_tx(&mut state, &auth, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "DepositPreauth failed: {}", r.ter);

    let allowed = signed_mpt_payment(&alice, 2, bob_id(), Amount::Xrp(100 * XRP));
    let r = run_tx(&mut state, &allowed, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "preauthorized payment failed: {}",
        r.ter
    );

    let unauth = signed_deposit_preauth_unauthorize(&bob, 3, alice_id());
    let r = run_tx(&mut state, &unauth, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "Deposit unauthorize failed: {}",
        r.ter
    );

    let blocked_again = signed_mpt_payment(&alice, 3, bob_id(), Amount::Xrp(100 * XRP));
    let r = run_tx(&mut state, &blocked_again, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_PERMISSION);
}

#[test]
fn deposit_preauth_malformed_field_combinations_and_missing_target() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let both = TxBuilder::deposit_preauth()
        .account(&alice)
        .authorize(bob_id())
        .unauthorize(bob_id())
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&both.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEM_MALFORMED);

    let missing_target = signed_deposit_preauth_authorize(&alice, 1, carol_id());
    let r = run_tx(&mut state, &missing_target, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_TARGET);
}

#[test]
fn deposit_preauth_credential_array_preflight_errors_match_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let empty = parse_blob(
        &TxBuilder::deposit_preauth()
            .account(&alice)
            .authorize_credentials_raw(vec![0xF1])
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &empty, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_ARRAY_EMPTY);

    let too_large_credentials: Vec<([u8; 20], &[u8])> =
        (1u8..=9).map(|n| ([n; 20], b"KYC".as_slice())).collect();
    let too_large = parse_blob(
        &TxBuilder::deposit_preauth()
            .account(&alice)
            .authorize_credentials_raw(deposit_preauth_credentials_raw(&too_large_credentials))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &too_large, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_ARRAY_TOO_LARGE);

    let zero_issuer = parse_blob(
        &TxBuilder::deposit_preauth()
            .account(&alice)
            .authorize_credentials_raw(deposit_preauth_credentials_raw(&[([0u8; 20], b"KYC")]))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &zero_issuer, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_INVALID_ACCOUNT_ID);

    let empty_type = parse_blob(
        &TxBuilder::deposit_preauth()
            .account(&alice)
            .authorize_credentials_raw(deposit_preauth_credentials_raw(&[([1u8; 20], b"")]))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &empty_type, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_MALFORMED);

    let long_type = vec![b'X'; 65];
    let too_long_type = parse_blob(
        &TxBuilder::deposit_preauth()
            .account(&alice)
            .authorize_credentials_raw(deposit_preauth_credentials_raw(&[(
                [1u8; 20],
                long_type.as_slice(),
            )]))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &too_long_type, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_MALFORMED);

    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}

#[test]
fn deposit_preauth_credentials_sort_key_and_remove_like_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);
    fund(&mut state, &carol, 10_000);

    let unsorted_raw = deposit_preauth_credentials_raw(&[(carol_id(), b"Z"), (bob_id(), b"A")]);
    let auth = parse_blob(
        &TxBuilder::deposit_preauth()
            .account(&alice)
            .authorize_credentials_raw(unsorted_raw.clone())
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &auth, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "auth credentials failed: {}", r.ter);

    let mut sorted_pairs = vec![(carol_id(), b"Z".to_vec()), (bob_id(), b"A".to_vec())];
    sorted_pairs.sort();
    let key = xrpl::ledger::deposit_preauth::credential_shamap_key(&alice_id(), &sorted_pairs);
    assert!(state.get_raw(&key).is_some());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);

    let duplicate = parse_blob(
        &TxBuilder::deposit_preauth()
            .account(&alice)
            .authorize_credentials_raw(deposit_preauth_credentials_raw(&[
                (bob_id(), b"A"),
                (carol_id(), b"Z"),
            ]))
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &duplicate, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_DUPLICATE);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);

    let unauth = parse_blob(
        &TxBuilder::deposit_preauth()
            .account(&alice)
            .unauthorize_credentials_raw(unsorted_raw)
            .fee(BASE_FEE)
            .sequence(3)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &unauth, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "unauth credentials failed: {}",
        r.ter
    );
    assert!(state.get_raw(&key).is_none());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}

#[test]
fn credential_create_accept_delete_lifecycle_matches_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let create = signed_credential_create(
        &alice,
        1,
        Some(bob_id()),
        Some(b"KYC"),
        Some(200),
        Some(b"https://issuer.example/kyc"),
        0,
    );
    let r = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "create failed: {}", r.ter);

    let key = xrpl::ledger::keylet::credential(&bob_id(), &alice_id(), b"KYC").key;
    let raw = state.get_raw(&key).expect("credential SLE").to_vec();
    assert_eq!(sle_account_field(&raw, 24), Some(bob_id()));
    assert_eq!(sle_account_field(&raw, 4), Some(alice_id()));
    assert_eq!(sle_blob_field(&raw, 31), Some(b"KYC".to_vec()));
    assert_eq!(
        sle_blob_field(&raw, 5),
        Some(b"https://issuer.example/kyc".to_vec())
    );
    assert_eq!(sle_u32_field(&raw, 10), 200);
    assert_eq!(sle_u32_field(&raw, 2), 0);
    assert_eq!(sle_u64_field(&raw, 27), Some(0));
    assert_eq!(sle_u64_field(&raw, 28), Some(0));
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 0);

    let accept = signed_credential_accept(&bob, 1, Some(alice_id()), Some(b"KYC"), 0);
    let r = run_tx(&mut state, &accept, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "accept failed: {}", r.ter);
    let raw = state.get_raw(&key).expect("accepted credential").to_vec();
    assert_eq!(sle_u32_field(&raw, 2), 0x0001_0000);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 1);

    let delete =
        signed_credential_delete(&bob, 2, Some(bob_id()), Some(alice_id()), Some(b"KYC"), 0);
    let r = run_tx(&mut state, &delete, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "delete failed: {}", r.ter);
    assert!(state.get_raw(&key).is_none());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 0);

    let self_create =
        signed_credential_create(&bob, 3, Some(bob_id()), Some(b"SELF"), None, None, 0);
    let r = run_tx(&mut state, &self_create, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "self create failed: {}", r.ter);
    let self_key = xrpl::ledger::keylet::credential(&bob_id(), &bob_id(), b"SELF").key;
    let raw = state.get_raw(&self_key).expect("self credential").to_vec();
    assert_eq!(sle_u32_field(&raw, 2), 0x0001_0000);
    assert_eq!(sle_u64_field(&raw, 27), Some(0));
    assert_eq!(sle_u64_field(&raw, 28), None);
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 1);
}

#[test]
fn credential_malformed_preflight_errors_do_not_claim_fee_or_sequence() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);
    let start_balance = state.get_account(&alice_id()).unwrap().balance;

    let long_type = vec![b'T'; 65];
    let long_uri = vec![b'U'; 257];
    let cases = [
        (
            signed_credential_create(&alice, 1, Some(bob_id()), Some(b"KYC"), None, None, 0x10000),
            ter::TEM_INVALID_FLAG,
        ),
        (
            signed_credential_create(&alice, 1, None, Some(b"KYC"), None, None, 0),
            ter::TEM_MALFORMED,
        ),
        (
            signed_credential_create(&alice, 1, Some([0u8; 20]), Some(b"KYC"), None, None, 0),
            ter::TEM_MALFORMED,
        ),
        (
            signed_credential_create(&alice, 1, Some(bob_id()), Some(b""), None, None, 0),
            ter::TEM_MALFORMED,
        ),
        (
            signed_credential_create(
                &alice,
                1,
                Some(bob_id()),
                Some(long_type.as_slice()),
                None,
                None,
                0,
            ),
            ter::TEM_MALFORMED,
        ),
        (
            signed_credential_create(&alice, 1, Some(bob_id()), Some(b"KYC"), None, Some(b""), 0),
            ter::TEM_MALFORMED,
        ),
        (
            signed_credential_create(
                &alice,
                1,
                Some(bob_id()),
                Some(b"KYC"),
                None,
                Some(long_uri.as_slice()),
                0,
            ),
            ter::TEM_MALFORMED,
        ),
        (
            signed_credential_accept(&alice, 1, None, Some(b"KYC"), 0),
            ter::TEM_MALFORMED,
        ),
        (
            signed_credential_accept(&alice, 1, Some([0u8; 20]), Some(b"KYC"), 0),
            ter::TEM_INVALID_ACCOUNT_ID,
        ),
        (
            signed_credential_delete(&alice, 1, None, None, Some(b"KYC"), 0),
            ter::TEM_MALFORMED,
        ),
        (
            signed_credential_delete(&alice, 1, Some([0u8; 20]), Some(bob_id()), Some(b"KYC"), 0),
            ter::TEM_INVALID_ACCOUNT_ID,
        ),
        (
            signed_credential_delete(&alice, 1, Some(bob_id()), Some(alice_id()), None, 0),
            ter::TEM_MALFORMED,
        ),
    ];

    for (tx, expected) in cases {
        let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
        assert_eq!(r.ter, expected);
        assert!(!r.applied);
        let account = state.get_account(&alice_id()).unwrap();
        assert_eq!(account.sequence, 1);
        assert_eq!(account.balance, start_balance);
        assert_eq!(account.owner_count, 0);
    }
}

#[test]
fn credential_accept_expiration_and_duplicate_order_matches_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let create =
        signed_credential_create(&alice, 1, Some(bob_id()), Some(b"EXP"), Some(50), None, 0);
    let r = run_tx(&mut state, &create, &pctx(40), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "create failed: {}", r.ter);
    let key = xrpl::ledger::keylet::credential(&bob_id(), &alice_id(), b"EXP").key;

    let accept = signed_credential_accept(&bob, 1, Some(alice_id()), Some(b"EXP"), 0);
    let r = run_tx(&mut state, &accept, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_EXPIRED);
    assert!(r.applied);
    assert!(state.get_raw(&key).is_none());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 0);

    let self_create =
        signed_credential_create(&bob, 2, Some(bob_id()), Some(b"SELFEXP"), Some(50), None, 0);
    let r = run_tx(&mut state, &self_create, &pctx(40), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "self create failed: {}", r.ter);
    let self_key = xrpl::ledger::keylet::credential(&bob_id(), &bob_id(), b"SELFEXP").key;

    let duplicate_accept = signed_credential_accept(&bob, 3, Some(bob_id()), Some(b"SELFEXP"), 0);
    let r = run_tx(&mut state, &duplicate_accept, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_DUPLICATE);
    assert!(r.applied);
    assert!(state.get_raw(&self_key).is_some());
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 1);
}

#[test]
fn did_set_modify_and_delete_matches_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let create = signed_did_set(&alice, 1, Some(b"uri"), None, None, 0);
    let r = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "DIDSet create failed: {}", r.ter);
    let key = xrpl::ledger::keylet::did(&alice_id()).key;
    let raw = state.get_raw(&key).expect("DID SLE exists").to_vec();
    assert_eq!(sle_account_field(&raw, 1), Some(alice_id()));
    assert_eq!(sle_blob_field(&raw, 5), Some(b"uri".to_vec()));
    assert_eq!(sle_blob_field(&raw, 26), None);
    assert_eq!(sle_blob_field(&raw, 27), None);
    assert_eq!(sle_u64_field(&raw, 4), Some(0));
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);

    let set_document = signed_did_set(&alice, 2, None, Some(b"document"), None, 0);
    let r = run_tx(&mut state, &set_document, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "DIDSet document failed: {}", r.ter);
    let raw = state.get_raw(&key).expect("DID SLE exists").to_vec();
    assert_eq!(sle_blob_field(&raw, 5), Some(b"uri".to_vec()));
    assert_eq!(sle_blob_field(&raw, 26), Some(b"document".to_vec()));
    assert_eq!(sle_blob_field(&raw, 27), None);

    let set_data = signed_did_set(&alice, 3, None, None, Some(b"attest"), 0);
    let r = run_tx(&mut state, &set_data, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "DIDSet data failed: {}", r.ter);

    let clear_uri = signed_did_set(&alice, 4, Some(b""), None, None, 0);
    let r = run_tx(&mut state, &clear_uri, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "DIDSet clear URI failed: {}", r.ter);
    let raw = state.get_raw(&key).expect("DID SLE exists").to_vec();
    assert_eq!(sle_blob_field(&raw, 5), None);
    assert_eq!(sle_blob_field(&raw, 26), Some(b"document".to_vec()));
    assert_eq!(sle_blob_field(&raw, 27), Some(b"attest".to_vec()));

    let replace = signed_did_set(&alice, 5, Some(b"uri2"), Some(b""), Some(b""), 0);
    let r = run_tx(&mut state, &replace, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "DIDSet replace failed: {}", r.ter);
    let raw = state.get_raw(&key).expect("DID SLE exists").to_vec();
    assert_eq!(sle_blob_field(&raw, 5), Some(b"uri2".to_vec()));
    assert_eq!(sle_blob_field(&raw, 26), None);
    assert_eq!(sle_blob_field(&raw, 27), None);

    let clear_last = signed_did_set(&alice, 6, Some(b""), None, None, 0);
    let r = run_tx(&mut state, &clear_last, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_EMPTY_DID);
    assert!(r.applied);
    let raw = state
        .get_raw(&key)
        .expect("DID SLE remains after tecEMPTY_DID")
        .to_vec();
    assert_eq!(sle_blob_field(&raw, 5), Some(b"uri2".to_vec()));
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 7);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);

    let delete = signed_did_delete(&alice, 7, 0);
    let r = run_tx(&mut state, &delete, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "DIDDelete failed: {}", r.ter);
    assert!(state.get_raw(&key).is_none());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}

#[test]
fn did_malformed_preflight_errors_do_not_claim_fee_or_sequence() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);
    let start_balance = state.get_account(&alice_id()).unwrap().balance;

    let long = vec![b'a'; 257];
    let cases = [
        (
            signed_did_set(&alice, 1, Some(b"uri"), None, None, 0x0001_0000),
            ter::TEM_INVALID_FLAG,
        ),
        (
            signed_did_set(&alice, 1, None, None, None, 0),
            ter::TEM_EMPTY_DID,
        ),
        (
            signed_did_set(&alice, 1, Some(b""), Some(b""), Some(b""), 0),
            ter::TEM_EMPTY_DID,
        ),
        (
            signed_did_set(&alice, 1, Some(long.as_slice()), None, None, 0),
            ter::TEM_MALFORMED,
        ),
        (
            signed_did_set(&alice, 1, None, Some(long.as_slice()), None, 0),
            ter::TEM_MALFORMED,
        ),
        (
            signed_did_set(&alice, 1, None, Some(b"document"), Some(long.as_slice()), 0),
            ter::TEM_MALFORMED,
        ),
        (
            signed_did_delete(&alice, 1, 0x0001_0000),
            ter::TEM_INVALID_FLAG,
        ),
    ];

    for (tx, expected) in cases {
        let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
        assert_eq!(r.ter, expected);
        assert!(!r.applied);
        let account = state.get_account(&alice_id()).unwrap();
        assert_eq!(account.sequence, 1);
        assert_eq!(account.balance, start_balance);
        assert_eq!(account.owner_count, 0);
    }
}

#[test]
fn did_stateful_failures_claim_fee_like_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);
    let start_balance = state.get_account(&alice_id()).unwrap().balance;

    let empty_create = signed_did_set(&alice, 1, Some(b""), None, None, 0);
    let r = run_tx(&mut state, &empty_create, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_EMPTY_DID);
    assert!(r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 2);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        start_balance - BASE_FEE
    );
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);

    let missing_delete = signed_did_delete(&alice, 2, 0);
    let r = run_tx(&mut state, &missing_delete, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_ENTRY);
    assert!(r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 3);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        start_balance - 2 * BASE_FEE
    );
}

#[test]
fn account_delete_requires_owner_reserve_fee() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let low_fee = parse_blob(
        &TxBuilder::account_delete()
            .account(&alice)
            .destination(&bob_addr())
            .unwrap()
            .fee(OWNER_RESERVE_FEE - 1)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &low_fee, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEL_INSUF_FEE_P);
    assert!(state.get_account(&alice_id()).is_some());

    let exact_fee = parse_blob(
        &TxBuilder::account_delete()
            .account(&alice)
            .destination(&bob_addr())
            .unwrap()
            .fee(OWNER_RESERVE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &exact_fee, &pctx(300), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "account delete failed: {}", r.ter);
    assert!(state.get_account(&alice_id()).is_none());
    assert_eq!(
        state.get_account(&bob_id()).unwrap().balance,
        20_000 * XRP - OWNER_RESERVE_FEE
    );
}

#[test]
fn account_delete_preclaim_precedence_matches_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let mut alice_account = state.get_account(&alice_id()).unwrap().clone();
    alice_account.minted_nftokens = 1;
    alice_account.burned_nftokens = 0;
    state.insert_account(alice_account);

    let missing_destination = parse_blob(
        &TxBuilder::account_delete()
            .account(&alice)
            .destination(&xrpl::crypto::base58::encode_account(&carol_id()))
            .unwrap()
            .fee(OWNER_RESERVE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(
        &mut state,
        &missing_destination,
        &pctx(300),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEC_NO_DST);

    let mut bob_account = state.get_account(&bob_id()).unwrap().clone();
    bob_account.flags |= LSF_REQUIRE_DEST_TAG;
    state.insert_account(bob_account);

    let missing_tag = parse_blob(
        &TxBuilder::account_delete()
            .account(&alice)
            .destination(&bob_addr())
            .unwrap()
            .fee(OWNER_RESERVE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &missing_tag, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_DST_TAG_NEEDED);
}

#[test]
fn account_delete_rejects_flags_and_self_destination_in_preflight() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let flagged = parse_blob(
        &TxBuilder::account_delete()
            .account(&alice)
            .destination(&bob_addr())
            .unwrap()
            .flags(0x0002_0000)
            .fee(OWNER_RESERVE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &flagged, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_INVALID_FLAG);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        10_000 * XRP
    );

    let self_destination = parse_blob(
        &TxBuilder::account_delete()
            .account(&alice)
            .destination(&xrpl::crypto::base58::encode_account(&alice_id()))
            .unwrap()
            .fee(OWNER_RESERVE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &self_destination, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_DST_IS_SRC);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        10_000 * XRP
    );
}

#[test]
fn account_delete_uses_preclaim_account_sequence_for_too_soon_boundary() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);

    let tx = parse_blob(
        &TxBuilder::account_delete()
            .account(&alice)
            .destination(&bob_addr())
            .unwrap()
            .fee(OWNER_RESERVE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &tx, &pctx(256), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "account delete failed: {}", r.ter);
    assert!(state.get_account(&alice_id()).is_none());
    assert_eq!(
        state.get_account(&bob_id()).unwrap().balance,
        20_000 * XRP - OWNER_RESERVE_FEE
    );
}

#[test]
fn signer_list_set_create_replace_and_delete_matches_rippled_shape() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let create = parse_blob(
        &TxBuilder::signer_list_set()
            .account(&alice)
            .signer_quorum(2)
            .signer_entries_raw(signer_entries_raw(&[(bob_id(), 1), (carol_id(), 1)]))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "SignerListSet failed: {}", r.ter);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);

    let signer_list_key = xrpl::ledger::keylet::signer_list(&alice_id()).key;
    let raw = state
        .get_raw(&signer_list_key)
        .expect("SignerList SLE exists");
    let parsed = xrpl::ledger::meta::parse_sle(raw).expect("SignerList SLE parses");
    assert_eq!(parsed.entry_type, 0x0053);
    assert!(parsed.fields.iter().any(|f| f.type_code == 2
        && f.field_code == 2
        && u32::from_be_bytes(f.data.as_slice().try_into().unwrap()) == 0x0001_0000));
    assert!(parsed.fields.iter().any(|f| f.type_code == 2
        && f.field_code == 35
        && u32::from_be_bytes(f.data.as_slice().try_into().unwrap()) == 2));
    assert!(parsed.fields.iter().any(|f| f.type_code == 2
        && f.field_code == 38
        && u32::from_be_bytes(f.data.as_slice().try_into().unwrap()) == 0));

    let replace = parse_blob(
        &TxBuilder::signer_list_set()
            .account(&alice)
            .signer_quorum(1)
            .signer_entries_raw(signer_entries_raw(&[(bob_id(), 1)]))
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &replace, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "SignerList replace failed: {}",
        r.ter
    );
    assert_eq!(
        state.get_account(&alice_id()).unwrap().owner_count,
        1,
        "post-MultiSignReserve replacement has net zero owner-count change"
    );

    let delete = parse_blob(
        &TxBuilder::signer_list_set()
            .account(&alice)
            .signer_quorum(0)
            .fee(BASE_FEE)
            .sequence(3)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &delete, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "SignerList delete failed: {}",
        r.ter
    );
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
    assert!(state.get_raw(&signer_list_key).is_none());
}

#[test]
fn signer_list_replace_checks_reserve_after_removing_old_list() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let create = parse_blob(
        &TxBuilder::signer_list_set()
            .account(&alice)
            .signer_quorum(1)
            .signer_entries_raw(signer_entries_raw(&[(bob_id(), 1)]))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let signer_list_key = xrpl::ledger::keylet::signer_list(&alice_id()).key;
    let original_raw = state
        .get_raw(&signer_list_key)
        .expect("SignerList exists")
        .to_vec();

    let mut alice_root = state.get_account(&alice_id()).unwrap().clone();
    alice_root.balance = 1_200_000 - 1;
    state.insert_account(alice_root);

    let replace = parse_blob(
        &TxBuilder::signer_list_set()
            .account(&alice)
            .signer_quorum(2)
            .signer_entries_raw(signer_entries_raw(&[(bob_id(), 1), (carol_id(), 1)]))
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &replace, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_INSUFFICIENT_RESERVE);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);
    assert_eq!(
        state.get_raw(&signer_list_key).unwrap(),
        original_raw.as_slice(),
        "failed replacement must leave the old SignerList intact"
    );
}

#[test]
fn legacy_signer_list_owner_count_delta_matches_entry_count() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let create = parse_blob(
        &TxBuilder::signer_list_set()
            .account(&alice)
            .signer_quorum(2)
            .signer_entries_raw(signer_entries_raw(&[(bob_id(), 1), (carol_id(), 1)]))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let signer_list_key = xrpl::ledger::keylet::signer_list(&alice_id()).key;
    let legacy_raw = xrpl::ledger::meta::patch_sle(
        state.get_raw(&signer_list_key).expect("SignerList exists"),
        &[],
        None,
        None,
        &[(2u16, 2u16)],
    );
    state.insert_raw(signer_list_key, legacy_raw);
    let mut alice_root = state.get_account(&alice_id()).unwrap().clone();
    alice_root.owner_count = 4;
    state.insert_account(alice_root);

    let replace = parse_blob(
        &TxBuilder::signer_list_set()
            .account(&alice)
            .signer_quorum(1)
            .signer_entries_raw(signer_entries_raw(&[(bob_id(), 1)]))
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &replace, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "legacy replace failed: {}", r.ter);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().owner_count,
        1,
        "legacy two-signer list costs 2 + signer_count and replacement adds one modern unit"
    );

    let delete = parse_blob(
        &TxBuilder::signer_list_set()
            .account(&alice)
            .signer_quorum(0)
            .fee(BASE_FEE)
            .sequence(3)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &delete, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "modern delete failed: {}", r.ter);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}

#[test]
fn signer_list_set_preflight_errors_do_not_claim_fee() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let bad_flags = parse_blob(
        &TxBuilder::signer_list_set()
            .account(&alice)
            .flags(0x0001_0000)
            .signer_quorum(1)
            .signer_entries_raw(signer_entries_raw(&[(bob_id(), 1)]))
            .fee(0)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &bad_flags, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_INVALID_FLAG);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        10_000 * XRP
    );

    let self_signer = parse_blob(
        &TxBuilder::signer_list_set()
            .account(&alice)
            .signer_quorum(1)
            .signer_entries_raw(signer_entries_raw(&[(alice_id(), 1)]))
            .fee(0)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &self_signer, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_BAD_SIGNER);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        10_000 * XRP
    );

    let zero_quorum_with_entries = parse_blob(
        &TxBuilder::signer_list_set()
            .account(&alice)
            .signer_quorum(0)
            .signer_entries_raw(signer_entries_raw(&[(bob_id(), 1)]))
            .fee(0)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(
        &mut state,
        &zero_quorum_with_entries,
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEM_MALFORMED);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        10_000 * XRP
    );
}

#[test]
fn ledger_state_fix_requires_owner_reserve_fee() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);
    state.enable_amendment(xrpl::crypto::sha512_first_half(
        "fixNFTokenPageLinks".as_bytes(),
    ));

    let low_fee = parse_blob(
        &TxBuilder::ledger_state_fix()
            .account(&alice)
            .ledger_fix_type(1)
            .owner(alice_id())
            .fee(OWNER_RESERVE_FEE - 1)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &low_fee, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEL_INSUF_FEE_P);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

#[test]
fn ledger_state_fix_preflight_matches_rippled_edges() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);
    state.enable_amendment(xrpl::crypto::sha512_first_half(
        "fixNFTokenPageLinks".as_bytes(),
    ));

    let missing_owner = parse_blob(
        &TxBuilder::ledger_state_fix()
            .account(&alice)
            .ledger_fix_type(1)
            .fee(OWNER_RESERVE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &missing_owner, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_INVALID);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        10_000 * XRP
    );

    let unknown_fix_type = parse_blob(
        &TxBuilder::ledger_state_fix()
            .account(&alice)
            .ledger_fix_type(2)
            .owner(alice_id())
            .fee(OWNER_RESERVE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &unknown_fix_type, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEF_INVALID_LEDGER_FIX_TYPE);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

#[test]
fn ledger_state_fix_apply_failures_claim_fee_like_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);
    state.enable_amendment(xrpl::crypto::sha512_first_half(
        "fixNFTokenPageLinks".as_bytes(),
    ));

    let missing_owner_account = parse_blob(
        &TxBuilder::ledger_state_fix()
            .account(&alice)
            .ledger_fix_type(1)
            .owner(bob_id())
            .fee(OWNER_RESERVE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(
        &mut state,
        &missing_owner_account,
        &pctx(300),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEC_OBJECT_NOT_FOUND);
    assert!(r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 2);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        10_000 * XRP - OWNER_RESERVE_FEE
    );

    let no_repair = parse_blob(
        &TxBuilder::ledger_state_fix()
            .account(&alice)
            .ledger_fix_type(1)
            .owner(alice_id())
            .fee(OWNER_RESERVE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &no_repair, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_FAILED_PROCESSING);
    assert!(r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 3);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        10_000 * XRP - 2 * OWNER_RESERVE_FEE
    );
}

// ── Ticket parity ───────────────────────────────────────────────────────────

#[test]
fn ticket_create_signed_builder_creates_canonical_ticket_range() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let tx = signed_ticket_create(&alice, 1, 2);
    assert_eq!(tx.ticket_count, Some(2));

    let r = run_tx(&mut state, &tx, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert!(r.applied);

    let first = xrpl::ledger::ticket::shamap_key(&alice_id(), 2);
    let second = xrpl::ledger::ticket::shamap_key(&alice_id(), 3);
    let wrong = xrpl::ledger::ticket::shamap_key(&alice_id(), 1);
    assert!(state.get_raw_owned(&first).is_some());
    assert!(state.get_raw_owned(&second).is_some());
    assert!(state.get_raw_owned(&wrong).is_none());

    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.sequence, 4);
    assert_eq!(account.ticket_count, 2);
    assert_eq!(account.owner_count, 2);
}

#[test]
fn ticket_create_invalid_count_is_preflight_no_fee_or_sequence() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let tx = signed_ticket_create(&alice, 1, 0);
    let r = run_tx(&mut state, &tx, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_INVALID_COUNT);
    assert!(!r.applied);

    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.balance, 10_000 * XRP);
    assert_eq!(account.sequence, 1);
    assert_eq!(account.ticket_count, 0);
}

#[test]
fn ticket_create_flag_mask_matches_rippled_preflight() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let universal_flag = parse_blob(
        &TxBuilder::ticket_create()
            .account(&alice)
            .ticket_count(1)
            .flags(0x8000_0000)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &universal_flag, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert_eq!(state.get_account(&alice_id()).unwrap().ticket_count, 1);

    let invalid_flag = parse_blob(
        &TxBuilder::ticket_create()
            .account(&alice)
            .ticket_count(1)
            .flags(0x0002_0000)
            .fee(0)
            .sequence(3)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let before_balance = state.get_account(&alice_id()).unwrap().balance;
    let r = run_tx(&mut state, &invalid_flag, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_INVALID_FLAG);
    assert!(!r.applied);

    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.balance, before_balance);
    assert_eq!(account.sequence, 3);
    assert_eq!(account.ticket_count, 1);
}

#[test]
fn ticketed_ticket_create_cap_subtracts_consumed_ticket_like_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 100_000);

    let tx = signed_ticket_create(&alice, 1, 1);
    let r = run_tx(&mut state, &tx, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);

    let ticketed = parse_blob(
        &TxBuilder::ticket_create()
            .account(&alice)
            .ticket_count(250)
            .ticket_sequence(2)
            .fee(BASE_FEE)
            .sequence(0)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &ticketed, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);

    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.ticket_count, 250);
    assert_eq!(account.owner_count, 250);
}

#[test]
fn ticket_create_rejects_total_ticket_count_over_mainnet_cap() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 100_000);

    let tx = signed_ticket_create(&alice, 1, 250);
    let r = run_tx(&mut state, &tx, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    let balance_after_first = state.get_account(&alice_id()).unwrap().balance;

    let tx = signed_ticket_create(&alice, 252, 1);
    let r = run_tx(&mut state, &tx, &pctx(300), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_DIR_FULL);
    assert!(!r.applied);

    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.ticket_count, 250);
    assert_eq!(account.owner_count, 250);
    assert_eq!(account.sequence, 252);
    assert_eq!(account.balance, balance_after_first);
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
fn escrow_create_preserves_tags_in_escrow_sle() {
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
        .source_tag(123)
        .destination_tag(456)
        .fee(BASE_FEE)
        .sequence(1)
        .finish_after(200)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "escrow create failed: {}",
        result.ter
    );

    let key = xrpl::ledger::escrow::shamap_key(&alice_id(), 1);
    let escrow = state.get_escrow(&key).unwrap();
    assert_eq!(escrow.source_tag, Some(123));
    assert_eq!(escrow.destination_tag, Some(456));

    let raw = state.get_raw_owned(&key).unwrap();
    let decoded = xrpl::ledger::Escrow::decode_from_sle(&raw).unwrap();
    assert_eq!(decoded.source_tag, Some(123));
    assert_eq!(decoded.destination_tag, Some(456));
}

#[test]
fn escrow_create_allows_close_time_equal_finish_after() {
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
        .finish_after(200)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(200), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "rippled permits EscrowCreate at FinishAfter boundary: {}",
        result.ter
    );
    assert!(state
        .get_escrow(&xrpl::ledger::escrow::shamap_key(&alice_id(), 1))
        .is_some());
}

#[test]
fn escrow_create_iou_bad_currency_is_tem_bad_currency() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);

    let signed = TxBuilder::escrow_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_bad_currency(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .finish_after(200)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEM_BAD_CURRENCY);
    assert!(!result.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

#[test]
fn escrow_create_iou_requires_issuer_trustline_locking_flag() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);
    fund(&mut state, &carol, 300);

    let trust = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(100.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&trust.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    let alice_line_key = xrpl::ledger::trustline::shamap_key(&alice_id(), &carol_id(), &usd);
    let mut line = state.get_trustline(&alice_line_key).unwrap().clone();
    line.transfer(
        &carol_id(),
        &xrpl::transaction::amount::IouValue::from_f64(50.0),
    );
    state.insert_trustline(line);

    let signed = TxBuilder::escrow_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(25.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .finish_after(200)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEC_NO_PERMISSION);
    assert!(result.applied, "tecNO_PERMISSION claims fee only");
    assert!(state
        .get_escrow(&xrpl::ledger::escrow::shamap_key(&alice_id(), 2))
        .is_none());
}

#[test]
fn escrow_create_iou_locks_sender_trustline_when_issuer_allows_locking() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);
    fund(&mut state, &carol, 300);

    {
        let mut issuer = state.get_account(&carol_id()).unwrap().clone();
        issuer.flags |= LSF_ALLOW_TRUST_LINE_LOCKING;
        state.insert_account(issuer);
    }

    let trust = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(100.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&trust.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    let alice_line_key = xrpl::ledger::trustline::shamap_key(&alice_id(), &carol_id(), &usd);
    let mut line = state.get_trustline(&alice_line_key).unwrap().clone();
    line.transfer(
        &carol_id(),
        &xrpl::transaction::amount::IouValue::from_f64(50.0),
    );
    state.insert_trustline(line);

    let signed = TxBuilder::escrow_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(25.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .finish_after(200)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "IOU escrow create failed: {}",
        result.ter
    );
    assert!(state
        .get_escrow(&xrpl::ledger::escrow::shamap_key(&alice_id(), 2))
        .is_some());
    let line = state.get_trustline(&alice_line_key).unwrap();
    assert_eq!(
        line.balance_for(&alice_id()),
        xrpl::transaction::amount::IouValue::from_f64(25.0)
    );
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

fn iou_bad_currency(limit: f64, issuer_id: [u8; 20]) -> Amount {
    use xrpl::transaction::amount::{Currency, IouValue};
    Amount::Iou {
        value: IouValue::from_f64(limit),
        currency: Currency::bad_currency(),
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
fn trustset_zero_limit_set_auth_creates_reserved_line() {
    const TF_SET_AUTH_TRUSTLINE: u32 = 0x0001_0000;

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mut alice_account = state.get_account(&alice_id()).unwrap().clone();
    alice_account.flags |= LSF_REQUIRE_AUTH;
    state.insert_account(alice_account);

    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(0.0, bob_id()))
        .flags(TF_SET_AUTH_TRUSTLINE)
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "zero-limit tfSetAuth should create line: {}",
        result.ter
    );

    let alice_after = state.get_account(&alice_id()).unwrap();
    assert_eq!(alice_after.sequence, 2);
    assert_eq!(alice_after.owner_count, 1);

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    let line = state
        .get_trustline_for(&alice_id(), &bob_id(), &usd)
        .expect("auth-created trust line exists");
    let (reserve_flag, auth_flag) = if line.low_account == alice_id() {
        (
            xrpl::ledger::trustline::LSF_LOW_RESERVE,
            xrpl::ledger::trustline::LSF_LOW_AUTH,
        )
    } else {
        (
            xrpl::ledger::trustline::LSF_HIGH_RESERVE,
            xrpl::ledger::trustline::LSF_HIGH_AUTH,
        )
    };
    assert_ne!(line.flags & reserve_flag, 0);
    assert_ne!(line.flags & auth_flag, 0);
    assert!(line.low_limit.is_zero());
    assert!(line.high_limit.is_zero());
    assert!(line.balance.is_zero());
}

#[test]
fn trustset_default_update_deletes_auth_only_line() {
    const TF_SET_AUTH_TRUSTLINE: u32 = 0x0001_0000;

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mut alice_account = state.get_account(&alice_id()).unwrap().clone();
    alice_account.flags |= LSF_REQUIRE_AUTH;
    state.insert_account(alice_account);

    let create = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(0.0, bob_id()))
        .flags(TF_SET_AUTH_TRUSTLINE)
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let create_tx = parse_blob(&create.blob).unwrap();
    let create_result = run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    assert!(create_result.ter.is_tes_success());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);

    let clear = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(0.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let clear_tx = parse_blob(&clear.blob).unwrap();
    let clear_result = run_tx(&mut state, &clear_tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        clear_result.ter.is_tes_success(),
        "default update should delete auth-only line: {}",
        clear_result.ter
    );

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    assert!(state
        .get_trustline_for(&alice_id(), &bob_id(), &usd)
        .is_none());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}

#[test]
fn trustset_zero_limit_set_auth_new_line_checks_create_reserve() {
    const TF_SET_AUTH_TRUSTLINE: u32 = 0x0001_0000;

    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    state.insert_account(make_account(alice_id(), XRP + BASE_FEE));
    fund(&mut state, &bob, 5_000);

    let mut alice_account = state.get_account(&alice_id()).unwrap().clone();
    alice_account.flags |= LSF_REQUIRE_AUTH;
    alice_account.owner_count = 2;
    state.insert_account(alice_account);

    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(0.0, bob_id()))
        .flags(TF_SET_AUTH_TRUSTLINE)
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEC_NO_LINE_INSUF_RESERVE);
    assert!(result.applied, "tec reserve failure claims fee only");
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    assert!(state
        .get_trustline_for(&alice_id(), &bob_id(), &usd)
        .is_none());
}

#[test]
fn trustset_bad_currency_is_tem_bad_currency() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_bad_currency(1000.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEM_BAD_CURRENCY);
    assert!(!result.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

#[test]
fn trustset_malformed_preflight_errors_do_not_claim_fee_or_sequence() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let cases = [
        (
            TxBuilder::trust_set()
                .account(&alice)
                .limit_amount(iou_usd(100.0, bob_id()))
                .flags(0x0008_0000)
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_INVALID_FLAG,
        ),
        (
            TxBuilder::trust_set()
                .account(&alice)
                .limit_amount(Amount::Xrp(100))
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_BAD_LIMIT,
        ),
        (
            TxBuilder::trust_set()
                .account(&alice)
                .limit_amount(iou_usd(-100.0, bob_id()))
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_BAD_LIMIT,
        ),
        (
            TxBuilder::trust_set()
                .account(&alice)
                .limit_amount(iou_usd(100.0, [0u8; 20]))
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_DST_NEEDED,
        ),
        (
            TxBuilder::trust_set()
                .account(&alice)
                .limit_amount(iou_bad_currency(100.0, bob_id()))
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_BAD_CURRENCY,
        ),
        (
            TxBuilder::trust_set()
                .account(&alice)
                .limit_amount(iou_usd(100.0, bob_id()))
                .flags(0x0040_0000)
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_INVALID_FLAG,
        ),
    ];

    for (blob, expected) in cases {
        let result = run_tx(
            &mut state,
            &parse_blob(&blob).unwrap(),
            &pctx(100),
            ApplyFlags::NONE,
        );
        assert_eq!(result.ter, expected);
        assert!(!result.applied);
        let account = state.get_account(&alice_id()).unwrap();
        assert_eq!(account.sequence, 1);
        assert_eq!(account.balance, 5_000 * XRP);
        assert_eq!(account.owner_count, 0);
    }
}

#[test]
fn trustset_zero_limit_then_matching_no_ripple_removes_trust_line() {
    const TF_SET_NO_RIPPLE: u32 = 0x0002_0000;

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
    assert_eq!(a.owner_count, 1);

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    assert!(state
        .get_trustline_for(&alice_id(), &bob_id(), &usd)
        .is_some());

    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(0.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(3)
        .flags(TF_SET_NO_RIPPLE)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();
    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "trustset no-ripple default failed: {}",
        result.ter
    );

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 0);
    assert!(state
        .get_trustline_for(&alice_id(), &bob_id(), &usd)
        .is_none());
}

#[test]
fn trustset_first_two_owned_lines_do_not_require_incremental_reserve() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    state.insert_account(make_account(alice_id(), XRP + BASE_FEE));
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
        "first trust line should not enforce owner reserve: {}",
        result.ter
    );
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);

    let mut alice_account = state.get_account(&alice_id()).unwrap().clone();
    alice_account.balance = XRP + BASE_FEE;
    alice_account.owner_count = 1;
    state.insert_account(alice_account);
    state.insert_account(make_account(carol_id(), 5_000 * XRP));
    let carol_limit = iou_usd(1000.0, carol_id());
    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(carol_limit)
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "second owned trust line should not enforce owner reserve: {}",
        result.ter
    );
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);
}

#[test]
fn trustset_third_owned_line_requires_incremental_reserve() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    state.insert_account(make_account(alice_id(), XRP + BASE_FEE));
    fund(&mut state, &bob, 5_000);

    let mut alice_account = state.get_account(&alice_id()).unwrap().clone();
    alice_account.owner_count = 2;
    state.insert_account(alice_account);

    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(1000.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEC_NO_LINE_INSUF_RESERVE);
    assert!(result.applied, "tec reserve failure claims fee only");
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);
}

#[test]
fn trustset_existing_line_reserve_increase_uses_existing_line_code() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    state.insert_account(make_account(alice_id(), XRP + BASE_FEE));
    fund(&mut state, &bob, 5_000);

    let bob_creates_line = TxBuilder::trust_set()
        .account(&bob)
        .limit_amount(iou_usd(1000.0, alice_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&bob)
        .unwrap();
    let bob_tx = parse_blob(&bob_creates_line.blob).unwrap();
    let bob_result = run_tx(&mut state, &bob_tx, &pctx(100), ApplyFlags::NONE);
    assert!(bob_result.ter.is_tes_success());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);

    let mut alice_account = state.get_account(&alice_id()).unwrap().clone();
    alice_account.owner_count = 2;
    state.insert_account(alice_account);

    let alice_claims_reserve = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(1000.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let alice_tx = parse_blob(&alice_claims_reserve.blob).unwrap();
    let result = run_tx(&mut state, &alice_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEC_INSUF_RESERVE_LINE);
    assert!(result.applied, "tec reserve failure claims fee only");
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);
}

#[test]
fn trustset_disallow_incoming_blocks_only_new_lines() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);
    let mut bob_account = state.get_account(&bob_id()).unwrap().clone();
    bob_account.flags |= LSF_DISALLOW_INCOMING_TRUSTLINE;
    state.insert_account(bob_account);

    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(1000.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();
    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEC_NO_PERMISSION);

    let mut bob_account = state.get_account(&bob_id()).unwrap().clone();
    bob_account.flags &= !LSF_DISALLOW_INCOMING_TRUSTLINE;
    state.insert_account(bob_account);
    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(1000.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();
    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(result.ter.is_tes_success());

    let mut bob_account = state.get_account(&bob_id()).unwrap().clone();
    bob_account.flags |= LSF_DISALLOW_INCOMING_TRUSTLINE;
    state.insert_account(bob_account);
    let signed = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(500.0, bob_id()))
        .fee(BASE_FEE)
        .sequence(3)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();
    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "existing line modification should bypass disallow incoming: {}",
        result.ter
    );
}

#[test]
fn trustset_to_amm_pseudo_requires_lp_token_currency() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);
    fund(&mut state, &carol, 5_000);
    enable_default_ripple(&mut state, bob_id());
    issue_usd_to_alice(&mut state, 100 * XRP);

    let (xrp, usd) = amm_test_pair();
    let create = amm_create_tx(&alice, 1, 100 * XRP);
    let result = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "AMMCreate failed: {}",
        result.ter
    );
    let lp = amm_lp_token_amount(&state, &xrp, &usd, 10);
    let amm_account = match &lp {
        Amount::Iou { issuer, .. } => *issuer,
        _ => panic!("LP token must be an IOU"),
    };

    let usd_to_amm = {
        use xrpl::transaction::amount::{Currency, IouValue};
        Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: amm_account,
        }
    };
    let wrong = TxBuilder::trust_set()
        .account(&carol)
        .limit_amount(usd_to_amm)
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&carol)
        .unwrap();
    let wrong_tx = parse_blob(&wrong.blob).unwrap();
    let wrong_result = run_tx(&mut state, &wrong_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(wrong_result.ter, ter::TEC_NO_PERMISSION);

    let allowed = TxBuilder::trust_set()
        .account(&bob)
        .limit_amount(lp.clone())
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&bob)
        .unwrap();
    let allowed_tx = parse_blob(&allowed.blob).unwrap();
    let allowed_result = run_tx(&mut state, &allowed_tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        allowed_result.ter.is_tes_success(),
        "LP TrustSet failed: {}",
        allowed_result.ter
    );
    let Amount::Iou {
        currency,
        issuer: lp_issuer,
        ..
    } = lp
    else {
        panic!("LP token must be an IOU");
    };
    assert!(state
        .get_trustline_for(&bob_id(), &lp_issuer, &currency)
        .is_some());
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
fn offer_create_lp_token_taker_gets_respects_underlying_freeze() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);
    enable_default_ripple(&mut state, bob_id());
    issue_usd_to_alice(&mut state, 100 * XRP);

    let (xrp, usd) = amm_test_pair();
    let create = amm_create_tx(&alice, 1, 100 * XRP);
    let result = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(
        result.ter.is_tes_success(),
        "AMMCreate failed: {}",
        result.ter
    );

    let mut issuer = state.get_account(&bob_id()).cloned().unwrap();
    issuer.flags |= xrpl::ledger::account::LSF_GLOBAL_FREEZE;
    state.insert_account(issuer);

    let lp = amm_lp_token_amount(&state, &xrp, &usd, 10);
    let signed = TxBuilder::offer_create()
        .account(&alice)
        .taker_pays(Amount::Xrp(1 * XRP))
        .taker_gets(lp)
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEC_UNFUNDED_OFFER);
    assert!(state.offers_by_account(&alice_id()).is_empty());
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

#[test]
fn offer_cancel_rejects_zero_or_current_sequence_without_fee() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let zero_offer_sequence = parse_blob(
        &TxBuilder::offer_cancel()
            .account(&alice)
            .offer_sequence(0)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(
        &mut state,
        &zero_offer_sequence,
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEM_BAD_SEQUENCE);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(state.get_account(&alice_id()).unwrap().balance, 5_000 * XRP);

    let current_sequence = parse_blob(
        &TxBuilder::offer_cancel()
            .account(&alice)
            .offer_sequence(1)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &current_sequence, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_BAD_SEQUENCE);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(state.get_account(&alice_id()).unwrap().balance, 5_000 * XRP);
}

#[test]
fn offer_cancel_missing_older_offer_still_succeeds() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let advance = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &advance, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success());

    let cancel_missing = parse_blob(
        &TxBuilder::offer_cancel()
            .account(&alice)
            .offer_sequence(1)
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &cancel_missing, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success());
    assert!(r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 3);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        5_000 * XRP - 2 * BASE_FEE
    );
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

#[test]
fn check_create_bad_currency_is_tem_bad_currency() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);

    let signed = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_bad_currency(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEM_BAD_CURRENCY);
    assert!(!result.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

#[test]
fn check_create_self_takes_preflight_priority_over_bad_currency() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 300);

    let signed = TxBuilder::check_create()
        .account(&alice)
        .destination(&xrpl::crypto::base58::encode_account(&alice_id()))
        .unwrap()
        .amount(iou_bad_currency(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEM_REDUNDANT);
    assert!(!result.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

#[test]
fn check_create_preclaim_destination_precedes_iou_freeze() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let carol = kp_carol();
    fund(&mut state, &alice, 300);
    fund(&mut state, &carol, 300);

    let mut issuer = state.get_account(&carol_id()).unwrap().clone();
    issuer.flags |= LSF_GLOBAL_FREEZE;
    state.insert_account(issuer);

    let missing_destination = xrpl::crypto::base58::encode_account(&[77u8; 20]);
    let signed = TxBuilder::check_create()
        .account(&alice)
        .destination(&missing_destination)
        .unwrap()
        .amount(iou_usd(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEC_NO_DST);
}

#[test]
fn check_create_preclaim_dest_tag_precedes_source_line_freeze() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);
    fund(&mut state, &carol, 300);

    let trust = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(100.0, carol_id()))
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

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    let line_key = xrpl::ledger::trustline::shamap_key(&alice_id(), &carol_id(), &usd);
    let mut line = state.get_trustline(&line_key).unwrap().clone();
    line.flags |= if carol_id() == line.low_account {
        LSF_LOW_FREEZE
    } else {
        LSF_HIGH_FREEZE
    };
    state.insert_trustline(line);

    let mut destination = state.get_account(&bob_id()).unwrap().clone();
    destination.flags |= LSF_REQUIRE_DEST_TAG;
    state.insert_account(destination);

    let signed = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEC_DST_TAG_NEEDED);
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
fn escrow_finish_rejects_at_finish_after_boundary() {
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
        .finish_after(200)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

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
    assert_eq!(result.ter, ter::TEC_NO_PERMISSION);
    assert!(result.applied);
    assert!(state
        .get_escrow(&xrpl::ledger::escrow::shamap_key(&alice_id(), 1))
        .is_some());
    assert_eq!(state.get_account(&bob_id()).unwrap().sequence, 2);
    assert_eq!(
        state.get_account(&bob_id()).unwrap().balance,
        5_000 * XRP - BASE_FEE
    );
}

#[test]
fn escrow_finish_allows_close_time_equal_cancel_after() {
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
        .finish_after(100)
        .cancel_after(200)
        .sign(&alice)
        .unwrap();
    let create = run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(50),
        ApplyFlags::NONE,
    );
    assert!(create.ter.is_tes_success());

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
    assert!(
        result.ter.is_tes_success(),
        "rippled permits EscrowFinish at CancelAfter boundary: {}",
        result.ter
    );
    assert!(state
        .get_escrow(&xrpl::ledger::escrow::shamap_key(&alice_id(), 1))
        .is_none());
    assert_eq!(
        state.get_account(&bob_id()).unwrap().balance,
        5_000 * XRP + 1_000 * XRP - BASE_FEE
    );
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
        .check_id(check::shamap_key(&alice_id(), 1).0)
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
        .check_id(check::shamap_key(&alice_id(), 1).0)
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
        .check_id(check::shamap_key(&alice_id(), 1).0)
        .sign(&bob)
        .unwrap();
    let mut tx = parse_blob(&signed.blob).unwrap();
    tx.owner = Some(alice_id());

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    // Should fail — Alice can't cover the check
    assert_eq!(r.ter, ter::TEC_UNFUNDED_PAYMENT);
}

#[test]
fn check_cash_bad_currency_is_tem_bad_currency_before_check_lookup() {
    let mut state = LedgerState::new();
    let bob = kp_bob();
    fund(&mut state, &bob, 300);

    let signed = TxBuilder::check_cash()
        .account(&bob)
        .amount(iou_bad_currency(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .check_id([0xAA; 32])
        .sign(&bob)
        .unwrap();
    let tx = parse_blob(&signed.blob).unwrap();

    let result = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEM_BAD_CURRENCY);
    assert!(!result.applied);
    assert_eq!(state.get_account(&bob_id()).unwrap().sequence, 1);
}

#[test]
fn check_malformed_preflight_errors_do_not_claim_fee_or_sequence() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);

    let create_bad_flags = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(10 * XRP))
        .flags(0x0002_0000)
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&create_bad_flags.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEM_INVALID_FLAG);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(state.get_account(&alice_id()).unwrap().balance, 300 * XRP);

    let cash_both_amounts = TxBuilder::check_cash()
        .account(&bob)
        .check_id([0xAA; 32])
        .amount(Amount::Xrp(1 * XRP))
        .deliver_min(Amount::Xrp(1 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&bob)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&cash_both_amounts.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEM_MALFORMED);
    assert!(!r.applied);
    assert_eq!(state.get_account(&bob_id()).unwrap().sequence, 1);
    assert_eq!(state.get_account(&bob_id()).unwrap().balance, 300 * XRP);

    let cancel_missing_id = TxBuilder::check_cancel()
        .account(&bob)
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&bob)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&cancel_missing_id.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEM_MALFORMED);
    assert!(!r.applied);
    assert_eq!(state.get_account(&bob_id()).unwrap().sequence, 1);
    assert_eq!(state.get_account(&bob_id()).unwrap().balance, 300 * XRP);
}

#[test]
fn check_create_and_cash_iou_creates_destination_line_and_transfers_issue() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);
    fund(&mut state, &carol, 300);

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();

    let trust = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(100.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&trust.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success(), "trustset failed: {}", r.ter);

    let alice_line_key = xrpl::ledger::trustline::shamap_key(&alice_id(), &carol_id(), &usd);
    let mut line = state
        .get_trustline(&alice_line_key)
        .expect("alice trustline")
        .clone();
    line.transfer(
        &carol_id(),
        &xrpl::transaction::amount::IouValue::from_f64(50.0),
    );
    state.insert_trustline(line);

    let check = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(25.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&check.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success(), "check create failed: {}", r.ter);

    let cash = TxBuilder::check_cash()
        .account(&bob)
        .amount(iou_usd(25.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .check_id(check::shamap_key(&alice_id(), 2).0)
        .sign(&bob)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&cash.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success(), "check cash failed: {}", r.ter);

    let alice_line = state
        .get_trustline(&alice_line_key)
        .expect("alice trustline remains");
    assert_eq!(
        alice_line.balance_for(&alice_id()),
        xrpl::transaction::amount::IouValue::from_f64(25.0)
    );

    let bob_line_key = xrpl::ledger::trustline::shamap_key(&bob_id(), &carol_id(), &usd);
    let bob_line = state
        .get_trustline(&bob_line_key)
        .expect("CheckCash creates destination trustline");
    assert_eq!(
        bob_line.balance_for(&bob_id()),
        xrpl::transaction::amount::IouValue::from_f64(25.0)
    );
    let bob_no_ripple = if bob_id() == bob_line.low_account {
        LSF_LOW_NO_RIPPLE
    } else {
        LSF_HIGH_NO_RIPPLE
    };
    let issuer_no_ripple = if carol_id() == bob_line.low_account {
        LSF_LOW_NO_RIPPLE
    } else {
        LSF_HIGH_NO_RIPPLE
    };
    assert_eq!(
        bob_line.flags & (bob_no_ripple | issuer_no_ripple),
        bob_no_ripple | issuer_no_ripple,
        "CheckCash-created trust line must inherit both parties' default NoRipple bits"
    );
    assert!(state
        .get_check(&check::shamap_key(&alice_id(), 2))
        .is_none());
}

#[test]
fn check_cash_iou_deliver_min_takes_available_up_to_sendmax() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);
    fund(&mut state, &carol, 300);

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    let trust = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(100.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&trust.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let alice_line_key = xrpl::ledger::trustline::shamap_key(&alice_id(), &carol_id(), &usd);
    let mut line = state.get_trustline(&alice_line_key).unwrap().clone();
    line.transfer(
        &carol_id(),
        &xrpl::transaction::amount::IouValue::from_f64(30.0),
    );
    state.insert_trustline(line);

    let check = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(50.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&check.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let cash = TxBuilder::check_cash()
        .account(&bob)
        .deliver_min(iou_usd(20.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .check_id(check::shamap_key(&alice_id(), 2).0)
        .sign(&bob)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&cash.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success(), "check cash failed: {}", r.ter);

    let bob_line_key = xrpl::ledger::trustline::shamap_key(&bob_id(), &carol_id(), &usd);
    let bob_line = state.get_trustline(&bob_line_key).unwrap();
    assert_eq!(
        bob_line.balance_for(&bob_id()),
        xrpl::transaction::amount::IouValue::from_f64(30.0)
    );
}

#[test]
fn check_cash_iou_rejects_wrong_issue_and_over_sendmax() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);
    fund(&mut state, &carol, 300);

    let trust = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(100.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&trust.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let check = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(25.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&check.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let wrong_issue = TxBuilder::check_cash()
        .account(&bob)
        .amount(iou_usd(1.0, alice_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .check_id(check::shamap_key(&alice_id(), 2).0)
        .sign(&bob)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&wrong_issue.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEM_MALFORMED);

    let over = TxBuilder::check_cash()
        .account(&bob)
        .amount(iou_usd(26.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .check_id(check::shamap_key(&alice_id(), 2).0)
        .sign(&bob)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&over.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEC_PATH_PARTIAL);
}

#[test]
fn check_cash_iou_uses_flow_transfer_rate_and_restores_destination_limit() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);
    fund(&mut state, &carol, 300);
    {
        let mut issuer = state.get_account(&carol_id()).unwrap().clone();
        issuer.transfer_rate = 2_000_000_000;
        state.insert_account(issuer);
    }

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    let trust = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(100.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&trust.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let alice_line_key = xrpl::ledger::trustline::shamap_key(&alice_id(), &carol_id(), &usd);
    let mut line = state.get_trustline(&alice_line_key).unwrap().clone();
    line.transfer(
        &carol_id(),
        &xrpl::transaction::amount::IouValue::from_f64(50.0),
    );
    state.insert_trustline(line);

    let check = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(50.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&check.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let cash = TxBuilder::check_cash()
        .account(&bob)
        .amount(iou_usd(25.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .check_id(check::shamap_key(&alice_id(), 2).0)
        .sign(&bob)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&cash.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success(), "check cash failed: {}", r.ter);

    let alice_line = state.get_trustline(&alice_line_key).unwrap();
    assert_eq!(
        alice_line.balance_for(&alice_id()),
        xrpl::transaction::amount::IouValue::ZERO,
        "owner-pays transfer rate should debit 50 USD to deliver 25 USD"
    );

    let bob_line_key = xrpl::ledger::trustline::shamap_key(&bob_id(), &carol_id(), &usd);
    let bob_line = state.get_trustline(&bob_line_key).unwrap();
    assert_eq!(
        bob_line.balance_for(&bob_id()),
        xrpl::transaction::amount::IouValue::from_f64(25.0)
    );
    assert!(
        bob_line.low_limit.is_zero() && bob_line.high_limit.is_zero(),
        "CheckCash must restore the temporary destination trustline limit"
    );
}

#[test]
fn check_cash_iou_failed_destination_line_creation_rolls_back() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 1);
    fund(&mut state, &carol, 300);

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    let trust = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(100.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&trust.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    let alice_line_key = xrpl::ledger::trustline::shamap_key(&alice_id(), &carol_id(), &usd);
    let mut line = state.get_trustline(&alice_line_key).unwrap().clone();
    line.transfer(
        &carol_id(),
        &xrpl::transaction::amount::IouValue::from_f64(25.0),
    );
    state.insert_trustline(line);

    let check = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(25.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&check.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let cash = TxBuilder::check_cash()
        .account(&bob)
        .amount(iou_usd(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .check_id(check::shamap_key(&alice_id(), 2).0)
        .sign(&bob)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&cash.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEC_NO_LINE_INSUF_RESERVE);

    let bob_line_key = xrpl::ledger::trustline::shamap_key(&bob_id(), &carol_id(), &usd);
    assert!(state.get_trustline(&bob_line_key).is_none());
    assert!(state
        .get_check(&check::shamap_key(&alice_id(), 2))
        .is_some());
}

#[test]
fn check_rejects_mpt_amount_fields() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);
    let mptid = make_mptid(1, &alice_id());

    let create = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::from_mpt_value(10, mptid))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&create.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEM_BAD_AMOUNT);

    let check = TxBuilder::check_create()
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
        &parse_blob(&check.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let cash = TxBuilder::check_cash()
        .account(&bob)
        .amount(Amount::from_mpt_value(1, mptid))
        .fee(BASE_FEE)
        .sequence(1)
        .check_id(check::shamap_key(&alice_id(), 1).0)
        .sign(&bob)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&cash.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEM_MALFORMED);
}

#[test]
fn check_create_rejects_pseudo_destination_by_designator_field() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);

    let mut pseudo = state.get_account(&bob_id()).unwrap().clone();
    pseudo.sequence = 0;
    pseudo.flags = LSF_DISABLE_MASTER | LSF_DEFAULT_RIPPLE | LSF_DEPOSIT_AUTH;
    let mut raw = pseudo.encode();
    raw.push(0x5e); // sfAMMID = UINT256, field 14
    raw.extend_from_slice(&[4u8; 32]);
    pseudo.raw_sle = Some(raw);
    state.insert_account(pseudo);

    let signed = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(10 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEC_NO_PERMISSION);
}

#[test]
fn check_create_iou_does_not_require_issuer_account() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);
    let missing_issuer = [88u8; 20];

    let signed = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(10.0, missing_issuer))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success(), "check create failed: {}", r.ter);
    assert!(state
        .get_check(&check::shamap_key(&alice_id(), 1))
        .is_some());
}

#[test]
fn check_cash_iou_source_freeze_is_path_partial() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);
    fund(&mut state, &carol, 300);

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    let trust = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(100.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&trust.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let alice_line_key = xrpl::ledger::trustline::shamap_key(&alice_id(), &carol_id(), &usd);
    let mut line = state.get_trustline(&alice_line_key).unwrap().clone();
    line.transfer(
        &carol_id(),
        &xrpl::transaction::amount::IouValue::from_f64(25.0),
    );
    state.insert_trustline(line);

    let check = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&check.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let mut frozen_line = state.get_trustline(&alice_line_key).unwrap().clone();
    frozen_line.flags |= if carol_id() == frozen_line.low_account {
        LSF_LOW_FREEZE
    } else {
        LSF_HIGH_FREEZE
    };
    state.insert_trustline(frozen_line);

    let cash = TxBuilder::check_cash()
        .account(&bob)
        .amount(iou_usd(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .check_id(check::shamap_key(&alice_id(), 2).0)
        .sign(&bob)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&cash.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEC_PATH_PARTIAL);
    assert!(state
        .get_check(&check::shamap_key(&alice_id(), 2))
        .is_some());
}

#[test]
fn check_cash_iou_global_freeze_is_path_partial() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 300);
    fund(&mut state, &bob, 300);
    fund(&mut state, &carol, 300);

    let usd = xrpl::transaction::amount::Currency::from_code("USD").unwrap();
    let trust = TxBuilder::trust_set()
        .account(&alice)
        .limit_amount(iou_usd(100.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&trust.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let alice_line_key = xrpl::ledger::trustline::shamap_key(&alice_id(), &carol_id(), &usd);
    let mut line = state.get_trustline(&alice_line_key).unwrap().clone();
    line.transfer(
        &carol_id(),
        &xrpl::transaction::amount::IouValue::from_f64(25.0),
    );
    state.insert_trustline(line);

    let check = TxBuilder::check_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(iou_usd(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&check.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );

    let mut issuer = state.get_account(&carol_id()).unwrap().clone();
    issuer.flags |= LSF_GLOBAL_FREEZE;
    state.insert_account(issuer);

    let cash = TxBuilder::check_cash()
        .account(&bob)
        .amount(iou_usd(10.0, carol_id()))
        .fee(BASE_FEE)
        .sequence(1)
        .check_id(check::shamap_key(&alice_id(), 2).0)
        .sign(&bob)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&cash.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEC_PATH_PARTIAL);
    assert!(state
        .get_check(&check::shamap_key(&alice_id(), 2))
        .is_some());
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
fn paychan_create_preserves_tags_in_channel_sle() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let create = TxBuilder::paychan_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .source_tag(123)
        .destination_tag(456)
        .amount(Amount::Xrp(500 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .settle_delay(86400)
        .public_key_field(alice.public_key_bytes())
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&create.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success(), "paychan create failed: {}", r.ter);

    let chan_key = xrpl::ledger::paychan::shamap_key(&alice_id(), &bob_id(), 1);
    let pc = state.get_paychan(&chan_key).expect("channel exists");
    assert_eq!(pc.source_tag, Some(123));
    assert_eq!(pc.destination_tag, Some(456));

    let raw = state.get_raw(&chan_key).expect("channel raw exists");
    let parsed = xrpl::ledger::meta::parse_sle(raw).expect("PayChannel SLE parses");
    assert!(parsed.fields.iter().any(|f| f.type_code == 2
        && f.field_code == 3
        && u32::from_be_bytes(f.data.as_slice().try_into().unwrap()) == 123));
    assert!(parsed.fields.iter().any(|f| f.type_code == 2
        && f.field_code == 14
        && u32::from_be_bytes(f.data.as_slice().try_into().unwrap()) == 456));
}

#[test]
fn paychan_malformed_preflight_errors_do_not_claim_fee() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let bad_create_amount = parse_blob(
        &TxBuilder::paychan_create()
            .account(&alice)
            .destination(&bob_addr())
            .unwrap()
            .amount(iou_usd(1.0, carol_id()))
            .fee(0)
            .sequence(1)
            .settle_delay(86400)
            .public_key_field(alice.public_key_bytes())
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &bad_create_amount, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_BAD_AMOUNT);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(state.get_account(&alice_id()).unwrap().balance, 5_000 * XRP);

    let bad_fund_amount = parse_blob(
        &TxBuilder::paychan_fund()
            .account(&alice)
            .channel([0x55; 32])
            .amount(iou_usd(1.0, carol_id()))
            .fee(0)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &bad_fund_amount, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_BAD_AMOUNT);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(state.get_account(&alice_id()).unwrap().balance, 5_000 * XRP);

    let bad_claim_flags = parse_blob(
        &TxBuilder::paychan_claim()
            .account(&alice)
            .channel([0x66; 32])
            .flags(0x0004_0000)
            .fee(0)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &bad_claim_flags, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_INVALID_FLAG);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(state.get_account(&alice_id()).unwrap().balance, 5_000 * XRP);
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

#[test]
fn paychan_fund_missing_channel_is_tec_no_entry() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let missing = [0x77; 32];
    let signed = TxBuilder::paychan_fund()
        .account(&alice)
        .channel(missing)
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&signed.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEC_NO_ENTRY);
    assert!(r.applied);
}

#[test]
fn paychan_signed_claim_uses_balance_and_auth_amount() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let create = TxBuilder::paychan_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(500 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .settle_delay(86400)
        .public_key_field(alice.public_key_bytes())
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&create.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    let chan_key = xrpl::ledger::paychan::shamap_key(&alice_id(), &bob_id(), 1);

    let sig = paychan_claim_signature(&alice, chan_key.0, 300 * XRP);
    assert!(xrpl::ledger::paychan::verify_claim_with_public_key(
        &alice.public_key_bytes(),
        &chan_key.0,
        300 * XRP,
        &sig
    ));
    let claim = signed_paychan_claim(
        &bob,
        1,
        chan_key.0,
        0,
        Some(200 * XRP),
        Some(300 * XRP),
        Some(alice.public_key_bytes()),
        Some(sig),
    );
    assert!(xrpl::ledger::paychan::verify_claim_with_public_key(
        claim.public_key.as_ref().unwrap(),
        &chan_key.0,
        claim.amount_drops.unwrap(),
        claim.paychan_sig.as_ref().unwrap()
    ));
    assert!(state.get_paychan(&chan_key).unwrap().verify_claim(
        claim.amount_drops.unwrap(),
        claim.paychan_sig.as_ref().unwrap()
    ));
    let bob_before = state.get_account(&bob_id()).unwrap().balance;
    let r = run_tx(&mut state, &claim, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);

    assert_eq!(
        state.get_account(&bob_id()).unwrap().balance,
        bob_before - BASE_FEE + 200 * XRP
    );
    assert_eq!(state.get_paychan(&chan_key).unwrap().balance, 200 * XRP);
}

#[test]
fn paychan_claim_flags_close_and_renew_match_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let create = TxBuilder::paychan_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(500 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .settle_delay(60)
        .public_key_field(alice.public_key_bytes())
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&create.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    let chan_key = xrpl::ledger::paychan::shamap_key(&alice_id(), &bob_id(), 1);

    let close = signed_paychan_claim(
        &alice,
        2,
        chan_key.0,
        TF_PAYCHAN_CLOSE,
        None,
        None,
        None,
        None,
    );
    let r = run_tx(&mut state, &close, &pctx(200), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert_eq!(state.get_paychan(&chan_key).unwrap().expiration, 260);

    let renew = signed_paychan_claim(
        &alice,
        3,
        chan_key.0,
        TF_PAYCHAN_RENEW,
        None,
        None,
        None,
        None,
    );
    let r = run_tx(&mut state, &renew, &pctx(201), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert_eq!(state.get_paychan(&chan_key).unwrap().expiration, 0);

    let bad_flags = signed_paychan_claim(
        &alice,
        4,
        chan_key.0,
        TF_PAYCHAN_RENEW | TF_PAYCHAN_CLOSE,
        None,
        None,
        None,
        None,
    );
    let r = run_tx(&mut state, &bad_flags, &pctx(202), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_MALFORMED);
}

#[test]
fn paychan_receiver_close_deletes_immediately_and_refunds_source() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let create = TxBuilder::paychan_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(500 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .settle_delay(86400)
        .public_key_field(alice.public_key_bytes())
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&create.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    let chan_key = xrpl::ledger::paychan::shamap_key(&alice_id(), &bob_id(), 1);
    let alice_after_create = state.get_account(&alice_id()).unwrap().balance;

    let close = signed_paychan_claim(
        &bob,
        1,
        chan_key.0,
        TF_PAYCHAN_CLOSE,
        None,
        None,
        None,
        None,
    );
    let r = run_tx(&mut state, &close, &pctx(101), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert!(state.get_paychan(&chan_key).is_none());
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        alice_after_create + 500 * XRP
    );
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}

#[test]
fn paychan_fund_expired_channel_closes_without_adding_funds() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let create = TxBuilder::paychan_create()
        .account(&alice)
        .destination(&bob_addr())
        .unwrap()
        .amount(Amount::Xrp(500 * XRP))
        .fee(BASE_FEE)
        .sequence(1)
        .settle_delay(60)
        .cancel_after(150)
        .public_key_field(alice.public_key_bytes())
        .sign(&alice)
        .unwrap();
    run_tx(
        &mut state,
        &parse_blob(&create.blob).unwrap(),
        &pctx(100),
        ApplyFlags::NONE,
    );
    let chan_key = xrpl::ledger::paychan::shamap_key(&alice_id(), &bob_id(), 1);
    let alice_after_create = state.get_account(&alice_id()).unwrap().balance;

    let fund_tx = TxBuilder::paychan_fund()
        .account(&alice)
        .channel(chan_key.0)
        .amount(Amount::Xrp(100 * XRP))
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let r = run_tx(
        &mut state,
        &parse_blob(&fund_tx.blob).unwrap(),
        &pctx(150),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert!(state.get_paychan(&chan_key).is_none());
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        alice_after_create - BASE_FEE + 500 * XRP
    );
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

fn sle_number_field(raw: &[u8], field_code: u16) -> i64 {
    let parsed = xrpl::ledger::meta::parse_sle(raw).expect("valid SLE");
    parsed
        .fields
        .iter()
        .find(|field| field.type_code == 9 && field.field_code == field_code)
        .map(|field| i64::from_be_bytes(field.data[..8].try_into().unwrap()))
        .unwrap_or(0)
}

fn sle_blob_field(raw: &[u8], field_code: u16) -> Option<Vec<u8>> {
    let parsed = xrpl::ledger::meta::parse_sle(raw)?;
    parsed
        .fields
        .iter()
        .find(|field| field.type_code == 7 && field.field_code == field_code)
        .map(|field| field.data.clone())
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

fn sle_u16_field(raw: &[u8], field_code: u16) -> u16 {
    let parsed = xrpl::ledger::meta::parse_sle(raw).expect("valid SLE");
    parsed
        .fields
        .iter()
        .find(|field| field.type_code == 1 && field.field_code == field_code)
        .map(|field| u16::from_be_bytes(field.data[..2].try_into().unwrap()))
        .unwrap_or(0)
}

fn sle_account_field(raw: &[u8], field_code: u16) -> Option<[u8; 20]> {
    let parsed = xrpl::ledger::meta::parse_sle(raw)?;
    parsed
        .fields
        .iter()
        .find(|field| field.type_code == 8 && field.field_code == field_code)
        .and_then(|field| field.data.as_slice().try_into().ok())
}

fn sle_u64_field(raw: &[u8], field_code: u16) -> Option<u64> {
    let parsed = xrpl::ledger::meta::parse_sle(raw)?;
    parsed
        .fields
        .iter()
        .find(|field| field.type_code == 3 && field.field_code == field_code)
        .map(|field| u64::from_be_bytes(field.data[..8].try_into().unwrap()))
}

fn sle_uint192_field(raw: &[u8], field_code: u16) -> Option<[u8; 24]> {
    let parsed = xrpl::ledger::meta::parse_sle(raw)?;
    parsed
        .fields
        .iter()
        .find(|field| field.type_code == 21 && field.field_code == field_code)
        .and_then(|field| field.data.as_slice().try_into().ok())
}

fn test_mptoken_sle(account: [u8; 20], mptid: [u8; 24], amount: u64) -> Vec<u8> {
    xrpl::ledger::meta::build_sle(
        0x007F,
        &[
            xrpl::ledger::meta::ParsedField {
                type_code: 8,
                field_code: 1,
                data: account.to_vec(),
            },
            xrpl::ledger::meta::ParsedField {
                type_code: 21,
                field_code: 1,
                data: mptid.to_vec(),
            },
            xrpl::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 26,
                data: amount.to_be_bytes().to_vec(),
            },
            xrpl::ledger::meta::ParsedField {
                type_code: 2,
                field_code: 2,
                data: 0u32.to_be_bytes().to_vec(),
            },
        ],
        None,
        None,
    )
}

#[test]
fn vault_create_basic() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = signed_vault_create(&alice, 1);
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
fn vault_set_assets_maximum_updates_vault() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let deposit_tx = signed_vault_deposit(&alice, 2, vkey.0, 100 * XRP);
    run_tx(&mut state, &deposit_tx, &pctx(100), ApplyFlags::NONE);

    let set_tx = signed_vault_set(&alice, 3, vkey.0, Some(150 * XRP as i64), None, None);
    let r = run_tx(&mut state, &set_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "vault set failed: {}", r.ter);

    let raw = state.get_raw(&vkey).expect("vault SLE exists");
    assert_eq!(sle_number_field(raw, 3), 150 * XRP as i64);
}

#[test]
fn vault_set_data_updates_vault() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let payload = b"vault metadata".to_vec();
    let set_tx = signed_vault_set(&alice, 2, vkey.0, None, Some(payload.clone()), None);
    let r = run_tx(&mut state, &set_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "vault data set failed: {}", r.ter);

    let raw = state.get_raw(&vkey).expect("vault SLE exists");
    assert_eq!(sle_blob_field(raw, 27), Some(payload));
}

#[test]
fn vault_set_assets_maximum_below_total_fails() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let deposit_tx = signed_vault_deposit(&alice, 2, vkey.0, 100 * XRP);
    run_tx(&mut state, &deposit_tx, &pctx(100), ApplyFlags::NONE);

    let set_tx = signed_vault_set(&alice, 3, vkey.0, Some(50 * XRP as i64), None, None);
    let r = run_tx(&mut state, &set_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_LIMIT_EXCEEDED,
        "expected tecLIMIT_EXCEEDED, got {}",
        r.ter
    );
}

#[test]
fn vault_set_no_update_is_malformed() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let set_tx = signed_vault_set(&alice, 2, vkey.0, None, None, None);
    let r = run_tx(&mut state, &set_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, xrpl::ledger::ter::TEM_MALFORMED);
}

#[test]
fn vault_set_empty_data_is_malformed() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let set_tx = signed_vault_set(&alice, 2, vkey.0, None, Some(Vec::new()), None);
    let r = run_tx(&mut state, &set_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, xrpl::ledger::ter::TEM_MALFORMED);
}

#[test]
fn vault_set_non_owner_fails() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let set_tx = signed_vault_set(&bob, 1, vkey.0, Some(150 * XRP as i64), None, None);
    let r = run_tx(&mut state, &set_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_NO_PERMISSION,
        "expected tecNO_PERMISSION, got {}",
        r.ter
    );
}

#[test]
fn vault_set_domain_requires_private_vault() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let set_tx = signed_vault_set(&alice, 2, vkey.0, None, None, Some([0u8; 32]));
    let r = run_tx(&mut state, &set_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_NO_PERMISSION,
        "expected public vault domain update to be rejected, got {}",
        r.ter
    );
}

#[test]
fn vault_delete_empty() {
    // Create a vault, then delete it. All objects removed, owner_count back to 0.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Create vault at sequence 1
    let create_tx = signed_vault_create(&alice, 1);
    let r = run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "vault create failed: {}", r.ter);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);

    let vkey = test_vault_key(&alice_id(), 1);
    assert!(state.get_raw(&vkey).is_some());

    // Delete vault at sequence 2
    let delete_tx = signed_vault_delete(&alice, 2, vkey.0);

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
    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let balance_after_create = state.get_account(&alice_id()).unwrap().balance;

    // Deposit 100 XRP
    let deposit_tx = signed_vault_deposit(&alice, 2, vkey.0, 100 * XRP);

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
    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    // Deposit 100 XRP
    let deposit_tx = signed_vault_deposit(&alice, 2, vkey.0, 100 * XRP);
    run_tx(&mut state, &deposit_tx, &pctx(100), ApplyFlags::NONE);

    let balance_after_deposit = state.get_account(&alice_id()).unwrap().balance;

    // Withdraw 100 XRP worth of shares (shares = drops at scale=0)
    let withdraw_tx = signed_vault_withdraw(&alice, 3, vkey.0, 100 * XRP);

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
    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    // Deposit 100 XRP
    let deposit_tx = signed_vault_deposit(&alice, 2, vkey.0, 100 * XRP);
    run_tx(&mut state, &deposit_tx, &pctx(100), ApplyFlags::NONE);

    // Try to delete — should fail (non-empty)
    let delete_tx = signed_vault_delete(&alice, 3, vkey.0);
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

    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    // First deposit: 100 XRP
    let d1 = signed_vault_deposit(&alice, 2, vkey.0, 100 * XRP);
    let r = run_tx(&mut state, &d1, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success());

    let balance_after_d1 = state.get_account(&alice_id()).unwrap().balance;

    // Second deposit: 50 XRP
    let d2 = signed_vault_deposit(&alice, 3, vkey.0, 50 * XRP);
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

    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let dep = signed_vault_deposit(&alice, 2, vkey.0, 200 * XRP);
    run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);

    let balance_after_dep = state.get_account(&alice_id()).unwrap().balance;

    // Withdraw 80 shares (= 80 XRP at 1:1 for first deposit)
    let wd = signed_vault_withdraw(&alice, 3, vkey.0, 80 * XRP);
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

    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let dep = signed_vault_deposit(&alice, 2, vkey.0, 100 * XRP);
    run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);

    // Try to withdraw 200 shares — only 100 exist
    let wd = signed_vault_withdraw(&alice, 3, vkey.0, 200 * XRP);
    let r = run_tx(&mut state, &wd, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tec_claim(), "expected tec failure, got {}", r.ter);
}

#[test]
fn vault_withdraw_to_empty_then_delete() {
    // Deposit 100, withdraw 100, then delete succeeds.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    // Deposit
    let dep = signed_vault_deposit(&alice, 2, vkey.0, 100 * XRP);
    run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);

    // Full withdraw
    let wd = signed_vault_withdraw(&alice, 3, vkey.0, 100 * XRP);
    let r = run_tx(&mut state, &wd, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "full withdraw failed: {}", r.ter);

    // Delete should now succeed
    let del = signed_vault_delete(&alice, 4, vkey.0);
    let r = run_tx(&mut state, &del, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "delete after full withdraw failed: {}",
        r.ter
    );

    assert!(state.get_raw(&vkey).is_none());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}

#[test]
fn vault_clawback_xrp_asset_matches_rippled_rejections() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let xrp_amount = signed_vault_clawback(&alice, 2, vkey.0, alice_id(), Some(Amount::Xrp(1)));
    let r = run_tx(&mut state, &xrp_amount, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_MALFORMED);

    let non_owner_default_asset = signed_vault_clawback(&bob, 1, vkey.0, alice_id(), None);
    let r = run_tx(
        &mut state,
        &non_owner_default_asset,
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TEC_NO_PERMISSION);
}

#[test]
fn vault_clawback_owner_burns_stale_shares_when_vault_has_no_assets() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create_tx = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_tx, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let dep = signed_vault_deposit(&alice, 2, vkey.0, 100 * XRP);
    run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);

    let vault_raw = state.get_raw(&vkey).expect("vault exists").to_vec();
    let share_mptid = sle_uint192_field(&vault_raw, 2).expect("vault share mptid");
    let issuance_key = mpt_issuance_key_for(&share_mptid);
    let holder_key = mpt_holder_key_for(&share_mptid, &alice_id());

    let stale_vault = xrpl::ledger::meta::patch_sle(
        &vault_raw,
        &[
            xrpl::ledger::meta::ParsedField {
                type_code: 9,
                field_code: 4,
                data: 0i64.to_be_bytes().to_vec(),
            },
            xrpl::ledger::meta::ParsedField {
                type_code: 9,
                field_code: 2,
                data: 0i64.to_be_bytes().to_vec(),
            },
        ],
        None,
        None,
        &[],
    );
    state.insert_raw(vkey, stale_vault);

    let clawback = signed_vault_clawback(&alice, 3, vkey.0, alice_id(), None);
    let r = run_tx(&mut state, &clawback, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "owner share clawback failed: {}",
        r.ter
    );

    assert_eq!(
        sle_u64(state.get_raw(&issuance_key).expect("issuance remains"), 25),
        0,
        "share issuance outstanding amount should be burned"
    );
    assert_eq!(
        sle_u64(state.get_raw(&holder_key).expect("owner token remains"), 26),
        0,
        "owner share MPToken should remain with zero balance"
    );
}

#[test]
fn vault_clawback_mpt_asset_recovers_assets_and_burns_proportional_shares() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);
    fund(&mut state, &carol, 5_000);

    let create_mpt = signed_mpt_create(&alice, 1, 0x0000_0040, Some(1_000), None, None, None);
    let r = run_tx(&mut state, &create_mpt, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "mpt create failed: {}", r.ter);
    let asset_mptid = make_mptid(1, &alice_id());

    let create_vault = signed_vault_create_with_asset(
        &carol,
        1,
        xrpl::transaction::amount::Issue::Mpt(asset_mptid),
    );
    let r = run_tx(&mut state, &create_vault, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "vault create failed: {}", r.ter);
    let vkey = test_vault_key(&carol_id(), 1);

    let vault_raw = state.get_raw(&vkey).expect("vault exists").to_vec();
    let pseudo = sle_account_field(&vault_raw, 1).expect("vault pseudo account");
    let share_mptid = sle_uint192_field(&vault_raw, 2).expect("vault share mptid");
    let share_issuance_key = mpt_issuance_key_for(&share_mptid);
    let bob_share_key = mpt_holder_key_for(&share_mptid, &bob_id());
    let pseudo_asset_key = mpt_holder_key_for(&asset_mptid, &pseudo);
    let asset_issuance_key = mpt_issuance_key_for(&asset_mptid);

    let funded_vault = xrpl::ledger::meta::patch_sle(
        &vault_raw,
        &[
            xrpl::ledger::meta::ParsedField {
                type_code: 9,
                field_code: 4,
                data: 200i64.to_be_bytes().to_vec(),
            },
            xrpl::ledger::meta::ParsedField {
                type_code: 9,
                field_code: 2,
                data: 200i64.to_be_bytes().to_vec(),
            },
        ],
        None,
        None,
        &[],
    );
    state.insert_raw(vkey, funded_vault);

    let share_issuance = state
        .get_raw(&share_issuance_key)
        .expect("share issuance exists")
        .to_vec();
    state.insert_raw(
        share_issuance_key,
        xrpl::ledger::meta::patch_sle(
            &share_issuance,
            &[xrpl::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 25,
                data: 100u64.to_be_bytes().to_vec(),
            }],
            None,
            None,
            &[],
        ),
    );
    state.insert_raw(bob_share_key, test_mptoken_sle(bob_id(), share_mptid, 50));
    state.insert_raw(pseudo_asset_key, test_mptoken_sle(pseudo, asset_mptid, 200));
    let asset_issuance = state
        .get_raw(&asset_issuance_key)
        .expect("asset issuance exists")
        .to_vec();
    state.insert_raw(
        asset_issuance_key,
        xrpl::ledger::meta::patch_sle(
            &asset_issuance,
            &[xrpl::ledger::meta::ParsedField {
                type_code: 3,
                field_code: 25,
                data: 200u64.to_be_bytes().to_vec(),
            }],
            None,
            None,
            &[],
        ),
    );

    let clawback = signed_vault_clawback(
        &alice,
        2,
        vkey.0,
        bob_id(),
        Some(Amount::from_mpt_value(40, asset_mptid)),
    );
    let r = run_tx(&mut state, &clawback, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "mpt asset vault clawback failed: {}",
        r.ter
    );

    let vault_raw = state.get_raw(&vkey).expect("vault remains");
    assert_eq!(sle_number_field(vault_raw, 4), 160);
    assert_eq!(sle_number_field(vault_raw, 2), 160);
    assert_eq!(
        sle_u64(state.get_raw(&share_issuance_key).unwrap(), 25),
        80,
        "share outstanding should decrease by the proportional burn"
    );
    assert_eq!(
        sle_u64(state.get_raw(&bob_share_key).unwrap(), 26),
        30,
        "holder keeps only unburned shares"
    );
    assert_eq!(
        sle_u64(state.get_raw(&pseudo_asset_key).unwrap(), 26),
        160,
        "vault pseudo-account asset balance should be debited"
    );
    assert_eq!(
        sle_u64(state.get_raw(&asset_issuance_key).unwrap(), 25),
        160,
        "MPT issuer clawback should reduce asset outstanding"
    );
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
    let create_vault = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_vault, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);

    // Create loan broker at seq=2, linked to vault
    let broker_tx = signed_loan_broker_set(&alice, 2, vkey.0);
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
    let create_vault = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_vault, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    // Create broker
    let broker_tx = signed_loan_broker_set(&alice, 2, vkey.0);
    run_tx(&mut state, &broker_tx, &pctx(100), ApplyFlags::NONE);
    let bkey = test_loan_broker_key(&alice_id(), 2);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 4);

    // Delete broker
    let delete_tx = signed_loan_broker_delete(&alice, 3, bkey.0);
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

    let broker_tx = signed_loan_broker_set(&kp_alice(), 1, [0xAA; 32]);
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
    let alice = kp_alice();
    let create_vault = signed_vault_create(&alice, 1);
    run_tx(state, &create_vault, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let dep = signed_vault_deposit(&alice, 2, vkey.0, 1_000 * XRP);
    run_tx(state, &dep, &pctx(100), ApplyFlags::NONE);

    let broker_tx = signed_loan_broker_set(&alice, 3, vkey.0);
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
    let create_vault = signed_vault_create(&alice, 1);
    run_tx(&mut state, &create_vault, &pctx(100), ApplyFlags::NONE);
    let vkey = test_vault_key(&alice_id(), 1);

    let dep = signed_vault_deposit(&alice, 2, vkey.0, 1_000 * XRP);
    run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);

    // Create broker linked to vault
    let broker_tx = signed_loan_broker_set(&alice, 3, vkey.0);
    run_tx(&mut state, &broker_tx, &pctx(100), ApplyFlags::NONE);
    let bkey = test_loan_broker_key(&alice_id(), 3);

    let bob_balance_before = state.get_account(&bob_id()).unwrap().balance;

    // Bob creates a loan for 100 XRP principal
    let loan_tx = signed_loan_set(&bob, 1, bkey.0, 100 * XRP);

    let r = run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "loan create failed: {}", r.ter);

    // Bob should have received 100 XRP
    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.balance, bob_balance_before + 100 * XRP - BASE_FEE);
    assert!(b.owner_count >= 1, "bob should own the loan");

    // Loan SLE should exist
    let lkey = test_loan_key(&bkey.0, 1); // first loan sequence = 1
    let loan_raw = state.get_raw(&lkey).expect("loan SLE should exist");
    assert_eq!(
        sle_account_field(loan_raw, 25),
        Some(bob_id()),
        "Loan must store canonical sfBorrower, not sfAccount"
    );
    assert!(
        sle_u64_field(loan_raw, 31).is_some(),
        "Loan must store sfLoanBrokerNode for broker pseudo directory removal"
    );
    assert_eq!(sle_u32_field(loan_raw, 54), 100);
    assert_eq!(sle_u32_field(loan_raw, 55), 60);
    assert_eq!(sle_u32_field(loan_raw, 56), 60);
    assert_eq!(sle_u32_field(loan_raw, 58), 160);
    assert_eq!(
        sle_u32_field(state.get_raw(&bkey).expect("broker exists"), 13),
        1,
        "LoanBroker sfOwnerCount tracks outstanding loans"
    );
}

#[test]
fn loan_signed_ids_parse_as_loan_fields_not_vault_id() {
    let alice = kp_alice();
    let broker_id = [0xB1; 32];
    let loan_id = [0x1A; 32];

    let set = signed_loan_set(&alice, 1, broker_id, 1);
    assert_eq!(set.loan_broker_id, Some(broker_id));
    assert_eq!(set.loan_id, None);
    assert_eq!(set.vault_id, None);

    let pay = signed_loan_pay(&alice, 2, loan_id, 1);
    assert_eq!(pay.loan_id, Some(loan_id));
    assert_eq!(pay.loan_broker_id, None);
    assert_eq!(pay.vault_id, None);
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
    let loan_tx = signed_loan_set(&bob, 1, bkey.0, 100 * XRP);
    run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    let lkey = test_loan_key(&bkey.0, 1);

    let bob_balance_after_loan = state.get_account(&bob_id()).unwrap().balance;

    // Bob repays 100 XRP
    let pay_tx = signed_loan_pay(&bob, 2, lkey.0, 100 * XRP);

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

    let loan_tx = signed_loan_set(&bob, 1, bkey.0, 200 * XRP);
    run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    let lkey = test_loan_key(&bkey.0, 1);

    let bob_balance = state.get_account(&bob_id()).unwrap().balance;

    // Repay 80 XRP
    let pay_tx = signed_loan_pay(&bob, 2, lkey.0, 80 * XRP);
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

    let loan_tx = signed_loan_set(&bob, 1, bkey.0, 100 * XRP);
    run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    let lkey = test_loan_key(&bkey.0, 1);

    // Try to repay 200 XRP (more than principal)
    let pay_tx = signed_loan_pay(&bob, 2, lkey.0, 200 * XRP);
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

    let loan_tx = signed_loan_set(&bob, 1, bkey.0, 100 * XRP);
    run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    let lkey = test_loan_key(&bkey.0, 1);

    // Try to delete active loan
    let del_tx = signed_loan_delete(&bob, 2, lkey.0);
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
    let loan_tx = signed_loan_set(&bob, 1, bkey.0, 100 * XRP);
    run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    let lkey = test_loan_key(&bkey.0, 1);

    assert!(state.get_account(&bob_id()).unwrap().owner_count >= 1);

    // Full repayment
    let pay_tx = signed_loan_pay(&bob, 2, lkey.0, 100 * XRP);
    run_tx(&mut state, &pay_tx, &pctx(100), ApplyFlags::NONE);

    // Delete loan
    let del_tx = signed_loan_delete(&bob, 3, lkey.0);
    let r = run_tx(&mut state, &del_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "loan delete failed: {}", r.ter);

    // Loan SLE gone
    assert!(state.get_raw(&lkey).is_none());

    // Bob's owner_count should have decreased
    let b = state.get_account(&bob_id()).unwrap();
    assert_eq!(b.owner_count, 0);
    assert_eq!(
        sle_u32_field(state.get_raw(&bkey).expect("broker remains"), 13),
        0,
        "LoanBroker sfOwnerCount is decremented when a loan is deleted"
    );
}

#[test]
fn loan_create_no_broker_fails() {
    // LoanSet without a valid broker → tecNO_ENTRY
    let mut state = LedgerState::new();
    let bob = kp_bob();
    fund(&mut state, &bob, 5_000);

    let loan_tx = signed_loan_set(&bob, 1, [0xBB; 32], 100 * XRP);

    let r = run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_NO_ENTRY,
        "expected tecNO_ENTRY, got {}",
        r.ter
    );
}

#[test]
fn loan_cover_deposit_and_withdraw_update_cover_pool() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let (_vkey, bkey) = setup_vault_and_broker(&mut state);

    let deposit = signed_loan_cover_deposit(&alice, 4, bkey.0, 50 * XRP);
    let r = run_tx(&mut state, &deposit, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "cover deposit failed: {}", r.ter);
    let broker_raw = state.get_raw(&bkey).expect("broker exists");
    assert_eq!(sle_number_field(broker_raw, 8), (50 * XRP) as i64);

    let withdraw = signed_loan_cover_withdraw(&alice, 5, bkey.0, 20 * XRP, None);
    let r = run_tx(&mut state, &withdraw, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "cover withdraw failed: {}", r.ter);
    let broker_raw = state.get_raw(&bkey).expect("broker exists");
    assert_eq!(sle_number_field(broker_raw, 8), (30 * XRP) as i64);
}

#[test]
fn loan_cover_only_broker_owner_can_move_cover() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 5_000);

    let (_vkey, bkey) = setup_vault_and_broker(&mut state);

    let deposit = signed_loan_cover_deposit(&bob, 1, bkey.0, 10 * XRP);
    let r = run_tx(&mut state, &deposit, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_PERMISSION);
}

#[test]
fn loan_cover_withdraw_rejects_more_than_available() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let (_vkey, bkey) = setup_vault_and_broker(&mut state);

    let deposit = signed_loan_cover_deposit(&alice, 4, bkey.0, 10 * XRP);
    run_tx(&mut state, &deposit, &pctx(100), ApplyFlags::NONE);

    let withdraw = signed_loan_cover_withdraw(&alice, 5, bkey.0, 11 * XRP, None);
    let r = run_tx(&mut state, &withdraw, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_INSUFFICIENT_FUNDS);
}

#[test]
fn loan_cover_clawback_xrp_matches_rippled_rejections() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let (_vkey, bkey) = setup_vault_and_broker(&mut state);

    let no_amount = signed_loan_cover_clawback(&alice, 4, Some(bkey.0), None);
    let r = run_tx(&mut state, &no_amount, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_PERMISSION);

    let xrp_amount = signed_loan_cover_clawback(&alice, 5, Some(bkey.0), Some(1));
    let r = run_tx(&mut state, &xrp_amount, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_BAD_AMOUNT);
}

#[test]
fn loan_manage_impair_unimpair_and_default_follow_rippled_state_transitions() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 5_000);

    let (vkey, bkey) = setup_vault_and_broker(&mut state);
    let loan_tx = signed_loan_set(&bob, 1, bkey.0, 100 * XRP);
    run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    let lkey = test_loan_key(&bkey.0, 1);

    let impair = signed_loan_manage(&alice, 4, lkey.0, TF_LOAN_IMPAIR);
    let r = run_tx(&mut state, &impair, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "impair failed: {}", r.ter);
    assert_eq!(
        sle_flags(state.get_raw(&lkey).expect("loan exists")) & LSF_LOAN_IMPAIRED,
        LSF_LOAN_IMPAIRED
    );
    assert_eq!(
        sle_number_field(state.get_raw(&vkey).expect("vault exists"), 5),
        (100 * XRP) as i64
    );

    let duplicate_impair = signed_loan_manage(&alice, 5, lkey.0, TF_LOAN_IMPAIR);
    let r = run_tx(&mut state, &duplicate_impair, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_PERMISSION);

    let unimpair = signed_loan_manage(&alice, 6, lkey.0, TF_LOAN_UNIMPAIR);
    let r = run_tx(&mut state, &unimpair, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "unimpair failed: {}", r.ter);
    assert_eq!(
        sle_flags(state.get_raw(&lkey).expect("loan exists")) & LSF_LOAN_IMPAIRED,
        0
    );
    assert_eq!(
        sle_number_field(state.get_raw(&vkey).expect("vault exists"), 5),
        0
    );

    let too_soon = signed_loan_manage(&alice, 7, lkey.0, TF_LOAN_DEFAULT);
    let r = run_tx(&mut state, &too_soon, &pctx(0), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_TOO_SOON);

    let default = signed_loan_manage(&alice, 8, lkey.0, TF_LOAN_DEFAULT);
    let r = run_tx(&mut state, &default, &pctx(221), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "default failed: {}", r.ter);
    let loan_raw = state.get_raw(&lkey).expect("defaulted loan remains");
    assert_eq!(sle_flags(loan_raw) & LSF_LOAN_DEFAULT, LSF_LOAN_DEFAULT);
    assert_eq!(sle_number_field(loan_raw, 13), 0);
    assert_eq!(sle_number_field(loan_raw, 15), 0);
}

#[test]
fn loan_manage_only_broker_owner_can_manage() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 5_000);

    let (_vkey, bkey) = setup_vault_and_broker(&mut state);
    let loan_tx = signed_loan_set(&bob, 1, bkey.0, 100 * XRP);
    run_tx(&mut state, &loan_tx, &pctx(100), ApplyFlags::NONE);
    let lkey = test_loan_key(&bkey.0, 1);

    let manage = signed_loan_manage(&bob, 2, lkey.0, TF_LOAN_IMPAIR);
    let r = run_tx(&mut state, &manage, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_PERMISSION);
}

// ── Oracle parity ────────────────────────────────────────────────────────────

fn oracle_currency(code: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    let bytes = code.as_bytes();
    out[12..12 + bytes.len()].copy_from_slice(bytes);
    out
}

fn oracle_price_entry(base: [u8; 20], quote: [u8; 20], price: Option<u64>) -> Vec<u8> {
    let mut raw = Vec::new();
    xrpl::ledger::meta::write_field_header_pub(&mut raw, 14, 32);
    if let Some(price) = price {
        xrpl::ledger::meta::write_field_header_pub(&mut raw, 3, 23);
        raw.extend_from_slice(&price.to_be_bytes());
        xrpl::ledger::meta::write_field_header_pub(&mut raw, 16, 4);
        raw.push(0);
    }
    xrpl::ledger::meta::write_field_header_pub(&mut raw, 17, 1);
    raw.extend_from_slice(&base);
    xrpl::ledger::meta::write_field_header_pub(&mut raw, 17, 2);
    raw.extend_from_slice(&quote);
    xrpl::ledger::meta::write_field_header_pub(&mut raw, 14, 1);
    raw
}

fn oracle_price_series(entries: Vec<Vec<u8>>) -> Vec<u8> {
    let mut raw = Vec::new();
    for entry in entries {
        raw.extend_from_slice(&entry);
    }
    xrpl::ledger::meta::write_field_header_pub(&mut raw, 15, 1);
    raw
}

fn enable_amendment_name(state: &mut LedgerState, name: &str) {
    state.enable_amendment(xrpl::crypto::sha512_first_half(name.as_bytes()));
}

fn oracle_sle_field(raw: &[u8], type_code: u16, field_code: u16) -> Option<Vec<u8>> {
    xrpl::ledger::meta::parse_sle(raw).and_then(|sle| {
        sle.fields
            .into_iter()
            .find(|field| field.type_code == type_code && field.field_code == field_code)
            .map(|field| field.data)
    })
}

fn oracle_read_field_header(data: &[u8], pos: usize) -> (u16, u16, usize) {
    let b = data[pos];
    let mut type_code = (b >> 4) as u16;
    let mut field_code = (b & 0x0f) as u16;
    let mut pos = pos + 1;
    if type_code == 0 {
        type_code = data[pos] as u16;
        pos += 1;
    }
    if field_code == 0 {
        field_code = data[pos] as u16;
        pos += 1;
    }
    (type_code, field_code, pos)
}

fn oracle_skip_field_raw(_data: &[u8], pos: usize, type_code: u16) -> usize {
    match type_code {
        3 => pos + 8,
        14 => pos,
        16 => pos + 1,
        17 => pos + 20,
        _ => panic!("unexpected Oracle test field type {type_code}"),
    }
}

fn oracle_series_quote_codes(raw: &[u8]) -> Vec<String> {
    let series = oracle_sle_field(raw, 15, 24).expect("Oracle SLE has PriceDataSeries");
    let mut pos = 0usize;
    let mut codes = Vec::new();

    while pos < series.len() && series[pos] != 0xF1 {
        let (type_code, field_code, new_pos) = oracle_read_field_header(&series, pos);
        assert_eq!((type_code, field_code), (14, 32));
        pos = new_pos;

        let mut quote = None;
        while pos < series.len() && series[pos] != 0xE1 {
            let (inner_type, inner_field, inner_pos) = oracle_read_field_header(&series, pos);
            pos = inner_pos;
            let next = oracle_skip_field_raw(&series, pos, inner_type);
            if (inner_type, inner_field) == (17, 2) {
                quote = Some(series[pos..next].to_vec());
            }
            pos = next;
        }
        assert_eq!(series[pos], 0xE1);
        pos += 1;

        let quote = quote.expect("PriceData has QuoteAsset");
        let code_bytes: Vec<u8> = quote[12..]
            .iter()
            .copied()
            .filter(|byte| *byte != 0)
            .collect();
        codes.push(String::from_utf8(code_bytes).expect("ASCII test currency"));
    }

    codes
}

fn signed_oracle_set(
    account: &KeyPair,
    seq: u32,
    document_id: u32,
    last_update_time: u32,
    series: Vec<u8>,
) -> ParsedTx {
    let signed = TxBuilder::oracle_set()
        .account(account)
        .oracle_document_id(document_id)
        .oracle_last_update_time(last_update_time)
        .oracle_price_data_series_raw(series)
        .oracle_provider(b"xledgrs".to_vec())
        .oracle_asset_class(b"currency".to_vec())
        .uri(b"https://oracle.example".to_vec())
        .fee(BASE_FEE)
        .sequence(seq)
        .sign(account)
        .unwrap();
    parse_blob(&signed.blob).unwrap()
}

fn signed_oracle_delete(account: &KeyPair, seq: u32, document_id: u32) -> ParsedTx {
    let signed = TxBuilder::oracle_delete()
        .account(account)
        .oracle_document_id(document_id)
        .fee(BASE_FEE)
        .sequence(seq)
        .sign(account)
        .unwrap();
    parse_blob(&signed.blob).unwrap()
}

fn oracle_state_committed_after_create(
    document_id: u32,
) -> (std::sync::Arc<MemNodeStore>, [u8; 32]) {
    let backend = std::sync::Arc::new(MemNodeStore::new());
    let mut state = LedgerState::new();
    state.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend.clone()));
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let xrp = [0u8; 20];
    let usd = oracle_currency("USD");
    let create = signed_oracle_set(
        &alice,
        1,
        document_id,
        946_684_900,
        oracle_price_series(vec![oracle_price_entry(xrp, usd, Some(100))]),
    );
    let result = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TES_SUCCESS);
    state.flush_nudb().unwrap();
    let root = state.nudb_root_hash().unwrap();

    (backend, root)
}

#[test]
fn oracle_create_sle_respects_pre_fix_amendment_history() {
    let mut state = LedgerState::new();
    enable_amendment_name(&mut state, "PriceOracle");
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let xrp = [0u8; 20];
    let usd = oracle_currency("USD");
    let eur = oracle_currency("EUR");
    let document_id = 91;
    let close_time = 100;
    let last_update = 946_684_800 + close_time;
    let key = xrpl::ledger::keylet::oracle(&alice_id(), document_id).key;
    let unsorted = oracle_price_series(vec![
        oracle_price_entry(xrp, usd, Some(100)),
        oracle_price_entry(xrp, eur, Some(200)),
    ]);

    let create = signed_oracle_set(&alice, 1, document_id, last_update as u32, unsorted.clone());
    let result = run_tx(&mut state, &create, &pctx(close_time), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TES_SUCCESS);
    let raw = state.get_raw_owned(&key).expect("Oracle SLE exists");
    assert!(
        oracle_sle_field(&raw, 2, 51).is_none(),
        "pre-fixIncludeKeyletFields Oracle SLE omits OracleDocumentID"
    );
    assert_eq!(oracle_series_quote_codes(&raw), ["USD", "EUR"]);

    let update = signed_oracle_set(
        &alice,
        2,
        document_id,
        (last_update + 1) as u32,
        unsorted.clone(),
    );
    let result = run_tx(&mut state, &update, &pctx(close_time + 1), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TES_SUCCESS);
    let raw = state.get_raw_owned(&key).expect("Oracle SLE exists");
    assert_eq!(
        oracle_series_quote_codes(&raw),
        ["EUR", "USD"],
        "rippled update path sorts existing Oracle series even before PriceOracleOrder"
    );
    assert!(oracle_sle_field(&raw, 2, 51).is_none());

    enable_amendment_name(&mut state, "fixIncludeKeyletFields");
    let update = signed_oracle_set(&alice, 3, document_id, (last_update + 2) as u32, unsorted);
    let result = run_tx(&mut state, &update, &pctx(close_time + 2), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TES_SUCCESS);
    let raw = state.get_raw_owned(&key).expect("Oracle SLE exists");
    assert_eq!(
        oracle_sle_field(&raw, 2, 51).expect("OracleDocumentID backfilled"),
        document_id.to_be_bytes()
    );
}

#[test]
fn oracle_create_sle_respects_post_fix_amendment_history() {
    let mut state = LedgerState::new();
    enable_amendment_name(&mut state, "PriceOracle");
    enable_amendment_name(&mut state, "fixPriceOracleOrder");
    enable_amendment_name(&mut state, "fixIncludeKeyletFields");
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let xrp = [0u8; 20];
    let usd = oracle_currency("USD");
    let eur = oracle_currency("EUR");
    let document_id = 92;
    let close_time = 100;
    let last_update = 946_684_800 + close_time;
    let key = xrpl::ledger::keylet::oracle(&alice_id(), document_id).key;

    let create = signed_oracle_set(
        &alice,
        1,
        document_id,
        last_update as u32,
        oracle_price_series(vec![
            oracle_price_entry(xrp, usd, Some(100)),
            oracle_price_entry(xrp, eur, Some(200)),
        ]),
    );
    let result = run_tx(&mut state, &create, &pctx(close_time), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TES_SUCCESS);

    let raw = state.get_raw_owned(&key).expect("Oracle SLE exists");
    assert_eq!(
        oracle_sle_field(&raw, 2, 51).expect("OracleDocumentID present"),
        document_id.to_be_bytes()
    );
    assert_eq!(oracle_series_quote_codes(&raw), ["EUR", "USD"]);
}

#[test]
fn oracle_set_update_delete_matches_rippled_lifecycle_and_reserve_slots() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let xrp = [0u8; 20];
    let usd = oracle_currency("USD");
    let eur = oracle_currency("EUR");
    let document_id = 7;
    let close_time = 100;
    let last_update = 946_684_800 + close_time;
    let key = xrpl::ledger::keylet::oracle(&alice_id(), document_id).key;

    let create = signed_oracle_set(
        &alice,
        1,
        document_id,
        last_update as u32,
        oracle_price_series(vec![oracle_price_entry(xrp, usd, Some(100))]),
    );
    let result = run_tx(&mut state, &create, &pctx(close_time), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TES_SUCCESS);
    assert!(state.get_raw_owned(&key).is_some());
    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.sequence, 2);
    assert_eq!(account.owner_count, 1);

    let update = TxBuilder::oracle_set()
        .account(&alice)
        .oracle_document_id(document_id)
        .oracle_last_update_time((last_update + 1) as u32)
        .oracle_price_data_series_raw(oracle_price_series(vec![
            oracle_price_entry(xrp, usd, Some(125)),
            oracle_price_entry(xrp, eur, Some(200)),
        ]))
        .uri(b"https://oracle.example/updated".to_vec())
        .fee(BASE_FEE)
        .sequence(2)
        .sign(&alice)
        .unwrap();
    let result = run_tx(
        &mut state,
        &parse_blob(&update.blob).unwrap(),
        &pctx(close_time + 1),
        ApplyFlags::NONE,
    );
    assert_eq!(result.ter, ter::TES_SUCCESS);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);

    let mut six_entries = Vec::new();
    for (idx, code) in ["USD", "EUR", "JPY", "GBP", "CAD", "AUD"]
        .into_iter()
        .enumerate()
    {
        six_entries.push(oracle_price_entry(
            xrp,
            oracle_currency(code),
            Some(100 + idx as u64),
        ));
    }
    let expand = TxBuilder::oracle_set()
        .account(&alice)
        .oracle_document_id(document_id)
        .oracle_last_update_time((last_update + 2) as u32)
        .oracle_price_data_series_raw(oracle_price_series(six_entries))
        .fee(BASE_FEE)
        .sequence(3)
        .sign(&alice)
        .unwrap();
    let result = run_tx(
        &mut state,
        &parse_blob(&expand.blob).unwrap(),
        &pctx(close_time + 2),
        ApplyFlags::NONE,
    );
    assert_eq!(result.ter, ter::TES_SUCCESS);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);

    let delete = signed_oracle_delete(&alice, 4, document_id);
    let result = run_tx(&mut state, &delete, &pctx(close_time + 3), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TES_SUCCESS);
    assert!(state.get_raw_owned(&key).is_none());
    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.sequence, 5);
    assert_eq!(account.owner_count, 0);
}

#[test]
fn oracle_set_updates_committed_only_oracle_sle() {
    let document_id = 77;
    let (backend, root) = oracle_state_committed_after_create(document_id);
    let alice = kp_alice();
    let key = xrpl::ledger::keylet::oracle(&alice_id(), document_id).key;

    let mut state = LedgerState::new();
    state.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend));
    assert!(state.load_nudb_root(root).unwrap());
    enable_parity_amendments(&mut state);
    assert!(
        state.get_raw(&key).is_none(),
        "oracle must be absent from the in-memory raw overlay"
    );
    assert!(
        state.get_raw_owned(&key).is_some(),
        "oracle must be visible through the committed raw SHAMap"
    );

    let xrp = [0u8; 20];
    let usd = oracle_currency("USD");
    let update = signed_oracle_set(
        &alice,
        2,
        document_id,
        946_684_901,
        oracle_price_series(vec![oracle_price_entry(xrp, usd, Some(125))]),
    );
    let result = run_tx(&mut state, &update, &pctx(101), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TES_SUCCESS);
    assert!(result.applied);

    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.sequence, 3);
    assert_eq!(account.owner_count, 1);
    let raw = state.get_raw_owned(&key).unwrap();
    let series = xrpl::ledger::meta::parse_sle(&raw)
        .unwrap()
        .fields
        .into_iter()
        .find(|field| field.type_code == 15 && field.field_code == 24)
        .unwrap()
        .data;
    assert!(series
        .windows(8)
        .any(|window| window == 125u64.to_be_bytes()));
}

#[test]
fn oracle_delete_removes_committed_only_oracle_sle() {
    let document_id = 78;
    let (backend, root) = oracle_state_committed_after_create(document_id);
    let alice = kp_alice();
    let key = xrpl::ledger::keylet::oracle(&alice_id(), document_id).key;

    let mut state = LedgerState::new();
    state.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend));
    assert!(state.load_nudb_root(root).unwrap());
    enable_parity_amendments(&mut state);
    assert!(state.get_raw(&key).is_none());
    assert!(state.get_raw_owned(&key).is_some());

    let delete = signed_oracle_delete(&alice, 2, document_id);
    let result = run_tx(&mut state, &delete, &pctx(101), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TES_SUCCESS);
    assert!(result.applied);
    assert!(state.get_raw_owned(&key).is_none());
    assert!(state.get_committed_raw_owned(&key).is_none());

    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.sequence, 3);
    assert_eq!(account.owner_count, 0);
}

#[test]
fn oracle_malformed_preflight_errors_do_not_claim_fee_or_sequence() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let xrp = [0u8; 20];
    let usd = oracle_currency("USD");
    let mut eleven_entries = Vec::new();
    for idx in 1..=11 {
        let mut quote = [0u8; 20];
        quote[19] = idx;
        eleven_entries.push(oracle_price_entry(xrp, quote, Some(100 + idx as u64)));
    }

    let cases = [
        (
            TxBuilder::oracle_set()
                .account(&alice)
                .oracle_document_id(1)
                .oracle_last_update_time(946_684_900)
                .oracle_price_data_series_raw(oracle_price_series(Vec::new()))
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_ARRAY_EMPTY,
        ),
        (
            TxBuilder::oracle_set()
                .account(&alice)
                .oracle_document_id(1)
                .oracle_last_update_time(946_684_900)
                .oracle_price_data_series_raw(oracle_price_series(eleven_entries))
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_ARRAY_TOO_LARGE,
        ),
        (
            TxBuilder::oracle_set()
                .account(&alice)
                .oracle_document_id(1)
                .oracle_last_update_time(946_684_900)
                .oracle_price_data_series_raw(oracle_price_series(vec![oracle_price_entry(
                    xrp,
                    usd,
                    Some(100),
                )]))
                .oracle_provider(Vec::new())
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_MALFORMED,
        ),
        (
            TxBuilder::oracle_set()
                .account(&alice)
                .oracle_document_id(1)
                .oracle_last_update_time(946_684_900)
                .oracle_price_data_series_raw(oracle_price_series(vec![oracle_price_entry(
                    xrp,
                    usd,
                    Some(100),
                )]))
                .flags(0x0001_0000)
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_INVALID_FLAG,
        ),
        (
            TxBuilder::oracle_delete()
                .account(&alice)
                .fee(BASE_FEE)
                .sequence(1)
                .sign(&alice)
                .unwrap()
                .blob,
            ter::TEM_MALFORMED,
        ),
    ];

    for (blob, expected) in cases {
        let result = run_tx(
            &mut state,
            &parse_blob(&blob).unwrap(),
            &pctx(100),
            ApplyFlags::NONE,
        );
        assert_eq!(result.ter, expected);
        assert!(!result.applied);
        let account = state.get_account(&alice_id()).unwrap();
        assert_eq!(account.sequence, 1);
        assert_eq!(account.balance, 5_000 * XRP);
        assert_eq!(account.owner_count, 0);
    }
}

#[test]
fn oracle_stateful_failures_claim_fee_like_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let xrp = [0u8; 20];
    let usd = oracle_currency("USD");
    let document_id = 8;
    let close_time = 100;
    let last_update = 946_684_800 + close_time;

    let create = signed_oracle_set(
        &alice,
        1,
        document_id,
        last_update as u32,
        oracle_price_series(vec![oracle_price_entry(xrp, usd, Some(100))]),
    );
    assert_eq!(
        run_tx(&mut state, &create, &pctx(close_time), ApplyFlags::NONE).ter,
        ter::TES_SUCCESS
    );

    let stale = signed_oracle_set(
        &alice,
        2,
        document_id,
        last_update as u32,
        oracle_price_series(vec![oracle_price_entry(xrp, usd, Some(125))]),
    );
    let result = run_tx(&mut state, &stale, &pctx(close_time + 1), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::TEC_INVALID_UPDATE_TIME);
    assert!(result.applied);
    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.sequence, 3);
    assert_eq!(account.balance, 5_000 * XRP - 2 * BASE_FEE);
    assert_eq!(account.owner_count, 1);

    let missing_delete = signed_oracle_delete(&alice, 3, 999);
    let result = run_tx(
        &mut state,
        &missing_delete,
        &pctx(close_time + 2),
        ApplyFlags::NONE,
    );
    assert_eq!(result.ter, ter::TEC_NO_ENTRY);
    assert!(result.applied);
    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.sequence, 4);
    assert_eq!(account.balance, 5_000 * XRP - 3 * BASE_FEE);
    assert_eq!(account.owner_count, 1);
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

fn amm_test_pair() -> (
    xrpl::transaction::amount::Issue,
    xrpl::transaction::amount::Issue,
) {
    use xrpl::transaction::amount::{Currency, Issue};

    (
        Issue::Xrp,
        Issue::Iou {
            currency: Currency::from_code("USD").unwrap(),
            issuer: bob_id(),
        },
    )
}

fn amm_iou_amount(units: u64) -> Amount {
    use xrpl::transaction::amount::{Currency, IouValue};

    Amount::Iou {
        value: IouValue::from_f64(units as f64),
        currency: Currency::from_code("USD").unwrap(),
        issuer: bob_id(),
    }
}

fn issue_usd_to_alice(state: &mut LedgerState, units: u64) {
    use xrpl::ledger::RippleState;
    use xrpl::transaction::amount::{Currency, IouValue};

    let currency = Currency::from_code("USD").unwrap();
    let mut line = RippleState::new(&alice_id(), &bob_id(), currency);
    let value = IouValue::from_f64(units as f64);
    line.balance = if line.low_account == alice_id() {
        value
    } else {
        IouValue {
            mantissa: -value.mantissa,
            exponent: value.exponent,
        }
    };
    state.insert_trustline(line);
}

fn amm_create_tx(kp: &KeyPair, seq: u32, xrp_drops: u64) -> ParsedTx {
    signed_amm_create(
        kp,
        seq,
        Amount::Xrp(xrp_drops),
        amm_iou_amount(xrp_drops),
        0,
    )
}

fn amm_deposit_tx(kp: &KeyPair, seq: u32, xrp_drops: u64) -> ParsedTx {
    let (xrp, usd) = amm_test_pair();
    signed_amm_deposit(
        kp,
        seq,
        xrp,
        usd,
        Amount::Xrp(xrp_drops),
        amm_iou_amount(xrp_drops),
    )
}

fn amm_lp_token_amount(
    state: &LedgerState,
    asset: &xrpl::transaction::amount::Issue,
    asset2: &xrpl::transaction::amount::Issue,
    units: u64,
) -> Amount {
    use xrpl::transaction::amount::IouValue;

    let raw = state
        .get_raw(&test_amm_key(asset, asset2))
        .expect("AMM SLE exists");
    let parsed = xrpl::ledger::meta::parse_sle(raw).expect("AMM SLE parses");
    let lp_token_balance = parsed
        .fields
        .iter()
        .find(|field| field.type_code == 6 && field.field_code == 31)
        .expect("sfLPTokenBalance exists");
    match Amount::from_bytes(&lp_token_balance.data)
        .expect("LP token amount parses")
        .0
    {
        Amount::Iou {
            currency, issuer, ..
        } => Amount::Iou {
            value: IouValue::from_f64(units as f64),
            currency,
            issuer,
        },
        _ => panic!("LP token balance must be an IOU amount"),
    }
}

#[test]
fn amm_create_basic() {
    // AMMCreate with XRP + USD(bob) → tesSUCCESS
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);
    enable_default_ripple(&mut state, bob_id());
    issue_usd_to_alice(&mut state, 1_000 * XRP);

    let (xrp_issue, usd_issue) = amm_test_pair();
    let tx = amm_create_tx(&alice, 1, 100 * XRP);

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
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 10_000);

    let tx = signed_amm_create(&alice, 1, Amount::Xrp(1), Amount::Xrp(1), 0);

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tec_claim() || r.ter.token().contains("BAD_AMM"),
        "expected failure for same asset pair, got {}",
        r.ter
    );
}

#[test]
fn amm_create_duplicate_fails() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);
    enable_default_ripple(&mut state, bob_id());
    issue_usd_to_alice(&mut state, 1_000 * XRP);

    // First create succeeds
    let tx = amm_create_tx(&alice, 1, 100 * XRP);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    // Second create with same pair → tecDUPLICATE
    let tx2 = amm_create_tx(&alice, 2, 100 * XRP);
    let r = run_tx(&mut state, &tx2, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_DUPLICATE,
        "expected tecDUPLICATE, got {}",
        r.ter
    );
}

#[test]
fn amm_create_requires_lp_token_trustline_reserve() {
    use xrpl::transaction::amount::{Currency, IouValue};

    let mut state = LedgerState::new();
    enable_parity_amendments(&mut state);
    let mut alice = make_account(alice_id(), 1_200_000);
    alice.flags |= LSF_DEFAULT_RIPPLE;
    state.insert_account(alice);

    let usd = Currency::from_code("USD").unwrap();
    let tx = signed_amm_create(
        &kp_alice(),
        1,
        Amount::Xrp(1),
        Amount::Iou {
            value: IouValue::from_f64(1.0),
            currency: usd,
            issuer: alice_id(),
        },
        0,
    );

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        ter::TEC_INSUF_RESERVE_LINE,
        "AMMCreate must reserve space for the LP-token trustline"
    );
}

#[test]
fn amm_create_requires_owner_reserve_fee() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);
    enable_default_ripple(&mut state, bob_id());
    issue_usd_to_alice(&mut state, 1_000 * XRP);

    let tx = parse_blob(
        &TxBuilder::amm_create()
            .account(&alice)
            .amount(Amount::Xrp(100 * XRP))
            .amount2(amm_iou_amount(100 * XRP))
            .trading_fee(0)
            .fee(OWNER_RESERVE_FEE - 1)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEL_INSUF_FEE_P);
    let (xrp, usd) = amm_test_pair();
    assert!(state.get_raw(&test_amm_key(&xrp, &usd)).is_none());
}

#[test]
fn amm_delete_empty() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);
    enable_default_ripple(&mut state, bob_id());
    issue_usd_to_alice(&mut state, 1_000 * XRP);

    let (xrp, usd) = amm_test_pair();

    // Create AMM
    let tx = amm_create_tx(&alice, 1, 100 * XRP);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let akey = test_amm_key(&xrp, &usd);
    assert!(state.get_raw(&akey).is_some());

    // Emptying the pool deletes the AMM account/SLE during AMMWithdraw,
    // matching rippled's deleteAMMAccountIfEmpty path.
    let lp = amm_lp_token_amount(&state, &xrp, &usd, 100 * XRP);
    let wd = signed_amm_withdraw_lp(&alice, 2, xrp.clone(), usd.clone(), lp);
    let r = run_tx(&mut state, &wd, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm withdraw failed: {}", r.ter);

    // AMM SLE should be gone
    assert!(state.get_raw(&akey).is_none(), "AMM SLE should be removed");

    // Owner count back to 0
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 0);
}

#[test]
fn amm_delete_nonempty_fails() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);
    enable_default_ripple(&mut state, bob_id());
    issue_usd_to_alice(&mut state, 1_000 * XRP);

    let (xrp, usd) = amm_test_pair();

    let create = amm_create_tx(&alice, 1, 100 * XRP);
    let r = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm create failed: {}", r.ter);

    let deposit = amm_deposit_tx(&alice, 2, 100 * XRP);
    let r = run_tx(&mut state, &deposit, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm deposit failed: {}", r.ter);

    let akey = test_amm_key(&xrp, &usd);
    assert!(
        state.get_raw(&akey).is_some(),
        "AMM SLE should exist before delete"
    );

    let del = signed_amm_delete(&alice, 3, xrp.clone(), usd.clone());
    let r = run_tx(&mut state, &del, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        ter::TEC_AMM_NOT_EMPTY,
        "expected tecAMM_NOT_EMPTY, got {}",
        r.ter
    );

    assert!(
        state.get_raw(&akey).is_some(),
        "AMM SLE should remain after failed delete"
    );
}

#[test]
fn amm_vote_updates_weighted_fee_and_rejects_bad_pair() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);
    enable_default_ripple(&mut state, bob_id());
    issue_usd_to_alice(&mut state, 1_000 * XRP);

    let (xrp, usd) = amm_test_pair();
    let create = amm_create_tx(&alice, 1, 100 * XRP);
    let r = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm create failed: {}", r.ter);

    let vote = signed_amm_vote(&alice, 2, xrp.clone(), usd.clone(), 600);
    let r = run_tx(&mut state, &vote, &pctx(200), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm vote failed: {}", r.ter);

    let akey = test_amm_key(&xrp, &usd);
    let amm_raw = state.get_raw(&akey).expect("amm remains");
    assert_eq!(
        sle_u16_field(amm_raw, 5),
        600,
        "single LP vote should set weighted trading fee"
    );

    let bad_pair = signed_amm_vote(&alice, 3, xrp.clone(), xrp.clone(), 10);
    let r = run_tx(&mut state, &bad_pair, &pctx(300), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        ter::TEM_BAD_AMM_TOKENS,
        "AMMVote preflight should reject identical assets before AMM lookup"
    );

    let bad_fee = signed_amm_vote(&alice, 3, xrp.clone(), usd, 1001);
    let r = run_tx(&mut state, &bad_fee, &pctx(300), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        ter::TEM_BAD_FEE,
        "AMMVote should validate sfTradingFee before preclaim state lookup"
    );
}

#[test]
fn amm_bid_burns_min_price_and_zero_bid_is_bad_amount() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);
    enable_default_ripple(&mut state, bob_id());
    issue_usd_to_alice(&mut state, 1_000 * XRP);

    let (xrp, usd) = amm_test_pair();
    let zero_before_amm = signed_amm_bid(
        &alice,
        1,
        xrp.clone(),
        usd.clone(),
        Some(Amount::Xrp(0)),
        None,
    );
    let r = run_tx(&mut state, &zero_before_amm, &pctx(50), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        ter::TEM_BAD_AMOUNT,
        "AMMBid should validate malformed bid amounts before AMM lookup"
    );

    let create = signed_amm_create(
        &alice,
        1,
        Amount::Xrp(100 * XRP),
        amm_iou_amount(100 * XRP),
        500,
    );
    let r = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm create failed: {}", r.ter);

    let zero_bid = signed_amm_bid(
        &alice,
        2,
        xrp.clone(),
        usd.clone(),
        Some(amm_lp_token_amount(&state, &xrp, &usd, 0)),
        None,
    );
    let r = run_tx(&mut state, &zero_bid, &pctx(200), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        ter::TEM_BAD_AMOUNT,
        "AMMBid zero sfBidMin should follow invalidAMMAmount"
    );

    let bid = signed_amm_bid(&alice, 2, xrp.clone(), usd.clone(), None, None);
    let r = run_tx(&mut state, &bid, &pctx(200), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm bid failed: {}", r.ter);

    let akey = test_amm_key(&xrp, &usd);
    let amm_raw = state.get_raw(&akey).expect("amm remains");
    assert_eq!(
        sle_number_field(amm_raw, 12),
        100 * XRP as i64 - 20_000,
        "minimum slot bid should burn LP tokens from total supply"
    );
}

#[test]
fn amm_deposit_basic() {
    // Deposit XRP into AMM pool, LP tokens minted.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);
    enable_default_ripple(&mut state, bob_id());
    issue_usd_to_alice(&mut state, 1_000 * XRP);

    // Create AMM
    let tx = amm_create_tx(&alice, 1, 100 * XRP);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let balance_before = state.get_account(&alice_id()).unwrap().balance;

    // Deposit 100 XRP
    let dep = amm_deposit_tx(&alice, 2, 100 * XRP);

    let r = run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm deposit failed: {}", r.ter);

    // Alice lost 100 XRP + fee
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, balance_before - 100 * XRP - BASE_FEE);
}

#[test]
fn amm_withdraw_basic() {
    // Deposit then withdraw from AMM pool.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);
    enable_default_ripple(&mut state, bob_id());
    issue_usd_to_alice(&mut state, 1_000 * XRP);

    let (xrp, usd) = amm_test_pair();

    // Create + deposit
    let tx = amm_create_tx(&alice, 1, 100 * XRP);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let dep = amm_deposit_tx(&alice, 2, 100 * XRP);
    run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);

    let balance_after_dep = state.get_account(&alice_id()).unwrap().balance;

    // Withdraw the initial LP-token slice from the simplified local AMM model.
    let lp = amm_lp_token_amount(&state, &xrp, &usd, 100 * XRP);
    let wd = signed_amm_withdraw_lp(&alice, 3, xrp.clone(), usd.clone(), lp);

    let r = run_tx(&mut state, &wd, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "amm withdraw failed: {}", r.ter);

    // Alice got 100 XRP back minus fee
    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.balance, balance_after_dep + 100 * XRP - BASE_FEE);
}

#[test]
fn amm_withdraw_too_much_fails() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 10_000);
    fund(&mut state, &bob, 10_000);
    enable_default_ripple(&mut state, bob_id());
    issue_usd_to_alice(&mut state, 1_000 * XRP);

    let (xrp, usd) = amm_test_pair();

    // Create + deposit 100 XRP
    let tx = amm_create_tx(&alice, 1, 100 * XRP);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let dep = amm_deposit_tx(&alice, 2, 100 * XRP);
    run_tx(&mut state, &dep, &pctx(100), ApplyFlags::NONE);

    // Try to withdraw more LP tokens than the create+deposit pool issued.
    let lp = amm_lp_token_amount(&state, &xrp, &usd, 300 * XRP);
    let wd = signed_amm_withdraw_lp(&alice, 3, xrp.clone(), usd.clone(), lp);

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

    let tx = signed_nft_mint(&alice, 1, 1);
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
        let tx = signed_nft_mint(&alice, seq, 1);
        let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
        assert!(r.ter.is_tes_success(), "mint {} failed: {}", seq, r.ter);
    }

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.minted_nftokens, 5);
    assert_eq!(a.owner_count, 1);
}

fn seed_full_equivalent_nft_page(
    state: &mut LedgerState,
    owner: &[u8; 20],
    low96_source: &[u8; 32],
) {
    for i in 0..xrpl::ledger::nft_page::MAX_TOKENS_PER_PAGE {
        let mut token_id = [0u8; 32];
        token_id[0] = 0x80 | (i as u8);
        token_id[4..20].copy_from_slice(&low96_source[4..20]);
        token_id[20..32].copy_from_slice(&low96_source[20..32]);
        state
            .insert_nftoken_paged(owner, token_id, None)
            .expect("seed token should fit before the page is full");
    }
}

#[test]
fn nft_page_mint_full_equivalent_page_returns_no_suitable_page() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let alice_id = alice_id();
    fund(&mut state, &alice, 5_000);

    let mint_tx = signed_nft_mint(&alice, 1, 42);
    let mint_id = xrpl::ledger::nftoken::make_nftoken_id(0, 0, &alice_id, 42, 0);
    seed_full_equivalent_nft_page(&mut state, &alice_id, &mint_id);

    let r = run_tx(&mut state, &mint_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_SUITABLE_NFTOKEN_PAGE);

    let account = state.get_account(&alice_id).unwrap();
    assert_eq!(account.minted_nftokens, 0);
    assert_eq!(
        state.iter_nftokens().count(),
        xrpl::ledger::nft_page::MAX_TOKENS_PER_PAGE
    );
}

#[test]
fn nft_page_burn_removes_from_page() {
    // Burn should remove the NFT and decrement owner_count.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Mint 3 NFTs
    for seq in 1..=3u32 {
        let tx = signed_nft_mint(&alice, seq, 1);
        run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    }
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);

    // Find and burn the first NFT
    let nft_id = {
        let mut found = None;
        for (id, _) in state.iter_nftokens() {
            found = Some(*id);
            break;
        }
        found.unwrap()
    };

    let burn_tx = signed_nft_burn(&alice, 4, nft_id);
    let r = run_tx(&mut state, &burn_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "burn failed: {}", r.ter);

    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);
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
        let tx = signed_nft_mint(&alice, seq, 1);
        run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    }

    // Burn all
    let ids: Vec<[u8; 32]> = state.iter_nftokens().map(|(id, _)| *id).collect();
    for (i, nft_id) in ids.iter().enumerate() {
        let burn_tx = signed_nft_burn(&alice, 3 + i as u32, *nft_id);
        let r = run_tx(&mut state, &burn_tx, &pctx(100), ApplyFlags::NONE);
        assert!(r.ter.is_tes_success(), "burn {} failed: {}", i, r.ter);
    }

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 0);
    assert_eq!(a.burned_nftokens, 2);
}

#[test]
fn nft_burn_owner_field_issuer_burns_holder_page_and_increments_issuer() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mint = signed_nft_mint_flags(&alice, 1, 1, 0x0001);
    let r = run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "mint failed: {}", r.ter);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    let offer_tx = signed_nft_sell_offer(&alice, 2, nft_id, Amount::Xrp(0));
    let r = run_tx(&mut state, &offer_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "offer failed: {}", r.ter);
    let offer_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 2);
    let accept_tx = signed_nft_accept_sell(&bob, 1, offer_key.0);
    let r = run_tx(&mut state, &accept_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "accept failed: {}", r.ter);
    assert_eq!(state.nftoken_page_owner(&nft_id), Some(bob_id()));

    let burn_tx = signed_nft_burn_owner(&alice, 3, nft_id, bob_id());
    let r = run_tx(&mut state, &burn_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "issuer burn failed: {}", r.ter);

    assert_eq!(state.nftoken_page_owner(&nft_id), None);
    assert_eq!(state.get_account(&alice_id()).unwrap().burned_nftokens, 1);
    assert_eq!(state.get_account(&bob_id()).unwrap().burned_nftokens, 0);
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 0);
}

#[test]
fn nft_burn_deletes_sell_offers_before_buy_offers_with_500_cap() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 2_000);
    fund(&mut state, &bob, 2_000);

    let mint = signed_nft_mint(&alice, 1, 1);
    let r = run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "mint failed: {}", r.ter);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    for seq in 2..=501 {
        let offer_tx = signed_nft_sell_offer(&alice, seq, nft_id, Amount::Xrp(0));
        let r = run_tx(&mut state, &offer_tx, &pctx(100), ApplyFlags::NONE);
        assert!(
            r.ter.is_tes_success(),
            "sell offer seq {} failed: {}",
            seq,
            r.ter
        );
    }
    let buy_offer = parse_blob(
        &TxBuilder::nftoken_create_offer()
            .account(&bob)
            .owner(alice_id())
            .nftoken_id(nft_id)
            .amount(Amount::Xrp(1))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&bob)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &buy_offer, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "buy offer failed: {}", r.ter);

    let burn_tx = signed_nft_burn(&alice, 502, nft_id);
    let r = run_tx(&mut state, &burn_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "burn failed: {}", r.ter);

    let remaining: Vec<_> = state
        .iter_nft_offers()
        .filter(|(_, offer)| offer.nftoken_id == nft_id)
        .map(|(_, offer)| offer.clone())
        .collect();
    assert_eq!(remaining.len(), 1);
    assert!(
        !remaining[0].is_sell(),
        "buy offer should remain after sell cap"
    );
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 1);
}

#[test]
fn nft_page_split_on_overflow() {
    // Mint 33 NFTs — should trigger a page split at 32.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 50_000);

    for seq in 1..=33u32 {
        let tx = signed_nft_mint(&alice, seq, 1);
        let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
        assert!(r.ter.is_tes_success(), "mint {} failed: {}", seq, r.ter);
    }

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.minted_nftokens, 33);
    assert_eq!(a.owner_count, 2);
}

#[test]
fn nft_page_burn_after_split() {
    // Mint 33 (triggers split), then burn one. Should work correctly.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 50_000);

    for seq in 1..=33u32 {
        let tx = signed_nft_mint(&alice, seq, 1);
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

    let burn_tx = signed_nft_burn(&alice, 34, nft_id);
    let r = run_tx(&mut state, &burn_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "burn after split failed: {}", r.ter);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 1);
    assert_eq!(a.burned_nftokens, 1);
}

#[test]
fn nft_page_sle_exists_in_shamap() {
    // After minting, the page SLE should exist in state_map at the correct key.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = signed_nft_mint(&alice, 1, 1);
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
        let tx = signed_nft_mint(&alice, seq, 1);
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
fn nft_page_split_keeps_max_page_as_successor() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 50_000);

    for seq in 1..=33u32 {
        let tx = signed_nft_mint(&alice, seq, 1);
        let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
        assert!(r.ter.is_tes_success(), "mint {} failed: {}", seq, r.ter);
    }

    let max_key = xrpl::ledger::nft_page::page_max(&alice_id());
    let pages: Vec<_> = state.iter_nft_pages_for(&alice_id()).collect();
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[1].0, max_key);
    assert_eq!(pages[0].1.next_page, Some(max_key));
    assert_eq!(pages[1].1.prev_page, Some(pages[0].0));
    assert!(pages[0].0 < pages[1].0);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);
}

#[test]
fn nft_page_empty_page_deleted_from_shamap() {
    // Mint 1 NFT, burn it. The page SLE should be removed from state_map.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = signed_nft_mint(&alice, 1, 1);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let max_key = xrpl::ledger::nft_page::page_max(&alice_id());
    assert!(
        state.get_raw(&max_key).is_some(),
        "page should exist after mint"
    );

    // Find and burn the NFT
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();
    let burn_tx = signed_nft_burn(&alice, 2, nft_id);
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
    let mint = signed_nft_mint(&alice, 1, 1);
    run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    assert_eq!(state.nft_page_count(&alice_id()), 1);
    assert_eq!(state.nft_page_count(&bob_id()), 0);

    // Alice creates sell offer (free transfer)
    let offer_tx = signed_nft_sell_offer(&alice, 2, nft_id, Amount::Xrp(0));
    run_tx(&mut state, &offer_tx, &pctx(100), ApplyFlags::NONE);

    // Find the offer key
    let offer_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 2);

    // Bob accepts
    let accept_tx = signed_nft_accept_sell(&bob, 1, offer_key.0);
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
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 1);
}

#[test]
fn nft_page_accept_full_equivalent_destination_returns_no_suitable_page() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let alice_id = alice_id();
    let bob_id = bob_id();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mint = signed_nft_mint(&alice, 1, 1);
    let r = run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "mint failed: {}", r.ter);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    let offer_tx = signed_nft_sell_offer(&alice, 2, nft_id, Amount::Xrp(0));
    let r = run_tx(&mut state, &offer_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "offer failed: {}", r.ter);
    let offer_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id, 2);

    seed_full_equivalent_nft_page(&mut state, &bob_id, &nft_id);

    let accept_tx = signed_nft_accept_sell(&bob, 1, offer_key.0);
    let r = run_tx(&mut state, &accept_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_SUITABLE_NFTOKEN_PAGE);

    let nft = state.get_nftoken(&nft_id).expect("NFT remains with seller");
    assert_eq!(nft.owner, alice_id);
    assert!(state.get_nft_offer(&offer_key).is_some());
}

#[test]
fn nft_page_transfer_into_existing_page_does_not_increase_owner_count() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let alice_mint = signed_nft_mint(&alice, 1, 1);
    run_tx(&mut state, &alice_mint, &pctx(100), ApplyFlags::NONE);
    let alice_nft_id = state
        .iter_nftokens()
        .find(|(_, nft)| nft.owner == alice_id())
        .map(|(id, _)| *id)
        .unwrap();

    let bob_mint = signed_nft_mint(&bob, 1, 1);
    run_tx(&mut state, &bob_mint, &pctx(100), ApplyFlags::NONE);
    assert_eq!(state.nft_page_count(&bob_id()), 1);
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 1);

    let offer_tx = signed_nft_sell_offer(&alice, 2, alice_nft_id, Amount::Xrp(0));
    run_tx(&mut state, &offer_tx, &pctx(100), ApplyFlags::NONE);
    let offer_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 2);

    let accept_tx = signed_nft_accept_sell(&bob, 2, offer_key.0);
    let r = run_tx(&mut state, &accept_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "accept failed: {}", r.ter);

    assert_eq!(state.nftoken_page_owner(&alice_nft_id), Some(bob_id()));
    assert_eq!(state.nft_page_count(&alice_id()), 0);
    assert_eq!(state.nft_page_count(&bob_id()), 1);
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 1);
}

#[test]
fn nft_offer_keylet_uses_rippled_namespace() {
    let keylet_key = xrpl::ledger::keylet::nft_offer(&alice_id(), 2).key;
    let canonical_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 2);
    assert_eq!(keylet_key, canonical_key);

    let mut old_space = Vec::with_capacity(26);
    old_space.extend_from_slice(&[0x00, 0x37]);
    old_space.extend_from_slice(&alice_id());
    old_space.extend_from_slice(&2u32.to_be_bytes());
    let old_key = xrpl::ledger::Key(xrpl::crypto::sha512_first_half(&old_space));
    assert_ne!(keylet_key, old_key);
}

#[test]
fn nft_create_offer_stores_offer_directory_node_and_directory() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mint = signed_nft_mint(&alice, 1, 1);
    run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    let offer_tx = signed_nft_sell_offer(&alice, 2, nft_id, Amount::Xrp(0));
    let r = run_tx(&mut state, &offer_tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "create offer failed: {}", r.ter);

    let offer_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 2);
    let offer = state
        .get_nft_offer(&offer_key)
        .expect("created NFT offer exists");
    assert_eq!(offer.nft_offer_node, 0);

    let offer_raw = state
        .get_raw(&offer_key)
        .expect("created NFT offer has raw SLE");
    let offer_sle = xrpl::ledger::meta::parse_sle(offer_raw).expect("offer SLE parses");
    assert!(offer_sle
        .fields
        .iter()
        .any(|f| matches!((f.type_code, f.field_code), (3, 4))));
    assert!(offer_sle
        .fields
        .iter()
        .any(|f| matches!((f.type_code, f.field_code), (3, 12))));

    let dir_key = xrpl::ledger::directory::nft_sell_offers_dir_key(&nft_id);
    let dir_raw = state
        .get_raw(&dir_key)
        .expect("created sell-offer directory exists");
    let dir_sle = xrpl::ledger::meta::parse_sle(dir_raw).expect("directory SLE parses");
    let flags = dir_sle
        .fields
        .iter()
        .find(|f| matches!((f.type_code, f.field_code), (2, 2)))
        .map(|f| u32::from_be_bytes(f.data[..4].try_into().unwrap()))
        .unwrap();
    assert_eq!(flags, 0x0000_0002);
    assert!(dir_sle
        .fields
        .iter()
        .any(|f| matches!((f.type_code, f.field_code), (5, 10)) && f.data.as_slice() == nft_id));
    let dir = state
        .get_directory(&dir_key)
        .expect("sell-offer directory typed state exists");
    assert_eq!(dir.indexes, vec![offer_key.0]);

    let buy_offer = parse_blob(
        &TxBuilder::nftoken_create_offer()
            .account(&bob)
            .owner(alice_id())
            .nftoken_id(nft_id)
            .amount(Amount::Xrp(1))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&bob)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &buy_offer, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "buy offer failed: {}", r.ter);
    let buy_key = xrpl::ledger::nftoken::offer_shamap_key(&bob_id(), 1);
    let buy_dir_key = xrpl::ledger::directory::nft_buy_offers_dir_key(&nft_id);
    let buy_dir_raw = state
        .get_raw(&buy_dir_key)
        .expect("created buy-offer directory exists");
    let buy_dir_sle = xrpl::ledger::meta::parse_sle(buy_dir_raw).expect("buy dir SLE parses");
    let buy_flags = buy_dir_sle
        .fields
        .iter()
        .find(|f| matches!((f.type_code, f.field_code), (2, 2)))
        .map(|f| u32::from_be_bytes(f.data[..4].try_into().unwrap()))
        .unwrap();
    assert_eq!(buy_flags, 0x0000_0001);
    let buy_dir = state
        .get_directory(&buy_dir_key)
        .expect("buy-offer directory typed state exists");
    assert_eq!(buy_dir.indexes, vec![buy_key.0]);
}

#[test]
fn nft_create_offer_rejects_missing_or_wrong_owner_nft() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);
    fund(&mut state, &carol, 5_000);

    let missing_sell = parse_blob(
        &TxBuilder::nftoken_create_offer()
            .account(&alice)
            .nftoken_id([0xAB; 32])
            .amount(Amount::Xrp(0))
            .flags(0x0001)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &missing_sell, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter.to_string(), "tecNO_ENTRY");
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);

    let mint = signed_nft_mint(&alice, 2, 1);
    run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    let bob_sell = signed_nft_sell_offer(&bob, 1, nft_id, Amount::Xrp(0));
    let r = run_tx(&mut state, &bob_sell, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter.to_string(), "tecNO_ENTRY");
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 0);

    let wrong_owner_buy = parse_blob(
        &TxBuilder::nftoken_create_offer()
            .account(&bob)
            .owner(carol_id())
            .nftoken_id(nft_id)
            .amount(Amount::Xrp(1))
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&bob)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &wrong_owner_buy, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter.to_string(), "tecNO_ENTRY");
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 0);
    assert_eq!(state.nftoken_page_owner(&nft_id), Some(alice_id()));
}

#[test]
fn nft_cancel_offer_removes_token_offer_directory_entry() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mint = signed_nft_mint(&alice, 1, 1);
    run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    let offer_tx = signed_nft_sell_offer(&alice, 2, nft_id, Amount::Xrp(0));
    run_tx(&mut state, &offer_tx, &pctx(100), ApplyFlags::NONE);
    let offer_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 2);
    let dir_key = xrpl::ledger::directory::nft_sell_offers_dir_key(&nft_id);
    assert!(state.get_directory(&dir_key).is_some());

    let cancel = parse_blob(
        &TxBuilder::nftoken_cancel_offer()
            .account(&alice)
            .nft_sell_offer(offer_key.0)
            .fee(BASE_FEE)
            .sequence(3)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &cancel, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "cancel offer failed: {}", r.ter);

    assert!(state.get_nft_offer(&offer_key).is_none());
    assert!(state.get_directory(&dir_key).is_none());
    assert!(state.get_raw(&dir_key).is_none());
}

#[test]
fn nft_accept_rejects_own_offer_before_transfer() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let mint = signed_nft_mint(&alice, 1, 1);
    run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    let offer_tx = signed_nft_sell_offer(&alice, 2, nft_id, Amount::Xrp(1_000));
    run_tx(&mut state, &offer_tx, &pctx(100), ApplyFlags::NONE);
    let offer_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 2);

    let accept = signed_nft_accept_sell(&alice, 3, offer_key.0);
    let r = run_tx(&mut state, &accept, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter.to_string(), "tecCANT_ACCEPT_OWN_NFTOKEN_OFFER");
    assert!(state.get_nft_offer(&offer_key).is_some());
}

#[test]
fn nft_accept_buy_offer_pays_seller_and_moves_token() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mint = signed_nft_mint(&alice, 1, 1);
    run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    let buy_offer = parse_blob(
        &TxBuilder::nftoken_create_offer()
            .account(&bob)
            .owner(alice_id())
            .nftoken_id(nft_id)
            .amount(Amount::Xrp(1_000))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&bob)
            .unwrap()
            .blob,
    )
    .unwrap();
    run_tx(&mut state, &buy_offer, &pctx(100), ApplyFlags::NONE);
    let buy_key = xrpl::ledger::nftoken::offer_shamap_key(&bob_id(), 1);

    let alice_before = state.get_account(&alice_id()).unwrap().balance;
    let bob_before = state.get_account(&bob_id()).unwrap().balance;
    let accept = signed_nft_accept_buy(&alice, 2, buy_key.0);
    let r = run_tx(&mut state, &accept, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "accept buy failed: {}", r.ter);

    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        alice_before + 1_000 - BASE_FEE
    );
    assert_eq!(
        state.get_account(&bob_id()).unwrap().balance,
        bob_before - 1_000
    );
    assert_eq!(state.nftoken_page_owner(&nft_id), Some(bob_id()));
    assert!(state.get_nft_offer(&buy_key).is_none());
}

#[test]
fn nft_brokered_accept_pays_broker_seller_and_moves_token() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);
    fund(&mut state, &carol, 5_000);

    let mint = signed_nft_mint(&alice, 1, 1);
    run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    let sell_offer = signed_nft_sell_offer(&alice, 2, nft_id, Amount::Xrp(900));
    run_tx(&mut state, &sell_offer, &pctx(100), ApplyFlags::NONE);
    let sell_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 2);

    let buy_offer = parse_blob(
        &TxBuilder::nftoken_create_offer()
            .account(&bob)
            .owner(alice_id())
            .nftoken_id(nft_id)
            .amount(Amount::Xrp(1_000))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&bob)
            .unwrap()
            .blob,
    )
    .unwrap();
    run_tx(&mut state, &buy_offer, &pctx(100), ApplyFlags::NONE);
    let buy_key = xrpl::ledger::nftoken::offer_shamap_key(&bob_id(), 1);

    let alice_before = state.get_account(&alice_id()).unwrap().balance;
    let bob_before = state.get_account(&bob_id()).unwrap().balance;
    let carol_before = state.get_account(&carol_id()).unwrap().balance;
    let accept = parse_blob(
        &TxBuilder::nftoken_accept_offer()
            .account(&carol)
            .nft_buy_offer(buy_key.0)
            .nft_sell_offer(sell_key.0)
            .nftoken_broker_fee(Amount::Xrp(100))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&carol)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &accept, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "broker accept failed: {}", r.ter);

    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        alice_before + 900
    );
    assert_eq!(
        state.get_account(&bob_id()).unwrap().balance,
        bob_before - 1_000
    );
    assert_eq!(
        state.get_account(&carol_id()).unwrap().balance,
        carol_before + 100 - BASE_FEE
    );
    assert_eq!(state.nftoken_page_owner(&nft_id), Some(bob_id()));
    assert!(state.get_nft_offer(&sell_key).is_none());
    assert!(state.get_nft_offer(&buy_key).is_none());
}

#[test]
fn nft_brokered_accept_rejects_broker_fee_equal_to_buy_amount() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);
    fund(&mut state, &carol, 5_000);

    let mint = signed_nft_mint(&alice, 1, 1);
    run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    let sell_offer = signed_nft_sell_offer(&alice, 2, nft_id, Amount::Xrp(0));
    run_tx(&mut state, &sell_offer, &pctx(100), ApplyFlags::NONE);
    let sell_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 2);

    let buy_offer = parse_blob(
        &TxBuilder::nftoken_create_offer()
            .account(&bob)
            .owner(alice_id())
            .nftoken_id(nft_id)
            .amount(Amount::Xrp(1_000))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&bob)
            .unwrap()
            .blob,
    )
    .unwrap();
    run_tx(&mut state, &buy_offer, &pctx(100), ApplyFlags::NONE);
    let buy_key = xrpl::ledger::nftoken::offer_shamap_key(&bob_id(), 1);

    let accept = parse_blob(
        &TxBuilder::nftoken_accept_offer()
            .account(&carol)
            .nft_buy_offer(buy_key.0)
            .nft_sell_offer(sell_key.0)
            .nftoken_broker_fee(Amount::Xrp(1_000))
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&carol)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &accept, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter.to_string(), "tecINSUFFICIENT_PAYMENT");
    assert!(state.get_nft_offer(&sell_key).is_some());
    assert!(state.get_nft_offer(&buy_key).is_some());
    assert_eq!(state.nftoken_page_owner(&nft_id), Some(alice_id()));
}

#[test]
fn nft_accept_expired_offer_deletes_offer_and_returns_tecexpired() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mint = signed_nft_mint(&alice, 1, 1);
    run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    let offer_tx = parse_blob(
        &TxBuilder::nftoken_create_offer()
            .account(&alice)
            .nftoken_id(nft_id)
            .amount(Amount::Xrp(0))
            .flags(0x0001)
            .expiration(50)
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    run_tx(&mut state, &offer_tx, &pctx(10), ApplyFlags::NONE);
    let offer_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 2);
    let dir_key = xrpl::ledger::directory::nft_sell_offers_dir_key(&nft_id);
    assert!(state.get_nft_offer(&offer_key).is_some());

    let accept = signed_nft_accept_sell(&bob, 1, offer_key.0);
    let r = run_tx(&mut state, &accept, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter.to_string(), "tecEXPIRED");
    assert!(r.applied, "expired offer deletion must survive tecEXPIRED");
    assert!(state.get_nft_offer(&offer_key).is_none());
    assert!(state.get_directory(&dir_key).is_none());
    assert_eq!(state.nftoken_page_owner(&nft_id), Some(alice_id()));
}

#[test]
fn nft_accept_sell_offer_enforces_buyer_post_transfer_reserve() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    enable_parity_amendments(&mut state);
    state.insert_account(make_account(bob_id(), 1_000_011));

    let mint = signed_nft_mint(&alice, 1, 1);
    run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    let offer_tx = signed_nft_sell_offer(&alice, 2, nft_id, Amount::Xrp(1));
    run_tx(&mut state, &offer_tx, &pctx(100), ApplyFlags::NONE);
    let offer_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 2);

    let accept = signed_nft_accept_sell(&bob, 1, offer_key.0);
    let r = run_tx(&mut state, &accept, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter.to_string(), "tecINSUFFICIENT_RESERVE");
    assert!(r.applied, "tec reserve path preserves doApply side effects");
    assert!(state.get_nft_offer(&offer_key).is_none());
    assert_eq!(state.nftoken_page_owner(&nft_id), Some(bob_id()));
    assert_eq!(state.get_account(&bob_id()).unwrap().balance, 1_000_001);
}

#[test]
fn nft_accept_iou_offer_requires_authorized_buyer_trustline() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mut issuer = state.get_account(&alice_id()).unwrap().clone();
    issuer.flags |= LSF_REQUIRE_AUTH;
    state.insert_account(issuer);

    let usd = Currency::from_code("USD").unwrap();
    let mut line = xrpl::ledger::RippleState::new(&bob_id(), &alice_id(), usd.clone());
    line.set_limit_for(&bob_id(), IouValue::from_f64(1_000.0));
    line.balance = if bob_id() == line.low_account {
        IouValue::from_f64(100.0)
    } else {
        IouValue::from_f64(-100.0)
    };
    state.insert_trustline(line);

    let mint = signed_nft_mint(&alice, 1, 1);
    run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();

    let offer_tx = signed_nft_sell_offer(
        &alice,
        2,
        nft_id,
        Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd,
            issuer: alice_id(),
        },
    );
    run_tx(&mut state, &offer_tx, &pctx(100), ApplyFlags::NONE);
    let offer_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 2);

    let accept = signed_nft_accept_sell(&bob, 1, offer_key.0);
    let r = run_tx(&mut state, &accept, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter.to_string(), "tecNO_AUTH");
    assert!(state.get_nft_offer(&offer_key).is_some());
    assert_eq!(state.nftoken_page_owner(&nft_id), Some(alice_id()));
}

#[test]
fn nft_mint_with_amount_creates_sell_offer() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mint = parse_blob(
        &TxBuilder::nftoken_mint()
            .account(&alice)
            .nftoken_taxon(1)
            .amount(Amount::Xrp(1_000))
            .destination_account(bob_id())
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "mint with offer failed: {}", r.ter);

    let nft_id = state.iter_nftokens().next().map(|(id, _)| *id).unwrap();
    let offer_key = xrpl::ledger::nftoken::offer_shamap_key(&alice_id(), 1);
    let offer = state
        .get_nft_offer(&offer_key)
        .expect("mint-created sell offer exists");
    assert!(offer.is_sell());
    assert_eq!(offer.nftoken_id, nft_id);
    assert_eq!(offer.amount, Amount::Xrp(1_000));
    assert_eq!(offer.destination, Some(bob_id()));
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);
}

#[test]
fn nft_mint_sets_first_nftoken_sequence_for_issuer_and_authorized_minter() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let mint = signed_nft_mint(&alice, 1, 1);
    let r = run_tx(&mut state, &mint, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "first self mint failed: {}", r.ter);
    let alice_root = state.get_account(&alice_id()).unwrap();
    assert_eq!(alice_root.first_nftoken_sequence(), Some(1));
    assert_eq!(alice_root.minted_nftokens, 1);

    let mut issuer = state.get_account(&alice_id()).unwrap().clone();
    issuer.set_nftoken_minter(Some(bob_id()));
    state.insert_account(issuer);

    let mint_by_bob = parse_blob(
        &TxBuilder::nftoken_mint()
            .account(&bob)
            .issuer(alice_id())
            .nftoken_taxon(2)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&bob)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &mint_by_bob, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "authorized mint failed: {}", r.ter);
    let alice_root = state.get_account(&alice_id()).unwrap();
    assert_eq!(alice_root.first_nftoken_sequence(), Some(1));
    assert_eq!(alice_root.minted_nftokens, 2);
}

#[test]
fn nft_page_merge_on_removal() {
    // Mint 33 (split into 2 pages), burn enough to trigger merge back to 1.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 100_000);

    // Mint 33 → 2 pages
    for seq in 1..=33u32 {
        let tx = signed_nft_mint(&alice, seq, 1);
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
        let burn_tx = signed_nft_burn(&alice, 34 + i as u32, *nft_id);
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
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);
}

// ── NFToken behavioral parity ─────────────────────────────────────────────────
//
// NFToken page-storage parity is still being tightened. These tests keep the
// behavioral surface honest while lower-level page/hash coverage evolves.

#[test]
fn nft_mint_basic() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = signed_nft_mint(&alice, 1, 42);

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
        let tx = signed_nft_mint(&alice, seq, 1);
        let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
        assert!(r.ter.is_tes_success(), "mint {} failed: {}", seq, r.ter);
    }

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.owner_count, 1);
    assert_eq!(a.minted_nftokens, 3);
}

#[test]
fn nft_burn_reduces_owner_count() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Mint
    let mint_tx = signed_nft_mint(&alice, 1, 1);
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
    let burn_tx = signed_nft_burn(&alice, 2, nft_id);

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

    let burn_tx = signed_nft_burn(&alice, 1, [0xAA; 32]);

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

fn sle_has_field(raw: &[u8], type_code: u16, field_code: u16) -> bool {
    xrpl::ledger::meta::parse_sle(raw)
        .map(|sle| {
            sle.fields
                .into_iter()
                .any(|field| field.type_code == type_code && field.field_code == field_code)
        })
        .unwrap_or(false)
}

fn patch_sle_u64(raw: &[u8], field_code: u16, value: u64) -> Vec<u8> {
    xrpl::ledger::meta::patch_sle(
        raw,
        &[xrpl::ledger::meta::ParsedField {
            type_code: 3,
            field_code,
            data: value.to_be_bytes().to_vec(),
        }],
        None,
        None,
        &[],
    )
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

    let tx = signed_mpt_create(&alice, 1, 0, Some(100), Some(0), None, None);

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
fn mpt_dynamic_fields_require_dynamic_mpt_amendment() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    state.enable_amendment(xrpl::crypto::sha512_first_half("MPTokensV1".as_bytes()));
    state.insert_account(make_account(alice_id(), 5_000 * XRP));

    let create_mutable = parse_blob(
        &TxBuilder::mptoken_issuance_create()
            .account(&alice)
            .fee(BASE_FEE)
            .sequence(1)
            .mutable_flags(0x0000_0001)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &create_mutable, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, xrpl::ledger::ter::TEM_DISABLED);
    assert!(!r.applied);

    let mptid = make_mptid(1, &alice_id());
    let set_metadata = signed_mpt_set(&alice, 1, mptid, 0, Some(b"blocked"), None);
    let r = run_tx(&mut state, &set_metadata, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, xrpl::ledger::ter::TEM_DISABLED);
    assert!(!r.applied);

    let set_fee = signed_mpt_set_transfer_fee(&alice, 1, mptid, 0, None);
    let r = run_tx(&mut state, &set_fee, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, xrpl::ledger::ter::TEM_DISABLED);
    assert!(!r.applied);

    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(state.get_account(&alice_id()).unwrap().balance, 5_000 * XRP);
}

#[test]
fn mpt_owner_node_fields_do_not_overlap_supply_fields() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 20_000);
    fund(&mut state, &bob, 20_000);

    let tickets = signed_ticket_create(&alice, 1, 40);
    assert!(run_tx(&mut state, &tickets, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let create = signed_mpt_create(&alice, 42, 0, Some(1_000), None, None, None);
    let r = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "mpt create failed: {}", r.ter);
    let mptid = make_mptid(42, &alice_id());
    let issuance = state
        .get_raw(&mpt_issuance_key_for(&mptid))
        .expect("issuance exists")
        .to_vec();
    assert!(
        sle_u64(&issuance, 4) > 0,
        "sfOwnerNode should store the owner directory page"
    );
    assert_eq!(
        sle_u64(&issuance, 25),
        0,
        "sfOutstandingAmount must be separate from sfOwnerNode"
    );

    let bob_tickets = signed_ticket_create(&bob, 1, 40);
    assert!(
        run_tx(&mut state, &bob_tickets, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );
    let authorize = signed_mpt_authorize(&bob, 42, mptid, 0, None);
    assert!(run_tx(&mut state, &authorize, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    let holder = state
        .get_raw(&mpt_holder_key_for(&mptid, &bob_id()))
        .expect("holder token exists")
        .to_vec();
    assert!(
        sle_u64(&holder, 4) > 0,
        "MPToken sfOwnerNode should store the owner directory page"
    );
    assert_eq!(sle_u64(&holder, 26), 0);
    assert_eq!(sle_u64(&holder, 29), 0);
}

#[test]
fn mpt_issuance_destroy_basic() {
    // rippled: create then destroy → owner_count back to 0
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    // Create
    let tx = signed_mpt_create(&alice, 1, 0, Some(100), None, None, None);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    // Destroy
    let mptid = make_mptid(1, &alice_id());
    let tx = signed_mpt_destroy(&alice, 2, mptid);

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
    let tx = signed_mpt_destroy(&alice, 1, fake_mptid);

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
    let tx = signed_mpt_create(&alice, 1, 0, Some(1000), None, None, None);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let mptid = make_mptid(1, &alice_id());

    // Bob creates MPToken (holder authorize, no holder field)
    let tx = signed_mpt_authorize(&bob, 1, mptid, 0, None);
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
    let tx = signed_mpt_create(&alice, 1, 0, Some(1000), None, None, None);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let mptid = make_mptid(1, &alice_id());

    // Bob creates MPToken (first time)
    let tx = signed_mpt_authorize(&bob, 1, mptid, 0, None);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    // Bob tries to create again → tecDUPLICATE
    let tx = signed_mpt_authorize(&bob, 2, mptid, 0, None);
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
    let tx = signed_mpt_create(&alice, 1, 0, Some(1000), None, None, None);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let mptid = make_mptid(1, &alice_id());

    let tx = signed_mpt_authorize(&bob, 1, mptid, 0, None);
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 1);

    // Destroy with tfMPTUnauthorize (0x01)
    let tx = signed_mpt_authorize(&bob, 2, mptid, 0x0000_0001, None);

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
    let tx = signed_mpt_create(&alice, 1, 0, Some(1000), None, None, Some(b"initial"));
    run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);

    let mptid = make_mptid(1, &alice_id());

    // Set: update metadata
    let tx = signed_mpt_set(&alice, 2, mptid, 0, Some(b"updated"), None);

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "mpt issuance set failed: {}", r.ter);

    let a = state.get_account(&alice_id()).unwrap();
    assert_eq!(a.sequence, 3);
    // owner_count should be unchanged (set doesn't change ownership)
    assert_eq!(a.owner_count, 1);
}

#[test]
fn mpt_issuance_set_nonexistent_fails() {
    // rippled: set on nonexistent issuance -> tecOBJECT_NOT_FOUND
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let fake_mptid = make_mptid(99, &alice_id());
    let tx = signed_mpt_set(&alice, 1, fake_mptid, 0, Some(b"test"), None);

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(
        r.ter,
        xrpl::ledger::ter::TEC_OBJECT_NOT_FOUND,
        "expected tecOBJECT_NOT_FOUND, got {}",
        r.ter
    );
}

#[test]
fn mpt_issuance_set_rejects_holder_with_issuance_mutation_fields() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let create = signed_mpt_create(&alice, 1, 0x0000_0024, Some(1_000), None, None, None);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    let mptid = make_mptid(1, &alice_id());
    let holder_create = signed_mpt_authorize(&bob, 1, mptid, 0, None);
    assert!(
        run_tx(&mut state, &holder_create, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let metadata_with_holder = signed_mpt_set(&alice, 2, mptid, 0, Some(b"bad"), Some(bob_id()));
    let r = run_tx(
        &mut state,
        &metadata_with_holder,
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, xrpl::ledger::ter::TEM_MALFORMED);

    let fee_with_holder = signed_mpt_set_transfer_fee(&alice, 2, mptid, 100, Some(bob_id()));
    let r = run_tx(&mut state, &fee_with_holder, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, xrpl::ledger::ter::TEM_MALFORMED);
}

#[test]
fn mpt_issuance_set_transfer_fee_zero_removes_without_can_transfer() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create = signed_mpt_create(&alice, 1, 0, Some(1_000), None, None, None);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    let mptid = make_mptid(1, &alice_id());

    let clear_fee = signed_mpt_set_transfer_fee(&alice, 2, mptid, 0, None);
    let r = run_tx(&mut state, &clear_fee, &pctx(100), ApplyFlags::NONE);
    assert!(
        r.ter.is_tes_success(),
        "TransferFee=0 should not require lsfMPTCanTransfer: {}",
        r.ter
    );
    let issuance = state
        .get_raw(&mpt_issuance_key_for(&mptid))
        .expect("issuance exists")
        .to_vec();
    assert!(
        !sle_has_field(&issuance, 1, 4),
        "TransferFee=0 should remove/omit sfTransferFee"
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
    let tx = signed_mpt_create(&alice, 1, 0, Some(1000), None, None, None);
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 1);

    let mptid = make_mptid(1, &alice_id());

    // 2. Bob creates MPToken
    let tx = signed_mpt_authorize(&bob, 1, mptid, 0, None);
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success());
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 1);

    // 3. Bob destroys MPToken
    let tx = signed_mpt_authorize(&bob, 2, mptid, 0x01, None);
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success());
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 0);

    // 4. Alice destroys issuance (no holders remaining)
    let tx = signed_mpt_destroy(&alice, 2, mptid);
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}

#[test]
fn mpt_payment_direct_requires_holder_and_tracks_outstanding() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let create = signed_mpt_create(&alice, 1, 0, Some(1_000), None, None, None);
    let r = run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "issuance create failed: {}", r.ter);

    let mptid = make_mptid(1, &alice_id());

    let holder_create = signed_mpt_authorize(&bob, 1, mptid, 0, None);
    let r = run_tx(&mut state, &holder_create, &pctx(100), ApplyFlags::NONE);
    assert!(r.ter.is_tes_success(), "holder authorize failed: {}", r.ter);

    let payment = signed_mpt_payment(&alice, 2, bob_id(), Amount::from_mpt_value(100, mptid));
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
        sle_u64(&issuance, 25),
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
        "payment should use bob's existing MPToken entry"
    );
}

#[test]
fn mpt_payment_missing_holder_fails_without_creating_mptoken() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let create = signed_mpt_create(&alice, 1, 0, Some(1_000), None, None, None);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());
    let payment = signed_mpt_payment(&alice, 2, bob_id(), Amount::from_mpt_value(100, mptid));
    let r = run_tx(&mut state, &payment, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, xrpl::ledger::ter::TEC_NO_AUTH);
    assert!(
        state
            .get_raw(&mpt_holder_key_for(&mptid, &bob_id()))
            .is_none(),
        "failed payment must not create destination MPToken"
    );
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 0);
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

    let create = signed_mpt_create(&alice, 1, 0x0000_0020, Some(1_000), None, Some(5_000), None);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());

    let bob_holder = signed_mpt_authorize(&bob, 1, mptid, 0, None);
    assert!(
        run_tx(&mut state, &bob_holder, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let carol_holder = signed_mpt_authorize(&carol, 1, mptid, 0, None);
    assert!(
        run_tx(&mut state, &carol_holder, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let issue_to_bob = signed_mpt_payment(&alice, 2, bob_id(), Amount::from_mpt_value(200, mptid));
    assert!(
        run_tx(&mut state, &issue_to_bob, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let bob_to_carol = signed_mpt_payment_sendmax(
        &bob,
        2,
        carol_id(),
        Amount::from_mpt_value(100, mptid),
        Amount::from_mpt_value(105, mptid),
    );
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
        sle_u64(&issuance, 25),
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

    let create = signed_mpt_create(&alice, 1, 0x0000_0004, Some(1_000), None, None, None);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());

    let holder_create = signed_mpt_authorize(&bob, 1, mptid, 0, None);
    assert!(
        run_tx(&mut state, &holder_create, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let payment = signed_mpt_payment(&alice, 2, bob_id(), Amount::from_mpt_value(50, mptid));
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

    let create = signed_mpt_create(&alice, 1, 0x0000_0040, Some(1_000), None, None, None);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());
    let holder_create = signed_mpt_authorize(&bob, 1, mptid, 0, None);
    assert!(
        run_tx(&mut state, &holder_create, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let payment = signed_mpt_payment(&alice, 2, bob_id(), Amount::from_mpt_value(150, mptid));
    assert!(run_tx(&mut state, &payment, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let clawback = signed_mpt_clawback(&alice, 3, bob_id(), Amount::from_mpt_value(60, mptid));
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
    assert_eq!(sle_u64(&issuance, 25), 90);
}

#[test]
fn mpt_clawback_self_holder_is_malformed() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let create = signed_mpt_create(&alice, 1, 0x0000_0040, Some(1_000), None, None, None);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());
    let clawback = signed_mpt_clawback(&alice, 2, alice_id(), Amount::from_mpt_value(1, mptid));
    let r = run_tx(&mut state, &clawback, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, xrpl::ledger::ter::TEM_MALFORMED);
}

#[test]
fn mpt_authorize_holder_cannot_destroy_nonzero_balance() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let create = signed_mpt_create(&alice, 1, 0, Some(1_000), None, None, None);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());
    let holder_create = signed_mpt_authorize(&bob, 1, mptid, 0, None);
    assert!(
        run_tx(&mut state, &holder_create, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let payment = signed_mpt_payment(&alice, 2, bob_id(), Amount::from_mpt_value(10, mptid));
    assert!(run_tx(&mut state, &payment, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let unauthorize = signed_mpt_authorize(&bob, 2, mptid, 0x0000_0001, None);
    let r = run_tx(&mut state, &unauthorize, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, xrpl::ledger::ter::TEC_HAS_OBLIGATIONS);
}

#[test]
fn mpt_authorize_holder_cannot_destroy_locked_balance() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let create = signed_mpt_create(&alice, 1, 0, Some(1_000), None, None, None);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    let mptid = make_mptid(1, &alice_id());
    let holder_create = signed_mpt_authorize(&bob, 1, mptid, 0, None);
    assert!(
        run_tx(&mut state, &holder_create, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let holder_key = mpt_holder_key_for(&mptid, &bob_id());
    let holder_raw = state.get_raw(&holder_key).unwrap().to_vec();
    state.insert_raw(holder_key, patch_sle_u64(&holder_raw, 29, 1));

    let unauthorize = signed_mpt_authorize(&bob, 2, mptid, 0x0000_0001, None);
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

    let create = signed_mpt_create(&alice, 1, 0, Some(1_000), None, None, None);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());
    let holder_create = signed_mpt_authorize(&bob, 1, mptid, 0, None);
    assert!(
        run_tx(&mut state, &holder_create, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let payment = signed_mpt_payment(&alice, 2, bob_id(), Amount::from_mpt_value(10, mptid));
    assert!(run_tx(&mut state, &payment, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let destroy = signed_mpt_destroy(&alice, 3, mptid);
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

    let create = signed_mpt_create(&alice, 1, 0x0000_0022, Some(1_000), None, None, None);
    assert!(run_tx(&mut state, &create, &pctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let mptid = make_mptid(1, &alice_id());
    let holder_create = signed_mpt_authorize(&bob, 1, mptid, 0, None);
    assert!(
        run_tx(&mut state, &holder_create, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let issue_to_bob = signed_mpt_payment(&alice, 2, bob_id(), Amount::from_mpt_value(100, mptid));
    assert!(
        run_tx(&mut state, &issue_to_bob, &pctx(100), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let lock = signed_mpt_set(&alice, 3, mptid, 0x0000_0001, None, None);
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

    let blocked = signed_mpt_payment(&bob, 2, carol_id(), Amount::from_mpt_value(10, mptid));
    let r = run_tx(&mut state, &blocked, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, xrpl::ledger::ter::TEC_LOCKED);

    let return_to_issuer =
        signed_mpt_payment(&bob, 3, alice_id(), Amount::from_mpt_value(10, mptid));
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
    assert_eq!(sle_u64(&issuance, 25), 90);
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
    assert_eq!(r.ter, ter::TEM_REDUNDANT);
}

#[test]
fn ter_nft_mint_bad_transfer_fee() {
    // rippled: NFTokenMint with transfer_fee > 50000 → temBAD_NFTOKEN_TRANSFER_FEE
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = parse_blob(
        &TxBuilder::nftoken_mint()
            .account(&alice)
            .nftoken_taxon(1)
            .transfer_fee_field(60_000)
            .flags(0x0008) // tfTransferable
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_BAD_NFTOKEN_TRANSFER_FEE);
}

#[test]
fn ter_nft_mint_transfer_fee_without_transferable() {
    // rippled: Transfer fee > 0 without tfTransferable → temMALFORMED
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = parse_blob(
        &TxBuilder::nftoken_mint()
            .account(&alice)
            .nftoken_taxon(1)
            .transfer_fee_field(100)
            .flags(0) // no tfTransferable
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_MALFORMED);
}

#[test]
fn ter_set_regular_key_self_rejected() {
    // rippled: SetRegularKey with key == account → temBAD_REGKEY
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = parse_blob(
        &TxBuilder::set_regular_key()
            .account(&alice)
            .regular_key(alice_id())
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_BAD_REGKEY);
}

#[test]
fn ter_account_set_bad_transfer_rate() {
    // rippled: TransferRate < QUALITY_ONE (1B) → temBAD_TRANSFER_RATE
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .transfer_rate(500_000_000)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_BAD_TRANSFER_RATE);
}

#[test]
fn ter_account_set_bad_tick_size() {
    // rippled: TickSize not in [3, 16] → temBAD_TICK_SIZE
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .tick_size(1)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_BAD_TICK_SIZE);
}

#[test]
fn ter_account_set_conflicting_flags() {
    // rippled: SetFlag == ClearFlag → temINVALID_FLAG
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .set_flag(7)
            .clear_flag(7)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();

    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_INVALID_FLAG);
}

#[test]
fn account_set_legacy_require_dest_flags_set_and_clear_account_flag() {
    // rippled: AccountSet legacy tx flags still mutate AccountRoot lsfRequireDestTag.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let set_tx = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .flags(TF_REQUIRE_DEST_TAG)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &set_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert_ne!(
        state.get_account(&alice_id()).unwrap().flags & LSF_REQUIRE_DEST_TAG,
        0
    );

    let clear_tx = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .flags(TF_OPTIONAL_DEST_TAG)
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &clear_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().flags & LSF_REQUIRE_DEST_TAG,
        0
    );
}

#[test]
fn account_set_legacy_require_auth_flags_set_and_clear_account_flag() {
    // rippled: tfRequireAuth/tfOptionalAuth are equivalent to asfRequireAuth set/clear.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let set_tx = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .flags(TF_REQUIRE_AUTH)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &set_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert_ne!(
        state.get_account(&alice_id()).unwrap().flags & LSF_REQUIRE_AUTH,
        0
    );

    let clear_tx = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .flags(TF_OPTIONAL_AUTH)
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &clear_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().flags & LSF_REQUIRE_AUTH,
        0
    );
}

#[test]
fn account_set_legacy_disallow_xrp_flags_set_and_clear_account_flag() {
    // rippled: tfDisallowXRP/tfAllowXRP are equivalent to asfDisallowXRP set/clear.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let set_tx = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .flags(TF_DISALLOW_XRP)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &set_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert_ne!(
        state.get_account(&alice_id()).unwrap().flags & LSF_DISALLOW_XRP,
        0
    );

    let clear_tx = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .flags(TF_ALLOW_XRP)
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &clear_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().flags & LSF_DISALLOW_XRP,
        0
    );
}

#[test]
fn account_set_legacy_flag_pair_conflicts_are_tem_invalid_flag() {
    // rippled: contradictory legacy AccountSet flags are malformed, including mixed SetFlag forms.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .flags(TF_REQUIRE_AUTH | TF_OPTIONAL_AUTH)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_INVALID_FLAG);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);

    let mixed_tx = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .set_flag(1)
            .flags(TF_OPTIONAL_DEST_TAG)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &mixed_tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_INVALID_FLAG);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

#[test]
fn account_set_allow_trustline_locking_uses_mainnet_lsf_bit() {
    // rippled: asfAllowTrustLineLocking maps to lsfAllowTrustLineLocking, not clawback.
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .set_flag(17)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert_ne!(
        state.get_account(&alice_id()).unwrap().flags & LSF_ALLOW_TRUST_LINE_LOCKING,
        0
    );
}

#[test]
fn account_set_allow_trustline_locking_requires_token_escrow() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    state.insert_account(make_account(alice_id(), 5_000 * XRP));

    let set_locking = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .set_flag(17)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &set_locking, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_DISABLED);
    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.sequence, 1);
    assert_eq!(account.flags & LSF_ALLOW_TRUST_LINE_LOCKING, 0);

    let mut account = account.clone();
    account.flags |= LSF_ALLOW_TRUST_LINE_LOCKING;
    state.insert_account(account);

    let clear_locking = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .clear_flag(17)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &clear_locking, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_DISABLED);
    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.sequence, 1);
    assert_ne!(account.flags & LSF_ALLOW_TRUST_LINE_LOCKING, 0);
}

#[test]
fn account_set_disable_master_requires_master_signature_and_alternative_key() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let no_alt = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .set_flag(4)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &no_alt, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_ALTERNATIVE_KEY);

    let set_regular = parse_blob(
        &TxBuilder::set_regular_key()
            .account(&alice)
            .regular_key(bob_id())
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert_eq!(
        run_tx(&mut state, &set_regular, &pctx(100), ApplyFlags::NONE).ter,
        ter::TES_SUCCESS
    );

    let disable = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .set_flag(4)
            .fee(BASE_FEE)
            .sequence(3)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &disable, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert_ne!(
        state.get_account(&alice_id()).unwrap().flags & LSF_DISABLE_MASTER,
        0
    );
}

#[test]
fn set_regular_key_cannot_remove_last_alternative_when_master_disabled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);

    let mut account = state.get_account(&alice_id()).unwrap().clone();
    account.flags |= LSF_DISABLE_MASTER;
    account.regular_key = Some(bob_id());
    state.insert_account(account);

    let clear = parse_blob(
        &TxBuilder::set_regular_key()
            .account(&alice)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&bob)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &clear, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEC_NO_ALTERNATIVE_KEY);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().regular_key,
        Some(bob_id())
    );
}

#[test]
fn set_regular_key_first_master_signed_zero_fee_spends_password_flag() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    let carol = kp_carol();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);
    fund(&mut state, &carol, 5_000);

    let free = parse_blob(
        &TxBuilder::set_regular_key()
            .account(&alice)
            .regular_key(bob_id())
            .fee(0)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &free, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.balance, 5_000 * XRP);
    assert_eq!(account.sequence, 2);
    assert_eq!(account.regular_key, Some(bob_id()));
    assert_ne!(account.flags & LSF_PASSWORD_SPENT, 0);

    let repeated_free = parse_blob(
        &TxBuilder::set_regular_key()
            .account(&alice)
            .regular_key(carol_id())
            .fee(0)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &repeated_free, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEL_INSUF_FEE_P);
    let account = state.get_account(&alice_id()).unwrap();
    assert_eq!(account.sequence, 2);
    assert_eq!(account.regular_key, Some(bob_id()));
}

#[test]
fn set_regular_key_rejects_universal_flags() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    let bob = kp_bob();
    fund(&mut state, &alice, 5_000);
    fund(&mut state, &bob, 5_000);

    let tx = parse_blob(
        &TxBuilder::set_regular_key()
            .account(&alice)
            .regular_key(bob_id())
            .flags(0xffff_0000)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_INVALID_FLAG);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
}

#[test]
fn account_set_freeze_flags_follow_rippled_one_way_rules() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let set_global = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .set_flag(7)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert_eq!(
        run_tx(&mut state, &set_global, &pctx(100), ApplyFlags::NONE).ter,
        ter::TES_SUCCESS
    );

    let set_no_freeze = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .set_flag(6)
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert_eq!(
        run_tx(&mut state, &set_no_freeze, &pctx(100), ApplyFlags::NONE).ter,
        ter::TES_SUCCESS
    );

    let clear_global = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .clear_flag(7)
            .fee(BASE_FEE)
            .sequence(3)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &clear_global, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    let flags = state.get_account(&alice_id()).unwrap().flags;
    assert_ne!(flags & LSF_NO_FREEZE, 0);
    assert_ne!(flags & LSF_GLOBAL_FREEZE, 0);
}

#[test]
fn account_set_clawback_is_not_clearable() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let set = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .set_flag(16)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert_eq!(
        run_tx(&mut state, &set, &pctx(100), ApplyFlags::NONE).ter,
        ter::TES_SUCCESS
    );

    let clear = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .clear_flag(16)
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    let r = run_tx(&mut state, &clear, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert_ne!(
        state.get_account(&alice_id()).unwrap().flags & LSF_ALLOW_TRUST_LINE_CLAWBACK,
        0
    );
}

#[test]
fn account_set_tick_size_maximum_clears_field() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let set = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .tick_size(3)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert_eq!(
        run_tx(&mut state, &set, &pctx(100), ApplyFlags::NONE).ter,
        ter::TES_SUCCESS
    );
    assert_eq!(state.get_account(&alice_id()).unwrap().tick_size, 3);

    let set_max_stored = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .tick_size(15)
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert_eq!(
        run_tx(&mut state, &set_max_stored, &pctx(100), ApplyFlags::NONE).ter,
        ter::TES_SUCCESS
    );
    assert_eq!(state.get_account(&alice_id()).unwrap().tick_size, 15);

    let clear = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .tick_size(16)
            .fee(BASE_FEE)
            .sequence(3)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert_eq!(
        run_tx(&mut state, &clear, &pctx(100), ApplyFlags::NONE).ter,
        ter::TES_SUCCESS
    );
    assert_eq!(state.get_account(&alice_id()).unwrap().tick_size, 0);
}

#[test]
fn account_set_tick_size_above_max_is_bad_tick_size() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let tx = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .tick_size(17)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();

    assert_eq!(
        run_tx(&mut state, &tx, &pctx(100), ApplyFlags::NONE).ter,
        ter::TEM_BAD_TICK_SIZE
    );
}

#[test]
fn account_set_raw_fields_set_and_clear_like_rippled() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let set = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .email_hash([0x11; 16])
            .wallet_locator([0x22; 32])
            .message_key(alice.public_key_bytes())
            .set_flag(10)
            .nftoken_minter(bob_id())
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert_eq!(
        run_tx(&mut state, &set, &pctx(100), ApplyFlags::NONE).ter,
        ter::TES_SUCCESS
    );
    let raw = state
        .get_raw(&xrpl::ledger::account::shamap_key(&alice_id()))
        .expect("account raw exists");
    let parsed = xrpl::ledger::meta::parse_sle(raw).expect("account SLE parses");
    assert!(parsed
        .fields
        .iter()
        .any(|f| f.type_code == 4 && f.field_code == 1 && f.data == [0x11; 16]));
    assert!(parsed
        .fields
        .iter()
        .any(|f| f.type_code == 5 && f.field_code == 7 && f.data == [0x22; 32]));
    assert!(parsed
        .fields
        .iter()
        .any(|f| f.type_code == 7 && f.field_code == 2 && f.data == alice.public_key_bytes()));
    assert!(parsed
        .fields
        .iter()
        .any(|f| f.type_code == 8 && f.field_code == 9 && f.data == bob_id()));

    let clear = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .email_hash([0; 16])
            .wallet_locator([0; 32])
            .message_key(Vec::new())
            .clear_flag(10)
            .fee(BASE_FEE)
            .sequence(2)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert_eq!(
        run_tx(&mut state, &clear, &pctx(100), ApplyFlags::NONE).ter,
        ter::TES_SUCCESS
    );
    let raw = state
        .get_raw(&xrpl::ledger::account::shamap_key(&alice_id()))
        .expect("account raw exists");
    let parsed = xrpl::ledger::meta::parse_sle(raw).expect("account SLE parses");
    assert!(!parsed.fields.iter().any(|f| matches!(
        (f.type_code, f.field_code),
        (4, 1) | (5, 7) | (7, 2) | (8, 9)
    )));
}

#[test]
fn account_set_rejects_unknown_transaction_flags_before_fee() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let invalid_flags = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .flags(0x0040_0000)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();

    let r = run_tx(&mut state, &invalid_flags, &pctx(100), ApplyFlags::NONE);
    assert_eq!(r.ter, ter::TEM_INVALID_FLAG);
    assert!(!r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 1);
    assert_eq!(state.get_account(&alice_id()).unwrap().balance, 5_000 * XRP);
}

#[test]
fn account_set_message_key_uses_rippled_public_key_type_shape_check() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let prefix_and_length_only_key = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .message_key(vec![0x02; 33])
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();

    let r = run_tx(
        &mut state,
        &prefix_and_length_only_key,
        &pctx(100),
        ApplyFlags::NONE,
    );
    assert_eq!(r.ter, ter::TES_SUCCESS);
    assert!(r.applied);
    assert_eq!(state.get_account(&alice_id()).unwrap().sequence, 2);
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        5_000 * XRP - BASE_FEE
    );
}

#[test]
fn account_set_authorized_minter_and_message_key_preflight() {
    let mut state = LedgerState::new();
    let alice = kp_alice();
    fund(&mut state, &alice, 5_000);

    let missing_minter = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .set_flag(10)
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert_eq!(
        run_tx(&mut state, &missing_minter, &pctx(100), ApplyFlags::NONE).ter,
        ter::TEM_MALFORMED
    );

    let invalid_message_key = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .message_key(vec![1, 2, 3])
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert_eq!(
        run_tx(
            &mut state,
            &invalid_message_key,
            &pctx(100),
            ApplyFlags::NONE
        )
        .ter,
        ter::TEL_BAD_PUBLIC_KEY
    );

    let clear_with_minter = parse_blob(
        &TxBuilder::account_set()
            .account(&alice)
            .clear_flag(10)
            .nftoken_minter(bob_id())
            .fee(BASE_FEE)
            .sequence(1)
            .sign(&alice)
            .unwrap()
            .blob,
    )
    .unwrap();
    assert_eq!(
        run_tx(&mut state, &clear_with_minter, &pctx(100), ApplyFlags::NONE).ter,
        ter::TEM_MALFORMED
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

    // Create -> deposit -> withdraw. AMMWithdraw deletes the AMM when the LP
    // supply reaches zero, matching rippled's deleteAMMAccountIfEmpty path.
    let r = run_tx(
        &mut state,
        &signed_vault_create(&alice, 1),
        &ctx(&header, 200),
        ApplyFlags::NONE,
    );
    assert!(r.ter.is_tes_success());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 2);

    let dep = signed_vault_deposit(&alice, 2, vkey.0, 500 * XRP);
    assert!(
        run_tx(&mut state, &dep, &ctx(&header, 300), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let wd = signed_vault_withdraw(&alice, 3, vkey.0, 500 * XRP);
    assert!(
        run_tx(&mut state, &wd, &ctx(&header, 400), ApplyFlags::NONE)
            .ter
            .is_tes_success()
    );

    let del = signed_vault_delete(&alice, 4, vkey.0);
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
        &signed_vault_create(&alice, 1),
        &ctx(100),
        ApplyFlags::NONE
    )
    .ter
    .is_tes_success());
    let vkey = test_vault_key(&alice_id(), 1);
    let dep = signed_vault_deposit(&alice, 2, vkey.0, 1_000 * XRP);
    assert!(run_tx(&mut state, &dep, &ctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    let bt = signed_loan_broker_set(&alice, 3, vkey.0);
    assert!(run_tx(&mut state, &bt, &ctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    let bkey = test_loan_broker_key(&alice_id(), 3);

    // Bob: loan → repay → delete
    let lt = signed_loan_set(&bob, 1, bkey.0, 100 * XRP);
    assert!(run_tx(&mut state, &lt, &ctx(200), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    let lkey = test_loan_key(&bkey.0, 1);

    let pay = signed_loan_pay(&bob, 2, lkey.0, 100 * XRP);
    assert!(run_tx(&mut state, &pay, &ctx(300), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let dl = signed_loan_delete(&bob, 3, lkey.0);
    assert!(run_tx(&mut state, &dl, &ctx(400), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    assert!(state.get_raw(&lkey).is_none());
    assert_eq!(state.get_account(&bob_id()).unwrap().owner_count, 0);

    // Alice: delete broker
    let db = signed_loan_broker_delete(&alice, 4, bkey.0);
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
    enable_default_ripple(&mut state, bob_id());
    issue_usd_to_alice(&mut state, 1_000 * XRP);

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
    let tx = amm_create_tx(&alice, 1, 200 * XRP);
    assert!(run_tx(&mut state, &tx, &ctx(100), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let dep = amm_deposit_tx(&alice, 2, 200 * XRP);
    assert!(run_tx(&mut state, &dep, &ctx(200), ApplyFlags::NONE)
        .ter
        .is_tes_success());

    let bal = state.get_account(&alice_id()).unwrap().balance;
    let lp = amm_lp_token_amount(&state, &xrp, &usd, 400 * XRP);
    let wd = signed_amm_withdraw_lp(&alice, 3, xrp.clone(), usd.clone(), lp);
    assert!(run_tx(&mut state, &wd, &ctx(300), ApplyFlags::NONE)
        .ter
        .is_tes_success());
    assert_eq!(
        state.get_account(&alice_id()).unwrap().balance,
        bal + 400 * XRP - BASE_FEE
    );

    assert!(state.get_raw(&akey).is_none());
    assert_eq!(state.get_account(&alice_id()).unwrap().owner_count, 0);
}
