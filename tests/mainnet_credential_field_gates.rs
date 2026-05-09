use xrpl::crypto::keys::{KeyPair, Secp256k1KeyPair};
use xrpl::ledger::account::AccountRoot;
use xrpl::ledger::ter::{self, ApplyFlags};
use xrpl::ledger::tx::{run_tx, TxContext};
use xrpl::ledger::LedgerState;
use xrpl::transaction::amount::{Currency, IouValue};
use xrpl::transaction::builder::TxBuilder;
use xrpl::transaction::field::FieldDef;
use xrpl::transaction::serialize::{
    encode_length, serialize_fields, tx_blob_hash, Field, FieldValue, PREFIX_TX_SIGN,
};
use xrpl::transaction::{parse_blob, Amount};

const BASE_FEE: u64 = 12;
const START_BALANCE: u64 = 1_000_000_000;
const CREDENTIAL_ID: [u8; 32] = [0xC7; 32];
const CREDENTIAL_IDS_FIELD: FieldDef = FieldDef {
    type_code: 19,
    field_code: 5,
    name: "CREDENTIAL_IDS",
    is_signing: true,
};

fn kp(byte: u8) -> KeyPair {
    KeyPair::Secp256k1(Secp256k1KeyPair::from_seed_entropy(&[byte; 16]))
}

fn account_id(kp: &KeyPair) -> [u8; 20] {
    xrpl::crypto::account_id(&kp.public_key_bytes())
}

fn account(account_id: [u8; 20], balance: u64, sequence: u32) -> AccountRoot {
    AccountRoot {
        account_id,
        balance,
        sequence,
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
        previous_txn_id: [0; 32],
        previous_txn_lgr_seq: 0,
        raw_sle: None,
    }
}

fn state_with_accounts(credentials_active: bool) -> (LedgerState, KeyPair, [u8; 20]) {
    let sender = kp(1);
    let dest = kp(2);
    let sender_id = account_id(&sender);
    let dest_id = account_id(&dest);

    let mut state = LedgerState::new();
    if credentials_active {
        state.enable_amendment(xrpl::crypto::sha512_first_half(b"Credentials"));
    }
    state.insert_account(account(sender_id, START_BALANCE, 1));
    state.insert_account(account(dest_id, START_BALANCE, 1));
    (state, sender, dest_id)
}

fn credential_ids_value(ids: &[[u8; 32]]) -> Vec<u8> {
    let mut raw = Vec::new();
    encode_length(ids.len() * 32, &mut raw);
    for id in ids {
        raw.extend_from_slice(id);
    }
    raw
}

fn sign_with_credential_ids(builder: TxBuilder, signer: &KeyPair, ids: &[[u8; 32]]) -> Vec<u8> {
    let signing_pubkey = signer.public_key_bytes();
    let mut fields = builder
        .build_fields(signing_pubkey.clone(), None)
        .expect("transaction fields");
    fields.push(Field {
        def: CREDENTIAL_IDS_FIELD,
        value: FieldValue::Raw(credential_ids_value(ids)),
    });

    let mut payload = PREFIX_TX_SIGN.to_vec();
    payload.extend_from_slice(&serialize_fields(&mut fields, true));
    let signature = signer.sign(&payload);

    let mut fields = builder
        .build_fields(signing_pubkey, Some(signature))
        .expect("signed transaction fields");
    fields.push(Field {
        def: CREDENTIAL_IDS_FIELD,
        value: FieldValue::Raw(credential_ids_value(ids)),
    });
    serialize_fields(&mut fields, false)
}

fn credential_array_raw(issuer: [u8; 20], credential_type: &[u8]) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0xE0, 33]); // sfCredential
    raw.push(0x84); // sfIssuer
    encode_length(20, &mut raw);
    raw.extend_from_slice(&issuer);
    raw.extend_from_slice(&[0x70, 31]); // sfCredentialType
    encode_length(credential_type.len(), &mut raw);
    raw.extend_from_slice(credential_type);
    raw.push(0xE1);
    raw.push(0xF1);
    raw
}

fn assert_inactive_rejects_before_fee_and_sequence(blob: Vec<u8>) {
    let tx = parse_blob(&blob).expect("signed canonical transaction parses");
    let (mut state, sender, _) = state_with_accounts(false);
    let sender_id = account_id(&sender);

    let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);
    assert_eq!(
        result.ter,
        ter::TEM_DISABLED,
        "inactive Credentials must reject in preflight"
    );
    assert!(!result.applied);

    let account = state.get_account(&sender_id).expect("sender remains");
    assert_eq!(account.balance, START_BALANCE, "fee was not charged");
    assert_eq!(account.sequence, 1, "sequence was not consumed");
}

fn assert_active_claims_existing_credential_failure(blob: Vec<u8>, expected: &'static str) {
    let tx = parse_blob(&blob).expect("signed canonical transaction parses");
    assert_eq!(
        tx.tx_id,
        tx_blob_hash(&blob),
        "parsed hash matches blob hash"
    );

    let (mut state, sender, _) = state_with_accounts(true);
    let sender_id = account_id(&sender);

    let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);
    assert_eq!(result.ter, ter::token_to_code(expected).unwrap());
    assert!(result.applied, "existing tec behavior claims the fee");

    let account = state.get_account(&sender_id).expect("sender remains");
    assert_eq!(account.balance, START_BALANCE - tx.fee);
    assert_eq!(account.sequence, 2);
}

#[test]
fn payment_credential_ids_are_gated_by_credentials_amendment() {
    let (_, sender, dest_id) = state_with_accounts(false);
    let dest_addr = xrpl::crypto::base58::encode_account(&dest_id);
    let inactive = sign_with_credential_ids(
        TxBuilder::payment()
            .account(&sender)
            .destination(&dest_addr)
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(0)
            .sequence(99),
        &sender,
        &[CREDENTIAL_ID],
    );
    assert_inactive_rejects_before_fee_and_sequence(inactive);

    let active = sign_with_credential_ids(
        TxBuilder::payment()
            .account(&sender)
            .destination(&dest_addr)
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(BASE_FEE)
            .sequence(1),
        &sender,
        &[CREDENTIAL_ID],
    );
    assert_active_claims_existing_credential_failure(active, "tecBAD_CREDENTIALS");
}

#[test]
fn payment_destination_preclaim_errors_precede_credential_lookup() {
    let (mut state, sender, dest_id) = state_with_accounts(true);
    state.remove_account(&dest_id);
    let dest_addr = xrpl::crypto::base58::encode_account(&dest_id);
    let issuer = account_id(&sender);
    let blob = sign_with_credential_ids(
        TxBuilder::payment()
            .account(&sender)
            .destination(&dest_addr)
            .unwrap()
            .amount(Amount::Iou {
                value: IouValue::from_f64(1.0),
                currency: Currency::from_code("USD").unwrap(),
                issuer,
            })
            .fee(BASE_FEE)
            .sequence(1),
        &sender,
        &[CREDENTIAL_ID],
    );
    let tx = parse_blob(&blob).expect("signed payment parses");

    let result = run_tx(&mut state, &tx, &TxContext::default(), ApplyFlags::NONE);

    assert_eq!(result.ter, ter::TEC_NO_DST);
    assert!(result.applied, "tecNO_DST still claims fee");
}

#[test]
fn deposit_preauth_credential_arrays_are_gated_by_credentials_amendment() {
    let (_, sender, _) = state_with_accounts(false);
    let issuer = account_id(&kp(3));
    let credentials = credential_array_raw(issuer, b"KYC");

    let inactive_authorize = TxBuilder::deposit_preauth()
        .account(&sender)
        .authorize_credentials_raw(credentials.clone())
        .fee(0)
        .sequence(99)
        .sign(&sender)
        .unwrap()
        .blob;
    assert_inactive_rejects_before_fee_and_sequence(inactive_authorize);

    let inactive_unauthorize = TxBuilder::deposit_preauth()
        .account(&sender)
        .unauthorize_credentials_raw(credentials.clone())
        .fee(0)
        .sequence(99)
        .sign(&sender)
        .unwrap()
        .blob;
    assert_inactive_rejects_before_fee_and_sequence(inactive_unauthorize);

    let active = TxBuilder::deposit_preauth()
        .account(&sender)
        .authorize_credentials_raw(credentials)
        .fee(BASE_FEE)
        .sequence(1)
        .sign(&sender)
        .unwrap()
        .blob;
    assert_active_claims_existing_credential_failure(active, "tecNO_ISSUER");
}

#[test]
fn account_delete_credential_ids_are_gated_by_credentials_amendment() {
    let (_, sender, dest_id) = state_with_accounts(false);
    let inactive = sign_with_credential_ids(
        TxBuilder::account_delete()
            .account(&sender)
            .destination_account(dest_id)
            .fee(0)
            .sequence(99),
        &sender,
        &[CREDENTIAL_ID],
    );
    assert_inactive_rejects_before_fee_and_sequence(inactive);

    let active = sign_with_credential_ids(
        TxBuilder::account_delete()
            .account(&sender)
            .destination_account(dest_id)
            .fee(2_000_000)
            .sequence(1),
        &sender,
        &[CREDENTIAL_ID],
    );
    assert_active_claims_existing_credential_failure(active, "tecBAD_CREDENTIALS");
}

#[test]
fn escrow_finish_credential_ids_are_gated_by_credentials_amendment() {
    let (_, sender, _) = state_with_accounts(false);
    let inactive = sign_with_credential_ids(
        TxBuilder::escrow_finish()
            .account(&sender)
            .owner(account_id(&sender))
            .offer_sequence(7)
            .fee(0)
            .sequence(99),
        &sender,
        &[CREDENTIAL_ID],
    );
    assert_inactive_rejects_before_fee_and_sequence(inactive);

    let active = sign_with_credential_ids(
        TxBuilder::escrow_finish()
            .account(&sender)
            .owner(account_id(&sender))
            .offer_sequence(7)
            .fee(BASE_FEE)
            .sequence(1),
        &sender,
        &[CREDENTIAL_ID],
    );
    assert_active_claims_existing_credential_failure(active, "tecBAD_CREDENTIALS");
}

#[test]
fn payment_channel_claim_credential_ids_are_gated_by_credentials_amendment() {
    let (_, sender, _) = state_with_accounts(false);
    let inactive = sign_with_credential_ids(
        TxBuilder::paychan_claim()
            .account(&sender)
            .channel([0x55; 32])
            .fee(0)
            .sequence(99),
        &sender,
        &[CREDENTIAL_ID],
    );
    assert_inactive_rejects_before_fee_and_sequence(inactive);

    let active = sign_with_credential_ids(
        TxBuilder::paychan_claim()
            .account(&sender)
            .channel([0x55; 32])
            .fee(BASE_FEE)
            .sequence(1),
        &sender,
        &[CREDENTIAL_ID],
    );
    assert_active_claims_existing_credential_failure(active, "tecBAD_CREDENTIALS");
}
