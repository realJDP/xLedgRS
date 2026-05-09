//! High-level transaction builder.
//!
//! Constructs, signs, and serializes XRPL transactions.
//!
//! # Example
//! ```rust,ignore
//! let kp = Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap();
//! let signed = TxBuilder::payment()
//!     .account(&kp)
//!     .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
//!     .amount(Amount::Xrp(1_000_000))
//!     .fee(12)
//!     .sequence(1)
//!     .sign(&kp);
//! println!("TxHash: {}", signed.hash_hex());
//! println!("Blob:   {}", signed.blob_hex());
//! ```

use crate::crypto::base58::decode_account;
use crate::crypto::keys::KeyPair;
use crate::transaction::amount::{Amount, Issue};
use crate::transaction::field::{self};
use crate::transaction::serialize::{
    serialize_fields, signing_hash, Field, FieldValue, PREFIX_TX_SIGN,
};
use crate::transaction::TransactionType;
use anyhow::Result;

// ── Signed transaction ────────────────────────────────────────────────────────

/// A fully signed, serialized transaction ready to submit.
pub struct SignedTx {
    /// The transaction hash (32 bytes) — this is the ID on the ledger.
    pub hash: [u8; 32],
    /// The canonical binary encoding of the complete transaction.
    pub blob: Vec<u8>,
}

impl SignedTx {
    pub fn hash_hex(&self) -> String {
        hex::encode_upper(self.hash)
    }

    pub fn blob_hex(&self) -> String {
        hex::encode_upper(&self.blob)
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Builds an XRPL transaction field-by-field, then signs it.
pub struct TxBuilder {
    tx_type: TransactionType,
    account: Option<[u8; 20]>,
    destination: Option<[u8; 20]>,
    amount: Option<Amount>,
    balance: Option<Amount>,
    fee: u64,
    sequence: u32,
    flags: u32,
    last_ledger: Option<u32>,
    ticket_count: Option<u32>,
    ticket_sequence: Option<u32>,
    dest_tag: Option<u32>,
    source_tag: Option<u32>,
    set_flag: Option<u32>,
    clear_flag: Option<u32>,
    signer_quorum: Option<u32>,
    signer_entries_raw: Option<Vec<u8>>,
    ledger_fix_type: Option<u16>,
    transfer_rate: Option<u32>,
    quality_in: Option<u32>,
    quality_out: Option<u32>,
    tick_size: Option<u8>,
    limit_amount: Option<Amount>,
    taker_pays: Option<Amount>,
    taker_gets: Option<Amount>,
    amount2: Option<Amount>,
    send_max: Option<Amount>,
    deliver_min: Option<Amount>,
    bid_min: Option<Amount>,
    bid_max: Option<Amount>,
    lp_token_out: Option<Amount>,
    lp_token_in: Option<Amount>,
    eprice: Option<Amount>,
    asset: Option<Issue>,
    asset2: Option<Issue>,
    offer_sequence: Option<u32>,
    finish_after: Option<u32>,
    cancel_after: Option<u32>,
    settle_delay: Option<u32>,
    expiration: Option<u32>,
    domain: Option<Vec<u8>>,
    email_hash: Option<[u8; 16]>,
    wallet_locator: Option<[u8; 32]>,
    message_key: Option<Vec<u8>>,
    public_key_field: Option<Vec<u8>>,
    signature_field: Option<Vec<u8>>,
    channel: Option<[u8; 32]>,
    check_id: Option<[u8; 32]>,
    invoice_id: Option<[u8; 32]>,
    regular_key: Option<[u8; 20]>,
    nftoken_minter: Option<[u8; 20]>,
    nftoken_id: Option<[u8; 32]>,
    nft_sell_offer: Option<[u8; 32]>,
    nft_buy_offer: Option<[u8; 32]>,
    nftoken_broker_fee: Option<Amount>,
    nftoken_taxon: Option<u32>,
    transfer_fee_field: Option<u16>,
    trading_fee: Option<u16>,
    asset_scale: Option<u8>,
    maximum_amount: Option<u64>,
    assets_maximum: Option<i64>,
    mutable_flags: Option<u32>,
    mptoken_metadata: Option<Vec<u8>>,
    domain_id: Option<[u8; 32]>,
    data: Option<Vec<u8>>,
    did_document: Option<Vec<u8>>,
    holder: Option<[u8; 20]>,
    owner: Option<[u8; 20]>,
    issuer: Option<[u8; 20]>,
    subject: Option<[u8; 20]>,
    mptoken_issuance_id: Option<[u8; 24]>,
    vault_id: Option<[u8; 32]>,
    loan_broker_id: Option<[u8; 32]>,
    loan_id: Option<[u8; 32]>,
    uri: Option<Vec<u8>>,
    oracle_document_id: Option<u32>,
    oracle_last_update_time: Option<u32>,
    oracle_price_data_series_raw: Option<Vec<u8>>,
    oracle_provider: Option<Vec<u8>>,
    oracle_asset_class: Option<Vec<u8>>,
    credential_type: Option<Vec<u8>>,
    authorize: Option<[u8; 20]>,
    unauthorize: Option<[u8; 20]>,
    authorize_credentials_raw: Option<Vec<u8>>,
    unauthorize_credentials_raw: Option<Vec<u8>>,
    /// Extra arbitrary fields (for future tx types).
    extra: Vec<Field>,
}

impl TxBuilder {
    fn new(tx_type: TransactionType) -> Self {
        Self {
            tx_type,
            account: None,
            destination: None,
            amount: None,
            balance: None,
            fee: 12, // minimum fee in drops
            sequence: 0,
            flags: 0,
            last_ledger: None,
            ticket_count: None,
            ticket_sequence: None,
            dest_tag: None,
            source_tag: None,
            set_flag: None,
            clear_flag: None,
            signer_quorum: None,
            signer_entries_raw: None,
            ledger_fix_type: None,
            transfer_rate: None,
            quality_in: None,
            quality_out: None,
            tick_size: None,
            limit_amount: None,
            taker_pays: None,
            taker_gets: None,
            amount2: None,
            send_max: None,
            deliver_min: None,
            bid_min: None,
            bid_max: None,
            lp_token_out: None,
            lp_token_in: None,
            eprice: None,
            asset: None,
            asset2: None,
            offer_sequence: None,
            finish_after: None,
            cancel_after: None,
            settle_delay: None,
            expiration: None,
            domain: None,
            email_hash: None,
            wallet_locator: None,
            message_key: None,
            public_key_field: None,
            signature_field: None,
            channel: None,
            check_id: None,
            invoice_id: None,
            regular_key: None,
            nftoken_minter: None,
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            nftoken_broker_fee: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            trading_fee: None,
            asset_scale: None,
            maximum_amount: None,
            assets_maximum: None,
            mutable_flags: None,
            mptoken_metadata: None,
            domain_id: None,
            data: None,
            did_document: None,
            holder: None,
            owner: None,
            issuer: None,
            subject: None,
            mptoken_issuance_id: None,
            vault_id: None,
            loan_broker_id: None,
            loan_id: None,
            uri: None,
            oracle_document_id: None,
            oracle_last_update_time: None,
            oracle_price_data_series_raw: None,
            oracle_provider: None,
            oracle_asset_class: None,
            credential_type: None,
            authorize: None,
            unauthorize: None,
            authorize_credentials_raw: None,
            unauthorize_credentials_raw: None,
            extra: Vec::new(),
        }
    }

    pub fn payment() -> Self {
        Self::new(TransactionType::Payment)
    }
    pub fn account_set() -> Self {
        Self::new(TransactionType::AccountSet)
    }
    pub fn set_regular_key() -> Self {
        Self::new(TransactionType::SetRegularKey)
    }
    pub fn account_delete() -> Self {
        Self::new(TransactionType::AccountDelete)
    }
    pub fn signer_list_set() -> Self {
        Self::new(TransactionType::SignerListSet)
    }
    pub fn ledger_state_fix() -> Self {
        Self::new(TransactionType::LedgerStateFix)
    }
    pub fn oracle_set() -> Self {
        Self::new(TransactionType::OracleSet)
    }
    pub fn oracle_delete() -> Self {
        Self::new(TransactionType::OracleDelete)
    }
    pub fn ticket_create() -> Self {
        Self::new(TransactionType::TicketCreate)
    }
    pub fn trust_set() -> Self {
        Self::new(TransactionType::TrustSet)
    }
    pub fn offer_create() -> Self {
        Self::new(TransactionType::OfferCreate)
    }
    pub fn offer_cancel() -> Self {
        Self::new(TransactionType::OfferCancel)
    }
    pub fn escrow_create() -> Self {
        Self::new(TransactionType::EscrowCreate)
    }
    pub fn escrow_finish() -> Self {
        Self::new(TransactionType::EscrowFinish)
    }
    pub fn escrow_cancel() -> Self {
        Self::new(TransactionType::EscrowCancel)
    }
    pub fn paychan_create() -> Self {
        Self::new(TransactionType::PaymentChannelCreate)
    }
    pub fn paychan_fund() -> Self {
        Self::new(TransactionType::PaymentChannelFund)
    }
    pub fn paychan_claim() -> Self {
        Self::new(TransactionType::PaymentChannelClaim)
    }
    pub fn check_create() -> Self {
        Self::new(TransactionType::CheckCreate)
    }
    pub fn check_cash() -> Self {
        Self::new(TransactionType::CheckCash)
    }
    pub fn check_cancel() -> Self {
        Self::new(TransactionType::CheckCancel)
    }
    pub fn deposit_preauth() -> Self {
        Self::new(TransactionType::DepositPreauth)
    }
    pub fn nftoken_mint() -> Self {
        Self::new(TransactionType::NFTokenMint)
    }
    pub fn nftoken_burn() -> Self {
        Self::new(TransactionType::NFTokenBurn)
    }
    pub fn nftoken_create_offer() -> Self {
        Self::new(TransactionType::NFTokenCreateOffer)
    }
    pub fn nftoken_accept_offer() -> Self {
        Self::new(TransactionType::NFTokenAcceptOffer)
    }
    pub fn nftoken_cancel_offer() -> Self {
        Self::new(TransactionType::NFTokenCancelOffer)
    }
    pub fn amm_create() -> Self {
        Self::new(TransactionType::AMMCreate)
    }
    pub fn amm_deposit() -> Self {
        Self::new(TransactionType::AMMDeposit)
    }
    pub fn amm_withdraw() -> Self {
        Self::new(TransactionType::AMMWithdraw)
    }
    pub fn amm_vote() -> Self {
        Self::new(TransactionType::AMMVote)
    }
    pub fn amm_bid() -> Self {
        Self::new(TransactionType::AMMBid)
    }
    pub fn amm_delete() -> Self {
        Self::new(TransactionType::AMMDelete)
    }
    pub fn clawback() -> Self {
        Self::new(TransactionType::Clawback)
    }
    pub fn mptoken_issuance_create() -> Self {
        Self::new(TransactionType::MPTokenIssuanceCreate)
    }
    pub fn mptoken_issuance_destroy() -> Self {
        Self::new(TransactionType::MPTokenIssuanceDestroy)
    }
    pub fn mptoken_issuance_set() -> Self {
        Self::new(TransactionType::MPTokenIssuanceSet)
    }
    pub fn mptoken_authorize() -> Self {
        Self::new(TransactionType::MPTokenAuthorize)
    }
    pub fn did_set() -> Self {
        Self::new(TransactionType::DIDSet)
    }
    pub fn did_delete() -> Self {
        Self::new(TransactionType::DIDDelete)
    }
    pub fn credential_create() -> Self {
        Self::new(TransactionType::CredentialCreate)
    }
    pub fn credential_accept() -> Self {
        Self::new(TransactionType::CredentialAccept)
    }
    pub fn credential_delete() -> Self {
        Self::new(TransactionType::CredentialDelete)
    }
    pub fn vault_create() -> Self {
        Self::new(TransactionType::VaultCreate)
    }
    pub fn vault_set() -> Self {
        Self::new(TransactionType::VaultSet)
    }
    pub fn vault_delete() -> Self {
        Self::new(TransactionType::VaultDelete)
    }
    pub fn vault_deposit() -> Self {
        Self::new(TransactionType::VaultDeposit)
    }
    pub fn vault_withdraw() -> Self {
        Self::new(TransactionType::VaultWithdraw)
    }
    pub fn vault_clawback() -> Self {
        Self::new(TransactionType::VaultClawback)
    }
    pub fn loan_broker_set() -> Self {
        Self::new(TransactionType::LoanBrokerSet)
    }
    pub fn loan_broker_delete() -> Self {
        Self::new(TransactionType::LoanBrokerDelete)
    }
    pub fn loan_set() -> Self {
        Self::new(TransactionType::LoanSet)
    }
    pub fn loan_delete() -> Self {
        Self::new(TransactionType::LoanDelete)
    }
    pub fn loan_pay() -> Self {
        Self::new(TransactionType::LoanPay)
    }
    pub fn loan_broker_cover_deposit() -> Self {
        Self::new(TransactionType::LoanBrokerCoverDeposit)
    }
    pub fn loan_broker_cover_withdraw() -> Self {
        Self::new(TransactionType::LoanBrokerCoverWithdraw)
    }
    pub fn loan_broker_cover_clawback() -> Self {
        Self::new(TransactionType::LoanBrokerCoverClawback)
    }
    pub fn loan_manage() -> Self {
        Self::new(TransactionType::LoanManage)
    }

    // ── Setters ───────────────────────────────────────────────────────────────

    /// Set the signing account from a keypair (derives address automatically).
    pub fn account(mut self, kp: &KeyPair) -> Self {
        let pubkey = match kp {
            KeyPair::Ed25519(k) => {
                let mut v = vec![0xED];
                v.extend_from_slice(&k.public_key_bytes());
                v
            }
            KeyPair::Secp256k1(k) => k.public_key_bytes(),
        };
        let id = crate::crypto::account_id(&pubkey);
        self.account = Some(id);
        self
    }

    /// Set the account address directly (r... string).
    pub fn account_address(mut self, addr: &str) -> Result<Self> {
        self.account = Some(decode_account(addr)?);
        Ok(self)
    }

    /// Set the destination address (r... string).
    pub fn destination(mut self, addr: &str) -> Result<Self> {
        self.destination = Some(decode_account(addr)?);
        Ok(self)
    }

    /// Set the destination directly from an account ID.
    pub fn destination_account(mut self, id: [u8; 20]) -> Self {
        self.destination = Some(id);
        self
    }

    pub fn amount(mut self, amount: Amount) -> Self {
        self.amount = Some(amount);
        self
    }

    pub fn balance(mut self, amount: Amount) -> Self {
        self.balance = Some(amount);
        self
    }

    pub fn fee(mut self, drops: u64) -> Self {
        self.fee = drops;
        self
    }

    pub fn sequence(mut self, seq: u32) -> Self {
        self.sequence = seq;
        self
    }

    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    pub fn last_ledger_sequence(mut self, seq: u32) -> Self {
        self.last_ledger = Some(seq);
        self
    }

    pub fn ticket_count(mut self, count: u32) -> Self {
        self.ticket_count = Some(count);
        self
    }

    pub fn ticket_sequence(mut self, seq: u32) -> Self {
        self.ticket_sequence = Some(seq);
        self
    }

    pub fn destination_tag(mut self, tag: u32) -> Self {
        self.dest_tag = Some(tag);
        self
    }

    pub fn source_tag(mut self, tag: u32) -> Self {
        self.source_tag = Some(tag);
        self
    }

    pub fn check_id(mut self, id: [u8; 32]) -> Self {
        self.check_id = Some(id);
        self
    }

    pub fn invoice_id(mut self, id: [u8; 32]) -> Self {
        self.invoice_id = Some(id);
        self
    }

    pub fn regular_key(mut self, account: [u8; 20]) -> Self {
        self.regular_key = Some(account);
        self
    }

    pub fn nftoken_id(mut self, id: [u8; 32]) -> Self {
        self.nftoken_id = Some(id);
        self
    }

    pub fn nft_sell_offer(mut self, id: [u8; 32]) -> Self {
        self.nft_sell_offer = Some(id);
        self
    }

    pub fn nft_buy_offer(mut self, id: [u8; 32]) -> Self {
        self.nft_buy_offer = Some(id);
        self
    }

    pub fn nftoken_broker_fee(mut self, amount: Amount) -> Self {
        self.nftoken_broker_fee = Some(amount);
        self
    }

    pub fn nftoken_taxon(mut self, taxon: u32) -> Self {
        self.nftoken_taxon = Some(taxon);
        self
    }

    pub fn transfer_fee_field(mut self, fee: u16) -> Self {
        self.transfer_fee_field = Some(fee);
        self
    }

    pub fn trading_fee(mut self, fee: u16) -> Self {
        self.trading_fee = Some(fee);
        self
    }

    pub fn asset_scale(mut self, scale: u8) -> Self {
        self.asset_scale = Some(scale);
        self
    }

    pub fn maximum_amount(mut self, amount: u64) -> Self {
        self.maximum_amount = Some(amount);
        self
    }

    pub fn assets_maximum(mut self, amount: i64) -> Self {
        self.assets_maximum = Some(amount);
        self
    }

    pub fn mutable_flags(mut self, flags: u32) -> Self {
        self.mutable_flags = Some(flags);
        self
    }

    pub fn mptoken_metadata(mut self, metadata: Vec<u8>) -> Self {
        self.mptoken_metadata = Some(metadata);
        self
    }

    pub fn domain_id(mut self, id: [u8; 32]) -> Self {
        self.domain_id = Some(id);
        self
    }

    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    pub fn did_document(mut self, document: Vec<u8>) -> Self {
        self.did_document = Some(document);
        self
    }

    pub fn holder(mut self, id: [u8; 20]) -> Self {
        self.holder = Some(id);
        self
    }

    pub fn owner(mut self, id: [u8; 20]) -> Self {
        self.owner = Some(id);
        self
    }

    pub fn issuer(mut self, id: [u8; 20]) -> Self {
        self.issuer = Some(id);
        self
    }

    pub fn subject(mut self, id: [u8; 20]) -> Self {
        self.subject = Some(id);
        self
    }

    pub fn credential_type(mut self, credential_type: Vec<u8>) -> Self {
        self.credential_type = Some(credential_type);
        self
    }

    pub fn authorize(mut self, id: [u8; 20]) -> Self {
        self.authorize = Some(id);
        self
    }

    pub fn unauthorize(mut self, id: [u8; 20]) -> Self {
        self.unauthorize = Some(id);
        self
    }

    pub fn authorize_credentials_raw(mut self, raw: Vec<u8>) -> Self {
        self.authorize_credentials_raw = Some(raw);
        self
    }

    pub fn unauthorize_credentials_raw(mut self, raw: Vec<u8>) -> Self {
        self.unauthorize_credentials_raw = Some(raw);
        self
    }

    pub fn ledger_fix_type(mut self, fix_type: u16) -> Self {
        self.ledger_fix_type = Some(fix_type);
        self
    }

    pub fn mptoken_issuance_id(mut self, id: [u8; 24]) -> Self {
        self.mptoken_issuance_id = Some(id);
        self
    }

    pub fn vault_id(mut self, id: [u8; 32]) -> Self {
        self.vault_id = Some(id);
        self
    }

    pub fn loan_broker_id(mut self, id: [u8; 32]) -> Self {
        self.loan_broker_id = Some(id);
        self
    }

    pub fn loan_id(mut self, id: [u8; 32]) -> Self {
        self.loan_id = Some(id);
        self
    }

    pub fn uri(mut self, uri: Vec<u8>) -> Self {
        self.uri = Some(uri);
        self
    }

    pub fn oracle_document_id(mut self, document_id: u32) -> Self {
        self.oracle_document_id = Some(document_id);
        self
    }

    pub fn oracle_last_update_time(mut self, last_update_time: u32) -> Self {
        self.oracle_last_update_time = Some(last_update_time);
        self
    }

    pub fn oracle_price_data_series_raw(mut self, raw: Vec<u8>) -> Self {
        self.oracle_price_data_series_raw = Some(raw);
        self
    }

    pub fn oracle_provider(mut self, provider: Vec<u8>) -> Self {
        self.oracle_provider = Some(provider);
        self
    }

    pub fn oracle_asset_class(mut self, asset_class: Vec<u8>) -> Self {
        self.oracle_asset_class = Some(asset_class);
        self
    }

    pub fn set_flag(mut self, flag: u32) -> Self {
        self.set_flag = Some(flag);
        self
    }

    pub fn clear_flag(mut self, flag: u32) -> Self {
        self.clear_flag = Some(flag);
        self
    }

    pub fn signer_quorum(mut self, quorum: u32) -> Self {
        self.signer_quorum = Some(quorum);
        self
    }

    pub fn signer_entries_raw(mut self, raw: Vec<u8>) -> Self {
        self.signer_entries_raw = Some(raw);
        self
    }

    pub fn transfer_rate(mut self, rate: u32) -> Self {
        self.transfer_rate = Some(rate);
        self
    }

    /// Set QualityIn for TrustSet transactions.
    pub fn quality_in(mut self, quality: u32) -> Self {
        self.quality_in = Some(quality);
        self
    }

    /// Set QualityOut for TrustSet transactions.
    pub fn quality_out(mut self, quality: u32) -> Self {
        self.quality_out = Some(quality);
        self
    }

    pub fn tick_size(mut self, size: u8) -> Self {
        self.tick_size = Some(size);
        self
    }

    /// Set the LimitAmount for TrustSet transactions.
    pub fn limit_amount(mut self, amount: Amount) -> Self {
        self.limit_amount = Some(amount);
        self
    }

    /// Set TakerPays for OfferCreate.
    pub fn taker_pays(mut self, amount: Amount) -> Self {
        self.taker_pays = Some(amount);
        self
    }

    /// Set TakerGets for OfferCreate.
    pub fn taker_gets(mut self, amount: Amount) -> Self {
        self.taker_gets = Some(amount);
        self
    }

    pub fn amount2(mut self, amount: Amount) -> Self {
        self.amount2 = Some(amount);
        self
    }

    pub fn send_max(mut self, amount: Amount) -> Self {
        self.send_max = Some(amount);
        self
    }

    pub fn deliver_min(mut self, amount: Amount) -> Self {
        self.deliver_min = Some(amount);
        self
    }

    pub fn bid_min(mut self, amount: Amount) -> Self {
        self.bid_min = Some(amount);
        self
    }

    pub fn bid_max(mut self, amount: Amount) -> Self {
        self.bid_max = Some(amount);
        self
    }

    pub fn lp_token_out(mut self, amount: Amount) -> Self {
        self.lp_token_out = Some(amount);
        self
    }

    pub fn lp_token_in(mut self, amount: Amount) -> Self {
        self.lp_token_in = Some(amount);
        self
    }

    pub fn eprice(mut self, amount: Amount) -> Self {
        self.eprice = Some(amount);
        self
    }

    pub fn asset(mut self, issue: Issue) -> Self {
        self.asset = Some(issue);
        self
    }

    pub fn asset2(mut self, issue: Issue) -> Self {
        self.asset2 = Some(issue);
        self
    }

    /// Set OfferSequence for OfferCancel / EscrowFinish / EscrowCancel.
    pub fn offer_sequence(mut self, seq: u32) -> Self {
        self.offer_sequence = Some(seq);
        self
    }

    pub fn finish_after(mut self, time: u32) -> Self {
        self.finish_after = Some(time);
        self
    }

    pub fn cancel_after(mut self, time: u32) -> Self {
        self.cancel_after = Some(time);
        self
    }

    pub fn settle_delay(mut self, secs: u32) -> Self {
        self.settle_delay = Some(secs);
        self
    }

    pub fn expiration(mut self, time: u32) -> Self {
        self.expiration = Some(time);
        self
    }

    pub fn domain(mut self, domain: Vec<u8>) -> Self {
        self.domain = Some(domain);
        self
    }

    pub fn email_hash(mut self, hash: [u8; 16]) -> Self {
        self.email_hash = Some(hash);
        self
    }

    pub fn wallet_locator(mut self, locator: [u8; 32]) -> Self {
        self.wallet_locator = Some(locator);
        self
    }

    pub fn message_key(mut self, key: Vec<u8>) -> Self {
        self.message_key = Some(key);
        self
    }

    pub fn nftoken_minter(mut self, minter: [u8; 20]) -> Self {
        self.nftoken_minter = Some(minter);
        self
    }

    pub fn public_key_field(mut self, pk: Vec<u8>) -> Self {
        self.public_key_field = Some(pk);
        self
    }

    pub fn signature_field(mut self, sig: Vec<u8>) -> Self {
        self.signature_field = Some(sig);
        self
    }

    pub fn channel(mut self, ch: [u8; 32]) -> Self {
        self.channel = Some(ch);
        self
    }

    // ── Build fields list ─────────────────────────────────────────────────────

    pub fn build_fields(
        &self,
        signing_pubkey: Vec<u8>,
        signature: Option<Vec<u8>>,
    ) -> Result<Vec<Field>> {
        let account = self
            .account
            .ok_or_else(|| anyhow::anyhow!("account not set"))?;

        let mut fields = vec![
            Field {
                def: field::TRANSACTION_TYPE,
                value: FieldValue::UInt16(self.tx_type as u16),
            },
            Field {
                def: field::FLAGS,
                value: FieldValue::UInt32(self.flags),
            },
            Field {
                def: field::SEQUENCE,
                value: FieldValue::UInt32(self.sequence),
            },
            Field {
                def: field::FEE,
                value: FieldValue::Amount(Amount::Xrp(self.fee)),
            },
            Field {
                def: field::SIGNING_PUB_KEY,
                value: FieldValue::Blob(signing_pubkey),
            },
            Field {
                def: field::ACCOUNT,
                value: FieldValue::AccountID(account),
            },
        ];

        if let Some(tag) = self.source_tag {
            fields.push(Field {
                def: field::SOURCE_TAG,
                value: FieldValue::UInt32(tag),
            });
        }
        if let Some(os) = self.offer_sequence {
            fields.push(Field {
                def: field::OFFER_SEQUENCE,
                value: FieldValue::UInt32(os),
            });
        }
        if let Some(lls) = self.last_ledger {
            fields.push(Field {
                def: field::LAST_LEDGER_SEQUENCE,
                value: FieldValue::UInt32(lls),
            });
        }
        if let Some(count) = self.ticket_count {
            fields.push(Field {
                def: field::TICKET_COUNT,
                value: FieldValue::UInt32(count),
            });
        }
        if let Some(ts) = self.ticket_sequence {
            fields.push(Field {
                def: field::TICKET_SEQUENCE,
                value: FieldValue::UInt32(ts),
            });
        }
        if let Some(flag) = self.set_flag {
            fields.push(Field {
                def: field::SET_FLAG,
                value: FieldValue::UInt32(flag),
            });
        }
        if let Some(flag) = self.clear_flag {
            fields.push(Field {
                def: field::CLEAR_FLAG,
                value: FieldValue::UInt32(flag),
            });
        }
        if let Some(quorum) = self.signer_quorum {
            fields.push(Field {
                def: field::SIGNER_QUORUM,
                value: FieldValue::UInt32(quorum),
            });
        }
        if let Some(fix_type) = self.ledger_fix_type {
            fields.push(Field {
                def: field::LEDGER_FIX_TYPE,
                value: FieldValue::UInt16(fix_type),
            });
        }
        if let Some(rate) = self.transfer_rate {
            fields.push(Field {
                def: field::TRANSFER_RATE,
                value: FieldValue::UInt32(rate),
            });
        }
        if let Some(hash) = self.email_hash {
            fields.push(Field {
                def: field::EMAIL_HASH,
                value: FieldValue::Hash128(hash),
            });
        }
        if let Some(locator) = self.wallet_locator {
            fields.push(Field {
                def: field::WALLET_LOCATOR,
                value: FieldValue::Hash256(locator),
            });
        }
        if let Some(quality) = self.quality_in {
            fields.push(Field {
                def: field::QUALITY_IN,
                value: FieldValue::UInt32(quality),
            });
        }
        if let Some(quality) = self.quality_out {
            fields.push(Field {
                def: field::QUALITY_OUT,
                value: FieldValue::UInt32(quality),
            });
        }
        if let Some(fa) = self.finish_after {
            fields.push(Field {
                def: field::FINISH_AFTER,
                value: FieldValue::UInt32(fa),
            });
        }
        if let Some(ca) = self.cancel_after {
            fields.push(Field {
                def: field::CANCEL_AFTER,
                value: FieldValue::UInt32(ca),
            });
        }
        if let Some(sd) = self.settle_delay {
            fields.push(Field {
                def: field::SETTLE_DELAY,
                value: FieldValue::UInt32(sd),
            });
        }
        if let Some(exp) = self.expiration {
            fields.push(Field {
                def: field::EXPIRATION,
                value: FieldValue::UInt32(exp),
            });
        }
        if let Some(size) = self.tick_size {
            fields.push(Field {
                def: field::TICK_SIZE,
                value: FieldValue::UInt8(size),
            });
        }
        if let Some(scale) = self.asset_scale {
            fields.push(Field {
                def: field::ASSET_SCALE,
                value: FieldValue::UInt8(scale),
            });
        }
        if let Some(maximum) = self.maximum_amount {
            fields.push(Field {
                def: field::MAXIMUM_AMOUNT,
                value: FieldValue::UInt64(maximum),
            });
        }
        if let Some(maximum) = self.assets_maximum {
            fields.push(Field {
                def: field::ASSETS_MAXIMUM,
                value: FieldValue::Number(maximum),
            });
        }
        if let Some(mutable_flags) = self.mutable_flags {
            fields.push(Field {
                def: field::MUTABLE_FLAGS,
                value: FieldValue::UInt32(mutable_flags),
            });
        }
        if let Some(ref ch) = self.channel {
            fields.push(Field {
                def: field::CHANNEL,
                value: FieldValue::Hash256(*ch),
            });
        }
        if let Some(id) = self.domain_id {
            fields.push(Field {
                def: field::DOMAIN_ID,
                value: FieldValue::Hash256(id),
            });
        }
        if let Some(id) = self.vault_id {
            fields.push(Field {
                def: field::VAULT_ID,
                value: FieldValue::Hash256(id),
            });
        }
        if let Some(id) = self.loan_broker_id {
            fields.push(Field {
                def: field::LOAN_BROKER_ID,
                value: FieldValue::Hash256(id),
            });
        }
        if let Some(id) = self.loan_id {
            fields.push(Field {
                def: field::LOAN_ID,
                value: FieldValue::Hash256(id),
            });
        }
        if let Some(ref id) = self.check_id {
            fields.push(Field {
                def: field::CHECK_ID,
                value: FieldValue::Hash256(*id),
            });
        }
        if let Some(ref id) = self.invoice_id {
            fields.push(Field {
                def: field::INVOICE_ID,
                value: FieldValue::Hash256(*id),
            });
        }
        if let Some(ref id) = self.nftoken_id {
            fields.push(Field {
                def: field::NFTOKEN_ID,
                value: FieldValue::Hash256(*id),
            });
        }
        if let Some(ref id) = self.nft_buy_offer {
            fields.push(Field {
                def: field::NFTOKEN_BUY_OFFER,
                value: FieldValue::Hash256(*id),
            });
        }
        if let Some(ref id) = self.nft_sell_offer {
            fields.push(Field {
                def: field::NFTOKEN_SELL_OFFER,
                value: FieldValue::Hash256(*id),
            });
        }
        if let Some(ref amount) = self.nftoken_broker_fee {
            fields.push(Field {
                def: field::NFTOKEN_BROKER_FEE,
                value: FieldValue::Amount(amount.clone()),
            });
        }
        if let Some(taxon) = self.nftoken_taxon {
            fields.push(Field {
                def: field::NFTOKEN_TAXON,
                value: FieldValue::UInt32(taxon),
            });
        }
        if let Some(fee) = self.transfer_fee_field {
            fields.push(Field {
                def: field::TRANSFER_FEE,
                value: FieldValue::UInt16(fee),
            });
        }
        if let Some(fee) = self.trading_fee {
            fields.push(Field {
                def: field::TRADING_FEE,
                value: FieldValue::UInt16(fee),
            });
        }
        if let Some(ref pk) = self.public_key_field {
            fields.push(Field {
                def: field::PUBLIC_KEY,
                value: FieldValue::Blob(pk.clone()),
            });
        }
        if let Some(ref sig) = self.signature_field {
            fields.push(Field {
                def: field::SIGNATURE,
                value: FieldValue::Blob(sig.clone()),
            });
        }
        if let Some(ref key) = self.message_key {
            fields.push(Field {
                def: field::MESSAGE_KEY,
                value: FieldValue::Blob(key.clone()),
            });
        }
        if let Some(ref uri) = self.uri {
            fields.push(Field {
                def: field::URI,
                value: FieldValue::Blob(uri.clone()),
            });
        }
        if let Some(ref asset_class) = self.oracle_asset_class {
            fields.push(Field {
                def: field::ASSET_CLASS,
                value: FieldValue::Blob(asset_class.clone()),
            });
        }
        if let Some(ref provider) = self.oracle_provider {
            fields.push(Field {
                def: field::PROVIDER,
                value: FieldValue::Blob(provider.clone()),
            });
        }
        if let Some(ref metadata) = self.mptoken_metadata {
            fields.push(Field {
                def: field::MPTOKEN_METADATA,
                value: FieldValue::Blob(metadata.clone()),
            });
        }
        if let Some(ref credential_type) = self.credential_type {
            fields.push(Field {
                def: field::CREDENTIAL_TYPE,
                value: FieldValue::Blob(credential_type.clone()),
            });
        }
        if let Some(ref domain) = self.domain {
            fields.push(Field {
                def: field::DOMAIN,
                value: FieldValue::Blob(domain.clone()),
            });
        }
        if let Some(ref document) = self.did_document {
            fields.push(Field {
                def: field::DID_DOCUMENT,
                value: FieldValue::Blob(document.clone()),
            });
        }
        if let Some(ref data) = self.data {
            fields.push(Field {
                def: field::DATA,
                value: FieldValue::Blob(data.clone()),
            });
        }
        if let Some(ref amt) = self.amount {
            let def = if self.tx_type == TransactionType::CheckCreate {
                field::SEND_MAX
            } else {
                field::AMOUNT
            };
            fields.push(Field {
                def,
                value: FieldValue::Amount(amt.clone()),
            });
        }
        if let Some(ref balance) = self.balance {
            fields.push(Field {
                def: field::BALANCE,
                value: FieldValue::Amount(balance.clone()),
            });
        }
        if let Some(ref lmt) = self.limit_amount {
            fields.push(Field {
                def: field::LIMIT_AMOUNT,
                value: FieldValue::Amount(lmt.clone()),
            });
        }
        if let Some(ref tp) = self.taker_pays {
            fields.push(Field {
                def: field::TAKER_PAYS,
                value: FieldValue::Amount(tp.clone()),
            });
        }
        if let Some(ref tg) = self.taker_gets {
            fields.push(Field {
                def: field::TAKER_GETS,
                value: FieldValue::Amount(tg.clone()),
            });
        }
        if let Some(ref amount2) = self.amount2 {
            fields.push(Field {
                def: field::AMOUNT2,
                value: FieldValue::Amount(amount2.clone()),
            });
        }
        if let Some(ref send_max) = self.send_max {
            fields.push(Field {
                def: field::SEND_MAX,
                value: FieldValue::Amount(send_max.clone()),
            });
        }
        if let Some(ref deliver_min) = self.deliver_min {
            fields.push(Field {
                def: field::DELIVER_MIN,
                value: FieldValue::Amount(deliver_min.clone()),
            });
        }
        if let Some(ref bid_min) = self.bid_min {
            fields.push(Field {
                def: field::BID_MIN,
                value: FieldValue::Amount(bid_min.clone()),
            });
        }
        if let Some(ref bid_max) = self.bid_max {
            fields.push(Field {
                def: field::BID_MAX,
                value: FieldValue::Amount(bid_max.clone()),
            });
        }
        if let Some(ref lp_token_out) = self.lp_token_out {
            fields.push(Field {
                def: field::LP_TOKEN_OUT,
                value: FieldValue::Amount(lp_token_out.clone()),
            });
        }
        if let Some(ref lp_token_in) = self.lp_token_in {
            fields.push(Field {
                def: field::LP_TOKEN_IN,
                value: FieldValue::Amount(lp_token_in.clone()),
            });
        }
        if let Some(ref eprice) = self.eprice {
            fields.push(Field {
                def: field::EPRICE,
                value: FieldValue::Amount(eprice.clone()),
            });
        }
        if let Some(dest) = self.destination {
            fields.push(Field {
                def: field::DESTINATION,
                value: FieldValue::AccountID(dest),
            });
        }
        if let Some(regular_key) = self.regular_key {
            fields.push(Field {
                def: field::REGULAR_KEY,
                value: FieldValue::AccountID(regular_key),
            });
        }
        if let Some(minter) = self.nftoken_minter {
            fields.push(Field {
                def: field::NFTOKEN_MINTER,
                value: FieldValue::AccountID(minter),
            });
        }
        if let Some(holder) = self.holder {
            fields.push(Field {
                def: field::HOLDER,
                value: FieldValue::AccountID(holder),
            });
        }
        if let Some(owner) = self.owner {
            fields.push(Field {
                def: field::OWNER,
                value: FieldValue::AccountID(owner),
            });
        }
        if let Some(issuer) = self.issuer {
            fields.push(Field {
                def: field::ISSUER,
                value: FieldValue::AccountID(issuer),
            });
        }
        if let Some(subject) = self.subject {
            fields.push(Field {
                def: field::SUBJECT,
                value: FieldValue::AccountID(subject),
            });
        }
        if let Some(authorize) = self.authorize {
            fields.push(Field {
                def: field::AUTHORIZE,
                value: FieldValue::AccountID(authorize),
            });
        }
        if let Some(unauthorize) = self.unauthorize {
            fields.push(Field {
                def: field::UNAUTHORIZE,
                value: FieldValue::AccountID(unauthorize),
            });
        }
        if let Some(tag) = self.dest_tag {
            fields.push(Field {
                def: field::DESTINATION_TAG,
                value: FieldValue::UInt32(tag),
            });
        }
        if let Some(id) = self.mptoken_issuance_id {
            fields.push(Field {
                def: field::MPTOKEN_ISSUANCE_ID,
                value: FieldValue::UInt192(id),
            });
        }
        if let Some(document_id) = self.oracle_document_id {
            fields.push(Field {
                def: field::ORACLE_DOCUMENT_ID,
                value: FieldValue::UInt32(document_id),
            });
        }
        if let Some(last_update_time) = self.oracle_last_update_time {
            fields.push(Field {
                def: field::LAST_UPDATE_TIME,
                value: FieldValue::UInt32(last_update_time),
            });
        }
        if let Some(ref asset) = self.asset {
            fields.push(Field {
                def: field::ASSET,
                value: FieldValue::Issue(asset.clone()),
            });
        }
        if let Some(ref asset2) = self.asset2 {
            fields.push(Field {
                def: field::ASSET2,
                value: FieldValue::Issue(asset2.clone()),
            });
        }
        if let Some(ref raw) = self.authorize_credentials_raw {
            fields.push(Field {
                def: field::AUTHORIZE_CREDENTIALS,
                value: FieldValue::Raw(raw.clone()),
            });
        }
        if let Some(ref raw) = self.unauthorize_credentials_raw {
            fields.push(Field {
                def: field::UNAUTHORIZE_CREDENTIALS,
                value: FieldValue::Raw(raw.clone()),
            });
        }
        if let Some(ref raw) = self.oracle_price_data_series_raw {
            fields.push(Field {
                def: field::PRICE_DATA_SERIES,
                value: FieldValue::Raw(raw.clone()),
            });
        }
        if let Some(ref raw) = self.signer_entries_raw {
            fields.push(Field {
                def: field::SIGNER_ENTRIES,
                value: FieldValue::Raw(raw.clone()),
            });
        }
        if let Some(sig) = signature {
            fields.push(Field {
                def: field::TXN_SIGNATURE,
                value: FieldValue::Blob(sig),
            });
        }

        fields.extend_from_slice(&self.extra);
        Ok(fields)
    }

    // ── Sign ──────────────────────────────────────────────────────────────────

    /// Sign the transaction with a keypair and return a `SignedTx`.
    pub fn sign(self, kp: &KeyPair) -> Result<SignedTx> {
        // 1. Determine signing pubkey bytes (Ed25519 is prefixed with 0xED on-ledger)
        let signing_pubkey = match kp {
            KeyPair::Ed25519(k) => {
                let mut v = vec![0xED];
                v.extend_from_slice(&k.public_key_bytes());
                v
            }
            KeyPair::Secp256k1(k) => k.public_key_bytes(),
        };

        // 2. Build fields without signature to compute signing data
        let mut fields_for_signing = self.build_fields(signing_pubkey.clone(), None)?;

        // 3. Sign — Ed25519 needs the *raw* signing payload (it hashes internally
        //    via SHA-512), while secp256k1 needs the SHA-512-Half hash.
        let signature = match kp {
            KeyPair::Ed25519(_) => {
                // rippled passes raw (PREFIX_TX_SIGN || serialized_fields) to ed25519_sign.
                let mut payload = PREFIX_TX_SIGN.to_vec();
                payload.extend_from_slice(&serialize_fields(&mut fields_for_signing, true));
                kp.sign(&payload)
            }
            KeyPair::Secp256k1(sk) => {
                // signing_hash returns SHA512Half(STX\0 || fields) — already hashed.
                // Use sign_digest to avoid double-hashing (sign() would hash again).
                let hash_to_sign = signing_hash(&mut fields_for_signing);
                sk.sign_digest(&hash_to_sign)
            }
        };

        // 4. Rebuild with signature included
        let mut fields_final = self.build_fields(signing_pubkey, Some(signature))?;

        // 5. Serialize the full signed transaction
        let blob = serialize_fields(&mut fields_final, false);

        // 6. Compute the transaction hash (ID)
        let hash = {
            use crate::transaction::serialize::PREFIX_TX_ID;
            let mut payload = PREFIX_TX_ID.to_vec();
            payload.extend_from_slice(&blob);
            crate::crypto::sha512_first_half(&payload)
        };

        Ok(SignedTx { hash, blob })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Secp256k1KeyPair;

    fn genesis_keypair() -> KeyPair {
        KeyPair::Secp256k1(
            Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb")
                .expect("genesis seed valid"),
        )
    }

    #[test]
    fn test_payment_signs_without_panic() {
        let kp = genesis_keypair();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .expect("signing should succeed");

        assert_eq!(signed.hash.len(), 32);
        assert!(!signed.blob.is_empty());
        println!("TxHash: {}", signed.hash_hex());
        println!("Blob:   {}", &signed.blob_hex()[..80]);
    }

    #[test]
    fn test_signing_is_deterministic() {
        let kp = genesis_keypair();
        let sign = || {
            TxBuilder::payment()
                .account(&kp)
                .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
                .unwrap()
                .amount(Amount::Xrp(500_000))
                .fee(12)
                .sequence(5)
                .sign(&kp)
                .unwrap()
        };
        let a = sign();
        let b = sign();
        assert_eq!(a.hash, b.hash, "same tx must produce same hash");
        assert_eq!(a.blob, b.blob, "same tx must produce same blob");
    }

    #[test]
    fn test_hash_changes_with_different_fields() {
        let kp = genesis_keypair();
        let a = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();

        let b = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(2_000_000)) // different amount
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();

        assert_ne!(
            a.hash, b.hash,
            "different amounts must produce different hashes"
        );
        assert_ne!(a.blob, b.blob);
    }

    #[test]
    fn test_blob_starts_with_transaction_type_field() {
        let kp = genesis_keypair();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();

        // First field must be TransactionType (field ID 0x12) with value 0x0000 (Payment)
        assert_eq!(
            signed.blob[0], 0x12,
            "first byte must be TransactionType field ID"
        );
        assert_eq!(signed.blob[1], 0x00, "Payment = 0");
        assert_eq!(signed.blob[2], 0x00);
    }

    #[test]
    fn test_destination_tag() {
        let kp = genesis_keypair();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .destination_tag(12345)
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();

        assert!(!signed.blob.is_empty());
    }
}
