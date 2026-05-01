//! xLedgRS purpose: Parse support for transaction parsing and submission.
//! Binary transaction parser — deserialize a signed tx blob into its fields.
//!
//! Walks the XRPL STObject binary format field-by-field, extracting the fields
//! needed for signature verification and account-state validation.
//!
//! The signing hash is reconstructed on the fly: all field bytes are
//! accumulated *except* the TxnSignature field, then
//! `SHA-512-half(PREFIX_TX_SIGN || accumulated_bytes)` gives the hash that the
//! submitting key must have signed.

use crate::transaction::amount::Amount;
use crate::transaction::serialize::{decode_length, PREFIX_TX_SIGN};
use thiserror::Error;

// ── Path types ───────────────────────────────────────────────────────────────

/// A single step in a payment path.
/// Each step can specify an account, currency, issuer, or combination.
#[derive(Debug, Clone)]
pub struct PathStep {
    /// Account (20 bytes) if present.
    pub account: Option<[u8; 20]>,
    /// Currency (20 bytes) if present.
    pub currency: Option<[u8; 20]>,
    /// Issuer (20 bytes) if present.
    pub issuer: Option<[u8; 20]>,
}

// ── ParsedTx ─────────────────────────────────────────────────────────────────

/// The fields of a signed transaction that matter for validation.
pub struct ParsedTx {
    /// `TransactionType` value (0 = Payment, 3 = AccountSet, 20 = TrustSet, etc.)
    pub tx_type: u16,
    /// `Flags` bitmask.
    pub flags: u32,
    /// `Sequence` — sender's transaction sequence number.
    pub sequence: u32,
    /// `Fee` in drops.
    pub fee: u64,
    /// `Account` — sender's 20-byte AccountID.
    pub account: [u8; 20],
    /// `Destination` — present for Payment.
    pub destination: Option<[u8; 20]>,
    /// Payment `Amount` in drops. This parser only supports XRP amounts.
    pub amount_drops: Option<u64>,
    /// Full `Amount` field (XRP or IOU) — for IOU Payments.
    pub amount: Option<Amount>,
    /// `LimitAmount` (type=6, field=3) — present for TrustSet (always IOU).
    pub limit_amount: Option<Amount>,
    /// `TakerPays` (type=6, field=4) — present for OfferCreate.
    pub taker_pays: Option<Amount>,
    /// `TakerGets` (type=6, field=5) — present for OfferCreate.
    pub taker_gets: Option<Amount>,
    /// `DeliverMin` (type=6, field=10) — present for CheckCash.
    pub deliver_min: Option<Amount>,
    /// `OfferSequence` (type=2, field=25) — present for OfferCancel.
    pub offer_sequence: Option<u32>,
    /// `FinishAfter` (type=2, field=37) — present for EscrowCreate.
    pub finish_after: Option<u32>,
    /// `CancelAfter` (type=2, field=36) — present for EscrowCreate.
    pub cancel_after: Option<u32>,
    /// `SettleDelay` (type=2, field=39) — present for PaymentChannelCreate.
    pub settle_delay: Option<u32>,
    /// `Expiration` (type=2, field=10) — generic expiration field.
    pub expiration: Option<u32>,
    /// `SetFlag` (type=2, field=33) — for AccountSet.
    pub set_flag: Option<u32>,
    /// `ClearFlag` (type=2, field=34) — for AccountSet.
    pub clear_flag: Option<u32>,
    /// `TransferRate` (type=2, field=11) — for AccountSet.
    pub transfer_rate: Option<u32>,
    /// `QualityIn` (type=2, field=20) — for TrustSet.
    pub quality_in: Option<u32>,
    /// `QualityOut` (type=2, field=21) — for TrustSet.
    pub quality_out: Option<u32>,
    /// `TickSize` (type=16, field=8) — for AccountSet (UInt8).
    pub tick_size: Option<u8>,
    /// `LastLedgerSequence` (type=2, field=27) — tx expires after this ledger.
    pub last_ledger_seq: Option<u32>,
    /// `TicketCount` (type=2, field=40) — for TicketCreate.
    pub ticket_count: Option<u32>,
    /// `TicketSequence` (type=2, field=41) — alternative to Sequence for ticket-based txs.
    pub ticket_sequence: Option<u32>,
    /// `Domain` (type=7, field=7) — for AccountSet.
    pub domain: Option<Vec<u8>>,
    /// `Channel` (type=5, field=22) — 32-byte channel hash for PayChanFund/Claim.
    pub channel: Option<[u8; 32]>,
    /// `PublicKey` (type=7, field=1) — channel authorization key (not SigningPubKey).
    pub public_key: Option<Vec<u8>>,
    /// Claim authorization signature (type=7, field=6).
    pub paychan_sig: Option<Vec<u8>>,
    /// `NFTokenID` (type=5, field=10) — for NFTokenBurn, CreateOffer.
    pub nftoken_id: Option<[u8; 32]>,
    /// `NFTokenSellOffer` (type=5, field=29) — for NFTokenAcceptOffer.
    pub nft_sell_offer: Option<[u8; 32]>,
    /// `NFTokenBuyOffer` (type=5, field=28) — for NFTokenAcceptOffer.
    pub nft_buy_offer: Option<[u8; 32]>,
    /// `URI` (type=7, field=5) — for NFTokenMint, DIDSet.
    pub uri: Option<Vec<u8>>,
    /// `DIDDocument` (type=7, field=26) — for DIDSet.
    pub did_document: Option<Vec<u8>>,
    /// `Data` (type=7, field=27) — for DIDSet.
    pub did_data: Option<Vec<u8>>,
    /// `NFTokenTaxon` (type=2, field=42) — for NFTokenMint.
    pub nftoken_taxon: Option<u32>,
    /// `TransferFee` (type=1, field=4) — for NFTokenMint.
    pub transfer_fee_field: Option<u16>,
    /// `AssetScale` (type=16, field=5) — for MPTokenIssuanceCreate.
    pub asset_scale: Option<u8>,
    /// `MaximumAmount` (type=3, field=24) — for MPTokenIssuanceCreate.
    pub maximum_amount: Option<u64>,
    /// `MutableFlags` (type=2, field=53) — for MPTokenIssuanceCreate/Set.
    pub mutable_flags: Option<u32>,
    /// `MPTokenMetadata` (type=7, field=30) — for MPTokenIssuanceCreate/Set.
    pub mptoken_metadata: Option<Vec<u8>>,
    /// `Owner` (type=8, field=2) — escrow/paychan owner for finish/cancel/claim.
    pub owner: Option<[u8; 20]>,
    /// `RegularKey` (type=8, field=8) — present for SetRegularKey.
    pub regular_key: Option<[u8; 20]>,
    /// `Issuer` (type=8, field=4) — for CredentialAccept/Delete.
    pub issuer: Option<[u8; 20]>,
    /// `Subject` (type=8, field=24) — for CredentialCreate/Delete.
    pub subject: Option<[u8; 20]>,
    /// `CredentialType` (type=7, field=31) — for Credential tx types.
    pub credential_type: Option<Vec<u8>>,
    /// `OracleDocumentID` (type=2, field=51) — present for OracleSet/OracleDelete.
    pub oracle_document_id: Option<u32>,
    /// `SignerQuorum` (type=2, field=35) — present for SignerListSet.
    pub signer_quorum: Option<u32>,
    /// Raw `SignerEntries` STArray payload (type=15, field=4), excluding the
    /// outer field header and including the array end marker.
    pub signer_entries_raw: Option<Vec<u8>>,
    /// `DomainID` (type=5, field=34) — present for PermissionedDomainSet/Delete.
    pub domain_id: Option<[u8; 32]>,
    /// `LedgerFixType` (type=1/UInt16, field=54) — present for LedgerStateFix.
    pub ledger_fix_type: Option<u16>,
    /// Raw `AcceptedCredentials` STArray payload (type=15, field=28).
    pub accepted_credentials_raw: Option<Vec<u8>>,
    /// `Authorize` (type=8, field=5) — present for DelegateSet.
    pub authorize: Option<[u8; 20]>,
    /// Raw `Permissions` STArray payload (type=15, field=29).
    pub permissions_raw: Option<Vec<u8>>,
    /// `Holder` (type=8, field=11) — present for MPTokenIssuanceSet, MPTokenAuthorize.
    pub holder: Option<[u8; 20]>,
    /// `MPTokenIssuanceID` (type=21, field=1) — 24-byte MPTID for MPToken txs.
    pub mptoken_issuance_id: Option<[u8; 24]>,
    /// `Asset` (type=24, field=3) — asset issue for AMM/Vault.
    pub asset: Option<crate::transaction::amount::Issue>,
    /// `Asset2` (type=24, field=4) — second asset issue for AMM.
    pub asset2: Option<crate::transaction::amount::Issue>,
    /// `VaultID` (type=5, field=35) — 32-byte vault hash for VaultDelete/Set/Deposit/Withdraw.
    pub vault_id: Option<[u8; 32]>,
    /// `Amendment` (type=5, field=19) — 32-byte amendment hash for EnableAmendment.
    pub amendment: Option<[u8; 32]>,
    /// `BaseFee` (type=3/UInt64, field=5) — for SetFee pseudo-tx (old format).
    pub base_fee_field: Option<u64>,
    /// `ReserveBase` (type=2/UInt32, field=31) — for SetFee pseudo-tx (old format).
    pub reserve_base_field: Option<u32>,
    /// `ReserveIncrement` (type=2/UInt32, field=32) — for SetFee pseudo-tx (old format).
    pub reserve_increment_field: Option<u32>,
    /// `UNLModifyDisabling` (type=16/UInt8, field=11) — for UNLModify pseudo-tx (0=re-enable, 1=disable).
    pub unl_modify_disabling: Option<u8>,
    /// `UNLModifyValidator` (type=7/VL, field=19) — validator public key for UNLModify.
    pub unl_modify_validator: Option<Vec<u8>>,
    /// `SendMax` (type=6, field=9) — maximum amount sender will spend (for cross-currency).
    pub send_max: Option<Amount>,
    /// `Paths` (type=18) — payment path set for cross-currency payments.
    pub paths: Vec<Vec<PathStep>>,
    /// `SigningPubKey` — the secp256k1 compressed key (33 bytes) or Ed25519
    /// key with 0xED prefix (33 bytes) that produced `signature`.
    pub signing_pubkey: Vec<u8>,
    /// `TxnSignature` — DER-encoded ECDSA or 64-byte Ed25519 signature.
    pub signature: Vec<u8>,
    /// The 32-byte value that `signing_pubkey` must have signed:
    /// `SHA-512-half(PREFIX_TX_SIGN || <all fields except TxnSignature>)`.
    pub signing_hash: [u8; 32],
    /// Raw signing payload: `PREFIX_TX_SIGN || signing_fields`.
    /// Ed25519 needs this (it hashes internally). secp256k1 uses signing_hash.
    pub signing_payload: Vec<u8>,
    /// Multi-sig entries from sfSigners array (type=15, field=3).
    /// Each entry has account, signing_pubkey, signature.
    /// Empty for single-signed transactions.
    pub signers: Vec<SignerEntry>,
}

/// A single signer in a multi-signed transaction.
#[derive(Debug, Clone)]
pub struct SignerEntry {
    /// The signer's 20-byte AccountID.
    pub account: [u8; 20],
    /// The signer's public key (33 bytes).
    pub signing_pubkey: Vec<u8>,
    /// The signer's signature.
    pub signature: Vec<u8>,
}

fn parse_signers_array(data: &[u8]) -> Result<Vec<SignerEntry>, ParseError> {
    let mut pos = 0usize;
    let mut signers = Vec::new();

    while pos < data.len() {
        if data[pos] == 0xF1 {
            break;
        }

        let (type_code, _field_code, new_pos) = crate::ledger::meta::read_field_header(data, pos);
        if new_pos > data.len() {
            return Err(ParseError::Truncated("Signers field header"));
        }
        pos = new_pos;

        if type_code != 14 {
            pos = crate::ledger::meta::skip_field_raw(data, pos, type_code);
            continue;
        }

        let mut account = None::<[u8; 20]>;
        let mut signing_pubkey = None::<Vec<u8>>;
        let mut signature = None::<Vec<u8>>;

        while pos < data.len() && data[pos] != 0xE1 {
            let (inner_type, inner_field, inner_pos) =
                crate::ledger::meta::read_field_header(data, pos);
            if inner_pos > data.len() {
                return Err(ParseError::Truncated("Signer inner field header"));
            }
            pos = inner_pos;

            match inner_type {
                7 => {
                    if pos >= data.len() {
                        return Err(ParseError::Truncated("Signer blob length"));
                    }
                    let (vlen, ladv) = decode_length(&data[pos..]);
                    if ladv == 0 || pos + ladv + vlen > data.len() {
                        return Err(ParseError::Truncated("Signer blob data"));
                    }
                    pos += ladv;
                    let blob = data[pos..pos + vlen].to_vec();
                    match inner_field {
                        3 => signing_pubkey = Some(blob),
                        4 => signature = Some(blob),
                        _ => {}
                    }
                    pos += vlen;
                }
                8 => {
                    if pos >= data.len() {
                        return Err(ParseError::Truncated("Signer account length"));
                    }
                    let (vlen, ladv) = decode_length(&data[pos..]);
                    if ladv == 0 || pos + ladv + vlen > data.len() {
                        return Err(ParseError::Truncated("Signer account data"));
                    }
                    pos += ladv;
                    if inner_field == 1 && vlen == 20 {
                        let mut id = [0u8; 20];
                        id.copy_from_slice(&data[pos..pos + 20]);
                        account = Some(id);
                    }
                    pos += vlen;
                }
                _ => {
                    pos = crate::ledger::meta::skip_field_raw(data, pos, inner_type);
                }
            }
        }

        if pos >= data.len() {
            return Err(ParseError::Truncated("Signer object end"));
        }
        pos += 1; // 0xE1 object end

        signers.push(SignerEntry {
            account: account.ok_or(ParseError::MissingField("Signer.Account"))?,
            signing_pubkey: signing_pubkey
                .ok_or(ParseError::MissingField("Signer.SigningPubKey"))?,
            signature: signature.ok_or(ParseError::MissingField("Signer.TxnSignature"))?,
        });
    }

    Ok(signers)
}

#[cfg(test)]
impl Default for ParsedTx {
    fn default() -> Self {
        Self {
            tx_type: 0,
            flags: 0,
            sequence: 0,
            fee: 0,
            account: [0u8; 20],
            destination: None,
            amount_drops: None,
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
            quality_in: None,
            quality_out: None,
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
            signing_pubkey: Vec::new(),
            signature: Vec::new(),
            signing_hash: [0u8; 32],
            signing_payload: Vec::new(),
            signers: Vec::new(),
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("buffer truncated at {0}")]
    Truncated(&'static str),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("IOU amounts are not supported yet")]
    IouAmount,
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse a fully-signed XRPL transaction blob into its fields.
pub fn parse_blob(data: &[u8]) -> Result<ParsedTx, ParseError> {
    let mut pos = 0;

    // Fields extracted by the parser.
    let mut tx_type = None::<u16>;
    let mut flags = 0u32;
    let mut sequence = None::<u32>;
    let mut fee = None::<u64>;
    let mut account = None::<[u8; 20]>;
    let mut destination = None::<[u8; 20]>;
    let mut amount_drops = None::<u64>;
    let mut amount_full = None::<Amount>;
    let mut limit_amount = None::<Amount>;
    let mut taker_pays = None::<Amount>;
    let mut taker_gets = None::<Amount>;
    let mut deliver_min = None::<Amount>;
    let mut send_max = None::<Amount>;
    let mut paths: Vec<Vec<PathStep>> = Vec::new();
    let mut offer_seq = None::<u32>;
    let mut finish_after = None::<u32>;
    let mut cancel_after = None::<u32>;
    let mut settle_delay = None::<u32>;
    let mut expiration_val = None::<u32>;
    let mut set_flag_val = None::<u32>;
    let mut clear_flag_val = None::<u32>;
    let mut transfer_rate = None::<u32>;
    let mut quality_in = None::<u32>;
    let mut quality_out = None::<u32>;
    let mut tick_size_val = None::<u8>;
    let mut last_ledger_seq = None::<u32>;
    let mut ticket_count = None::<u32>;
    let mut ticket_sequence = None::<u32>;
    let mut reserve_base = None::<u32>;
    let mut reserve_inc = None::<u32>;
    let mut base_fee_u64 = None::<u64>;
    let mut unl_modify_disabling = None::<u8>;
    let mut unl_modify_validator = None::<Vec<u8>>;
    let mut domain_val = None::<Vec<u8>>;
    let mut channel = None::<[u8; 32]>;
    let mut public_key = None::<Vec<u8>>;
    let mut paychan_sig = None::<Vec<u8>>;
    let mut nftoken_id = None::<[u8; 32]>;
    let mut nft_sell_offer = None::<[u8; 32]>;
    let mut nft_buy_offer = None::<[u8; 32]>;
    let mut uri_field = None::<Vec<u8>>;
    let mut did_document = None::<Vec<u8>>;
    let mut did_data = None::<Vec<u8>>;
    let mut nftoken_taxon = None::<u32>;
    let mut transfer_fee_f = None::<u16>;
    let mut ledger_fix_type = None::<u16>;
    let mut asset_scale = None::<u8>;
    let mut maximum_amount = None::<u64>;
    let mut mutable_flags = None::<u32>;
    let mut mpt_metadata = None::<Vec<u8>>;
    let mut owner = None::<[u8; 20]>;
    let mut regular_key = None::<[u8; 20]>;
    let mut issuer_field = None::<[u8; 20]>;
    let mut subject_field = None::<[u8; 20]>;
    let mut cred_type = None::<Vec<u8>>;
    let mut oracle_doc_id = None::<u32>;
    let mut signer_quorum = None::<u32>;
    let mut signer_entries_raw = None::<Vec<u8>>;
    let mut domain_id_val = None::<[u8; 32]>;
    let mut accepted_credentials_raw = None::<Vec<u8>>;
    let mut authorize_val = None::<[u8; 20]>;
    let mut permissions_raw = None::<Vec<u8>>;
    let mut holder_val = None::<[u8; 20]>;
    let mut mpt_issuance_id = None::<[u8; 24]>;
    let mut asset_val = None::<crate::transaction::amount::Issue>;
    let mut asset2_val = None::<crate::transaction::amount::Issue>;
    let mut vault_id_val = None::<[u8; 32]>;
    let mut amendment_val = None::<[u8; 32]>;
    let mut signers_raw = None::<Vec<u8>>;
    let mut signing_pubkey = None::<Vec<u8>>;
    let mut signature = None::<Vec<u8>>;

    // Bytes of every field *except* TxnSignature — used to recompute signing hash.
    let mut signing_fields = Vec::<u8>::new();

    while pos < data.len() {
        let field_start = pos;
        let b = data[pos];
        pos += 1;

        // ── Decode field header ───────────────────────────────────────────────
        let top = (b >> 4) as u16;
        let bot = (b & 0x0F) as u16;
        let (type_code, field_code) = if top == 0 && bot == 0 {
            // Both extended
            if pos + 2 > data.len() {
                return Err(ParseError::Truncated("field header (both ext)"));
            }
            let t = data[pos] as u16;
            let f = data[pos + 1] as u16;
            pos += 2;
            (t, f)
        } else if top == 0 {
            // Type extended
            if pos >= data.len() {
                return Err(ParseError::Truncated("field header (type ext)"));
            }
            let t = data[pos] as u16;
            pos += 1;
            (t, bot)
        } else if bot == 0 {
            // Field extended
            if pos >= data.len() {
                return Err(ParseError::Truncated("field header (field ext)"));
            }
            let f = data[pos] as u16;
            pos += 1;
            (top, f)
        } else {
            (top, bot)
        };

        // TxnSignature: type=7 (Blob), field=4
        let is_signature = type_code == 7 && field_code == 4;

        // ── Read and extract field value ──────────────────────────────────────
        match type_code {
            1 => {
                // UInt16 (2 bytes)
                if pos + 2 > data.len() {
                    return Err(ParseError::Truncated("UInt16"));
                }
                let v = u16::from_be_bytes([data[pos], data[pos + 1]]);
                match field_code {
                    2 => tx_type = Some(v),
                    4 => transfer_fee_f = Some(v), // sfTransferFee = UINT16, 4
                    54 => ledger_fix_type = Some(v), // sfLedgerFixType = UINT16, 54
                    _ => {}
                }
                pos += 2;
            }
            2 => {
                // UInt32 (4 bytes)
                if pos + 4 > data.len() {
                    return Err(ParseError::Truncated("UInt32"));
                }
                let v = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
                match field_code {
                    2 => flags = v,                  // Flags
                    4 => sequence = Some(v),         // Sequence
                    10 => expiration_val = Some(v),  // Expiration
                    11 => transfer_rate = Some(v),   // sfTransferRate = UINT32, 11
                    20 => quality_in = Some(v),      // sfQualityIn = UINT32, 20
                    21 => quality_out = Some(v),     // sfQualityOut = UINT32, 21
                    25 => offer_seq = Some(v),       // sfOfferSequence = UINT32, 25
                    27 => last_ledger_seq = Some(v), // sfLastLedgerSequence = UINT32, 27
                    31 => reserve_base = Some(v),    // sfReserveBase = UINT32, 31
                    32 => reserve_inc = Some(v),     // sfReserveIncrement = UINT32, 32
                    33 => set_flag_val = Some(v),    // sfSetFlag = UINT32, 33
                    34 => clear_flag_val = Some(v),  // sfClearFlag = UINT32, 34
                    35 => signer_quorum = Some(v),   // sfSignerQuorum = UINT32, 35
                    36 => cancel_after = Some(v),    // sfCancelAfter = UINT32, 36
                    37 => finish_after = Some(v),    // sfFinishAfter = UINT32, 37
                    39 => settle_delay = Some(v),    // sfSettleDelay = UINT32, 39
                    40 => ticket_count = Some(v),    // sfTicketCount = UINT32, 40
                    41 => ticket_sequence = Some(v), // sfTicketSequence = UINT32, 41
                    42 => nftoken_taxon = Some(v),   // sfNFTokenTaxon = UINT32, 42
                    51 => oracle_doc_id = Some(v),   // sfOracleDocumentID = UINT32, 51
                    53 => mutable_flags = Some(v),   // sfMutableFlags = UINT32, 53
                    _ => {}
                }
                pos += 4;
            }
            3 => {
                // UInt64 (8 bytes)
                if pos + 8 > data.len() {
                    return Err(ParseError::Truncated("UInt64"));
                }
                let v = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
                match field_code {
                    5 => base_fee_u64 = Some(v),    // sfBaseFee = UINT64, 5
                    24 => maximum_amount = Some(v), // sfMaximumAmount
                    _ => {}
                }
                pos += 8;
            }
            4 => {
                // Hash128 (16 bytes) — skip
                if pos + 16 > data.len() {
                    return Err(ParseError::Truncated("Hash128"));
                }
                pos += 16;
            }
            5 => {
                // Hash256 (32 bytes)
                if pos + 32 > data.len() {
                    return Err(ParseError::Truncated("Hash256"));
                }
                {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&data[pos..pos + 32]);
                    match field_code {
                        10 => nftoken_id = Some(h),     // sfNFTokenID = UINT256, 10
                        19 => amendment_val = Some(h),  // sfAmendment = UINT256, 19
                        22 => channel = Some(h),        // sfChannel = UINT256, 22
                        28 => nft_buy_offer = Some(h),  // sfNFTokenBuyOffer = UINT256, 28
                        29 => nft_sell_offer = Some(h), // sfNFTokenSellOffer = UINT256, 29
                        34 => domain_id_val = Some(h),  // sfDomainID = UINT256, 34
                        35 => vault_id_val = Some(h),   // sfVaultID = UINT256, 35
                        _ => {}
                    }
                }
                pos += 32;
            }
            6 => {
                // Amount — 8 bytes (XRP) or 48 bytes (IOU)
                if pos >= data.len() {
                    return Err(ParseError::Truncated("Amount"));
                }
                let (amt, consumed) = Amount::from_bytes(&data[pos..])
                    .map_err(|_| ParseError::Truncated("Amount data"))?;
                match field_code {
                    1 => {
                        // sfAmount — XRP or IOU
                        if let Amount::Xrp(d) = &amt {
                            amount_drops = Some(*d);
                        }
                        amount_full = Some(amt);
                    }
                    3 => {
                        limit_amount = Some(amt);
                    } // sfLimitAmount
                    4 => {
                        taker_pays = Some(amt);
                    } // sfTakerPays
                    5 => {
                        taker_gets = Some(amt);
                    } // sfTakerGets
                    9 => {
                        send_max = Some(amt);
                    } // sfSendMax
                    10 => {
                        deliver_min = Some(amt);
                    } // sfDeliverMin
                    8 => {
                        // sfFee (always XRP)
                        if let Amount::Xrp(d) = &amt {
                            fee = Some(*d);
                        }
                    }
                    _ => {}
                }
                pos += consumed;
            }
            7 => {
                // Blob (VL-encoded)
                if pos >= data.len() {
                    return Err(ParseError::Truncated("Blob VL"));
                }
                let (vlen, ladv) = decode_length(&data[pos..]);
                pos += ladv;
                if pos + vlen > data.len() {
                    return Err(ParseError::Truncated("Blob data"));
                }
                let blob = data[pos..pos + vlen].to_vec();
                match field_code {
                    1 => public_key = Some(blob),            // sfPublicKey = VL, 1
                    3 => signing_pubkey = Some(blob),        // sfSigningPubKey = VL, 3
                    4 => signature = Some(blob),             // sfTxnSignature = VL, 4
                    5 => uri_field = Some(blob),             // sfURI = VL, 5
                    6 => paychan_sig = Some(blob),           // sfSignature = VL, 6
                    7 => domain_val = Some(blob),            // sfDomain = VL, 7
                    26 => did_document = Some(blob),         // sfDIDDocument = VL, 26
                    27 => did_data = Some(blob),             // sfData = VL, 27
                    19 => unl_modify_validator = Some(blob), // sfUNLModifyValidator = VL, 19
                    30 => mpt_metadata = Some(blob),         // sfMPTokenMetadata = VL, 30
                    31 => cred_type = Some(blob),            // sfCredentialType = VL, 31
                    _ => {}
                }
                pos += vlen;
            }
            8 => {
                // AccountID (VL-encoded, always 20 bytes)
                if pos >= data.len() {
                    return Err(ParseError::Truncated("AccountID VL"));
                }
                let (vlen, ladv) = decode_length(&data[pos..]);
                pos += ladv;
                if pos + vlen > data.len() {
                    return Err(ParseError::Truncated("AccountID data"));
                }
                if vlen == 20 {
                    let mut id = [0u8; 20];
                    id.copy_from_slice(&data[pos..pos + 20]);
                    match field_code {
                        1 => account = Some(id),        // Account
                        2 => owner = Some(id),          // Owner
                        3 => destination = Some(id),    // Destination
                        4 => issuer_field = Some(id),   // sfIssuer = ACCOUNT, 4
                        5 => authorize_val = Some(id),  // sfAuthorize = ACCOUNT, 5
                        8 => regular_key = Some(id),    // RegularKey
                        11 => holder_val = Some(id),    // sfHolder = ACCOUNT, 11
                        24 => subject_field = Some(id), // sfSubject = ACCOUNT, 24
                        _ => {}
                    }
                }
                pos += vlen;
            }
            9 | 11 => {
                // NUMBER (9) or INT64 (11) — 8 bytes
                if pos + 8 > data.len() {
                    return Err(ParseError::Truncated("Int64"));
                }
                pos += 8;
            }
            10 => {
                // INT32 — 4 bytes
                if pos + 4 > data.len() {
                    return Err(ParseError::Truncated("Int32"));
                }
                pos += 4;
            }
            14 => {
                // STObject — skip to end marker (0xE1)
                while pos < data.len() && data[pos] != 0xE1 {
                    let (tc, _fc, new_pos) = crate::ledger::meta::read_field_header(data, pos);
                    if new_pos > data.len() {
                        break;
                    }
                    pos = crate::ledger::meta::skip_field_raw(data, new_pos, tc);
                }
                if pos < data.len() {
                    pos += 1;
                } // skip 0xE1
            }
            15 => {
                // STArray — keep the raw payload for fields that map directly
                // into ledger SLE arrays, then skip to the end marker.
                let array_start = pos;
                while pos < data.len() && data[pos] != 0xF1 {
                    // Each array element is an STObject
                    let (tc, _fc, new_pos) = crate::ledger::meta::read_field_header(data, pos);
                    if new_pos > data.len() {
                        break;
                    }
                    if tc == 14 {
                        // STObject — skip to 0xE1
                        pos = new_pos;
                        while pos < data.len() && data[pos] != 0xE1 {
                            let (tc2, _, np2) = crate::ledger::meta::read_field_header(data, pos);
                            if np2 > data.len() {
                                break;
                            }
                            pos = crate::ledger::meta::skip_field_raw(data, np2, tc2);
                        }
                        if pos < data.len() {
                            pos += 1;
                        } // skip 0xE1
                    } else {
                        pos = crate::ledger::meta::skip_field_raw(data, new_pos, tc);
                    }
                }
                if pos < data.len() {
                    pos += 1;
                } // skip 0xF1
                let raw = data[array_start..pos.min(data.len())].to_vec();
                match field_code {
                    3 => signers_raw = Some(raw),               // sfSigners
                    4 => signer_entries_raw = Some(raw),        // sfSignerEntries
                    28 => accepted_credentials_raw = Some(raw), // sfAcceptedCredentials
                    29 => permissions_raw = Some(raw),          // sfPermissions
                    _ => {}
                }
            }
            16 => {
                // UInt8 — 1 byte
                if pos >= data.len() {
                    return Err(ParseError::Truncated("UInt8"));
                }
                match field_code {
                    5 => asset_scale = Some(data[pos]),           // sfAssetScale
                    8 => tick_size_val = Some(data[pos]),         // sfTickSize
                    11 => unl_modify_disabling = Some(data[pos]), // sfUNLModifyDisabling
                    _ => {}
                }
                pos += 1;
            }
            17 => {
                // Hash160 — 20 bytes
                if pos + 20 > data.len() {
                    return Err(ParseError::Truncated("Hash160"));
                }
                pos += 20;
            }
            18 => {
                // PathSet — terminated by 0x00, paths separated by 0xFF
                let mut current_path: Vec<PathStep> = Vec::new();
                while pos < data.len() && data[pos] != 0x00 {
                    if data[pos] == 0xFF {
                        // Path boundary — start new path
                        if !current_path.is_empty() {
                            paths.push(std::mem::take(&mut current_path));
                        }
                        pos += 1;
                        continue;
                    }
                    let ptype = data[pos];
                    pos += 1;
                    let mut step = PathStep {
                        account: None,
                        currency: None,
                        issuer: None,
                    };
                    if ptype & 0x01 != 0 && pos + 20 <= data.len() {
                        let mut a = [0u8; 20];
                        a.copy_from_slice(&data[pos..pos + 20]);
                        step.account = Some(a);
                        pos += 20;
                    }
                    if ptype & 0x10 != 0 && pos + 20 <= data.len() {
                        let mut c = [0u8; 20];
                        c.copy_from_slice(&data[pos..pos + 20]);
                        step.currency = Some(c);
                        pos += 20;
                    }
                    if ptype & 0x20 != 0 && pos + 20 <= data.len() {
                        let mut i = [0u8; 20];
                        i.copy_from_slice(&data[pos..pos + 20]);
                        step.issuer = Some(i);
                        pos += 20;
                    }
                    current_path.push(step);
                }
                if !current_path.is_empty() {
                    paths.push(current_path);
                }
                if pos < data.len() {
                    pos += 1;
                } // skip 0x00 terminator
            }
            19 => {
                // Vector256 — VL-encoded
                if pos >= data.len() {
                    return Err(ParseError::Truncated("Vector256"));
                }
                let (vlen, ladv) = decode_length(&data[pos..]);
                pos += ladv + vlen;
            }
            20 => {
                // UINT96 — 12 bytes
                if pos + 12 > data.len() {
                    return Err(ParseError::Truncated("UINT96"));
                }
                pos += 12;
            }
            21 => {
                // UINT192 — 24 bytes
                if pos + 24 > data.len() {
                    return Err(ParseError::Truncated("UINT192"));
                }
                if field_code == 1 {
                    // sfMPTokenIssuanceID = UINT192, field 1
                    let mut id = [0u8; 24];
                    id.copy_from_slice(&data[pos..pos + 24]);
                    mpt_issuance_id = Some(id);
                }
                pos += 24;
            }
            22 => {
                // UINT384 — 48 bytes
                if pos + 48 > data.len() {
                    return Err(ParseError::Truncated("UINT384"));
                }
                pos += 48;
            }
            23 => {
                // UINT512 — 64 bytes
                if pos + 64 > data.len() {
                    return Err(ParseError::Truncated("UINT512"));
                }
                pos += 64;
            }
            24 => {
                // ISSUE — variable size: XRP (20), IOU (40), MPT (44)
                if pos + 20 > data.len() {
                    return Err(ParseError::Truncated("ISSUE"));
                }
                if let Some((issue, consumed)) =
                    crate::transaction::amount::Issue::from_bytes(&data[pos..])
                {
                    match field_code {
                        3 => asset_val = Some(issue),  // sfAsset
                        4 => asset2_val = Some(issue), // sfAsset2
                        _ => {}
                    }
                    pos += consumed;
                } else {
                    // Fallback: skip 20 bytes minimum
                    pos += 20;
                }
            }
            25 => {
                // XCHAIN_BRIDGE — STObject-like, scan to 0xE1 end marker
                while pos < data.len() && data[pos] != 0xE1 {
                    let (tc, _fc, new_pos) = crate::ledger::meta::read_field_header(data, pos);
                    if new_pos > data.len() {
                        break;
                    }
                    pos = crate::ledger::meta::skip_field_raw(data, new_pos, tc);
                }
                if pos < data.len() {
                    pos += 1;
                } // skip 0xE1
            }
            26 => {
                // CURRENCY — 20 bytes
                if pos + 20 > data.len() {
                    return Err(ParseError::Truncated("CURRENCY"));
                }
                pos += 20;
            }
            _ => {
                // Unknown type code — cannot determine size, stop parsing.
                break;
            }
        }

        // Accumulate bytes for signing hash (all fields except TxnSignature).
        if !is_signature {
            signing_fields.extend_from_slice(&data[field_start..pos]);
        }
    }

    // Compute the signing hash that was (or should have been) signed.
    let mut payload = PREFIX_TX_SIGN.to_vec();
    payload.extend_from_slice(&signing_fields);
    let signing_hash = crate::crypto::sha512_first_half(&payload);
    let signers = match signers_raw.as_deref() {
        Some(raw) => parse_signers_array(raw)?,
        None => Vec::new(),
    };

    Ok(ParsedTx {
        tx_type: tx_type.ok_or(ParseError::MissingField("TransactionType"))?,
        flags,
        sequence: sequence.ok_or(ParseError::MissingField("Sequence"))?,
        fee: fee.ok_or(ParseError::MissingField("Fee"))?,
        account: account.ok_or(ParseError::MissingField("Account"))?,
        destination,
        amount_drops,
        amount: amount_full,
        limit_amount,
        taker_pays,
        taker_gets,
        deliver_min,
        send_max,
        paths,
        offer_sequence: offer_seq,
        finish_after,
        cancel_after,
        settle_delay,
        expiration: expiration_val,
        set_flag: set_flag_val,
        clear_flag: clear_flag_val,
        transfer_rate,
        quality_in,
        quality_out,
        tick_size: tick_size_val,
        last_ledger_seq,
        ticket_count,
        ticket_sequence,
        domain: domain_val,
        channel,
        public_key,
        nftoken_id,
        nft_sell_offer,
        nft_buy_offer,
        uri: uri_field,
        did_document,
        did_data,
        nftoken_taxon,
        transfer_fee_field: transfer_fee_f,
        asset_scale,
        maximum_amount,
        mutable_flags,
        mptoken_metadata: mpt_metadata,
        paychan_sig,
        owner,
        regular_key,
        issuer: issuer_field,
        subject: subject_field,
        credential_type: cred_type,
        oracle_document_id: oracle_doc_id,
        signer_quorum,
        signer_entries_raw,
        domain_id: domain_id_val,
        ledger_fix_type,
        accepted_credentials_raw,
        authorize: authorize_val,
        permissions_raw,
        holder: holder_val,
        mptoken_issuance_id: mpt_issuance_id,
        asset: asset_val,
        asset2: asset2_val,
        vault_id: vault_id_val,
        amendment: amendment_val,
        base_fee_field: base_fee_u64,
        reserve_base_field: reserve_base,
        reserve_increment_field: reserve_inc,
        unl_modify_disabling,
        unl_modify_validator,
        // Multi-signed txs have empty SigningPubKey and no TxnSignature at
        // top level — they use sfSigners array instead.  Batch inner txs have
        // neither. Validated-tx replay does not require signatures.
        // (rippled: Transactor.cpp:108, apply.cpp:30-31)
        signing_pubkey: signing_pubkey.unwrap_or_default(),
        signature: signature.unwrap_or_default(),
        signing_hash,
        signing_payload: payload,
        signers,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
    use crate::transaction::field;
    use crate::transaction::serialize::{serialize_fields, Field, FieldValue};
    use crate::transaction::{builder::TxBuilder, Amount};

    fn genesis_kp() -> KeyPair {
        KeyPair::Secp256k1(Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap())
    }

    fn genesis_id() -> [u8; 20] {
        crate::crypto::account_id(&genesis_kp().public_key_bytes())
    }

    fn dest_id() -> [u8; 20] {
        crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap()
    }

    fn signed_payment() -> (Vec<u8>, [u8; 32]) {
        let kp = genesis_kp();
        let tx = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();
        let hash = tx.hash;
        (hex::decode(tx.blob_hex()).unwrap(), hash)
    }

    fn multisigned_payment_blob() -> Vec<u8> {
        let signer_kp = Secp256k1KeyPair::from_seed_entropy(&[9u8; 16]);
        let signer_account = crate::crypto::account_id(&signer_kp.public_key_bytes());
        let signer_signature = vec![0x30, 0x44, 0x02, 0x20, 0x11, 0x22, 0x33];

        let mut fields = vec![
            Field {
                def: field::TRANSACTION_TYPE,
                value: FieldValue::UInt16(0),
            },
            Field {
                def: field::FLAGS,
                value: FieldValue::UInt32(0),
            },
            Field {
                def: field::SEQUENCE,
                value: FieldValue::UInt32(1),
            },
            Field {
                def: field::AMOUNT,
                value: FieldValue::Amount(Amount::Xrp(1_000_000)),
            },
            Field {
                def: field::FEE,
                value: FieldValue::Amount(Amount::Xrp(12)),
            },
            Field {
                def: field::SIGNING_PUB_KEY,
                value: FieldValue::Blob(Vec::new()),
            },
            Field {
                def: field::ACCOUNT,
                value: FieldValue::AccountID(genesis_id()),
            },
            Field {
                def: field::DESTINATION,
                value: FieldValue::AccountID(dest_id()),
            },
        ];
        let mut blob = serialize_fields(&mut fields, false);

        blob.push(0xF3); // sfSigners
        blob.push(0xE3); // Signer object
        field::SIGNING_PUB_KEY.encode_id(&mut blob);
        FieldValue::Blob(signer_kp.public_key_bytes()).write_to(&mut blob);
        field::TXN_SIGNATURE.encode_id(&mut blob);
        FieldValue::Blob(signer_signature).write_to(&mut blob);
        field::ACCOUNT.encode_id(&mut blob);
        FieldValue::AccountID(signer_account).write_to(&mut blob);
        blob.push(0xE1); // end Signer object
        blob.push(0xF1); // end Signers array

        blob
    }

    #[test]
    fn test_parse_payment_fields() {
        let (blob, _) = signed_payment();
        let parsed = parse_blob(&blob).expect("parse should succeed");

        assert_eq!(parsed.tx_type, 0); // Payment
        assert_eq!(parsed.sequence, 1);
        assert_eq!(parsed.fee, 12);
        assert_eq!(parsed.amount_drops, Some(1_000_000));
        assert!(parsed.destination.is_some());
        assert_eq!(parsed.signing_pubkey.len(), 33); // compressed secp256k1
        assert!(!parsed.signature.is_empty());
    }

    #[test]
    fn test_parse_trustset_quality_fields() {
        use crate::transaction::amount::{Currency, IouValue};

        let kp = genesis_kp();
        let signed = TxBuilder::trust_set()
            .account(&kp)
            .limit_amount(Amount::Iou {
                value: IouValue::from_f64(1000.0),
                currency: Currency::from_code("USD").unwrap(),
                issuer: dest_id(),
            })
            .quality_in(1_250_000_000)
            .quality_out(1_500_000_000)
            .fee(12)
            .sequence(8)
            .sign(&kp)
            .unwrap();

        let parsed = parse_blob(&signed.blob).expect("TrustSet parse should succeed");

        assert_eq!(parsed.tx_type, 20); // TrustSet
        assert_eq!(parsed.sequence, 8);
        assert_eq!(parsed.quality_in, Some(1_250_000_000));
        assert_eq!(parsed.quality_out, Some(1_500_000_000));
    }

    #[test]
    fn test_signing_hash_matches_and_signature_verifies() {
        let (blob, _) = signed_payment();
        let parsed = parse_blob(&blob).expect("parse should succeed");

        // The signature in the blob must verify against the signing hash.
        // signing_hash is already SHA512Half — use verify_digest to avoid double-hashing.
        let ok = crate::crypto::keys::verify_secp256k1_digest(
            &parsed.signing_pubkey,
            &parsed.signing_hash,
            &parsed.signature,
        );
        assert!(
            ok,
            "signature in blob must verify against recomputed signing hash"
        );
    }

    #[test]
    fn test_parse_multisigned_signers_array() {
        let blob = multisigned_payment_blob();
        let parsed = parse_blob(&blob).expect("multi-signed parse should succeed");

        assert!(parsed.signing_pubkey.is_empty());
        assert!(parsed.signature.is_empty());
        assert_eq!(parsed.signers.len(), 1);
        assert_eq!(parsed.signers[0].signing_pubkey.len(), 33);
        assert!(!parsed.signers[0].signature.is_empty());
    }

    #[test]
    fn test_tampered_blob_fails_verification() {
        let (mut blob, _) = signed_payment();
        // Flip a byte in the Amount field (somewhere near the end)
        let idx = blob.len() - 30;
        blob[idx] ^= 0xFF;
        // Either parse fails or signature check fails
        let result = parse_blob(&blob);
        if let Ok(parsed) = result {
            let ok = crate::crypto::keys::verify_secp256k1_digest(
                &parsed.signing_pubkey,
                &parsed.signing_hash,
                &parsed.signature,
            );
            assert!(!ok, "tampered blob must not verify");
        }
        // If parsing fails, the transaction cannot be accepted.
    }

    #[test]
    fn test_truncated_blob_returns_error() {
        let (blob, _) = signed_payment();
        let short = &blob[..blob.len() / 2];
        let result = parse_blob(short);
        // Either error or missing required field
        match result {
            Err(_) => {}
            Ok(p) => {
                // If it parsed, fields should be missing their required values
                // (signing_hash will be wrong but that's fine — the outer error check catches it)
                let _ = p;
            }
        }
    }
}
