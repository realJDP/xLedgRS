//! XRPL field definitions and field-ID encoding.
//!
//! Every XRPL field has a (type_code, field_code) pair that determines
//! how its ID is encoded in the binary format:
//!
//!   Both < 16  → 1 byte:  (type_code << 4) | field_code
//!   Type ≥ 16  → 2 bytes: (0x00 << 4) | field_code, type_code
//!   Field ≥ 16 → 2 bytes: (type_code << 4) | 0x00, field_code
//!   Both ≥ 16  → 3 bytes: 0x00, type_code, field_code
//!
//! Fields must be sorted by (type_code, field_code) in canonical order
//! before serialization (used when computing signing hashes).

/// XRPL serialized type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum TypeCode {
    UInt16 = 1,
    UInt32 = 2,
    UInt64 = 3,
    Hash128 = 4,
    Hash256 = 5,
    Amount = 6,
    Blob = 7,
    AccountID = 8,
    Number = 9,
    STObject = 14,
    STArray = 15,
    UInt8 = 16,
    Hash160 = 17,
    Vector256 = 19,
    UInt192 = 21,
    Issue = 24,
}

/// A field descriptor: a (type_code, field_code) pair with a human name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldDef {
    pub type_code: u16,
    pub field_code: u16,
    pub name: &'static str,
    /// Fields marked `is_signing = false` are omitted from signing serialization.
    pub is_signing: bool,
}

impl FieldDef {
    /// Canonical sort key: (type_code, field_code).
    pub fn sort_key(self) -> (u16, u16) {
        (self.type_code, self.field_code)
    }

    /// Encode this field's ID into `buf` (1–3 bytes).
    pub fn encode_id(&self, buf: &mut Vec<u8>) {
        let t = self.type_code;
        let f = self.field_code;
        match (t < 16, f < 16) {
            (true, true) => buf.push(((t << 4) | f) as u8),
            (false, true) => {
                buf.push(f as u8);
                buf.push(t as u8);
            }
            (true, false) => {
                buf.push((t << 4) as u8);
                buf.push(f as u8);
            }
            (false, false) => {
                buf.push(0x00);
                buf.push(t as u8);
                buf.push(f as u8);
            }
        }
    }
}

// ── Field catalogue ──────────────────────────────────────────────────────────
// Verified against: rippled/include/xrpl/protocol/detail/sfields.macro

macro_rules! field {
    ($name:ident, $type:expr, $code:expr, $signing:expr) => {
        pub const $name: FieldDef = FieldDef {
            type_code: $type as u16,
            field_code: $code,
            name: stringify!($name),
            is_signing: $signing,
        };
    };
}

// UInt16 fields (type=1)
field!(TRANSACTION_TYPE, TypeCode::UInt16, 2, true);
field!(SIGNER_WEIGHT, TypeCode::UInt16, 3, true); // sfSignerWeight = UINT16, 3
field!(TRANSFER_FEE, TypeCode::UInt16, 4, true); // sfTransferFee = UINT16, 4
field!(TRADING_FEE, TypeCode::UInt16, 5, true); // sfTradingFee = UINT16, 5
field!(LEDGER_FIX_TYPE, TypeCode::UInt16, 21, true); // sfLedgerFixType = UINT16, 21

// UInt32 fields (type=2)
field!(FLAGS, TypeCode::UInt32, 2, true);
field!(SOURCE_TAG, TypeCode::UInt32, 3, true);
field!(SEQUENCE, TypeCode::UInt32, 4, true);
field!(SET_FLAG, TypeCode::UInt32, 33, true);
field!(CLEAR_FLAG, TypeCode::UInt32, 34, true);
field!(EXPIRATION, TypeCode::UInt32, 10, true);
field!(TRANSFER_RATE, TypeCode::UInt32, 11, true);
field!(DESTINATION_TAG, TypeCode::UInt32, 14, true); // sfDestinationTag = UINT32, 14
field!(LAST_UPDATE_TIME, TypeCode::UInt32, 15, true); // sfLastUpdateTime = UINT32, 15
field!(QUALITY_IN, TypeCode::UInt32, 20, true);
field!(QUALITY_OUT, TypeCode::UInt32, 21, true);
field!(OFFER_SEQUENCE, TypeCode::UInt32, 25, true);
field!(LAST_LEDGER_SEQUENCE, TypeCode::UInt32, 27, true);
field!(CANCEL_AFTER, TypeCode::UInt32, 36, true); // sfCancelAfter = UINT32, 36
field!(FINISH_AFTER, TypeCode::UInt32, 37, true); // sfFinishAfter = UINT32, 37
field!(SETTLE_DELAY, TypeCode::UInt32, 39, true);
field!(TICKET_COUNT, TypeCode::UInt32, 40, true); // sfTicketCount = UINT32, 40
field!(TICKET_SEQUENCE, TypeCode::UInt32, 41, true); // sfTicketSequence = UINT32, 41
field!(NFTOKEN_TAXON, TypeCode::UInt32, 42, true); // sfNFTokenTaxon = UINT32, 42
field!(FIRST_NFTOKEN_SEQUENCE, TypeCode::UInt32, 50, true); // sfFirstNFTokenSequence = UINT32, 50
field!(ORACLE_DOCUMENT_ID, TypeCode::UInt32, 51, true); // sfOracleDocumentID = UINT32, 51
field!(MUTABLE_FLAGS, TypeCode::UInt32, 53, true); // sfMutableFlags = UINT32, 53
field!(SIGNER_QUORUM, TypeCode::UInt32, 35, true); // sfSignerQuorum = UINT32, 35

// UInt64 fields (type=3)
// (sfIndexNext=1, sfIndexPrevious=2 — not needed for transaction building)
field!(MAXIMUM_AMOUNT, TypeCode::UInt64, 24, true); // sfMaximumAmount = UINT64, 24

// Hash128 fields (type=4)
field!(EMAIL_HASH, TypeCode::Hash128, 1, true); // sfEmailHash = UINT128, 1

// Number fields (type=9)
field!(ASSETS_MAXIMUM, TypeCode::Number, 3, true); // sfAssetsMaximum = NUMBER, 3

// Hash256 fields (type=5)
field!(ACCOUNT_TXID, TypeCode::Hash256, 9, true);
field!(WALLET_LOCATOR, TypeCode::Hash256, 7, true); // sfWalletLocator = UINT256, 7
field!(NFTOKEN_ID, TypeCode::Hash256, 10, true); // sfNFTokenID = UINT256, 10
field!(INVOICE_ID, TypeCode::Hash256, 17, true);
field!(CHANNEL, TypeCode::Hash256, 22, true); // sfChannel = UINT256, 22
field!(CHECK_ID, TypeCode::Hash256, 24, true); // sfCheckID = UINT256, 24
field!(NFTOKEN_BUY_OFFER, TypeCode::Hash256, 28, true); // sfNFTokenBuyOffer = UINT256, 28
field!(NFTOKEN_SELL_OFFER, TypeCode::Hash256, 29, true); // sfNFTokenSellOffer = UINT256, 29
field!(DOMAIN_ID, TypeCode::Hash256, 34, true); // sfDomainID = UINT256, 34
field!(VAULT_ID, TypeCode::Hash256, 35, true); // sfVaultID = UINT256, 35
field!(LOAN_BROKER_ID, TypeCode::Hash256, 37, true); // sfLoanBrokerID = UINT256, 37
field!(LOAN_ID, TypeCode::Hash256, 38, true); // sfLoanID = UINT256, 38

// Amount fields (type=6)
field!(AMOUNT, TypeCode::Amount, 1, true);
field!(BALANCE, TypeCode::Amount, 2, true); // sfBalance = AMOUNT, 2
field!(LIMIT_AMOUNT, TypeCode::Amount, 3, true);
field!(TAKER_PAYS, TypeCode::Amount, 4, true);
field!(TAKER_GETS, TypeCode::Amount, 5, true);
field!(FEE, TypeCode::Amount, 8, true);
field!(SEND_MAX, TypeCode::Amount, 9, true);
field!(DELIVER_MIN, TypeCode::Amount, 10, true);
field!(AMOUNT2, TypeCode::Amount, 11, true); // sfAmount2 = AMOUNT, 11
field!(BID_MIN, TypeCode::Amount, 12, true); // sfBidMin = AMOUNT, 12
field!(BID_MAX, TypeCode::Amount, 13, true); // sfBidMax = AMOUNT, 13
field!(NFTOKEN_BROKER_FEE, TypeCode::Amount, 19, true); // sfNFTokenBrokerFee = AMOUNT, 19
field!(LP_TOKEN_OUT, TypeCode::Amount, 25, true); // sfLPTokenOut = AMOUNT, 25
field!(LP_TOKEN_IN, TypeCode::Amount, 26, true); // sfLPTokenIn = AMOUNT, 26
field!(EPRICE, TypeCode::Amount, 27, true); // sfEPrice = AMOUNT, 27

// Issue fields (type=24)
field!(ASSET, TypeCode::Issue, 3, true); // sfAsset = ISSUE, 3
field!(ASSET2, TypeCode::Issue, 4, true); // sfAsset2 = ISSUE, 4

// Blob/VL fields (type=7)
field!(PUBLIC_KEY, TypeCode::Blob, 1, true); // sfPublicKey = VL, 1
field!(MESSAGE_KEY, TypeCode::Blob, 2, true); // sfMessageKey = VL, 2
field!(SIGNING_PUB_KEY, TypeCode::Blob, 3, true);
field!(TXN_SIGNATURE, TypeCode::Blob, 4, false); // excluded from signing hash
field!(URI, TypeCode::Blob, 5, true); // sfURI = VL, 5
field!(SIGNATURE, TypeCode::Blob, 6, false); // sfSignature = VL, 6 (notSigning)
field!(DOMAIN, TypeCode::Blob, 7, true);
field!(MEMO_TYPE, TypeCode::Blob, 12, true);
field!(MEMO_DATA, TypeCode::Blob, 13, true);
field!(DID_DOCUMENT, TypeCode::Blob, 26, true); // sfDIDDocument = VL, 26
field!(DATA, TypeCode::Blob, 27, true); // sfData = VL, 27
field!(ASSET_CLASS, TypeCode::Blob, 28, true); // sfAssetClass = VL, 28
field!(PROVIDER, TypeCode::Blob, 29, true); // sfProvider = VL, 29
field!(MPTOKEN_METADATA, TypeCode::Blob, 30, true); // sfMPTokenMetadata = VL, 30
field!(CREDENTIAL_TYPE, TypeCode::Blob, 31, true); // sfCredentialType = VL, 31

// UInt8 fields (type=16)
field!(ASSET_SCALE, TypeCode::UInt8, 5, true); // sfAssetScale = UINT8, 5
field!(TICK_SIZE, TypeCode::UInt8, 16, true); // sfTickSize = UINT8, 16

// UInt192 fields (type=21)
field!(MPTOKEN_ISSUANCE_ID, TypeCode::UInt192, 1, true); // sfMPTokenIssuanceID = UINT192, 1

// AccountID fields (type=8)
field!(ACCOUNT, TypeCode::AccountID, 1, true);
field!(OWNER, TypeCode::AccountID, 2, true);
field!(DESTINATION, TypeCode::AccountID, 3, true);
field!(ISSUER, TypeCode::AccountID, 4, true);
field!(AUTHORIZE, TypeCode::AccountID, 5, true); // sfAuthorize = ACCOUNT, 5
field!(UNAUTHORIZE, TypeCode::AccountID, 6, true); // sfUnauthorize = ACCOUNT, 6
field!(REGULAR_KEY, TypeCode::AccountID, 8, true); // sfRegularKey = ACCOUNT, 8
field!(NFTOKEN_MINTER, TypeCode::AccountID, 9, true); // sfNFTokenMinter = ACCOUNT, 9
field!(HOLDER, TypeCode::AccountID, 11, true); // sfHolder = ACCOUNT, 11
field!(SUBJECT, TypeCode::AccountID, 24, true); // sfSubject = ACCOUNT, 24

// STObject sentinels
field!(OBJECT_END_MARKER, TypeCode::STObject, 1, true);
field!(AUTH_ACCOUNT, TypeCode::STObject, 27, true); // sfAuthAccount = OBJECT, 27
                                                    // STArray sentinels
field!(ARRAY_END_MARKER, TypeCode::STArray, 1, true);
field!(AUTH_ACCOUNTS, TypeCode::STArray, 25, true); // sfAuthAccounts = ARRAY, 25
field!(SIGNER_ENTRIES, TypeCode::STArray, 4, true); // sfSignerEntries = ARRAY, 4
field!(PRICE_DATA_SERIES, TypeCode::STArray, 24, true); // sfPriceDataSeries = ARRAY, 24
field!(AUTHORIZE_CREDENTIALS, TypeCode::STArray, 26, true); // sfAuthorizeCredentials = ARRAY, 26
field!(UNAUTHORIZE_CREDENTIALS, TypeCode::STArray, 27, true); // sfUnauthorizeCredentials = ARRAY, 27
