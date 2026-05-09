//! Transaction module — types, serialization, signing, and application.

pub mod amount;
pub mod auth;
pub mod builder;
pub mod field;
pub mod master;
pub mod parse;
pub mod serialize;

pub use amount::Amount;
pub use parse::{parse_blob, ParseError, ParsedTx, PathStep};

/// Canonical XRPL transaction type codes for the `TransactionType` field.
/// Verified against `rippled/include/xrpl/protocol/detail/transactions.macro`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TransactionType {
    Payment = 0,
    EscrowCreate = 1,
    EscrowFinish = 2,
    AccountSet = 3,
    EscrowCancel = 4,
    SetRegularKey = 5,
    OfferCreate = 7,
    OfferCancel = 8,
    TicketCreate = 10,
    SignerListSet = 12,
    PaymentChannelCreate = 13,
    PaymentChannelFund = 14,
    PaymentChannelClaim = 15,
    CheckCreate = 16,
    CheckCash = 17,
    CheckCancel = 18,
    DepositPreauth = 19,
    TrustSet = 20,
    AccountDelete = 21,
    NFTokenMint = 25,
    NFTokenBurn = 26,
    NFTokenCreateOffer = 27,
    NFTokenCancelOffer = 28,
    NFTokenAcceptOffer = 29,
    Clawback = 30,
    AMMClawback = 31,
    AMMCreate = 35,
    AMMDeposit = 36,
    AMMWithdraw = 37,
    AMMVote = 38,
    AMMBid = 39,
    AMMDelete = 40,
    DIDSet = 49,
    DIDDelete = 50,
    OracleSet = 51,
    OracleDelete = 52,
    LedgerStateFix = 53,
    MPTokenIssuanceCreate = 54,
    MPTokenIssuanceDestroy = 55,
    MPTokenIssuanceSet = 56,
    MPTokenAuthorize = 57,
    CredentialCreate = 58,
    CredentialAccept = 59,
    CredentialDelete = 60,
    NFTokenModify = 61,
    PermissionedDomainSet = 62,
    PermissionedDomainDelete = 63,
    DelegateSet = 64,
    VaultCreate = 65,
    VaultSet = 66,
    VaultDelete = 67,
    VaultDeposit = 68,
    VaultWithdraw = 69,
    VaultClawback = 70,
    Batch = 71,
    LoanBrokerSet = 74,
    LoanBrokerDelete = 75,
    LoanBrokerCoverDeposit = 76,
    LoanBrokerCoverWithdraw = 77,
    LoanBrokerCoverClawback = 78,
    LoanSet = 80,
    LoanDelete = 81,
    LoanManage = 82,
    LoanPay = 84,
}
