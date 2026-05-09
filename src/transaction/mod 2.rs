//! Transaction module — types, serialization, signing, and application.

pub mod amount;
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
    AMMCreate = 35,
    AMMDeposit = 36,
    AMMWithdraw = 37,
    AMMVote = 38,
    AMMBid = 39,
    AMMDelete = 40,
    DelegateSet = 64,
    Batch = 71,
}
