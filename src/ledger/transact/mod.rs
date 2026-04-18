//! Transactor — three-stage transaction application pipeline matching rippled.
//!
//! Every transaction goes through:
//!   1. **preflight** — format validation, signature check (no state access)
//!   2. **preclaim** — fee sufficiency, sequence/ticket, state preconditions (read-only)
//!   3. **doApply** — actual state changes (mutable ApplyView)
//!
//! The Transactor handles the common logic: fee deduction, sequence bump,
//! PreviousTxnID threading, and metadata generation. Individual tx types
//! implement the `TxHandler` trait for type-specific logic.
//!
//! Matches rippled's Transactor base class.

use crate::ledger::apply_view_impl::{AffectedNodeInfo, ApplyViewImpl};
use crate::ledger::keylet;
use crate::ledger::open_view::OpenView;
use crate::ledger::views::{ApplyFlags, ApplyView, ReadView};
use crate::transaction::ParsedTx;
use std::sync::Arc;

// ── Handler modules ────────────────────────────────────────────────────────
pub mod account_delete;
pub mod account_set;
pub mod amm;
pub mod batch;
pub mod check;
pub mod clawback;
pub mod credential;
pub mod delegate;
pub mod deposit_preauth;
pub mod did;
pub mod escrow;
pub mod ledger_state_fix;
pub mod loan;
pub mod mptoken;
pub mod nftoken;
pub mod nftoken_accept;
pub mod nftoken_modify;
pub mod offer_cancel;
pub mod offer_create;
pub mod oracle;
pub(crate) mod owner_dir;
pub mod paychan;
pub mod payment;
pub mod permissioned_domain;
pub mod pseudo;
pub(crate) mod ripple_calc;
pub mod set_regular_key;
pub mod signer_list;
pub mod ticket_create;
pub mod trust_set;
pub mod vault;
pub mod xchain;

// ── Re-exports ─────────────────────────────────────────────────────────────
pub use account_delete::AccountDeleteHandler;
pub use account_set::{account_set_flag_to_ledger, AccountSetHandler};
pub use amm::{
    AMMBidHandler, AMMClawbackHandler, AMMCreateHandler, AMMDeleteHandler, AMMDepositHandler,
    AMMVoteHandler, AMMWithdrawHandler,
};
pub use batch::BatchHandler;
pub use check::{CheckCancelHandler, CheckCashHandler, CheckCreateHandler};
pub use clawback::ClawbackHandler;
pub use credential::{CredentialAcceptHandler, CredentialCreateHandler, CredentialDeleteHandler};
pub use delegate::DelegateSetHandler;
pub use deposit_preauth::DepositPreauthHandler;
pub use did::{DIDDeleteHandler, DIDSetHandler};
pub use escrow::{EscrowCancelHandler, EscrowCreateHandler, EscrowFinishHandler};
pub use ledger_state_fix::LedgerStateFixHandler;
pub use loan::{
    LoanBrokerDeleteHandler, LoanBrokerSetHandler, LoanCoverHandler, LoanDeleteHandler,
    LoanManageHandler, LoanPayHandler, LoanSetHandler,
};
pub use mptoken::{
    MPTokenAuthorizeHandler, MPTokenIssuanceCreateHandler, MPTokenIssuanceDestroyHandler,
    MPTokenIssuanceSetHandler,
};
pub use nftoken::{NFTokenBurnHandler, NFTokenCreateOfferHandler, NFTokenMintHandler};
pub use nftoken_accept::{NFTokenAcceptOfferHandler, NFTokenCancelOfferHandler};
pub use nftoken_modify::NFTokenModifyHandler;
pub use offer_cancel::OfferCancelHandler;
pub use offer_create::OfferCreateHandler;
pub use oracle::{OracleDeleteHandler, OracleSetHandler};
pub use paychan::{PayChanClaimHandler, PayChanCreateHandler, PayChanFundHandler};
pub use payment::PaymentHandler;
pub use permissioned_domain::{PermissionedDomainDeleteHandler, PermissionedDomainSetHandler};
pub use pseudo::{EnableAmendmentHandler, SetFeeHandler, UNLModifyHandler};
pub use set_regular_key::SetRegularKeyHandler;
pub use signer_list::SignerListSetHandler;
pub use ticket_create::TicketCreateHandler;
pub use trust_set::{extract_iou_issuer, TrustSetHandler};
pub use vault::{
    VaultClawbackHandler, VaultCreateHandler, VaultDeleteHandler, VaultDepositHandler,
    VaultSetHandler, VaultWithdrawHandler,
};
pub use xchain::XChainHandler;

// ── TER codes ───────────────────────────────────────────────────────────────

/// Transaction Engine Result — matches rippled's TER codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TER {
    /// tesSUCCESS — applied successfully
    Success,
    /// tec* — claimed fee, failed to apply (state conditions not met)
    ClaimedCost(TecCode),
    /// tef* — local failure, fee not claimed
    LocalFail(&'static str),
    /// tem* — malformed transaction
    Malformed(&'static str),
    /// ter* — retry
    Retry(&'static str),
}

impl TER {
    /// Is this a success result?
    pub fn is_success(&self) -> bool {
        matches!(self, TER::Success)
    }

    /// Does this result claim the fee? (tesSUCCESS and tec* both claim)
    pub fn claims_fee(&self) -> bool {
        matches!(self, TER::Success | TER::ClaimedCost(_))
    }
}

/// tec* error codes (fee claimed but tx effects not applied).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TecCode {
    NoTarget,
    NoEntry,
    InsufficientReserve,
    NoDst,
    NoDstInsuf,
    PathDry,
    Unfunded,
    UnfundedOffer,
    DirFull,
    OwnersFull,
    DuplicateEntry,
    Generic(&'static str),
}

impl std::fmt::Display for TecCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TecCode::NoTarget => write!(f, "tecNO_TARGET"),
            TecCode::NoEntry => write!(f, "tecNO_ENTRY"),
            TecCode::InsufficientReserve => write!(f, "tecINSUFFICIENT_RESERVE"),
            TecCode::NoDst => write!(f, "tecNO_DST"),
            TecCode::NoDstInsuf => write!(f, "tecNO_DST_INSUF"),
            TecCode::PathDry => write!(f, "tecPATH_DRY"),
            TecCode::Unfunded => write!(f, "tecUNFUNDED"),
            TecCode::UnfundedOffer => write!(f, "tecUNFUNDED_OFFER"),
            TecCode::DirFull => write!(f, "tecDIR_FULL"),
            TecCode::OwnersFull => write!(f, "tecOWNERS"),
            TecCode::DuplicateEntry => write!(f, "tecDUPLICATE"),
            TecCode::Generic(s) => write!(f, "{s}"),
        }
    }
}

// ── TxHandler trait ─────────────────────────────────────────────────────────

/// Trait implemented by each transaction type (Payment, TrustSet, etc.).
///
/// The Transactor calls these methods in order. Each may fail early,
/// preventing later stages from running.
pub trait TxHandler {
    /// Type-specific format validation (no state access).
    /// Return Err for malformed transactions.
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        let _ = tx;
        Ok(())
    }

    /// Type-specific state precondition checks (read-only view).
    /// Return Err if the transaction can't possibly succeed.
    fn preclaim(&self, tx: &ParsedTx, view: &dyn ReadView) -> Result<(), TER> {
        let _ = (tx, view);
        Ok(())
    }

    /// Type-specific state changes (mutable view).
    /// The sender's fee and sequence are already handled by the Transactor.
    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER;
}

// ── Transactor ──────────────────────────────────────────────────────────────

/// The result of applying a transaction through the Transactor.
pub struct TxApplyResult {
    /// The transaction result code.
    pub ter: TER,
    /// Metadata (affected nodes) if the fee was claimed.
    pub metadata: Option<Vec<AffectedNodeInfo>>,
}

/// Apply a transaction through the three-stage pipeline.
///
/// This is the main entry point for transaction application.
/// Creates an ApplyViewImpl, runs the pipeline, and either commits
/// or discards based on the result.
pub fn apply_transaction(
    open_view: &mut OpenView,
    tx: &ParsedTx,
    tx_hash: &[u8; 32],
    handler: &dyn TxHandler,
    flags: ApplyFlags,
) -> TxApplyResult {
    // ── Stage 1: Preflight ──────────────────────────────────────────────
    // Format validation, no state access.
    if let Err(ter) = handler.preflight(tx) {
        return TxApplyResult {
            ter,
            metadata: None,
        };
    }

    // ── Stage 2: Preclaim ───────────────────────────────────────────────
    // Read-only state checks.

    // Check sender account exists
    let sender_keylet = keylet::account(&tx.account);
    if !open_view.exists(&sender_keylet) {
        return TxApplyResult {
            ter: TER::LocalFail("terNO_ACCOUNT"),
            metadata: None,
        };
    }

    // Type-specific preclaim
    if let Err(ter) = handler.preclaim(tx, open_view) {
        return TxApplyResult {
            ter,
            metadata: None,
        };
    }

    // ── Stage 3: doApply ────────────────────────────────────────────────
    // Create a per-transaction view
    let mut view = ApplyViewImpl::new(open_view, flags);

    // Load sender account
    let sender_sle = match view.peek(&sender_keylet) {
        Some(sle) => sle,
        None => {
            view.discard();
            return TxApplyResult {
                ter: TER::LocalFail("terNO_ACCOUNT"),
                metadata: None,
            };
        }
    };

    // Deduct fee
    let balance = sender_sle.balance_xrp().unwrap_or(0);
    if balance < tx.fee {
        view.discard();
        return TxApplyResult {
            ter: TER::LocalFail("terINSUF_FEE_B"),
            metadata: None,
        };
    }

    let mut sender = (*sender_sle).clone();
    sender.set_balance_xrp(balance - tx.fee);

    // Bump sequence
    if let Some(seq) = sender.sequence() {
        sender.set_sequence(seq + 1);
    }

    // Thread PreviousTxnID
    sender.set_previous_txn_id(tx_hash);
    // PreviousTxnLgrSeq set by the caller (close_ledger) from the ledger seq

    // Persist sender with fee+sequence+threading changes
    view.update(Arc::new(sender));

    // Run type-specific logic
    let ter = handler.do_apply(tx, &mut view);

    // ── Commit or discard ───────────────────────────────────────────────
    if ter.claims_fee() {
        // Commit: flush to OpenView and collect metadata
        let result = view.apply();
        TxApplyResult {
            ter,
            metadata: Some(result.affected_nodes),
        }
    } else {
        // Discard: transaction had no effect (not even fee claimed)
        view.discard();
        TxApplyResult {
            ter,
            metadata: None,
        }
    }
}

// ── Explicit unsupported handlers for legacy view-stack close ───────────────

/// The runtime close path now uses `ledger::close` / `ledger::tx`.
/// If the legacy view-stack transactor is asked to execute an unknown type,
/// reject it up front instead of fabricating a success result.
pub struct UnsupportedHandler;

impl TxHandler for UnsupportedHandler {
    fn preflight(&self, _tx: &ParsedTx) -> Result<(), TER> {
        Err(TER::Malformed("temUNKNOWN"))
    }

    fn do_apply(&self, _tx: &ParsedTx, _view: &mut dyn ApplyView) -> TER {
        TER::Malformed("temUNKNOWN")
    }
}

/// Known legacy transactor paths that were previously papered over by
/// metadata patching now fail explicitly so the old close path cannot
/// silently report a successful application.
pub(crate) fn legacy_path_not_supported() -> TER {
    TER::LocalFail("tefNOT_SUPPORTED")
}

/// Get the handler for a given transaction type code.
/// Check if an account can afford the reserve for additional owned objects.
/// Returns Ok if balance covers base_reserve + (owner_count + additional) * reserve_inc.
/// Returns Err(tecINSUFFICIENT_RESERVE) if not.
/// Check if an account can afford the reserve for additional owned objects.
/// balance >= reserve_base + (owner_count + additional) * reserve_inc
pub fn check_reserve(
    balance: u64,
    owner_count: u32,
    additional: u32,
    fees: &crate::ledger::fees::Fees,
) -> Result<(), TER> {
    let required =
        fees.reserve_base + ((owner_count as u64 + additional as u64) * fees.reserve_inc);
    if balance < required {
        Err(TER::ClaimedCost(TecCode::InsufficientReserve))
    } else {
        Ok(())
    }
}

pub fn handler_for_type(tx_type: u16) -> Box<dyn TxHandler> {
    match tx_type {
        0 => Box::new(PaymentHandler),
        1 => Box::new(EscrowCreateHandler),
        2 => Box::new(EscrowFinishHandler),
        3 => Box::new(AccountSetHandler),
        4 => Box::new(EscrowCancelHandler),
        5 => Box::new(SetRegularKeyHandler),
        7 => Box::new(OfferCreateHandler),
        8 => Box::new(OfferCancelHandler),
        10 => Box::new(TicketCreateHandler),
        12 => Box::new(SignerListSetHandler),
        13 => Box::new(PayChanCreateHandler),
        14 => Box::new(PayChanFundHandler),
        15 => Box::new(PayChanClaimHandler),
        16 => Box::new(CheckCreateHandler),
        17 => Box::new(CheckCashHandler),
        18 => Box::new(CheckCancelHandler),
        19 => Box::new(DepositPreauthHandler),
        20 => Box::new(TrustSetHandler),
        21 => Box::new(AccountDeleteHandler),
        25 => Box::new(NFTokenMintHandler),
        26 => Box::new(NFTokenBurnHandler),
        27 => Box::new(NFTokenCreateOfferHandler),
        28 => Box::new(NFTokenCancelOfferHandler),
        29 => Box::new(NFTokenAcceptOfferHandler),
        30 => Box::new(ClawbackHandler),
        31 => Box::new(AMMClawbackHandler),
        35 => Box::new(AMMCreateHandler),
        36 => Box::new(AMMDepositHandler),
        37 => Box::new(AMMWithdrawHandler),
        38 => Box::new(AMMVoteHandler),
        39 => Box::new(AMMBidHandler),
        40 => Box::new(AMMDeleteHandler),
        41..=48 => Box::new(XChainHandler),
        49 => Box::new(DIDSetHandler),
        50 => Box::new(DIDDeleteHandler),
        51 => Box::new(OracleSetHandler),
        52 => Box::new(OracleDeleteHandler),
        53 => Box::new(LedgerStateFixHandler),
        54 => Box::new(MPTokenIssuanceCreateHandler),
        55 => Box::new(MPTokenIssuanceDestroyHandler),
        56 => Box::new(MPTokenIssuanceSetHandler),
        57 => Box::new(MPTokenAuthorizeHandler),
        58 => Box::new(CredentialCreateHandler),
        59 => Box::new(CredentialAcceptHandler),
        60 => Box::new(CredentialDeleteHandler),
        61 => Box::new(NFTokenModifyHandler),
        62 => Box::new(PermissionedDomainSetHandler),
        63 => Box::new(PermissionedDomainDeleteHandler),
        64 => Box::new(DelegateSetHandler),
        65 => Box::new(VaultCreateHandler),
        66 => Box::new(VaultSetHandler),
        67 => Box::new(VaultDeleteHandler),
        68 => Box::new(VaultDepositHandler),
        69 => Box::new(VaultWithdrawHandler),
        70 => Box::new(VaultClawbackHandler),
        71 => Box::new(BatchHandler),
        74 => Box::new(LoanBrokerSetHandler),
        75 => Box::new(LoanBrokerDeleteHandler),
        76..=78 => Box::new(LoanCoverHandler),
        80 => Box::new(LoanSetHandler),
        81 => Box::new(LoanDeleteHandler),
        82 => Box::new(LoanManageHandler),
        84 => Box::new(LoanPayHandler),
        100 => Box::new(SetFeeHandler),
        101 => Box::new(EnableAmendmentHandler),
        102 => Box::new(UNLModifyHandler),
        _ => Box::new(UnsupportedHandler),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::ledger_core::ClosedLedger;
    use crate::ledger::open_view::OpenView;
    use crate::ledger::sle::{LedgerEntryType, SLE};
    use crate::ledger::views::RawView;

    fn make_account_data(account_id: &[u8; 20], balance: u64, sequence: u32) -> Vec<u8> {
        let mut data = Vec::new();
        crate::ledger::meta::write_field_header(&mut data, 1, 1);
        data.extend_from_slice(&0x0061u16.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 2, 2);
        data.extend_from_slice(&0u32.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 2, 4);
        data.extend_from_slice(&sequence.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 2, 13);
        data.extend_from_slice(&0u32.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 6, 2);
        let balance_wire = balance | 0x4000_0000_0000_0000;
        data.extend_from_slice(&balance_wire.to_be_bytes());
        crate::ledger::meta::write_field_header(&mut data, 8, 1);
        crate::ledger::meta::encode_vl_length(&mut data, 20);
        data.extend_from_slice(account_id);
        data
    }

    fn setup_ledger_with_account(account_id: &[u8; 20], balance: u64) -> ClosedLedger {
        let mut ledger = ClosedLedger::genesis();
        let kl = keylet::account(account_id);
        let data = make_account_data(account_id, balance, 1);
        ledger.raw_insert(Arc::new(SLE::new(
            kl.key,
            LedgerEntryType::AccountRoot,
            data,
        )));
        ledger
    }

    #[test]
    fn test_payment_xrp_existing_dest() {
        let alice = [0xAA; 20];
        let bob = [0xBB; 20];

        let mut base = setup_ledger_with_account(&alice, 100_000_000);
        let bob_kl = keylet::account(&bob);
        let bob_data = make_account_data(&bob, 50_000_000, 1);
        base.raw_insert(Arc::new(SLE::new(
            bob_kl.key,
            LedgerEntryType::AccountRoot,
            bob_data,
        )));

        let mut open = OpenView::new(Arc::new(base));

        let tx = ParsedTx {
            tx_type: 0,
            account: alice,
            fee: 10,
            amount_drops: Some(1_000_000),
            destination: Some(bob),
            ..ParsedTx::default()
        };

        let tx_hash = [0x01; 32];
        let result = apply_transaction(&mut open, &tx, &tx_hash, &PaymentHandler, ApplyFlags::NONE);
        assert!(result.ter.is_success());
        assert!(result.metadata.is_some());

        // Check balances via ReadView
        let alice_sle = open.read(&keylet::account(&alice)).unwrap();
        let bob_sle = open.read(&keylet::account(&bob)).unwrap();
        // Alice: 100M - 10 (fee) - 1M (payment) = 98,999,990
        assert_eq!(alice_sle.balance_xrp(), Some(98_999_990));
        // Bob: 50M + 1M = 51M
        assert_eq!(bob_sle.balance_xrp(), Some(51_000_000));
    }

    #[test]
    fn test_payment_creates_new_account() {
        let alice = [0xAA; 20];
        let charlie = [0xCC; 20];

        let base = setup_ledger_with_account(&alice, 100_000_000);
        let mut open = OpenView::new(Arc::new(base));

        let tx = ParsedTx {
            tx_type: 0,
            account: alice,
            fee: 10,
            amount_drops: Some(20_000_000), // > reserve_base (10M)
            destination: Some(charlie),
            ..ParsedTx::default()
        };

        let tx_hash = [0x02; 32];
        let result = apply_transaction(&mut open, &tx, &tx_hash, &PaymentHandler, ApplyFlags::NONE);
        assert!(result.ter.is_success());

        // Charlie should exist now
        let charlie_sle = open.read(&keylet::account(&charlie)).unwrap();
        assert_eq!(charlie_sle.balance_xrp(), Some(20_000_000));
        assert_eq!(charlie_sle.sequence(), Some(1));
    }

    #[test]
    fn test_insufficient_balance() {
        let alice = [0xAA; 20];
        let bob = [0xBB; 20];

        let base = setup_ledger_with_account(&alice, 1_000); // only 1000 drops
        let bob_data = make_account_data(&bob, 50_000_000, 1);
        let mut base_mut = base;
        let bob_kl = keylet::account(&bob);
        base_mut.raw_insert(Arc::new(SLE::new(
            bob_kl.key,
            LedgerEntryType::AccountRoot,
            bob_data,
        )));

        let mut open = OpenView::new(Arc::new(base_mut));

        let tx = ParsedTx {
            tx_type: 0,
            account: alice,
            fee: 10,
            amount_drops: Some(5_000_000), // way more than balance
            destination: Some(bob),
            ..ParsedTx::default()
        };

        let tx_hash = [0x03; 32];
        let result = apply_transaction(&mut open, &tx, &tx_hash, &PaymentHandler, ApplyFlags::NONE);
        assert!(matches!(result.ter, TER::ClaimedCost(TecCode::Unfunded)));
    }

    #[test]
    fn test_account_set_flags() {
        let alice = [0xAA; 20];
        let base = setup_ledger_with_account(&alice, 100_000_000);
        let mut open = OpenView::new(Arc::new(base));

        let tx = ParsedTx {
            tx_type: 3,
            account: alice,
            fee: 10,
            set_flag: Some(1), // asfRequireDest -> lsfRequireDestTag (0x00010000)
            ..ParsedTx::default()
        };

        let tx_hash = [0x05; 32];
        let result = apply_transaction(
            &mut open,
            &tx,
            &tx_hash,
            &AccountSetHandler,
            ApplyFlags::NONE,
        );
        assert!(result.ter.is_success());

        let alice_sle = open.read(&keylet::account(&alice)).unwrap();
        assert_eq!(alice_sle.flags() & 0x00010000, 0x00010000); // RequireDestTag set
    }

    #[test]
    fn test_account_set_transfer_rate() {
        let alice = [0xAA; 20];
        let base = setup_ledger_with_account(&alice, 100_000_000);
        let mut open = OpenView::new(Arc::new(base));

        let tx = ParsedTx {
            tx_type: 3,
            account: alice,
            fee: 10,
            transfer_rate: Some(1_200_000_000), // 20% transfer fee
            ..ParsedTx::default()
        };

        let tx_hash = [0x06; 32];
        let result = apply_transaction(
            &mut open,
            &tx,
            &tx_hash,
            &AccountSetHandler,
            ApplyFlags::NONE,
        );
        assert!(result.ter.is_success());

        let alice_sle = open.read(&keylet::account(&alice)).unwrap();
        assert_eq!(alice_sle.get_field_u32(2, 11), Some(1_200_000_000));
    }

    #[test]
    fn test_escrow_create() {
        let alice = [0xAA; 20];
        let bob = [0xBB; 20];
        let base = setup_ledger_with_account(&alice, 100_000_000);
        let mut open = OpenView::new(Arc::new(base));

        let tx = ParsedTx {
            tx_type: 1,
            account: alice,
            fee: 10,
            amount_drops: Some(10_000_000),
            destination: Some(bob),
            finish_after: Some(1000),
            ..ParsedTx::default()
        };

        let tx_hash = [0x07; 32];
        let result = apply_transaction(
            &mut open,
            &tx,
            &tx_hash,
            &EscrowCreateHandler,
            ApplyFlags::NONE,
        );
        assert!(result.ter.is_success());

        // Alice balance reduced by fee + escrow amount
        let alice_sle = open.read(&keylet::account(&alice)).unwrap();
        assert_eq!(alice_sle.balance_xrp(), Some(100_000_000 - 10 - 10_000_000));
        // Owner count bumped
        assert_eq!(alice_sle.owner_count(), 1);

        // Escrow SLE exists
        let escrow_kl = keylet::escrow(&alice, 0); // sequence 0 from default
                                                   // Note: escrow key uses tx.sequence which is 0 in default ParsedTx
        assert!(open.exists(&escrow_kl));
    }

    #[test]
    fn test_account_delete() {
        let alice = [0xAA; 20];
        let bob = [0xBB; 20];
        let mut base = setup_ledger_with_account(&alice, 50_000_000);
        let bob_data = make_account_data(&bob, 10_000_000, 1);
        base.raw_insert(Arc::new(SLE::new(
            keylet::account(&bob).key,
            LedgerEntryType::AccountRoot,
            bob_data,
        )));

        let mut open = OpenView::new(Arc::new(base));

        let tx = ParsedTx {
            tx_type: 21,
            account: alice,
            fee: 2_000_000, // AccountDelete has high fee
            destination: Some(bob),
            ..ParsedTx::default()
        };

        let tx_hash = [0x08; 32];
        let result = apply_transaction(
            &mut open,
            &tx,
            &tx_hash,
            &AccountDeleteHandler,
            ApplyFlags::NONE,
        );
        assert!(result.ter.is_success());

        // Alice should be gone
        assert!(!open.exists(&keylet::account(&alice)));
        // Bob should have Alice's remaining balance
        let bob_sle = open.read(&keylet::account(&bob)).unwrap();
        // Bob: 10M + (50M - 2M fee) = 58M
        assert_eq!(
            bob_sle.balance_xrp(),
            Some(10_000_000 + 50_000_000 - 2_000_000)
        );
    }

    #[test]
    fn test_unknown_tx_type_is_rejected_without_mutation() {
        let alice = [0xAA; 20];
        let base = setup_ledger_with_account(&alice, 100_000_000);
        let mut open = OpenView::new(Arc::new(base));

        let tx = ParsedTx {
            tx_type: 255, // unknown type
            account: alice,
            fee: 10,
            ..ParsedTx::default()
        };

        let tx_hash = [0x04; 32];
        let result = apply_transaction(
            &mut open,
            &tx,
            &tx_hash,
            &UnsupportedHandler,
            ApplyFlags::NONE,
        );
        assert!(matches!(result.ter, TER::Malformed("temUNKNOWN")));
        assert!(result.metadata.is_none());

        // Unsupported transactions must not consume fee or sequence.
        let alice_sle = open.read(&keylet::account(&alice)).unwrap();
        assert_eq!(alice_sle.balance_xrp(), Some(100_000_000));
        assert_eq!(alice_sle.sequence(), Some(1));
    }

    #[test]
    fn test_legacy_iou_payment_is_rejected_without_mutation() {
        let alice = [0xAA; 20];
        let bob = [0xBB; 20];

        let mut base = setup_ledger_with_account(&alice, 100_000_000);
        let bob_kl = keylet::account(&bob);
        let bob_data = make_account_data(&bob, 50_000_000, 1);
        base.raw_insert(Arc::new(SLE::new(
            bob_kl.key,
            LedgerEntryType::AccountRoot,
            bob_data,
        )));

        let mut open = OpenView::new(Arc::new(base));
        let tx = ParsedTx {
            tx_type: 0,
            account: alice,
            fee: 10,
            destination: Some(bob),
            amount: Some(crate::transaction::Amount::Iou {
                value: crate::transaction::amount::IouValue::from_f64(5.0),
                currency: crate::transaction::amount::Currency::from_code("USD").unwrap(),
                issuer: bob,
            }),
            ..ParsedTx::default()
        };

        let tx_hash = [0x09; 32];
        let result = apply_transaction(&mut open, &tx, &tx_hash, &PaymentHandler, ApplyFlags::NONE);
        assert!(matches!(result.ter, TER::LocalFail("tefNOT_SUPPORTED")));
        assert!(result.metadata.is_none());

        let alice_sle = open.read(&keylet::account(&alice)).unwrap();
        let bob_sle = open.read(&keylet::account(&bob)).unwrap();
        assert_eq!(alice_sle.balance_xrp(), Some(100_000_000));
        assert_eq!(alice_sle.sequence(), Some(1));
        assert_eq!(bob_sle.balance_xrp(), Some(50_000_000));
    }

    #[test]
    fn test_legacy_unsupported_handlers_fail_without_mutation() {
        let alice = [0xAA; 20];
        let unsupported_types = [29u16, 30, 35, 51, 53, 54, 58, 61, 62, 64, 65, 100, 101, 102];

        for tx_type in unsupported_types {
            let base = setup_ledger_with_account(&alice, 100_000_000);
            let mut open = OpenView::new(Arc::new(base));
            let tx = ParsedTx {
                tx_type,
                account: alice,
                fee: 10,
                ..ParsedTx::default()
            };
            let handler = handler_for_type(tx_type);
            let result = apply_transaction(
                &mut open,
                &tx,
                &[tx_type as u8; 32],
                handler.as_ref(),
                ApplyFlags::NONE,
            );
            assert!(
                matches!(result.ter, TER::LocalFail("tefNOT_SUPPORTED")),
                "tx_type {tx_type} returned {:?}",
                result.ter
            );
            assert!(
                result.metadata.is_none(),
                "tx_type {tx_type} claimed metadata"
            );

            let alice_sle = open.read(&keylet::account(&alice)).unwrap();
            assert_eq!(
                alice_sle.balance_xrp(),
                Some(100_000_000),
                "tx_type {tx_type}"
            );
            assert_eq!(alice_sle.sequence(), Some(1), "tx_type {tx_type}");
        }
    }
}
