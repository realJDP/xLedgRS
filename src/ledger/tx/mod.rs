//! Transaction application — mutate `LedgerState` by applying a parsed transaction.
//!
//! Each transaction type lives in its own submodule.

mod account_delete;
mod account_set;
mod amm;
mod amm_step;
mod asset_flow;
mod batch;
mod check;
mod clawback;
pub(crate) mod credential;
mod delegate;
mod deposit_preauth;
mod did;
mod escrow;
pub(crate) mod flow;
mod ledger_state_fix;
mod loan;
mod mptoken;
mod nftoken;
mod nftoken_modify;
mod offer;
mod oracle;
mod paychan;
mod payment;
pub(crate) mod permissioned_domain;
pub(crate) mod ripple_calc;
mod signer_list_set;
mod ticket;
mod trust_set;
mod vault;
mod xchain;

pub(crate) use amm::amm_key;
pub(crate) use vault::{
    mpt_issuance_key as vault_mpt_issuance_key, vault_key, vault_sle_share_mptid,
};

use crate::ledger::invariants::{self, InvariantResult};
use crate::ledger::ter::{self, ApplyFlags, TxResult};
use crate::ledger::LedgerState;
use crate::transaction::{Amount, ParsedTx};

// ── Amendment hashes ─────────────────────────────────────────────────────────
// Each hash is SHA512-Half of the amendment name string (matches rippled's
// registerFeature() in Feature.cpp).

fn amendment_hash(name: &str) -> [u8; 32] {
    crate::crypto::sha512_first_half(name.as_bytes())
}

use std::sync::LazyLock;

static FEATURE_AMM: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("AMM"));
static FEATURE_CLAWBACK: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("Clawback"));
static FEATURE_AMM_CLAWBACK: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("AMMClawback"));
static FEATURE_MPTOKEN: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("MPTokensV1"));
static FEATURE_VAULT: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("SingleAssetVault"));
static FEATURE_BATCH: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("Batch"));
static FEATURE_LENDING: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("LendingProtocol"));
static FEATURE_DID: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("DID"));
static FEATURE_XCHAIN: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("XChainBridge"));
static FEATURE_CREDENTIALS: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("Credentials"));
static FEATURE_ORACLE: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("PriceOracle"));
static FEATURE_PERMISSIONED_DOMAINS: LazyLock<[u8; 32]> =
    LazyLock::new(|| amendment_hash("PermissionedDomains"));
static FEATURE_DYNAMIC_NFT: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("DynamicNFT"));
#[allow(dead_code)]
static FEATURE_TOKEN_ESCROW: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("TokenEscrow"));
#[allow(dead_code)]
static FEATURE_DEEP_FREEZE: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("DeepFreeze"));
#[allow(dead_code)]
static FEATURE_PERMISSIONED_DEX: LazyLock<[u8; 32]> =
    LazyLock::new(|| amendment_hash("PermissionedDEX"));
static FEATURE_DYNAMIC_MPT: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("DynamicMPT"));
static FEATURE_NFT_PAGE_LINKS: LazyLock<[u8; 32]> =
    LazyLock::new(|| amendment_hash("fixNFTokenPageLinks"));
static FEATURE_DELEGATION: LazyLock<[u8; 32]> =
    LazyLock::new(|| amendment_hash("PermissionDelegationV1_1"));
static FEATURE_XRP_FEES: LazyLock<[u8; 32]> = LazyLock::new(|| amendment_hash("XRPFees"));

/// Returns the required amendment hash for a given tx type, or None if the
/// tx type is always available (no amendment gate).
fn required_amendment(tx_type: u16) -> Option<&'static [u8; 32]> {
    match tx_type {
        // AMM: AMMCreate(35), AMMDeposit(36), AMMWithdraw(37), AMMVote(38), AMMBid(39), AMMDelete(40)
        35 | 36 | 37 | 38 | 39 | 40 => Some(&*FEATURE_AMM),
        // Clawback(30)
        30 => Some(&*FEATURE_CLAWBACK),
        // AMMClawback(31)
        31 => Some(&*FEATURE_AMM_CLAWBACK),
        // MPToken: Create(54), Destroy(55), Set(56), Authorize(57)
        54 | 55 | 56 | 57 => Some(&*FEATURE_MPTOKEN),
        // Vault: Create(65), Set(66), Delete(67), Deposit(68), Withdraw(69), Clawback(70)
        65 | 66 | 67 | 68 | 69 | 70 => Some(&*FEATURE_VAULT),
        // Batch(71)
        71 => Some(&*FEATURE_BATCH),
        // Loan: BrokerSet(74), BrokerDelete(75), Cover*(76-78), LoanSet(80), LoanDelete(81), LoanManage(82), LoanPay(84)
        74 | 75 | 76 | 77 | 78 | 80 | 81 | 82 | 84 => Some(&*FEATURE_LENDING),
        // DID: Set(49), Delete(50)
        49 | 50 => Some(&*FEATURE_DID),
        // XChain(41-48)
        41 | 42 | 43 | 44 | 45 | 46 | 47 | 48 => Some(&*FEATURE_XCHAIN),
        // Credential: Create(58), Accept(59), Delete(60)
        58 | 59 | 60 => Some(&*FEATURE_CREDENTIALS),
        // Oracle: Set(51), Delete(52)
        51 | 52 => Some(&*FEATURE_ORACLE),
        // PermissionedDomain: Set(62), Delete(63)
        62 | 63 => Some(&*FEATURE_PERMISSIONED_DOMAINS),
        // NFTokenModify(61) — DynamicNFT
        61 => Some(&*FEATURE_DYNAMIC_NFT),
        // LedgerStateFix(53) — fixNFTokenPageLinks
        53 => Some(&*FEATURE_NFT_PAGE_LINKS),
        // DelegateSet(64) — PermissionDelegationV1_1
        64 => Some(&*FEATURE_DELEGATION),
        // All other tx types (Payment, TrustSet, Offers, Escrow, etc.) — no gate
        _ => None,
    }
}

/// Transaction families that are present in the rippled source tree but are not
/// enabled XRPL mainnet behavior today.  Validated replay normally trusts the
/// network's ledger history, but these families should not mutate local state
/// unless the replayed ledger has explicitly activated their amendment.
fn requires_explicit_replay_amendment(tx_type: u16) -> bool {
    matches!(
        tx_type,
        // XChainBridge
        41..=48
            // PermissionedDomain / PermissionDelegation
            | 62..=64
            // SingleAssetVault
            | 65..=70
            // Batch
            | 71
            // LendingProtocol
            | 74..=78
            | 80..=82
            | 84
    )
}

/// Ledger context passed to transaction handlers.
/// Carries information from the parent ledger header that some handlers need.
#[derive(Debug, Clone)]
pub struct TxContext {
    /// Parent ledger hash — needed for pseudo-account derivation (VaultCreate, etc.)
    pub parent_hash: [u8; 32],
    /// Current ledger sequence being built.
    pub ledger_seq: u32,
    /// XRPL network ID used for transaction NetworkID canonicality checks.
    pub network_id: u32,
    /// Close time of the ledger being built.
    pub close_time: u64,
    /// Close time of the parent ledger. Amendment majority pseudo-transactions
    /// record this value, matching rippled's `view().parentCloseTime()`.
    pub parent_close_time: u64,
    /// Set only by `run_tx` for trusted validated-ledger replay. Metadata
    /// hints must never be honored by candidate or normal execution.
    pub trusted_validated_replay: bool,
    /// Authoritative result from validated metadata, when replaying a
    /// validated ledger. Used to bridge isolated engine gaps without
    /// affecting independent close/build paths.
    pub validated_result: Option<TxResult>,
    /// DeliveredAmount from validated metadata (top-level sfDeliveredAmount),
    /// when present.
    pub validated_delivered_amount: Option<Amount>,
    /// Validated replay bridge for OfferCreate transactions whose metadata
    /// shows AMM-only crossing that the local offer engine does not yet model.
    pub validated_offer_create_amm_bridge: bool,
    /// Validated replay bridge for self-Payment transactions whose metadata
    /// shows an AMM-only XRP/IOU swap that Flow does not yet model.
    pub validated_payment_amm_self_swap_bridge: bool,
}

impl TxContext {
    /// Create from a LedgerHeader (the parent/previous ledger).
    pub fn from_parent(parent: &crate::ledger::LedgerHeader, close_time: u64) -> Self {
        Self {
            parent_hash: parent.hash,
            ledger_seq: parent.sequence + 1,
            network_id: 0,
            close_time,
            parent_close_time: parent.close_time,
            trusted_validated_replay: false,
            validated_result: None,
            validated_delivered_amount: None,
            validated_offer_create_amm_bridge: false,
            validated_payment_amm_self_swap_bridge: false,
        }
    }
}

impl Default for TxContext {
    fn default() -> Self {
        Self {
            parent_hash: [0u8; 32],
            ledger_seq: 0,
            network_id: 0,
            close_time: 0,
            parent_close_time: 0,
            trusted_validated_replay: false,
            validated_result: None,
            validated_delivered_amount: None,
            validated_offer_create_amm_bridge: false,
            validated_payment_amm_self_swap_bridge: false,
        }
    }
}

/// Result of applying a single transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyResult {
    /// Transaction applied successfully.
    Success,
    /// Transaction claimed the fee but failed (tec class).
    ClaimedCost(&'static str),
}

pub(crate) fn tx_result_from_token(token: &str) -> TxResult {
    if let Some(code) = ter::token_to_code(token) {
        return code;
    }

    tracing::warn!("unmapped transaction result token: {token}");
    if token.starts_with("tec") {
        ter::TEC_CLAIM
    } else {
        ter::TEM_UNKNOWN
    }
}

/// Sequence proxy used by rippled when a transaction is submitted via a
/// ticket. Sequence-keyed objects (offers, escrows, checks, paychans, etc.)
/// must use `TicketSequence` instead of the literal `Sequence=0`.
pub(crate) fn sequence_proxy(tx: &ParsedTx) -> u32 {
    tx.ticket_sequence.unwrap_or(tx.sequence)
}

fn ticket_exists(state: &LedgerState, account: &[u8; 20], ticket_seq: u32) -> bool {
    let ticket_key = crate::ledger::keylet::ticket(account, ticket_seq);
    state.get_raw_owned(&ticket_key.key).is_some()
}

fn consume_ticket(
    state: &mut LedgerState,
    account: &[u8; 20],
    ticket_seq: u32,
    account_root: &mut crate::ledger::AccountRoot,
) -> bool {
    let ticket_key = crate::ledger::keylet::ticket(account, ticket_seq);
    let mut ticket_owner_node = None;
    let ticket_exists = if let Some(ticket) = state.remove_ticket(&ticket_key.key) {
        ticket_owner_node = Some(ticket.owner_node);
        true
    } else if let Some(raw) = state.get_raw_owned(&ticket_key.key) {
        // Ticket exists in NuDB but was not hydrated into the typed map.
        // Decode before deletion so OwnerNode can target the right page.
        ticket_owner_node =
            crate::ledger::Ticket::decode_from_sle(&raw).map(|ticket| ticket.owner_node);
        state.remove_raw(&ticket_key.key);
        true
    } else {
        false
    };

    if !ticket_exists {
        return false;
    }

    let owner_root = crate::ledger::directory::owner_dir_key(account);
    ticket_owner_node
        .map(|owner_node| {
            crate::ledger::directory::dir_remove_root_page(
                state,
                &owner_root,
                owner_node,
                &ticket_key.key.0,
            )
        })
        .unwrap_or(false);
    account_root.owner_count = account_root.owner_count.saturating_sub(1);
    account_root.ticket_count = account_root.ticket_count.saturating_sub(1);
    true
}

/// Bridge handlers that currently rely on authoritative metadata for
/// validated replay failures but are not yet independently implemented.
/// Success must come from a real local handler, not from metadata alone.
pub(crate) fn bridge_metadata_only_tx(
    ctx: &TxContext,
    tx_type: u16,
    label: &'static str,
    fallback_token: &'static str,
) -> ApplyResult {
    if !ctx.trusted_validated_replay {
        tracing::warn!(
            "apply_tx: tx type {} ({}) reached outside trusted validated replay; rejecting with {}",
            tx_type,
            label,
            fallback_token,
        );
        return ApplyResult::ClaimedCost(fallback_token);
    }

    if let Some(validated) = ctx.validated_result {
        if validated.is_tes_success() {
            tracing::warn!(
                "apply_tx: tx type {} ({}) validated replay metadata-only success bridge disabled; rejecting with {}",
                tx_type,
                label,
                fallback_token,
            );
            return ApplyResult::ClaimedCost(fallback_token);
        }

        tracing::debug!(
            "apply_tx: tx type {} ({}) using validated replay bridge with result {}",
            tx_type,
            label,
            validated.token(),
        );
        ApplyResult::ClaimedCost(validated.token())
    } else {
        tracing::warn!(
            "apply_tx: tx type {} ({}) reached without validated metadata; rejecting with {}",
            tx_type,
            label,
            fallback_token,
        );
        ApplyResult::ClaimedCost(fallback_token)
    }
}

// ── New transaction runner with proper TER lifecycle ─────────────────────────

/// Result of `run_tx` — the new TER-aware transaction runner.
#[derive(Debug, Clone)]
pub struct TxRunResult {
    /// The TER result code.
    pub ter: TxResult,
    /// Whether the transaction was applied (state changed).
    pub applied: bool,
    /// Journal entries for metadata generation (only when applied).
    pub touched: Vec<(crate::ledger::Key, Option<Vec<u8>>)>,
}

/// Run a transaction through the full preflight → preclaim → do_apply pipeline.
///
/// This wraps `apply_tx` with proper TER-gated fee/sequence consumption and
/// `begin_tx`/`discard_tx`/`commit_tx` lifecycle.
///
/// `flags` controls retry/replay behavior. Normal paths enforce signature
/// authorization; trusted validated replay is the only auth-skipping path.
pub fn run_tx(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
    flags: ApplyFlags,
) -> TxRunResult {
    run_tx_inner(
        state,
        tx,
        ctx,
        flags,
        !flags.contains(ApplyFlags::VALIDATED_REPLAY),
    )
}

/// Run a transaction admitted from a live candidate set.
///
/// Unlike validated replay, candidate-set transactions are not authoritative
/// history. They must prove the same authorization and preclaim checks
/// expected from local submit before they can execute.
pub(crate) fn run_candidate_tx(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
    flags: ApplyFlags,
) -> TxRunResult {
    run_tx_inner(state, tx, ctx, flags, true)
}

fn run_tx_inner(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
    flags: ApplyFlags,
    enforce_auth: bool,
) -> TxRunResult {
    let trusted_validated_replay = flags.contains(ApplyFlags::VALIDATED_REPLAY) && !enforce_auth;
    let exec_ctx = execution_context(ctx, trusted_validated_replay);

    // ── Pseudo-transactions bypass the pipeline ──────────────────────────
    match tx.tx_type {
        100 | 101 | 102 => {
            if let Err(preflight_ter) = preflight_pseudo_tx(tx) {
                return TxRunResult {
                    ter: preflight_ter,
                    applied: false,
                    touched: Vec::new(),
                };
            }
            state.begin_tx();
            let result = apply_tx(state, tx, &exec_ctx);
            let ter = match &result {
                ApplyResult::Success => ter::TES_SUCCESS,
                ApplyResult::ClaimedCost(code) => tx_result_from_token(code),
            };
            if ter == ter::TES_SUCCESS {
                let touched = state.commit_tx();
                return TxRunResult {
                    ter,
                    applied: true,
                    touched,
                };
            }
            state.discard_tx();
            return TxRunResult {
                ter,
                applied: false,
                touched: Vec::new(),
            };
        }
        _ => {}
    }

    if let Err(preclaim_ter) =
        preclaim_tx(state, tx, &exec_ctx, enforce_auth, trusted_validated_replay)
    {
        return TxRunResult {
            ter: preclaim_ter,
            applied: false,
            touched: Vec::new(),
        };
    }

    if trusted_validated_replay {
        if let Some(hash) = required_amendment(tx.tx_type) {
            if requires_explicit_replay_amendment(tx.tx_type) && !state.is_amendment_active(hash) {
                return TxRunResult {
                    ter: ter::TEM_DISABLED,
                    applied: false,
                    touched: Vec::new(),
                };
            }
        }
        if let Some(validated) = exec_ctx.validated_result {
            if validated.is_tec_claim() {
                return apply_validated_fee_only_result(state, tx, validated);
            }
            if validated.is_tes_success()
                && validated_success_uses_authoritative_payment_metadata(tx, &exec_ctx)
            {
                return apply_validated_fee_only_result(state, tx, validated);
            }
        }
    }

    // ── Gate: likely_to_claim_fee? ──────────────────────────────────────
    // At this point preclaim would return tesSUCCESS (all checks passed).
    // With tesSUCCESS, likely_to_claim_fee is always true.
    // Continue into `do_apply`.

    // ── do_apply: begin_tx → run handler → handle result ────────────────
    state.begin_tx();
    let old_result = apply_tx(state, tx, &exec_ctx);

    // Convert old ApplyResult to TxResult
    let ter = match &old_result {
        ApplyResult::Success => ter::TES_SUCCESS,
        ApplyResult::ClaimedCost(code_str) => tx_result_from_token(code_str),
    };

    // rippled treats tecINCOMPLETE specially: the transaction claims a fee and
    // keeps bounded cleanup work, such as AMM trustline deletion, so a later
    // transaction can finish the object lifecycle.
    if ter == ter::TEC_INCOMPLETE && !flags.contains(ApplyFlags::FAIL_HARD) {
        let touched_peek: Vec<_> = state.peek_tx_journal();
        let inv_result = if trusted_validated_replay {
            InvariantResult::Ok
        } else {
            invariants::check_invariants(state, &touched_peek, ter, tx.fee, tx, exec_ctx.ledger_seq)
        };
        if inv_result == InvariantResult::Ok {
            let touched = state.commit_tx();
            return TxRunResult {
                ter,
                applied: true,
                touched,
            };
        }
        tracing::warn!(
            "invariant failed for tecINCOMPLETE tx type={}: {:?}, attempting fee-only reset",
            tx.tx_type,
            inv_result,
        );
        state.discard_tx();
        state.begin_tx();
        let fee_only_ter = apply_fee_only(state, tx);
        if !fee_only_ter.is_tes_success() {
            state.discard_tx();
            return TxRunResult {
                ter: fee_only_ter,
                applied: false,
                touched: Vec::new(),
            };
        }
        let touched = state.commit_tx();
        return TxRunResult {
            ter: ter::TEC_INVARIANT_FAILED,
            applied: true,
            touched,
        };
    }

    // ── Handle tec hard-fail reset ──────────────────────────────────────
    // XRPL tec results claim the fee and consume the sequence, but they do
    // not keep transaction-specific side effects. That means a final tec
    // result must always collapse to a fee-only reset unless FAIL_HARD is in
    // force. Letting full mutations survive here is what poisons replay.
    // rippled CredentialAccept deliberately deletes an unaccepted expired
    // Credential SLE while returning tecEXPIRED.
    let preserves_credential_expiration_cleanup = tx.tx_type == 59 && ter == ter::TEC_EXPIRED;
    let preserves_nft_expired_offer_cleanup = tx.tx_type == 29 && ter == ter::TEC_EXPIRED;
    let preserves_offer_cleanup =
        tx.tx_type == 7 && matches!(ter, ter::TEC_KILLED | ter::TEC_OVERSIZE);
    let needs_reset = ter.is_tec_claim_hard_fail(flags)
        && !flags.contains(ApplyFlags::FAIL_HARD)
        && !preserves_credential_expiration_cleanup
        && !preserves_nft_expired_offer_cleanup
        && !preserves_offer_cleanup;

    if needs_reset {
        // Discard all tx effects, then re-apply fee+sequence only
        state.discard_tx();
        state.begin_tx();
        let fee_only_ter = apply_fee_only(state, tx);
        if !fee_only_ter.is_tes_success() {
            state.discard_tx();
            return TxRunResult {
                ter: fee_only_ter,
                applied: false,
                touched: Vec::new(),
            };
        }
        let touched = state.commit_tx();
        return TxRunResult {
            ter,
            applied: true,
            touched,
        };
    }

    // ── tec during retry pass → soft failure, discard ───────────────────
    if ter.is_tec_claim() && !ter.is_tec_claim_hard_fail(flags) {
        // Soft failure: discard changes, don't apply
        state.discard_tx();
        return TxRunResult {
            ter,
            applied: false,
            touched: Vec::new(),
        };
    }

    // ── tapFAIL_HARD: tec must not do anything ──────────────────────────
    if ter.is_tec_claim() && flags.contains(ApplyFlags::FAIL_HARD) {
        state.discard_tx();
        return TxRunResult {
            ter,
            applied: false,
            touched: Vec::new(),
        };
    }

    // ── ter/tef/tem/tel: never applied ──────────────────────────────────
    // These shouldn't reach here because handlers currently return
    // ClaimedCost for everything, but guard anyway for future handler
    // migrations that return proper ter/tef/tem codes.
    if !ter.is_tes_success() && !ter.is_tec_claim() {
        state.discard_tx();
        return TxRunResult {
            ter,
            applied: false,
            touched: Vec::new(),
        };
    }

    // ── Invariant checking before commit ────────────────────────────────
    // Peek at the journal without consuming it (commit_tx will return it).
    // The touched entries are required for invariant checking.
    let touched_peek: Vec<_> = state.peek_tx_journal();

    let inv_result = if trusted_validated_replay {
        InvariantResult::Ok
    } else {
        invariants::check_invariants(state, &touched_peek, ter, tx.fee, tx, exec_ctx.ledger_seq)
    };

    if inv_result == InvariantResult::Ok {
        // All invariants passed — commit
        let touched = state.commit_tx();
        return TxRunResult {
            ter,
            applied: true,
            touched,
        };
    }

    // Invariant failed — discard and try fee-only reset
    tracing::warn!(
        "invariant failed for tx type={}: {:?}, attempting fee-only reset",
        tx.tx_type,
        inv_result,
    );
    state.discard_tx();

    // Fee-only reset
    state.begin_tx();
    let fee_only_ter = apply_fee_only(state, tx);
    if !fee_only_ter.is_tes_success() {
        state.discard_tx();
        return TxRunResult {
            ter: fee_only_ter,
            applied: false,
            touched: Vec::new(),
        };
    }

    // Check invariants on fee-only path
    let fee_touched = state.peek_tx_journal();
    let fee_inv = invariants::check_invariants(
        state,
        &fee_touched,
        ter::TEC_INVARIANT_FAILED,
        tx.fee,
        tx,
        exec_ctx.ledger_seq,
    );

    if fee_inv == InvariantResult::Ok {
        let touched = state.commit_tx();
        TxRunResult {
            ter: ter::TEC_INVARIANT_FAILED,
            applied: true,
            touched,
        }
    } else {
        // Even fee-only failed invariants — don't apply at all
        tracing::error!(
            "invariant failed even on fee-only reset for tx type={}: {:?}",
            tx.tx_type,
            fee_inv,
        );
        state.discard_tx();
        TxRunResult {
            ter: ter::TEF_INVARIANT_FAILED,
            applied: false,
            touched: Vec::new(),
        }
    }
}

fn preflight_pseudo_tx(tx: &ParsedTx) -> Result<(), TxResult> {
    if tx.account != [0u8; 20] {
        return Err(ter::TEM_BAD_SRC_ACCOUNT);
    }
    if tx.fee != 0 {
        return Err(ter::TEM_BAD_FEE);
    }
    if !tx.signing_pubkey.is_empty() || !tx.signature.is_empty() || !tx.signers.is_empty() {
        return Err(ter::TEM_BAD_SIGNATURE);
    }
    if tx.sequence != 0 || tx.account_txn_id.is_some() {
        return Err(ter::TEM_BAD_SEQUENCE);
    }
    if tx.tx_type == 100 {
        let got_majority = (tx.flags & 0x0001_0000) != 0;
        let lost_majority = (tx.flags & 0x0002_0000) != 0;
        if (tx.flags & !0x0003_0000) != 0 || (got_majority && lost_majority) {
            return Err(ter::TEM_INVALID_FLAG);
        }
    }
    Ok(())
}

fn validated_success_uses_authoritative_payment_metadata(tx: &ParsedTx, ctx: &TxContext) -> bool {
    tx.tx_type == 0
        && !ctx.validated_payment_amm_self_swap_bridge
        && (!tx.paths.is_empty() || tx.send_max.is_some() || tx.deliver_min.is_some())
}

fn apply_validated_fee_only_result(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ter: TxResult,
) -> TxRunResult {
    state.begin_tx();
    let fee_only_ter = apply_fee_only(state, tx);
    if !fee_only_ter.is_tes_success() {
        state.discard_tx();
        return TxRunResult {
            ter: fee_only_ter,
            applied: false,
            touched: Vec::new(),
        };
    }
    let touched = state.commit_tx();
    TxRunResult {
        ter,
        applied: true,
        touched,
    }
}

fn execution_context(ctx: &TxContext, trusted_validated_replay: bool) -> TxContext {
    let mut exec_ctx = ctx.clone();
    exec_ctx.trusted_validated_replay = trusted_validated_replay;

    if trusted_validated_replay {
        return exec_ctx;
    }

    exec_ctx.validated_result = None;
    exec_ctx.validated_delivered_amount = None;
    exec_ctx.validated_offer_create_amm_bridge = false;
    exec_ctx.validated_payment_amm_self_swap_bridge = false;
    exec_ctx
}

fn preclaim_tx(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
    enforce_auth: bool,
    trusted_validated_replay: bool,
) -> Result<(), TxResult> {
    preflight_tx(state, tx, ctx, trusted_validated_replay)?;

    let acct = load_existing_account(state, &tx.account).ok_or(ter::TER_NO_ACCOUNT)?;

    // AccountTxnID constrains the transaction to a specific prior successful
    // transaction by this account.
    // rippled: Transactor.cpp checkPriorTxAndLastLedger → tefWRONG_PRIOR.
    if let Some(expected) = tx.account_txn_id {
        if acct.account_txn_id() != Some(expected) {
            return Err(ter::TEF_WRONG_PRIOR);
        }
    }

    // LastLedgerSequence: tx expires if current ledger > last_ledger_seq.
    // rippled: Transactor.cpp checkPriorTxAndLastLedger → tefMAX_LEDGER.
    if let Some(last_seq) = tx.last_ledger_seq {
        if ctx.ledger_seq > last_seq {
            return Err(ter::TEF_MAX_LEDGER);
        }
    }

    let fees = crate::ledger::read_fees(state);
    let fee_account_id = fee_payer(tx);
    let fee_account = if fee_account_id == tx.account {
        acct.clone()
    } else {
        load_existing_account(state, &fee_account_id).ok_or(ter::TER_NO_ACCOUNT)?
    };
    let minimum_fee = match tx.tx_type {
        // rippled calculateBaseFee overrides:
        // AccountDelete, AMMCreate, and LedgerStateFix charge one owner
        // reserve increment instead of the ordinary base fee.
        21 | 35 | 53 => fees.increment,
        2 => escrow_finish_minimum_fee(
            fees.base,
            tx.signers.len(),
            crate::transaction::parse::parsed_fulfillment(tx).map(|fulfillment| fulfillment.len()),
        ),
        5 if set_regular_key_first_master_signed_fee_free(tx, &acct) => 0,
        _ => fees
            .base
            .saturating_mul(1u64.saturating_add(tx.signers.len() as u64)),
    };
    if tx.fee < minimum_fee {
        return Err(ter::TEL_INSUF_FEE_P);
    }
    if fee_account.balance < tx.fee {
        return Err(ter::TER_INSUF_FEE_B);
    }

    // TicketSequence vs Sequence mutual exclusivity.
    // rippled: a tx uses EITHER Sequence (>0) OR TicketSequence, never both.
    // Sequence=0 signals ticket-based; TicketSequence present signals ticket-based.
    if tx.ticket_sequence.is_some() && tx.sequence != 0 {
        return Err(ter::TEM_SEQ_AND_TICKET);
    }

    if tx.sequence == 0 {
        let Some(ticket_seq) = tx.ticket_sequence else {
            return Err(ter::TEF_PAST_SEQ);
        };

        if acct.sequence <= ticket_seq {
            return Err(ter::TER_PRE_TICKET);
        }

        if !ticket_exists(state, &tx.account, ticket_seq) {
            return Err(ter::TEF_NO_TICKET);
        }
    } else if tx.sequence != acct.sequence {
        if trusted_validated_replay {
            tracing::warn!(
                "validated replay terPRE_SEQ: acct={} tx_seq={} acct_seq={} tx_type={} ticket_seq={:?}",
                hex::encode_upper(&tx.account[..4]),
                tx.sequence,
                acct.sequence,
                tx.tx_type,
                tx.ticket_sequence,
            );
        }
        let ter = if tx.sequence < acct.sequence {
            ter::TEF_PAST_SEQ
        } else {
            ter::TER_PRE_SEQ
        };
        return Err(ter);
    }

    if tx.tx_type == 10 {
        let added = tx.ticket_count.ok_or(ter::TEM_INVALID_COUNT)?;
        let consumed = u32::from(tx.ticket_sequence.is_some());
        if acct
            .ticket_count
            .saturating_add(added)
            .saturating_sub(consumed)
            > 250
        {
            return Err(ter::TEC_DIR_FULL);
        }
    }

    if tx.tx_type == 8 {
        let offer_sequence = tx.offer_sequence.ok_or(ter::TEM_BAD_SEQUENCE)?;
        if acct.sequence <= offer_sequence {
            return Err(ter::TEM_BAD_SEQUENCE);
        }
    }

    if enforce_auth {
        check_candidate_auth(state, tx, &acct)?;
    }

    Ok(())
}

fn preflight_tx(
    state: &LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
    trusted_validated_replay: bool,
) -> Result<(), TxResult> {
    check_network_id(tx, ctx)?;

    if !trusted_validated_replay && !is_known_tx_type(tx.tx_type) {
        return Err(ter::TEM_UNKNOWN);
    }

    // rippled invokes transaction feature gates during preflight, before
    // fee/sequence preclaim checks.
    if !trusted_validated_replay {
        if let Some(hash) = required_amendment(tx.tx_type) {
            if !state.is_amendment_active(hash) {
                return Err(ter::TEM_DISABLED);
            }
        }
    }

    if !trusted_validated_replay
        && credentials_field_requires_feature(tx)
        && !state.is_amendment_active(&*FEATURE_CREDENTIALS)
    {
        return Err(ter::TEM_DISABLED);
    }

    if let Some(mask) = tx_flag_mask(tx.tx_type) {
        if (tx.flags & !mask) != 0 {
            return Err(ter::TEM_INVALID_FLAG);
        }
    }

    if !trusted_validated_replay
        && (tx.flags & TF_INNER_BATCH_TXN) != 0
        && !state.is_amendment_active(&*FEATURE_BATCH)
    {
        return Err(ter::TEM_DISABLED);
    }

    if tx.tx_type == 20 {
        trust_set::preflight(tx, state.is_amendment_active(&*FEATURE_DEEP_FREEZE))?;
    }

    if !trusted_validated_replay
        && tx.tx_type == 0
        && tx.domain_id.is_some()
        && !state.is_amendment_active(&*FEATURE_PERMISSIONED_DEX)
    {
        return Err(ter::TEM_DISABLED);
    }

    if matches!(tx.tx_type, 54 | 56) {
        let inactive_domain = tx.domain_id.is_some()
            && !(state.is_amendment_active(&*FEATURE_PERMISSIONED_DOMAINS)
                && state.is_amendment_active(&*FEATURE_VAULT));
        if !trusted_validated_replay && inactive_domain {
            return Err(ter::TEM_DISABLED);
        }
        let dynamic_mpt_required = match tx.tx_type {
            54 => tx.mutable_flags.is_some(),
            56 => {
                tx.mutable_flags.is_some()
                    || tx.mptoken_metadata.is_some()
                    || tx.transfer_fee_field.is_some()
            }
            _ => false,
        };
        if !trusted_validated_replay
            && dynamic_mpt_required
            && !state.is_amendment_active(&*FEATURE_DYNAMIC_MPT)
        {
            return Err(ter::TEM_DISABLED);
        }
    }

    if tx.tx_type == 7 {
        if !trusted_validated_replay
            && tx.domain_id.is_some()
            && !state.is_amendment_active(&*FEATURE_PERMISSIONED_DEX)
        {
            return Err(ter::TEM_DISABLED);
        }
        offer_create_preflight(tx)?;
    }

    if tx.tx_type == 8 {
        match tx.offer_sequence {
            Some(0) | None => return Err(ter::TEM_BAD_SEQUENCE),
            Some(_) => {}
        }
    }

    if tx.tx_type == 3 {
        account_set_preflight(tx, state.is_amendment_active(&*FEATURE_TOKEN_ESCROW))?;
    }

    if tx.tx_type == 25 {
        nftoken_mint_preflight(tx)?;
    }

    if tx.tx_type == 29 {
        nftoken_accept_offer_preflight(tx)?;
    }

    if tx.tx_type == 5 {
        if (tx.flags & !TF_UNIVERSAL) != 0 {
            return Err(ter::TEM_INVALID_FLAG);
        }
        if tx.regular_key == Some(tx.account) {
            return Err(ter::TEM_BAD_REGKEY);
        }
    }

    if tx.tx_type == 21 {
        if (tx.flags & !TF_UNIVERSAL) != 0 {
            return Err(ter::TEM_INVALID_FLAG);
        }
        let Some(destination) = tx.destination else {
            return Err(ter::TEM_DST_NEEDED);
        };
        if destination == tx.account {
            return Err(ter::TEM_DST_IS_SRC);
        }
    }

    if tx.tx_type == 10 {
        ticket_create_preflight(tx)?;
    }

    if tx.tx_type == 12 {
        signer_list_set::preflight(tx)?;
    }

    if matches!(tx.tx_type, 13..=15) {
        paychan::preflight(tx)?;
    }

    if matches!(tx.tx_type, 16..=18) {
        check::preflight(tx)?;
    }

    if matches!(tx.tx_type, 51 | 52) {
        oracle::preflight(tx)?;
    }

    if matches!(tx.tx_type, 49 | 50) {
        did::preflight(tx)?;
    }

    if matches!(tx.tx_type, 58..=60) {
        credential::preflight(tx)?;
    }

    if tx.tx_type == 53 {
        match tx.ledger_fix_type {
            Some(1) => {}
            _ => return Err(ter::TEF_INVALID_LEDGER_FIX_TYPE),
        }
        if tx.owner.is_none() {
            return Err(ter::TEM_INVALID);
        }
    }

    // rippled: Transactor.cpp preflight1 rejects AccountTxnID with tickets.
    if tx.ticket_sequence.is_some() && tx.account_txn_id.is_some() {
        return Err(ter::TEM_INVALID);
    }

    if let Some(delegate) = tx.delegate {
        if !trusted_validated_replay && !state.is_amendment_active(&*FEATURE_DELEGATION) {
            return Err(ter::TEM_DISABLED);
        }
        if delegate == tx.account {
            return Err(ter::TEM_BAD_SIGNER);
        }
    }

    if tx.tx_type == 0 {
        payment::preflight(tx)?;
    }

    Ok(())
}

fn credentials_field_requires_feature(tx: &ParsedTx) -> bool {
    match tx.tx_type {
        // rippled checkExtraFeatures gates sfCredentialIDs on these existing
        // mainnet transaction families.
        0 | 2 | 15 | 21 => crate::transaction::parse::parsed_credential_ids_present(tx),
        // DepositPreauth gates its credential-array forms.
        19 => {
            crate::transaction::parse::parsed_authorize_credentials_raw(tx).is_some()
                || crate::transaction::parse::parsed_unauthorize_credentials_raw(tx).is_some()
        }
        _ => false,
    }
}

const TF_FULLY_CANONICAL_SIG: u32 = 0x8000_0000;
const TF_INNER_BATCH_TXN: u32 = 0x4000_0000;
const TF_UNIVERSAL: u32 = TF_FULLY_CANONICAL_SIG | TF_INNER_BATCH_TXN;

fn tx_flag_mask(tx_type: u16) -> Option<u32> {
    let mask = match tx_type {
        // Payment
        0 => TF_UNIVERSAL | 0x0001_0000 | 0x0002_0000 | 0x0004_0000,
        // EscrowCreate, EscrowFinish, EscrowCancel, SetRegularKey,
        // OfferCancel, TicketCreate, PayChan create/fund,
        // Check*, DepositPreauth, AccountDelete, NFTokenBurn/Cancel/Accept,
        // AMMCreate/Delete, Oracle, DID, Credential, PermissionedDomain.
        1 | 2 | 4 | 5 | 8 | 10 | 13 | 14 | 16 | 17 | 18 | 19 | 21 | 26 | 28 | 29 | 35 | 40 | 51
        | 52 | 49 | 50 | 58 | 59 | 60 | 62 | 63 => TF_UNIVERSAL,
        // AccountSet legacy transaction flags.
        3 => {
            TF_UNIVERSAL
                | 0x0001_0000
                | 0x0002_0000
                | 0x0004_0000
                | 0x0008_0000
                | 0x0010_0000
                | 0x0020_0000
        }
        // OfferCreate
        7 => TF_UNIVERSAL | 0x0001_0000 | 0x0002_0000 | 0x0004_0000 | 0x0008_0000 | 0x0010_0000,
        // SignerListSet
        12 => TF_UNIVERSAL,
        // PaymentChannelClaim
        15 => TF_UNIVERSAL | 0x0001_0000 | 0x0002_0000,
        // TrustSet
        20 => {
            TF_UNIVERSAL
                | 0x0001_0000
                | 0x0002_0000
                | 0x0004_0000
                | 0x0010_0000
                | 0x0020_0000
                | 0x0040_0000
                | 0x0080_0000
        }
        // NFTokenMint
        25 => TF_UNIVERSAL | 0x0000_0001 | 0x0000_0002 | 0x0000_0008 | 0x0000_0010,
        // NFTokenCreateOffer
        27 => TF_UNIVERSAL | 0x0000_0001,
        // AMMClawback
        31 => TF_UNIVERSAL | 0x0000_0001,
        // AMMDeposit
        36 => {
            TF_UNIVERSAL
                | 0x0001_0000
                | 0x0008_0000
                | 0x0010_0000
                | 0x0020_0000
                | 0x0040_0000
                | 0x0080_0000
        }
        // AMMWithdraw
        37 => {
            TF_UNIVERSAL
                | 0x0001_0000
                | 0x0002_0000
                | 0x0004_0000
                | 0x0008_0000
                | 0x0010_0000
                | 0x0020_0000
                | 0x0040_0000
        }
        // AMMVote, AMMBid
        38 | 39 => TF_UNIVERSAL,
        // MPTokenIssuanceCreate
        54 => {
            TF_UNIVERSAL
                | mptoken::LSF_MPT_CAN_LOCK
                | mptoken::LSF_MPT_REQUIRE_AUTH
                | mptoken::LSF_MPT_CAN_ESCROW
                | mptoken::LSF_MPT_CAN_TRADE
                | mptoken::LSF_MPT_CAN_TRANSFER
                | mptoken::LSF_MPT_CAN_CLAWBACK
        }
        // MPTokenIssuanceDestroy
        55 => TF_UNIVERSAL,
        // MPTokenIssuanceSet
        56 => TF_UNIVERSAL | 0x0000_0001 | 0x0000_0002,
        // MPTokenAuthorize
        57 => TF_UNIVERSAL | 0x0000_0001,
        // NFTokenModify, LedgerStateFix
        61 | 53 => TF_UNIVERSAL,
        _ => return None,
    };
    Some(mask)
}

fn ticket_create_preflight(tx: &ParsedTx) -> Result<(), TxResult> {
    if (tx.flags & !TF_UNIVERSAL) != 0 {
        return Err(ter::TEM_INVALID_FLAG);
    }
    match tx.ticket_count {
        Some(1..=250) => Ok(()),
        _ => Err(ter::TEM_INVALID_COUNT),
    }
}

fn account_set_preflight(tx: &ParsedTx, token_escrow_enabled: bool) -> Result<(), TxResult> {
    if !account_set::account_set_flags_are_valid(tx.flags) {
        return Err(ter::TEM_INVALID_FLAG);
    }

    if let (Some(set_flag), Some(clear_flag)) = (tx.set_flag, tx.clear_flag) {
        if set_flag == clear_flag {
            return Err(ter::TEM_INVALID_FLAG);
        }
    }

    if account_set::legacy_flag_pair_conflicts(tx) {
        return Err(ter::TEM_INVALID_FLAG);
    }

    if tx
        .set_flag
        .is_some_and(|flag| !account_set::valid_account_set_flag(flag))
        || tx
            .clear_flag
            .is_some_and(|flag| !account_set::valid_account_set_flag(flag))
    {
        return Err(ter::TEM_INVALID_FLAG);
    }
    if !token_escrow_enabled && matches!(tx.set_flag.or(tx.clear_flag), Some(17)) {
        return Err(ter::TEM_DISABLED);
    }

    if let Some(rate) = tx.transfer_rate {
        const QUALITY_ONE: u32 = 1_000_000_000;
        if rate != 0 && (rate < QUALITY_ONE || rate > 2 * QUALITY_ONE) {
            return Err(ter::TEM_BAD_TRANSFER_RATE);
        }
    }

    if let Some(tick_size) = tx.tick_size {
        if tick_size != 0 && !(3..=16).contains(&tick_size) {
            return Err(ter::TEM_BAD_TICK_SIZE);
        }
    }

    if tx.domain.as_ref().is_some_and(|domain| domain.len() > 256) {
        return Err(ter::TEL_BAD_DOMAIN);
    }
    if !account_set::accountset_message_key_is_valid(tx) {
        return Err(ter::TEL_BAD_PUBLIC_KEY);
    }
    if tx.set_flag == Some(10) && tx.nftoken_minter.is_none() {
        return Err(ter::TEM_MALFORMED);
    }
    if tx.clear_flag == Some(10) && tx.nftoken_minter.is_some() {
        return Err(ter::TEM_MALFORMED);
    }

    Ok(())
}

fn nftoken_mint_preflight(tx: &ParsedTx) -> Result<(), TxResult> {
    const TF_BURNABLE: u32 = crate::ledger::nftoken::TF_BURNABLE as u32;
    const TF_ONLY_XRP: u32 = crate::ledger::nftoken::TF_ONLY_XRP as u32;
    const TF_TRANSFERABLE: u32 = crate::ledger::nftoken::TF_TRANSFERABLE as u32;
    const TF_MUTABLE: u32 = crate::ledger::nftoken::TF_MUTABLE as u32;
    const NFTOKEN_MINT_MASK: u32 = TF_BURNABLE | TF_ONLY_XRP | TF_TRANSFERABLE | TF_MUTABLE;

    if (tx.flags & !(TF_UNIVERSAL | NFTOKEN_MINT_MASK)) != 0 {
        return Err(ter::TEM_INVALID_FLAG);
    }

    let transfer_fee = tx.transfer_fee_field.unwrap_or(0);
    if transfer_fee > 50_000 {
        return Err(ter::TEM_BAD_NFTOKEN_TRANSFER_FEE);
    }

    if transfer_fee > 0 && (tx.flags & crate::ledger::nftoken::TF_TRANSFERABLE as u32) == 0 {
        return Err(ter::TEM_MALFORMED);
    }

    if tx.issuer == Some(tx.account) {
        return Err(ter::TEM_MALFORMED);
    }

    if tx
        .uri
        .as_ref()
        .is_some_and(|uri| uri.is_empty() || uri.len() > 256)
    {
        return Err(ter::TEM_MALFORMED);
    }

    if (tx.destination.is_some() || tx.expiration.is_some()) && tx.amount.is_none() {
        return Err(ter::TEM_MALFORMED);
    }

    if tx.destination == Some(tx.account) {
        return Err(ter::TEM_MALFORMED);
    }

    if tx.expiration == Some(0) {
        return Err(ter::TEM_BAD_EXPIRATION);
    }

    if (tx.flags & TF_ONLY_XRP) != 0
        && tx
            .amount
            .as_ref()
            .is_some_and(|a| !matches!(a, Amount::Xrp(_)))
    {
        return Err(ter::TEM_BAD_AMOUNT);
    }

    Ok(())
}

fn nftoken_accept_offer_preflight(tx: &ParsedTx) -> Result<(), TxResult> {
    let bo = tx.nft_buy_offer;
    let so = tx.nft_sell_offer;

    if bo.is_none() && so.is_none() {
        return Err(ter::TEM_MALFORMED);
    }

    if let Some(broker_fee) = tx.nftoken_broker_fee.as_ref() {
        if bo.is_none() || so.is_none() || !amount_is_positive(broker_fee) {
            return Err(ter::TEM_MALFORMED);
        }
    }

    Ok(())
}

fn amount_is_positive(amount: &Amount) -> bool {
    match amount {
        Amount::Xrp(drops) => *drops > 0,
        Amount::Iou { value, .. } => !value.is_zero() && !value.is_negative(),
        Amount::Mpt(raw) => raw.iter().any(|byte| *byte != 0),
    }
}

fn is_known_tx_type(tx_type: u16) -> bool {
    matches!(
        tx_type,
        0..=5
            | 7
            | 8
            | 10
            | 12..=21
            | 25..=31
            | 35..=41
            | 42..=49
            | 50..=61
            | 62..=71
            | 74..=78
            | 80..=82
            | 84
            | 100..=102
    )
}

fn offer_create_preflight(tx: &ParsedTx) -> Result<(), TxResult> {
    const TF_IMMEDIATE_OR_CANCEL: u32 = 0x0002_0000;
    const TF_FILL_OR_KILL: u32 = 0x0004_0000;
    const TF_HYBRID: u32 = 0x0010_0000;
    const MAX_XRP_DROPS: u64 = 100_000_000_000_000_000;

    if (tx.flags & TF_IMMEDIATE_OR_CANCEL) != 0 && (tx.flags & TF_FILL_OR_KILL) != 0 {
        return Err(ter::TEM_INVALID_FLAG);
    }

    if (tx.flags & TF_HYBRID) != 0 && tx.domain_id.is_none() {
        return Err(ter::TEM_INVALID_FLAG);
    }

    if tx.expiration == Some(0) {
        return Err(ter::TEM_BAD_EXPIRATION);
    }

    if tx.offer_sequence == Some(0) {
        return Err(ter::TEM_BAD_SEQUENCE);
    }

    let taker_pays = tx.taker_pays.as_ref().ok_or(ter::TEM_BAD_OFFER)?;
    let taker_gets = tx.taker_gets.as_ref().ok_or(ter::TEM_BAD_OFFER)?;
    check_offer_amount_preflight(taker_pays, MAX_XRP_DROPS)?;
    check_offer_amount_preflight(taker_gets, MAX_XRP_DROPS)?;

    if same_iou_issue(taker_pays, taker_gets) {
        return Err(ter::TEM_REDUNDANT);
    }

    Ok(())
}

fn check_offer_amount_preflight(amount: &Amount, max_xrp_drops: u64) -> Result<(), TxResult> {
    match amount {
        Amount::Xrp(drops) => {
            if *drops == 0 {
                return Err(ter::TEM_BAD_OFFER);
            }
            if *drops > max_xrp_drops {
                return Err(ter::TEM_BAD_AMOUNT);
            }
        }
        Amount::Iou {
            value,
            currency,
            issuer,
        } => {
            if value.is_zero() || value.is_negative() {
                return Err(ter::TEM_BAD_OFFER);
            }
            if currency.is_bad_currency() {
                return Err(ter::TEM_BAD_CURRENCY);
            }
            if *issuer == [0u8; 20] {
                return Err(ter::TEM_BAD_ISSUER);
            }
        }
        Amount::Mpt(_) => return Err(ter::TEM_BAD_AMOUNT),
    }
    Ok(())
}

fn set_regular_key_first_master_signed_fee_free(
    tx: &ParsedTx,
    acct: &crate::ledger::account::AccountRoot,
) -> bool {
    tx.tx_type == 5
        && tx.signers.is_empty()
        && !tx.signing_pubkey.is_empty()
        && crate::crypto::account_id(&tx.signing_pubkey) == tx.account
        && (acct.flags & crate::ledger::account::LSF_PASSWORD_SPENT) == 0
}

fn same_iou_issue(lhs: &Amount, rhs: &Amount) -> bool {
    match (lhs, rhs) {
        (
            Amount::Iou {
                currency: left_currency,
                issuer: left_issuer,
                ..
            },
            Amount::Iou {
                currency: right_currency,
                issuer: right_issuer,
                ..
            },
        ) => left_currency == right_currency && left_issuer == right_issuer,
        _ => false,
    }
}

fn check_network_id(tx: &ParsedTx, ctx: &TxContext) -> Result<(), TxResult> {
    let is_pseudo_tx = matches!(tx.tx_type, 100 | 101 | 102);
    if is_pseudo_tx && tx.network_id.is_none() {
        return Ok(());
    }

    if ctx.network_id <= 1024 {
        if tx.network_id.is_some() {
            return Err(ter::TEL_NETWORK_ID_MAKES_TX_NON_CANONICAL);
        }
        return Ok(());
    }

    match tx.network_id {
        None => Err(ter::TEL_REQUIRES_NETWORK_ID),
        Some(id) if id != ctx.network_id => Err(ter::TEL_WRONG_NETWORK),
        Some(_) => Ok(()),
    }
}

fn check_candidate_auth(
    state: &mut LedgerState,
    tx: &ParsedTx,
    acct: &crate::ledger::account::AccountRoot,
) -> Result<(), TxResult> {
    if let Some(delegate_account) = tx.delegate {
        delegate::check_delegated_tx_permission(state, &tx.account, &delegate_account, tx.tx_type)?;

        if !delegated_auth_modeled_tx(tx.tx_type) {
            return Err(ter::TER_NO_DELEGATE_PERMISSION);
        }

        let delegate_acct =
            load_existing_account(state, &delegate_account).ok_or(ter::TER_NO_ACCOUNT)?;
        if tx.signers.is_empty() {
            return check_single_signature_auth(tx, &delegate_acct, &delegate_account);
        }
        return check_multisign_auth(state, tx, &delegate_account);
    }

    if tx.signers.is_empty() {
        return check_single_signature_auth(tx, acct, &tx.account);
    }

    check_multisign_auth(state, tx, &tx.account)
}

pub(crate) fn check_submit_auth(state: &mut LedgerState, tx: &ParsedTx) -> Result<(), TxResult> {
    let acct = load_existing_account(state, &tx.account).ok_or(ter::TER_NO_ACCOUNT)?;
    check_candidate_auth(state, tx, &acct)
}

fn delegated_auth_modeled_tx(tx_type: u16) -> bool {
    matches!(tx_type, 8)
}

fn check_single_signature_auth(
    tx: &ParsedTx,
    acct: &crate::ledger::account::AccountRoot,
    auth_account: &[u8; 20],
) -> Result<(), TxResult> {
    let signing_account = crate::transaction::auth::verify_single_signature(tx).map_err(|err| {
        if err == crate::transaction::auth::TxAuthError::UnsupportedMultiSign {
            ter::TEF_BAD_AUTH
        } else {
            ter::TEM_BAD_SIGNATURE
        }
    })?;

    if &signing_account == auth_account {
        if (acct.flags & crate::ledger::account::LSF_DISABLE_MASTER) != 0 {
            return Err(ter::TEF_MASTER_DISABLED);
        }
        return Ok(());
    }

    if acct.regular_key == Some(signing_account) {
        Ok(())
    } else {
        Err(ter::TEF_BAD_AUTH)
    }
}

#[derive(Debug, Clone, Copy)]
struct SignerListEntry {
    account: [u8; 20],
    weight: u16,
}

#[derive(Debug, Clone)]
struct SignerListAuth {
    quorum: u32,
    entries: Vec<SignerListEntry>,
}

fn check_multisign_auth(
    state: &mut LedgerState,
    tx: &ParsedTx,
    auth_account: &[u8; 20],
) -> Result<(), TxResult> {
    let verified = crate::transaction::auth::verify_multisign_signatures(tx).map_err(|err| {
        if err == crate::transaction::auth::TxAuthError::BadSignature {
            ter::TEM_BAD_SIGNATURE
        } else {
            ter::TEM_BAD_SIGNER
        }
    })?;

    let signer_list =
        load_signer_list_for_auth(state, auth_account).ok_or(ter::TEF_NOT_MULTI_SIGNING)?;
    if signer_list.quorum == 0 || signer_list.entries.is_empty() {
        return Err(ter::TEF_BAD_QUORUM);
    }

    let mut weight_sum = 0u32;
    for signer in verified {
        let entry = signer_list
            .entries
            .iter()
            .find(|entry| entry.account == signer.account)
            .ok_or(ter::TEF_BAD_SIGNATURE)?;
        check_signer_key_auth(state, signer.account, signer.signing_account)?;
        weight_sum = weight_sum.saturating_add(entry.weight as u32);
    }

    if weight_sum >= signer_list.quorum {
        Ok(())
    } else {
        Err(ter::TEF_BAD_QUORUM)
    }
}

fn check_signer_key_auth(
    state: &mut LedgerState,
    signer_account: [u8; 20],
    signing_account: [u8; 20],
) -> Result<(), TxResult> {
    let Some(signer_root) = load_existing_account(state, &signer_account) else {
        return if signing_account == signer_account {
            Ok(())
        } else {
            Err(ter::TEF_BAD_SIGNATURE)
        };
    };

    if signing_account == signer_account {
        if (signer_root.flags & crate::ledger::account::LSF_DISABLE_MASTER) != 0 {
            return Err(ter::TEF_MASTER_DISABLED);
        }
        return Ok(());
    }

    if signer_root.regular_key == Some(signing_account) {
        Ok(())
    } else {
        Err(ter::TEF_BAD_SIGNATURE)
    }
}

fn load_signer_list_for_auth(state: &LedgerState, account: &[u8; 20]) -> Option<SignerListAuth> {
    let key = crate::ledger::keylet::signer_list(account).key;
    let raw = state
        .get_raw(&key)
        .map(|raw| raw.to_vec())
        .or_else(|| state.get_raw_owned(&key))
        .or_else(|| state.get_committed_raw_owned(&key))?;
    parse_signer_list_for_auth(&raw)
}

fn parse_signer_list_for_auth(raw: &[u8]) -> Option<SignerListAuth> {
    let sle = crate::ledger::meta::parse_sle(raw)?;
    if sle.entry_type != 0x0053 {
        return None;
    }

    let mut quorum = None::<u32>;
    let mut entries = None::<Vec<SignerListEntry>>;

    for field in sle.fields {
        match (field.type_code, field.field_code) {
            (2, 35) if field.data.len() == 4 => {
                quorum = Some(u32::from_be_bytes(field.data.try_into().ok()?));
            }
            (15, 4) => {
                entries = Some(parse_signer_entries_for_auth(&field.data)?);
            }
            _ => {}
        }
    }

    Some(SignerListAuth {
        quorum: quorum?,
        entries: entries?,
    })
}

fn parse_signer_entries_for_auth(data: &[u8]) -> Option<Vec<SignerListEntry>> {
    let mut pos = 0usize;
    let mut entries = Vec::new();

    while pos < data.len() {
        if data[pos] == 0xF1 {
            break;
        }

        let (type_code, _field_code, new_pos) = crate::ledger::meta::read_field_header(data, pos);
        if new_pos > data.len() || type_code != 14 {
            return None;
        }
        pos = new_pos;

        let mut account = None::<[u8; 20]>;
        let mut weight = None::<u16>;

        while pos < data.len() && data[pos] != 0xE1 {
            let (inner_type, inner_field, inner_pos) =
                crate::ledger::meta::read_field_header(data, pos);
            if inner_pos > data.len() {
                return None;
            }
            pos = inner_pos;

            match (inner_type, inner_field) {
                (1, 3) => {
                    if pos + 2 > data.len() {
                        return None;
                    }
                    weight = Some(u16::from_be_bytes([data[pos], data[pos + 1]]));
                    pos += 2;
                }
                (8, 1) => {
                    let (vlen, ladv) = crate::transaction::serialize::decode_length(&data[pos..]);
                    if ladv == 0 || vlen != 20 || pos + ladv + vlen > data.len() {
                        return None;
                    }
                    pos += ladv;
                    let mut id = [0u8; 20];
                    id.copy_from_slice(&data[pos..pos + 20]);
                    account = Some(id);
                    pos += 20;
                }
                _ => {
                    let next = crate::ledger::meta::skip_field_raw(data, pos, inner_type);
                    if next <= pos || next > data.len() {
                        return None;
                    }
                    pos = next;
                }
            }
        }

        if pos >= data.len() {
            return None;
        }
        pos += 1;
        entries.push(SignerListEntry {
            account: account?,
            weight: weight?,
        });
    }

    Some(entries)
}

fn fee_payer(tx: &ParsedTx) -> [u8; 20] {
    tx.delegate.unwrap_or(tx.account)
}

/// Apply only fee deduction and sequence/ticket consumption — no transaction-specific logic.
/// Used after a reset (discard) to claim the fee on tec results.
fn apply_fee_only(state: &mut LedgerState, tx: &ParsedTx) -> TxResult {
    if let Some(acct) = load_existing_account(state, &tx.account) {
        let mut updated = acct.clone();
        let payer_id = fee_payer(tx);
        let mut payer = if payer_id == tx.account {
            None
        } else {
            match load_existing_account(state, &payer_id) {
                Some(account) => Some(account),
                None => return ter::TER_NO_ACCOUNT,
            }
        };
        // Cap fee to available balance (rippled Transactor.cpp:1033-1034)
        if let Some(ref mut payer) = payer {
            let fee = std::cmp::min(tx.fee, payer.balance);
            payer.balance -= fee;
        } else {
            let fee = std::cmp::min(tx.fee, updated.balance);
            updated.balance -= fee;
        }
        if tx.sequence != 0 {
            updated.sequence += 1;
        } else if let Some(ticket_seq) = tx.ticket_sequence {
            if !consume_ticket(state, &tx.account, ticket_seq, &mut updated) {
                return ter::TEF_BAD_LEDGER;
            }
        }
        if updated.account_txn_id().is_some() {
            updated.set_account_txn_id(tx.tx_id);
        }
        state.insert_account(updated);
        if let Some(payer) = payer {
            state.insert_account(payer);
        }
        ter::TES_SUCCESS
    } else {
        ter::TER_NO_ACCOUNT
    }
}

pub(crate) fn load_existing_account(
    state: &mut LedgerState,
    account_id: &[u8; 20],
) -> Option<crate::ledger::account::AccountRoot> {
    if let Some(existing) = state.get_account(account_id).cloned() {
        return Some(existing);
    }

    let key = crate::ledger::account::shamap_key(account_id);
    let raw = state
        .get_raw_owned(&key)
        .or_else(|| state.get_committed_raw_owned(&key))?;
    let account = crate::ledger::account::AccountRoot::decode(&raw).ok()?;
    state.hydrate_account(account.clone());
    Some(account)
}

/// Classify a TxRunResult for the close loop.
/// Returns: Success, Fail (permanent), or Retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Transaction applied (tesSUCCESS or tec hard-fail).
    Success,
    /// Permanent failure — remove from transaction set.
    Fail,
    /// Retry — keep in set for next pass.
    Retry,
}

pub fn classify_result(result: &TxRunResult) -> ApplyOutcome {
    if result.applied {
        ApplyOutcome::Success
    } else if result.ter.is_permanent_failure() {
        ApplyOutcome::Fail
    } else {
        ApplyOutcome::Retry
    }
}

/// Apply a *pre-validated* transaction to the ledger state.
///
/// The caller must have already verified:
///   - Signature
///   - Signing key -> account match
///   - Account existence
///   - Sequence == account.sequence
///   - Balance >= fee (and >= fee + amount for Payments)
///
/// Returns `ApplyResult` after mutating the state.
/// A single majority entry: amendment hash + close time when majority was reached.
struct MajorityEntry {
    amendment: [u8; 32],
    close_time: u32,
}

/// Parse majority entries from raw sfMajorities array bytes (inner content including 0xF1 end marker).
#[cfg(test)]
fn parse_majority_entries(raw: &[u8]) -> Vec<MajorityEntry> {
    try_parse_majority_entries(raw).unwrap_or_default()
}

fn try_parse_majority_entries(raw: &[u8]) -> Option<Vec<MajorityEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        if raw[pos] == 0xF1 {
            return (pos + 1 == raw.len()).then_some(entries);
        }

        let (tc, fc, object_start) = crate::ledger::meta::read_field_header(raw, pos);
        if object_start <= pos || object_start > raw.len() || tc != 14 || fc != 18 {
            return None;
        }
        let object_end = crate::ledger::meta::skip_field_raw(raw, object_start, tc);
        if object_end <= object_start || object_end > raw.len() || raw[object_end - 1] != 0xE1 {
            return None;
        }

        let mut field_pos = object_start;
        let field_end = object_end - 1;
        let mut amendment = None;
        let mut close_time = None;

        while field_pos < field_end {
            let (inner_tc, inner_fc, data_start) =
                crate::ledger::meta::read_field_header(raw, field_pos);
            if data_start <= field_pos || data_start > field_end {
                return None;
            }
            let data_end = crate::ledger::meta::skip_field_raw(raw, data_start, inner_tc);
            if data_end <= data_start || data_end > field_end {
                return None;
            }
            match (inner_tc, inner_fc) {
                (2, 7) => {
                    let data = raw.get(data_start..data_start + 4)?;
                    close_time = Some(u32::from_be_bytes(data.try_into().ok()?));
                }
                (5, 19) => {
                    let data = raw.get(data_start..data_start + 32)?;
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(data);
                    amendment = Some(hash);
                }
                _ => {}
            }
            field_pos = data_end;
        }

        if let (Some(amendment), Some(close_time)) = (amendment, close_time) {
            entries.push(MajorityEntry {
                amendment,
                close_time,
            });
        } else {
            return None;
        }

        pos = object_end;
    }
    None
}

/// Serialize majority entries back to sfMajorities array raw bytes (including 0xF1 end marker).
fn serialize_majority_entries(entries: &[MajorityEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * 40 + 1);
    for e in entries {
        // sfMajority object (type=14 OBJECT, field=18)
        crate::ledger::encode_field_header(&mut out, 14, 18);
        // sfCloseTime (type=2 UInt32, field=7)
        crate::ledger::encode_field_header(&mut out, 2, 7);
        out.extend_from_slice(&e.close_time.to_be_bytes());
        // sfAmendment (type=5 Hash256, field=19)
        crate::ledger::encode_field_header(&mut out, 5, 19);
        out.extend_from_slice(&e.amendment);
        // Object end marker
        out.push(0xE1);
    }
    // Array end marker
    out.push(0xF1);
    out
}

/// Extract the raw sfMajorities array bytes from an Amendments SLE binary.
/// Returns the inner content (objects + end marker) excluding the field header.
/// Returns None if sfMajorities is not present.
fn extract_majorities_raw(sle_data: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0usize;
    while pos < sle_data.len() {
        let (type_code, field_code, data_start) =
            crate::ledger::meta::read_field_header(sle_data, pos);
        if data_start <= pos || data_start > sle_data.len() {
            return None;
        }
        let data_end = crate::ledger::meta::skip_field_raw(sle_data, data_start, type_code);
        if data_end <= data_start || data_end > sle_data.len() {
            return None;
        }
        if type_code == 15 && field_code == 16 {
            return Some(sle_data[data_start..data_end].to_vec());
        }
        pos = data_end;
    }
    None
}

/// Recover the sender balance before the transaction fee was deducted.
///
/// Reserve gates for reserve-creating transactors should use the pre-fee
/// balance, matching rippled's convention.
pub(crate) fn balance_before_fee(balance_after_fee: u64, fee: u64) -> u64 {
    balance_after_fee.saturating_add(fee)
}

pub(crate) fn owner_reserve_requirement(
    state: &LedgerState,
    owner_count: u32,
    additional: u32,
) -> u64 {
    let fees = crate::ledger::read_fees(state);
    fees.reserve + ((owner_count as u64 + additional as u64) * fees.increment)
}

fn escrow_finish_minimum_fee(
    base_fee: u64,
    signer_count: usize,
    fulfillment_len: Option<usize>,
) -> u64 {
    let ordinary_fee = base_fee.saturating_mul(1u64.saturating_add(signer_count as u64));
    let fulfillment_fee = fulfillment_len.map_or(0, |len| {
        base_fee.saturating_mul(32u64.saturating_add((len / 16) as u64))
    });
    ordinary_fee.saturating_add(fulfillment_fee)
}

pub fn apply_tx(state: &mut LedgerState, tx: &ParsedTx, ctx: &TxContext) -> ApplyResult {
    // ── Pseudo-transactions (system txs) ─────────────────────────────────────
    // These have Account=0x0000..., Fee=0, Sequence=0.  They don't debit any
    // account, so they are skipped here. (rippled: `Change.cpp` —
    // `ttAMENDMENT`, `ttFEE`, `ttUNL_MODIFY`)
    match tx.tx_type {
        100 => {
            // EnableAmendment — write Amendments SLE + update in-memory set.
            // (no flags = enabled, tfGotMajority = 0x10000, tfLostMajority = 0x20000)
            use crate::ledger::{amendments_key, read_amendments, serialize_amendments};
            let amendment_hash = match tx.amendment {
                Some(h) => h,
                None => return ApplyResult::ClaimedCost("temMALFORMED"),
            };
            if crate::transaction::parse::parsed_ledger_sequence(tx).is_none() {
                return ApplyResult::ClaimedCost("temMALFORMED");
            }
            let key = amendments_key();
            let mut enabled = read_amendments(state);
            if enabled.contains(&amendment_hash) {
                return ApplyResult::ClaimedCost("tefALREADY");
            }
            // Read existing majority entries and rebuild sfMajorities the same
            // way rippled does: all non-target entries pass through, while the
            // target entry is either replaced, removed, or rejected.
            let existing_raw = state.get_raw_owned(&key).unwrap_or_default();
            let majorities_raw = extract_majorities_raw(&existing_raw);
            let entries = match majorities_raw.as_deref() {
                Some(raw) => match try_parse_majority_entries(raw) {
                    Some(entries) => entries,
                    None => return ApplyResult::ClaimedCost("temMALFORMED"),
                },
                None => Vec::new(),
            };
            let mut found_majority = false;
            let mut new_entries = Vec::with_capacity(entries.len() + 1);
            for entry in entries {
                if entry.amendment == amendment_hash {
                    found_majority = true;
                } else {
                    new_entries.push(entry);
                }
            }
            let got_majority = (tx.flags & 0x0001_0000) != 0;
            let lost_majority = (tx.flags & 0x0002_0000) != 0;
            if (tx.flags & !0x0003_0000) != 0 || (got_majority && lost_majority) {
                return ApplyResult::ClaimedCost("temINVALID_FLAG");
            }

            if got_majority {
                if found_majority {
                    return ApplyResult::ClaimedCost("tefALREADY");
                }
                let majority_close_time = if ctx.parent_close_time != 0 {
                    ctx.parent_close_time
                } else {
                    ctx.close_time
                };
                new_entries.push(MajorityEntry {
                    amendment: amendment_hash,
                    close_time: majority_close_time as u32,
                });
                let new_maj = serialize_majority_entries(&new_entries);
                let sle = serialize_amendments(&enabled, Some(&new_maj));
                state.insert_raw(key, sle);
            } else if lost_majority {
                if !found_majority {
                    return ApplyResult::ClaimedCost("tefALREADY");
                }
                let new_maj = if new_entries.is_empty() {
                    None
                } else {
                    Some(serialize_majority_entries(&new_entries))
                };
                let sle = serialize_amendments(&enabled, new_maj.as_deref());
                state.insert_raw(key, sle);
            } else {
                // Direct enable — add to sfAmendments if not already present.
                enabled.push(amendment_hash);
                state.enable_amendment(amendment_hash);
                tracing::info!(
                    "amendment enabled: {}",
                    hex::encode_upper(&amendment_hash[..8]),
                );
                let new_maj = if new_entries.is_empty() {
                    None
                } else {
                    Some(serialize_majority_entries(&new_entries))
                };
                let sle = serialize_amendments(&enabled, new_maj.as_deref());
                state.insert_raw(key, sle);
            }
            return ApplyResult::Success;
        }
        101 => {
            // SetFee — write FeeSettings SLE with fee fields from pseudo-tx.
            use crate::ledger::{
                fees_key, serialize_fee_settings, serialize_fee_settings_xrp_fees, Fees,
            };
            let key = fees_key();
            let xrp_fees_enabled = state.is_amendment_active(&*FEATURE_XRP_FEES);
            let has_new_fields = crate::transaction::parse::parsed_base_fee_drops(tx).is_some()
                || crate::transaction::parse::parsed_reserve_base_drops(tx).is_some()
                || crate::transaction::parse::parsed_reserve_increment_drops(tx).is_some();
            let has_old_fields = tx.base_fee_field.is_some()
                || crate::transaction::parse::parsed_reference_fee_units(tx).is_some()
                || tx.reserve_base_field.is_some()
                || tx.reserve_increment_field.is_some();
            let fees = if xrp_fees_enabled {
                if has_old_fields {
                    return ApplyResult::ClaimedCost("temMALFORMED");
                }
                Fees {
                    base: match crate::transaction::parse::parsed_base_fee_drops(tx) {
                        Some(base) => base,
                        None => return ApplyResult::ClaimedCost("temMALFORMED"),
                    },
                    reserve: match crate::transaction::parse::parsed_reserve_base_drops(tx) {
                        Some(reserve) => reserve,
                        None => return ApplyResult::ClaimedCost("temMALFORMED"),
                    },
                    increment: match crate::transaction::parse::parsed_reserve_increment_drops(tx) {
                        Some(increment) => increment,
                        None => return ApplyResult::ClaimedCost("temMALFORMED"),
                    },
                }
            } else {
                if has_new_fields {
                    return ApplyResult::ClaimedCost("temDISABLED");
                }
                if crate::transaction::parse::parsed_reference_fee_units(tx).is_none() {
                    return ApplyResult::ClaimedCost("temMALFORMED");
                }
                Fees {
                    base: match tx.base_fee_field {
                        Some(base) => base,
                        None => return ApplyResult::ClaimedCost("temMALFORMED"),
                    },
                    reserve: match tx.reserve_base_field {
                        Some(reserve) => reserve as u64,
                        None => return ApplyResult::ClaimedCost("temMALFORMED"),
                    },
                    increment: match tx.reserve_increment_field {
                        Some(increment) => increment as u64,
                        None => return ApplyResult::ClaimedCost("temMALFORMED"),
                    },
                }
            };
            let sle = if xrp_fees_enabled {
                serialize_fee_settings_xrp_fees(&fees)
            } else {
                serialize_fee_settings(&fees)
            };
            state.insert_raw(key, sle);
            tracing::info!(
                "SetFee: base={} reserve={} increment={}",
                fees.base,
                fees.reserve,
                fees.increment,
            );
            return ApplyResult::Success;
        }
        102 => {
            // UNLModify — mirror rippled's flag-ledger NegativeUNL update.
            use crate::ledger::{parse_negative_unl, serialize_negative_unl};
            if !is_flag_ledger(ctx.ledger_seq) {
                return ApplyResult::ClaimedCost("tefFAILURE");
            }
            if crate::transaction::parse::parsed_ledger_sequence(tx) != Some(ctx.ledger_seq) {
                return ApplyResult::ClaimedCost("tefFAILURE");
            }
            let validator_key = match &tx.unl_modify_validator {
                Some(k) => k.clone(),
                None => return ApplyResult::ClaimedCost("tefFAILURE"),
            };
            if !is_valid_validator_public_key(&validator_key) {
                return ApplyResult::ClaimedCost("tefFAILURE");
            }
            let disabling_field = match tx.unl_modify_disabling {
                Some(value) if value <= 1 => value,
                _ => return ApplyResult::ClaimedCost("tefFAILURE"),
            };
            let disabling = disabling_field == 1;
            let key = crate::ledger::keylet::negative_unl().key;
            let existing = state
                .get_raw_owned(&key)
                .or_else(|| state.get_committed_raw_owned(&key));
            let mut negative_unl = existing
                .as_deref()
                .map(parse_negative_unl)
                .unwrap_or_default();
            let already_disabled = negative_unl
                .disabled_validators
                .iter()
                .any(|validator| validator == &validator_key);
            if disabling {
                if negative_unl.to_disable.is_some()
                    || negative_unl.to_reenable.as_deref() == Some(validator_key.as_slice())
                    || already_disabled
                {
                    return ApplyResult::ClaimedCost("tefFAILURE");
                }
                negative_unl.to_disable = Some(validator_key.clone());
            } else {
                if negative_unl.to_reenable.is_some()
                    || negative_unl.to_disable.as_deref() == Some(validator_key.as_slice())
                    || !already_disabled
                {
                    return ApplyResult::ClaimedCost("tefFAILURE");
                }
                negative_unl.to_reenable = Some(validator_key.clone());
            }
            let sle = serialize_negative_unl(
                &negative_unl.disabled_validators,
                negative_unl.to_disable.as_deref(),
                negative_unl.to_reenable.as_deref(),
            );
            state.insert_raw(key, sle);
            tracing::info!(
                "UNLModify: {} validator {} at flag ledger {}",
                if disabling {
                    "disabling"
                } else {
                    "re-enabling"
                },
                hex::encode_upper(&validator_key[..8.min(validator_key.len())]),
                ctx.ledger_seq,
            );
            return ApplyResult::Success;
        }
        _ => {}
    }

    // ── Amendment gate ────────────────────────────────────────────────────────
    // Log, but generally do not block here, transaction types whose amendment
    // is not in the local amendment set.
    // During replay of validated ledgers, the network already accepted these txs.
    // Blocking them would cause hash divergence. Independent `run_tx` blocks
    // inactive amendments before this point.
    //
    // Exception: source-only/open-vote/obsolete families must stay inert unless
    // the ledger's amendment set explicitly activates them. This keeps mainnet
    // parity work focused on enabled XRPL behavior and prevents half-built
    // experimental handlers from mutating state during replay.
    if let Some(hash) = required_amendment(tx.tx_type) {
        if !state.is_amendment_active(hash) {
            if requires_explicit_replay_amendment(tx.tx_type) {
                tracing::warn!(
                    "apply_tx: tx type {} requires inactive/non-mainnet amendment {}; rejecting with temDISABLED",
                    tx.tx_type,
                    hex::encode(&hash[..4]),
                );
                return ApplyResult::ClaimedCost("temDISABLED");
            }
            tracing::debug!(
                "apply_tx: tx type {} — amendment {} not in local set (proceeding anyway)",
                tx.tx_type,
                hex::encode(&hash[..4]),
            );
        }
    }

    // Load the sender's account.
    let mut new_sender = match load_existing_account(state, &tx.account) {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("terNO_ACCOUNT"),
    };
    let payer_id = fee_payer(tx);
    let mut fee_payer_account = if payer_id == tx.account {
        None
    } else {
        match load_existing_account(state, &payer_id) {
            Some(a) => Some(a),
            None => return ApplyResult::ClaimedCost("terNO_ACCOUNT"),
        }
    };
    let pre_fee_balance = new_sender.balance;

    // 1. Deduct fee
    if let Some(ref mut payer) = fee_payer_account {
        payer.balance = payer.balance.saturating_sub(tx.fee);
    } else {
        new_sender.balance = new_sender.balance.saturating_sub(tx.fee);
    }

    // 2. Bump sequence (only for non-ticket txs)
    // Ticket-based txs (sequence=0) consume the ticket instead of bumping.
    if tx.sequence != 0 {
        new_sender.sequence += 1;
    } else if let Some(ticket_seq) = tx.ticket_sequence {
        // Consume the ticket: delete from state, remove from owner directory,
        // decrement owner_count. Matches rippled's consumeTicket().
        if !consume_ticket(state, &tx.account, ticket_seq, &mut new_sender) {
            return ApplyResult::ClaimedCost("tefBAD_LEDGER");
        }
    }

    if new_sender.account_txn_id().is_some() {
        new_sender.set_account_txn_id(tx.tx_id);
    }
    if let Some(payer) = fee_payer_account {
        state.insert_account(payer);
    }

    // 3. Apply transaction-type-specific effects
    //
    // For escrow finish/cancel: persist the sender FIRST because the handler
    // may update a different account (the escrow owner) in state.
    // Tx type codes verified against rippled/include/xrpl/protocol/detail/transactions.macro
    let result = match tx.tx_type {
        2 | 4 | 7 | 8 | 15 | 17 | 18 | 26 | 28 | 29 | 30 | 31 | 35 | 36 | 37 | 38 | 39 | 40
        | 59 | 60 | 65 | 67 | 68 | 69 | 74 | 75 | 76 | 77 | 78 | 80 | 81 | 82 | 84 => {
            // Persist sender (fee + sequence bump) before handler — these
            // handlers modify the sender's account (or other accounts) through
            // state directly, so the local `new_sender` copy must be written
            // first to avoid clobbering crossing/transfer changes.
            state.insert_account(new_sender);
            match tx.tx_type {
                2 => escrow::apply_escrow_finish(state, tx, ctx.close_time), // EscrowFinish
                4 => escrow::apply_escrow_cancel(state, tx, ctx.close_time), // EscrowCancel
                7 => {
                    let local = offer::apply_offer_create(state, tx, ctx.close_time);
                    if ctx.trusted_validated_replay
                        && ctx.validated_offer_create_amm_bridge
                        && local != ApplyResult::Success
                    {
                        bridge_metadata_only_tx(
                            ctx,
                            tx.tx_type,
                            "OfferCreate AMM validated bridge",
                            "temUNKNOWN",
                        )
                    } else {
                        local
                    }
                } // OfferCreate
                8 => offer::apply_offer_cancel(state, tx),                   // OfferCancel
                15 => paychan::apply_paychan_claim(state, tx, ctx.close_time), // PaymentChannelClaim
                17 => check::apply_check_cash(state, tx, ctx.close_time),      // CheckCash
                18 => check::apply_check_cancel(state, tx, ctx.close_time),    // CheckCancel
                26 => nftoken::apply_nftoken_burn(state, tx),                  // NFTokenBurn
                28 => nftoken::apply_nftoken_cancel_offer(state, tx),          // NFTokenCancelOffer
                29 => nftoken::apply_nftoken_accept_offer(state, tx, ctx.close_time), // NFTokenAcceptOffer
                30 => clawback::apply_clawback(state, tx, ctx),                       // Clawback
                31 => amm::apply_amm_clawback(state, tx),                             // AMMClawback
                59 => credential::apply_credential_accept(state, tx, ctx.close_time), // CredentialAccept
                60 => credential::apply_credential_delete(state, tx, ctx.close_time), // CredentialDelete
                35 => amm::apply_amm_create(state, tx, ctx),                          // AMMCreate
                36 => amm::apply_amm_deposit(state, tx),                              // AMMDeposit
                37 => amm::apply_amm_withdraw(state, tx),                             // AMMWithdraw
                38 => amm::apply_amm_vote(state, tx),                                 // AMMVote
                39 => amm::apply_amm_bid(state, tx, ctx),                             // AMMBid
                40 => amm::apply_amm_delete(state, tx),                               // AMMDelete
                65 => vault::apply_vault_create(state, tx, ctx),                      // VaultCreate
                67 => vault::apply_vault_delete(state, tx),                           // VaultDelete
                68 => vault::apply_vault_deposit(state, tx), // VaultDeposit
                69 => vault::apply_vault_withdraw(state, tx), // VaultWithdraw
                74 => loan::apply_loan_broker_set(state, tx, ctx), // LoanBrokerSet
                75 => loan::apply_loan_broker_delete(state, tx), // LoanBrokerDelete
                76 => loan::apply_loan_broker_cover_deposit(state, tx), // LoanBrokerCoverDeposit
                77 => loan::apply_loan_broker_cover_withdraw(state, tx), // LoanBrokerCoverWithdraw
                78 => loan::apply_loan_broker_cover_clawback(state, tx), // LoanBrokerCoverClawback
                80 => loan::apply_loan_set(state, tx, ctx),  // LoanSet
                81 => loan::apply_loan_delete(state, tx),    // LoanDelete
                82 => loan::apply_loan_manage(state, tx, ctx), // LoanManage
                84 => loan::apply_loan_pay(state, tx),       // LoanPay
                _ => unreachable!(),
            }
        }
        _ => {
            let r = match tx.tx_type {
                0 => payment::apply_payment(state, tx, &mut new_sender, ctx), // Payment
                1 => escrow::apply_escrow_create(state, tx, &mut new_sender, ctx.close_time), // EscrowCreate
                3 => account_set::apply_account_set(
                    state,
                    tx,
                    &mut new_sender,
                    state.is_amendment_active(&*FEATURE_CLAWBACK),
                    state.is_amendment_active(&*FEATURE_TOKEN_ESCROW),
                ), // AccountSet
                5 => account_set::apply_set_regular_key(state, tx, &mut new_sender), // SetRegularKey
                10 => ticket::apply_ticket_create(state, tx, &mut new_sender),       // TicketCreate
                12 => signer_list_set::apply_signer_list_set(state, tx, &mut new_sender), // SignerListSet
                13 => paychan::apply_paychan_create(state, tx, &mut new_sender, ctx.close_time), // PaymentChannelCreate
                14 => paychan::apply_paychan_fund(state, tx, &mut new_sender, ctx.close_time), // PaymentChannelFund
                16 => check::apply_check_create(state, tx, &mut new_sender, ctx.close_time), // CheckCreate
                19 => deposit_preauth::apply_deposit_preauth(state, tx, &mut new_sender), // DepositPreauth
                20 => {
                    let deep_freeze_enabled = state.is_amendment_active(&*FEATURE_DEEP_FREEZE);
                    trust_set::apply_trustset(state, tx, &mut new_sender, deep_freeze_enabled)
                } // TrustSet
                21 => account_delete::apply_account_delete(state, tx, &mut new_sender, ctx), // AccountDelete
                25 => nftoken::apply_nftoken_mint(
                    state,
                    tx,
                    &mut new_sender,
                    ctx.close_time,
                    pre_fee_balance,
                ), // NFTokenMint
                27 => nftoken::apply_nftoken_create_offer(state, tx, &mut new_sender), // NFTokenCreateOffer
                // ── XChain types (not active on mainnet) ────────────────────
                41 | 42 | 43 | 44 | 45 | 46 | 47 | 48 => xchain::apply_xchain(ctx), // XChain*
                49 => did::apply_did_set(state, tx, &mut new_sender),               // DIDSet
                50 => did::apply_did_delete(state, tx, &mut new_sender),            // DIDDelete
                51 => oracle::apply_oracle_set(state, tx, &mut new_sender, ctx.close_time), // OracleSet
                52 => oracle::apply_oracle_delete(state, tx, &mut new_sender), // OracleDelete
                53 => ledger_state_fix::apply_ledger_state_fix(state, tx),     // LedgerStateFix
                54 => mptoken::apply_mptoken_issuance_create(state, tx, &mut new_sender), // MPTokenIssuanceCreate
                55 => mptoken::apply_mptoken_issuance_destroy(state, tx, &mut new_sender), // MPTokenIssuanceDestroy
                56 => mptoken::apply_mptoken_issuance_set(state, tx, &mut new_sender), // MPTokenIssuanceSet
                57 => mptoken::apply_mptoken_authorize(state, tx, &mut new_sender), // MPTokenAuthorize
                58 => {
                    credential::apply_credential_create(state, tx, &mut new_sender, ctx.close_time)
                } // CredentialCreate
                61 => nftoken_modify::apply_nftoken_modify(state, tx),              // NFTokenModify
                62 => {
                    permissioned_domain::apply_permissioned_domain_set(state, tx, &mut new_sender)
                } // PermissionedDomainSet
                63 => permissioned_domain::apply_permissioned_domain_delete(
                    state,
                    tx,
                    &mut new_sender,
                ), // PermissionedDomainDelete
                64 => delegate::apply_delegate_set(state, tx, &mut new_sender),     // DelegateSet
                // ── Vault types ──────────────────────────────────────────────
                66 => vault::apply_vault_set(state, tx, ctx), // VaultSet
                70 => vault::apply_vault_clawback(state, tx, ctx), // VaultClawback
                71 => batch::apply_batch(ctx),                // Batch (not active)
                // ── Loan types ──────────────────────────────────────────────
                76 => loan::apply_loan_broker_cover_deposit(state, tx), // LoanBrokerCoverDeposit
                77 => loan::apply_loan_broker_cover_withdraw(state, tx), // LoanBrokerCoverWithdraw
                78 => loan::apply_loan_broker_cover_clawback(state, tx), // LoanBrokerCoverClawback
                82 => loan::apply_loan_manage(state, tx, ctx),          // LoanManage
                // ── Unknown/future tx types — fee+seq only ───────────────────
                _ => bridge_metadata_only_tx(
                    ctx,
                    tx.tx_type,
                    "unknown/future tx type",
                    "tecINCOMPLETE",
                ),
            };
            // 4. Persist the updated sender account. AccountDelete is the one
            // successful transactor that removes its AccountRoot instead.
            if !(tx.tx_type == 21 && matches!(r, ApplyResult::Success)) {
                state.insert_account(new_sender);
            }
            r
        }
    };

    result
}

fn is_valid_validator_public_key(key: &[u8]) -> bool {
    matches!(key, [0x02 | 0x03, ..] if key.len() == 33)
        || matches!(key, [0xED, ..] if key.len() == 33)
}

fn is_flag_ledger(seq: u32) -> bool {
    const FLAG_LEDGER_INTERVAL: u32 = 256;
    seq != 0 && seq % FLAG_LEDGER_INTERVAL == 0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
    use crate::ledger::{AccountRoot, LedgerState};
    use crate::transaction::{builder::TxBuilder, parse_blob, Amount};

    fn ctx(close_time: u64) -> TxContext {
        TxContext {
            close_time,
            ..TxContext::default()
        }
    }

    fn genesis_kp() -> KeyPair {
        KeyPair::Secp256k1(Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap())
    }

    fn genesis_id() -> [u8; 20] {
        let kp = genesis_kp();
        crate::crypto::account_id(&kp.public_key_bytes())
    }

    fn delegate_kp() -> KeyPair {
        KeyPair::Secp256k1(Secp256k1KeyPair::from_seed("shHM53KPZ87Gwdqarm1bAmPeXg8Tn").unwrap())
    }

    fn delegate_id() -> [u8; 20] {
        let kp = delegate_kp();
        crate::crypto::account_id(&kp.public_key_bytes())
    }

    #[test]
    fn escrow_finish_fulfillment_minimum_fee_matches_rippled_formula() {
        assert_eq!(escrow_finish_minimum_fee(10, 0, None), 10);
        assert_eq!(escrow_finish_minimum_fee(10, 0, Some(0)), 330);
        assert_eq!(escrow_finish_minimum_fee(10, 0, Some(15)), 330);
        assert_eq!(escrow_finish_minimum_fee(10, 0, Some(16)), 340);
        assert_eq!(escrow_finish_minimum_fee(10, 2, Some(32)), 370);
    }

    fn dest_id() -> [u8; 20] {
        crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap()
    }

    fn add_account(state: &mut LedgerState, account_id: [u8; 20], balance: u64, sequence: u32) {
        state.insert_account(AccountRoot {
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
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        });
    }

    fn permission_entries_raw(values: &[u32]) -> Vec<u8> {
        let mut raw = Vec::new();
        for value in values {
            raw.push(0xEF); // sfPermission object
            raw.push(0x20); // sfPermissionValue UInt32 extended field header
            raw.push(52);
            raw.extend_from_slice(&value.to_be_bytes());
            raw.push(0xE1); // object end
        }
        raw.push(0xF1); // array end
        raw
    }

    fn set_fee_xrp_fees_blob(base: u64, reserve: u64, increment: u64) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.push(0x12); // TransactionType
        blob.extend_from_slice(&101u16.to_be_bytes());
        blob.extend_from_slice(&[0x60, 22]); // sfBaseFeeDrops
        blob.extend_from_slice(&Amount::Xrp(base).to_bytes());
        blob.extend_from_slice(&[0x60, 23]); // sfReserveBaseDrops
        blob.extend_from_slice(&Amount::Xrp(reserve).to_bytes());
        blob.extend_from_slice(&[0x60, 24]); // sfReserveIncrementDrops
        blob.extend_from_slice(&Amount::Xrp(increment).to_bytes());
        blob
    }

    fn set_fee_legacy_blob(base: u64, reserve: u32, increment: u32) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.push(0x12); // TransactionType
        blob.extend_from_slice(&101u16.to_be_bytes());
        blob.extend_from_slice(&[0x20, 30]); // sfReferenceFeeUnits
        blob.extend_from_slice(&10u32.to_be_bytes());
        blob.extend_from_slice(&[0x20, 31]); // sfReserveBase
        blob.extend_from_slice(&reserve.to_be_bytes());
        blob.extend_from_slice(&[0x20, 32]); // sfReserveIncrement
        blob.extend_from_slice(&increment.to_be_bytes());
        blob.push(0x35); // sfBaseFee
        blob.extend_from_slice(&base.to_be_bytes());
        blob
    }

    fn unl_modify_blob(
        disabling: u8,
        ledger_seq: Option<u32>,
        validator: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.push(0x12); // TransactionType
        blob.extend_from_slice(&102u16.to_be_bytes());
        if let Some(seq) = ledger_seq {
            blob.extend_from_slice(&[0x20, 27]); // sfLedgerSequence
            blob.extend_from_slice(&seq.to_be_bytes());
        }
        if let Some(key) = validator {
            blob.extend_from_slice(&[0x70, 19]); // sfUNLModifyValidator
            crate::ledger::meta::encode_vl_length(&mut blob, key.len());
            blob.extend_from_slice(key);
        }
        blob.extend_from_slice(&[0x00, 16, 17]); // sfUNLModifyDisabling
        blob.push(disabling);
        blob
    }

    fn enable_amendment_blob(
        flags: u32,
        ledger_seq: Option<u32>,
        amendment: Option<[u8; 32]>,
    ) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.push(0x12); // TransactionType
        blob.extend_from_slice(&100u16.to_be_bytes());
        if flags != 0 {
            blob.push(0x22); // Flags
            blob.extend_from_slice(&flags.to_be_bytes());
        }
        if let Some(seq) = ledger_seq {
            blob.extend_from_slice(&[0x20, 27]); // sfLedgerSequence
            blob.extend_from_slice(&seq.to_be_bytes());
        }
        if let Some(hash) = amendment {
            blob.extend_from_slice(&[0x50, 19]); // sfAmendment
            blob.extend_from_slice(&hash);
        }
        blob
    }

    fn flag_ctx(ledger_seq: u32) -> TxContext {
        TxContext {
            ledger_seq,
            ..ctx(0)
        }
    }

    #[test]
    fn test_set_fee_xrp_fees_writes_new_fee_settings() {
        let mut state = LedgerState::new();
        state.enable_amendment(*FEATURE_XRP_FEES);
        let tx = parse_blob(&set_fee_xrp_fees_blob(12, 2_000_000, 300_000)).unwrap();

        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let raw = state.get_raw(&crate::ledger::fees_key()).unwrap();
        let fees = crate::ledger::parse_fee_settings(raw);
        assert_eq!(fees.base, 12);
        assert_eq!(fees.reserve, 2_000_000);
        assert_eq!(fees.increment, 300_000);
        assert!(raw.windows(2).any(|w| w == [0x60, 22]));
        assert!(raw.windows(2).any(|w| w == [0x60, 23]));
        assert!(raw.windows(2).any(|w| w == [0x60, 24]));
        assert!(!raw.windows(2).any(|w| w == [0x20, 30]));
        assert!(!raw.windows(2).any(|w| w == [0x20, 31]));
        assert!(!raw.windows(2).any(|w| w == [0x20, 32]));
        assert!(!raw.contains(&0x35));
    }

    #[test]
    fn test_set_fee_rejects_wrong_field_family_for_xrp_fees_state() {
        let mut state = LedgerState::new();
        state.enable_amendment(*FEATURE_XRP_FEES);
        let legacy = parse_blob(&set_fee_legacy_blob(10, 1_000_000, 200_000)).unwrap();
        assert_eq!(
            apply_tx(&mut state, &legacy, &ctx(0)),
            ApplyResult::ClaimedCost("temMALFORMED")
        );

        let mut legacy_state = LedgerState::new();
        let modern = parse_blob(&set_fee_xrp_fees_blob(10, 1_000_000, 200_000)).unwrap();
        assert_eq!(
            apply_tx(&mut legacy_state, &modern, &ctx(0)),
            ApplyResult::ClaimedCost("temDISABLED")
        );
    }

    #[test]
    fn test_set_fee_legacy_and_xrp_fees_write_distinct_field_families() {
        let legacy = parse_blob(&set_fee_legacy_blob(10, 1_000_000, 200_000)).unwrap();
        let modern = parse_blob(&set_fee_xrp_fees_blob(12, 2_000_000, 300_000)).unwrap();

        let mut legacy_state = LedgerState::new();
        assert_eq!(
            apply_tx(&mut legacy_state, &legacy, &ctx(0)),
            ApplyResult::Success
        );
        let legacy_raw = legacy_state.get_raw(&crate::ledger::fees_key()).unwrap();
        assert!(legacy_raw.windows(2).any(|w| w == [0x20, 30]));
        assert!(legacy_raw.windows(2).any(|w| w == [0x20, 31]));
        assert!(legacy_raw.windows(2).any(|w| w == [0x20, 32]));
        assert!(legacy_raw.contains(&0x35));
        assert!(!legacy_raw.windows(2).any(|w| w == [0x60, 22]));

        let mut modern_state = LedgerState::new();
        modern_state.enable_amendment(*FEATURE_XRP_FEES);
        assert_eq!(
            apply_tx(&mut modern_state, &modern, &ctx(0)),
            ApplyResult::Success
        );
        let modern_raw = modern_state.get_raw(&crate::ledger::fees_key()).unwrap();
        assert!(modern_raw.windows(2).any(|w| w == [0x60, 22]));
        assert!(modern_raw.windows(2).any(|w| w == [0x60, 23]));
        assert!(modern_raw.windows(2).any(|w| w == [0x60, 24]));
        assert!(!modern_raw.windows(2).any(|w| w == [0x20, 30]));
    }

    #[test]
    fn test_enable_amendment_requires_required_fields() {
        let amendment = [0xA1; 32];
        let missing_ledger = parse_blob(&enable_amendment_blob(0, None, Some(amendment))).unwrap();
        assert_eq!(
            apply_tx(&mut LedgerState::new(), &missing_ledger, &ctx(0)),
            ApplyResult::ClaimedCost("temMALFORMED")
        );

        let missing_amendment = parse_blob(&enable_amendment_blob(0, Some(123), None)).unwrap();
        assert_eq!(
            apply_tx(&mut LedgerState::new(), &missing_amendment, &ctx(0)),
            ApplyResult::ClaimedCost("temMALFORMED")
        );
    }

    #[test]
    fn test_enable_amendment_direct_enable_removes_matching_majority() {
        let amendment = [0xA2; 32];
        let other = [0xB2; 32];
        let key = crate::ledger::amendments_key();
        let majority_raw = serialize_majority_entries(&[
            MajorityEntry {
                amendment,
                close_time: 10,
            },
            MajorityEntry {
                amendment: other,
                close_time: 20,
            },
        ]);
        let mut state = LedgerState::new();
        state.insert_raw(
            key,
            crate::ledger::serialize_amendments(&[], Some(&majority_raw)),
        );
        let tx = parse_blob(&enable_amendment_blob(0, Some(321), Some(amendment))).unwrap();

        assert_eq!(apply_tx(&mut state, &tx, &ctx(0)), ApplyResult::Success);

        assert!(state.is_amendment_active(&amendment));
        assert_eq!(crate::ledger::read_amendments(&state), vec![amendment]);
        let raw = state.get_raw(&key).unwrap();
        let remaining = parse_majority_entries(&extract_majorities_raw(raw).unwrap());
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].amendment, other);
        assert_eq!(remaining[0].close_time, 20);
    }

    #[test]
    fn test_enable_amendment_got_majority_uses_parent_close_time() {
        let amendment = [0xA3; 32];
        let key = crate::ledger::amendments_key();
        let tx = parse_blob(&enable_amendment_blob(
            0x0001_0000,
            Some(512),
            Some(amendment),
        ))
        .unwrap();
        let run_ctx = TxContext {
            close_time: 999,
            parent_close_time: 777,
            ..TxContext::default()
        };
        let mut state = LedgerState::new();

        assert_eq!(apply_tx(&mut state, &tx, &run_ctx), ApplyResult::Success);

        assert!(!state.is_amendment_active(&amendment));
        assert!(crate::ledger::read_amendments(&state).is_empty());
        let raw = state.get_raw(&key).unwrap();
        let entries = parse_majority_entries(&extract_majorities_raw(raw).unwrap());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].amendment, amendment);
        assert_eq!(entries[0].close_time, 777);
    }

    #[test]
    fn test_enable_amendment_rejects_malformed_structured_majority_array() {
        let amendment = [0xAC; 32];
        let key = crate::ledger::amendments_key();
        let mut malformed_majority = Vec::new();
        crate::ledger::encode_field_header(&mut malformed_majority, 14, 18);
        crate::ledger::encode_field_header(&mut malformed_majority, 5, 19);
        malformed_majority.extend_from_slice(&amendment);
        malformed_majority.push(0xE1);
        malformed_majority.push(0xF1);
        let mut state = LedgerState::new();
        state.insert_raw(
            key,
            crate::ledger::serialize_amendments(&[], Some(&malformed_majority)),
        );
        let tx = parse_blob(&enable_amendment_blob(
            0x0002_0000,
            Some(512),
            Some(amendment),
        ))
        .unwrap();

        assert_eq!(
            apply_tx(&mut state, &tx, &ctx(0)),
            ApplyResult::ClaimedCost("temMALFORMED")
        );
    }

    #[test]
    fn test_enable_amendment_lost_majority_removes_matching_entry() {
        let amendment = [0xA4; 32];
        let key = crate::ledger::amendments_key();
        let majority_raw = serialize_majority_entries(&[MajorityEntry {
            amendment,
            close_time: 50,
        }]);
        let mut state = LedgerState::new();
        state.insert_raw(
            key,
            crate::ledger::serialize_amendments(&[], Some(&majority_raw)),
        );
        let tx = parse_blob(&enable_amendment_blob(
            0x0002_0000,
            Some(768),
            Some(amendment),
        ))
        .unwrap();

        assert_eq!(apply_tx(&mut state, &tx, &ctx(0)), ApplyResult::Success);

        let raw = state.get_raw(&key).unwrap();
        assert!(extract_majorities_raw(raw).is_none());

        let mut empty_state = LedgerState::new();
        assert_eq!(
            apply_tx(&mut empty_state, &tx, &ctx(0)),
            ApplyResult::ClaimedCost("tefALREADY")
        );
    }

    #[test]
    fn test_enable_amendment_rejects_already_enabled_for_all_modes() {
        let amendment = [0xA5; 32];
        let key = crate::ledger::amendments_key();
        let tx_direct = parse_blob(&enable_amendment_blob(0, Some(1), Some(amendment))).unwrap();
        let tx_got = parse_blob(&enable_amendment_blob(
            0x0001_0000,
            Some(1),
            Some(amendment),
        ))
        .unwrap();
        let tx_lost = parse_blob(&enable_amendment_blob(
            0x0002_0000,
            Some(1),
            Some(amendment),
        ))
        .unwrap();

        for tx in [&tx_direct, &tx_got, &tx_lost] {
            let mut state = LedgerState::new();
            state.insert_raw(key, crate::ledger::serialize_amendments(&[amendment], None));
            state.enable_amendment(amendment);
            assert_eq!(
                apply_tx(&mut state, tx, &ctx(0)),
                ApplyResult::ClaimedCost("tefALREADY")
            );
        }
    }

    #[test]
    fn test_unl_modify_requires_flag_ledger_and_matching_sequence() {
        let validator = vec![0x02; 33];
        let tx = parse_blob(&unl_modify_blob(1, Some(256), Some(&validator))).unwrap();

        assert_eq!(
            apply_tx(&mut LedgerState::new(), &tx, &flag_ctx(255)),
            ApplyResult::ClaimedCost("tefFAILURE")
        );

        assert_eq!(
            apply_tx(&mut LedgerState::new(), &tx, &flag_ctx(512)),
            ApplyResult::ClaimedCost("tefFAILURE")
        );

        let missing_seq = parse_blob(&unl_modify_blob(1, None, Some(&validator))).unwrap();
        assert_eq!(
            apply_tx(&mut LedgerState::new(), &missing_seq, &flag_ctx(256)),
            ApplyResult::ClaimedCost("tefFAILURE")
        );
    }

    #[test]
    fn test_unl_modify_disable_preserves_negative_unl_state() {
        let existing_disabled = vec![0x03; 33];
        let pending_reenable = vec![0xED; 33];
        let to_disable = vec![0x02; 33];
        let key = crate::ledger::keylet::negative_unl().key;
        let mut state = LedgerState::new();
        state.insert_raw(
            key,
            crate::ledger::serialize_negative_unl(
                &[existing_disabled.clone()],
                None,
                Some(&pending_reenable),
            ),
        );
        let tx = parse_blob(&unl_modify_blob(1, Some(256), Some(&to_disable))).unwrap();

        assert_eq!(
            apply_tx(&mut state, &tx, &flag_ctx(256)),
            ApplyResult::Success
        );

        let parsed = crate::ledger::parse_negative_unl(state.get_raw(&key).unwrap());
        assert_eq!(parsed.disabled_validators, vec![existing_disabled]);
        assert_eq!(parsed.to_disable, Some(to_disable));
        assert_eq!(parsed.to_reenable, Some(pending_reenable));
    }

    #[test]
    fn test_unl_modify_reenable_requires_disabled_validator() {
        let disabled = vec![0x02; 33];
        let key = crate::ledger::keylet::negative_unl().key;
        let tx = parse_blob(&unl_modify_blob(0, Some(256), Some(&disabled))).unwrap();

        assert_eq!(
            apply_tx(&mut LedgerState::new(), &tx, &flag_ctx(256)),
            ApplyResult::ClaimedCost("tefFAILURE")
        );

        let mut state = LedgerState::new();
        state.insert_raw(
            key,
            crate::ledger::serialize_negative_unl(&[disabled.clone()], None, None),
        );
        assert_eq!(
            apply_tx(&mut state, &tx, &flag_ctx(256)),
            ApplyResult::Success
        );

        let parsed = crate::ledger::parse_negative_unl(state.get_raw(&key).unwrap());
        assert_eq!(parsed.disabled_validators, vec![disabled.clone()]);
        assert_eq!(parsed.to_disable, None);
        assert_eq!(parsed.to_reenable, Some(disabled));
    }

    #[test]
    fn test_unl_modify_rejects_pending_and_disabled_conflicts() {
        let validator = vec![0x02; 33];
        let other = vec![0x03; 33];
        let key = crate::ledger::keylet::negative_unl().key;

        let mut pending_disable_state = LedgerState::new();
        pending_disable_state.insert_raw(
            key,
            crate::ledger::serialize_negative_unl(&[], Some(&other), None),
        );
        let disable_tx = parse_blob(&unl_modify_blob(1, Some(256), Some(&validator))).unwrap();
        assert_eq!(
            apply_tx(&mut pending_disable_state, &disable_tx, &flag_ctx(256)),
            ApplyResult::ClaimedCost("tefFAILURE")
        );

        let mut already_disabled_state = LedgerState::new();
        already_disabled_state.insert_raw(
            key,
            crate::ledger::serialize_negative_unl(&[validator.clone()], None, None),
        );
        assert_eq!(
            apply_tx(&mut already_disabled_state, &disable_tx, &flag_ctx(256)),
            ApplyResult::ClaimedCost("tefFAILURE")
        );

        let mut pending_reenable_state = LedgerState::new();
        pending_reenable_state.insert_raw(
            key,
            crate::ledger::serialize_negative_unl(&[validator.clone()], None, Some(&other)),
        );
        let reenable_tx = parse_blob(&unl_modify_blob(0, Some(256), Some(&validator))).unwrap();
        assert_eq!(
            apply_tx(&mut pending_reenable_state, &reenable_tx, &flag_ctx(256)),
            ApplyResult::ClaimedCost("tefFAILURE")
        );
    }

    fn install_delegate_permissions(
        state: &mut LedgerState,
        account: [u8; 20],
        delegate_account: [u8; 20],
        permission_values: &[u32],
    ) {
        let key = delegate::delegate_key(&account, &delegate_account);
        let raw = delegate::build_delegate_sle(
            &account,
            &delegate_account,
            &permission_entries_raw(permission_values),
        );
        state.insert_raw(key, raw);
    }

    fn sign_auth_fields(tx: &mut ParsedTx, kp: &KeyPair) {
        let payload = b"delegated-auth-unit-test".to_vec();
        let signing_hash = crate::crypto::sha512_first_half(&payload);
        tx.signing_pubkey = kp.public_key_bytes();
        tx.signing_hash = signing_hash;
        tx.signing_payload = payload;
        tx.signature = match kp {
            KeyPair::Secp256k1(sk) => sk.sign_digest(&signing_hash),
            KeyPair::Ed25519(_) => kp.sign(&tx.signing_payload),
        };
    }

    fn state_with_genesis(balance: u64) -> LedgerState {
        let mut state = LedgerState::new();
        state.insert_account(AccountRoot {
            account_id: genesis_id(),
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
        });
        state
    }

    fn sign_payment(seq: u32, amount: u64, fee: u64) -> ParsedTx {
        let kp = genesis_kp();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(amount))
            .fee(fee)
            .sequence(seq)
            .sign(&kp)
            .unwrap();
        parse_blob(&signed.blob).unwrap()
    }

    #[test]
    fn network_id_preflight_matches_rippled_thresholds() {
        let mut tx = ParsedTx {
            tx_type: 3,
            ..ParsedTx::default()
        };
        let mut context = TxContext {
            network_id: 0,
            ..TxContext::default()
        };

        assert_eq!(check_network_id(&tx, &context), Ok(()));

        tx.network_id = Some(0);
        assert_eq!(
            check_network_id(&tx, &context),
            Err(ter::TEL_NETWORK_ID_MAKES_TX_NON_CANONICAL)
        );

        tx.network_id = None;
        context.network_id = 1025;
        assert_eq!(
            check_network_id(&tx, &context),
            Err(ter::TEL_REQUIRES_NETWORK_ID)
        );

        tx.network_id = Some(1024);
        assert_eq!(check_network_id(&tx, &context), Err(ter::TEL_WRONG_NETWORK));

        tx.network_id = Some(1025);
        assert_eq!(check_network_id(&tx, &context), Ok(()));
    }

    #[test]
    fn account_txn_id_preclaim_requires_matching_account_root_field() {
        let prior = [0xAA; 32];
        let mut state = state_with_genesis(10_000_000);
        let mut sender = state.get_account(&genesis_id()).unwrap().clone();
        sender.set_account_txn_id(prior);
        state.insert_account(sender);

        let tx = ParsedTx {
            tx_type: 5,
            sequence: 1,
            fee: 12,
            account: genesis_id(),
            account_txn_id: Some(prior),
            ..ParsedTx::default()
        };

        assert_eq!(preclaim_tx(&mut state, &tx, &ctx(0), false, false), Ok(()));

        let wrong = ParsedTx {
            account_txn_id: Some([0xBB; 32]),
            ..tx
        };
        assert_eq!(
            preclaim_tx(&mut state, &wrong, &ctx(0), false, false),
            Err(ter::TEF_WRONG_PRIOR)
        );
    }

    #[test]
    fn account_txn_id_and_ticket_is_malformed() {
        let tx = ParsedTx {
            tx_type: 0,
            sequence: 0,
            fee: 12,
            account: genesis_id(),
            ticket_sequence: Some(2),
            account_txn_id: Some([0xAA; 32]),
            ..ParsedTx::default()
        };

        assert_eq!(
            preflight_tx(&state_with_genesis(10_000_000), &tx, &ctx(0), false),
            Err(ter::TEM_INVALID)
        );
    }

    #[test]
    fn delegate_matching_account_is_bad_signer() {
        let mut state = state_with_genesis(10_000_000);
        state.enable_amendment(*FEATURE_DELEGATION);
        let tx = ParsedTx {
            tx_type: 0,
            sequence: 1,
            fee: 12,
            account: genesis_id(),
            delegate: Some(genesis_id()),
            ..ParsedTx::default()
        };

        assert_eq!(
            preflight_tx(&state, &tx, &ctx(0), false),
            Err(ter::TEM_BAD_SIGNER)
        );
    }

    #[test]
    fn delegate_permission_lookup_matches_tx_type_plus_one() {
        let mut state = state_with_genesis(10_000_000);
        let delegated = delegate_id();

        install_delegate_permissions(&mut state, genesis_id(), delegated, &[1]);
        assert_eq!(
            delegate::check_delegated_tx_permission(&state, &genesis_id(), &delegated, 0),
            Ok(())
        );
        assert_eq!(
            delegate::check_delegated_tx_permission(&state, &genesis_id(), &delegated, 8),
            Err(ter::TER_NO_DELEGATE_PERMISSION)
        );
    }

    #[test]
    fn delegated_candidate_auth_requires_delegate_sle_permission() {
        let mut state = state_with_genesis(10_000_000);
        state.enable_amendment(*FEATURE_DELEGATION);
        add_account(&mut state, delegate_id(), 1_000_000, 1);
        let mut source = state.get_account(&genesis_id()).unwrap().clone();
        source.sequence = 2;
        state.insert_account(source);

        let mut tx = ParsedTx {
            tx_type: 8,
            sequence: 2,
            fee: 12,
            account: genesis_id(),
            offer_sequence: Some(1),
            delegate: Some(delegate_id()),
            ..ParsedTx::default()
        };
        sign_auth_fields(&mut tx, &delegate_kp());

        let result = run_candidate_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TER_NO_DELEGATE_PERMISSION);
        assert!(!result.applied);
    }

    #[test]
    fn delegated_candidate_auth_accepts_modeled_offer_cancel_permission() {
        let mut state = state_with_genesis(10_000_000);
        state.enable_amendment(*FEATURE_DELEGATION);
        add_account(&mut state, delegate_id(), 1_000_000, 1);
        install_delegate_permissions(&mut state, genesis_id(), delegate_id(), &[9]);
        let mut source = state.get_account(&genesis_id()).unwrap().clone();
        source.sequence = 2;
        state.insert_account(source);

        let mut tx = ParsedTx {
            tx_type: 8,
            sequence: 2,
            fee: 12,
            account: genesis_id(),
            offer_sequence: Some(1),
            delegate: Some(delegate_id()),
            ..ParsedTx::default()
        };
        sign_auth_fields(&mut tx, &delegate_kp());

        let result = run_candidate_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TES_SUCCESS);
        assert!(result.applied);
        assert_eq!(state.get_account(&genesis_id()).unwrap().sequence, 3);
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            10_000_000
        );
        assert_eq!(state.get_account(&delegate_id()).unwrap().balance, 999_988);
    }

    #[test]
    fn delegated_candidate_auth_rejects_source_signature_for_delegate() {
        let mut state = state_with_genesis(10_000_000);
        state.enable_amendment(*FEATURE_DELEGATION);
        add_account(&mut state, delegate_id(), 1_000_000, 1);
        install_delegate_permissions(&mut state, genesis_id(), delegate_id(), &[9]);
        let mut source = state.get_account(&genesis_id()).unwrap().clone();
        source.sequence = 2;
        state.insert_account(source);

        let mut tx = ParsedTx {
            tx_type: 8,
            sequence: 2,
            fee: 12,
            account: genesis_id(),
            offer_sequence: Some(1),
            delegate: Some(delegate_id()),
            ..ParsedTx::default()
        };
        sign_auth_fields(&mut tx, &genesis_kp());

        let result = run_candidate_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEF_BAD_AUTH);
        assert!(!result.applied);
    }

    #[test]
    fn delegated_payment_permission_is_not_admitted_until_effects_are_modeled() {
        let mut state = state_with_genesis(10_000_000);
        state.enable_amendment(*FEATURE_DELEGATION);
        add_account(&mut state, delegate_id(), 1_000_000, 1);
        install_delegate_permissions(&mut state, genesis_id(), delegate_id(), &[1]);

        let mut tx = ParsedTx {
            tx_type: 0,
            sequence: 1,
            fee: 12,
            account: genesis_id(),
            destination: Some(dest_id()),
            amount: Some(Amount::Xrp(1_000)),
            amount_drops: Some(1_000),
            delegate: Some(delegate_id()),
            ..ParsedTx::default()
        };
        sign_auth_fields(&mut tx, &delegate_kp());

        let result = run_candidate_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TER_NO_DELEGATE_PERMISSION);
        assert!(!result.applied);
    }

    #[test]
    fn apply_updates_existing_account_txn_id_to_current_tx_id() {
        let mut state = state_with_genesis(10_000_000);
        let mut sender = state.get_account(&genesis_id()).unwrap().clone();
        sender.set_account_txn_id([0u8; 32]);
        state.insert_account(sender);

        let tx_id = [0x77; 32];
        let tx = ParsedTx {
            tx_id,
            tx_type: 5,
            sequence: 1,
            fee: 12,
            account: genesis_id(),
            ..ParsedTx::default()
        };

        assert_eq!(apply_tx(&mut state, &tx, &ctx(0)), ApplyResult::Success);
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.account_txn_id(), Some(tx_id));
    }

    fn secp_key(byte: u8) -> KeyPair {
        KeyPair::Secp256k1(Secp256k1KeyPair::from_secret_bytes(&[byte; 32]).unwrap())
    }

    fn key_account(kp: &KeyPair) -> [u8; 20] {
        crate::crypto::account_id(&kp.public_key_bytes())
    }

    fn insert_account_with_auth(
        state: &mut LedgerState,
        account_id: [u8; 20],
        balance: u64,
        sequence: u32,
        flags: u32,
        regular_key: Option<[u8; 20]>,
    ) {
        state.insert_account(AccountRoot {
            account_id,
            balance,
            sequence,
            owner_count: 0,
            flags,
            regular_key,
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
        });
    }

    fn signer_entries_raw(entries: &[([u8; 20], u16)]) -> Vec<u8> {
        let mut entries = entries.to_vec();
        entries.sort_by_key(|(account, _)| *account);
        signer_entries_raw_in_order(&entries)
    }

    fn signer_entries_raw_in_order(entries: &[([u8; 20], u16)]) -> Vec<u8> {
        let mut raw = Vec::new();
        for (account, weight) in entries {
            raw.push(0xE4); // sfSignerEntry
            raw.push(0x13); // sfSignerWeight
            raw.extend_from_slice(&weight.to_be_bytes());
            raw.push(0x81); // sfAccount
            raw.push(20);
            raw.extend_from_slice(account);
            raw.push(0xE1);
        }
        raw.push(0xF1);
        raw
    }

    fn install_signer_list(
        state: &mut LedgerState,
        account: [u8; 20],
        quorum: u32,
        entries: &[([u8; 20], u16)],
    ) {
        let mut tx = ParsedTx::default();
        tx.tx_type = 12;
        tx.account = account;
        tx.signer_quorum = Some(quorum);
        tx.signer_entries_raw = Some(signer_entries_raw(entries));

        let mut sender = state.get_account(&account).unwrap().clone();
        assert_eq!(
            signer_list_set::apply_signer_list_set(state, &tx, &mut sender),
            ApplyResult::Success
        );
        state.insert_account(sender);
    }

    fn signer_array_field(
        signing_fields: &[crate::transaction::serialize::Field],
        signers: &[(&KeyPair, [u8; 20])],
    ) -> Vec<u8> {
        let mut signers = signers.to_vec();
        signers.sort_by_key(|(_, account)| *account);

        let mut array = vec![0xF3]; // sfSigners
        for (kp, signer_account) in signers {
            let pubkey = kp.public_key_bytes();
            let mut payload = crate::transaction::serialize::PREFIX_TX_MULTISIGN.to_vec();
            let mut fields_for_signing = signing_fields.to_vec();
            payload.extend_from_slice(&crate::transaction::serialize::serialize_fields(
                &mut fields_for_signing,
                true,
            ));
            payload.extend_from_slice(&signer_account);
            let hash = crate::crypto::sha512_first_half(&payload);
            let signature = match kp {
                KeyPair::Secp256k1(sk) => sk.sign_digest(&hash),
                KeyPair::Ed25519(_) => kp.sign(&payload),
            };

            array.push(0xE3); // sfSigner
            array.push(0x73); // sfSigningPubKey
            crate::transaction::serialize::encode_length(pubkey.len(), &mut array);
            array.extend_from_slice(&pubkey);
            array.push(0x74); // sfTxnSignature
            crate::transaction::serialize::encode_length(signature.len(), &mut array);
            array.extend_from_slice(&signature);
            array.push(0x81); // sfAccount
            array.push(20);
            array.extend_from_slice(&signer_account);
            array.push(0xE1);
        }
        array.push(0xF1);
        array
    }

    fn multisigned_payment(
        account: [u8; 20],
        sequence: u32,
        signers: &[(&KeyPair, [u8; 20])],
    ) -> ParsedTx {
        let builder = TxBuilder::payment()
            .account_address(&crate::crypto::base58::encode_account(&account))
            .unwrap()
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12 * (1 + signers.len() as u64))
            .sequence(sequence);
        let mut fields = builder.build_fields(Vec::new(), None).unwrap();
        let mut blob = crate::transaction::serialize::serialize_fields(&mut fields, false);
        blob.extend_from_slice(&signer_array_field(&fields, signers));
        parse_blob(&blob).unwrap()
    }

    #[test]
    fn candidate_multisign_accepts_present_quorum() {
        let source_kp = secp_key(3);
        let signer1 = secp_key(4);
        let signer2 = secp_key(5);
        let source = key_account(&source_kp);
        let signer1_id = key_account(&signer1);
        let signer2_id = key_account(&signer2);

        let mut state = LedgerState::new();
        insert_account_with_auth(&mut state, source, 100_000_000, 1, 0, None);
        insert_account_with_auth(&mut state, signer1_id, 10_000_000, 1, 0, None);
        insert_account_with_auth(&mut state, signer2_id, 10_000_000, 1, 0, None);
        install_signer_list(&mut state, source, 2, &[(signer1_id, 1), (signer2_id, 1)]);

        let tx = multisigned_payment(source, 1, &[(&signer1, signer1_id), (&signer2, signer2_id)]);
        let result = run_candidate_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TES_SUCCESS);
        assert!(result.applied);
    }

    #[test]
    fn candidate_multisign_rejects_missing_quorum() {
        let source_kp = secp_key(6);
        let signer1 = secp_key(7);
        let signer2 = secp_key(8);
        let source = key_account(&source_kp);
        let signer1_id = key_account(&signer1);
        let signer2_id = key_account(&signer2);

        let mut state = LedgerState::new();
        insert_account_with_auth(&mut state, source, 100_000_000, 1, 0, None);
        insert_account_with_auth(&mut state, signer1_id, 10_000_000, 1, 0, None);
        insert_account_with_auth(&mut state, signer2_id, 10_000_000, 1, 0, None);
        install_signer_list(&mut state, source, 2, &[(signer1_id, 1), (signer2_id, 1)]);

        let tx = multisigned_payment(source, 1, &[(&signer1, signer1_id)]);
        let result = run_candidate_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEF_BAD_QUORUM);
        assert!(!result.applied);
    }

    #[test]
    fn signer_list_set_sorts_entries_and_allows_thirty_two() {
        let source_kp = secp_key(12);
        let source = key_account(&source_kp);
        let mut state = LedgerState::new();
        insert_account_with_auth(&mut state, source, 1_000_000_000, 1, 0, None);

        let mut entries = Vec::new();
        for byte in 13u8..45 {
            let kp = secp_key(byte);
            entries.push((key_account(&kp), 1));
        }
        let mut unsorted = entries.clone();
        unsorted.reverse();

        let mut tx = ParsedTx::default();
        tx.tx_type = 12;
        tx.account = source;
        tx.fee = 12;
        tx.signer_quorum = Some(32);
        tx.signer_entries_raw = Some(signer_entries_raw_in_order(&unsorted));

        let mut sender = state.get_account(&source).unwrap().clone();
        assert_eq!(
            signer_list_set::apply_signer_list_set(&mut state, &tx, &mut sender),
            ApplyResult::Success
        );
        state.insert_account(sender);

        let signer_list = load_signer_list_for_auth(&state, &source).unwrap();
        let mut sorted_accounts: Vec<_> = entries.iter().map(|(account, _)| *account).collect();
        sorted_accounts.sort();
        assert_eq!(signer_list.entries.len(), 32);
        assert_eq!(signer_list.quorum, 32);
        assert_eq!(
            signer_list
                .entries
                .iter()
                .map(|entry| entry.account)
                .collect::<Vec<_>>(),
            sorted_accounts
        );
    }

    #[test]
    fn signer_list_set_matches_rippled_bad_weight_and_quorum_codes() {
        let source_kp = secp_key(45);
        let signer1 = secp_key(46);
        let signer2 = secp_key(47);
        let source = key_account(&source_kp);
        let signer1_id = key_account(&signer1);
        let signer2_id = key_account(&signer2);
        let mut state = LedgerState::new();
        insert_account_with_auth(&mut state, source, 100_000_000, 1, 0, None);

        let mut tx = ParsedTx::default();
        tx.tx_type = 12;
        tx.account = source;
        tx.fee = 12;
        tx.signer_quorum = Some(1);
        tx.signer_entries_raw = Some(signer_entries_raw(&[(signer1_id, 0)]));
        let mut sender = state.get_account(&source).unwrap().clone();
        assert_eq!(
            signer_list_set::apply_signer_list_set(&mut state, &tx, &mut sender),
            ApplyResult::ClaimedCost("temBAD_WEIGHT")
        );

        tx.signer_quorum = Some(3);
        tx.signer_entries_raw = Some(signer_entries_raw(&[(signer1_id, 1), (signer2_id, 1)]));
        assert_eq!(
            signer_list_set::apply_signer_list_set(&mut state, &tx, &mut sender),
            ApplyResult::ClaimedCost("temBAD_QUORUM")
        );
    }

    #[test]
    fn signer_list_destroy_requires_alternative_key_when_master_disabled() {
        let source_kp = secp_key(48);
        let signer1 = secp_key(49);
        let source = key_account(&source_kp);
        let signer1_id = key_account(&signer1);
        let mut state = LedgerState::new();
        insert_account_with_auth(
            &mut state,
            source,
            100_000_000,
            1,
            crate::ledger::account::LSF_DISABLE_MASTER,
            None,
        );
        install_signer_list(&mut state, source, 1, &[(signer1_id, 1)]);

        let mut tx = ParsedTx::default();
        tx.tx_type = 12;
        tx.account = source;
        tx.fee = 12;
        tx.signer_quorum = Some(0);
        let mut sender = state.get_account(&source).unwrap().clone();
        assert_eq!(
            signer_list_set::apply_signer_list_set(&mut state, &tx, &mut sender),
            ApplyResult::ClaimedCost("tecNO_ALTERNATIVE_KEY")
        );
    }

    #[test]
    fn candidate_multisign_accepts_phantom_master_signer() {
        let source_kp = secp_key(50);
        let phantom = secp_key(51);
        let source = key_account(&source_kp);
        let phantom_id = key_account(&phantom);

        let mut state = LedgerState::new();
        insert_account_with_auth(&mut state, source, 100_000_000, 1, 0, None);
        install_signer_list(&mut state, source, 1, &[(phantom_id, 1)]);

        let tx = multisigned_payment(source, 1, &[(&phantom, phantom_id)]);
        let result = run_candidate_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TES_SUCCESS);
        assert!(result.applied);
    }

    #[test]
    fn candidate_multisign_uses_rippled_auth_failure_codes() {
        let source_kp = secp_key(52);
        let signer1 = secp_key(53);
        let signer2 = secp_key(54);
        let source = key_account(&source_kp);
        let signer1_id = key_account(&signer1);
        let signer2_id = key_account(&signer2);

        let mut state = LedgerState::new();
        insert_account_with_auth(&mut state, source, 100_000_000, 1, 0, None);
        insert_account_with_auth(&mut state, signer1_id, 10_000_000, 1, 0, None);
        insert_account_with_auth(&mut state, signer2_id, 10_000_000, 1, 0, None);

        let tx = multisigned_payment(source, 1, &[(&signer1, signer1_id)]);
        let result = run_candidate_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEF_NOT_MULTI_SIGNING);

        install_signer_list(&mut state, source, 1, &[(signer1_id, 1)]);
        let tx = multisigned_payment(source, 1, &[(&signer2, signer2_id)]);
        let result = run_candidate_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEF_BAD_SIGNATURE);
    }

    #[test]
    fn candidate_regular_key_still_auths_when_master_disabled() {
        let source_kp = secp_key(9);
        let regular_kp = secp_key(10);
        let source = key_account(&source_kp);
        let regular = key_account(&regular_kp);

        let mut state = LedgerState::new();
        insert_account_with_auth(
            &mut state,
            source,
            100_000_000,
            1,
            crate::ledger::account::LSF_DISABLE_MASTER,
            Some(regular),
        );

        let signed = TxBuilder::payment()
            .account_address(&crate::crypto::base58::encode_account(&source))
            .unwrap()
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&regular_kp)
            .unwrap();
        let tx = parse_blob(&signed.blob).unwrap();
        let result = run_candidate_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TES_SUCCESS);
        assert!(result.applied);
    }

    #[test]
    fn candidate_disabled_master_still_rejects_master_signature() {
        let source_kp = secp_key(11);
        let source = key_account(&source_kp);

        let mut state = LedgerState::new();
        insert_account_with_auth(
            &mut state,
            source,
            100_000_000,
            1,
            crate::ledger::account::LSF_DISABLE_MASTER,
            None,
        );

        let signed = TxBuilder::payment()
            .account_address(&crate::crypto::base58::encode_account(&source))
            .unwrap()
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&source_kp)
            .unwrap();
        let tx = parse_blob(&signed.blob).unwrap();
        let result = run_candidate_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEF_MASTER_DISABLED);
        assert!(!result.applied);
    }

    #[test]
    fn test_apply_payment_debits_sender_credits_dest() {
        let mut state = state_with_genesis(10_000_000); // 10 XRP
        let tx = sign_payment(1, 1_000_000, 12); // send 1 XRP, fee 12 drops
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 10_000_000 - 1_000_000 - 12);
        assert_eq!(sender.sequence, 2);

        let dest = state.get_account(&dest_id()).unwrap();
        assert_eq!(dest.balance, 1_000_000);
    }

    #[test]
    fn direct_xrp_payment_to_deposit_auth_requires_preauth_above_unwedge_limit() {
        let mut state = state_with_two_accounts();
        let mut dest = state.get_account(&dest_id()).unwrap().clone();
        dest.flags |= crate::ledger::account::LSF_DEPOSIT_AUTH;
        state.insert_account(dest);

        let tx = sign_payment(1, 1_000, 12);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEC_NO_PERMISSION);
        assert_eq!(state.get_account(&dest_id()).unwrap().balance, 50_000_000);
    }

    #[test]
    fn direct_xrp_payment_to_deposit_auth_allows_preauthorized_sender() {
        let mut state = state_with_two_accounts();
        let mut dest = state.get_account(&dest_id()).unwrap().clone();
        dest.flags |= crate::ledger::account::LSF_DEPOSIT_AUTH;
        state.insert_account(dest);
        state.insert_deposit_preauth(crate::ledger::DepositPreauth {
            account: dest_id(),
            authorized: genesis_id(),
            owner_node: 0,
            previous_txn_id: [0u8; 32],
            previous_txn_lgrseq: 0,
            raw_sle: None,
        });

        let tx = sign_payment(1, 1_000, 12);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TES_SUCCESS);
        assert_eq!(state.get_account(&dest_id()).unwrap().balance, 50_001_000);
    }

    #[test]
    fn direct_xrp_payment_to_pseudo_account_is_rejected() {
        let mut state = state_with_two_accounts();
        let mut dest = state.get_account(&dest_id()).unwrap().clone();
        dest.sequence = 0;
        dest.flags = crate::ledger::account::LSF_DISABLE_MASTER
            | crate::ledger::account::LSF_DEFAULT_RIPPLE
            | crate::ledger::account::LSF_DEPOSIT_AUTH;
        state.insert_account(dest);

        let tx = sign_payment(1, 1, 12);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEC_NO_PERMISSION);
        assert_eq!(state.get_account(&dest_id()).unwrap().balance, 50_000_000);
    }

    #[test]
    fn direct_xrp_payment_to_pseudo_checks_sender_funds_first() {
        let mut state = state_with_genesis(20_000_000);
        state.insert_account(AccountRoot {
            account_id: dest_id(),
            balance: 1,
            sequence: 0,
            owner_count: 0,
            flags: crate::ledger::account::LSF_DISABLE_MASTER
                | crate::ledger::account::LSF_DEFAULT_RIPPLE
                | crate::ledger::account::LSF_DEPOSIT_AUTH,
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
        });
        let tx = sign_payment(1, 19_500_000, 12);

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEC_UNFUNDED_PAYMENT);
        assert!(result.applied, "direct tec should collapse to fee-only");

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 20_000_000 - 12);
        assert_eq!(sender.sequence, 2);
        assert_eq!(state.get_account(&dest_id()).unwrap().balance, 1);
    }

    #[test]
    fn validated_replay_amm_payment_bridge_spends_exact_quote_not_send_max() {
        use crate::ledger::meta::ParsedField;
        use crate::ledger::RippleState;
        use crate::transaction::amount::{Currency, IouValue, Issue};

        let mut state = state_with_genesis(1_000_000_000);
        let issuer = dest_id();
        let pseudo = [0xBB; 20];
        let usd = Currency::from_code("USD").unwrap();
        let usd_issue = Issue::Iou {
            currency: usd.clone(),
            issuer,
        };
        let deliver = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer,
        };

        state.insert_account(AccountRoot {
            account_id: issuer,
            balance: 0,
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
        });
        state.insert_account(AccountRoot {
            account_id: pseudo,
            balance: 10_000_000_000,
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
        });

        let mut pool_line = RippleState::new(&pseudo, &issuer, usd.clone());
        pool_line.transfer(&issuer, &IouValue::from_f64(1_000.0));
        state.insert_trustline(pool_line);

        let amm_fields = vec![
            ParsedField {
                type_code: 8,
                field_code: 1,
                data: pseudo.to_vec(),
            },
            ParsedField {
                type_code: 1,
                field_code: 2,
                data: 0u16.to_be_bytes().to_vec(),
            },
            ParsedField {
                type_code: 24,
                field_code: 3,
                data: Issue::Xrp.to_bytes(),
            },
            ParsedField {
                type_code: 24,
                field_code: 4,
                data: usd_issue.to_bytes(),
            },
        ];
        state.insert_raw(
            amm::amm_key(&Issue::Xrp, &usd_issue),
            crate::ledger::meta::build_sle(0x0079, &amm_fields, None, None),
        );

        let tx = ParsedTx {
            tx_type: 0,
            flags: 0x0002_0000,
            sequence: 1,
            fee: 12,
            account: genesis_id(),
            destination: Some(genesis_id()),
            amount: Some(deliver.clone()),
            send_max: Some(Amount::Xrp(200_000_000)),
            ..ParsedTx::default()
        };
        let replay_ctx = TxContext {
            ledger_seq: 2,
            validated_result: Some(ter::TES_SUCCESS),
            validated_delivered_amount: Some(deliver.clone()),
            validated_payment_amm_self_swap_bridge: true,
            ..TxContext::default()
        };

        let result = run_tx(&mut state, &tx, &replay_ctx, ApplyFlags::VALIDATED_REPLAY);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let expected_spend = 101_010_102;
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 1_000_000_000 - 12 - expected_spend);
        assert_eq!(sender.sequence, 2);

        let pool_account = state.get_account(&pseudo).unwrap();
        assert_eq!(pool_account.balance, 10_000_000_000 + expected_spend);

        let sender_line = state
            .get_trustline_for(&genesis_id(), &issuer, &usd)
            .unwrap();
        assert_eq!(
            sender_line.balance_for(&genesis_id()),
            IouValue::from_f64(10.0)
        );

        let pool_line = state.get_trustline_for(&pseudo, &issuer, &usd).unwrap();
        assert_eq!(pool_line.balance_for(&pseudo), IouValue::from_f64(990.0));
    }

    #[test]
    fn direct_xrp_self_payment_without_paths_is_redundant() {
        let mut state = state_with_genesis(1_000_000);
        let mut tx = ParsedTx {
            tx_type: 0,
            sequence: 1,
            fee: 12,
            account: genesis_id(),
            destination: Some(genesis_id()),
            amount: Some(Amount::Xrp(100_000)),
            ..ParsedTx::default()
        };
        sign_auth_fields(&mut tx, &genesis_kp());

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEM_REDUNDANT);
        assert!(!result.applied);
        assert!(result.touched.is_empty());

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 1_000_000);
        assert_eq!(sender.sequence, 1);
    }

    #[test]
    fn validated_replay_same_currency_sendmax_does_not_mutate_trustline_locally() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let trustset = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        assert_eq!(
            apply_tx(&mut state, &trustset, &ctx(0)),
            ApplyResult::Success
        );

        let usd = Currency::from_code("USD").unwrap();
        let key = crate::ledger::trustline::shamap_key(&genesis_id(), &dest_id(), &usd);
        {
            let mut tl = state.get_trustline(&key).unwrap().clone();
            if genesis_id() < dest_id() {
                tl.balance = IouValue::from_f64(100.0);
            } else {
                tl.balance = IouValue::from_f64(-100.0);
            }
            state.insert_trustline(tl);
        }
        let before = state
            .get_trustline(&key)
            .unwrap()
            .balance_for(&genesis_id());

        let tx = ParsedTx {
            tx_type: 0,
            sequence: 2,
            fee: 12,
            account: genesis_id(),
            destination: Some(dest_id()),
            amount: Some(Amount::Iou {
                value: IouValue::from_f64(50.0),
                currency: usd.clone(),
                issuer: dest_id(),
            }),
            send_max: Some(Amount::Iou {
                value: IouValue::from_f64(60.0),
                currency: usd.clone(),
                issuer: dest_id(),
            }),
            ..ParsedTx::default()
        };
        let replay_ctx = TxContext {
            ledger_seq: 3,
            validated_result: Some(ter::TES_SUCCESS),
            ..TxContext::default()
        };

        let result = run_tx(&mut state, &tx, &replay_ctx, ApplyFlags::VALIDATED_REPLAY);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let after = state
            .get_trustline(&key)
            .unwrap()
            .balance_for(&genesis_id());
        assert_eq!(after.mantissa, before.mantissa);
        assert_eq!(after.exponent, before.exponent);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.sequence, 3);
    }

    #[test]
    fn validated_replay_direct_xrp_payment_applies_locally() {
        let mut state = state_with_genesis(50_000_000);
        let tx = sign_payment(1, 10_000_000, 12);
        let replay_ctx = TxContext {
            ledger_seq: 2,
            validated_result: Some(ter::TES_SUCCESS),
            ..TxContext::default()
        };

        let result = run_tx(&mut state, &tx, &replay_ctx, ApplyFlags::VALIDATED_REPLAY);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 50_000_000 - 12 - 10_000_000);
        assert_eq!(sender.sequence, 2);

        let dest = state.get_account(&dest_id()).unwrap();
        assert_eq!(dest.balance, 10_000_000);
    }

    #[test]
    fn same_currency_sendmax_without_validated_replay_returns_path_dry() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let trustset = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        assert_eq!(
            apply_tx(&mut state, &trustset, &ctx(0)),
            ApplyResult::Success
        );

        let usd = Currency::from_code("USD").unwrap();
        let mut tx = ParsedTx {
            tx_type: 0,
            sequence: 2,
            fee: 12,
            account: genesis_id(),
            destination: Some(dest_id()),
            amount: Some(Amount::Iou {
                value: IouValue::from_f64(50.0),
                currency: usd.clone(),
                issuer: dest_id(),
            }),
            send_max: Some(Amount::Iou {
                value: IouValue::from_f64(60.0),
                currency: usd,
                issuer: dest_id(),
            }),
            ..ParsedTx::default()
        };
        sign_auth_fields(&mut tx, &genesis_kp());

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEC_PATH_DRY);
        assert!(
            result.applied,
            "unsupported same-currency SendMax should fee-claim"
        );
    }

    #[test]
    fn direct_xrp_payment_below_reserve_returns_tec_unfunded_payment() {
        let mut state = state_with_genesis(20_000_000);
        state.insert_account(AccountRoot {
            account_id: dest_id(),
            balance: 1,
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
        });
        let tx = sign_payment(1, 19_500_000, 12);

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEC_UNFUNDED_PAYMENT);
        assert!(result.applied, "direct tec should collapse to fee-only");

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 20_000_000 - 12);
        assert_eq!(sender.sequence, 2);
        assert_eq!(state.get_account(&dest_id()).unwrap().balance, 1);
    }

    #[test]
    fn direct_xrp_payment_creates_destination_with_ledger_sequence() {
        let mut state = state_with_genesis(50_000_000);
        let tx = sign_payment(1, 10_000_000, 12);
        let run_ctx = TxContext {
            ledger_seq: 88,
            ..ctx(0)
        };

        let result = run_tx(&mut state, &tx, &run_ctx, ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let dest = state.get_account(&dest_id()).unwrap();
        assert_eq!(dest.balance, 10_000_000);
        assert_eq!(dest.sequence, 88);
    }

    #[test]
    fn direct_xrp_payment_clears_destination_password_spent() {
        let mut state = state_with_two_accounts();
        state.insert_account(AccountRoot {
            account_id: dest_id(),
            balance: 10_000_000,
            sequence: 1,
            owner_count: 0,
            flags: crate::ledger::account::LSF_PASSWORD_SPENT,
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
        });

        let tx = sign_payment(1, 1_000_000, 12);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let dest = state.get_account(&dest_id()).unwrap();
        assert_eq!(dest.balance, 11_000_000);
        assert_eq!(dest.flags & crate::ledger::account::LSF_PASSWORD_SPENT, 0);
    }

    #[test]
    fn self_issued_iou_self_payment_without_paths_is_redundant() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let usd = Currency::from_code("USD").unwrap();
        let mut tx = ParsedTx {
            tx_type: 0,
            sequence: 1,
            fee: 12,
            account: genesis_id(),
            destination: Some(genesis_id()),
            amount: Some(Amount::Iou {
                value: IouValue::from_f64(5.0),
                currency: usd,
                issuer: genesis_id(),
            }),
            ..ParsedTx::default()
        };
        sign_auth_fields(&mut tx, &genesis_kp());

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEM_REDUNDANT);
        assert!(!result.applied);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 50_000_000);
        assert_eq!(sender.sequence, 1);
    }

    #[test]
    fn direct_xrp_payment_uses_existing_raw_destination_account() {
        let mut state = state_with_genesis(50_000_000);
        let dest = AccountRoot {
            account_id: dest_id(),
            balance: 25,
            sequence: 7,
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
        };
        let dest_key = crate::ledger::account::shamap_key(&dest.account_id);
        state.insert_raw(dest_key, dest.to_sle_binary());
        assert!(state.get_account(&dest.account_id).is_none());

        let tx = sign_payment(1, 10_000_000, 12);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let hydrated = state.get_account(&dest.account_id).unwrap();
        assert_eq!(hydrated.balance, 10_000_025);
        assert_eq!(hydrated.sequence, 7);
    }

    #[test]
    fn direct_xrp_payment_uses_committed_raw_destination_account() {
        use crate::ledger::node_store::MemNodeStore;
        use crate::ledger::shamap::{MapType, SHAMap};

        let backend = std::sync::Arc::new(MemNodeStore::new());
        let mut state = state_with_genesis(50_000_000);
        state.set_nudb_shamap(SHAMap::with_backend(MapType::AccountState, backend));

        let dest = AccountRoot {
            account_id: dest_id(),
            balance: 25,
            sequence: 7,
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
        };
        let dest_key = crate::ledger::account::shamap_key(&dest.account_id);
        state.insert_raw(dest_key, dest.to_sle_binary());
        state.flush_nudb().unwrap();
        state.enable_sparse();

        let tx = sign_payment(1, 10_000_000, 12);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let hydrated = state.get_account(&dest.account_id).unwrap();
        assert_eq!(hydrated.balance, 10_000_025);
        assert_eq!(hydrated.sequence, 7);
    }

    #[test]
    fn test_apply_creates_destination_account() {
        let mut state = state_with_genesis(50_000_000);
        assert!(state.get_account(&dest_id()).is_none());

        let tx = sign_payment(1, 10_000_000, 12);
        apply_tx(&mut state, &tx, &ctx(0));

        let dest = state.get_account(&dest_id()).unwrap();
        assert_eq!(dest.balance, 10_000_000);
        assert_eq!(dest.sequence, 1); // new account starts at seq 1
    }

    #[test]
    fn test_apply_credits_existing_destination() {
        let mut state = state_with_genesis(50_000_000);
        // Pre-fund destination
        state.insert_account(AccountRoot {
            account_id: dest_id(),
            balance: 5_000_000,
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
        });

        let tx = sign_payment(1, 2_000_000, 12);
        apply_tx(&mut state, &tx, &ctx(0));

        let dest = state.get_account(&dest_id()).unwrap();
        assert_eq!(dest.balance, 7_000_000); // 5M + 2M
    }

    #[test]
    fn test_apply_bumps_sequence() {
        let mut state = state_with_genesis(50_000_000);
        let tx = sign_payment(1, 1_000_000, 12);
        apply_tx(&mut state, &tx, &ctx(0));

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.sequence, 2);
    }

    #[test]
    fn test_apply_two_consecutive_txs() {
        let mut state = state_with_genesis(50_000_000);

        let tx1 = sign_payment(1, 1_000_000, 12);
        apply_tx(&mut state, &tx1, &ctx(0));

        let tx2 = sign_payment(2, 2_000_000, 12);
        apply_tx(&mut state, &tx2, &ctx(0));

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 50_000_000 - 3_000_000 - 24);
        assert_eq!(sender.sequence, 3);

        let dest = state.get_account(&dest_id()).unwrap();
        assert_eq!(dest.balance, 3_000_000);
    }

    #[test]
    fn test_state_hash_changes_after_apply() {
        let mut state = state_with_genesis(50_000_000);
        let hash_before = state.state_hash();

        let tx = sign_payment(1, 1_000_000, 12);
        apply_tx(&mut state, &tx, &ctx(0));

        let hash_after = state.state_hash();
        assert_ne!(
            hash_before, hash_after,
            "state hash must change after applying a tx"
        );
    }

    // ── TrustSet tests ──────────────────────────────────────────────────────

    fn sign_trustset(seq: u32, currency: &str, issuer: &str, limit: f64) -> ParsedTx {
        sign_trustset_with_flags(seq, currency, issuer, limit, 0)
    }

    fn sign_trustset_with_flags(
        seq: u32,
        currency: &str,
        issuer: &str,
        limit: f64,
        flags: u32,
    ) -> ParsedTx {
        use crate::transaction::amount::{Currency, IouValue};
        let kp = genesis_kp();
        let issuer_id = crate::crypto::base58::decode_account(issuer).unwrap();
        let iou_amount = Amount::Iou {
            value: IouValue::from_f64(limit),
            currency: Currency::from_code(currency).unwrap(),
            issuer: issuer_id,
        };
        let signed = TxBuilder::trust_set()
            .account(&kp)
            .limit_amount(iou_amount)
            .fee(12)
            .sequence(seq)
            .flags(flags)
            .sign(&kp)
            .unwrap();
        parse_blob(&signed.blob).unwrap()
    }

    fn state_with_two_accounts() -> LedgerState {
        let mut state = state_with_genesis(50_000_000);
        state.insert_account(AccountRoot {
            account_id: dest_id(),
            balance: 50_000_000,
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
        });
        state
    }

    #[test]
    fn test_trustset_creates_trust_line() {
        let mut state = state_with_two_accounts();
        let tx = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        // Check trust line exists
        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let tl = state.get_trustline_for(&genesis_id(), &dest_id(), &usd);
        assert!(tl.is_some(), "trust line should have been created");
        let tl = tl.unwrap();

        // Only the side that set the limit should carry owner reserve.
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.owner_count, 1);
        let peer = state.get_account(&dest_id()).unwrap();
        assert_eq!(peer.owner_count, 0);

        if genesis_id() < dest_id() {
            assert_eq!(
                tl.flags & crate::ledger::trustline::LSF_LOW_RESERVE,
                crate::ledger::trustline::LSF_LOW_RESERVE
            );
            assert_eq!(tl.flags & crate::ledger::trustline::LSF_HIGH_RESERVE, 0);
        } else {
            assert_eq!(
                tl.flags & crate::ledger::trustline::LSF_HIGH_RESERVE,
                crate::ledger::trustline::LSF_HIGH_RESERVE
            );
            assert_eq!(tl.flags & crate::ledger::trustline::LSF_LOW_RESERVE, 0);
        }

        let key = crate::ledger::trustline::shamap_key(&genesis_id(), &dest_id(), &usd);
        let raw = state
            .get_raw_owned(&key)
            .expect("raw trustline should exist");
        let parsed = crate::ledger::meta::parse_sle(&raw).expect("trustline SLE should parse");
        assert!(parsed
            .fields
            .iter()
            .any(|f| f.type_code == 3 && f.field_code == 7));
        assert!(parsed
            .fields
            .iter()
            .any(|f| f.type_code == 3 && f.field_code == 8));
    }

    #[test]
    fn test_trustset_rejects_self_issuer() {
        let mut state = state_with_genesis(50_000_000);
        let issuer = crate::crypto::base58::encode_account(&genesis_id());
        let tx = sign_trustset(1, "USD", &issuer, 1000.0);

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEM_DST_IS_SRC);
        assert!(!result.applied);
    }

    #[test]
    fn test_trustset_rejects_missing_counterparty() {
        let mut state = state_with_genesis(50_000_000);
        let tx = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEC_NO_DST);
        assert!(result.applied, "tecNO_DST claims fee only");
    }

    #[test]
    fn test_trustset_set_auth_requires_sender_require_auth() {
        const TF_SET_AUTH: u32 = 0x0001_0000;

        let mut state = state_with_two_accounts();
        let tx = sign_trustset_with_flags(
            1,
            "USD",
            "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            0.0,
            TF_SET_AUTH,
        );

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEF_NO_AUTH_REQUIRED);
        assert!(!result.applied);
    }

    #[test]
    fn test_trustset_set_no_ripple_sets_sender_side_flag() {
        const TF_SET_NO_RIPPLE: u32 = 0x0002_0000;

        let mut state = state_with_two_accounts();
        let tx = sign_trustset_with_flags(
            1,
            "USD",
            "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            1000.0,
            TF_SET_NO_RIPPLE,
        );
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let tl = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .expect("trust line should have been created");
        let expected = if tl.low_account == genesis_id() {
            crate::ledger::trustline::LSF_LOW_NO_RIPPLE
        } else {
            crate::ledger::trustline::LSF_HIGH_NO_RIPPLE
        };
        assert_eq!(tl.flags & expected, expected);
    }

    #[test]
    fn test_trustset_deep_freeze_requires_regular_freeze() {
        const TF_SET_DEEP_FREEZE: u32 = 0x0040_0000;

        let mut state = state_with_two_accounts();
        state.enable_amendment(*FEATURE_DEEP_FREEZE);
        let tx = sign_trustset_with_flags(
            1,
            "USD",
            "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            1000.0,
            TF_SET_DEEP_FREEZE,
        );

        let result = apply_tx(&mut state, &tx, &ctx(0));

        assert_eq!(result, ApplyResult::ClaimedCost("tecNO_PERMISSION"));
        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
        assert!(
            state
                .get_trustline_for(&genesis_id(), &dest_id(), &usd)
                .is_none(),
            "failed DeepFreeze setup must not create a trust line"
        );
    }

    #[test]
    fn test_trustset_sets_and_clears_deep_freeze_with_regular_freeze() {
        const TF_SET_FREEZE: u32 = 0x0010_0000;
        const TF_CLEAR_FREEZE: u32 = 0x0020_0000;
        const TF_SET_DEEP_FREEZE: u32 = 0x0040_0000;
        const TF_CLEAR_DEEP_FREEZE: u32 = 0x0080_0000;

        let mut state = state_with_two_accounts();
        state.enable_amendment(*FEATURE_DEEP_FREEZE);
        let set_tx = sign_trustset_with_flags(
            1,
            "USD",
            "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            0.0,
            TF_SET_FREEZE | TF_SET_DEEP_FREEZE,
        );
        assert_eq!(apply_tx(&mut state, &set_tx, &ctx(0)), ApplyResult::Success);

        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let tl = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .expect("freeze-only trust line should persist");
        let (freeze, deep_freeze) = if tl.low_account == genesis_id() {
            (
                crate::ledger::trustline::LSF_LOW_FREEZE,
                crate::ledger::trustline::LSF_LOW_DEEP_FREEZE,
            )
        } else {
            (
                crate::ledger::trustline::LSF_HIGH_FREEZE,
                crate::ledger::trustline::LSF_HIGH_DEEP_FREEZE,
            )
        };
        assert_eq!(tl.flags & freeze, freeze);
        assert_eq!(tl.flags & deep_freeze, deep_freeze);
        assert_eq!(state.get_account(&genesis_id()).unwrap().owner_count, 1);

        let clear_freeze_only_tx = sign_trustset_with_flags(
            2,
            "USD",
            "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            0.0,
            TF_CLEAR_FREEZE,
        );
        assert_eq!(
            apply_tx(&mut state, &clear_freeze_only_tx, &ctx(0)),
            ApplyResult::ClaimedCost("tecNO_PERMISSION")
        );

        let clear_both_tx = sign_trustset_with_flags(
            3,
            "USD",
            "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            0.0,
            TF_CLEAR_FREEZE | TF_CLEAR_DEEP_FREEZE | 0x0002_0000,
        );
        assert_eq!(
            apply_tx(&mut state, &clear_both_tx, &ctx(0)),
            ApplyResult::Success
        );
        assert!(
            state
                .get_trustline_for(&genesis_id(), &dest_id(), &usd)
                .is_none(),
            "clearing both freeze flags should delete the default line"
        );
        assert_eq!(state.get_account(&genesis_id()).unwrap().owner_count, 0);
    }

    #[test]
    fn test_trustset_applies_sender_quality_fields() {
        let mut state = state_with_two_accounts();
        let mut tx = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        tx.quality_in = Some(1_250_000_000);
        tx.quality_out = Some(1_000_000_000);

        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let tl = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .expect("trust line should have been created");
        if tl.low_account == genesis_id() {
            assert_eq!(tl.low_quality_in, 1_250_000_000);
            assert_eq!(tl.low_quality_out, 0);
            assert_eq!(tl.high_quality_in, 0);
            assert_eq!(tl.high_quality_out, 0);
        } else {
            assert_eq!(tl.high_quality_in, 1_250_000_000);
            assert_eq!(tl.high_quality_out, 0);
            assert_eq!(tl.low_quality_in, 0);
            assert_eq!(tl.low_quality_out, 0);
        }
    }

    #[test]
    fn test_trustset_quality_only_line_is_not_redundant() {
        let mut state = state_with_two_accounts();
        let mut tx = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 0.0);
        tx.quality_out = Some(1_500_000_000);

        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let tl = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .expect("quality-only trust line should be created");
        if tl.low_account == genesis_id() {
            assert_eq!(tl.low_quality_out, 1_500_000_000);
        } else {
            assert_eq!(tl.high_quality_out, 1_500_000_000);
        }
        assert_eq!(state.get_account(&genesis_id()).unwrap().owner_count, 1);
    }

    #[test]
    fn test_trustset_quality_one_clears_quality_and_deletes_default_line() {
        let mut state = state_with_two_accounts();
        let mut tx = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 0.0);
        tx.quality_out = Some(1_500_000_000);
        assert_eq!(apply_tx(&mut state, &tx, &ctx(0)), ApplyResult::Success);

        let mut clear_tx = sign_trustset(2, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 0.0);
        clear_tx.quality_out = Some(1_000_000_000);
        clear_tx.flags |= 0x0002_0000;
        assert_eq!(
            apply_tx(&mut state, &clear_tx, &ctx(0)),
            ApplyResult::Success
        );

        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
        assert!(
            state
                .get_trustline_for(&genesis_id(), &dest_id(), &usd)
                .is_none(),
            "defaulted quality-only trust line should be deleted"
        );
        assert_eq!(state.get_account(&genesis_id()).unwrap().owner_count, 0);
    }

    #[test]
    fn test_trustset_hydrates_and_touches_raw_only_peer_account() {
        let mut state = state_with_genesis(50_000_000);
        let peer = AccountRoot {
            account_id: dest_id(),
            balance: 50_000_000,
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
        };
        let peer_key = crate::ledger::account::shamap_key(&peer.account_id);
        state.insert_raw(peer_key, peer.to_sle_binary());

        let tx = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TES_SUCCESS);
        assert!(result.touched.iter().any(|(key, _)| *key == peer_key));

        let tx_id = [7u8; 32];
        crate::ledger::close::stamp_touched_previous_fields(
            &mut state,
            &result.touched,
            &tx_id,
            1234,
        );

        let peer = state
            .get_account(&dest_id())
            .expect("raw-only peer account should be hydrated");
        assert_eq!(peer.owner_count, 0);
        assert_eq!(peer.previous_txn_id, tx_id);
        assert_eq!(peer.previous_txn_lgr_seq, 1234);

        let meta = crate::ledger::close::build_tx_metadata(
            &state,
            &result.touched,
            tx_id,
            1234,
            0,
            "tesSUCCESS",
            None,
        );
        let (_, nodes) = crate::ledger::meta::parse_metadata_with_index(&meta);
        let peer_node = nodes
            .iter()
            .find(|node| node.ledger_index == peer_key.0)
            .expect("peer previous-txn-only touch should produce a ModifiedNode");
        assert!(matches!(
            peer_node.action,
            crate::ledger::meta::Action::Modified
        ));
        assert!(peer_node.previous_fields.is_empty());
    }

    #[test]
    fn test_trustset_allows_balance_that_only_clears_reserve_pre_fee() {
        let mut state = state_with_two_accounts();
        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let fees = crate::ledger::fees::Fees::default();
        let required = fees.reserve_base + fees.reserve_inc;

        let mut sender = state.get_account(&genesis_id()).unwrap().clone();
        sender.balance = required + 1;
        state.insert_account(sender);

        let tx = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.owner_count, 1);
        assert_eq!(sender.balance, required + 1 - tx.fee);
        assert!(
            state
                .get_trustline_for(&genesis_id(), &dest_id(), &usd)
                .is_some(),
            "trust line should be created when pre-fee balance clears reserve"
        );
    }

    #[test]
    fn test_trustset_allows_second_owned_object_without_incremental_reserve() {
        let mut state = state_with_two_accounts();
        let fees = crate::ledger::read_fees(&state);

        let mut sender = state.get_account(&genesis_id()).unwrap().clone();
        sender.balance = fees.reserve + 1;
        sender.owner_count = 1;
        state.insert_account(sender);

        let tx = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        let result = apply_tx(&mut state, &tx, &ctx(0));

        assert_eq!(result, ApplyResult::Success);
        assert_eq!(state.get_account(&genesis_id()).unwrap().owner_count, 2);
    }

    #[test]
    fn test_trustset_requires_full_owner_reserve_after_two_owned_objects() {
        let mut state = state_with_two_accounts();
        let fees = crate::ledger::read_fees(&state);

        let mut sender = state.get_account(&genesis_id()).unwrap().clone();
        sender.balance = fees.reserve + 1;
        sender.owner_count = 2;
        state.insert_account(sender);

        let tx = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        let result = apply_tx(&mut state, &tx, &ctx(0));

        assert_eq!(result, ApplyResult::ClaimedCost("tecNO_LINE_INSUF_RESERVE"));
        assert_eq!(state.get_account(&genesis_id()).unwrap().owner_count, 2);
    }

    #[test]
    fn test_trustset_records_actual_owner_directory_page_numbers() {
        let mut state = state_with_two_accounts();
        for i in 0..32u8 {
            let mut fake = [0u8; 32];
            fake[31] = i;
            crate::ledger::directory::dir_add(&mut state, &genesis_id(), fake);
        }

        let tx = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let tl = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .expect("trust line should have been created");

        if tl.low_account == genesis_id() {
            assert_eq!(tl.low_node, 1);
            assert_eq!(tl.high_node, 0);
        } else {
            assert_eq!(tl.low_node, 0);
            assert_eq!(tl.high_node, 1);
        }
    }

    #[test]
    fn test_trustset_updates_limit() {
        let mut state = state_with_two_accounts();
        // Create with 1000 limit
        let tx1 = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        apply_tx(&mut state, &tx1, &ctx(0));
        // Update to 5000 limit
        let tx2 = sign_trustset(2, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 5000.0);
        apply_tx(&mut state, &tx2, &ctx(0));

        // Owner count should still be 1 (same trust line updated, not new)
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.owner_count, 1);
        let peer = state.get_account(&dest_id()).unwrap();
        assert_eq!(peer.owner_count, 0);
    }

    #[test]
    fn test_trustset_zero_limit_deletes() {
        let mut state = state_with_two_accounts();
        let tx1 = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        apply_tx(&mut state, &tx1, &ctx(0));

        // A zero limit alone does not delete if the sender-side NoRipple bit
        // does not match the sender's DefaultRipple setting.
        let tx2 = sign_trustset(2, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 0.0);
        apply_tx(&mut state, &tx2, &ctx(0));

        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
        assert!(state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .is_some());
        assert_eq!(state.get_account(&genesis_id()).unwrap().owner_count, 1);

        let tx3 = sign_trustset_with_flags(
            3,
            "USD",
            "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            0.0,
            0x0002_0000,
        );
        apply_tx(&mut state, &tx3, &ctx(0));

        assert!(state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .is_none());

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.owner_count, 0);
        let peer = state.get_account(&dest_id()).unwrap();
        assert_eq!(peer.owner_count, 0);
    }

    #[test]
    fn test_iou_payment_through_trust_line() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();

        // Step 1: Genesis sets trust line for USD from dest
        let tx1 = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 10000.0);
        apply_tx(&mut state, &tx1, &ctx(0));

        // Step 2: Directly manipulate the trust line to simulate the issuer funding the line
        {
            let usd = Currency::from_code("USD").unwrap();
            let key = crate::ledger::trustline::shamap_key(&genesis_id(), &dest_id(), &usd);
            let mut tl = state.get_trustline(&key).unwrap().clone();
            if genesis_id() < dest_id() {
                tl.balance = IouValue {
                    mantissa: 500_000_000_000_000_0,
                    exponent: -15,
                };
            } else {
                tl.balance = IouValue {
                    mantissa: -500_000_000_000_000_0,
                    exponent: -15,
                };
            }
            state.insert_trustline(tl);
        }

        // Step 3: Genesis sends 100 USD to dest (paying back some of the IOU)
        let kp = genesis_kp();
        let dest_account_id = dest_id();
        let iou_amount = Amount::Iou {
            value: IouValue {
                mantissa: 100_000_000_000_000_0,
                exponent: -15,
            },
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_account_id,
        };
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(iou_amount)
            .fee(12)
            .sequence(2)
            .sign(&kp)
            .unwrap();
        let tx = parse_blob(&signed.blob).unwrap();
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        // Check the trust line balance changed
        let usd = Currency::from_code("USD").unwrap();
        let tl = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .unwrap();
        let bal = tl.balance_for(&genesis_id());
        assert!(
            bal.mantissa > 0,
            "genesis should still have a positive balance"
        );
    }

    // ── OfferCreate tests ───────────────────────────────────────────────────

    fn sign_offer_create(seq: u32, pays: Amount, gets: Amount) -> ParsedTx {
        let kp = genesis_kp();
        let signed = TxBuilder::offer_create()
            .account(&kp)
            .taker_pays(pays)
            .taker_gets(gets)
            .fee(12)
            .sequence(seq)
            .sign(&kp)
            .unwrap();
        parse_blob(&signed.blob).unwrap()
    }

    fn sign_offer_replace(seq: u32, cancel_seq: u32, pays: Amount, gets: Amount) -> ParsedTx {
        let kp = genesis_kp();
        let signed = TxBuilder::offer_create()
            .account(&kp)
            .taker_pays(pays)
            .taker_gets(gets)
            .offer_sequence(cancel_seq)
            .fee(12)
            .sequence(seq)
            .sign(&kp)
            .unwrap();
        parse_blob(&signed.blob).unwrap()
    }

    #[test]
    fn offer_create_rejects_same_iou_issue_in_preflight() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let usd = Currency::from_code("USD").unwrap();
        let pays = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd.clone(),
            issuer: dest_id(),
        };
        let gets = Amount::Iou {
            value: IouValue::from_f64(5.0),
            currency: usd,
            issuer: dest_id(),
        };
        let tx = sign_offer_create(1, pays, gets);

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEM_REDUNDANT);
        assert!(!result.applied);
        assert!(state.offers_by_account(&genesis_id()).is_empty());
    }

    #[test]
    fn offer_create_rejects_malformed_iou_issue_in_preflight() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let bad_currency = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: Currency::bad_currency(),
            issuer: dest_id(),
        };
        let tx = sign_offer_create(1, bad_currency, Amount::Xrp(1_000_000));
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEM_BAD_CURRENCY);
        assert!(!result.applied);

        let bad_issuer = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: [0u8; 20],
        };
        let tx = sign_offer_create(1, bad_issuer, Amount::Xrp(1_000_000));
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEM_BAD_ISSUER);
        assert!(!result.applied);
    }

    #[test]
    fn offer_create_rejects_oversized_xrp_amount_in_preflight() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let usd = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let mut tx = sign_offer_create(1, Amount::Xrp(1_000_000), usd);
        tx.taker_pays = Some(Amount::Xrp(100_000_000_000_000_001));

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEM_BAD_AMOUNT);
        assert!(!result.applied);
    }

    #[test]
    fn offer_create_rejects_cancel_sequence_at_or_after_account_sequence() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_genesis(50_000_000);
        let self_issued = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: genesis_id(),
        };
        let tx = sign_offer_replace(1, 1, Amount::Xrp(1_000_000), self_issued);

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEM_BAD_SEQUENCE);
        assert!(!result.applied);
    }

    #[test]
    fn validated_replay_offer_create_amm_bridge_does_not_fake_success_without_pool() {
        let mut state = state_with_genesis(50_000_000);
        let usd = Amount::Iou {
            value: crate::transaction::amount::IouValue::from_f64(25.0),
            currency: crate::transaction::amount::Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let tx = sign_offer_create(1, Amount::Xrp(500_000), usd);
        let replay_ctx = TxContext {
            ledger_seq: 2,
            validated_result: Some(ter::TES_SUCCESS),
            validated_offer_create_amm_bridge: true,
            ..TxContext::default()
        };

        let result = run_tx(&mut state, &tx, &replay_ctx, ApplyFlags::VALIDATED_REPLAY);
        assert_eq!(result.ter, ter::TEM_UNKNOWN);
        assert!(!result.applied);
        assert!(result.touched.is_empty());

        let acct = load_existing_account(&mut state, &genesis_id()).expect("sender account");
        assert_eq!(acct.sequence, 1);
        assert_eq!(acct.balance, 50_000_000);

        let offer_key = crate::ledger::offer::shamap_key(&genesis_id(), 1);
        assert!(
            state.get_raw_owned(&offer_key).is_none(),
            "failed AMM bridge must not create a local standing offer"
        );
    }

    fn sign_offer_cancel(seq: u32, cancel_seq: u32) -> ParsedTx {
        let kp = genesis_kp();
        let signed = TxBuilder::offer_cancel()
            .account(&kp)
            .offer_sequence(cancel_seq)
            .fee(12)
            .sequence(seq)
            .sign(&kp)
            .unwrap();
        parse_blob(&signed.blob).unwrap()
    }

    #[test]
    fn test_offer_create_places_offer() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let usd = Amount::Iou {
            value: IouValue::from_f64(100.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let tx = sign_offer_create(1, usd, Amount::Xrp(1_000_000));
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        // Offer should exist
        let offers = state.offers_by_account(&genesis_id());
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].sequence, 1);

        // Owner count incremented
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.owner_count, 1);
        assert_eq!(sender.sequence, 2);
    }

    #[test]
    fn offer_create_rounds_standing_offer_to_issuer_tick_size() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_genesis(50_000_000);
        let mut issuer = state.get_account(&genesis_id()).unwrap().clone();
        issuer.tick_size = 3;
        state.insert_account(issuer);

        let usd = Amount::Iou {
            value: IouValue::from_f64(123.456789),
            currency: Currency::from_code("USD").unwrap(),
            issuer: genesis_id(),
        };
        let original_gets = Amount::Xrp(1_000_000);
        let original_quality = crate::ledger::directory::offer_quality(&original_gets, &usd);
        let tx = sign_offer_create(1, usd.clone(), original_gets.clone());

        let result = apply_tx(&mut state, &tx, &ctx(0));

        assert_eq!(result, ApplyResult::Success);
        let offers = state.offers_by_account(&genesis_id());
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].taker_pays, usd);
        assert_ne!(
            offers[0].taker_gets, original_gets,
            "non-sell OfferCreate should keep TakerPays exact and round TakerGets"
        );
        let mut stored_quality = [0u8; 8];
        stored_quality.copy_from_slice(&offers[0].book_directory[24..32]);
        let stored_quality = u64::from_be_bytes(stored_quality);
        assert_ne!(
            stored_quality, original_quality,
            "book directory quality should use tick-rounded offer quality"
        );
        assert_eq!(
            stored_quality,
            crate::ledger::directory::offer_quality(&offers[0].taker_gets, &offers[0].taker_pays)
        );
    }

    #[test]
    fn offer_create_standing_offer_requires_owner_reserve() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_genesis(1_000_000);
        let issued_usd = Amount::Iou {
            value: IouValue::from_f64(1.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: genesis_id(),
        };
        let tx = sign_offer_create(1, Amount::Xrp(1_000), issued_usd);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEC_INSUF_RESERVE_OFFER);
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.owner_count, 0);
    }

    #[test]
    fn test_offer_create_with_positive_xrp_liquidity_is_not_unfunded() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        {
            let mut sender = state.get_account(&genesis_id()).unwrap().clone();
            sender.balance = 10_500_000;
            state.insert_account(sender);
        }
        let usd = Amount::Iou {
            value: IouValue::from_f64(100.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let tx = sign_offer_create(1, usd, Amount::Xrp(100_000_000));

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TES_SUCCESS);
        assert_eq!(state.offers_by_account(&genesis_id()).len(), 1);
    }

    #[test]
    fn test_offer_create_with_opposite_limit_headroom_is_not_unfunded() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let trustset = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        apply_tx(&mut state, &trustset, &ctx(0));

        let usd = Currency::from_code("USD").unwrap();
        let key = crate::ledger::trustline::shamap_key(&genesis_id(), &dest_id(), &usd);
        let mut tl = state.get_trustline(&key).unwrap().clone();
        tl.balance = IouValue::ZERO;
        tl.low_limit = IouValue::ZERO;
        tl.high_limit = IouValue::ZERO;
        if genesis_id() < dest_id() {
            tl.high_limit = IouValue::from_f64(1000.0);
        } else {
            tl.low_limit = IouValue::from_f64(1000.0);
        }
        state.insert_trustline(tl);

        let usd_amount = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd,
            issuer: dest_id(),
        };
        let tx = sign_offer_create(2, usd_amount, Amount::Xrp(1_000_000));
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TES_SUCCESS);
        assert_eq!(state.offers_by_account(&genesis_id()).len(), 1);
    }

    #[test]
    fn offer_create_rejects_receive_iou_from_missing_issuer() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_genesis(50_000_000);
        let usd = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let tx = sign_offer_create(1, usd, Amount::Xrp(1_000_000));

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEC_NO_ISSUER);
        assert!(state.offers_by_account(&genesis_id()).is_empty());
    }

    #[test]
    fn offer_create_requires_auth_line_to_receive_iou() {
        use crate::ledger::account::LSF_REQUIRE_AUTH;
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let mut issuer = state.get_account(&dest_id()).unwrap().clone();
        issuer.flags |= LSF_REQUIRE_AUTH;
        state.insert_account(issuer);

        let usd = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let tx = sign_offer_create(1, usd, Amount::Xrp(1_000_000));

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEC_NO_LINE);
    }

    #[test]
    fn offer_create_requires_authorized_line_to_receive_iou() {
        use crate::ledger::account::LSF_REQUIRE_AUTH;
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let trustset = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        assert_eq!(
            apply_tx(&mut state, &trustset, &ctx(0)),
            ApplyResult::Success
        );
        let mut issuer = state.get_account(&dest_id()).unwrap().clone();
        issuer.flags |= LSF_REQUIRE_AUTH;
        state.insert_account(issuer);

        let usd = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let tx = sign_offer_create(2, usd, Amount::Xrp(1_000_000));

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEC_NO_AUTH);
    }

    #[test]
    fn offer_create_rejects_deep_frozen_receive_iou_line() {
        use crate::ledger::trustline::LSF_LOW_DEEP_FREEZE;
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let trustset = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        assert_eq!(
            apply_tx(&mut state, &trustset, &ctx(0)),
            ApplyResult::Success
        );
        let usd_currency = Currency::from_code("USD").unwrap();
        let key = crate::ledger::trustline::shamap_key(&genesis_id(), &dest_id(), &usd_currency);
        let mut line = state.get_trustline(&key).unwrap().clone();
        line.flags |= LSF_LOW_DEEP_FREEZE;
        state.insert_trustline(line);

        let usd = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: usd_currency,
            issuer: dest_id(),
        };
        let tx = sign_offer_create(2, usd, Amount::Xrp(1_000_000));

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEC_FROZEN);
    }

    #[test]
    fn offer_create_rejects_global_frozen_issue() {
        use crate::ledger::account::LSF_GLOBAL_FREEZE;
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let mut issuer = state.get_account(&dest_id()).unwrap().clone();
        issuer.flags |= LSF_GLOBAL_FREEZE;
        state.insert_account(issuer);

        let usd = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let tx = sign_offer_create(1, usd, Amount::Xrp(1_000_000));

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEC_FROZEN);
    }

    #[test]
    fn test_offer_create_appears_in_book() {
        use crate::ledger::directory::{book_dir_quality_key, offer_quality};
        use crate::ledger::BookKey;
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let usd = Amount::Iou {
            value: IouValue::from_f64(50.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let tx = sign_offer_create(1, usd.clone(), Amount::Xrp(500_000));
        apply_tx(&mut state, &tx, &ctx(0));

        let book_key = BookKey::from_amounts(&usd, &Amount::Xrp(500_000));
        let book = state.get_book(&book_key).expect("order book should exist");
        assert_eq!(book.len(), 1);

        let offer = state.offers_by_account(&genesis_id())[0];
        let quality = offer_quality(&offer.taker_gets, &offer.taker_pays);
        let expected_dir = book_dir_quality_key(&book_key, quality);
        assert_eq!(offer.book_directory, expected_dir.0);
        assert_eq!(offer.book_node, 0);

        let dir = state
            .get_directory(&expected_dir)
            .expect("book dir should exist");
        assert_eq!(dir.exchange_rate, Some(quality));
        assert!(dir.indexes.contains(&offer.key().0));
    }

    #[test]
    fn test_offer_create_respects_expiration_close_time() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_genesis(50_000_000);
        let usd = Amount::Iou {
            value: IouValue::from_f64(50.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let mut tx = sign_offer_create(1, usd, Amount::Xrp(500_000));
        tx.expiration = Some(700);

        let result = apply_tx(&mut state, &tx, &ctx(700));
        assert_eq!(result, ApplyResult::ClaimedCost("tecEXPIRED"));
        assert!(state.offers_by_account(&genesis_id()).is_empty());
    }

    #[test]
    fn offer_create_rejects_zero_expiration_as_malformed() {
        let mut state = state_with_genesis(100_000_000);
        let mut tx = sign_offer_create(1, Amount::Xrp(1_000_000), Amount::Xrp(2_000_000));
        tx.expiration = Some(0);

        let result = apply_tx(&mut state, &tx, &ctx(0));

        assert_eq!(result, ApplyResult::ClaimedCost("temBAD_EXPIRATION"));
        assert!(state.offers_by_account(&genesis_id()).is_empty());
    }

    #[test]
    fn offer_create_rejects_ioc_and_fok_as_invalid_flag() {
        const TF_IMMEDIATE_OR_CANCEL: u32 = 0x0002_0000;
        const TF_FILL_OR_KILL: u32 = 0x0004_0000;

        let mut state = state_with_genesis(100_000_000);
        let mut tx = sign_offer_create(1, Amount::Xrp(1_000_000), Amount::Xrp(2_000_000));
        tx.flags = TF_IMMEDIATE_OR_CANCEL | TF_FILL_OR_KILL;

        let result = apply_tx(&mut state, &tx, &ctx(0));

        assert_eq!(result, ApplyResult::ClaimedCost("temINVALID_FLAG"));
        assert!(state.offers_by_account(&genesis_id()).is_empty());
    }

    #[test]
    fn test_offer_cancel_hydrates_raw_offer_and_clears_book_directory() {
        use crate::ledger::directory::owner_dir_contains_entry;
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let usd = Amount::Iou {
            value: IouValue::from_f64(50.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let create_tx = sign_offer_create(1, usd, Amount::Xrp(500_000));
        assert_eq!(
            apply_tx(&mut state, &create_tx, &ctx(0)),
            ApplyResult::Success
        );

        let offer = state.offers_by_account(&genesis_id())[0].clone();
        let offer_key = offer.key();
        let book_dir_key = crate::ledger::Key(offer.book_directory);
        assert!(state.get_raw_owned(&offer_key).is_some());
        assert!(owner_dir_contains_entry(
            &state,
            &genesis_id(),
            &offer_key.0
        ));

        state.clear_typed_entry_for_key(&offer_key);
        assert!(state.get_offer(&offer_key).is_none());
        assert!(state.get_raw_owned(&offer_key).is_some());

        let cancel_tx = sign_offer_cancel(2, 1);
        assert_eq!(
            apply_tx(&mut state, &cancel_tx, &ctx(0)),
            ApplyResult::Success
        );

        assert!(state.get_raw_owned(&offer_key).is_none());
        assert!(state.get_offer(&offer_key).is_none());
        assert!(!owner_dir_contains_entry(
            &state,
            &genesis_id(),
            &offer_key.0
        ));

        if let Some(raw) = state.get_raw_owned(&book_dir_key) {
            let dir = crate::ledger::DirectoryNode::decode(&raw, book_dir_key.0)
                .expect("book directory should decode");
            assert!(!dir.indexes.contains(&offer_key.0));
        }

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.owner_count, 0);
    }

    #[test]
    fn test_multiple_offers_sorted_by_quality() {
        use crate::ledger::BookKey;
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let usd = |v: f64| Amount::Iou {
            value: IouValue::from_f64(v),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };

        let tx1 = sign_offer_create(1, usd(100.0), Amount::Xrp(2_000_000));
        apply_tx(&mut state, &tx1, &ctx(0));

        let tx2 = sign_offer_create(2, usd(100.0), Amount::Xrp(1_000_000));
        apply_tx(&mut state, &tx2, &ctx(0));

        let book_key = BookKey::from_amounts(&usd(1.0), &Amount::Xrp(1));
        let book = state.get_book(&book_key).unwrap();
        assert_eq!(book.len(), 2);

        let keys: Vec<_> = book.iter_by_quality().collect();
        let first = state.get_offer(keys[0]).unwrap();
        assert_eq!(first.sequence, 1);
    }

    // ── Offer crossing tests ────────────────────────────────────────────────

    #[test]
    fn test_offer_crossing_full_fill() {
        let mut state = state_with_genesis(100_000_000);
        let kp2 = crate::crypto::keys::Secp256k1KeyPair::from_seed_entropy(&[99u8; 16]);
        let acct2_pub = kp2.public_key_bytes();
        let acct2_id = crate::crypto::account_id(&acct2_pub);
        state.insert_account(AccountRoot {
            account_id: acct2_id,
            balance: 100_000_000,
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
        });

        let tx1 = sign_offer_create(1, Amount::Xrp(1_000_000), Amount::Xrp(2_000_000));
        apply_tx(&mut state, &tx1, &ctx(0));

        assert_eq!(state.offers_by_account(&genesis_id()).len(), 1);

        let kp2_full = crate::crypto::keys::KeyPair::Secp256k1(kp2);
        let signed = TxBuilder::offer_create()
            .account(&kp2_full)
            .taker_pays(Amount::Xrp(2_000_000))
            .taker_gets(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&kp2_full)
            .unwrap();
        let tx2 = parse_blob(&signed.blob).unwrap();
        apply_tx(&mut state, &tx2, &ctx(0));

        assert_eq!(
            state.offers_by_account(&genesis_id()).len(),
            0,
            "genesis offer should be consumed by crossing"
        );

        let genesis = state.get_account(&genesis_id()).unwrap();
        assert_eq!(genesis.balance, 100_000_000 - 12 - 2_000_000 + 1_000_000);
    }

    #[test]
    fn offer_create_passive_does_not_cross_equal_quality() {
        const TF_PASSIVE: u32 = 0x00010000;

        let mut state = state_with_genesis(100_000_000);
        let kp2 = secp_key(99);
        let acct2_id = key_account(&kp2);
        insert_account_with_auth(&mut state, acct2_id, 100_000_000, 1, 0, None);

        let resting = sign_offer_create(1, Amount::Xrp(1_000_000), Amount::Xrp(2_000_000));
        assert_eq!(
            apply_tx(&mut state, &resting, &ctx(0)),
            ApplyResult::Success
        );

        let signed = TxBuilder::offer_create()
            .account(&kp2)
            .taker_pays(Amount::Xrp(2_000_000))
            .taker_gets(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .flags(TF_PASSIVE)
            .sign(&kp2)
            .unwrap();
        let passive = parse_blob(&signed.blob).unwrap();
        assert_eq!(
            apply_tx(&mut state, &passive, &ctx(0)),
            ApplyResult::Success
        );

        assert_eq!(
            state.offers_by_account(&genesis_id()).len(),
            1,
            "equal-quality passive taker must not consume the resting offer"
        );
        let passive_offers = state.offers_by_account(&acct2_id);
        assert_eq!(
            passive_offers.len(),
            1,
            "passive remainder should be placed as a standing offer"
        );
        assert_ne!(
            passive_offers[0].flags & crate::ledger::offer::LSF_PASSIVE,
            0,
            "standing offer should preserve the passive ledger flag"
        );
    }

    #[test]
    fn offer_create_ioc_no_cross_returns_teckilled() {
        const TF_IMMEDIATE_OR_CANCEL: u32 = 0x00020000;

        let mut state = state_with_genesis(100_000_000);
        let tx = TxBuilder::offer_create()
            .account(&genesis_kp())
            .taker_pays(Amount::Xrp(1_000_000))
            .taker_gets(Amount::Xrp(2_000_000))
            .fee(12)
            .sequence(1)
            .flags(TF_IMMEDIATE_OR_CANCEL)
            .sign(&genesis_kp())
            .unwrap();
        let tx = parse_blob(&tx.blob).unwrap();

        let result = apply_tx(&mut state, &tx, &ctx(0));

        assert_eq!(result, ApplyResult::ClaimedCost("tecKILLED"));
        assert!(
            state.offers_by_account(&genesis_id()).is_empty(),
            "IOC offer that transfers no funds must not leave a standing offer"
        );
        let account = state.get_account(&genesis_id()).unwrap();
        assert_eq!(account.sequence, 2);
        assert_eq!(account.balance, 100_000_000 - 12);
    }

    #[test]
    fn offer_create_fok_partial_cross_rolls_back_crossing() {
        const TF_FILL_OR_KILL: u32 = 0x00040000;

        let mut state = state_with_genesis(100_000_000);
        let kp2 = secp_key(99);
        let acct2_id = key_account(&kp2);
        insert_account_with_auth(&mut state, acct2_id, 100_000_000, 1, 0, None);

        let resting = sign_offer_create(1, Amount::Xrp(1_000_000), Amount::Xrp(2_000_000));
        assert_eq!(
            apply_tx(&mut state, &resting, &ctx(0)),
            ApplyResult::Success
        );
        let resting_key = state.offers_by_account(&genesis_id())[0].key();
        let genesis_before = state.get_account(&genesis_id()).unwrap().clone();
        let taker_before = state.get_account(&acct2_id).unwrap().clone();

        let signed = TxBuilder::offer_create()
            .account(&kp2)
            .taker_pays(Amount::Xrp(4_000_000))
            .taker_gets(Amount::Xrp(2_000_000))
            .fee(12)
            .sequence(1)
            .flags(TF_FILL_OR_KILL)
            .sign(&kp2)
            .unwrap();
        let fok = parse_blob(&signed.blob).unwrap();
        let result = apply_tx(&mut state, &fok, &ctx(0));

        assert_eq!(result, ApplyResult::ClaimedCost("tecKILLED"));
        assert!(
            state.get_offer(&resting_key).is_some(),
            "FOK partial cross must leave the resting offer unchanged"
        );
        let genesis_after = state.get_account(&genesis_id()).unwrap();
        assert_eq!(genesis_after.balance, genesis_before.balance);
        assert_eq!(genesis_after.owner_count, genesis_before.owner_count);

        let taker_after = state.get_account(&acct2_id).unwrap();
        assert_eq!(taker_after.balance, taker_before.balance - 12);
        assert_eq!(taker_after.sequence, taker_before.sequence + 1);
        assert!(
            state.offers_by_account(&acct2_id).is_empty(),
            "failed FOK must not place a remainder"
        );
    }

    #[test]
    fn offer_quality_gate_allows_iou_input_transfer_rate_window() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let usd = Currency::from_code("USD").unwrap();
        let usd_amount = |v: f64| Amount::Iou {
            value: IouValue::from_f64(v),
            currency: usd.clone(),
            issuer: dest_id(),
        };

        let mut issuer = state.get_account(&dest_id()).unwrap().clone();
        issuer.transfer_rate = 1_200_000_000;
        state.insert_account(issuer);

        let trustset = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        assert_eq!(
            apply_tx(&mut state, &trustset, &ctx(0)),
            ApplyResult::Success
        );
        {
            let key = crate::ledger::trustline::shamap_key(&genesis_id(), &dest_id(), &usd);
            let mut tl = state.get_trustline(&key).unwrap().clone();
            if genesis_id() < dest_id() {
                tl.balance = IouValue::from_f64(200.0);
            } else {
                tl.balance = IouValue::from_f64(-200.0);
            }
            state.insert_trustline(tl);
        }

        let maker_kp = secp_key(88);
        let maker_id = key_account(&maker_kp);
        insert_account_with_auth(&mut state, maker_id, 50_000_000, 1, 0, None);

        let maker_offer = TxBuilder::offer_create()
            .account(&maker_kp)
            .taker_pays(usd_amount(110.0))
            .taker_gets(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&maker_kp)
            .unwrap();
        assert_eq!(
            apply_tx(&mut state, &parse_blob(&maker_offer.blob).unwrap(), &ctx(0)),
            ApplyResult::Success
        );

        let taker_offer = sign_offer_create(2, Amount::Xrp(1_000_000), usd_amount(100.0));
        assert_eq!(
            apply_tx(&mut state, &taker_offer, &ctx(0)),
            ApplyResult::Success
        );

        assert_eq!(
            state.offers_by_account(&maker_id).len(),
            0,
            "book offer inside the transfer-rate-adjusted window should cross"
        );
        assert_eq!(
            state.offers_by_account(&genesis_id()).len(),
            0,
            "fully crossed taker offer should not leave a standing remainder"
        );
        let taker_line = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .expect("taker trustline");
        assert_eq!(
            taker_line.balance_for(&genesis_id()),
            IouValue::from_f64(90.0),
            "crossing should debit the book price once transfer-rate-adjusted quality allows it"
        );
    }

    #[test]
    fn test_offer_crossing_hydrates_raw_only_counterparty_account() {
        let mut state = state_with_genesis(100_000_000);
        let kp2 = crate::crypto::keys::Secp256k1KeyPair::from_seed_entropy(&[99u8; 16]);
        let acct2_id = crate::crypto::account_id(&kp2.public_key_bytes());
        let acct2 = AccountRoot {
            account_id: acct2_id,
            balance: 100_000_000,
            sequence: 1,
            owner_count: 1,
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
        };
        let acct2_key = crate::ledger::account::shamap_key(&acct2_id);
        state.insert_raw(acct2_key, acct2.to_sle_binary());

        state.insert_offer(crate::ledger::Offer {
            account: acct2_id,
            sequence: 1,
            taker_pays: Amount::Xrp(1_000_000),
            taker_gets: Amount::Xrp(2_000_000),
            flags: 0,
            book_directory: [0u8; 32],
            book_node: 0,
            owner_node: 0,
            expiration: None,
            domain_id: None,
            additional_books: Vec::new(),
            previous_txn_id: [0u8; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        });

        let tx = sign_offer_create(1, Amount::Xrp(2_000_000), Amount::Xrp(1_000_000));
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let acct2 = state
            .get_account(&acct2_id)
            .expect("crossed counterparty account should hydrate from raw bytes");
        assert_eq!(
            acct2.owner_count, 0,
            "consumed offer should decrement owner count"
        );
        assert_eq!(
            acct2.balance, 99_000_000,
            "counterparty XRP balance should be updated during crossing"
        );
    }

    #[test]
    fn test_offer_no_crossing_when_prices_dont_overlap() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();

        let usd_amount = |v: f64| Amount::Iou {
            value: IouValue::from_f64(v),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };

        // Fund genesis with USD so the second offer (TakerGets=USD) is not
        // rejected as unfunded. Matches the setup pattern in
        // test_iou_payment_through_trust_line.
        let trustset = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 10000.0);
        apply_tx(&mut state, &trustset, &ctx(0));
        {
            let usd = Currency::from_code("USD").unwrap();
            let key = crate::ledger::trustline::shamap_key(&genesis_id(), &dest_id(), &usd);
            let mut tl = state.get_trustline(&key).unwrap().clone();
            // Trust-line balance sign depends on account-ID ordering
            // (lower account is "owner" with positive balance).
            if genesis_id() < dest_id() {
                tl.balance = IouValue {
                    mantissa: 1000_000_000_000_000_0,
                    exponent: -15,
                };
            } else {
                tl.balance = IouValue {
                    mantissa: -1000_000_000_000_000_0,
                    exponent: -15,
                };
            }
            state.insert_trustline(tl);
        }

        // tx1: sell 1M XRP for 100 USD (book: USD->XRP, quality 1e-4 USD/XRP)
        let tx1 = sign_offer_create(2, usd_amount(100.0), Amount::Xrp(1_000_000));
        let r1 = apply_tx(&mut state, &tx1, &ctx(0));
        assert_eq!(r1, ApplyResult::Success, "tx1 should be placed");

        // tx2: sell 1 USD for 1M XRP (book: XRP->USD, opposite side).
        // Prices don't overlap — tx1 wants 100 USD for 1M XRP, tx2 offers
        // only 1 USD for 1M XRP — so no crossing should happen.
        let tx2 = sign_offer_create(3, Amount::Xrp(1_000_000), usd_amount(1.0));
        let r2 = apply_tx(&mut state, &tx2, &ctx(0));
        assert_eq!(r2, ApplyResult::Success, "tx2 should be placed");

        // Both offers must remain because prices do not overlap; self-owned
        // offers in the opposite book still have to pass the quality gate.
        assert_eq!(
            state.offers_by_account(&genesis_id()).len(),
            2,
            "both offers should remain — prices don't overlap, no crossing",
        );
    }

    #[test]
    fn offer_crossing_caps_partially_funded_iou_book_offer() {
        use crate::ledger::RippleState;
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let usd = Currency::from_code("USD").unwrap();
        let usd_amount = |v: f64| Amount::Iou {
            value: IouValue::from_f64(v),
            currency: usd.clone(),
            issuer: dest_id(),
        };

        let trustset = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        assert_eq!(
            apply_tx(&mut state, &trustset, &ctx(0)),
            ApplyResult::Success
        );

        let maker_kp = crate::crypto::keys::Secp256k1KeyPair::from_seed_entropy(&[77u8; 16]);
        let maker_id = crate::crypto::account_id(&maker_kp.public_key_bytes());
        state.insert_account(AccountRoot {
            account_id: maker_id,
            balance: 50_000_000,
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
        });

        let mut maker_line = RippleState::new(&maker_id, &dest_id(), usd.clone());
        maker_line.transfer(&dest_id(), &IouValue::from_f64(10.0));
        state.insert_trustline(maker_line);

        let maker_keypair = KeyPair::Secp256k1(maker_kp);
        let maker_offer = TxBuilder::offer_create()
            .account(&maker_keypair)
            .taker_pays(Amount::Xrp(1_000_000))
            .taker_gets(usd_amount(100.0))
            .fee(12)
            .sequence(1)
            .sign(&maker_keypair)
            .unwrap();
        assert_eq!(
            apply_tx(&mut state, &parse_blob(&maker_offer.blob).unwrap(), &ctx(0)),
            ApplyResult::Success
        );

        let taker_offer = sign_offer_create(2, usd_amount(100.0), Amount::Xrp(1_000_000));
        assert_eq!(
            apply_tx(&mut state, &taker_offer, &ctx(0)),
            ApplyResult::Success
        );

        let maker_line = state
            .get_trustline_for(&maker_id, &dest_id(), &usd)
            .expect("maker trustline");
        assert_eq!(maker_line.balance_for(&maker_id), IouValue::ZERO);

        let taker_line = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .expect("taker trustline");
        assert_eq!(
            taker_line.balance_for(&genesis_id()),
            IouValue::from_f64(10.0)
        );

        assert!(
            state.offers_by_account(&maker_id).is_empty(),
            "the book offer should be removed once its funded IOU amount is exhausted"
        );
        assert_eq!(
            state.get_account(&maker_id).unwrap().balance,
            50_000_000 - 12 + 100_000
        );
    }

    #[test]
    fn offer_crossing_caps_partially_funded_iou_taker_input() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        let usd = Currency::from_code("USD").unwrap();
        let usd_amount = |v: f64| Amount::Iou {
            value: IouValue::from_f64(v),
            currency: usd.clone(),
            issuer: dest_id(),
        };

        let trustset = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000.0);
        assert_eq!(
            apply_tx(&mut state, &trustset, &ctx(0)),
            ApplyResult::Success
        );
        {
            let key = crate::ledger::trustline::shamap_key(&genesis_id(), &dest_id(), &usd);
            let mut tl = state.get_trustline(&key).unwrap().clone();
            if genesis_id() < dest_id() {
                tl.balance = IouValue::from_f64(10.0);
            } else {
                tl.balance = IouValue::from_f64(-10.0);
            }
            state.insert_trustline(tl);
        }

        let maker_kp = secp_key(88);
        let maker_id = key_account(&maker_kp);
        insert_account_with_auth(&mut state, maker_id, 50_000_000, 1, 0, None);

        let maker_offer = TxBuilder::offer_create()
            .account(&maker_kp)
            .taker_pays(usd_amount(100.0))
            .taker_gets(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&maker_kp)
            .unwrap();
        assert_eq!(
            apply_tx(&mut state, &parse_blob(&maker_offer.blob).unwrap(), &ctx(0)),
            ApplyResult::Success
        );

        let taker_offer = sign_offer_create(2, Amount::Xrp(1_000_000), usd_amount(100.0));
        assert_eq!(
            apply_tx(&mut state, &taker_offer, &ctx(0)),
            ApplyResult::Success
        );

        let taker_line = state
            .get_trustline_for(&genesis_id(), &dest_id(), &usd)
            .expect("taker trustline");
        assert_eq!(
            taker_line.balance_for(&genesis_id()),
            IouValue::ZERO,
            "crossing should spend only the taker's funded 10 USD"
        );
        assert!(
            state.offers_by_account(&genesis_id()).is_empty(),
            "no taker remainder should be placed after funded IOU input is exhausted"
        );

        let maker_offers = state.offers_by_account(&maker_id);
        assert_eq!(maker_offers.len(), 1, "maker offer should be reduced");
        assert_eq!(maker_offers[0].taker_gets, Amount::Xrp(900_000));
        assert_eq!(maker_offers[0].taker_pays, usd_amount(90.0));
    }

    #[test]
    fn test_offer_crossing_partial_fill() {
        let mut state = state_with_genesis(100_000_000);

        let tx1 = sign_offer_create(1, Amount::Xrp(1_000_000), Amount::Xrp(2_000_000));
        apply_tx(&mut state, &tx1, &ctx(0));

        let tx2 = sign_offer_create(2, Amount::Xrp(4_000_000), Amount::Xrp(2_000_000));
        apply_tx(&mut state, &tx2, &ctx(0));

        let offers = state.offers_by_account(&genesis_id());
        assert!(
            offers.len() <= 2,
            "at most one remaining offer plus possibly a partial"
        );
    }

    #[test]
    fn test_offer_replace_reuses_released_iou_liquidity() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();

        let usd_amount = |v: f64| Amount::Iou {
            value: IouValue::from_f64(v),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };

        let trustset = sign_trustset(1, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 10000.0);
        assert_eq!(
            apply_tx(&mut state, &trustset, &ctx(0)),
            ApplyResult::Success
        );
        {
            let usd = Currency::from_code("USD").unwrap();
            let key = crate::ledger::trustline::shamap_key(&genesis_id(), &dest_id(), &usd);
            let mut tl = state.get_trustline(&key).unwrap().clone();
            if genesis_id() < dest_id() {
                tl.balance = IouValue::from_f64(100.0);
            } else {
                tl.balance = IouValue::from_f64(-100.0);
            }
            state.insert_trustline(tl);
        }

        let old_offer = sign_offer_create(2, Amount::Xrp(1_000_000), usd_amount(100.0));
        assert_eq!(
            apply_tx(&mut state, &old_offer, &ctx(0)),
            ApplyResult::Success
        );

        {
            let usd = Currency::from_code("USD").unwrap();
            let key = crate::ledger::trustline::shamap_key(&genesis_id(), &dest_id(), &usd);
            let mut tl = state.get_trustline(&key).unwrap().clone();
            tl.balance = IouValue::ZERO;
            state.insert_trustline(tl);
        }

        let replacement = sign_offer_replace(3, 2, Amount::Xrp(1_000_000), usd_amount(90.0));
        assert_eq!(
            apply_tx(&mut state, &replacement, &ctx(0)),
            ApplyResult::Success
        );

        let old_key = crate::ledger::offer::shamap_key(&genesis_id(), 2);
        let new_key = crate::ledger::offer::shamap_key(&genesis_id(), 3);

        assert!(
            state.get_offer(&old_key).is_none(),
            "old offer should be canceled"
        );
        assert!(
            state.get_offer(&new_key).is_some(),
            "replacement offer should be placed"
        );
        assert!(crate::ledger::directory::owner_dir_contains_entry(
            &state,
            &genesis_id(),
            &new_key.0
        ));
        assert!(!crate::ledger::directory::owner_dir_contains_entry(
            &state,
            &genesis_id(),
            &old_key.0
        ));
    }

    #[test]
    fn apply_fee_only_hydrates_raw_only_sender_account() {
        let mut state = LedgerState::new();
        let raw_only = AccountRoot {
            account_id: genesis_id(),
            balance: 1_000,
            sequence: 7,
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
        };
        let key = crate::ledger::account::shamap_key(&raw_only.account_id);
        state.insert_raw(key, raw_only.to_sle_binary());

        let tx = sign_offer_create(7, Amount::Xrp(1), Amount::Xrp(2));
        apply_fee_only(&mut state, &tx);

        let updated = state
            .get_account(&genesis_id())
            .expect("fee-only path should hydrate the sender account");
        assert_eq!(updated.balance, 988);
        assert_eq!(updated.sequence, 8);
    }

    #[test]
    fn run_tx_hydrates_raw_only_sender_for_preclaim_and_apply() {
        let mut state = LedgerState::new();
        let raw_only = AccountRoot {
            account_id: genesis_id(),
            balance: 100_000_000,
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
        };
        let key = crate::ledger::account::shamap_key(&raw_only.account_id);
        state.insert_raw(key, raw_only.to_sle_binary());

        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
        let tx = sign_offer_create(
            1,
            Amount::Iou {
                value: crate::transaction::amount::IouValue::from_f64(1.0),
                currency: usd,
                issuer: genesis_id(),
            },
            Amount::Xrp(2_000_000),
        );
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TES_SUCCESS);
        assert!(state
            .get_offer(&crate::ledger::offer::shamap_key(&genesis_id(), 1))
            .is_some());
        let sender = state
            .get_account(&genesis_id())
            .expect("sender should hydrate from raw bytes during run_tx");
        assert_eq!(sender.sequence, 2);
        assert_eq!(sender.balance, 100_000_000 - tx.fee);
    }

    // ── Escrow tests ────────────────────────────────────────────────────────

    fn sign_escrow_create(seq: u32, amount: u64, dest: &str, finish: u32, cancel: u32) -> ParsedTx {
        let kp = genesis_kp();
        let mut b = TxBuilder::escrow_create()
            .account(&kp)
            .destination(dest)
            .unwrap()
            .amount(Amount::Xrp(amount))
            .fee(12)
            .sequence(seq);
        if finish > 0 {
            b = b.finish_after(finish);
        }
        if cancel > 0 {
            b = b.cancel_after(cancel);
        }
        let signed = b.sign(&kp).unwrap();
        parse_blob(&signed.blob).unwrap()
    }

    fn sign_escrow_finish(seq: u32, owner_dest: &str, escrow_seq: u32) -> ParsedTx {
        let kp = genesis_kp();
        let signed = TxBuilder::escrow_finish()
            .account(&kp)
            .destination(owner_dest)
            .unwrap()
            .offer_sequence(escrow_seq)
            .fee(12)
            .sequence(seq)
            .sign(&kp)
            .unwrap();
        parse_blob(&signed.blob).unwrap()
    }

    #[allow(dead_code)]
    fn sign_escrow_cancel(seq: u32, owner_dest: &str, escrow_seq: u32) -> ParsedTx {
        let kp = genesis_kp();
        let signed = TxBuilder::escrow_cancel()
            .account(&kp)
            .destination(owner_dest)
            .unwrap()
            .offer_sequence(escrow_seq)
            .fee(12)
            .sequence(seq)
            .sign(&kp)
            .unwrap();
        parse_blob(&signed.blob).unwrap()
    }

    #[test]
    fn test_escrow_create_locks_funds() {
        let mut state = state_with_genesis(50_000_000);
        add_account(&mut state, dest_id(), 1_000_000, 1);
        let tx = sign_escrow_create(
            1,
            10_000_000,
            "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            1000,
            2000,
        );
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 50_000_000 - 10_000_000 - 12);
        assert_eq!(sender.owner_count, 1);
        assert_eq!(sender.sequence, 2);
    }

    #[test]
    fn test_escrow_finish_after_time() {
        let mut state = state_with_two_accounts();
        let dest_addr = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";

        let tx1 = sign_escrow_create(1, 5_000_000, dest_addr, 1000, 0);
        apply_tx(&mut state, &tx1, &ctx(0));

        let _tx2 = sign_escrow_finish(2, dest_addr, 1);
        let kp = genesis_kp();
        let genesis_addr = {
            let pubkey = kp.public_key_bytes();
            let id = crate::crypto::account_id(&pubkey);
            crate::crypto::base58::encode_account(&id)
        };
        let tx2 = {
            let kp = genesis_kp();
            let signed = TxBuilder::escrow_finish()
                .account(&kp)
                .destination(&genesis_addr)
                .unwrap()
                .offer_sequence(1)
                .fee(12)
                .sequence(2)
                .sign(&kp)
                .unwrap();
            parse_blob(&signed.blob).unwrap()
        };
        let result = apply_tx(&mut state, &tx2, &ctx(1001));
        assert_eq!(result, ApplyResult::Success);

        let dest = state.get_account(&dest_id()).unwrap();
        assert_eq!(dest.balance, 50_000_000 + 5_000_000);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.owner_count, 0);
    }

    #[test]
    fn test_escrow_finish_too_early_fails() {
        let mut state = state_with_two_accounts();
        let dest_addr = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";

        let tx1 = sign_escrow_create(1, 5_000_000, dest_addr, 1000, 0);
        apply_tx(&mut state, &tx1, &ctx(0));

        let genesis_addr = crate::crypto::base58::encode_account(&genesis_id());
        let tx2 = {
            let kp = genesis_kp();
            let signed = TxBuilder::escrow_finish()
                .account(&kp)
                .destination(&genesis_addr)
                .unwrap()
                .offer_sequence(1)
                .fee(12)
                .sequence(2)
                .sign(&kp)
                .unwrap();
            parse_blob(&signed.blob).unwrap()
        };
        let result = apply_tx(&mut state, &tx2, &ctx(500));
        assert_eq!(result, ApplyResult::ClaimedCost("tecNO_PERMISSION"));
    }

    #[test]
    fn test_escrow_cancel_after_time() {
        let mut state = state_with_two_accounts();
        let dest_addr = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";

        let tx1 = sign_escrow_create(1, 5_000_000, dest_addr, 1000, 2000);
        apply_tx(&mut state, &tx1, &ctx(0));

        let balance_after_create = state.get_account(&genesis_id()).unwrap().balance;

        let genesis_addr = crate::crypto::base58::encode_account(&genesis_id());
        let tx2 = {
            let kp = genesis_kp();
            let signed = TxBuilder::escrow_cancel()
                .account(&kp)
                .destination(&genesis_addr)
                .unwrap()
                .offer_sequence(1)
                .fee(12)
                .sequence(2)
                .sign(&kp)
                .unwrap();
            parse_blob(&signed.blob).unwrap()
        };
        let result = apply_tx(&mut state, &tx2, &ctx(2001));
        assert_eq!(result, ApplyResult::Success);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, balance_after_create + 5_000_000 - 12);
        assert_eq!(sender.owner_count, 0);
    }

    #[test]
    fn test_escrow_cancel_too_early_fails() {
        let mut state = state_with_two_accounts();
        let dest_addr = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";

        let tx1 = sign_escrow_create(1, 5_000_000, dest_addr, 1000, 2000);
        apply_tx(&mut state, &tx1, &ctx(0));

        let genesis_addr = crate::crypto::base58::encode_account(&genesis_id());
        let tx2 = {
            let kp = genesis_kp();
            let signed = TxBuilder::escrow_cancel()
                .account(&kp)
                .destination(&genesis_addr)
                .unwrap()
                .offer_sequence(1)
                .fee(12)
                .sequence(2)
                .sign(&kp)
                .unwrap();
            parse_blob(&signed.blob).unwrap()
        };
        let result = apply_tx(&mut state, &tx2, &ctx(100));
        assert_eq!(result, ApplyResult::ClaimedCost("tecNO_PERMISSION"));
    }

    #[test]
    fn test_escrow_finish_nonexistent() {
        let mut state = state_with_genesis(50_000_000);
        let genesis_addr = crate::crypto::base58::encode_account(&genesis_id());
        let tx = {
            let kp = genesis_kp();
            let signed = TxBuilder::escrow_finish()
                .account(&kp)
                .destination(&genesis_addr)
                .unwrap()
                .offer_sequence(999)
                .fee(12)
                .sequence(1)
                .sign(&kp)
                .unwrap();
            parse_blob(&signed.blob).unwrap()
        };
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::ClaimedCost("tecNO_TARGET"));
    }

    // ── Payment channel tests ───────────────────────────────────────────────

    #[test]
    fn test_paychan_create_locks_funds() {
        let mut state = state_with_two_accounts();
        let chan_kp = crate::crypto::keys::Secp256k1KeyPair::generate();

        let kp = genesis_kp();
        let signed = TxBuilder::paychan_create()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(10_000_000))
            .settle_delay(3600)
            .public_key_field(chan_kp.public_key_bytes())
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();
        let tx = parse_blob(&signed.blob).unwrap();
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 50_000_000 - 10_000_000 - 12);
        assert_eq!(sender.owner_count, 1);
    }

    #[test]
    fn paychan_create_requires_locked_amount_plus_owner_reserve() {
        let mut state = state_with_two_accounts();
        let mut sender = state.get_account(&genesis_id()).unwrap().clone();
        sender.balance = 1_200_000;
        state.insert_account(sender);
        let chan_kp = crate::crypto::keys::Secp256k1KeyPair::generate();
        let kp = genesis_kp();
        let signed = TxBuilder::paychan_create()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1))
            .settle_delay(3600)
            .public_key_field(chan_kp.public_key_bytes())
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();
        let tx = parse_blob(&signed.blob).unwrap();
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEC_UNFUNDED);
        assert!(state.iter_paychans().next().is_none());
    }

    #[test]
    fn test_paychan_claim_with_signature() {
        let mut state = state_with_two_accounts();
        let chan_kp = crate::crypto::keys::Secp256k1KeyPair::generate();

        let kp = genesis_kp();
        let signed = TxBuilder::paychan_create()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(10_000_000))
            .settle_delay(3600)
            .public_key_field(chan_kp.public_key_bytes())
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();
        let create_tx = parse_blob(&signed.blob).unwrap();
        apply_tx(&mut state, &create_tx, &ctx(0));

        let chan_key = crate::ledger::paychan::shamap_key(&genesis_id(), &dest_id(), 1);

        let claimed = 5_000_000u64;
        let mut claim_payload = crate::ledger::paychan::PREFIX_CLAIM.to_vec();
        claim_payload.extend_from_slice(&chan_key.0);
        claim_payload.extend_from_slice(&claimed.to_be_bytes());
        let claim_sig = chan_kp.sign(&claim_payload);

        let dest_balance_before = state.get_account(&dest_id()).unwrap().balance;
        let claim_tx_id = [0x15u8; 32];
        crate::transaction::parse::remember_paychan_balance_for_test(claim_tx_id, Some(claimed));

        let claim_tx = ParsedTx {
            tx_id: claim_tx_id,
            tx_type: 15,
            network_id: None,
            flags: 0,
            sequence: 2,
            fee: 12,
            account: genesis_id(),
            destination: None,
            destination_tag: None,
            amount_drops: Some(claimed),
            amount: None,
            amount2: None,
            limit_amount: None,
            taker_pays: None,
            taker_gets: None,
            offer_sequence: None,
            finish_after: None,
            cancel_after: None,
            settle_delay: None,
            expiration: None,
            channel: Some(chan_key.0),
            public_key: Some(chan_kp.public_key_bytes()),
            deliver_min: None,
            bid_min: None,
            bid_max: None,
            lp_token_out: None,
            lp_token_in: None,
            eprice: None,
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            nftoken_broker_fee: None,
            uri: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            trading_fee: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            paychan_sig: Some(claim_sig),
            owner: None,
            regular_key: None,
            nftoken_minter: None,
            issuer: None,
            subject: None,
            credential_type: None,
            oracle_document_id: None,
            oracle_last_update_time: None,
            oracle_price_data_series_raw: None,
            signer_quorum: None,
            signer_entries_raw: None,
            domain_id: None,
            ledger_fix_type: None,
            accepted_credentials_raw: None,
            authorize: None,
            unauthorize: None,
            delegate: None,
            account_txn_id: None,
            permissions_raw: None,
            did_document: None,
            did_data: None,
            holder: None,
            mptoken_issuance_id: None,
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
            email_hash: None,
            wallet_locator: None,
            message_key: None,
            asset: None,
            asset2: None,
            vault_id: None,
            loan_broker_id: None,
            loan_id: None,
            amendment: None,
            base_fee_field: None,
            reserve_base_field: None,
            reserve_increment_field: None,
            unl_modify_disabling: None,
            unl_modify_validator: None,
            signing_pubkey: vec![0x02; 33],
            signature: vec![],
            signing_hash: [0u8; 32],
            signing_payload: vec![],
            send_max: None,
            paths: vec![],
            signers: vec![],
        };
        let result = apply_tx(&mut state, &claim_tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let dest = state.get_account(&dest_id()).unwrap();
        assert_eq!(dest.balance, dest_balance_before + 5_000_000);

        let pc = state.get_paychan(&chan_key).unwrap();
        assert_eq!(pc.balance, 5_000_000);
    }

    #[test]
    fn test_paychan_fund_adds_xrp() {
        let mut state = state_with_two_accounts();
        let chan_kp = crate::crypto::keys::Secp256k1KeyPair::generate();
        let kp = genesis_kp();

        let signed = TxBuilder::paychan_create()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(5_000_000))
            .settle_delay(3600)
            .public_key_field(chan_kp.public_key_bytes())
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();
        apply_tx(&mut state, &parse_blob(&signed.blob).unwrap(), &ctx(0));

        let chan_key = crate::ledger::paychan::shamap_key(&genesis_id(), &dest_id(), 1);

        let signed = TxBuilder::paychan_fund()
            .account(&kp)
            .channel(chan_key.0)
            .amount(Amount::Xrp(3_000_000))
            .fee(12)
            .sequence(2)
            .sign(&kp)
            .unwrap();
        let result = apply_tx(&mut state, &parse_blob(&signed.blob).unwrap(), &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let pc = state.get_paychan(&chan_key).unwrap();
        assert_eq!(pc.amount, 8_000_000);
    }

    #[test]
    fn paychan_fund_preserves_existing_owner_reserve() {
        let mut state = state_with_two_accounts();
        let chan_kp = crate::crypto::keys::Secp256k1KeyPair::generate();
        let kp = genesis_kp();

        let signed = TxBuilder::paychan_create()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(5_000_000))
            .settle_delay(3600)
            .public_key_field(chan_kp.public_key_bytes())
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();
        apply_tx(&mut state, &parse_blob(&signed.blob).unwrap(), &ctx(0));

        let chan_key = crate::ledger::paychan::shamap_key(&genesis_id(), &dest_id(), 1);
        let mut sender = state.get_account(&genesis_id()).unwrap().clone();
        sender.balance = 1_200_000;
        sender.sequence = 2;
        state.insert_account(sender);

        let signed = TxBuilder::paychan_fund()
            .account(&kp)
            .channel(chan_key.0)
            .amount(Amount::Xrp(1))
            .fee(12)
            .sequence(2)
            .sign(&kp)
            .unwrap();
        let result = run_tx(
            &mut state,
            &parse_blob(&signed.blob).unwrap(),
            &ctx(0),
            ApplyFlags::NONE,
        );

        assert_eq!(result.ter, ter::TEC_INSUFFICIENT_RESERVE);
        let pc = state.get_paychan(&chan_key).unwrap();
        assert_eq!(pc.amount, 5_000_000);
    }

    #[test]
    fn test_paychan_close_and_delete() {
        let mut state = state_with_two_accounts();
        let chan_kp = crate::crypto::keys::Secp256k1KeyPair::generate();
        let kp = genesis_kp();

        let signed = TxBuilder::paychan_create()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(10_000_000))
            .settle_delay(60)
            .public_key_field(chan_kp.public_key_bytes())
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();
        apply_tx(&mut state, &parse_blob(&signed.blob).unwrap(), &ctx(1000));

        let chan_key = crate::ledger::paychan::shamap_key(&genesis_id(), &dest_id(), 1);

        let close_tx = ParsedTx {
            tx_id: [0u8; 32],
            tx_type: 15,
            network_id: None,
            flags: 0x00020000,
            sequence: 2,
            fee: 12,
            account: genesis_id(),
            destination: None,
            destination_tag: None,
            amount_drops: None,
            amount: None,
            amount2: None,
            limit_amount: None,
            taker_pays: None,
            taker_gets: None,
            offer_sequence: None,
            finish_after: None,
            cancel_after: None,
            settle_delay: None,
            expiration: None,
            channel: Some(chan_key.0),
            public_key: None,
            deliver_min: None,
            bid_min: None,
            bid_max: None,
            lp_token_out: None,
            lp_token_in: None,
            eprice: None,
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            nftoken_broker_fee: None,
            uri: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            trading_fee: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            paychan_sig: None,
            owner: None,
            regular_key: None,
            nftoken_minter: None,
            issuer: None,
            subject: None,
            credential_type: None,
            oracle_document_id: None,
            oracle_last_update_time: None,
            oracle_price_data_series_raw: None,
            signer_quorum: None,
            signer_entries_raw: None,
            domain_id: None,
            ledger_fix_type: None,
            accepted_credentials_raw: None,
            authorize: None,
            unauthorize: None,
            delegate: None,
            account_txn_id: None,
            permissions_raw: None,
            did_document: None,
            did_data: None,
            holder: None,
            mptoken_issuance_id: None,
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
            email_hash: None,
            wallet_locator: None,
            message_key: None,
            asset: None,
            asset2: None,
            vault_id: None,
            loan_broker_id: None,
            loan_id: None,
            amendment: None,
            base_fee_field: None,
            reserve_base_field: None,
            reserve_increment_field: None,
            unl_modify_disabling: None,
            unl_modify_validator: None,
            signing_pubkey: vec![0x02; 33],
            signature: vec![],
            signing_hash: [0u8; 32],
            signing_payload: vec![],
            send_max: None,
            paths: vec![],
            signers: vec![],
        };
        apply_tx(&mut state, &close_tx, &ctx(2000));

        let pc = state.get_paychan(&chan_key).unwrap();
        assert_eq!(pc.expiration, 2000 + 60);

        let delete_tx = ParsedTx {
            tx_id: [0u8; 32],
            tx_type: 15,
            network_id: None,
            flags: 0,
            sequence: 3,
            fee: 12,
            account: genesis_id(),
            destination: None,
            destination_tag: None,
            amount_drops: None,
            amount: None,
            amount2: None,
            limit_amount: None,
            taker_pays: None,
            taker_gets: None,
            offer_sequence: None,
            finish_after: None,
            cancel_after: None,
            settle_delay: None,
            expiration: None,
            channel: Some(chan_key.0),
            public_key: None,
            deliver_min: None,
            bid_min: None,
            bid_max: None,
            lp_token_out: None,
            lp_token_in: None,
            eprice: None,
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            nftoken_broker_fee: None,
            uri: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            trading_fee: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            paychan_sig: None,
            owner: None,
            regular_key: None,
            nftoken_minter: None,
            issuer: None,
            subject: None,
            credential_type: None,
            oracle_document_id: None,
            oracle_last_update_time: None,
            oracle_price_data_series_raw: None,
            signer_quorum: None,
            signer_entries_raw: None,
            domain_id: None,
            ledger_fix_type: None,
            accepted_credentials_raw: None,
            authorize: None,
            unauthorize: None,
            delegate: None,
            account_txn_id: None,
            permissions_raw: None,
            did_document: None,
            did_data: None,
            holder: None,
            mptoken_issuance_id: None,
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
            email_hash: None,
            wallet_locator: None,
            message_key: None,
            asset: None,
            asset2: None,
            vault_id: None,
            loan_broker_id: None,
            loan_id: None,
            amendment: None,
            base_fee_field: None,
            reserve_base_field: None,
            reserve_increment_field: None,
            unl_modify_disabling: None,
            unl_modify_validator: None,
            signing_pubkey: vec![0x02; 33],
            signature: vec![],
            signing_hash: [0u8; 32],
            signing_payload: vec![],
            send_max: None,
            paths: vec![],
            signers: vec![],
        };
        apply_tx(&mut state, &delete_tx, &ctx(2050));
        assert!(
            state.get_paychan(&chan_key).is_some(),
            "channel shouldn't be deleted yet"
        );

        apply_tx(&mut state, &delete_tx, &ctx(2061));
        assert!(
            state.get_paychan(&chan_key).is_none(),
            "channel should be deleted after expiration"
        );

        let creator = state.get_account(&genesis_id()).unwrap();
        assert_eq!(creator.owner_count, 0);
    }

    // ── Check tests ─────────────────────────────────────────────────────────

    fn sign_check_create(seq: u32, amount: u64, dest: &str, expiration: u32) -> ParsedTx {
        let kp = genesis_kp();
        let mut b = TxBuilder::check_create()
            .account(&kp)
            .destination(dest)
            .unwrap()
            .amount(Amount::Xrp(amount))
            .fee(12)
            .sequence(seq);
        if expiration > 0 {
            b = b.expiration(expiration);
        }
        parse_blob(&b.sign(&kp).unwrap().blob).unwrap()
    }

    fn check_id_for(account: [u8; 20], sequence: u32) -> [u8; 32] {
        crate::ledger::check::shamap_key(&account, sequence).0
    }

    fn sign_check_cash_exact(seq: u32, check_id: [u8; 32], amount: u64) -> ParsedTx {
        let kp = KeyPair::Secp256k1(
            Secp256k1KeyPair::from_seed("ssbTMHrmEJP7QEQjWJH3a72LQipBM").unwrap(),
        );
        let mut tx = parse_blob(
            &TxBuilder::check_cash()
                .account(&kp)
                .check_id(check_id)
                .amount(Amount::Xrp(amount))
                .fee(12)
                .sequence(seq)
                .sign(&kp)
                .unwrap()
                .blob,
        )
        .unwrap();
        tx.account = dest_id();
        tx
    }

    fn sign_check_cash_min(seq: u32, check_id: [u8; 32], deliver_min: u64) -> ParsedTx {
        let kp = KeyPair::Secp256k1(
            Secp256k1KeyPair::from_seed("ssbTMHrmEJP7QEQjWJH3a72LQipBM").unwrap(),
        );
        let mut tx = parse_blob(
            &TxBuilder::check_cash()
                .account(&kp)
                .check_id(check_id)
                .deliver_min(Amount::Xrp(deliver_min))
                .fee(12)
                .sequence(seq)
                .sign(&kp)
                .unwrap()
                .blob,
        )
        .unwrap();
        tx.account = dest_id();
        tx
    }

    #[test]
    fn test_check_create_no_debit() {
        let mut state = state_with_two_accounts();
        let tx = sign_check_create(1, 5_000_000, "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 0);
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 50_000_000 - 12);
        assert_eq!(sender.owner_count, 1);
    }

    #[test]
    fn check_create_requires_owner_reserve() {
        let mut state = state_with_two_accounts();
        let mut sender = state.get_account(&genesis_id()).unwrap().clone();
        sender.balance = 1_000_000;
        state.insert_account(sender);
        let tx = sign_check_create(1, 5_000_000, "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 0);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEC_INSUFFICIENT_RESERVE);
        assert!(state.iter_checks().next().is_none());
        assert_eq!(state.get_account(&genesis_id()).unwrap().owner_count, 0);
    }

    #[test]
    fn test_check_cash_exact() {
        let mut state = state_with_two_accounts();
        let dest_addr = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";

        let tx1 = sign_check_create(1, 5_000_000, dest_addr, 0);
        apply_tx(&mut state, &tx1, &ctx(0));

        let cash_tx = sign_check_cash_exact(1, check_id_for(genesis_id(), 1), 5_000_000);
        let result = apply_tx(&mut state, &cash_tx, &ctx(100));
        assert_eq!(result, ApplyResult::Success);

        let creator = state.get_account(&genesis_id()).unwrap();
        assert_eq!(creator.balance, 50_000_000 - 12 - 5_000_000);
        assert_eq!(creator.owner_count, 0);

        let dest = state.get_account(&dest_id()).unwrap();
        assert_eq!(dest.balance, 50_000_000 - 12 + 5_000_000);
    }

    #[test]
    fn test_check_cash_insufficient_balance() {
        let mut state = state_with_two_accounts();

        let tx1 = sign_check_create(1, 5_000_000, "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 0);
        apply_tx(&mut state, &tx1, &ctx(0));

        let mut acct = state.get_account(&genesis_id()).unwrap().clone();
        acct.balance = 100;
        state.insert_account(acct);

        let cash_tx = sign_check_cash_exact(1, check_id_for(genesis_id(), 1), 5_000_000);
        let result = apply_tx(&mut state, &cash_tx, &ctx(100));
        assert_eq!(result, ApplyResult::ClaimedCost("tecUNFUNDED_PAYMENT"));
    }

    #[test]
    fn test_check_cash_deliver_min_takes_available_up_to_send_max() {
        let mut state = state_with_two_accounts();
        let tx1 = sign_check_create(1, 5_000_000, "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 0);
        apply_tx(&mut state, &tx1, &ctx(0));

        let mut creator = state.get_account(&genesis_id()).unwrap().clone();
        creator.balance = 4_000_000;
        state.insert_account(creator);

        let cash_tx = sign_check_cash_min(1, check_id_for(genesis_id(), 1), 2_000_000);
        let result = apply_tx(&mut state, &cash_tx, &ctx(100));
        assert_eq!(result, ApplyResult::Success);

        let creator = state.get_account(&genesis_id()).unwrap();
        assert_eq!(creator.balance, 1_000_000);
        assert_eq!(creator.owner_count, 0);

        let dest = state.get_account(&dest_id()).unwrap();
        assert_eq!(dest.balance, 50_000_000 - 12 + 3_000_000);
    }

    #[test]
    fn test_check_cancel_by_creator() {
        let mut state = state_with_two_accounts();
        let tx1 = sign_check_create(1, 5_000_000, "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 0);
        apply_tx(&mut state, &tx1, &ctx(0));

        let kp = genesis_kp();
        let _genesis_addr = crate::crypto::base58::encode_account(&genesis_id());
        let cancel = TxBuilder::check_cancel()
            .account(&kp)
            .check_id(check_id_for(genesis_id(), 1))
            .fee(12)
            .sequence(2)
            .sign(&kp)
            .unwrap();
        let cancel_tx = parse_blob(&cancel.blob).unwrap();
        let result = apply_tx(&mut state, &cancel_tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.owner_count, 0);
    }

    #[test]
    fn test_check_cash_expired() {
        let mut state = state_with_two_accounts();
        let tx1 = sign_check_create(1, 5_000_000, "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 1000);
        apply_tx(&mut state, &tx1, &ctx(0));

        let cash_tx = sign_check_cash_exact(1, check_id_for(genesis_id(), 1), 5_000_000);
        let result = apply_tx(&mut state, &cash_tx, &ctx(1001));
        assert_eq!(result, ApplyResult::ClaimedCost("tecEXPIRED"));
    }

    #[test]
    fn test_check_cash_wrong_account() {
        let mut state = state_with_two_accounts();
        let tx1 = sign_check_create(1, 5_000_000, "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 0);
        apply_tx(&mut state, &tx1, &ctx(0));

        let wrong_kp = genesis_kp();
        let cash_tx = parse_blob(
            &TxBuilder::check_cash()
                .account(&wrong_kp)
                .check_id(check_id_for(genesis_id(), 1))
                .amount(Amount::Xrp(5_000_000))
                .fee(12)
                .sequence(2)
                .sign(&wrong_kp)
                .unwrap()
                .blob,
        )
        .unwrap();
        let result = apply_tx(&mut state, &cash_tx, &ctx(100));
        assert_eq!(result, ApplyResult::ClaimedCost("tecNO_PERMISSION"));
    }

    // ── run_tx tests (new TER-aware pipeline) ──────────────────────────────

    #[test]
    fn run_tx_success_applies_and_returns_tes() {
        let mut state = state_with_genesis(10_000_000);
        let tx = sign_payment(1, 1_000_000, 12);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert!(result.ter.is_tes_success());
        assert!(result.applied);
        assert!(!result.touched.is_empty());

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 10_000_000 - 1_000_000 - 12);
        assert_eq!(sender.sequence, 2);
    }

    #[test]
    fn run_tx_no_account_returns_ter_not_applied() {
        let mut state = LedgerState::new();
        let tx = sign_payment(1, 1_000_000, 12);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TER_NO_ACCOUNT);
        assert!(!result.applied);
        assert!(result.touched.is_empty());
        // No account should exist — nothing was touched
        assert_eq!(state.account_count(), 0);
    }

    #[test]
    fn run_tx_wrong_sequence_returns_ter_pre_seq() {
        let mut state = state_with_genesis(10_000_000);
        // Account is at seq 1, but tx has seq 5
        let tx = sign_payment(5, 1_000_000, 12);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TER_PRE_SEQ);
        assert!(!result.applied);
        // Account balance should be unchanged
        assert_eq!(
            state.get_account(&genesis_id()).unwrap().balance,
            10_000_000
        );
        assert_eq!(state.get_account(&genesis_id()).unwrap().sequence, 1);
    }

    #[test]
    fn run_tx_insufficient_fee_returns_ter() {
        let mut state = state_with_genesis(5); // only 5 drops
        let tx = sign_payment(1, 1, 12); // fee = 12 drops > balance
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TER_INSUF_FEE_B);
        assert!(!result.applied);
        assert_eq!(state.get_account(&genesis_id()).unwrap().balance, 5);
    }

    #[test]
    fn run_tx_offer_create_tec_killed_preserves_stale_offer_cleanup() {
        const TF_FILL_OR_KILL: u32 = 0x0004_0000;

        use crate::ledger::trustline::{LSF_HIGH_FREEZE, LSF_LOW_FREEZE};
        use crate::ledger::{Offer, RippleState};
        use crate::transaction::amount::{Currency, IouValue};

        let maker = [1u8; 20];
        let issuer = [2u8; 20];
        let usd = Currency::from_code("USD").unwrap();
        let mut state = state_with_genesis(100_000_000);
        add_account(&mut state, maker, 1_000_000, 2);
        add_account(&mut state, issuer, 1_000_000, 1);

        let mut maker_account = state.get_account(&maker).unwrap().clone();
        maker_account.owner_count = 1;
        state.insert_account(maker_account);

        let mut line = RippleState::new(&maker, &issuer, usd.clone());
        line.transfer(&issuer, &IouValue::from_f64(10.0));
        if issuer == line.low_account {
            line.flags |= LSF_LOW_FREEZE;
        } else {
            line.flags |= LSF_HIGH_FREEZE;
        }
        state.insert_trustline(line);

        let stale = Offer {
            account: maker,
            sequence: 1,
            taker_pays: Amount::Xrp(1_000),
            taker_gets: Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd.clone(),
                issuer,
            },
            flags: 0,
            book_directory: [0; 32],
            book_node: 0,
            owner_node: 0,
            expiration: None,
            domain_id: None,
            additional_books: Vec::new(),
            previous_txn_id: [0; 32],
            previous_txn_lgr_seq: 0,
            raw_sle: None,
        };
        let stale_key = stale.key();
        state.insert_offer(stale);

        let signed = TxBuilder::offer_create()
            .account(&genesis_kp())
            .taker_pays(Amount::Iou {
                value: IouValue::from_f64(10.0),
                currency: usd,
                issuer,
            })
            .taker_gets(Amount::Xrp(1_000))
            .flags(TF_FILL_OR_KILL)
            .fee(12)
            .sequence(1)
            .sign(&genesis_kp())
            .unwrap();
        let tx = parse_blob(&signed.blob).unwrap();

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEC_KILLED);
        assert!(result.applied);
        assert!(
            state.get_offer(&stale_key).is_none(),
            "tecKILLED should retain stale offer deletion side effects"
        );
        let taker = state.get_account(&genesis_id()).unwrap();
        assert_eq!(taker.sequence, 2);
        assert_eq!(taker.balance, 100_000_000 - 12);
    }

    #[test]
    fn run_tx_zero_fee_rejected_before_sequence_acceptance() {
        let mut state = state_with_genesis(10_000_000);
        let tx = sign_payment(5, 1_000, 0);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEL_INSUF_FEE_P);
        assert!(!result.applied);
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 10_000_000);
        assert_eq!(sender.sequence, 1);
    }

    #[test]
    fn run_tx_inactive_amendment_rejects_before_fee_or_sequence() {
        let mut state = state_with_genesis(10_000_000);
        let tx = ParsedTx {
            tx_type: 35, // AMMCreate is gated by the AMM amendment.
            sequence: 1,
            fee: 12,
            account: genesis_id(),
            ..ParsedTx::default()
        };

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(
            result.ter,
            ter::token_to_code("temDISABLED").unwrap_or(ter::TEM_UNKNOWN)
        );
        assert!(!result.applied);
        assert!(result.touched.is_empty());

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 10_000_000);
        assert_eq!(sender.sequence, 1);
    }

    #[test]
    fn unmapped_non_tec_tokens_do_not_claim_fee() {
        assert_eq!(tx_result_from_token("temFUTURE_UNKNOWN"), ter::TEM_UNKNOWN);
        assert_eq!(tx_result_from_token("tefFUTURE_UNKNOWN"), ter::TEM_UNKNOWN);
        assert_eq!(tx_result_from_token("terFUTURE_UNKNOWN"), ter::TEM_UNKNOWN);
        assert_eq!(tx_result_from_token("telFUTURE_UNKNOWN"), ter::TEM_UNKNOWN);
        assert_eq!(tx_result_from_token("tecFUTURE_UNKNOWN"), ter::TEC_CLAIM);
    }

    #[test]
    fn run_tx_ter_does_not_consume_fee_or_sequence() {
        let mut state = state_with_genesis(10_000_000);
        // Wrong sequence → terPRE_SEQ
        let tx = sign_payment(99, 1_000_000, 12);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert!(!result.applied);
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 10_000_000); // no fee deducted
        assert_eq!(sender.sequence, 1); // no sequence bump
    }

    #[test]
    fn run_tx_classify_success() {
        let result = TxRunResult {
            ter: ter::TES_SUCCESS,
            applied: true,
            touched: Vec::new(),
        };
        assert_eq!(classify_result(&result), ApplyOutcome::Success);
    }

    #[test]
    fn run_tx_classify_permanent_failure() {
        let result = TxRunResult {
            ter: ter::TEF_PAST_SEQ,
            applied: false,
            touched: Vec::new(),
        };
        assert_eq!(classify_result(&result), ApplyOutcome::Fail);

        let result2 = TxRunResult {
            ter: ter::TEM_MALFORMED,
            applied: false,
            touched: Vec::new(),
        };
        assert_eq!(classify_result(&result2), ApplyOutcome::Fail);
    }

    #[test]
    fn run_tx_classify_retry() {
        let result = TxRunResult {
            ter: ter::TER_PRE_SEQ,
            applied: false,
            touched: Vec::new(),
        };
        assert_eq!(classify_result(&result), ApplyOutcome::Retry);
    }

    fn ctx_at_seq(ledger_seq: u32) -> TxContext {
        TxContext {
            ledger_seq,
            ..TxContext::default()
        }
    }

    #[test]
    fn run_tx_last_ledger_seq_expired() {
        let mut state = state_with_genesis(10_000_000);
        let mut tx = sign_payment(1, 1_000_000, 12);
        tx.last_ledger_seq = Some(5); // expires after ledger 5
                                      // ledger_seq = 10 (> 5) → tefMAX_LEDGER
        let result = run_tx(&mut state, &tx, &ctx_at_seq(10), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEF_MAX_LEDGER);
        assert!(!result.applied);
    }

    #[test]
    fn run_tx_last_ledger_seq_still_valid() {
        let mut state = state_with_genesis(10_000_000);
        let mut tx = sign_payment(1, 1_000, 12);
        tx.last_ledger_seq = Some(10); // expires after ledger 10
                                       // ledger_seq = 5 (≤ 10) → should proceed normally
        let result = run_tx(&mut state, &tx, &ctx_at_seq(5), ApplyFlags::NONE);
        assert!(result.ter.is_tes_success() || result.ter.is_tec_claim());
    }

    #[test]
    fn run_tx_ticket_sequence_with_nonzero_seq_rejected() {
        let mut state = state_with_genesis(10_000_000);
        let mut tx = sign_payment(1, 1_000, 12);
        tx.ticket_sequence = Some(42); // ticket mode
        tx.sequence = 1; // but sequence is also set (non-zero) → conflict
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEM_SEQ_AND_TICKET);
        assert!(!result.applied);
    }

    #[test]
    fn run_tx_sequence_zero_without_ticket_is_past_sequence() {
        let mut state = state_with_genesis(10_000_000);
        let mut tx = sign_payment(0, 1_000, 12);
        tx.sequence = 0;
        tx.ticket_sequence = None;

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEF_PAST_SEQ);
        assert!(!result.applied);
    }

    #[test]
    fn run_tx_future_ticket_sequence_retries() {
        let mut state = state_with_genesis(10_000_000);
        let mut tx = sign_payment(0, 1_000, 12);
        tx.ticket_sequence = Some(42); // ticket mode
        tx.sequence = 0; // correct: sequence=0 for ticket-based
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TER_PRE_TICKET);
        assert!(!result.applied);
    }

    #[test]
    fn run_tx_missing_past_ticket_is_permanent_failure() {
        let mut state = state_with_genesis(10_000_000);
        {
            let mut sender = state.get_account(&genesis_id()).unwrap().clone();
            sender.sequence = 43;
            state.insert_account(sender);
        }
        let mut tx = sign_payment(0, 1_000, 12);
        tx.sequence = 0;
        tx.ticket_sequence = Some(42);

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEF_NO_TICKET);
        assert!(!result.applied);
    }

    #[test]
    fn run_tx_validated_replay_tec_offer_resets_to_fee_only() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_genesis(50_000_000);
        let usd = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let tx = sign_offer_create(1, usd, Amount::Xrp(100_000_000));

        let replay_ctx = TxContext {
            validated_result: Some(ter::TEC_UNFUNDED_OFFER),
            ..ctx(0)
        };

        let result = run_tx(&mut state, &tx, &replay_ctx, ApplyFlags::VALIDATED_REPLAY);
        assert_eq!(result.ter, ter::TEC_UNFUNDED_OFFER);
        assert!(result.applied, "validated tec replay must claim fee only");

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 50_000_000 - 12);
        assert_eq!(sender.sequence, 2);
        assert_eq!(sender.owner_count, 0);
        assert_eq!(state.offers_by_account(&genesis_id()).len(), 0);
    }

    #[test]
    fn run_tx_validated_replay_authoritative_tec_overrides_local_success() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_genesis(50_000_000);
        let usd = Amount::Iou {
            value: IouValue::from_f64(10.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let tx = sign_offer_create(1, usd, Amount::Xrp(500_000));
        let ctx = TxContext {
            validated_result: Some(ter::TEC_KILLED),
            ..ctx(0)
        };

        let result = run_tx(&mut state, &tx, &ctx, ApplyFlags::VALIDATED_REPLAY);
        assert_eq!(result.ter, ter::TEC_KILLED);
        assert!(result.applied, "validated tec replay must claim fee only");

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 50_000_000 - 12);
        assert_eq!(sender.sequence, 2);
        assert_eq!(sender.owner_count, 0);
        assert_eq!(state.offers_by_account(&genesis_id()).len(), 0);
    }

    #[test]
    fn run_tx_nftoken_create_offer_missing_destination_claims_fee_only() {
        let mut state = state_with_genesis(50_000_000);
        state.insert_nftoken(crate::ledger::NFToken {
            nftoken_id: [0xAB; 32],
            owner: genesis_id(),
            issuer: genesis_id(),
            uri: None,
            flags: 0,
            transfer_fee: 0,
            taxon: 0,
        });
        let mut tx = ParsedTx {
            tx_type: 27,
            flags: 1,
            sequence: 1,
            fee: 12,
            account: genesis_id(),
            destination: Some(dest_id()),
            amount: Some(Amount::Xrp(1_000)),
            nftoken_id: Some([0xAB; 32]),
            signing_pubkey: vec![0x02; 33],
            ..ParsedTx::default()
        };
        sign_auth_fields(&mut tx, &genesis_kp());

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEC_NO_DST);
        assert!(result.applied, "tecNO_DST must still claim fee only");

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 50_000_000 - 12);
        assert_eq!(sender.sequence, 2);
        assert_eq!(sender.owner_count, 0);
        assert!(state.iter_nft_offers().next().is_none());
    }

    fn ticket_create_tx(seq: u32, count: u32) -> ParsedTx {
        let mut tx = ParsedTx {
            tx_id: [0u8; 32],
            tx_type: 10,
            network_id: None,
            flags: 0,
            sequence: seq,
            fee: 12,
            account: genesis_id(),
            destination: None,
            destination_tag: None,
            amount_drops: None,
            amount: None,
            amount2: None,
            limit_amount: None,
            taker_pays: None,
            taker_gets: None,
            offer_sequence: None,
            finish_after: None,
            cancel_after: None,
            settle_delay: None,
            expiration: None,
            channel: None,
            public_key: None,
            deliver_min: None,
            bid_min: None,
            bid_max: None,
            lp_token_out: None,
            lp_token_in: None,
            eprice: None,
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            nftoken_broker_fee: None,
            uri: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            trading_fee: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            paychan_sig: None,
            owner: None,
            regular_key: None,
            nftoken_minter: None,
            issuer: None,
            subject: None,
            credential_type: None,
            oracle_document_id: None,
            oracle_last_update_time: None,
            oracle_price_data_series_raw: None,
            signer_quorum: None,
            signer_entries_raw: None,
            domain_id: None,
            ledger_fix_type: None,
            accepted_credentials_raw: None,
            authorize: None,
            unauthorize: None,
            delegate: None,
            account_txn_id: None,
            permissions_raw: None,
            did_document: None,
            did_data: None,
            holder: None,
            mptoken_issuance_id: None,
            set_flag: None,
            clear_flag: None,
            transfer_rate: None,
            quality_in: None,
            quality_out: None,
            tick_size: None,
            last_ledger_seq: None,
            ticket_count: Some(count),
            ticket_sequence: None,
            domain: None,
            email_hash: None,
            wallet_locator: None,
            message_key: None,
            asset: None,
            asset2: None,
            vault_id: None,
            loan_broker_id: None,
            loan_id: None,
            amendment: None,
            base_fee_field: None,
            reserve_base_field: None,
            reserve_increment_field: None,
            unl_modify_disabling: None,
            unl_modify_validator: None,
            signing_pubkey: vec![0x02; 33],
            signature: vec![],
            signing_hash: [0u8; 32],
            signing_payload: vec![],
            send_max: None,
            paths: vec![],
            signers: vec![],
        };
        sign_auth_fields(&mut tx, &genesis_kp());
        tx
    }

    fn insert_ticket_for_genesis(state: &mut LedgerState, ticket_seq: u32) {
        let ticket_key = crate::ledger::ticket::shamap_key(&genesis_id(), ticket_seq);
        let owner_node = crate::ledger::directory::dir_add(state, &genesis_id(), ticket_key.0);
        state.insert_ticket(crate::ledger::Ticket {
            account: genesis_id(),
            sequence: ticket_seq,
            owner_node,
            previous_txn_id: [0u8; 32],
            previous_txn_lgrseq: 0,
            raw_sle: None,
        });
        let mut acct = state.get_account(&genesis_id()).unwrap().clone();
        acct.owner_count += 1;
        acct.ticket_count += 1;
        acct.sequence = acct.sequence.max(ticket_seq.saturating_add(1));
        state.insert_account(acct);
    }

    #[test]
    fn ticket_create_starts_at_next_sequence() {
        let mut state = state_with_genesis(100_000_000);
        let tx = ticket_create_tx(1, 2);
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let wrong_first = crate::ledger::ticket::shamap_key(&genesis_id(), 1);
        let first = crate::ledger::ticket::shamap_key(&genesis_id(), 2);
        let second = crate::ledger::ticket::shamap_key(&genesis_id(), 3);

        assert!(
            state.get_raw_owned(&wrong_first).is_none(),
            "must not create a ticket at the tx Sequence itself"
        );
        assert!(
            state.get_raw_owned(&first).is_some(),
            "first ticket should use Sequence + 1"
        );
        assert!(
            state.get_raw_owned(&second).is_some(),
            "second ticket should use Sequence + 2"
        );
    }

    #[test]
    fn ticket_create_adds_next_sequence_ticket_to_owner_dir() {
        let mut state = state_with_genesis(100_000_000);
        let tx = ticket_create_tx(1, 1);
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let first = crate::ledger::ticket::shamap_key(&genesis_id(), 2);
        let wrong_first = crate::ledger::ticket::shamap_key(&genesis_id(), 1);

        assert!(crate::ledger::directory::owner_dir_contains_entry(
            &state,
            &genesis_id(),
            &first.0
        ));
        assert!(!crate::ledger::directory::owner_dir_contains_entry(
            &state,
            &genesis_id(),
            &wrong_first.0
        ));
    }

    #[test]
    fn ticket_create_updates_ticket_count() {
        let mut state = state_with_genesis(100_000_000);
        let tx = ticket_create_tx(1, 2);
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.ticket_count, 2);
        assert_eq!(sender.owner_count, 2);
    }

    #[test]
    fn ticket_create_requires_owner_reserve_for_all_tickets() {
        let mut state = state_with_genesis(1_000_000);
        let tx = ticket_create_tx(1, 1);
        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);

        assert_eq!(result.ter, ter::TEC_INSUFFICIENT_RESERVE);
        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.ticket_count, 0);
        assert_eq!(sender.owner_count, 0);
    }

    #[test]
    fn ticket_create_rejects_total_ticket_count_over_cap() {
        let mut state = state_with_genesis(100_000_000_000);
        let mut sender = state.get_account(&genesis_id()).unwrap().clone();
        sender.ticket_count = 249;
        state.insert_account(sender);

        let tx = ticket_create_tx(1, 2);
        let result = apply_tx(&mut state, &tx, &ctx(0));

        assert_eq!(result, ApplyResult::ClaimedCost("tecDIR_FULL"));
        assert_eq!(state.get_account(&genesis_id()).unwrap().ticket_count, 249);
    }

    #[test]
    fn ticket_create_advances_account_sequence_past_reserved_range() {
        let mut state = state_with_genesis(100_000_000);
        let tx = ticket_create_tx(1, 2);
        let result = apply_tx(&mut state, &tx, &ctx(0));
        assert_eq!(result, ApplyResult::Success);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(
            sender.sequence, 4,
            "Sequence should advance past tx seq and reserved tickets"
        );
    }

    #[test]
    fn ticketed_ticket_create_starts_at_current_account_sequence() {
        let mut state = state_with_genesis(100_000_000);
        insert_ticket_for_genesis(&mut state, 42);

        let mut tx = ticket_create_tx(0, 2);
        tx.ticket_sequence = Some(42);

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let wrong_first = crate::ledger::ticket::shamap_key(&genesis_id(), 1);
        let first = crate::ledger::ticket::shamap_key(&genesis_id(), 43);
        let second = crate::ledger::ticket::shamap_key(&genesis_id(), 44);

        assert!(state.get_raw_owned(&wrong_first).is_none());
        assert!(state.get_raw_owned(&first).is_some());
        assert!(state.get_raw_owned(&second).is_some());

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.sequence, 45);
        assert_eq!(sender.ticket_count, 2);
        assert_eq!(sender.owner_count, 2);
    }

    #[test]
    fn run_tx_consuming_ticket_decrements_ticket_count() {
        let mut state = state_with_two_accounts();
        insert_ticket_for_genesis(&mut state, 42);

        let mut tx = sign_payment(0, 1_000, 12);
        tx.sequence = 0;
        tx.ticket_sequence = Some(42);

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.ticket_count, 0);
        assert_eq!(sender.owner_count, 0);
    }

    #[test]
    fn run_tx_ticketed_tec_consumes_ticket_without_bumping_sequence() {
        let mut state = state_with_two_accounts();
        insert_ticket_for_genesis(&mut state, 42);
        state.insert_nftoken(crate::ledger::NFToken {
            nftoken_id: [0xAB; 32],
            owner: genesis_id(),
            issuer: genesis_id(),
            uri: None,
            flags: 0,
            transfer_fee: 0,
            taxon: 0,
        });
        let starting_sequence = state.get_account(&genesis_id()).unwrap().sequence;

        let mut tx = ParsedTx {
            tx_type: 27,
            flags: 1,
            sequence: 0,
            fee: 12,
            account: genesis_id(),
            destination: Some([0x44; 20]),
            amount: Some(Amount::Xrp(1_000)),
            nftoken_id: Some([0xAB; 32]),
            ticket_sequence: Some(42),
            signing_pubkey: vec![0x02; 33],
            ..ParsedTx::default()
        };
        sign_auth_fields(&mut tx, &genesis_kp());
        tx.sequence = 0;

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEC_NO_DST);
        assert!(result.applied, "ticketed tec must still claim fee");

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 50_000_000 - 12);
        assert_eq!(sender.sequence, starting_sequence);
        assert_eq!(sender.ticket_count, 0);
        assert_eq!(sender.owner_count, 0);
    }

    #[test]
    fn ticketed_offer_create_uses_ticket_sequence_proxy() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();
        insert_ticket_for_genesis(&mut state, 42);

        let wants_usd = Amount::Iou {
            value: IouValue::from_f64(100.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let mut tx = sign_offer_create(1, wants_usd, Amount::Xrp(2_000_000));
        tx.sequence = 0;
        tx.ticket_sequence = Some(42);

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let ticket_offer_key = crate::ledger::offer::shamap_key(&genesis_id(), 42);
        let zero_offer_key = crate::ledger::offer::shamap_key(&genesis_id(), 0);
        let offer = state
            .get_offer(&ticket_offer_key)
            .expect("ticket-based offer should use ticket sequence");
        assert_eq!(offer.sequence, 42);
        assert!(
            state.get_offer(&zero_offer_key).is_none(),
            "must not create a sequence-0 offer"
        );

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.ticket_count, 0);
        assert_eq!(sender.owner_count, 1, "ticket consumed, offer placed");
    }

    #[test]
    fn offer_create_preserves_expiration_on_created_sle() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_two_accounts();

        let wants_usd = Amount::Iou {
            value: IouValue::from_f64(100.0),
            currency: Currency::from_code("USD").unwrap(),
            issuer: dest_id(),
        };
        let mut tx = sign_offer_create(1, wants_usd, Amount::Xrp(2_000_000));
        tx.expiration = Some(700);

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let offer_key = crate::ledger::offer::shamap_key(&genesis_id(), 1);
        let offer = state.get_offer(&offer_key).expect("offer should exist");
        assert_eq!(offer.expiration, Some(700));

        let raw = state
            .get_raw_owned(&offer_key)
            .expect("offer raw SLE should exist");
        let decoded =
            crate::ledger::Offer::decode_from_sle(&raw).expect("offer raw SLE should decode");
        assert_eq!(decoded.expiration, Some(700));
    }

    #[test]
    fn batch_without_validated_result_fails_cleanly() {
        let mut state = state_with_genesis(1_000_000);
        let tx = ParsedTx {
            tx_type: 71,
            account: genesis_id(),
            sequence: 1,
            fee: 12,
            ..ParsedTx::default()
        };

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEM_DISABLED);
        assert!(!result.applied);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 1_000_000);
        assert_eq!(sender.sequence, 1);
    }

    #[test]
    fn batch_validated_replay_requires_active_mainnet_amendment() {
        let mut state = state_with_genesis(1_000_000);
        let tx = ParsedTx {
            tx_type: 71,
            account: genesis_id(),
            sequence: 1,
            fee: 12,
            ..ParsedTx::default()
        };
        let replay_ctx = TxContext {
            validated_result: Some(ter::TEC_NO_ENTRY),
            ..ctx(0)
        };

        let result = run_tx(&mut state, &tx, &replay_ctx, ApplyFlags::VALIDATED_REPLAY);
        assert_eq!(result.ter, ter::TEM_DISABLED);
        assert!(!result.applied);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 1_000_000);
        assert_eq!(sender.sequence, 1);
    }

    #[test]
    fn unknown_tx_type_without_validated_result_is_rejected() {
        let mut state = state_with_genesis(1_000_000);
        let tx = ParsedTx {
            tx_type: 255,
            account: genesis_id(),
            sequence: 1,
            fee: 12,
            ..ParsedTx::default()
        };

        let result = run_tx(&mut state, &tx, &ctx(0), ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEM_UNKNOWN);
        assert!(!result.applied);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 1_000_000);
        assert_eq!(sender.sequence, 1);
    }
}
