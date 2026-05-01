//! xLedgRS purpose: Route transaction engine handlers by XRPL transaction type.
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
mod credential;
mod delegate;
mod deposit_preauth;
mod did;
mod escrow;
mod ledger_state_fix;
mod loan;
mod mptoken;
mod nftoken;
mod nftoken_modify;
mod offer;
mod oracle;
mod paychan;
mod payment;
mod permissioned_domain;
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
static FEATURE_NFT_PAGE_LINKS: LazyLock<[u8; 32]> =
    LazyLock::new(|| amendment_hash("fixNFTokenPageLinks"));
static FEATURE_DELEGATION: LazyLock<[u8; 32]> =
    LazyLock::new(|| amendment_hash("PermissionDelegationV1_1"));

/// Returns the required amendment hash for a given tx type, or None if the
/// tx type is always available (no amendment gate).
fn required_amendment(tx_type: u16) -> Option<&'static [u8; 32]> {
    match tx_type {
        // AMM: AMMCreate(35), AMMDeposit(36), AMMWithdraw(37), AMMVote(38), AMMBid(39), AMMDelete(40)
        35 | 36 | 37 | 38 | 39 | 40 => Some(&*FEATURE_AMM),
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

/// Ledger context passed to transaction handlers.
/// Carries information from the parent ledger header that some handlers need.
#[derive(Debug, Clone)]
pub struct TxContext {
    /// Parent ledger hash — needed for pseudo-account derivation (VaultCreate, etc.)
    pub parent_hash: [u8; 32],
    /// Current ledger sequence being built.
    pub ledger_seq: u32,
    /// Close time of the ledger being built.
    pub close_time: u64,
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
            close_time,
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
            close_time: 0,
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
    let removed_from_owner_dir = ticket_owner_node
        .map(|owner_node| {
            crate::ledger::directory::dir_remove_root_page(
                state,
                &owner_root,
                owner_node,
                &ticket_key.key.0,
            )
        })
        .unwrap_or(false);
    if !removed_from_owner_dir {
        crate::ledger::directory::dir_remove(state, account, &ticket_key.key.0);
    }
    account_root.owner_count = account_root.owner_count.saturating_sub(1);
    account_root.ticket_count = account_root.ticket_count.saturating_sub(1);
    true
}

/// Bridge handlers that currently rely on authoritative metadata during
/// validated replay but are not yet independently implemented.
pub(crate) fn bridge_metadata_only_tx(
    ctx: &TxContext,
    tx_type: u16,
    label: &'static str,
    fallback_token: &'static str,
) -> ApplyResult {
    if let Some(validated) = ctx.validated_result {
        tracing::debug!(
            "apply_tx: tx type {} ({}) using validated replay bridge with result {}",
            tx_type,
            label,
            validated.token(),
        );
        if validated == ter::TES_SUCCESS {
            ApplyResult::Success
        } else {
            ApplyResult::ClaimedCost(validated.token())
        }
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
/// `flags` controls retry behavior (see `ApplyFlags::RETRY`).
pub fn run_tx(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
    flags: ApplyFlags,
) -> TxRunResult {
    // ── Pseudo-transactions bypass the pipeline ──────────────────────────
    match tx.tx_type {
        100 | 101 | 102 => {
            state.begin_tx();
            let _old_result = apply_tx(state, tx, ctx);
            let touched = state.commit_tx();
            return TxRunResult {
                ter: ter::TES_SUCCESS,
                applied: true,
                touched,
            };
        }
        _ => {}
    }

    // ── Preclaim: check LastLedgerSequence, account, sequence, fee ──────

    // LastLedgerSequence: tx expires if current ledger > last_ledger_seq.
    // rippled: Transactor.cpp checkPriorTxAndLastLedger → tefMAX_LEDGER.
    if let Some(last_seq) = tx.last_ledger_seq {
        if ctx.ledger_seq > last_seq {
            return TxRunResult {
                ter: ter::TEF_MAX_LEDGER,
                applied: false,
                touched: Vec::new(),
            };
        }
    }

    let acct = match load_existing_account(state, &tx.account) {
        Some(a) => a.clone(),
        None => {
            return TxRunResult {
                ter: ter::TER_NO_ACCOUNT,
                applied: false,
                touched: Vec::new(),
            }
        }
    };

    // TicketSequence vs Sequence mutual exclusivity.
    // rippled: a tx uses EITHER Sequence (>0) OR TicketSequence, never both.
    // Sequence=0 signals ticket-based; TicketSequence present signals ticket-based.
    if tx.ticket_sequence.is_some() && tx.sequence != 0 {
        return TxRunResult {
            ter: ter::TEM_SEQ_AND_TICKET,
            applied: false,
            touched: Vec::new(),
        };
    }

    if tx.sequence == 0 {
        let Some(ticket_seq) = tx.ticket_sequence else {
            return TxRunResult {
                ter: ter::TEF_PAST_SEQ,
                applied: false,
                touched: Vec::new(),
            };
        };

        if acct.sequence <= ticket_seq {
            return TxRunResult {
                ter: ter::TER_PRE_TICKET,
                applied: false,
                touched: Vec::new(),
            };
        }

        if !ticket_exists(state, &tx.account, ticket_seq) {
            return TxRunResult {
                ter: ter::TEF_NO_TICKET,
                applied: false,
                touched: Vec::new(),
            };
        }
    } else if tx.sequence != acct.sequence {
        if flags.contains(ApplyFlags::VALIDATED_REPLAY) {
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
        return TxRunResult {
            ter,
            applied: false,
            touched: Vec::new(),
        };
    }

    if acct.balance < tx.fee {
        return TxRunResult {
            ter: ter::TER_INSUF_FEE_B,
            applied: false,
            touched: Vec::new(),
        };
    }

    // ── Gate: likely_to_claim_fee? ──────────────────────────────────────
    // At this point preclaim would return tesSUCCESS (all checks passed).
    // With tesSUCCESS, likely_to_claim_fee is always true.
    // Continue into `do_apply`.

    // ── do_apply: begin_tx → run handler → handle result ────────────────
    state.begin_tx();
    let old_result = apply_tx(state, tx, ctx);

    // Convert old ApplyResult to TxResult
    let local_ter = match &old_result {
        ApplyResult::Success => ter::TES_SUCCESS,
        ApplyResult::ClaimedCost(code_str) => {
            ter::token_to_code(code_str).unwrap_or(ter::TEC_CLAIM)
        }
    };
    let ter = if flags.contains(ApplyFlags::VALIDATED_REPLAY) {
        if let Some(validated) = ctx.validated_result {
            if validated != local_ter {
                tracing::warn!(
                    "validated replay TER override: tx_type={} seq={} local={} authoritative={}",
                    tx.tx_type,
                    sequence_proxy(tx),
                    local_ter,
                    validated,
                );
            }
            validated
        } else {
            local_ter
        }
    } else {
        local_ter
    };

    // ── Handle tec hard-fail reset ──────────────────────────────────────
    // XRPL tec results claim the fee and consume the sequence, but they do
    // not keep transaction-specific side effects. That means a final tec
    // result must always collapse to a fee-only reset unless FAIL_HARD is in
    // force. Letting full mutations survive here is what poisons replay.
    let needs_reset = ter.is_tec_claim_hard_fail(flags) && !flags.contains(ApplyFlags::FAIL_HARD);

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

    let inv_result = if flags.contains(ApplyFlags::VALIDATED_REPLAY) {
        InvariantResult::Ok
    } else {
        invariants::check_invariants(state, &touched_peek, ter, tx.fee, tx)
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
    let fee_inv =
        invariants::check_invariants(state, &fee_touched, ter::TEC_INVARIANT_FAILED, tx.fee, tx);

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

/// Apply only fee deduction and sequence/ticket consumption — no transaction-specific logic.
/// Used after a reset (discard) to claim the fee on tec results.
fn apply_fee_only(state: &mut LedgerState, tx: &ParsedTx) -> TxResult {
    if let Some(acct) = load_existing_account(state, &tx.account) {
        let mut updated = acct.clone();
        // Cap fee to available balance (rippled Transactor.cpp:1033-1034)
        let fee = std::cmp::min(tx.fee, updated.balance);
        updated.balance -= fee;
        if tx.sequence != 0 {
            updated.sequence += 1;
        } else if let Some(ticket_seq) = tx.ticket_sequence {
            if !consume_ticket(state, &tx.account, ticket_seq, &mut updated) {
                return ter::TEF_BAD_LEDGER;
            }
        }
        state.insert_account(updated);
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
fn parse_majority_entries(raw: &[u8]) -> Vec<MajorityEntry> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos < raw.len() {
        if raw[pos] == 0xF1 {
            break;
        } // array end marker
          // Expect sfMajority object header (type=14, field=18)
          // Skip the object header and continue scanning the inner fields.
        let start = pos;
        // Skip field header (1-3 bytes)
        let byte = raw[pos];
        pos += 1;
        let hi = (byte >> 4) & 0x0F;
        let lo = byte & 0x0F;
        if hi == 0 || lo == 0 {
            if hi == 0 && lo != 0 {
                if pos < raw.len() {
                    pos += 1;
                }
            } else if hi != 0 && lo == 0 {
                if pos < raw.len() {
                    pos += 1;
                }
            } else {
                pos += 2.min(raw.len() - pos);
            }
        }

        // Now scan fields inside the object until 0xE1 (object end)
        let mut amendment = [0u8; 32];
        let mut close_time = 0u32;
        while pos < raw.len() && raw[pos] != 0xE1 {
            let fb = raw[pos];
            pos += 1;
            let tc = (fb >> 4) & 0x0F;
            let fc = fb & 0x0F;
            let (tc, fc) = if tc != 0 && fc != 0 {
                (tc, fc)
            } else if tc == 0 && fc != 0 {
                if pos >= raw.len() {
                    break;
                }
                let t = raw[pos];
                pos += 1;
                (t, fc)
            } else if tc != 0 && fc == 0 {
                if pos >= raw.len() {
                    break;
                }
                let f = raw[pos];
                pos += 1;
                (tc, f)
            } else {
                if pos + 1 >= raw.len() {
                    break;
                }
                let t = raw[pos];
                pos += 1;
                let f = raw[pos];
                pos += 1;
                (t, f)
            };
            match tc {
                2 => {
                    // UInt32
                    if pos + 4 > raw.len() {
                        break;
                    }
                    let v = u32::from_be_bytes(raw[pos..pos + 4].try_into().unwrap());
                    if fc == 7 {
                        close_time = v;
                    } // sfCloseTime
                    pos += 4;
                }
                5 => {
                    // Hash256
                    if pos + 32 > raw.len() {
                        break;
                    }
                    if fc == 19 {
                        // sfAmendment
                        amendment.copy_from_slice(&raw[pos..pos + 32]);
                    }
                    pos += 32;
                }
                _ => {
                    // Unknown field in majority object — skip to end marker
                    while pos < raw.len() && raw[pos] != 0xE1 {
                        pos += 1;
                    }
                    break;
                }
            }
        }
        if pos < raw.len() && raw[pos] == 0xE1 {
            pos += 1;
        } // skip object end
        if amendment != [0u8; 32] || close_time != 0 || pos > start + 3 {
            entries.push(MajorityEntry {
                amendment,
                close_time,
            });
        }
    }
    entries
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
    let mut pos = 0;
    while pos < sle_data.len() {
        let byte = sle_data[pos];
        pos += 1;
        let type_code;
        let field_code;
        let hi = (byte >> 4) & 0x0F;
        let lo = byte & 0x0F;
        if hi != 0 && lo != 0 {
            type_code = hi;
            field_code = lo;
        } else if hi == 0 && lo != 0 {
            if pos >= sle_data.len() {
                break;
            }
            type_code = sle_data[pos];
            pos += 1;
            field_code = lo;
        } else if hi != 0 && lo == 0 {
            if pos >= sle_data.len() {
                break;
            }
            type_code = hi;
            field_code = sle_data[pos];
            pos += 1;
        } else {
            if pos + 1 >= sle_data.len() {
                break;
            }
            type_code = sle_data[pos];
            pos += 1;
            field_code = sle_data[pos];
            pos += 1;
        }
        match type_code {
            1 => {
                pos += 2;
            } // UInt16
            2 => {
                pos += 4;
            } // UInt32
            3 => {
                pos += 8;
            } // UInt64
            5 => {
                pos += 32;
            } // Hash256
            7 => {
                // VL
                if pos >= sle_data.len() {
                    break;
                }
                let (len, consumed) = crate::ledger::decode_vl_length(&sle_data[pos..]);
                pos += consumed + len;
            }
            15 => {
                // ARRAY — if field=16 (sfMajorities), extract everything up to 0xF1.
                if field_code == 16 {
                    let start = pos;
                    while pos < sle_data.len() && sle_data[pos] != 0xF1 {
                        pos += 1;
                    }
                    if pos < sle_data.len() {
                        pos += 1;
                    } // include 0xF1
                    return Some(sle_data[start..pos].to_vec());
                } else {
                    while pos < sle_data.len() && sle_data[pos] != 0xF1 {
                        pos += 1;
                    }
                    if pos < sle_data.len() {
                        pos += 1;
                    }
                }
            }
            19 => {
                // VECTOR256
                if pos >= sle_data.len() {
                    break;
                }
                let (len, consumed) = crate::ledger::decode_vl_length(&sle_data[pos..]);
                pos += consumed + len;
            }
            _ => break,
        }
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
                None => return ApplyResult::Success,
            };
            let key = amendments_key();
            let mut enabled = read_amendments(state);
            // Read existing majorities raw bytes (pass through unchanged for got/lost).
            let existing_raw = state.get_raw_owned(&key).unwrap_or_default();
            let majorities_raw = extract_majorities_raw(&existing_raw);

            if tx.flags == 0 {
                // Direct enable — add to sfAmendments if not already present.
                if !enabled.contains(&amendment_hash) {
                    enabled.push(amendment_hash);
                }
                state.enable_amendment(amendment_hash);
                tracing::info!(
                    "amendment enabled: {}",
                    hex::encode_upper(&amendment_hash[..8]),
                );
                let sle = serialize_amendments(&enabled, majorities_raw.as_deref());
                state.insert_raw(key, sle);
            } else if tx.flags == 0x10000 {
                // tfGotMajority — add entry to sfMajorities array.
                // Parse existing majority objects, append new one, reserialize.
                let mut entries = parse_majority_entries(majorities_raw.as_deref().unwrap_or(&[]));
                entries.push(MajorityEntry {
                    amendment: amendment_hash,
                    close_time: ctx.close_time as u32,
                });
                let new_maj = serialize_majority_entries(&entries);
                let sle = serialize_amendments(&enabled, Some(&new_maj));
                state.insert_raw(key, sle);
            } else if tx.flags == 0x20000 {
                // tfLostMajority — remove only the matching entry from sfMajorities.
                let mut entries = parse_majority_entries(majorities_raw.as_deref().unwrap_or(&[]));
                entries.retain(|e| e.amendment != amendment_hash);
                let new_maj = if entries.is_empty() {
                    None
                } else {
                    Some(serialize_majority_entries(&entries))
                };
                let sle = serialize_amendments(&enabled, new_maj.as_deref());
                state.insert_raw(key, sle);
            }
            return ApplyResult::Success;
        }
        101 => {
            // SetFee — write FeeSettings SLE with fee fields from pseudo-tx.
            use crate::ledger::{fees_key, serialize_fee_settings, Fees};
            let key = fees_key();
            let fees = Fees {
                base: tx.base_fee_field.unwrap_or(10),
                reserve: tx.reserve_base_field.unwrap_or(10_000_000) as u64,
                increment: tx.reserve_increment_field.unwrap_or(2_000_000) as u64,
            };
            let sle = serialize_fee_settings(&fees);
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
            // UNLModify — write NegativeUNL SLE.
            use crate::ledger::serialize_negative_unl;
            let validator_key = match &tx.unl_modify_validator {
                Some(k) => k.clone(),
                None => return ApplyResult::Success,
            };
            let disabling = tx.unl_modify_disabling.unwrap_or(0) == 1;
            // Write the pending disable/re-enable field.
            // Full disabled-validators-list management requires tracking the
            // accumulation across flag ledgers — deferred to when validator
            // mode is active.
            let sle = if disabling {
                serialize_negative_unl(&[], Some(&validator_key), None)
            } else {
                serialize_negative_unl(&[], None, Some(&validator_key))
            };
            let key = crate::ledger::Key(crate::crypto::sha512_first_half(&[0x00, 0x4e]));
            state.insert_raw(key, sle);
            tracing::info!(
                "UNLModify: {} validator {}",
                if disabling {
                    "disabling"
                } else {
                    "re-enabling"
                },
                hex::encode_upper(&validator_key[..8.min(validator_key.len())]),
            );
            return ApplyResult::Success;
        }
        _ => {}
    }

    // ── Amendment gate ────────────────────────────────────────────────────────
    // Log, but do not block, transaction types whose amendment is not in the
    // local amendment set.
    // During replay of validated ledgers, the network already accepted these txs.
    // Blocking them would cause hash divergence. The gate is informational only
    // until ledgers are computed independently in validator mode.
    if let Some(hash) = required_amendment(tx.tx_type) {
        if !state.is_amendment_active(hash) {
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

    // 1. Deduct fee
    new_sender.balance = new_sender.balance.saturating_sub(tx.fee);

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

    // 3. Apply transaction-type-specific effects
    //
    // For escrow finish/cancel: persist the sender FIRST because the handler
    // may update a different account (the escrow owner) in state.
    // Tx type codes verified against rippled/include/xrpl/protocol/detail/transactions.macro
    let result = match tx.tx_type {
        2 | 4 | 7 | 8 | 15 | 17 | 18 | 26 | 28 | 29 | 30 | 31 | 35 | 36 | 37 | 38 | 39 | 40
        | 59 | 60 | 65 | 67 | 68 | 69 | 74 | 75 | 80 | 81 | 84 => {
            // Persist sender (fee + sequence bump) before handler — these
            // handlers modify the sender's account (or other accounts) through
            // state directly, so the local `new_sender` copy must be written
            // first to avoid clobbering crossing/transfer changes.
            state.insert_account(new_sender);
            match tx.tx_type {
                2 => escrow::apply_escrow_finish(state, tx, ctx.close_time), // EscrowFinish
                4 => escrow::apply_escrow_cancel(state, tx, ctx.close_time), // EscrowCancel
                7 => {
                    if ctx.validated_offer_create_amm_bridge {
                        offer::apply_validated_amm_offer_create(state, tx, ctx.close_time)
                            .unwrap_or_else(|| {
                                bridge_metadata_only_tx(
                                    ctx,
                                    tx.tx_type,
                                    "OfferCreate AMM validated bridge",
                                    "temUNKNOWN",
                                )
                            })
                    } else {
                        offer::apply_offer_create(state, tx, ctx.close_time)
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
                59 => credential::apply_credential_accept(state, tx), // CredentialAccept
                60 => credential::apply_credential_delete(state, tx), // CredentialDelete
                35 => amm::apply_amm_create(state, tx, ctx),          // AMMCreate
                36 => amm::apply_amm_deposit(state, tx),              // AMMDeposit
                37 => amm::apply_amm_withdraw(state, tx),             // AMMWithdraw
                38 => amm::apply_amm_vote(state, tx),                 // AMMVote
                39 => amm::apply_amm_bid(state, tx),                  // AMMBid
                40 => amm::apply_amm_delete(state, tx),               // AMMDelete
                65 => vault::apply_vault_create(state, tx, ctx),      // VaultCreate
                67 => vault::apply_vault_delete(state, tx),           // VaultDelete
                68 => vault::apply_vault_deposit(state, tx),          // VaultDeposit
                69 => vault::apply_vault_withdraw(state, tx),         // VaultWithdraw
                74 => loan::apply_loan_broker_set(state, tx, ctx),    // LoanBrokerSet
                75 => loan::apply_loan_broker_delete(state, tx),      // LoanBrokerDelete
                80 => loan::apply_loan_set(state, tx),                // LoanSet
                81 => loan::apply_loan_delete(state, tx),             // LoanDelete
                84 => loan::apply_loan_pay(state, tx),                // LoanPay
                _ => unreachable!(),
            }
        }
        _ => {
            let r = match tx.tx_type {
                0 => payment::apply_payment(state, tx, &mut new_sender, ctx), // Payment
                1 => escrow::apply_escrow_create(state, tx, &mut new_sender), // EscrowCreate
                3 => account_set::apply_account_set(tx, &mut new_sender),     // AccountSet
                5 => account_set::apply_set_regular_key(tx, &mut new_sender), // SetRegularKey
                10 => ticket::apply_ticket_create(state, tx, &mut new_sender), // TicketCreate
                12 => signer_list_set::apply_signer_list_set(state, tx, &mut new_sender), // SignerListSet
                13 => paychan::apply_paychan_create(state, tx, &mut new_sender), // PaymentChannelCreate
                14 => paychan::apply_paychan_fund(state, tx, &mut new_sender), // PaymentChannelFund
                16 => check::apply_check_create(state, tx, &mut new_sender),   // CheckCreate
                19 => deposit_preauth::apply_deposit_preauth(state, tx, &mut new_sender), // DepositPreauth
                20 => trust_set::apply_trustset(state, tx, &mut new_sender), // TrustSet
                21 => account_delete::apply_account_delete(state, tx, &mut new_sender), // AccountDelete
                25 => nftoken::apply_nftoken_mint(state, tx, &mut new_sender), // NFTokenMint
                27 => nftoken::apply_nftoken_create_offer(state, tx, &mut new_sender), // NFTokenCreateOffer
                // ── XChain types (not active on mainnet) ────────────────────
                41 | 42 | 43 | 44 | 45 | 46 | 47 | 48 => xchain::apply_xchain(ctx), // XChain*
                49 => did::apply_did_set(state, tx, &mut new_sender),               // DIDSet
                50 => did::apply_did_delete(state, tx, &mut new_sender),            // DIDDelete
                51 => oracle::apply_oracle_set(state, tx, &mut new_sender),         // OracleSet
                52 => oracle::apply_oracle_delete(state, tx, &mut new_sender),      // OracleDelete
                53 => ledger_state_fix::apply_ledger_state_fix(), // LedgerStateFix
                54 => mptoken::apply_mptoken_issuance_create(state, tx, &mut new_sender), // MPTokenIssuanceCreate
                55 => mptoken::apply_mptoken_issuance_destroy(state, tx, &mut new_sender), // MPTokenIssuanceDestroy
                56 => mptoken::apply_mptoken_issuance_set(state, tx, &mut new_sender), // MPTokenIssuanceSet
                57 => mptoken::apply_mptoken_authorize(state, tx, &mut new_sender), // MPTokenAuthorize
                58 => credential::apply_credential_create(state, tx, &mut new_sender), // CredentialCreate
                61 => nftoken_modify::apply_nftoken_modify(ctx), // NFTokenModify
                62 => {
                    permissioned_domain::apply_permissioned_domain_set(state, tx, &mut new_sender)
                } // PermissionedDomainSet
                63 => permissioned_domain::apply_permissioned_domain_delete(
                    state,
                    tx,
                    &mut new_sender,
                ), // PermissionedDomainDelete
                64 => delegate::apply_delegate_set(state, tx, &mut new_sender), // DelegateSet
                // ── Vault types ──────────────────────────────────────────────
                66 => vault::apply_vault_set(state, tx, ctx), // VaultSet
                70 => vault::apply_vault_clawback(state, tx, ctx), // VaultClawback
                71 => batch::apply_batch(ctx),                // Batch (not active)
                // ── Loan types ──────────────────────────────────────────────
                76 | 77 | 78 | 82 => loan::apply_loan_modify(ctx, tx.tx_type), // LoanBrokerCover*/LoanManage
                // ── Unknown/future tx types — fee+seq only ───────────────────
                _ => {
                    bridge_metadata_only_tx(ctx, tx.tx_type, "unknown/future tx type", "temUNKNOWN")
                }
            };
            // 4. Persist the updated sender account
            state.insert_account(new_sender);
            r
        }
    };

    result
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

    fn dest_id() -> [u8; 20] {
        crate::crypto::base58::decode_account("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap()
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
    fn validated_replay_self_payment_credits_authoritative_xrp_delivery() {
        let mut state = state_with_genesis(1_000_000);
        let tx = ParsedTx {
            tx_type: 0,
            flags: 0x0002_0000,
            sequence: 1,
            fee: 12,
            account: genesis_id(),
            destination: Some(genesis_id()),
            amount: Some(Amount::Xrp(100_000)),
            send_max: Some(Amount::Iou {
                value: crate::transaction::amount::IouValue {
                    mantissa: 1_000_000_000_000_000,
                    exponent: -3,
                },
                currency: crate::transaction::amount::Currency {
                    code: *b"ZERPS\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                },
                issuer: dest_id(),
            }),
            ..ParsedTx::default()
        };
        let ctx = TxContext {
            ledger_seq: 2,
            validated_result: Some(ter::TES_SUCCESS),
            validated_delivered_amount: Some(Amount::Xrp(99_000)),
            ..TxContext::default()
        };

        let result = run_tx(&mut state, &tx, &ctx, ApplyFlags::VALIDATED_REPLAY);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 1_000_000 - 12 + 99_000);
        assert_eq!(sender.sequence, 2);
    }

    #[test]
    fn validated_replay_self_payment_falls_back_to_requested_xrp_amount() {
        let mut state = state_with_genesis(1_000_000);
        let tx = ParsedTx {
            tx_type: 0,
            flags: 0x0002_0000,
            sequence: 1,
            fee: 12,
            account: genesis_id(),
            destination: Some(genesis_id()),
            amount: Some(Amount::Xrp(100_000)),
            send_max: Some(Amount::Iou {
                value: crate::transaction::amount::IouValue {
                    mantissa: 1_000_000_000_000_000,
                    exponent: -3,
                },
                currency: crate::transaction::amount::Currency {
                    code: *b"ZERPS\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                },
                issuer: dest_id(),
            }),
            ..ParsedTx::default()
        };
        let ctx = TxContext {
            ledger_seq: 2,
            validated_result: Some(ter::TES_SUCCESS),
            validated_delivered_amount: None,
            ..TxContext::default()
        };

        let result = run_tx(&mut state, &tx, &ctx, ApplyFlags::VALIDATED_REPLAY);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 1_000_000 - 12 + 100_000);
        assert_eq!(sender.sequence, 2);
    }

    #[test]
    fn validated_replay_self_payment_debits_xrp_send_max_for_iou_delivery() {
        let mut state = state_with_genesis(1_000_000);
        let tx = ParsedTx {
            tx_type: 0,
            flags: 0x0002_0000,
            sequence: 1,
            fee: 12,
            account: genesis_id(),
            destination: Some(genesis_id()),
            amount: Some(Amount::Iou {
                value: crate::transaction::amount::IouValue {
                    mantissa: 5_000_000_000_000_000,
                    exponent: -12,
                },
                currency: crate::transaction::amount::Currency {
                    code: *b"ZERPS\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                },
                issuer: dest_id(),
            }),
            send_max: Some(Amount::Xrp(100)),
            ..ParsedTx::default()
        };
        let ctx = TxContext {
            ledger_seq: 2,
            validated_result: Some(ter::TES_SUCCESS),
            validated_delivered_amount: Some(Amount::Iou {
                value: crate::transaction::amount::IouValue {
                    mantissa: 4_610_695_040_000_000,
                    exponent: -14,
                },
                currency: crate::transaction::amount::Currency {
                    code: *b"ZERPS\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                },
                issuer: dest_id(),
            }),
            ..TxContext::default()
        };

        let result = run_tx(&mut state, &tx, &ctx, ApplyFlags::VALIDATED_REPLAY);
        assert_eq!(result.ter, ter::TES_SUCCESS);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 1_000_000 - 12 - 100);
        assert_eq!(sender.sequence, 2);
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
        let tx = ParsedTx {
            tx_type: 0,
            sequence: 1,
            fee: 12,
            account: genesis_id(),
            destination: Some(genesis_id()),
            amount: Some(Amount::Xrp(100_000)),
            ..ParsedTx::default()
        };

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
                currency: usd,
                issuer: dest_id(),
            }),
            ..ParsedTx::default()
        };

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
        let mut state = state_with_genesis(50_000_000);
        state.insert_account(AccountRoot {
            account_id: dest_id(),
            balance: 10_000_000,
            sequence: 1,
            owner_count: 0,
            flags: crate::ledger::account::LSF_PASSWORD_SPENT,
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

        let mut state = state_with_genesis(50_000_000);
        let usd = Currency::from_code("USD").unwrap();
        let tx = ParsedTx {
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

        // Set limit to 0 -> should delete the trust line
        let tx2 = sign_trustset(2, "USD", "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 0.0);
        apply_tx(&mut state, &tx2, &ctx(0));

        let usd = crate::transaction::amount::Currency::from_code("USD").unwrap();
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
    fn validated_replay_offer_create_amm_bridge_avoids_local_standing_offer() {
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
        assert_eq!(result.ter, ter::TES_SUCCESS);
        assert!(result.applied);
        assert_eq!(
            result.touched.len(),
            1,
            "bridge should only touch sender account"
        );

        let acct = load_existing_account(&mut state, &genesis_id()).expect("sender account");
        assert_eq!(acct.sequence, 2);
        assert_eq!(acct.balance, 49_999_988);

        let offer_key = crate::ledger::offer::shamap_key(&genesis_id(), 1);
        assert!(
            state.get_raw_owned(&offer_key).is_none(),
            "validated AMM bridge must not create a local standing offer"
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

        let mut state = state_with_genesis(50_000_000);
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
    fn test_offer_create_with_positive_xrp_liquidity_is_not_unfunded() {
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_genesis(10_500_000);
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
    fn test_offer_create_appears_in_book() {
        use crate::ledger::directory::{book_dir_quality_key, offer_quality};
        use crate::ledger::BookKey;
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_genesis(50_000_000);
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
    fn test_offer_cancel_hydrates_raw_offer_and_clears_book_directory() {
        use crate::ledger::directory::owner_dir_contains_entry;
        use crate::transaction::amount::{Currency, IouValue};

        let mut state = state_with_genesis(50_000_000);
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

        let mut state = state_with_genesis(50_000_000);
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

        let tx = sign_offer_create(1, Amount::Xrp(1_000_000), Amount::Xrp(2_000_000));
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

        let tx1 = sign_escrow_create(1, 5_000_000, dest_addr, 0, 2000);
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

        let tx1 = sign_escrow_create(1, 5_000_000, dest_addr, 0, 2000);
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

        let claim_tx = ParsedTx {
            tx_type: 15,
            flags: 0,
            sequence: 2,
            fee: 12,
            account: genesis_id(),
            destination: None,
            amount_drops: Some(claimed),
            amount: None,
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
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            uri: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            paychan_sig: Some(claim_sig),
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
            asset: None,
            asset2: None,
            vault_id: None,
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
            tx_type: 15,
            flags: 0x00010000,
            sequence: 2,
            fee: 12,
            account: genesis_id(),
            destination: None,
            amount_drops: None,
            amount: None,
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
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            uri: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            paychan_sig: None,
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
            asset: None,
            asset2: None,
            vault_id: None,
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
            tx_type: 15,
            flags: 0,
            sequence: 3,
            fee: 12,
            account: genesis_id(),
            destination: None,
            amount_drops: None,
            amount: None,
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
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            uri: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            paychan_sig: None,
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
            asset: None,
            asset2: None,
            vault_id: None,
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
    fn test_check_cash_exact() {
        let mut state = state_with_two_accounts();
        let dest_addr = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
        let _genesis_addr = crate::crypto::base58::encode_account(&genesis_id());

        let tx1 = sign_check_create(1, 5_000_000, dest_addr, 0);
        apply_tx(&mut state, &tx1, &ctx(0));

        let cash_tx = ParsedTx {
            tx_type: 17,
            flags: 0,
            sequence: 1,
            fee: 12,
            account: dest_id(),
            destination: None,
            amount_drops: Some(5_000_000),
            amount: None,
            limit_amount: None,
            taker_pays: None,
            taker_gets: None,
            deliver_min: None,
            offer_sequence: Some(1),
            finish_after: None,
            cancel_after: None,
            settle_delay: None,
            expiration: None,
            channel: None,
            public_key: None,
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            uri: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            paychan_sig: None,
            owner: Some(genesis_id()),
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
            asset: None,
            asset2: None,
            vault_id: None,
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
        let mut acct = state.get_account(&genesis_id()).unwrap().clone();
        acct.balance = 100;
        state.insert_account(acct);

        let tx1 = sign_check_create(1, 5_000_000, "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 0);
        apply_tx(&mut state, &tx1, &ctx(0));

        let cash_tx = ParsedTx {
            tx_type: 17,
            flags: 0,
            sequence: 1,
            fee: 12,
            account: dest_id(),
            destination: None,
            amount_drops: Some(5_000_000),
            amount: None,
            limit_amount: None,
            taker_pays: None,
            taker_gets: None,
            deliver_min: None,
            offer_sequence: Some(1),
            finish_after: None,
            cancel_after: None,
            settle_delay: None,
            expiration: None,
            channel: None,
            public_key: None,
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            uri: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            paychan_sig: None,
            owner: Some(genesis_id()),
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
            asset: None,
            asset2: None,
            vault_id: None,
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
        let result = apply_tx(&mut state, &cash_tx, &ctx(100));
        assert_eq!(result, ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS"));
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
            .offer_sequence(1)
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

        let cash_tx = ParsedTx {
            tx_type: 17,
            flags: 0,
            sequence: 1,
            fee: 12,
            account: dest_id(),
            destination: None,
            amount_drops: Some(5_000_000),
            amount: None,
            limit_amount: None,
            taker_pays: None,
            taker_gets: None,
            deliver_min: None,
            offer_sequence: Some(1),
            finish_after: None,
            cancel_after: None,
            settle_delay: None,
            expiration: None,
            channel: None,
            public_key: None,
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            uri: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            paychan_sig: None,
            owner: Some(genesis_id()),
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
            asset: None,
            asset2: None,
            vault_id: None,
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
        let result = apply_tx(&mut state, &cash_tx, &ctx(1001));
        assert_eq!(result, ApplyResult::ClaimedCost("tecEXPIRED"));
    }

    #[test]
    fn test_check_cash_wrong_account() {
        let mut state = state_with_two_accounts();
        let tx1 = sign_check_create(1, 5_000_000, "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", 0);
        apply_tx(&mut state, &tx1, &ctx(0));

        let cash_tx = ParsedTx {
            tx_type: 17,
            flags: 0,
            sequence: 2,
            fee: 12,
            account: genesis_id(),
            destination: None,
            amount_drops: Some(5_000_000),
            amount: None,
            limit_amount: None,
            taker_pays: None,
            taker_gets: None,
            deliver_min: None,
            offer_sequence: Some(1),
            finish_after: None,
            cancel_after: None,
            settle_delay: None,
            expiration: None,
            channel: None,
            public_key: None,
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            uri: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            paychan_sig: None,
            owner: Some(genesis_id()),
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
            asset: None,
            asset2: None,
            vault_id: None,
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
        let tx = ParsedTx {
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
        ParsedTx {
            tx_type: 10,
            flags: 0,
            sequence: seq,
            fee: 12,
            account: genesis_id(),
            destination: None,
            amount_drops: None,
            amount: None,
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
            nftoken_id: None,
            nft_sell_offer: None,
            nft_buy_offer: None,
            uri: None,
            nftoken_taxon: None,
            transfer_fee_field: None,
            asset_scale: None,
            maximum_amount: None,
            mutable_flags: None,
            mptoken_metadata: None,
            paychan_sig: None,
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
            asset: None,
            asset2: None,
            vault_id: None,
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
        }
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
        assert_eq!(result.ter, ter::TEM_UNKNOWN);
        assert!(!result.applied);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 1_000_000);
        assert_eq!(sender.sequence, 1);
    }

    #[test]
    fn batch_validated_replay_uses_authoritative_result() {
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

        let result = run_tx(&mut state, &tx, &replay_ctx, ApplyFlags::NONE);
        assert_eq!(result.ter, ter::TEC_NO_ENTRY);
        assert!(result.applied);

        let sender = state.get_account(&genesis_id()).unwrap();
        assert_eq!(sender.balance, 1_000_000 - 12);
        assert_eq!(sender.sequence, 2);
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
