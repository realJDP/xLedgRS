//! Transaction Engine Result — mirrors rippled's TER code space.
//!
//! A single `i32` with predicate helpers, matching rippled's
//! `TER.h` ranges and `applySteps.h` behavioral predicates.

use std::fmt;

// ── ApplyFlags ───────────────────────────────────────────────────────────────

/// Flags controlling transaction application behavior.
/// Mirrors rippled's `ApplyFlags` in `ApplyView.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyFlags(u32);

impl ApplyFlags {
    pub const NONE:      ApplyFlags = ApplyFlags(0x00);
    /// Local transaction with fail_hard requested.
    pub const FAIL_HARD: ApplyFlags = ApplyFlags(0x10);
    /// Not the transaction's last pass — soft failures allowed.
    pub const RETRY:     ApplyFlags = ApplyFlags(0x20);
    /// Transaction came from a privileged source.
    pub const UNLIMITED: ApplyFlags = ApplyFlags(0x400);
    /// Transaction is executing as part of a batch.
    pub const BATCH:     ApplyFlags = ApplyFlags(0x800);
    /// Dry-run: compute result but don't apply.
    pub const DRY_RUN:   ApplyFlags = ApplyFlags(0x1000);
    /// Validated replay path: apply authoritative transactions without local invariant gating.
    pub const VALIDATED_REPLAY: ApplyFlags = ApplyFlags(0x2000);

    #[inline]
    pub const fn contains(self, other: ApplyFlags) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: ApplyFlags) -> ApplyFlags {
        ApplyFlags(self.0 | other.0)
    }
}

// ── TxResult ─────────────────────────────────────────────────────────────────

/// Transaction Engine Result code.
///
/// Wraps the raw `i32` from rippled's TER code space.  Behavior is derived
/// from predicate helpers — not from enum variant names.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxResult(i32);

impl TxResult {
    /// Construct from a raw code value.
    #[inline]
    pub const fn from_code(code: i32) -> Self {
        Self(code)
    }

    /// Raw numeric code.
    #[inline]
    pub const fn code(self) -> i32 {
        self.0
    }

    // ── Category predicates (rippled TER.h:626-661) ──────────────────────

    /// tel: local/application error, not applied, removed from set.
    /// Range: -399 .. -300
    #[inline]
    pub const fn is_tel_local(self) -> bool {
        self.0 >= -399 && self.0 < -299
    }

    /// tem: malformed transaction, cannot succeed in any ledger.
    /// Range: -299 .. -200
    #[inline]
    pub const fn is_tem_malformed(self) -> bool {
        self.0 >= -299 && self.0 < -199
    }

    /// tef: failure due to ledger state, not applied.
    /// Range: -199 .. -100
    #[inline]
    pub const fn is_tef_failure(self) -> bool {
        self.0 >= -199 && self.0 < -99
    }

    /// ter: retry — might succeed after a prior transaction lands.
    /// Range: -99 .. -1
    #[inline]
    pub const fn is_ter_retry(self) -> bool {
        self.0 >= -99 && self.0 < 0
    }

    /// tes: success (value 0).
    #[inline]
    pub const fn is_tes_success(self) -> bool {
        self.0 == 0
    }

    /// tec: claim fee only — applied, sequence consumed, but tx "failed".
    /// Range: 100+
    #[inline]
    pub const fn is_tec_claim(self) -> bool {
        self.0 >= 100
    }

    // ── Behavioral predicates (rippled applySteps.h:27-31) ───────────────

    /// tec code AND tapRETRY is NOT set → hard fail, fee claimed.
    /// During retry passes (tapRETRY set), tec codes are soft failures.
    #[inline]
    pub const fn is_tec_claim_hard_fail(self, flags: ApplyFlags) -> bool {
        self.is_tec_claim() && !flags.contains(ApplyFlags::RETRY)
    }

    /// True if this result means the transaction will claim a fee.
    /// Mirrors rippled's `PreclaimResult::likelyToClaimFee`.
    #[inline]
    pub const fn likely_to_claim_fee(self, flags: ApplyFlags) -> bool {
        self.is_tes_success() || self.is_tec_claim_hard_fail(flags)
    }

    /// True if the transaction should be marked as applied in the ledger.
    #[inline]
    pub const fn is_applied(self, flags: ApplyFlags) -> bool {
        self.is_tes_success() || self.is_tec_claim_hard_fail(flags)
    }

    // ── Close-loop classification ────────────────────────────────────────

    /// Permanent failure — remove from transaction set, don't retry.
    /// tef, tem, or tel.
    #[inline]
    pub const fn is_permanent_failure(self) -> bool {
        self.is_tef_failure() || self.is_tem_malformed() || self.is_tel_local()
    }

    // ── Token / display ──────────────────────────────────────────────────

    /// Human-readable token string for this result code.
    pub fn token(self) -> &'static str {
        code_to_token(self.0)
    }
}

impl fmt::Debug for TxResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxResult({}, {})", self.0, self.token())
    }
}

impl fmt::Display for TxResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.token())
    }
}

// ── TEL codes (local) ────────────────────────────────────────────────────────

pub const TEL_LOCAL_ERROR:                     TxResult = TxResult(-399);
pub const TEL_BAD_DOMAIN:                      TxResult = TxResult(-398);
pub const TEL_BAD_PATH_COUNT:                  TxResult = TxResult(-397);
pub const TEL_BAD_PUBLIC_KEY:                  TxResult = TxResult(-396);
pub const TEL_FAILED_PROCESSING:               TxResult = TxResult(-395);
pub const TEL_INSUF_FEE_P:                     TxResult = TxResult(-394);
pub const TEL_NO_DST_PARTIAL:                  TxResult = TxResult(-393);
pub const TEL_CAN_NOT_QUEUE:                   TxResult = TxResult(-392);
pub const TEL_CAN_NOT_QUEUE_BALANCE:           TxResult = TxResult(-391);
pub const TEL_CAN_NOT_QUEUE_BLOCKS:            TxResult = TxResult(-390);
pub const TEL_CAN_NOT_QUEUE_BLOCKED:           TxResult = TxResult(-389);
pub const TEL_CAN_NOT_QUEUE_FEE:               TxResult = TxResult(-388);
pub const TEL_CAN_NOT_QUEUE_FULL:              TxResult = TxResult(-387);
pub const TEL_WRONG_NETWORK:                   TxResult = TxResult(-386);
pub const TEL_REQUIRES_NETWORK_ID:             TxResult = TxResult(-385);
pub const TEL_NETWORK_ID_MAKES_TX_NON_CANONICAL: TxResult = TxResult(-384);
pub const TEL_ENV_RPC_FAILED:                  TxResult = TxResult(-383);

// ── TEM codes (malformed) ────────────────────────────────────────────────────

pub const TEM_MALFORMED:                       TxResult = TxResult(-299);
pub const TEM_BAD_AMOUNT:                      TxResult = TxResult(-298);
pub const TEM_BAD_CURRENCY:                    TxResult = TxResult(-297);
pub const TEM_BAD_EXPIRATION:                  TxResult = TxResult(-296);
pub const TEM_BAD_FEE:                         TxResult = TxResult(-295);
pub const TEM_BAD_ISSUER:                      TxResult = TxResult(-294);
pub const TEM_BAD_LIMIT:                       TxResult = TxResult(-293);
pub const TEM_BAD_OFFER:                       TxResult = TxResult(-292);
pub const TEM_BAD_PATH:                        TxResult = TxResult(-291);
pub const TEM_BAD_PATH_LOOP:                   TxResult = TxResult(-290);
pub const TEM_BAD_REGKEY:                      TxResult = TxResult(-289);
pub const TEM_BAD_SEND_XRP_LIMIT:              TxResult = TxResult(-288);
pub const TEM_BAD_SEND_XRP_MAX:                TxResult = TxResult(-287);
pub const TEM_BAD_SEND_XRP_NO_DIRECT:          TxResult = TxResult(-286);
pub const TEM_BAD_SEND_XRP_PARTIAL:            TxResult = TxResult(-285);
pub const TEM_BAD_SEND_XRP_PATHS:              TxResult = TxResult(-284);
pub const TEM_BAD_SEQUENCE:                    TxResult = TxResult(-283);
pub const TEM_BAD_SIGNATURE:                   TxResult = TxResult(-282);
pub const TEM_BAD_SRC_ACCOUNT:                 TxResult = TxResult(-281);
pub const TEM_BAD_TRANSFER_RATE:               TxResult = TxResult(-280);
pub const TEM_DST_IS_SRC:                      TxResult = TxResult(-279);
pub const TEM_DST_NEEDED:                      TxResult = TxResult(-278);
pub const TEM_INVALID:                         TxResult = TxResult(-277);
pub const TEM_INVALID_FLAG:                    TxResult = TxResult(-276);
pub const TEM_REDUNDANT:                       TxResult = TxResult(-275);
pub const TEM_RIPPLE_EMPTY:                    TxResult = TxResult(-274);
pub const TEM_DISABLED:                        TxResult = TxResult(-273);
pub const TEM_BAD_SIGNER:                      TxResult = TxResult(-272);
pub const TEM_BAD_QUORUM:                      TxResult = TxResult(-271);
pub const TEM_BAD_WEIGHT:                      TxResult = TxResult(-270);
pub const TEM_BAD_TICK_SIZE:                   TxResult = TxResult(-269);
pub const TEM_INVALID_ACCOUNT_ID:              TxResult = TxResult(-268);
pub const TEM_CANNOT_PREAUTH_SELF:             TxResult = TxResult(-267);
pub const TEM_INVALID_COUNT:                   TxResult = TxResult(-266);
pub const TEM_UNCERTAIN:                       TxResult = TxResult(-265); // internal
pub const TEM_UNKNOWN:                         TxResult = TxResult(-264); // internal
pub const TEM_SEQ_AND_TICKET:                  TxResult = TxResult(-263);
pub const TEM_BAD_NFTOKEN_TRANSFER_FEE:        TxResult = TxResult(-262);
pub const TEM_BAD_AMM_TOKENS:                  TxResult = TxResult(-261);
pub const TEM_XCHAIN_EQUAL_DOOR_ACCOUNTS:      TxResult = TxResult(-260);
pub const TEM_XCHAIN_BAD_PROOF:                TxResult = TxResult(-259);
pub const TEM_XCHAIN_BRIDGE_BAD_ISSUES:        TxResult = TxResult(-258);
pub const TEM_XCHAIN_BRIDGE_NONDOOR_OWNER:     TxResult = TxResult(-257);
pub const TEM_XCHAIN_BRIDGE_BAD_MIN_ACCOUNT_CREATE_AMOUNT: TxResult = TxResult(-256);
pub const TEM_XCHAIN_BRIDGE_BAD_REWARD_AMOUNT: TxResult = TxResult(-255);
pub const TEM_EMPTY_DID:                       TxResult = TxResult(-254);
pub const TEM_ARRAY_EMPTY:                     TxResult = TxResult(-253);
pub const TEM_ARRAY_TOO_LARGE:                 TxResult = TxResult(-252);
pub const TEM_BAD_TRANSFER_FEE:                TxResult = TxResult(-251);
pub const TEM_INVALID_INNER_BATCH:             TxResult = TxResult(-250);

// ── TEF codes (failure) ──────────────────────────────────────────────────────

pub const TEF_FAILURE:                         TxResult = TxResult(-199);
pub const TEF_ALREADY:                         TxResult = TxResult(-198);
pub const TEF_BAD_ADD_AUTH:                    TxResult = TxResult(-197);
pub const TEF_BAD_AUTH:                        TxResult = TxResult(-196);
pub const TEF_BAD_LEDGER:                      TxResult = TxResult(-195);
pub const TEF_CREATED:                         TxResult = TxResult(-194);
pub const TEF_EXCEPTION:                       TxResult = TxResult(-193);
pub const TEF_INTERNAL:                        TxResult = TxResult(-192);
pub const TEF_NO_AUTH_REQUIRED:                TxResult = TxResult(-191);
pub const TEF_PAST_SEQ:                        TxResult = TxResult(-190);
pub const TEF_WRONG_PRIOR:                     TxResult = TxResult(-189);
pub const TEF_MASTER_DISABLED:                 TxResult = TxResult(-188);
pub const TEF_MAX_LEDGER:                      TxResult = TxResult(-187);
pub const TEF_BAD_SIGNATURE:                   TxResult = TxResult(-186);
pub const TEF_BAD_QUORUM:                      TxResult = TxResult(-185);
pub const TEF_NOT_MULTI_SIGNING:               TxResult = TxResult(-184);
pub const TEF_BAD_AUTH_MASTER:                 TxResult = TxResult(-183);
pub const TEF_INVARIANT_FAILED:                TxResult = TxResult(-182);
pub const TEF_TOO_BIG:                         TxResult = TxResult(-181);
pub const TEF_NO_TICKET:                       TxResult = TxResult(-180);
pub const TEF_NFTOKEN_IS_NOT_TRANSFERABLE:     TxResult = TxResult(-179);
pub const TEF_INVALID_LEDGER_FIX_TYPE:         TxResult = TxResult(-178);

// ── TER codes (retry) ────────────────────────────────────────────────────────

pub const TER_RETRY:                           TxResult = TxResult(-99);
pub const TER_FUNDS_SPENT:                     TxResult = TxResult(-98); // deprecated
pub const TER_INSUF_FEE_B:                     TxResult = TxResult(-97);
pub const TER_NO_ACCOUNT:                      TxResult = TxResult(-96);
pub const TER_NO_AUTH:                         TxResult = TxResult(-95);
pub const TER_NO_LINE:                         TxResult = TxResult(-94);
pub const TER_OWNERS:                          TxResult = TxResult(-93);
pub const TER_PRE_SEQ:                         TxResult = TxResult(-92);
pub const TER_LAST:                            TxResult = TxResult(-91); // deprecated
pub const TER_NO_RIPPLE:                       TxResult = TxResult(-90);
pub const TER_QUEUED:                          TxResult = TxResult(-89);
pub const TER_PRE_TICKET:                      TxResult = TxResult(-88);
pub const TER_NO_AMM:                          TxResult = TxResult(-87);
pub const TER_ADDRESS_COLLISION:               TxResult = TxResult(-86);
pub const TER_NO_DELEGATE_PERMISSION:          TxResult = TxResult(-85);

// ── TES codes (success) ──────────────────────────────────────────────────────

pub const TES_SUCCESS: TxResult = TxResult(0);

// ── TEC codes (claim fee) ────────────────────────────────────────────────────

pub const TEC_CLAIM:                           TxResult = TxResult(100);
pub const TEC_PATH_PARTIAL:                    TxResult = TxResult(101);
pub const TEC_UNFUNDED_ADD:                    TxResult = TxResult(102); // unused legacy
pub const TEC_UNFUNDED_OFFER:                  TxResult = TxResult(103);
pub const TEC_UNFUNDED_PAYMENT:                TxResult = TxResult(104);
pub const TEC_FAILED_PROCESSING:               TxResult = TxResult(105);
pub const TEC_DIR_FULL:                        TxResult = TxResult(121);
pub const TEC_INSUF_RESERVE_LINE:              TxResult = TxResult(122);
pub const TEC_INSUF_RESERVE_OFFER:             TxResult = TxResult(123);
pub const TEC_NO_DST:                          TxResult = TxResult(124);
pub const TEC_NO_DST_INSUF_XRP:                TxResult = TxResult(125);
pub const TEC_NO_LINE_INSUF_RESERVE:           TxResult = TxResult(126);
pub const TEC_NO_LINE_REDUNDANT:               TxResult = TxResult(127);
pub const TEC_PATH_DRY:                        TxResult = TxResult(128);
pub const TEC_UNFUNDED:                        TxResult = TxResult(129);
pub const TEC_NO_ALTERNATIVE_KEY:              TxResult = TxResult(130);
pub const TEC_NO_REGULAR_KEY:                  TxResult = TxResult(131);
pub const TEC_OWNERS:                          TxResult = TxResult(132);
pub const TEC_NO_ISSUER:                       TxResult = TxResult(133);
pub const TEC_NO_AUTH:                         TxResult = TxResult(134);
pub const TEC_NO_LINE:                         TxResult = TxResult(135);
pub const TEC_INSUFF_FEE:                      TxResult = TxResult(136);
pub const TEC_FROZEN:                          TxResult = TxResult(137);
pub const TEC_NO_TARGET:                       TxResult = TxResult(138);
pub const TEC_NO_PERMISSION:                   TxResult = TxResult(139);
pub const TEC_NO_ENTRY:                        TxResult = TxResult(140);
pub const TEC_INSUFFICIENT_RESERVE:            TxResult = TxResult(141);
pub const TEC_NEED_MASTER_KEY:                 TxResult = TxResult(142);
pub const TEC_DST_TAG_NEEDED:                  TxResult = TxResult(143);
pub const TEC_INTERNAL:                        TxResult = TxResult(144);
pub const TEC_OVERSIZE:                        TxResult = TxResult(145);
pub const TEC_CRYPTOCONDITION_ERROR:           TxResult = TxResult(146);
pub const TEC_INVARIANT_FAILED:                TxResult = TxResult(147);
pub const TEC_EXPIRED:                         TxResult = TxResult(148);
pub const TEC_DUPLICATE:                       TxResult = TxResult(149);
pub const TEC_KILLED:                          TxResult = TxResult(150);
pub const TEC_HAS_OBLIGATIONS:                 TxResult = TxResult(151);
pub const TEC_TOO_SOON:                        TxResult = TxResult(152);
pub const TEC_HOOK_REJECTED:                   TxResult = TxResult(153);
pub const TEC_MAX_SEQUENCE_REACHED:            TxResult = TxResult(154);
pub const TEC_NO_SUITABLE_NFTOKEN_PAGE:        TxResult = TxResult(155);
pub const TEC_NFTOKEN_BUY_SELL_MISMATCH:       TxResult = TxResult(156);
pub const TEC_NFTOKEN_OFFER_TYPE_MISMATCH:     TxResult = TxResult(157);
pub const TEC_CANT_ACCEPT_OWN_NFTOKEN_OFFER:   TxResult = TxResult(158);
pub const TEC_INSUFFICIENT_FUNDS:              TxResult = TxResult(159);
pub const TEC_OBJECT_NOT_FOUND:                TxResult = TxResult(160);
pub const TEC_INSUFFICIENT_PAYMENT:            TxResult = TxResult(161);
pub const TEC_UNFUNDED_AMM:                    TxResult = TxResult(162);
pub const TEC_AMM_BALANCE:                     TxResult = TxResult(163);
pub const TEC_AMM_FAILED:                      TxResult = TxResult(164);
pub const TEC_AMM_INVALID_TOKENS:              TxResult = TxResult(165);
pub const TEC_AMM_EMPTY:                       TxResult = TxResult(166);
pub const TEC_AMM_NOT_EMPTY:                   TxResult = TxResult(167);
pub const TEC_AMM_ACCOUNT:                     TxResult = TxResult(168);
pub const TEC_INCOMPLETE:                      TxResult = TxResult(169);
pub const TEC_XCHAIN_BAD_TRANSFER_ISSUE:       TxResult = TxResult(170);
pub const TEC_XCHAIN_NO_CLAIM_ID:              TxResult = TxResult(171);
pub const TEC_XCHAIN_BAD_CLAIM_ID:             TxResult = TxResult(172);
pub const TEC_XCHAIN_CLAIM_NO_QUORUM:          TxResult = TxResult(173);
pub const TEC_XCHAIN_PROOF_UNKNOWN_KEY:        TxResult = TxResult(174);
pub const TEC_XCHAIN_CREATE_ACCOUNT_NONXRP_ISSUE: TxResult = TxResult(175);
pub const TEC_XCHAIN_WRONG_CHAIN:              TxResult = TxResult(176);
pub const TEC_XCHAIN_REWARD_MISMATCH:          TxResult = TxResult(177);
pub const TEC_XCHAIN_NO_SIGNERS_LIST:          TxResult = TxResult(178);
pub const TEC_XCHAIN_SENDING_ACCOUNT_MISMATCH: TxResult = TxResult(179);
pub const TEC_XCHAIN_INSUFF_CREATE_AMOUNT:     TxResult = TxResult(180);
pub const TEC_XCHAIN_ACCOUNT_CREATE_PAST:      TxResult = TxResult(181);
pub const TEC_XCHAIN_ACCOUNT_CREATE_TOO_MANY:  TxResult = TxResult(182);
pub const TEC_XCHAIN_PAYMENT_FAILED:           TxResult = TxResult(183);
pub const TEC_XCHAIN_SELF_COMMIT:              TxResult = TxResult(184);
pub const TEC_XCHAIN_BAD_PUBLIC_KEY_ACCOUNT_PAIR: TxResult = TxResult(185);
pub const TEC_XCHAIN_CREATE_ACCOUNT_DISABLED:  TxResult = TxResult(186);
pub const TEC_EMPTY_DID:                       TxResult = TxResult(187);
pub const TEC_INVALID_UPDATE_TIME:             TxResult = TxResult(188);
pub const TEC_TOKEN_PAIR_NOT_FOUND:            TxResult = TxResult(189);
pub const TEC_ARRAY_EMPTY:                     TxResult = TxResult(190);
pub const TEC_ARRAY_TOO_LARGE:                 TxResult = TxResult(191);
pub const TEC_LOCKED:                          TxResult = TxResult(192);
pub const TEC_BAD_CREDENTIALS:                 TxResult = TxResult(193);
pub const TEC_WRONG_ASSET:                     TxResult = TxResult(194);
pub const TEC_LIMIT_EXCEEDED:                  TxResult = TxResult(195);
pub const TEC_PSEUDO_ACCOUNT:                  TxResult = TxResult(196);
pub const TEC_PRECISION_LOSS:                  TxResult = TxResult(197);
pub const TEC_NO_DELEGATE_PERMISSION:          TxResult = TxResult(198);

// ── Token lookup ─────────────────────────────────────────────────────────────

/// Human-readable message for a TER code (matches rippled's transToken).
pub fn code_to_message(code: i32) -> &'static str {
    if code == 0 { return "The transaction was applied. Only final in a validated ledger."; }
    if code >= 100 { return "The transaction failed but consumed the fee."; }
    if (-99..0).contains(&code) { return "The transaction may be retried."; }
    if (-199..-100).contains(&code) { return "A required field was missing or invalid."; }
    if (-299..-200).contains(&code) { return "The transaction was malformed."; }
    if (-399..-300).contains(&code) { return "A local error occurred."; }
    "Unknown result."
}

fn code_to_token(code: i32) -> &'static str {
    match code {
        // tes
        0 => "tesSUCCESS",

        // tel
        -399 => "telLOCAL_ERROR",
        -398 => "telBAD_DOMAIN",
        -397 => "telBAD_PATH_COUNT",
        -396 => "telBAD_PUBLIC_KEY",
        -395 => "telFAILED_PROCESSING",
        -394 => "telINSUF_FEE_P",
        -393 => "telNO_DST_PARTIAL",
        -392 => "telCAN_NOT_QUEUE",
        -391 => "telCAN_NOT_QUEUE_BALANCE",
        -390 => "telCAN_NOT_QUEUE_BLOCKS",
        -389 => "telCAN_NOT_QUEUE_BLOCKED",
        -388 => "telCAN_NOT_QUEUE_FEE",
        -387 => "telCAN_NOT_QUEUE_FULL",
        -386 => "telWRONG_NETWORK",
        -385 => "telREQUIRES_NETWORK_ID",
        -384 => "telNETWORK_ID_MAKES_TX_NON_CANONICAL",
        -383 => "telENV_RPC_FAILED",

        // tem
        -299 => "temMALFORMED",
        -298 => "temBAD_AMOUNT",
        -297 => "temBAD_CURRENCY",
        -296 => "temBAD_EXPIRATION",
        -295 => "temBAD_FEE",
        -294 => "temBAD_ISSUER",
        -293 => "temBAD_LIMIT",
        -292 => "temBAD_OFFER",
        -291 => "temBAD_PATH",
        -290 => "temBAD_PATH_LOOP",
        -289 => "temBAD_REGKEY",
        -288 => "temBAD_SEND_XRP_LIMIT",
        -287 => "temBAD_SEND_XRP_MAX",
        -286 => "temBAD_SEND_XRP_NO_DIRECT",
        -285 => "temBAD_SEND_XRP_PARTIAL",
        -284 => "temBAD_SEND_XRP_PATHS",
        -283 => "temBAD_SEQUENCE",
        -282 => "temBAD_SIGNATURE",
        -281 => "temBAD_SRC_ACCOUNT",
        -280 => "temBAD_TRANSFER_RATE",
        -279 => "temDST_IS_SRC",
        -278 => "temDST_NEEDED",
        -277 => "temINVALID",
        -276 => "temINVALID_FLAG",
        -275 => "temREDUNDANT",
        -274 => "temRIPPLE_EMPTY",
        -273 => "temDISABLED",
        -272 => "temBAD_SIGNER",
        -271 => "temBAD_QUORUM",
        -270 => "temBAD_WEIGHT",
        -269 => "temBAD_TICK_SIZE",
        -268 => "temINVALID_ACCOUNT_ID",
        -267 => "temCANNOT_PREAUTH_SELF",
        -266 => "temINVALID_COUNT",
        -265 => "temUNCERTAIN",
        -264 => "temUNKNOWN",
        -263 => "temSEQ_AND_TICKET",
        -262 => "temBAD_NFTOKEN_TRANSFER_FEE",
        -261 => "temBAD_AMM_TOKENS",
        -260 => "temXCHAIN_EQUAL_DOOR_ACCOUNTS",
        -259 => "temXCHAIN_BAD_PROOF",
        -258 => "temXCHAIN_BRIDGE_BAD_ISSUES",
        -257 => "temXCHAIN_BRIDGE_NONDOOR_OWNER",
        -256 => "temXCHAIN_BRIDGE_BAD_MIN_ACCOUNT_CREATE_AMOUNT",
        -255 => "temXCHAIN_BRIDGE_BAD_REWARD_AMOUNT",
        -254 => "temEMPTY_DID",
        -253 => "temARRAY_EMPTY",
        -252 => "temARRAY_TOO_LARGE",
        -251 => "temBAD_TRANSFER_FEE",
        -250 => "temINVALID_INNER_BATCH",

        // tef
        -199 => "tefFAILURE",
        -198 => "tefALREADY",
        -197 => "tefBAD_ADD_AUTH",
        -196 => "tefBAD_AUTH",
        -195 => "tefBAD_LEDGER",
        -194 => "tefCREATED",
        -193 => "tefEXCEPTION",
        -192 => "tefINTERNAL",
        -191 => "tefNO_AUTH_REQUIRED",
        -190 => "tefPAST_SEQ",
        -189 => "tefWRONG_PRIOR",
        -188 => "tefMASTER_DISABLED",
        -187 => "tefMAX_LEDGER",
        -186 => "tefBAD_SIGNATURE",
        -185 => "tefBAD_QUORUM",
        -184 => "tefNOT_MULTI_SIGNING",
        -183 => "tefBAD_AUTH_MASTER",
        -182 => "tefINVARIANT_FAILED",
        -181 => "tefTOO_BIG",
        -180 => "tefNO_TICKET",
        -179 => "tefNFTOKEN_IS_NOT_TRANSFERABLE",
        -178 => "tefINVALID_LEDGER_FIX_TYPE",

        // ter
        -99 => "terRETRY",
        -98 => "terFUNDS_SPENT",
        -97 => "terINSUF_FEE_B",
        -96 => "terNO_ACCOUNT",
        -95 => "terNO_AUTH",
        -94 => "terNO_LINE",
        -93 => "terOWNERS",
        -92 => "terPRE_SEQ",
        -91 => "terLAST",
        -90 => "terNO_RIPPLE",
        -89 => "terQUEUED",
        -88 => "terPRE_TICKET",
        -87 => "terNO_AMM",
        -86 => "terADDRESS_COLLISION",
        -85 => "terNO_DELEGATE_PERMISSION",

        // tec
        100 => "tecCLAIM",
        101 => "tecPATH_PARTIAL",
        102 => "tecUNFUNDED_ADD",
        103 => "tecUNFUNDED_OFFER",
        104 => "tecUNFUNDED_PAYMENT",
        105 => "tecFAILED_PROCESSING",
        121 => "tecDIR_FULL",
        122 => "tecINSUF_RESERVE_LINE",
        123 => "tecINSUF_RESERVE_OFFER",
        124 => "tecNO_DST",
        125 => "tecNO_DST_INSUF_XRP",
        126 => "tecNO_LINE_INSUF_RESERVE",
        127 => "tecNO_LINE_REDUNDANT",
        128 => "tecPATH_DRY",
        129 => "tecUNFUNDED",
        130 => "tecNO_ALTERNATIVE_KEY",
        131 => "tecNO_REGULAR_KEY",
        132 => "tecOWNERS",
        133 => "tecNO_ISSUER",
        134 => "tecNO_AUTH",
        135 => "tecNO_LINE",
        136 => "tecINSUFF_FEE",
        137 => "tecFROZEN",
        138 => "tecNO_TARGET",
        139 => "tecNO_PERMISSION",
        140 => "tecNO_ENTRY",
        141 => "tecINSUFFICIENT_RESERVE",
        142 => "tecNEED_MASTER_KEY",
        143 => "tecDST_TAG_NEEDED",
        144 => "tecINTERNAL",
        145 => "tecOVERSIZE",
        146 => "tecCRYPTOCONDITION_ERROR",
        147 => "tecINVARIANT_FAILED",
        148 => "tecEXPIRED",
        149 => "tecDUPLICATE",
        150 => "tecKILLED",
        151 => "tecHAS_OBLIGATIONS",
        152 => "tecTOO_SOON",
        153 => "tecHOOK_REJECTED",
        154 => "tecMAX_SEQUENCE_REACHED",
        155 => "tecNO_SUITABLE_NFTOKEN_PAGE",
        156 => "tecNFTOKEN_BUY_SELL_MISMATCH",
        157 => "tecNFTOKEN_OFFER_TYPE_MISMATCH",
        158 => "tecCANT_ACCEPT_OWN_NFTOKEN_OFFER",
        159 => "tecINSUFFICIENT_FUNDS",
        160 => "tecOBJECT_NOT_FOUND",
        161 => "tecINSUFFICIENT_PAYMENT",
        162 => "tecUNFUNDED_AMM",
        163 => "tecAMM_BALANCE",
        164 => "tecAMM_FAILED",
        165 => "tecAMM_INVALID_TOKENS",
        166 => "tecAMM_EMPTY",
        167 => "tecAMM_NOT_EMPTY",
        168 => "tecAMM_ACCOUNT",
        169 => "tecINCOMPLETE",
        170 => "tecXCHAIN_BAD_TRANSFER_ISSUE",
        171 => "tecXCHAIN_NO_CLAIM_ID",
        172 => "tecXCHAIN_BAD_CLAIM_ID",
        173 => "tecXCHAIN_CLAIM_NO_QUORUM",
        174 => "tecXCHAIN_PROOF_UNKNOWN_KEY",
        175 => "tecXCHAIN_CREATE_ACCOUNT_NONXRP_ISSUE",
        176 => "tecXCHAIN_WRONG_CHAIN",
        177 => "tecXCHAIN_REWARD_MISMATCH",
        178 => "tecXCHAIN_NO_SIGNERS_LIST",
        179 => "tecXCHAIN_SENDING_ACCOUNT_MISMATCH",
        180 => "tecXCHAIN_INSUFF_CREATE_AMOUNT",
        181 => "tecXCHAIN_ACCOUNT_CREATE_PAST",
        182 => "tecXCHAIN_ACCOUNT_CREATE_TOO_MANY",
        183 => "tecXCHAIN_PAYMENT_FAILED",
        184 => "tecXCHAIN_SELF_COMMIT",
        185 => "tecXCHAIN_BAD_PUBLIC_KEY_ACCOUNT_PAIR",
        186 => "tecXCHAIN_CREATE_ACCOUNT_DISABLED",
        187 => "tecEMPTY_DID",
        188 => "tecINVALID_UPDATE_TIME",
        189 => "tecTOKEN_PAIR_NOT_FOUND",
        190 => "tecARRAY_EMPTY",
        191 => "tecARRAY_TOO_LARGE",
        192 => "tecLOCKED",
        193 => "tecBAD_CREDENTIALS",
        194 => "tecWRONG_ASSET",
        195 => "tecLIMIT_EXCEEDED",
        196 => "tecPSEUDO_ACCOUNT",
        197 => "tecPRECISION_LOSS",
        198 => "tecNO_DELEGATE_PERMISSION",

        _ => "telUNKNOWN",
    }
}

/// Look up a TxResult by its token string. Returns `None` for unknown tokens.
pub fn token_to_code(token: &str) -> Option<TxResult> {
    // Linear scan is fine — this is only used for parsing, not hot paths.
    for code in -399..=198 {
        let r = TxResult(code);
        let t = r.token();
        if t != "telUNKNOWN" && t == token {
            return Some(r);
        }
    }
    None
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_ranges() {
        // tes
        assert!(TES_SUCCESS.is_tes_success());
        assert!(!TES_SUCCESS.is_tec_claim());
        assert!(!TES_SUCCESS.is_ter_retry());
        assert!(!TES_SUCCESS.is_tef_failure());
        assert!(!TES_SUCCESS.is_tem_malformed());
        assert!(!TES_SUCCESS.is_tel_local());

        // tec
        assert!(TEC_CLAIM.is_tec_claim());
        assert!(TEC_NO_DELEGATE_PERMISSION.is_tec_claim());
        assert!(!TEC_CLAIM.is_tes_success());
        assert!(!TEC_CLAIM.is_ter_retry());

        // ter
        assert!(TER_RETRY.is_ter_retry());
        assert!(TER_NO_ACCOUNT.is_ter_retry());
        assert!(TER_PRE_SEQ.is_ter_retry());
        assert!(!TER_RETRY.is_tef_failure());

        // tef
        assert!(TEF_FAILURE.is_tef_failure());
        assert!(TEF_PAST_SEQ.is_tef_failure());
        assert!(!TEF_FAILURE.is_ter_retry());

        // tem
        assert!(TEM_MALFORMED.is_tem_malformed());
        assert!(TEM_BAD_SIGNATURE.is_tem_malformed());
        assert!(!TEM_MALFORMED.is_tef_failure());

        // tel
        assert!(TEL_LOCAL_ERROR.is_tel_local());
        assert!(TEL_WRONG_NETWORK.is_tel_local());
        assert!(!TEL_LOCAL_ERROR.is_tem_malformed());
    }

    #[test]
    fn permanent_failure() {
        assert!(TEF_FAILURE.is_permanent_failure());
        assert!(TEM_MALFORMED.is_permanent_failure());
        assert!(TEL_LOCAL_ERROR.is_permanent_failure());
        assert!(!TES_SUCCESS.is_permanent_failure());
        assert!(!TEC_CLAIM.is_permanent_failure());
        assert!(!TER_RETRY.is_permanent_failure());
    }

    #[test]
    fn claim_hard_fail_with_retry_flag() {
        let retry = ApplyFlags::RETRY;
        let none = ApplyFlags::NONE;

        // tec with RETRY flag → soft fail (NOT hard fail)
        assert!(!TEC_CLAIM.is_tec_claim_hard_fail(retry));
        assert!(!TEC_PATH_DRY.is_tec_claim_hard_fail(retry));

        // tec without RETRY flag → hard fail (fee claimed)
        assert!(TEC_CLAIM.is_tec_claim_hard_fail(none));
        assert!(TEC_PATH_DRY.is_tec_claim_hard_fail(none));

        // non-tec codes → never hard fail regardless of flags
        assert!(!TES_SUCCESS.is_tec_claim_hard_fail(none));
        assert!(!TER_RETRY.is_tec_claim_hard_fail(none));
        assert!(!TEF_FAILURE.is_tec_claim_hard_fail(none));
    }

    #[test]
    fn likely_to_claim_fee() {
        let retry = ApplyFlags::RETRY;
        let none = ApplyFlags::NONE;

        // tesSUCCESS always claims fee
        assert!(TES_SUCCESS.likely_to_claim_fee(retry));
        assert!(TES_SUCCESS.likely_to_claim_fee(none));

        // tec without RETRY → claims fee
        assert!(TEC_CLAIM.likely_to_claim_fee(none));

        // tec with RETRY → does NOT claim fee (soft fail)
        assert!(!TEC_CLAIM.likely_to_claim_fee(retry));

        // ter/tef/tem/tel never claim fee
        assert!(!TER_NO_ACCOUNT.likely_to_claim_fee(none));
        assert!(!TEF_FAILURE.likely_to_claim_fee(none));
        assert!(!TEM_MALFORMED.likely_to_claim_fee(none));
        assert!(!TEL_LOCAL_ERROR.likely_to_claim_fee(none));
    }

    #[test]
    fn token_roundtrip() {
        assert_eq!(TES_SUCCESS.token(), "tesSUCCESS");
        assert_eq!(TEC_PATH_DRY.token(), "tecPATH_DRY");
        assert_eq!(TER_NO_ACCOUNT.token(), "terNO_ACCOUNT");
        assert_eq!(TEF_PAST_SEQ.token(), "tefPAST_SEQ");
        assert_eq!(TEM_BAD_SIGNATURE.token(), "temBAD_SIGNATURE");
        assert_eq!(TEL_WRONG_NETWORK.token(), "telWRONG_NETWORK");

        // roundtrip
        assert_eq!(token_to_code("tesSUCCESS"), Some(TES_SUCCESS));
        assert_eq!(token_to_code("tecPATH_DRY"), Some(TEC_PATH_DRY));
        assert_eq!(token_to_code("terNO_ACCOUNT"), Some(TER_NO_ACCOUNT));
        assert_eq!(token_to_code("nonsense"), None);
    }

    #[test]
    fn code_values_match_rippled() {
        // Verify specific numeric values match rippled's TER.h
        assert_eq!(TES_SUCCESS.code(), 0);
        assert_eq!(TEC_CLAIM.code(), 100);
        assert_eq!(TEC_PATH_PARTIAL.code(), 101);
        assert_eq!(TEC_DIR_FULL.code(), 121);  // gap at 106-120
        assert_eq!(TEC_NO_DST.code(), 124);
        assert_eq!(TEC_OVERSIZE.code(), 145);
        assert_eq!(TEC_KILLED.code(), 150);
        assert_eq!(TEC_EXPIRED.code(), 148);
        assert_eq!(TEC_INCOMPLETE.code(), 169);
        assert_eq!(TER_RETRY.code(), -99);
        assert_eq!(TER_NO_ACCOUNT.code(), -96);
        assert_eq!(TER_PRE_SEQ.code(), -92);
        assert_eq!(TEF_FAILURE.code(), -199);
        assert_eq!(TEF_PAST_SEQ.code(), -190);
        assert_eq!(TEF_INVARIANT_FAILED.code(), -182);
        assert_eq!(TEM_MALFORMED.code(), -299);
        assert_eq!(TEM_BAD_SIGNATURE.code(), -282);
        assert_eq!(TEL_LOCAL_ERROR.code(), -399);
    }
}
