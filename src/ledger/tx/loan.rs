//! Loan — LoanBrokerSet (74), LoanBrokerDelete (75), LoanBrokerCoverDeposit (76),
//!        LoanBrokerCoverWithdraw (77), LoanBrokerCoverClawback (78),
//!        LoanSet (80), LoanDelete (81), LoanManage (82), LoanPay (84).
//!
//! LoanBrokerSet (create) creates a pseudo-account + LoanBroker SLE.
//! LoanBrokerDelete removes them.
//! LoanSet creates a Loan SLE.
//! LoanDelete removes a Loan SLE.
//! Other types modify existing SLEs (balances, status flags).
//!
//! SHAMap keys:
//!   LoanBroker: SHA-512-half(0x006C || owner || sequence)
//!     namespace 'l' = 0x6C
//!   Loan: SHA-512-half(0x004C || loanBrokerID || loanSequence)
//!     namespace 'L' = 0x4C
//!
//! (rippled: LoanBrokerSet.cpp, LoanBrokerDelete.cpp,
//!  LoanBrokerCoverDeposit.cpp, LoanBrokerCoverWithdraw.cpp,
//!  LoanBrokerCoverClawback.cpp, LoanSet.cpp, LoanDelete.cpp,
//!  LoanManage.cpp, LoanPay.cpp)

use crate::crypto::{ripemd160, sha256, sha512_first_half};
use crate::ledger::tx::TxContext;
use crate::ledger::{directory, AccountRoot, Key, LedgerState};
use crate::transaction::amount::{Amount, Issue};
use crate::transaction::ParsedTx;

use super::ApplyResult;

/// LedgerNameSpace::LOAN_BROKER = 'l' = 0x6C.
const LOAN_BROKER_SPACE: [u8; 2] = [0x00, 0x6C];

/// LoanBroker entry type (ltLOAN_BROKER = 0x0088).
const LT_LOAN_BROKER: u16 = 0x0088;

/// Account flags for pseudo-accounts (same as vault).
const LSF_DISABLE_MASTER: u32 = 0x00100000;
const LSF_DEFAULT_RIPPLE: u32 = 0x00800000;
const LSF_DEPOSIT_AUTH: u32 = 0x01000000;
const LSF_LOAN_DEFAULT: u32 = 0x00010000;
const LSF_LOAN_IMPAIRED: u32 = 0x00020000;
const TF_LOAN_DEFAULT: u32 = 0x00010000;
const TF_LOAN_IMPAIR: u32 = 0x00020000;
const TF_LOAN_UNIMPAIR: u32 = 0x00040000;
const LOAN_MANAGE_FLAGS: u32 = TF_LOAN_DEFAULT | TF_LOAN_IMPAIR | TF_LOAN_UNIMPAIR;
const SF_FLAGS: u16 = 2;
const SF_OWNER_COUNT: u16 = 13;
const SF_DEBT_TOTAL: u16 = 6;
const SF_COVER_AVAILABLE: u16 = 8;
const SF_PRINCIPAL_OUTSTANDING: u16 = 13;
const SF_TOTAL_VALUE_OUTSTANDING: u16 = 15;
const SF_MANAGEMENT_FEE_OUTSTANDING: u16 = 17;
const SF_LOSS_UNREALIZED: u16 = 5;
const SF_ASSETS_TOTAL: u16 = 4;
const SF_ASSETS_AVAILABLE: u16 = 2;
const SF_COVER_RATE_MINIMUM: u16 = 62;
const SF_COVER_RATE_LIQUIDATION: u16 = 63;
const SF_PAYMENT_REMAINING: u16 = 59;
const SF_NEXT_PAYMENT_DUE_DATE: u16 = 58;
const SF_LOAN_BROKER_ID: u16 = 37;
const SF_LOAN_BROKER_NODE: u16 = 31;
const SF_BORROWER: u16 = 25;
const SF_START_DATE: u16 = 54;
const SF_PAYMENT_INTERVAL: u16 = 55;
const SF_GRACE_PERIOD: u16 = 56;
const SF_PREVIOUS_PAYMENT_DUE_DATE: u16 = 57;
const DEFAULT_PAYMENT_INTERVAL: u32 = 60;
const DEFAULT_GRACE_PERIOD: u32 = 60;

/// Compute the LoanBroker SHAMap key.
fn loan_broker_key(owner: &[u8; 20], sequence: u32) -> Key {
    let mut data = Vec::with_capacity(2 + 20 + 4);
    data.extend_from_slice(&LOAN_BROKER_SPACE);
    data.extend_from_slice(owner);
    data.extend_from_slice(&sequence.to_be_bytes());
    Key(sha512_first_half(&data))
}

/// Derive a pseudo-account address (same algorithm as vault).
fn pseudo_account_address(
    state: &LedgerState,
    parent_hash: &[u8; 32],
    owner_key: &[u8; 32],
) -> Option<[u8; 20]> {
    for i in 0u16..256 {
        let mut input = Vec::with_capacity(2 + 32 + 32);
        input.extend_from_slice(&i.to_be_bytes());
        input.extend_from_slice(parent_hash);
        input.extend_from_slice(owner_key);
        let hash = sha512_first_half(&input);
        let addr = ripemd160(&sha256(&hash));
        if state.get_account(&addr).is_none() {
            return Some(addr);
        }
    }
    None
}

/// Build a LoanBroker SLE.
fn build_loan_broker_sle(
    owner: &[u8; 20],
    pseudo_account: &[u8; 20],
    vault_id: &[u8; 32],
    sequence: u32,
    owner_node: u64,
    vault_node: u64,
) -> Vec<u8> {
    use crate::ledger::meta::ParsedField;
    crate::ledger::meta::build_sle(
        LT_LOAN_BROKER,
        &[
            // sfOwner (ACCOUNT=8, field=2)
            ParsedField {
                type_code: 8,
                field_code: 2,
                data: owner.to_vec(),
            },
            // sfAccount (ACCOUNT=8, field=1) — pseudo-account
            ParsedField {
                type_code: 8,
                field_code: 1,
                data: pseudo_account.to_vec(),
            },
            // sfSequence (UINT32=2, field=4)
            ParsedField {
                type_code: 2,
                field_code: 4,
                data: sequence.to_be_bytes().to_vec(),
            },
            // sfFlags (UINT32=2, field=2)
            ParsedField {
                type_code: 2,
                field_code: 2,
                data: 0u32.to_be_bytes().to_vec(),
            },
            // sfOwnerNode (UINT64=3, field=4)
            ParsedField {
                type_code: 3,
                field_code: 4,
                data: owner_node.to_be_bytes().to_vec(),
            },
            // sfVaultNode (UINT64=3, field=30)
            ParsedField {
                type_code: 3,
                field_code: 30,
                data: vault_node.to_be_bytes().to_vec(),
            },
            // sfVaultID (HASH256=5, field=35)
            ParsedField {
                type_code: 5,
                field_code: 35,
                data: vault_id.to_vec(),
            },
            // sfLoanSequence (UINT32=2, field=61) — starts at 1
            ParsedField {
                type_code: 2,
                field_code: 61,
                data: 1u32.to_be_bytes().to_vec(),
            },
            // sfOwnerCount (UINT32=2, field=13) — outstanding Loan objects.
            ParsedField {
                type_code: 2,
                field_code: SF_OWNER_COUNT,
                data: 0u32.to_be_bytes().to_vec(),
            },
            // sfDebtTotal (NUMBER=9, field=6) — 0 initially
            ParsedField {
                type_code: 9,
                field_code: SF_DEBT_TOTAL,
                data: 0i64.to_be_bytes().to_vec(),
            },
            // sfDebtMaximum (NUMBER=9, field=7) — 0 = unlimited
            ParsedField {
                type_code: 9,
                field_code: 7,
                data: 0i64.to_be_bytes().to_vec(),
            },
            // sfCoverAvailable (NUMBER=9, field=8) — 0 initially
            ParsedField {
                type_code: 9,
                field_code: SF_COVER_AVAILABLE,
                data: 0i64.to_be_bytes().to_vec(),
            },
        ],
        None,
        None,
    )
}

/// Extract sfOwner from a LoanBroker SLE.
fn broker_sle_owner(raw: &[u8]) -> Option<[u8; 20]> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    for field in &parsed.fields {
        if field.type_code == 8 && field.field_code == 2 && field.data.len() == 20 {
            let mut id = [0u8; 20];
            id.copy_from_slice(&field.data);
            return Some(id);
        }
    }
    None
}

/// Extract sfAccount (pseudo-account) from a LoanBroker SLE.
fn broker_sle_pseudo_id(raw: &[u8]) -> Option<[u8; 20]> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    for field in &parsed.fields {
        if field.type_code == 8 && field.field_code == 1 && field.data.len() == 20 {
            let mut id = [0u8; 20];
            id.copy_from_slice(&field.data);
            return Some(id);
        }
    }
    None
}

// ── Transaction handlers ─────────────────────────────────────────────────────

/// Type 74: LoanBrokerSet — create a new loan broker.
///
/// Creates: LoanBroker SLE, pseudo-account, directory linkage.
/// owner_count += 2.
///
/// (rippled: LoanBrokerSet.cpp — doApply, create path)
pub(crate) fn apply_loan_broker_set(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
) -> ApplyResult {
    let sequence = super::sequence_proxy(tx);
    // 1. Validate VaultID exists
    let vault_id = match tx.vault_id {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let vault_key = Key(vault_id);
    let vault_raw = match state.get_raw(&vault_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    let vault_pseudo = match super::vault::vault_sle_pseudo_id(&vault_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 2. Compute broker key
    let bkey = loan_broker_key(&tx.account, sequence);

    // 3. Derive pseudo-account
    let pseudo_id = match pseudo_account_address(state, &ctx.parent_hash, &bkey.0) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("terADDRESS_COLLISION"),
    };

    // 4. Add broker to owner's directory
    let owner_node = directory::dir_add(state, &tx.account, bkey.0);

    // 5. Create pseudo-account
    state.insert_account(AccountRoot {
        account_id: pseudo_id,
        balance: 0,
        sequence: 0,
        owner_count: 0,
        flags: LSF_DISABLE_MASTER | LSF_DEFAULT_RIPPLE | LSF_DEPOSIT_AUTH,
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

    // 6. Add broker to vault pseudo-account's directory.
    let vault_node = directory::dir_add(state, &vault_pseudo, bkey.0);

    // 7. Create LoanBroker SLE
    let broker_sle = build_loan_broker_sle(
        &tx.account,
        &pseudo_id,
        &vault_id,
        sequence,
        owner_node,
        vault_node,
    );
    state.insert_raw(bkey, broker_sle);

    // 8. Update sender: owner_count += 2
    if let Some(sender) = state.get_account(&tx.account) {
        let mut sender = sender.clone();
        sender.owner_count += 2;
        state.insert_account(sender);
    }

    ApplyResult::Success
}

/// Type 75: LoanBrokerDelete — delete a loan broker.
///
/// Validates: caller == owner, no active loans (ownerCount on pseudo == 0).
/// Removes: broker SLE, pseudo-account. owner_count -= 2.
///
/// (rippled: LoanBrokerDelete.cpp — doApply)
pub(crate) fn apply_loan_broker_delete(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    // 1. Find broker SLE
    let broker_key = match tx_loan_broker_id(tx) {
        Some(id) => Key(id),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let broker_raw = match state.get_raw(&broker_key) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };

    // 2. Verify caller is owner
    let owner = match broker_sle_owner(&broker_raw) {
        Some(o) => o,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    if owner != tx.account {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    // 3. Extract pseudo-account
    let pseudo_id = match broker_sle_pseudo_id(&broker_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 4. Check broker has no active loans. rippled tracks outstanding loans on
    // the LoanBroker SLE's sfOwnerCount, distinct from the pseudo-account root.
    if sle_uint32(&broker_raw, SF_OWNER_COUNT) != 0 {
        return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
    }
    let cover_available = loan_sle_number(&broker_raw, SF_COVER_AVAILABLE).max(0) as u64;
    if let Some(pa) = state.get_account(&pseudo_id) {
        if pa.balance != cover_available || pa.owner_count > 0 {
            return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
        }
    }

    // 5. Remove from owner directory
    directory::dir_remove(state, &tx.account, &broker_key.0);
    if let Some(vault_id) = broker_sle_vault_id(&broker_raw) {
        if let Some(vault_raw) = state.get_raw(&Key(vault_id)).map(|raw| raw.to_vec()) {
            if let Some(vault_pseudo) = super::vault::vault_sle_pseudo_id(&vault_raw) {
                directory::dir_remove(state, &vault_pseudo, &broker_key.0);
            }
        }
    }

    // 6. Return remaining cover for the local XRP model, then remove
    // pseudo-account.
    if cover_available > 0 {
        if let Err(code) =
            transfer_xrp_between_accounts(state, &pseudo_id, &tx.account, cover_available)
        {
            return ApplyResult::ClaimedCost(code);
        }
    }
    state.remove_account(&pseudo_id);

    // 7. Remove broker SLE
    state.remove_raw(&broker_key);

    // 8. Decrement owner_count by 2
    if let Some(sender) = state.get_account(&tx.account) {
        let mut sender = sender.clone();
        sender.owner_count = sender.owner_count.saturating_sub(2);
        state.insert_account(sender);
    }

    ApplyResult::Success
}

/// LedgerNameSpace::LOAN = 'L' = 0x4C.
const LOAN_SPACE: [u8; 2] = [0x00, 0x4C];

/// Loan entry type (ltLOAN = 0x0089).
const LT_LOAN: u16 = 0x0089;

/// Compute the Loan SHAMap key.
fn loan_key(broker_key: &[u8; 32], loan_seq: u32) -> Key {
    let mut data = Vec::with_capacity(2 + 32 + 4);
    data.extend_from_slice(&LOAN_SPACE);
    data.extend_from_slice(broker_key);
    data.extend_from_slice(&loan_seq.to_be_bytes());
    Key(sha512_first_half(&data))
}

fn tx_loan_broker_id(tx: &ParsedTx) -> Option<[u8; 32]> {
    tx.loan_broker_id.or(tx.vault_id)
}

fn tx_loan_id(tx: &ParsedTx) -> Option<[u8; 32]> {
    tx.loan_id.or(tx.vault_id)
}

/// Extract a UInt32 field from a parsed SLE.
fn sle_uint32(raw: &[u8], target_field: u16) -> u32 {
    let parsed = match crate::ledger::meta::parse_sle(raw) {
        Some(p) => p,
        None => return 0,
    };
    for field in &parsed.fields {
        if field.type_code == 2 && field.field_code == target_field && field.data.len() == 4 {
            return u32::from_be_bytes(field.data[..4].try_into().unwrap());
        }
    }
    0
}

/// Extract sfVaultID from a broker SLE.
fn broker_sle_vault_id(raw: &[u8]) -> Option<[u8; 32]> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    for field in &parsed.fields {
        if field.type_code == 5 && field.field_code == 35 && field.data.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&field.data);
            return Some(id);
        }
    }
    None
}

/// Build a Loan SLE.
fn build_loan_sle(
    borrower: &[u8; 20],
    broker_key: &[u8; 32],
    loan_seq: u32,
    principal: u64,
    owner_node: u64,
    loan_broker_node: u64,
    start_date: u32,
) -> Vec<u8> {
    use crate::ledger::meta::ParsedField;
    crate::ledger::meta::build_sle(
        LT_LOAN,
        &[
            // sfBorrower (ACCOUNT=8, field=25)
            ParsedField {
                type_code: 8,
                field_code: SF_BORROWER,
                data: borrower.to_vec(),
            },
            // sfLoanBrokerID (HASH256=5, field=37)
            ParsedField {
                type_code: 5,
                field_code: SF_LOAN_BROKER_ID,
                data: broker_key.to_vec(),
            },
            // sfFlags (UINT32=2, field=2)
            ParsedField {
                type_code: 2,
                field_code: SF_FLAGS,
                data: 0u32.to_be_bytes().to_vec(),
            },
            // sfLoanSequence (UINT32=2, field=61)
            ParsedField {
                type_code: 2,
                field_code: 61,
                data: loan_seq.to_be_bytes().to_vec(),
            },
            // sfOwnerNode (UINT64=3, field=4)
            ParsedField {
                type_code: 3,
                field_code: 4,
                data: owner_node.to_be_bytes().to_vec(),
            },
            // sfLoanBrokerNode (UINT64=3, field=31)
            ParsedField {
                type_code: 3,
                field_code: SF_LOAN_BROKER_NODE,
                data: loan_broker_node.to_be_bytes().to_vec(),
            },
            // sfPrincipalOutstanding (NUMBER=9, field=13)
            ParsedField {
                type_code: 9,
                field_code: SF_PRINCIPAL_OUTSTANDING,
                data: (principal as i64).to_be_bytes().to_vec(),
            },
            // sfTotalValueOutstanding (NUMBER=9, field=15)
            ParsedField {
                type_code: 9,
                field_code: SF_TOTAL_VALUE_OUTSTANDING,
                data: (principal as i64).to_be_bytes().to_vec(),
            },
            // sfManagementFeeOutstanding (NUMBER=9, field=17)
            ParsedField {
                type_code: 9,
                field_code: SF_MANAGEMENT_FEE_OUTSTANDING,
                data: 0i64.to_be_bytes().to_vec(),
            },
            // sfPaymentRemaining (UINT32=2, field=59)
            ParsedField {
                type_code: 2,
                field_code: SF_PAYMENT_REMAINING,
                data: 1u32.to_be_bytes().to_vec(),
            },
            // sfStartDate (UINT32=2, field=54)
            ParsedField {
                type_code: 2,
                field_code: SF_START_DATE,
                data: start_date.to_be_bytes().to_vec(),
            },
            // sfPaymentInterval (UINT32=2, field=55)
            ParsedField {
                type_code: 2,
                field_code: SF_PAYMENT_INTERVAL,
                data: DEFAULT_PAYMENT_INTERVAL.to_be_bytes().to_vec(),
            },
            // sfGracePeriod (UINT32=2, field=56)
            ParsedField {
                type_code: 2,
                field_code: SF_GRACE_PERIOD,
                data: DEFAULT_GRACE_PERIOD.to_be_bytes().to_vec(),
            },
            // sfPreviousPaymentDueDate (UINT32=2, field=57)
            ParsedField {
                type_code: 2,
                field_code: SF_PREVIOUS_PAYMENT_DUE_DATE,
                data: 0u32.to_be_bytes().to_vec(),
            },
            // sfNextPaymentDueDate (UINT32=2, field=58)
            ParsedField {
                type_code: 2,
                field_code: SF_NEXT_PAYMENT_DUE_DATE,
                data: start_date
                    .saturating_add(DEFAULT_PAYMENT_INTERVAL)
                    .to_be_bytes()
                    .to_vec(),
            },
        ],
        None,
        None,
    )
}

/// Type 80: LoanSet — create a new loan.
///
/// Simplified flow for XRP vaults:
/// 1. Validate broker exists and has a vault
/// 2. Get loan sequence from broker, create Loan SLE
/// 3. Transfer principal from vault pseudo-account to borrower
/// 4. Update broker state (loan_sequence++, debt_total += principal)
/// 5. Update vault (assets_available -= principal)
/// 6. Directory linkage, owner_count effects
///
/// (rippled: LoanSet.cpp — doApply)
pub(crate) fn apply_loan_set(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
) -> ApplyResult {
    // 1. Find broker
    let broker_key = match tx_loan_broker_id(tx) {
        Some(id) => Key(id),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let broker_raw = match state.get_raw(&broker_key) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };

    // 2. Get vault from broker
    let vault_id = match broker_sle_vault_id(&broker_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let vault_key = Key(vault_id);
    let vault_raw = match state.get_raw(&vault_key) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 3. Get vault pseudo-account
    let vault_pseudo = match super::vault::vault_sle_pseudo_id(&vault_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let vault_asset = sle_issue(&vault_raw, 3).unwrap_or(Issue::Xrp);
    let principal = match xrp_amount_matching_vault(tx, &vault_asset) {
        Ok(drops) => drops,
        Err(code) => return ApplyResult::ClaimedCost(code),
    };

    // 4. Check vault has sufficient available assets
    let assets_avail = {
        let parsed = crate::ledger::meta::parse_sle(&vault_raw);
        parsed
            .and_then(|p| {
                p.fields
                    .iter()
                    .find(|f| f.type_code == 9 && f.field_code == 2)
                    .and_then(|f| {
                        (f.data.len() == 8)
                            .then(|| i64::from_be_bytes(f.data[..8].try_into().unwrap()))
                    })
            })
            .unwrap_or(0)
    };
    if (assets_avail as u64) < principal {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
    }

    // 5. Get loan sequence and pseudo-account from broker (before patching)
    let loan_seq = sle_uint32(&broker_raw, 61); // sfLoanSequence
    let broker_pseudo = match broker_sle_pseudo_id(&broker_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 6. Create Loan SLE
    let lkey = loan_key(&broker_key.0, loan_seq);
    let owner_node = directory::dir_add(state, &tx.account, lkey.0);
    let loan_broker_node = directory::dir_add(state, &broker_pseudo, lkey.0);
    let loan_sle = build_loan_sle(
        &tx.account,
        &broker_key.0,
        loan_seq,
        principal,
        owner_node,
        loan_broker_node,
        ctx.close_time as u32,
    );
    state.insert_raw(lkey, loan_sle);

    // 7. Transfer principal from vault pseudo-account to borrower
    if let Some(pa) = state.get_account(&vault_pseudo) {
        let mut pa = pa.clone();
        pa.balance = pa.balance.saturating_sub(principal);
        state.insert_account(pa);
    }
    if let Some(borrower) = state.get_account(&tx.account) {
        let mut borrower = borrower.clone();
        borrower.balance += principal;
        borrower.owner_count += 1; // borrower owns the loan
        state.insert_account(borrower);
    }

    // 8. Update broker: increment loan_sequence, add to debt_total
    let new_loan_seq = loan_seq + 1;
    let debt_total = loan_sle_number(&broker_raw, SF_DEBT_TOTAL);
    let owner_count = sle_uint32(&broker_raw, SF_OWNER_COUNT);
    let broker_raw = patch_uint32_field(&broker_raw, 61, new_loan_seq);
    let broker_raw = patch_number_field(&broker_raw, SF_DEBT_TOTAL, debt_total + principal as i64);
    let broker_raw = patch_uint32_field(&broker_raw, SF_OWNER_COUNT, owner_count + 1);
    state.insert_raw(broker_key, broker_raw);

    // 9. Update vault: assets_available -= principal
    let new_avail = assets_avail - principal as i64;
    let vault_raw = patch_number_field(&vault_raw, SF_ASSETS_AVAILABLE, new_avail);
    state.insert_raw(vault_key, vault_raw);

    ApplyResult::Success
}

/// Extract sfBorrower (ACCOUNT=8, field=1) from a Loan SLE.
fn loan_sle_borrower(raw: &[u8]) -> Option<[u8; 20]> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    for field in &parsed.fields {
        if field.type_code == 8
            && (field.field_code == SF_BORROWER || field.field_code == 1)
            && field.data.len() == 20
        {
            let mut id = [0u8; 20];
            id.copy_from_slice(&field.data);
            return Some(id);
        }
    }
    None
}

/// Extract sfLoanBrokerID (HASH256=5, field=37) from a Loan SLE.
fn loan_sle_broker_id(raw: &[u8]) -> Option<[u8; 32]> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    for field in &parsed.fields {
        if field.type_code == 5
            && (field.field_code == SF_LOAN_BROKER_ID || field.field_code == 36)
            && field.data.len() == 32
        {
            let mut id = [0u8; 32];
            id.copy_from_slice(&field.data);
            return Some(id);
        }
    }
    None
}

/// Extract a NUMBER field (type=9) from a parsed SLE.
fn loan_sle_number(raw: &[u8], target_field: u16) -> i64 {
    let parsed = match crate::ledger::meta::parse_sle(raw) {
        Some(p) => p,
        None => return 0,
    };
    for field in &parsed.fields {
        if field.type_code == 9 && field.field_code == target_field && field.data.len() == 8 {
            return i64::from_be_bytes(field.data[..8].try_into().unwrap());
        }
    }
    0
}

fn patch_number_field(raw: &[u8], field_code: u16, value: i64) -> Vec<u8> {
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 9,
            field_code,
            data: value.to_be_bytes().to_vec(),
        }],
        None,
        None,
        &[],
    )
}

fn patch_uint32_field(raw: &[u8], field_code: u16, value: u32) -> Vec<u8> {
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 2,
            field_code,
            data: value.to_be_bytes().to_vec(),
        }],
        None,
        None,
        &[],
    )
}

fn patch_flags(raw: &[u8], flags: u32) -> Vec<u8> {
    patch_uint32_field(raw, SF_FLAGS, flags)
}

fn vault_sle_number(raw: &[u8], field_code: u16) -> i64 {
    loan_sle_number(raw, field_code)
}

fn sle_issue(raw: &[u8], field_code: u16) -> Option<Issue> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    parsed
        .fields
        .iter()
        .find(|field| field.type_code == 24 && field.field_code == field_code)
        .and_then(|field| Issue::from_bytes(&field.data).map(|(issue, _)| issue))
}

fn amount_issue(amount: &Amount) -> Option<Issue> {
    match amount {
        Amount::Xrp(_) => Some(Issue::Xrp),
        Amount::Iou {
            currency, issuer, ..
        } => Some(Issue::Iou {
            currency: currency.clone(),
            issuer: *issuer,
        }),
        Amount::Mpt(_) => amount.mpt_parts().map(|(_, mptid)| Issue::Mpt(mptid)),
    }
}

fn xrp_amount_matching_vault(tx: &ParsedTx, vault_asset: &Issue) -> Result<u64, &'static str> {
    let amount = tx.amount.as_ref().ok_or("temBAD_AMOUNT")?;
    if amount_issue(amount).as_ref() != Some(vault_asset) {
        return Err("tecWRONG_ASSET");
    }
    match (amount, vault_asset) {
        (Amount::Xrp(drops), Issue::Xrp) if *drops > 0 => Ok(*drops),
        (Amount::Xrp(_), Issue::Xrp) => Err("temBAD_AMOUNT"),
        _ => Err("tecINCOMPLETE"),
    }
}

fn xrp_optional_claw_amount_matching_vault(
    tx: &ParsedTx,
    vault_asset: &Issue,
) -> Result<Option<u64>, &'static str> {
    let Some(amount) = tx.amount.as_ref() else {
        return Ok(None);
    };
    if amount_issue(amount).as_ref() != Some(vault_asset) {
        return Err("tecWRONG_ASSET");
    }
    match (amount, vault_asset) {
        (Amount::Xrp(_), Issue::Xrp) => Err("temBAD_AMOUNT"),
        _ => Err("tecINCOMPLETE"),
    }
}

fn min_cover_for_debt(debt_total: i64, cover_rate_minimum: u32) -> i64 {
    if debt_total <= 0 || cover_rate_minimum == 0 {
        return 0;
    }
    let numerator = debt_total as i128 * cover_rate_minimum as i128;
    ((numerator + 99_999) / 100_000) as i64
}

fn liquidation_cover_amount(
    minimum_cover: i64,
    cover_rate_liquidation: u32,
    total_default_amount: i64,
) -> i64 {
    if minimum_cover <= 0 || cover_rate_liquidation == 0 || total_default_amount <= 0 {
        return 0;
    }
    let numerator = minimum_cover as i128 * cover_rate_liquidation as i128;
    let liquidated = ((numerator + 99_999) / 100_000) as i64;
    liquidated.min(total_default_amount)
}

fn loan_owed_to_vault(loan_raw: &[u8]) -> i64 {
    (loan_sle_number(loan_raw, SF_TOTAL_VALUE_OUTSTANDING)
        - loan_sle_number(loan_raw, SF_MANAGEMENT_FEE_OUTSTANDING))
    .max(0)
}

fn loan_time_expired(close_time: u64, deadline: u32) -> bool {
    close_time >= deadline as u64
}

fn transfer_xrp_between_accounts(
    state: &mut LedgerState,
    from: &[u8; 20],
    to: &[u8; 20],
    drops: u64,
) -> Result<(), &'static str> {
    if drops == 0 {
        return Err("temBAD_AMOUNT");
    }
    let Some(from_acct) = state.get_account(from).cloned() else {
        return Err("tecNO_ACCOUNT");
    };
    if from_acct.balance < drops {
        return Err("tecINSUFFICIENT_FUNDS");
    }
    let Some(to_acct) = state.get_account(to).cloned() else {
        return Err("tecNO_DST");
    };

    let mut from_acct = from_acct;
    from_acct.balance -= drops;
    state.insert_account(from_acct);

    let mut to_acct = to_acct;
    to_acct.balance += drops;
    state.insert_account(to_acct);
    Ok(())
}

fn load_broker_and_vault(
    state: &LedgerState,
    broker_key: Key,
) -> Result<(Vec<u8>, Key, Vec<u8>, [u8; 20]), ApplyResult> {
    let broker_raw = state
        .get_raw(&broker_key)
        .map(|raw| raw.to_vec())
        .ok_or(ApplyResult::ClaimedCost("tecNO_ENTRY"))?;
    let vault_id =
        broker_sle_vault_id(&broker_raw).ok_or(ApplyResult::ClaimedCost("tecINTERNAL"))?;
    let vault_key = Key(vault_id);
    let vault_raw = state
        .get_raw(&vault_key)
        .map(|raw| raw.to_vec())
        .ok_or(ApplyResult::ClaimedCost("tecINTERNAL"))?;
    let broker_pseudo =
        broker_sle_pseudo_id(&broker_raw).ok_or(ApplyResult::ClaimedCost("tecINTERNAL"))?;
    Ok((broker_raw, vault_key, vault_raw, broker_pseudo))
}

/// Type 84: LoanPay — repay part or all of a loan.
///
/// Simplified XRP flow:
/// 1. Validate loan exists and caller is borrower
/// 2. Transfer repayment XRP from borrower to vault pseudo-account
/// 3. Reduce sfPrincipalOutstanding on loan
/// 4. Increase vault's sfAssetsAvailable
///
/// (rippled: LoanPay.cpp — doApply, simplified)
pub(crate) fn apply_loan_pay(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    // 1. Find the loan
    let loan_key_val = match tx_loan_id(tx) {
        Some(id) => Key(id),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let loan_raw = match state.get_raw(&loan_key_val) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };

    // 2. Verify caller is borrower
    let borrower = match loan_sle_borrower(&loan_raw) {
        Some(b) => b,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    if borrower != tx.account {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    // 3. Get repayment amount
    let repay_amount = match tx.amount_drops {
        Some(d) if d > 0 => d,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };

    // 4. Get current principal outstanding
    let principal_outstanding = loan_sle_number(&loan_raw, SF_PRINCIPAL_OUTSTANDING) as u64;
    if repay_amount > principal_outstanding {
        return ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED");
    }

    // 5. Get broker and vault to find pseudo-account
    let broker_id = match loan_sle_broker_id(&loan_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let broker_raw = match state.get_raw(&Key(broker_id)) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let vault_id = match broker_sle_vault_id(&broker_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let vault_raw = match state.get_raw(&Key(vault_id)) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let vault_pseudo = match super::vault::vault_sle_pseudo_id(&vault_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 6. Transfer XRP from borrower to vault pseudo-account
    if let Some(b) = state.get_account(&tx.account) {
        let mut b = b.clone();
        if b.balance < repay_amount {
            return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
        }
        b.balance -= repay_amount;
        state.insert_account(b);
    }
    if let Some(pa) = state.get_account(&vault_pseudo) {
        let mut pa = pa.clone();
        pa.balance += repay_amount;
        state.insert_account(pa);
    }

    // 7. Reduce principal outstanding on loan
    let new_principal = principal_outstanding - repay_amount;
    let loan_raw = patch_number_field(&loan_raw, SF_PRINCIPAL_OUTSTANDING, new_principal as i64);
    let total_value = loan_sle_number(&loan_raw, SF_TOTAL_VALUE_OUTSTANDING);
    let loan_raw = patch_number_field(
        &loan_raw,
        SF_TOTAL_VALUE_OUTSTANDING,
        (total_value - repay_amount as i64).max(0),
    );
    let loan_raw = if new_principal == 0 {
        patch_uint32_field(&loan_raw, SF_PAYMENT_REMAINING, 0)
    } else {
        loan_raw
    };
    state.insert_raw(loan_key_val, loan_raw);

    // 8. Increase vault's sfAssetsAvailable
    let assets_avail = vault_sle_number(&vault_raw, SF_ASSETS_AVAILABLE);
    let vault_raw = patch_number_field(
        &vault_raw,
        SF_ASSETS_AVAILABLE,
        assets_avail + repay_amount as i64,
    );
    state.insert_raw(Key(vault_id), vault_raw);

    let debt_total = loan_sle_number(&broker_raw, SF_DEBT_TOTAL);
    let broker_raw = patch_number_field(
        &broker_raw,
        SF_DEBT_TOTAL,
        (debt_total - repay_amount as i64).max(0),
    );
    state.insert_raw(Key(broker_id), broker_raw);

    ApplyResult::Success
}

/// Type 81: LoanDelete — delete a fully repaid loan.
///
/// Validates: principal outstanding == 0. Removes loan SLE, directory entries,
/// decrements borrower and broker owner counts.
///
/// (rippled: LoanDelete.cpp — doApply)
pub(crate) fn apply_loan_delete(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    // 1. Find the loan
    let loan_key_val = match tx_loan_id(tx) {
        Some(id) => Key(id),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let loan_raw = match state.get_raw(&loan_key_val) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };

    // 2. Verify the loan has no remaining payments.
    if sle_uint32(&loan_raw, SF_PAYMENT_REMAINING) > 0 {
        return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
    }

    // 3. Get borrower and broker info
    let borrower = match loan_sle_borrower(&loan_raw) {
        Some(b) => b,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let broker_id = match loan_sle_broker_id(&loan_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let broker_raw = match state.get_raw(&Key(broker_id)) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let broker_owner = match broker_sle_owner(&broker_raw) {
        Some(owner) => owner,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    if tx.account != borrower && tx.account != broker_owner {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    let broker_pseudo = match broker_sle_pseudo_id(&broker_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 4. Remove from borrower's directory
    directory::dir_remove(state, &borrower, &loan_key_val.0);
    directory::dir_remove(state, &broker_pseudo, &loan_key_val.0);

    // 5. Remove loan SLE
    state.remove_raw(&loan_key_val);

    // 6. Decrement borrower's owner_count
    if let Some(b) = state.get_account(&borrower) {
        let mut b = b.clone();
        b.owner_count = b.owner_count.saturating_sub(1);
        state.insert_account(b);
    }

    // 7. Decrement LoanBroker sfOwnerCount. If this was the last loan, rippled
    // forgives dust debt that rounds to zero; the local integer XRP model can
    // clear the remaining debt exactly when no loans remain.
    let owner_count = sle_uint32(&broker_raw, SF_OWNER_COUNT).saturating_sub(1);
    let broker_raw = patch_uint32_field(&broker_raw, SF_OWNER_COUNT, owner_count);
    let broker_raw = if owner_count == 0 {
        patch_number_field(&broker_raw, SF_DEBT_TOTAL, 0)
    } else {
        broker_raw
    };
    state.insert_raw(Key(broker_id), broker_raw);

    ApplyResult::Success
}

/// Type 76: LoanBrokerCoverDeposit — deposit first-loss cover into a broker.
pub(crate) fn apply_loan_broker_cover_deposit(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
    let broker_key = match tx_loan_broker_id(tx) {
        Some(id) if id != [0u8; 32] => Key(id),
        _ => return ApplyResult::ClaimedCost("temINVALID"),
    };
    let (broker_raw, _vault_key, vault_raw, broker_pseudo) =
        match load_broker_and_vault(state, broker_key) {
            Ok(v) => v,
            Err(result) => return result,
        };
    let owner = match broker_sle_owner(&broker_raw) {
        Some(owner) => owner,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    if owner != tx.account {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    let vault_asset = sle_issue(&vault_raw, 3).unwrap_or(Issue::Xrp);
    let amount = match xrp_amount_matching_vault(tx, &vault_asset) {
        Ok(drops) => drops,
        Err(code) => return ApplyResult::ClaimedCost(code),
    };
    if let Err(code) = transfer_xrp_between_accounts(state, &tx.account, &broker_pseudo, amount) {
        return ApplyResult::ClaimedCost(code);
    }

    let cover = loan_sle_number(&broker_raw, SF_COVER_AVAILABLE);
    let broker_raw = patch_number_field(&broker_raw, SF_COVER_AVAILABLE, cover + amount as i64);
    state.insert_raw(broker_key, broker_raw);
    ApplyResult::Success
}

/// Type 77: LoanBrokerCoverWithdraw — withdraw available first-loss cover.
pub(crate) fn apply_loan_broker_cover_withdraw(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
    let broker_key = match tx_loan_broker_id(tx) {
        Some(id) if id != [0u8; 32] => Key(id),
        _ => return ApplyResult::ClaimedCost("temINVALID"),
    };
    let destination = tx.destination.unwrap_or(tx.account);
    if destination == [0u8; 20] {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    if state
        .get_account(&destination)
        .is_some_and(|account| account.sequence == 0)
    {
        return ApplyResult::ClaimedCost("tecPSEUDO_ACCOUNT");
    }
    let (broker_raw, _vault_key, vault_raw, broker_pseudo) =
        match load_broker_and_vault(state, broker_key) {
            Ok(v) => v,
            Err(result) => return result,
        };
    let owner = match broker_sle_owner(&broker_raw) {
        Some(owner) => owner,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    if owner != tx.account {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    let vault_asset = sle_issue(&vault_raw, 3).unwrap_or(Issue::Xrp);
    let amount = match xrp_amount_matching_vault(tx, &vault_asset) {
        Ok(drops) => drops,
        Err(code) => return ApplyResult::ClaimedCost(code),
    };
    let cover = loan_sle_number(&broker_raw, SF_COVER_AVAILABLE);
    if cover < amount as i64 {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
    }
    let minimum_cover = min_cover_for_debt(
        loan_sle_number(&broker_raw, SF_DEBT_TOTAL),
        sle_uint32(&broker_raw, SF_COVER_RATE_MINIMUM),
    );
    if cover - (amount as i64) < minimum_cover {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
    }
    if let Err(code) = transfer_xrp_between_accounts(state, &broker_pseudo, &destination, amount) {
        return ApplyResult::ClaimedCost(code);
    }
    let broker_raw = patch_number_field(&broker_raw, SF_COVER_AVAILABLE, cover - amount as i64);
    state.insert_raw(broker_key, broker_raw);
    ApplyResult::Success
}

/// Type 78: LoanBrokerCoverClawback.
///
/// XRP cannot be clawed back in rippled. IOU/MPT cover clawback needs the full
/// asset transfer/clawback permission stack, so local XRP vaults return the
/// real mainnet result instead of a metadata-only placeholder.
pub(crate) fn apply_loan_broker_cover_clawback(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
    let broker_key = match tx_loan_broker_id(tx) {
        Some(id) if id != [0u8; 32] => Some(Key(id)),
        Some(_) => return ApplyResult::ClaimedCost("temINVALID"),
        None => None,
    };
    if broker_key.is_none() && tx.amount.is_none() {
        return ApplyResult::ClaimedCost("temINVALID");
    }
    let broker_key = match broker_key {
        Some(key) => key,
        None => return ApplyResult::ClaimedCost("tecINCOMPLETE"),
    };
    let (broker_raw, _vault_key, vault_raw, broker_pseudo) =
        match load_broker_and_vault(state, broker_key) {
            Ok(v) => v,
            Err(result) => return result,
        };
    let vault_asset = sle_issue(&vault_raw, 3).unwrap_or(Issue::Xrp);
    if matches!(vault_asset, Issue::Xrp) {
        if tx.amount.is_some() {
            return ApplyResult::ClaimedCost("temBAD_AMOUNT");
        }
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if let Err(code) = xrp_optional_claw_amount_matching_vault(tx, &vault_asset) {
        return ApplyResult::ClaimedCost(code);
    }
    let _ = (broker_raw, broker_pseudo);
    ApplyResult::ClaimedCost("tecINCOMPLETE")
}

/// Type 82: LoanManage — update loan delinquency/default status.
pub(crate) fn apply_loan_manage(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
) -> ApplyResult {
    let loan_key_val = match tx_loan_id(tx) {
        Some(id) if id != [0u8; 32] => Key(id),
        _ => return ApplyResult::ClaimedCost("temINVALID"),
    };
    let active_flags = tx.flags & LOAN_MANAGE_FLAGS;
    if active_flags.count_ones() > 1 {
        return ApplyResult::ClaimedCost("temINVALID_FLAG");
    }
    let loan_raw = match state.get_raw(&loan_key_val) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    let mut loan_flags = sle_uint32(&loan_raw, SF_FLAGS);
    if (loan_flags & LSF_LOAN_DEFAULT) != 0 {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    let broker_id = match loan_sle_broker_id(&loan_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let (broker_raw, vault_key, vault_raw, broker_pseudo) =
        match load_broker_and_vault(state, Key(broker_id)) {
            Ok(v) => v,
            Err(result) => return result,
        };
    let owner = match broker_sle_owner(&broker_raw) {
        Some(owner) => owner,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    if owner != tx.account {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    let owed_to_vault = loan_owed_to_vault(&loan_raw);
    if owed_to_vault <= 0 || sle_uint32(&loan_raw, SF_PAYMENT_REMAINING) == 0 {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    match active_flags {
        0 => ApplyResult::Success,
        TF_LOAN_IMPAIR => {
            if (loan_flags & LSF_LOAN_IMPAIRED) != 0 {
                return ApplyResult::ClaimedCost("tecNO_PERMISSION");
            }
            let loss = vault_sle_number(&vault_raw, SF_LOSS_UNREALIZED);
            let unavailable = vault_sle_number(&vault_raw, SF_ASSETS_TOTAL)
                - vault_sle_number(&vault_raw, SF_ASSETS_AVAILABLE);
            if loss + owed_to_vault > unavailable {
                return ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED");
            }
            let vault_raw =
                patch_number_field(&vault_raw, SF_LOSS_UNREALIZED, loss + owed_to_vault);
            state.insert_raw(vault_key, vault_raw);
            loan_flags |= LSF_LOAN_IMPAIRED;
            let loan_raw = patch_flags(&loan_raw, loan_flags);
            let next_due = sle_uint32(&loan_raw, SF_NEXT_PAYMENT_DUE_DATE);
            let loan_raw = if next_due != 0 && !loan_time_expired(ctx.close_time, next_due) {
                patch_uint32_field(&loan_raw, SF_NEXT_PAYMENT_DUE_DATE, ctx.close_time as u32)
            } else {
                loan_raw
            };
            state.insert_raw(loan_key_val, loan_raw);
            ApplyResult::Success
        }
        TF_LOAN_UNIMPAIR => {
            if (loan_flags & LSF_LOAN_IMPAIRED) == 0 {
                return ApplyResult::ClaimedCost("tecNO_PERMISSION");
            }
            let loss = vault_sle_number(&vault_raw, SF_LOSS_UNREALIZED);
            if loss < owed_to_vault {
                return ApplyResult::ClaimedCost("tefBAD_LEDGER");
            }
            let vault_raw =
                patch_number_field(&vault_raw, SF_LOSS_UNREALIZED, loss - owed_to_vault);
            state.insert_raw(vault_key, vault_raw);
            loan_flags &= !LSF_LOAN_IMPAIRED;
            let loan_raw = patch_flags(&loan_raw, loan_flags);
            let payment_interval = sle_uint32(&loan_raw, SF_PAYMENT_INTERVAL);
            let normal_due = sle_uint32(&loan_raw, SF_PREVIOUS_PAYMENT_DUE_DATE)
                .max(sle_uint32(&loan_raw, SF_START_DATE))
                .saturating_add(payment_interval);
            let restored_due = if !loan_time_expired(ctx.close_time, normal_due) {
                normal_due
            } else {
                (ctx.close_time as u32).saturating_add(payment_interval)
            };
            let loan_raw = patch_uint32_field(&loan_raw, SF_NEXT_PAYMENT_DUE_DATE, restored_due);
            state.insert_raw(loan_key_val, loan_raw);
            ApplyResult::Success
        }
        TF_LOAN_DEFAULT => {
            let default_time = sle_uint32(&loan_raw, SF_NEXT_PAYMENT_DUE_DATE)
                .saturating_add(sle_uint32(&loan_raw, SF_GRACE_PERIOD));
            if default_time == 0 || !loan_time_expired(ctx.close_time, default_time) {
                return ApplyResult::ClaimedCost("tecTOO_SOON");
            }
            let cover = loan_sle_number(&broker_raw, SF_COVER_AVAILABLE).max(0);
            let minimum_cover = min_cover_for_debt(
                loan_sle_number(&broker_raw, SF_DEBT_TOTAL),
                sle_uint32(&broker_raw, SF_COVER_RATE_MINIMUM),
            );
            let target_covered = liquidation_cover_amount(
                minimum_cover,
                sle_uint32(&broker_raw, SF_COVER_RATE_LIQUIDATION),
                owed_to_vault,
            );
            let covered = cover.min(target_covered);
            let debt = loan_sle_number(&broker_raw, SF_DEBT_TOTAL);
            let broker_raw = patch_number_field(&broker_raw, SF_COVER_AVAILABLE, cover - covered);
            let broker_raw =
                patch_number_field(&broker_raw, SF_DEBT_TOTAL, (debt - owed_to_vault).max(0));
            state.insert_raw(Key(broker_id), broker_raw);

            let assets_total = vault_sle_number(&vault_raw, SF_ASSETS_TOTAL);
            let assets_avail = vault_sle_number(&vault_raw, SF_ASSETS_AVAILABLE);
            let loss = vault_sle_number(&vault_raw, SF_LOSS_UNREALIZED);
            let vault_raw = patch_number_field(
                &vault_raw,
                SF_ASSETS_TOTAL,
                (assets_total - (owed_to_vault - covered)).max(0),
            );
            let vault_raw =
                patch_number_field(&vault_raw, SF_ASSETS_AVAILABLE, assets_avail + covered);
            let vault_raw = patch_number_field(
                &vault_raw,
                SF_LOSS_UNREALIZED,
                (loss - owed_to_vault).max(0),
            );
            let vault_pseudo = if covered > 0 {
                match super::vault::vault_sle_pseudo_id(&vault_raw) {
                    Some(id) => Some(id),
                    None => return ApplyResult::ClaimedCost("tecINTERNAL"),
                }
            } else {
                None
            };
            state.insert_raw(vault_key, vault_raw);

            if let Some(vault_pseudo) = vault_pseudo {
                if let Err(code) = transfer_xrp_between_accounts(
                    state,
                    &broker_pseudo,
                    &vault_pseudo,
                    covered as u64,
                ) {
                    return ApplyResult::ClaimedCost(code);
                }
            }

            loan_flags = (loan_flags | LSF_LOAN_DEFAULT) & !LSF_LOAN_IMPAIRED;
            let loan_raw = patch_flags(&loan_raw, loan_flags);
            let loan_raw = patch_number_field(&loan_raw, SF_PRINCIPAL_OUTSTANDING, 0);
            let loan_raw = patch_number_field(&loan_raw, SF_TOTAL_VALUE_OUTSTANDING, 0);
            let loan_raw = patch_number_field(&loan_raw, SF_MANAGEMENT_FEE_OUTSTANDING, 0);
            let loan_raw = patch_uint32_field(&loan_raw, SF_PAYMENT_REMAINING, 0);
            let loan_raw = patch_uint32_field(&loan_raw, SF_NEXT_PAYMENT_DUE_DATE, 0);
            state.insert_raw(loan_key_val, loan_raw);
            ApplyResult::Success
        }
        _ => ApplyResult::ClaimedCost("temINVALID_FLAG"),
    }
}
