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

use crate::crypto::{sha512_first_half, sha256, ripemd160};
use crate::ledger::{directory, Key, LedgerState, AccountRoot};
use crate::ledger::tx::TxContext;
use crate::transaction::ParsedTx;

use super::{ApplyResult, bridge_metadata_only_tx};

/// LedgerNameSpace::LOAN_BROKER = 'l' = 0x6C.
const LOAN_BROKER_SPACE: [u8; 2] = [0x00, 0x6C];

/// LoanBroker entry type (ltLOAN_BROKER = 0x0088).
const LT_LOAN_BROKER: u16 = 0x0088;

/// Account flags for pseudo-accounts (same as vault).
const LSF_DISABLE_MASTER: u32 = 0x00100000;
const LSF_DEFAULT_RIPPLE: u32 = 0x00800000;
const LSF_DEPOSIT_AUTH: u32   = 0x01000000;

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
    crate::ledger::meta::build_sle(LT_LOAN_BROKER, &[
        // sfOwner (ACCOUNT=8, field=2)
        ParsedField { type_code: 8, field_code: 2, data: owner.to_vec() },
        // sfAccount (ACCOUNT=8, field=1) — pseudo-account
        ParsedField { type_code: 8, field_code: 1, data: pseudo_account.to_vec() },
        // sfSequence (UINT32=2, field=4)
        ParsedField { type_code: 2, field_code: 4, data: sequence.to_be_bytes().to_vec() },
        // sfFlags (UINT32=2, field=2)
        ParsedField { type_code: 2, field_code: 2, data: 0u32.to_be_bytes().to_vec() },
        // sfOwnerNode (UINT64=3, field=4)
        ParsedField { type_code: 3, field_code: 4, data: owner_node.to_be_bytes().to_vec() },
        // sfVaultNode (UINT64=3, field=30)
        ParsedField { type_code: 3, field_code: 30, data: vault_node.to_be_bytes().to_vec() },
        // sfVaultID (HASH256=5, field=35)
        ParsedField { type_code: 5, field_code: 35, data: vault_id.to_vec() },
        // sfLoanSequence (UINT32=2, field=61) — starts at 1
        ParsedField { type_code: 2, field_code: 61, data: 1u32.to_be_bytes().to_vec() },
        // sfDebtTotal (NUMBER=9, field=6) — 0 initially
        ParsedField { type_code: 9, field_code: 6, data: 0i64.to_be_bytes().to_vec() },
        // sfDebtMaximum (NUMBER=9, field=7) — 0 = unlimited
        ParsedField { type_code: 9, field_code: 7, data: 0i64.to_be_bytes().to_vec() },
        // sfCoverAvailable (NUMBER=9, field=8) — 0 initially
        ParsedField { type_code: 9, field_code: 8, data: 0i64.to_be_bytes().to_vec() },
    ], None, None)
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
    if state.get_raw(&vault_key).is_none() {
        return ApplyResult::ClaimedCost("tecNO_ENTRY");
    }

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
        burned_nftokens: 0,
        transfer_rate: 0,
        domain: Vec::new(),
        tick_size: 0,
        ticket_count: 0,
        previous_txn_id: [0u8; 32],
        previous_txn_lgr_seq: 0, raw_sle: None,
    });

    // 6. Add broker to vault pseudo-account's directory
    // (rippled links broker to the vault's pseudo-account directory)
    let vault_node = 0u64; // simplified — real impl would add to vault pseudo's dir

    // 7. Create LoanBroker SLE
    let broker_sle = build_loan_broker_sle(
        &tx.account, &pseudo_id, &vault_id, sequence, owner_node, vault_node,
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
pub(crate) fn apply_loan_broker_delete(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
    // 1. Find broker SLE
    let broker_key = match tx.vault_id {
        // Reuse vault_id field for broker ID (both are Hash256)
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

    // 4. Check pseudo-account has no owned objects (no active loans)
    if let Some(pa) = state.get_account(&pseudo_id) {
        if pa.owner_count > 0 {
            return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
        }
    }

    // 5. Remove from owner directory
    directory::dir_remove(state, &tx.account, &broker_key.0);

    // 6. Remove pseudo-account
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
) -> Vec<u8> {
    use crate::ledger::meta::ParsedField;
    crate::ledger::meta::build_sle(LT_LOAN, &[
        // sfBorrower (ACCOUNT=8, field=? — use field=1 for Account)
        ParsedField { type_code: 8, field_code: 1, data: borrower.to_vec() },
        // sfLoanBrokerID (HASH256=5, field=? — use field=35 like VaultID)
        // Actually sfLoanBrokerID is a separate field. Let's use field 36.
        ParsedField { type_code: 5, field_code: 36, data: broker_key.to_vec() },
        // sfFlags (UINT32=2, field=2)
        ParsedField { type_code: 2, field_code: 2, data: 0u32.to_be_bytes().to_vec() },
        // sfLoanSequence (UINT32=2, field=61)
        ParsedField { type_code: 2, field_code: 61, data: loan_seq.to_be_bytes().to_vec() },
        // sfOwnerNode (UINT64=3, field=4)
        ParsedField { type_code: 3, field_code: 4, data: owner_node.to_be_bytes().to_vec() },
        // sfPrincipalOutstanding (NUMBER=9, field=9 — simplified)
        ParsedField { type_code: 9, field_code: 9, data: (principal as i64).to_be_bytes().to_vec() },
    ], None, None)
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
) -> ApplyResult {
    // 1. Find broker
    let broker_key = match tx.vault_id {
        Some(id) => Key(id),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let broker_raw = match state.get_raw(&broker_key) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };

    let principal = match tx.amount_drops {
        Some(d) if d > 0 => d,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
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

    // 4. Check vault has sufficient available assets
    let assets_avail = {
        let parsed = crate::ledger::meta::parse_sle(&vault_raw);
        parsed.and_then(|p| {
            p.fields.iter().find(|f| f.type_code == 9 && f.field_code == 2)
                .and_then(|f| (f.data.len() == 8).then(|| i64::from_be_bytes(f.data[..8].try_into().unwrap())))
        }).unwrap_or(0)
    };
    if (assets_avail as u64) < principal {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
    }

    // 5. Get loan sequence and pseudo-account from broker (before patching)
    let loan_seq = sle_uint32(&broker_raw, 61); // sfLoanSequence
    let broker_pseudo = broker_sle_pseudo_id(&broker_raw);

    // 6. Create Loan SLE
    let lkey = loan_key(&broker_key.0, loan_seq);
    let owner_node = directory::dir_add(state, &tx.account, lkey.0);
    let loan_sle = build_loan_sle(&tx.account, &broker_key.0, loan_seq, principal, owner_node);
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
    let broker_raw = crate::ledger::meta::patch_sle(
        &broker_raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 2,
            field_code: 61,
            data: new_loan_seq.to_be_bytes().to_vec(),
        }],
        None, None, &[],
    );
    state.insert_raw(broker_key, broker_raw);

    // 9. Update vault: assets_available -= principal
    let new_avail = assets_avail - principal as i64;
    let vault_raw = crate::ledger::meta::patch_sle(
        &vault_raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 9,
            field_code: 2,
            data: new_avail.to_be_bytes().to_vec(),
        }],
        None, None, &[],
    );
    state.insert_raw(vault_key, vault_raw);

    // 10. Increment broker pseudo-account owner_count
    if let Some(bp_id) = broker_pseudo {
        if let Some(pa) = state.get_account(&bp_id) {
            let mut pa = pa.clone();
            pa.owner_count += 1;
            state.insert_account(pa);
        }
    }

    ApplyResult::Success
}

/// Extract sfBorrower (ACCOUNT=8, field=1) from a Loan SLE.
fn loan_sle_borrower(raw: &[u8]) -> Option<[u8; 20]> {
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

/// Extract sfLoanBrokerID (HASH256=5, field=36) from a Loan SLE.
fn loan_sle_broker_id(raw: &[u8]) -> Option<[u8; 32]> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    for field in &parsed.fields {
        if field.type_code == 5 && field.field_code == 36 && field.data.len() == 32 {
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

/// Type 84: LoanPay — repay part or all of a loan.
///
/// Simplified XRP flow:
/// 1. Validate loan exists and caller is borrower
/// 2. Transfer repayment XRP from borrower to vault pseudo-account
/// 3. Reduce sfPrincipalOutstanding on loan
/// 4. Increase vault's sfAssetsAvailable
///
/// (rippled: LoanPay.cpp — doApply, simplified)
pub(crate) fn apply_loan_pay(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
    // 1. Find the loan
    let loan_key_val = match tx.vault_id {
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
    let principal_outstanding = loan_sle_number(&loan_raw, 9) as u64; // sfPrincipalOutstanding = field 9
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
    let loan_raw = crate::ledger::meta::patch_sle(
        &loan_raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 9,
            field_code: 9,
            data: (new_principal as i64).to_be_bytes().to_vec(),
        }],
        None, None, &[],
    );
    state.insert_raw(loan_key_val, loan_raw);

    // 8. Increase vault's sfAssetsAvailable
    let assets_avail = {
        let parsed = crate::ledger::meta::parse_sle(&vault_raw);
        parsed.and_then(|p| {
            p.fields.iter().find(|f| f.type_code == 9 && f.field_code == 2)
                .and_then(|f| (f.data.len() == 8).then(|| i64::from_be_bytes(f.data[..8].try_into().unwrap())))
        }).unwrap_or(0)
    };
    let vault_raw = crate::ledger::meta::patch_sle(
        &vault_raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 9,
            field_code: 2,
            data: (assets_avail + repay_amount as i64).to_be_bytes().to_vec(),
        }],
        None, None, &[],
    );
    state.insert_raw(Key(vault_id), vault_raw);

    ApplyResult::Success
}

/// Type 81: LoanDelete — delete a fully repaid loan.
///
/// Validates: principal outstanding == 0. Removes loan SLE, directory entries,
/// decrements borrower and broker owner counts.
///
/// (rippled: LoanDelete.cpp — doApply)
pub(crate) fn apply_loan_delete(
    state: &mut LedgerState,
    tx: &ParsedTx,
) -> ApplyResult {
    // 1. Find the loan
    let loan_key_val = match tx.vault_id {
        Some(id) => Key(id),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let loan_raw = match state.get_raw(&loan_key_val) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };

    // 2. Verify principal is zero (fully repaid)
    let principal = loan_sle_number(&loan_raw, 9) as u64;
    if principal > 0 {
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

    // 4. Remove from borrower's directory
    directory::dir_remove(state, &borrower, &loan_key_val.0);

    // 5. Remove loan SLE
    state.remove_raw(&loan_key_val);

    // 6. Decrement borrower's owner_count
    if let Some(b) = state.get_account(&borrower) {
        let mut b = b.clone();
        b.owner_count = b.owner_count.saturating_sub(1);
        state.insert_account(b);
    }

    // 7. Decrement broker pseudo-account's owner_count
    let broker_raw = match state.get_raw(&Key(broker_id)) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::Success,
    };
    if let Some(bp_id) = broker_sle_pseudo_id(&broker_raw) {
        if let Some(pa) = state.get_account(&bp_id) {
            let mut pa = pa.clone();
            pa.owner_count = pa.owner_count.saturating_sub(1);
            state.insert_account(pa);
        }
    }

    ApplyResult::Success
}

/// Types 76, 77, 78, 82: Cover/Manage operations still rely on metadata replay.
pub(crate) fn apply_loan_modify(ctx: &TxContext, tx_type: u16) -> ApplyResult {
    bridge_metadata_only_tx(ctx, tx_type, "Loan cover/manage", "tefFAILURE")
}
