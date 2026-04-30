//! Vault — VaultCreate (65), VaultSet (66), VaultDelete (67),
//!         VaultDeposit (68), VaultWithdraw (69), VaultClawback (70).
//!
//! VaultCreate creates a pseudo-account + Vault SLE + MPTokenIssuance for shares.
//! VaultDelete removes all of those.
//! Other types modify existing SLEs (balances, share accounting).
//!
//! SHAMap keys:
//!   Vault: SHA-512-half(0x0056 || owner || sequence)
//!     namespace 'V' = 0x56
//!
//! (rippled: VaultCreate.cpp, VaultSet.cpp, VaultDelete.cpp,
//!  VaultDeposit.cpp, VaultWithdraw.cpp, VaultClawback.cpp)

use crate::crypto::{ripemd160, sha256, sha512_first_half};
use crate::ledger::tx::TxContext;
use crate::ledger::{directory, AccountRoot, Key, LedgerState};
use crate::transaction::ParsedTx;

use super::{bridge_metadata_only_tx, ApplyResult};

/// LedgerNameSpace::VAULT = 'V' = 0x56.
const VAULT_SPACE: [u8; 2] = [0x00, 0x56];

/// LedgerNameSpace::MPTOKEN_ISSUANCE = '~' = 0x7E.
const MPT_ISSUANCE_SPACE: [u8; 2] = [0x00, 0x7E];

/// LedgerNameSpace::MPTOKEN = 't' = 0x74.
const MPTOKEN_SPACE: [u8; 2] = [0x00, 0x74];

/// Vault SLE entry type (ltVAULT = 0x0084).
const LT_VAULT: u16 = 0x0084;

/// MPTokenIssuance entry type (ltMPTOKEN_ISSUANCE = 0x007E).
const LT_MPT_ISSUANCE: u16 = 0x007E;

/// MPToken entry type (ltMPTOKEN = 0x007F).
const LT_MPTOKEN: u16 = 0x007F;

/// Account flags for pseudo-accounts.
const LSF_DISABLE_MASTER: u32 = 0x00100000;
const LSF_DEFAULT_RIPPLE: u32 = 0x00800000;
const LSF_DEPOSIT_AUTH: u32 = 0x01000000;

/// Compute the Vault SHAMap key.
/// `SHA-512-Half(0x0056 || owner || sequence)`
pub fn vault_key(owner: &[u8; 20], sequence: u32) -> Key {
    let mut data = Vec::with_capacity(2 + 20 + 4);
    data.extend_from_slice(&VAULT_SPACE);
    data.extend_from_slice(owner);
    data.extend_from_slice(&sequence.to_be_bytes());
    Key(sha512_first_half(&data))
}

/// Construct a 24-byte MPTID from sequence + account.
fn make_mptid(sequence: u32, account: &[u8; 20]) -> [u8; 24] {
    let mut id = [0u8; 24];
    id[0..4].copy_from_slice(&sequence.to_be_bytes());
    id[4..24].copy_from_slice(account);
    id
}

/// Compute MPTokenIssuance SHAMap key.
pub(crate) fn mpt_issuance_key(mptid: &[u8; 24]) -> Key {
    let mut data = Vec::with_capacity(2 + 24);
    data.extend_from_slice(&MPT_ISSUANCE_SPACE);
    data.extend_from_slice(mptid);
    Key(sha512_first_half(&data))
}

/// Compute MPToken SHAMap key.
fn mptoken_key(issuance_key: &[u8; 32], holder: &[u8; 20]) -> Key {
    let mut data = Vec::with_capacity(2 + 32 + 20);
    data.extend_from_slice(&MPTOKEN_SPACE);
    data.extend_from_slice(issuance_key);
    data.extend_from_slice(holder);
    Key(sha512_first_half(&data))
}

/// Derive a pseudo-account address from a vault key and parent hash.
///
/// Matches rippled's `pseudoAccountAddress()` in AccountRootHelpers.cpp:
/// Try up to 256 iterations of:
///   hash = SHA-512-Half(i_u16_be || parent_hash || owner_key)
///   addr = RIPEMD160(SHA256(hash))
///   if no collision → return addr
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
        // Check no collision
        if state.get_account(&addr).is_none() {
            return Some(addr);
        }
    }
    None // terADDRESS_COLLISION after 256 attempts
}

/// Build a Vault SLE as raw bytes.
fn build_vault_sle(
    owner: &[u8; 20],
    pseudo_account: &[u8; 20],
    sequence: u32,
    share_mptid: &[u8; 24],
    owner_node: u64,
    flags: u32,
) -> Vec<u8> {
    use crate::ledger::meta::ParsedField;

    let fields = vec![
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
            data: flags.to_be_bytes().to_vec(),
        },
        // sfOwnerNode (UINT64=3, field=4)
        ParsedField {
            type_code: 3,
            field_code: 4,
            data: owner_node.to_be_bytes().to_vec(),
        },
        // sfShareMPTID (UINT192=21, field=2)
        ParsedField {
            type_code: 21,
            field_code: 2,
            data: share_mptid.to_vec(),
        },
        // sfAssetsTotal (NUMBER=9, field=4) — 0 initially
        ParsedField {
            type_code: 9,
            field_code: 4,
            data: 0i64.to_be_bytes().to_vec(),
        },
        // sfAssetsAvailable (NUMBER=9, field=2) — 0 initially
        ParsedField {
            type_code: 9,
            field_code: 2,
            data: 0i64.to_be_bytes().to_vec(),
        },
        // sfLossUnrealized (NUMBER=9, field=5) — 0 initially
        ParsedField {
            type_code: 9,
            field_code: 5,
            data: 0i64.to_be_bytes().to_vec(),
        },
        // sfWithdrawalPolicy (UINT8=16, field=20) — default: FirstComeFirstServe = 0
        ParsedField {
            type_code: 16,
            field_code: 20,
            data: vec![0],
        },
        // sfScale (UINT8=16, field=4) — 0 for XRP
        ParsedField {
            type_code: 16,
            field_code: 4,
            data: vec![0],
        },
    ];

    crate::ledger::meta::build_sle(LT_VAULT, &fields, None, None)
}

/// Build an MPTokenIssuance SLE for vault shares.
fn build_share_issuance_sle(pseudo_account: &[u8; 20], sequence: u32) -> Vec<u8> {
    use crate::ledger::meta::ParsedField;
    crate::ledger::meta::build_sle(
        LT_MPT_ISSUANCE,
        &[
            // sfIssuer (ACCOUNT=8, field=4)
            ParsedField {
                type_code: 8,
                field_code: 4,
                data: pseudo_account.to_vec(),
            },
            // sfSequence (UINT32=2, field=4)
            ParsedField {
                type_code: 2,
                field_code: 4,
                data: sequence.to_be_bytes().to_vec(),
            },
            // sfOutstandingAmount (UINT64=3, field=4) — 0 initially
            ParsedField {
                type_code: 3,
                field_code: 4,
                data: 0u64.to_be_bytes().to_vec(),
            },
            // sfLockedAmount (UINT64=3, field=25) — 0 initially
            ParsedField {
                type_code: 3,
                field_code: 25,
                data: 0u64.to_be_bytes().to_vec(),
            },
            // sfFlags (UINT32=2, field=2) — CanEscrow | CanTrade | CanTransfer
            ParsedField {
                type_code: 2,
                field_code: 2,
                data: 0u32.to_be_bytes().to_vec(),
            },
        ],
        None,
        None,
    )
}

/// Build an MPToken SLE for a holder.
fn build_mptoken_sle(account: &[u8; 20], mptid: &[u8; 24], flags: u32) -> Vec<u8> {
    use crate::ledger::meta::ParsedField;
    crate::ledger::meta::build_sle(
        LT_MPTOKEN,
        &[
            // sfAccount (ACCOUNT=8, field=1)
            ParsedField {
                type_code: 8,
                field_code: 1,
                data: account.to_vec(),
            },
            // sfMPTokenIssuanceID (UINT192=21, field=1)
            ParsedField {
                type_code: 21,
                field_code: 1,
                data: mptid.to_vec(),
            },
            // sfMPTAmount (UINT64=3, field=26) — 0 initially
            ParsedField {
                type_code: 3,
                field_code: 26,
                data: 0u64.to_be_bytes().to_vec(),
            },
            // sfLockedAmount (UINT64=3, field=4)
            ParsedField {
                type_code: 3,
                field_code: 4,
                data: 0u64.to_be_bytes().to_vec(),
            },
            // sfFlags (UINT32=2, field=2)
            ParsedField {
                type_code: 2,
                field_code: 2,
                data: flags.to_be_bytes().to_vec(),
            },
        ],
        None,
        None,
    )
}

/// Extract the pseudo-account ID (sfAccount) from a Vault SLE.
/// sfAccount = (ACCOUNT=8, field=1) — 20 bytes after VL prefix.
pub(super) fn vault_sle_pseudo_id(raw: &[u8]) -> Option<[u8; 20]> {
    extract_account_field(raw, 1)
}

/// Extract sfOwner from a Vault SLE.
/// sfOwner = (ACCOUNT=8, field=2) — 20 bytes after VL prefix.
fn vault_sle_owner(raw: &[u8]) -> Option<[u8; 20]> {
    extract_account_field(raw, 2)
}

/// Extract sfShareMPTID from a Vault SLE.
/// sfShareMPTID = (UINT192=21, field=2) — 24 bytes.
pub(crate) fn vault_sle_share_mptid(raw: &[u8]) -> Option<[u8; 24]> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    for field in &parsed.fields {
        if field.type_code == 21 && field.field_code == 2 && field.data.len() == 24 {
            let mut id = [0u8; 24];
            id.copy_from_slice(&field.data);
            return Some(id);
        }
    }
    None
}

/// Extract an ACCOUNT field (type=8) with a given field_code from an SLE.
fn extract_account_field(raw: &[u8], target_field: u16) -> Option<[u8; 20]> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    for field in &parsed.fields {
        if field.type_code == 8 && field.field_code == target_field && field.data.len() == 20 {
            let mut id = [0u8; 20];
            id.copy_from_slice(&field.data);
            return Some(id);
        }
    }
    None
}

// ── Transaction handlers ─────────────────────────────────────────────────────

/// Type 65: VaultCreate — create a new vault.
///
/// Creates:
///   1. Vault SLE
///   2. Pseudo-account (AccountRoot)
///   3. MPTokenIssuance for vault shares (owned by pseudo-account)
///   4. Owner's MPToken for shares
///   5. Directory linkage, owner_count += 2
///
/// (rippled: VaultCreate.cpp — doApply)
pub(crate) fn apply_vault_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
) -> ApplyResult {
    let sequence = super::sequence_proxy(tx);
    // 1. Compute vault key
    let vkey = vault_key(&tx.account, sequence);

    // 2. Derive pseudo-account address
    let pseudo_id = match pseudo_account_address(state, &ctx.parent_hash, &vkey.0) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("terADDRESS_COLLISION"),
    };

    // 3. Add vault to owner's directory
    let owner_node = directory::dir_add(state, &tx.account, vkey.0);

    // 4. Create pseudo-account
    let pseudo_acct = AccountRoot {
        account_id: pseudo_id,
        balance: 0,
        sequence: 0, // pseudo-accounts have sequence 0
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
        previous_txn_lgr_seq: 0,
        raw_sle: None,
    };
    state.insert_account(pseudo_acct);

    // 5. Create MPTokenIssuance for shares (pseudo-account, sequence=1)
    let share_mptid = make_mptid(1, &pseudo_id);
    let issuance_key = mpt_issuance_key(&share_mptid);
    let issuance_sle = build_share_issuance_sle(&pseudo_id, 1);
    directory::dir_add(state, &pseudo_id, issuance_key.0);
    state.insert_raw(issuance_key, issuance_sle);
    // Increment pseudo-account owner_count for the issuance
    if let Some(pa) = state.get_account(&pseudo_id) {
        let mut pa = pa.clone();
        pa.owner_count += 1;
        state.insert_account(pa);
    }

    // 6. Create owner's MPToken for shares (authorized)
    let owner_token_key = mptoken_key(&issuance_key.0, &tx.account);
    let owner_token_sle = build_mptoken_sle(&tx.account, &share_mptid, 0x0000_0002); // lsfMPTAuthorized
    directory::dir_add(state, &tx.account, owner_token_key.0);
    state.insert_raw(owner_token_key, owner_token_sle);

    // 7. Create Vault SLE
    let vault_sle = build_vault_sle(
        &tx.account,
        &pseudo_id,
        tx.sequence,
        &share_mptid,
        owner_node,
        tx.flags, // only tfVaultPrivate stored
    );
    state.insert_raw(vkey, vault_sle);

    // 8. Update sender: owner_count += 2 (vault + MPToken for shares)
    // Sender was already persisted before handler (in the "persist sender first" branch)
    if let Some(sender) = state.get_account(&tx.account) {
        let mut sender = sender.clone();
        sender.owner_count += 2;
        state.insert_account(sender);
    }

    ApplyResult::Success
}

/// Type 67: VaultDelete — delete an empty vault.
///
/// Validates: caller == owner, assets == 0, shares == 0.
/// Removes: owner MPToken → share issuance → pseudo-account → vault SLE.
/// owner_count -= 2.
///
/// (rippled: VaultDelete.cpp — doApply)
pub(crate) fn apply_vault_delete(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    // 1. Find the Vault SLE
    let vault_key = match tx.vault_id {
        Some(id) => Key(id),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let vault_raw = match state.get_raw(&vault_key) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };

    // 2. Verify caller is the owner
    let owner = match vault_sle_owner(&vault_raw) {
        Some(o) => o,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    if owner != tx.account {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    // 3. Extract pseudo-account and share MPTID
    let pseudo_id = match vault_sle_pseudo_id(&vault_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let share_mptid = match vault_sle_share_mptid(&vault_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 4. Verify vault is empty (rippled: VaultDelete preclaim)
    let assets_total = vault_sle_number(&vault_raw, 4); // sfAssetsTotal
    let assets_avail = vault_sle_number(&vault_raw, 2); // sfAssetsAvailable
    if assets_total != 0 || assets_avail != 0 {
        return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
    }

    // Also verify outstanding shares == 0
    let issuance_key_check = mpt_issuance_key(&share_mptid);
    if let Some(issuance_raw) = state.get_raw(&issuance_key_check) {
        let outstanding = sle_uint64(&issuance_raw.to_vec(), 4);
        if outstanding != 0 {
            return ApplyResult::ClaimedCost("tecHAS_OBLIGATIONS");
        }
    }

    // 5. Remove owner's MPToken for shares
    let issuance_key = mpt_issuance_key(&share_mptid);
    let owner_token_key = mptoken_key(&issuance_key.0, &tx.account);
    directory::dir_remove(state, &tx.account, &owner_token_key.0);
    state.remove_raw(&owner_token_key);

    // 6. Remove MPTokenIssuance for shares
    directory::dir_remove(state, &pseudo_id, &issuance_key.0);
    state.remove_raw(&issuance_key);
    // Decrement pseudo-account owner_count
    if let Some(pa) = state.get_account(&pseudo_id) {
        let mut pa = pa.clone();
        pa.owner_count = pa.owner_count.saturating_sub(1);
        state.insert_account(pa);
    }

    // 7. Remove pseudo-account
    state.remove_account(&pseudo_id);

    // 8. Remove vault from owner's directory
    directory::dir_remove(state, &tx.account, &vault_key.0);

    // 9. Remove vault SLE
    state.remove_raw(&vault_key);

    // 10. Decrement sender's owner_count by 2
    if let Some(sender) = state.get_account(&tx.account) {
        let mut sender = sender.clone();
        sender.owner_count = sender.owner_count.saturating_sub(2);
        state.insert_account(sender);
    }

    ApplyResult::Success
}

/// Extract a NUMBER field (type=9, 8 bytes → i64) from a parsed SLE.
fn vault_sle_number(raw: &[u8], target_field: u16) -> i64 {
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

/// Extract a UInt64 field (type=3) from a parsed SLE.
fn sle_uint64(raw: &[u8], target_field: u16) -> u64 {
    let parsed = match crate::ledger::meta::parse_sle(raw) {
        Some(p) => p,
        None => return 0,
    };
    for field in &parsed.fields {
        if field.type_code == 3 && field.field_code == target_field && field.data.len() == 8 {
            return u64::from_be_bytes(field.data[..8].try_into().unwrap());
        }
    }
    0
}

/// Patch a NUMBER field in an SLE.
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

/// Patch a UInt64 field in an SLE.
fn patch_uint64_field(raw: &[u8], type_code: u16, field_code: u16, value: u64) -> Vec<u8> {
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            type_code,
            field_code,
            data: value.to_be_bytes().to_vec(),
        }],
        None,
        None,
        &[],
    )
}

/// Type 68: VaultDeposit — deposit assets into a vault and receive shares.
///
/// For XRP vaults (scale=0), first deposit: shares = deposit_drops (1:1).
/// Subsequent: shares = (outstanding_shares * deposit) / assets_total.
///
/// (rippled: VaultDeposit.cpp — doApply)
pub(crate) fn apply_vault_deposit(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    // 1. Find the vault
    let vkey = match tx.vault_id {
        Some(id) => Key(id),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let vault_raw = match state.get_raw(&vkey) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };

    let pseudo_id = match vault_sle_pseudo_id(&vault_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let share_mptid = match vault_sle_share_mptid(&vault_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 2. Get the deposit amount. This path currently uses XRP drops.
    let deposit_drops = match tx.amount_drops {
        Some(d) if d > 0 => d,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };

    // 3. Compute shares to mint
    let assets_total = vault_sle_number(&vault_raw, 4); // sfAssetsTotal = field 4
    let issuance_key = mpt_issuance_key(&share_mptid);
    let issuance_raw = match state.get_raw(&issuance_key) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let outstanding_shares = sle_uint64(&issuance_raw, 4); // sfOutstandingAmount = UInt64, field 4

    let shares_minted: u64 = if assets_total == 0 {
        // First deposit, scale=0: shares = deposit_drops (1:1)
        deposit_drops
    } else {
        // shares = (outstanding_shares * deposit) / assets_total
        let at = assets_total as u64;
        if at == 0 {
            deposit_drops
        } else {
            ((outstanding_shares as u128 * deposit_drops as u128) / at as u128) as u64
        }
    };

    if shares_minted == 0 {
        return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
    }

    // 4. Transfer XRP from depositor to pseudo-account
    let sender = match state.get_account(&tx.account) {
        Some(a) => a.clone(),
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    if sender.balance < deposit_drops {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
    }
    let mut sender = sender;
    sender.balance -= deposit_drops;
    state.insert_account(sender);

    if let Some(pa) = state.get_account(&pseudo_id) {
        let mut pa = pa.clone();
        pa.balance += deposit_drops;
        state.insert_account(pa);
    }

    // 5. Update vault: assetsTotal += deposit, assetsAvailable += deposit
    let new_total = assets_total + deposit_drops as i64;
    let assets_avail = vault_sle_number(&vault_raw, 2); // sfAssetsAvailable = field 2
    let new_avail = assets_avail + deposit_drops as i64;
    let vault_raw = patch_number_field(&vault_raw, 4, new_total);
    let vault_raw = patch_number_field(&vault_raw, 2, new_avail);
    state.insert_raw(vkey, vault_raw);

    // 6. Mint shares: update OutstandingAmount on issuance
    let new_outstanding = outstanding_shares + shares_minted;
    let issuance_raw = patch_uint64_field(&issuance_raw, 3, 4, new_outstanding);
    state.insert_raw(issuance_key, issuance_raw);

    // 7. Credit depositor's MPToken with shares
    let depositor_token_key = mptoken_key(&issuance_key.0, &tx.account);
    if let Some(token_raw) = state.get_raw(&depositor_token_key) {
        let token_raw = token_raw.to_vec();
        let current = sle_uint64(&token_raw, 26); // sfMPTAmount = UInt64, field 26
        let updated = patch_uint64_field(&token_raw, 3, 26, current + shares_minted);
        state.insert_raw(depositor_token_key, updated);
    }

    ApplyResult::Success
}

/// Type 69: VaultWithdraw — withdraw assets from a vault by burning shares.
///
/// For XRP vaults (scale=0): assets = (shares * assets_total) / outstanding_shares.
///
/// (rippled: VaultWithdraw.cpp — doApply)
pub(crate) fn apply_vault_withdraw(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    // 1. Find the vault
    let vkey = match tx.vault_id {
        Some(id) => Key(id),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let vault_raw = match state.get_raw(&vkey) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };

    let pseudo_id = match vault_sle_pseudo_id(&vault_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let share_mptid = match vault_sle_share_mptid(&vault_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    // 2. Get withdrawal amount in shares (passed as amount_drops for XRP vaults)
    let shares_to_burn = match tx.amount_drops {
        Some(d) if d > 0 => d,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };

    // 3. Compute assets to return
    let assets_total = vault_sle_number(&vault_raw, 4) as u64;
    let assets_avail = vault_sle_number(&vault_raw, 2) as u64;
    let issuance_key = mpt_issuance_key(&share_mptid);
    let issuance_raw = match state.get_raw(&issuance_key) {
        Some(d) => d.to_vec(),
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let outstanding_shares = sle_uint64(&issuance_raw, 4);

    if outstanding_shares == 0 || shares_to_burn > outstanding_shares {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
    }

    // assets_returned = (shares_to_burn * assets_total) / outstanding_shares
    let assets_returned =
        ((shares_to_burn as u128 * assets_total as u128) / outstanding_shares as u128) as u64;

    if assets_returned == 0 {
        return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
    }

    if assets_returned > assets_avail {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
    }

    // 4. Verify withdrawer has enough shares
    let withdrawer_token_key = mptoken_key(&issuance_key.0, &tx.account);
    let withdrawer_shares = match state.get_raw(&withdrawer_token_key) {
        Some(d) => sle_uint64(&d.to_vec(), 26),
        None => return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS"),
    };
    if withdrawer_shares < shares_to_burn {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
    }

    // 5. Transfer XRP from pseudo-account to withdrawer
    if let Some(pa) = state.get_account(&pseudo_id) {
        let mut pa = pa.clone();
        pa.balance = pa.balance.saturating_sub(assets_returned);
        state.insert_account(pa);
    }
    if let Some(sender) = state.get_account(&tx.account) {
        let mut sender = sender.clone();
        sender.balance += assets_returned;
        state.insert_account(sender);
    }

    // 6. Update vault: assetsTotal -= returned, assetsAvailable -= returned
    let new_total = (assets_total - assets_returned) as i64;
    let new_avail = (assets_avail - assets_returned) as i64;
    let vault_raw = patch_number_field(&vault_raw, 4, new_total);
    let vault_raw = patch_number_field(&vault_raw, 2, new_avail);
    state.insert_raw(vkey, vault_raw);

    // 7. Burn shares: reduce OutstandingAmount and depositor's MPToken balance
    let new_outstanding = outstanding_shares - shares_to_burn;
    let issuance_raw = patch_uint64_field(&issuance_raw, 3, 4, new_outstanding);
    state.insert_raw(issuance_key, issuance_raw);

    let token_raw = state.get_raw(&withdrawer_token_key).unwrap().to_vec();
    let current_shares = sle_uint64(&token_raw, 26);
    let updated = patch_uint64_field(&token_raw, 3, 26, current_shares - shares_to_burn);
    state.insert_raw(withdrawer_token_key, updated);

    ApplyResult::Success
}

/// Type 66: VaultSet — modify vault parameters.
///
/// Can update: withdrawal policy, flags, data payload.
/// The vault owner can change operational parameters without
/// destroying and recreating the vault.
///
/// (rippled: VaultSet.cpp — doApply)
pub(crate) fn apply_vault_set(
    _state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
) -> ApplyResult {
    // 1. Find the vault — need owner + sequence to compute key
    let owner = tx.account;
    let _vault_seq = tx.sequence.saturating_sub(1); // vault was created at a prior sequence
                                                    // Try to find vault from tx destination (VaultID passed as destination)
                                                    // Simplified: use tx.destination_account as the vault pseudo-account
                                                    // and look it up. In practice, VaultSet passes the VaultID.
                                                    // Return `Success` and let metadata apply the field changes.
                                                    // The fee and sequence are already consumed, and the amendment gate
                                                    // ensures this only runs when SingleAssetVault is active.
    tracing::debug!("VaultSet: applying for account {:?}", hex::encode(owner));

    // VaultSet primarily modifies flags on the Vault SLE.
    // The actual field patching is handled by metadata application in follower mode.
    // In validator mode, the flags from tx.flags would be applied to the vault SLE.
    // Since vault SLE lookup by VaultID requires additional parsing of the tx blob
    // (`sfVaultID` field). Full implementation is deferred until the amendment activates.
    bridge_metadata_only_tx(ctx, 66, "VaultSet", "temUNKNOWN")
}

/// Type 70: VaultClawback — issuer recovers assets from the vault.
///
/// The asset issuer can claw back deposited assets from the vault,
/// reducing the vault's total and available assets and burning
/// corresponding shares.
///
/// (rippled: VaultClawback.cpp — doApply)
pub(crate) fn apply_vault_clawback(
    _state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
) -> ApplyResult {
    // VaultClawback requires:
    // 1. Caller is the issuer of the vault's asset
    // 2. Clawback amount from the vault's pool
    // 3. Burn proportional shares
    // 4. Transfer clawed-back assets to the issuer

    // The amendment gate ensures this only runs when SingleAssetVault is active.
    // Metadata/diff sync handles the actual state changes in follower mode.
    // Validator mode requires the full `VaultID -> vault SLE -> asset` lookup chain.
    // Because the amendment is not active on mainnet, this path returns `Success` and
    // the amendment gate will block it until the amendment passes.
    tracing::debug!(
        "VaultClawback: applying for account {:?}",
        hex::encode(tx.account)
    );
    bridge_metadata_only_tx(ctx, 70, "VaultClawback", "temUNKNOWN")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_sle_round_trip() {
        let owner = [1u8; 20];
        let pseudo = [2u8; 20];
        let mptid = [3u8; 24];

        let raw = build_vault_sle(&owner, &pseudo, 42, &mptid, 7, 0);

        // Verify parse_sle can read the SLE
        let parsed = crate::ledger::meta::parse_sle(&raw);
        assert!(parsed.is_some(), "parse_sle should succeed on vault SLE");
        let parsed = parsed.unwrap();

        // Check entry type
        assert_eq!(parsed.entry_type, LT_VAULT);

        // Extract owner (ACCOUNT=8, field=2)
        let extracted_owner = vault_sle_owner(&raw);
        assert_eq!(extracted_owner, Some(owner), "should extract sfOwner");

        // Extract pseudo-account (ACCOUNT=8, field=1)
        let extracted_pseudo = vault_sle_pseudo_id(&raw);
        assert_eq!(
            extracted_pseudo,
            Some(pseudo),
            "should extract sfAccount (pseudo)"
        );

        // Extract share MPTID (UINT192=21, field=2)
        let extracted_mptid = vault_sle_share_mptid(&raw);
        assert_eq!(extracted_mptid, Some(mptid), "should extract sfShareMPTID");
    }
}
