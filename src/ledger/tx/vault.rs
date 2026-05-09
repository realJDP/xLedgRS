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
use crate::transaction::amount::{Amount, Issue};
use crate::transaction::ParsedTx;

use super::asset_flow::{self, AssetDelta};
use super::mptoken;
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
const LSF_VAULT_PRIVATE: u32 = 0x00010000;
const LSF_MPT_REQUIRE_AUTH: u32 = 0x00000004;
const MAX_DATA_PAYLOAD_LENGTH: usize = 256;
const VAULT_STRATEGY_FIRST_COME_FIRST_SERVE: u8 = 1;

const SF_OWNER_NODE: u16 = 4;
const SF_OUTSTANDING_AMOUNT: u16 = 25;
const SF_MPT_AMOUNT: u16 = 26;

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

fn issue_from_amount(amount: &Amount) -> Option<Issue> {
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

fn amount_units(amount: &Amount) -> Option<u64> {
    match amount {
        Amount::Xrp(drops) => Some(*drops),
        Amount::Iou { value, .. } => {
            if !value.is_positive() {
                return Some(0);
            }
            let mut v = value.mantissa as i128;
            if value.exponent >= 0 {
                v = v.checked_mul(10_i128.checked_pow(value.exponent as u32)?)?;
            } else {
                v /= 10_i128.checked_pow((-value.exponent) as u32)?;
            }
            (v >= 0 && v <= u64::MAX as i128).then_some(v as u64)
        }
        Amount::Mpt(_) => amount.mpt_parts().map(|(value, _)| value),
    }
}

fn amount_from_issue(issue: &Issue, units: u64) -> Option<Amount> {
    match issue {
        Issue::Xrp => Some(Amount::Xrp(units)),
        Issue::Iou { currency, issuer } => Some(Amount::Iou {
            value: crate::transaction::amount::IouValue {
                mantissa: i64::try_from(units).ok()?,
                exponent: 0,
            },
            currency: currency.clone(),
            issuer: *issuer,
        }),
        Issue::Mpt(mptid) => Some(Amount::from_mpt_value(units, *mptid)),
    }
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
    asset: &Issue,
    assets_maximum: i64,
    data: Option<&[u8]>,
) -> Vec<u8> {
    use crate::ledger::meta::ParsedField;

    let mut fields = vec![
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
        // sfAsset (ISSUE=24, field=3) — held asset type
        ParsedField {
            type_code: 24,
            field_code: 3,
            data: asset.to_bytes(),
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
        // sfAssetsMaximum (NUMBER=9, field=3) — 0 means unlimited
        ParsedField {
            type_code: 9,
            field_code: 3,
            data: assets_maximum.to_be_bytes().to_vec(),
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
        // sfWithdrawalPolicy (UINT8=16, field=20) — FirstComeFirstServe
        ParsedField {
            type_code: 16,
            field_code: 20,
            data: vec![VAULT_STRATEGY_FIRST_COME_FIRST_SERVE],
        },
        // sfScale (UINT8=16, field=4) — 0 for XRP
        ParsedField {
            type_code: 16,
            field_code: 4,
            data: vec![0],
        },
    ];
    if let Some(data) = data {
        fields.push(ParsedField {
            type_code: 7,
            field_code: 27,
            data: data.to_vec(),
        });
    }

    crate::ledger::meta::build_sle(LT_VAULT, &fields, None, None)
}

/// Build an MPTokenIssuance SLE for vault shares.
fn build_share_issuance_sle(
    pseudo_account: &[u8; 20],
    sequence: u32,
    flags: u32,
    owner_node: u64,
) -> Vec<u8> {
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
            // sfOwnerNode (UINT64=3, field=4)
            ParsedField {
                type_code: 3,
                field_code: SF_OWNER_NODE,
                data: owner_node.to_be_bytes().to_vec(),
            },
            // sfOutstandingAmount (UINT64=3, field=25) — 0 initially
            ParsedField {
                type_code: 3,
                field_code: SF_OUTSTANDING_AMOUNT,
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

/// Build an MPToken SLE for a holder.
fn build_mptoken_sle(account: &[u8; 20], mptid: &[u8; 24], flags: u32, owner_node: u64) -> Vec<u8> {
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
                field_code: SF_MPT_AMOUNT,
                data: 0u64.to_be_bytes().to_vec(),
            },
            // sfOwnerNode (UINT64=3, field=4)
            ParsedField {
                type_code: 3,
                field_code: SF_OWNER_NODE,
                data: owner_node.to_be_bytes().to_vec(),
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

fn vault_sle_asset(raw: &[u8]) -> Option<Issue> {
    let parsed = crate::ledger::meta::parse_sle(raw)?;
    parsed
        .fields
        .iter()
        .find(|field| field.type_code == 24 && field.field_code == 3)
        .and_then(|field| Issue::from_bytes(&field.data).map(|(issue, _)| issue))
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
    state.insert_account(pseudo_acct);

    // 5. Create MPTokenIssuance for shares (pseudo-account, sequence=1)
    let share_mptid = make_mptid(1, &pseudo_id);
    let issuance_key = mpt_issuance_key(&share_mptid);
    let tx_flags = tx.flags & LSF_VAULT_PRIVATE;
    let issuance_flags = if (tx_flags & LSF_VAULT_PRIVATE) != 0 {
        LSF_MPT_REQUIRE_AUTH
    } else {
        0
    };
    let issuance_owner_node = directory::dir_add(state, &pseudo_id, issuance_key.0);
    let issuance_sle = build_share_issuance_sle(&pseudo_id, 1, issuance_flags, issuance_owner_node);
    state.insert_raw(issuance_key, issuance_sle);
    // Increment pseudo-account owner_count for the issuance
    if let Some(pa) = state.get_account(&pseudo_id) {
        let mut pa = pa.clone();
        pa.owner_count += 1;
        state.insert_account(pa);
    }

    // 6. Create owner's MPToken for shares (authorized)
    let owner_token_key = mptoken_key(&issuance_key.0, &tx.account);
    let owner_token_node = directory::dir_add(state, &tx.account, owner_token_key.0);
    let owner_token_sle =
        build_mptoken_sle(&tx.account, &share_mptid, 0x0000_0002, owner_token_node); // lsfMPTAuthorized
    state.insert_raw(owner_token_key, owner_token_sle);

    // 7. Create Vault SLE
    let asset = tx.asset.clone().unwrap_or(Issue::Xrp);
    let assets_maximum = tx.maximum_amount.unwrap_or(0) as i64;
    let vault_sle = build_vault_sle(
        &tx.account,
        &pseudo_id,
        tx.sequence,
        &share_mptid,
        owner_node,
        tx_flags, // only tfVaultPrivate stored
        &asset,
        assets_maximum,
        tx.did_data.as_deref(),
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
        let outstanding = sle_uint64(&issuance_raw.to_vec(), SF_OUTSTANDING_AMOUNT);
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

/// Extract a UInt32 field (type=2) from a parsed SLE.
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

fn patch_blob_field(raw: &[u8], field_code: u16, value: &[u8]) -> Vec<u8> {
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 7,
            field_code,
            data: value.to_vec(),
        }],
        None,
        None,
        &[],
    )
}

fn patch_hash256_field(raw: &[u8], field_code: u16, value: [u8; 32]) -> Vec<u8> {
    crate::ledger::meta::patch_sle(
        raw,
        &[crate::ledger::meta::ParsedField {
            type_code: 5,
            field_code,
            data: value.to_vec(),
        }],
        None,
        None,
        &[],
    )
}

fn remove_sle_field(raw: &[u8], type_code: u16, field_code: u16) -> Vec<u8> {
    crate::ledger::meta::patch_sle(raw, &[], None, None, &[(type_code, field_code)])
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
    let outstanding_shares = sle_uint64(&issuance_raw, SF_OUTSTANDING_AMOUNT);

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
    let issuance_raw = patch_uint64_field(&issuance_raw, 3, SF_OUTSTANDING_AMOUNT, new_outstanding);
    state.insert_raw(issuance_key, issuance_raw);

    // 7. Credit depositor's MPToken with shares
    let depositor_token_key = mptoken_key(&issuance_key.0, &tx.account);
    if let Some(token_raw) = state.get_raw(&depositor_token_key) {
        let token_raw = token_raw.to_vec();
        let current = sle_uint64(&token_raw, SF_MPT_AMOUNT);
        let updated = patch_uint64_field(&token_raw, 3, SF_MPT_AMOUNT, current + shares_minted);
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
    let outstanding_shares = sle_uint64(&issuance_raw, SF_OUTSTANDING_AMOUNT);

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
        Some(d) => sle_uint64(&d.to_vec(), SF_MPT_AMOUNT),
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
    let issuance_raw = patch_uint64_field(&issuance_raw, 3, SF_OUTSTANDING_AMOUNT, new_outstanding);
    state.insert_raw(issuance_key, issuance_raw);

    let token_raw = state.get_raw(&withdrawer_token_key).unwrap().to_vec();
    let current_shares = sle_uint64(&token_raw, SF_MPT_AMOUNT);
    let updated = patch_uint64_field(
        &token_raw,
        3,
        SF_MPT_AMOUNT,
        current_shares - shares_to_burn,
    );
    state.insert_raw(withdrawer_token_key, updated);

    ApplyResult::Success
}

/// Type 66: VaultSet — modify mutable vault parameters.
///
/// Mirrors rippled's VaultSet.cpp: update sfData and sfAssetsMaximum on the
/// Vault SLE, and update/clear sfDomainID on the share issuance for private
/// vaults.
pub(crate) fn apply_vault_set(
    state: &mut LedgerState,
    tx: &ParsedTx,
    ctx: &TxContext,
) -> ApplyResult {
    if ctx.validated_result.is_some() {
        return bridge_metadata_only_tx(ctx, 66, "VaultSet", "tecINCOMPLETE");
    }

    let vault_key = match tx.vault_id {
        Some(id) => Key(id),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    if vault_key.0 == [0u8; 32] {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }
    if let Some(data) = tx.did_data.as_deref() {
        if data.is_empty() || data.len() > MAX_DATA_PAYLOAD_LENGTH {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
    }
    if tx.domain_id.is_none() && tx.maximum_amount.is_none() && tx.did_data.is_none() {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    let vault_raw = match state.get_raw(&vault_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    let owner = match vault_sle_owner(&vault_raw) {
        Some(owner) => owner,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    if owner != tx.account {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    let share_mptid = match vault_sle_share_mptid(&vault_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let issuance_key = mpt_issuance_key(&share_mptid);
    let issuance_raw = match state.get_raw(&issuance_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };

    if let Some(domain_id) = tx.domain_id {
        let vault_flags = sle_uint32(&vault_raw, 2);
        if (vault_flags & LSF_VAULT_PRIVATE) == 0 {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
        if domain_id != [0u8; 32] && state.get_raw(&Key(domain_id)).is_none() {
            return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND");
        }
        let issuance_flags = sle_uint32(&issuance_raw, 2);
        if (issuance_flags & LSF_MPT_REQUIRE_AUTH) == 0 {
            return ApplyResult::ClaimedCost("tecINTERNAL");
        }
    }

    let mut next_vault = vault_raw;
    if let Some(data) = tx.did_data.as_deref() {
        next_vault = patch_blob_field(&next_vault, 27, data);
    }
    if let Some(maximum) = tx.maximum_amount {
        let maximum = maximum as i64;
        let assets_total = vault_sle_number(&next_vault, 4);
        if maximum != 0 && maximum < assets_total {
            return ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED");
        }
        next_vault = patch_number_field(&next_vault, 3, maximum);
    }

    if let Some(domain_id) = tx.domain_id {
        let next_issuance = if domain_id == [0u8; 32] {
            remove_sle_field(&issuance_raw, 5, 34)
        } else {
            patch_hash256_field(&issuance_raw, 34, domain_id)
        };
        state.insert_raw(issuance_key, next_issuance);
    }

    state.insert_raw(vault_key, next_vault);
    ApplyResult::Success
}

/// Type 70: VaultClawback — issuer recovers assets from the vault, or the
/// vault owner burns stale share tokens when the vault has no assets.
///
/// Mirrors rippled's two successful paths: the owner may burn stale share
/// MPTokens once the vault has no assets, and a clawback-enabled IOU/MPT issuer
/// may recover vault assets by destroying the holder's proportional shares.
pub(crate) fn apply_vault_clawback(
    state: &mut LedgerState,
    tx: &ParsedTx,
    _ctx: &TxContext,
) -> ApplyResult {
    let vault_key = match tx.vault_id {
        Some(id) if id != [0u8; 32] => Key(id),
        _ => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let holder = match tx.holder {
        Some(holder) if holder != [0u8; 20] => holder,
        _ => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    if matches!(tx.amount.as_ref(), Some(Amount::Xrp(_))) {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    let vault_raw = match state.get_raw(&vault_key) {
        Some(raw) => raw.to_vec(),
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    let owner = match vault_sle_owner(&vault_raw) {
        Some(owner) => owner,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let vault_asset = vault_sle_asset(&vault_raw).unwrap_or(Issue::Xrp);
    let share_mptid = match vault_sle_share_mptid(&vault_raw) {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("tecINTERNAL"),
    };
    let share_issue = Issue::Mpt(share_mptid);

    let claw_issue = match tx.amount.as_ref() {
        Some(amount) => match issue_from_amount(amount) {
            Some(issue) => issue,
            None => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
        },
        None if tx.account == owner => share_issue.clone(),
        None => vault_asset.clone(),
    };

    if claw_issue == share_issue {
        if tx.account != owner {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }

        let assets_total = vault_sle_number(&vault_raw, 4);
        let assets_available = vault_sle_number(&vault_raw, 2);
        let issuance_key = mpt_issuance_key(&share_mptid);
        let issuance_raw = match state.get_raw(&issuance_key) {
            Some(raw) => raw.to_vec(),
            None => return ApplyResult::ClaimedCost("tefINTERNAL"),
        };
        let outstanding = sle_uint64(&issuance_raw, SF_OUTSTANDING_AMOUNT);
        if outstanding == 0 || assets_total != 0 || assets_available != 0 {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }

        let holder_token_key = mptoken_key(&issuance_key.0, &holder);
        let holder_token_raw = match state.get_raw(&holder_token_key) {
            Some(raw) => raw.to_vec(),
            None => return ApplyResult::ClaimedCost("tecPRECISION_LOSS"),
        };
        let holder_shares = sle_uint64(&holder_token_raw, SF_MPT_AMOUNT);
        if holder_shares == 0 {
            return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
        }
        if let Some(amount) = tx.amount.as_ref() {
            let Some((requested, requested_mptid)) = amount.mpt_parts() else {
                return ApplyResult::ClaimedCost("tecWRONG_ASSET");
            };
            if requested_mptid != share_mptid {
                return ApplyResult::ClaimedCost("tecWRONG_ASSET");
            }
            if requested != 0 && requested != holder_shares {
                return ApplyResult::ClaimedCost("tecLIMIT_EXCEEDED");
            }
        }
        if outstanding < holder_shares {
            return ApplyResult::ClaimedCost("tecINTERNAL");
        }

        let issuance_raw = patch_uint64_field(
            &issuance_raw,
            3,
            SF_OUTSTANDING_AMOUNT,
            outstanding - holder_shares,
        );
        state.insert_raw(issuance_key, issuance_raw);

        let holder_token_raw = patch_uint64_field(&holder_token_raw, 3, SF_MPT_AMOUNT, 0);
        if holder != owner {
            directory::dir_remove(state, &holder, &holder_token_key.0);
            state.remove_raw(&holder_token_key);
        } else {
            state.insert_raw(holder_token_key, holder_token_raw);
        }

        return ApplyResult::Success;
    }

    if claw_issue == vault_asset {
        if matches!(vault_asset, Issue::Xrp) {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }

        let asset_issuer = match vault_asset {
            Issue::Iou { issuer, .. } => issuer,
            Issue::Mpt(mptid) => mptoken::mpt_issuer(&mptid),
            Issue::Xrp => unreachable!("XRP handled above"),
        };
        if tx.account != asset_issuer || tx.account == holder {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
        match vault_asset {
            Issue::Iou { .. } => {
                let Some(issuer_account) = state.get_account(&tx.account) else {
                    return ApplyResult::ClaimedCost("tefINTERNAL");
                };
                if (issuer_account.flags & crate::ledger::account::LSF_ALLOW_TRUST_LINE_CLAWBACK)
                    == 0
                    || (issuer_account.flags & crate::ledger::account::LSF_NO_FREEZE) != 0
                {
                    return ApplyResult::ClaimedCost("tecNO_PERMISSION");
                }
            }
            Issue::Mpt(mptid) => {
                let issuance_key = mptoken::mpt_issuance_key(&mptid);
                let Some(issuance_raw) = state.get_raw(&issuance_key) else {
                    return ApplyResult::ClaimedCost("tecOBJECT_NOT_FOUND");
                };
                if mptoken::sle_flags(issuance_raw)
                    & crate::ledger::tx::mptoken::LSF_MPT_CAN_CLAWBACK
                    == 0
                {
                    return ApplyResult::ClaimedCost("tecNO_PERMISSION");
                }
            }
            Issue::Xrp => unreachable!("XRP handled above"),
        }

        let pseudo_id = match vault_sle_pseudo_id(&vault_raw) {
            Some(id) => id,
            None => return ApplyResult::ClaimedCost("tecINTERNAL"),
        };
        let issuance_key = mpt_issuance_key(&share_mptid);
        let issuance_raw = match state.get_raw(&issuance_key) {
            Some(raw) => raw.to_vec(),
            None => return ApplyResult::ClaimedCost("tefINTERNAL"),
        };
        let outstanding = sle_uint64(&issuance_raw, SF_OUTSTANDING_AMOUNT);
        let holder_token_key = mptoken_key(&issuance_key.0, &holder);
        let holder_token_raw = match state.get_raw(&holder_token_key) {
            Some(raw) => raw.to_vec(),
            None => return ApplyResult::ClaimedCost("tecPRECISION_LOSS"),
        };
        let holder_shares = sle_uint64(&holder_token_raw, SF_MPT_AMOUNT);
        if holder_shares == 0 || outstanding == 0 {
            return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
        }

        let assets_total = vault_sle_number(&vault_raw, 4).max(0) as u64;
        let assets_available = vault_sle_number(&vault_raw, 2).max(0) as u64;
        if assets_total == 0 || assets_available == 0 {
            return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
        }

        let requested_assets = match tx.amount.as_ref() {
            Some(Amount::Iou { value, .. }) if !value.is_zero() => {
                let Some(units) = amount_units(tx.amount.as_ref().expect("amount checked")) else {
                    return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
                };
                if units == 0 {
                    return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
                }
                units
            }
            Some(amount) => amount_units(amount).unwrap_or(0),
            None => 0,
        };
        let mut assets_recovered = if requested_assets == 0 {
            ((holder_shares as u128 * assets_total as u128) / outstanding as u128) as u64
        } else {
            requested_assets
        };
        assets_recovered = assets_recovered.min(assets_available);
        if assets_recovered == 0 {
            return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
        }

        let mut shares_destroyed =
            ((assets_recovered as u128 * outstanding as u128) / assets_total as u128) as u64;
        shares_destroyed = shares_destroyed.min(holder_shares);
        if shares_destroyed == 0 {
            return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
        }
        let assets_recovered =
            ((shares_destroyed as u128 * assets_total as u128) / outstanding as u128) as u64;
        if assets_recovered == 0 || assets_recovered > assets_available {
            return ApplyResult::ClaimedCost("tecPRECISION_LOSS");
        }

        let Some(asset_amount) = amount_from_issue(&vault_asset, assets_recovered) else {
            return ApplyResult::ClaimedCost("tecINTERNAL");
        };
        if !asset_flow::apply_amount_delta(state, &pseudo_id, AssetDelta::Debit, &asset_amount) {
            return ApplyResult::ClaimedCost("tecINSUFFICIENT_FUNDS");
        }
        if matches!(vault_asset, Issue::Mpt(_))
            && !asset_flow::apply_amount_delta(
                state,
                &tx.account,
                AssetDelta::Credit,
                &asset_amount,
            )
        {
            return ApplyResult::ClaimedCost("tecINTERNAL");
        }

        let vault_raw = patch_number_field(&vault_raw, 4, (assets_total - assets_recovered) as i64);
        let vault_raw =
            patch_number_field(&vault_raw, 2, (assets_available - assets_recovered) as i64);
        state.insert_raw(vault_key, vault_raw);

        let issuance_raw = patch_uint64_field(
            &issuance_raw,
            3,
            SF_OUTSTANDING_AMOUNT,
            outstanding - shares_destroyed,
        );
        state.insert_raw(issuance_key, issuance_raw);
        let holder_token_raw = patch_uint64_field(
            &holder_token_raw,
            3,
            SF_MPT_AMOUNT,
            holder_shares - shares_destroyed,
        );
        if holder != owner && holder_shares == shares_destroyed {
            directory::dir_remove(state, &holder, &holder_token_key.0);
            state.remove_raw(&holder_token_key);
        } else {
            state.insert_raw(holder_token_key, holder_token_raw);
        }

        return ApplyResult::Success;
    }

    ApplyResult::ClaimedCost("tecWRONG_ASSET")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_sle_round_trip() {
        let owner = [1u8; 20];
        let pseudo = [2u8; 20];
        let mptid = [3u8; 24];

        let raw = build_vault_sle(&owner, &pseudo, 42, &mptid, 7, 0, &Issue::Xrp, 0, None);

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
