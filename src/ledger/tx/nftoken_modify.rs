//! NFTokenModify — type 61 (amendment: DynamicNFT).
//!
//! Modifies the URI on an existing mutable NFToken within its NFTokenPage.
//! The NFToken must have been minted with the tfMutable flag (0x0010).
//!
//! Fields:
//!   - NFTokenID (required, uint256): the token to modify
//!   - URI (optional, VL): new URI (1-256 bytes), or absent to clear
//!   - Owner (optional, Account): the token owner (must differ from sender)
//!
//! Validation (rippled NFTokenModify.cpp):
//!   - Sender must be the issuer, or the issuer's authorized NFTokenMinter
//!   - NFToken must have tfMutable flag set
//!   - URI must be 1-256 bytes if present
//!
//! No directory or owner_count changes.
//!
//! (rippled: NFTokenModify.cpp — doApply calls nft::changeTokenURI)

use super::ApplyResult;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

const MAX_NFTOKEN_URI_BYTES: usize = 256;
const SF_NFTOKEN_MINTER: (u16, u16) = (8, 9);

/// Type 61: NFTokenModify — update URI on a mutable NFToken.
///
/// No structural changes: no SLEs created/deleted, no directory or owner_count
/// modifications.
pub(crate) fn apply_nftoken_modify(state: &mut LedgerState, tx: &ParsedTx) -> ApplyResult {
    let nftoken_id = match tx.nftoken_id {
        Some(id) => id,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    if tx.flags != 0 {
        return ApplyResult::ClaimedCost("temINVALID_FLAG");
    }
    if tx
        .uri
        .as_ref()
        .is_some_and(|uri| uri.len() > MAX_NFTOKEN_URI_BYTES)
    {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    let owner = match tx.owner {
        Some(owner) => owner,
        None => state.nftoken_page_owner(&nftoken_id).unwrap_or(tx.account),
    };
    let nft = match load_nftoken_for_modify(state, &owner, &nftoken_id) {
        Some(nft) => nft,
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };
    if nft.owner != owner {
        return ApplyResult::ClaimedCost("tecNO_ENTRY");
    }
    if nft.flags & crate::ledger::nftoken::TF_MUTABLE == 0 {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if tx.account != nft.issuer && !is_authorized_nftoken_minter(state, &nft.issuer, &tx.account) {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    if state.update_nftoken_uri_paged(&owner, &nftoken_id, tx.uri.clone()) {
        ApplyResult::Success
    } else {
        ApplyResult::ClaimedCost("tecNO_ENTRY")
    }
}

fn load_nftoken_for_modify(
    state: &LedgerState,
    owner: &[u8; 20],
    id: &[u8; 32],
) -> Option<crate::ledger::NFToken> {
    if let Some(nft) = state.get_nftoken(id) {
        let mut nft = nft.clone();
        if nft.issuer == [0u8; 20] || nft.issuer == nft.owner {
            nft.issuer.copy_from_slice(&id[4..24]);
        }
        nft.flags = u16::from_be_bytes([id[0], id[1]]);
        nft.transfer_fee = u16::from_be_bytes([id[2], id[3]]);
        return Some(nft);
    }

    let page_token = state.get_nftoken_from_pages(id)?;
    let actual_owner = state.nftoken_page_owner(id)?;
    if &actual_owner != owner {
        return None;
    }
    let flags = u16::from_be_bytes([id[0], id[1]]);
    let transfer_fee = u16::from_be_bytes([id[2], id[3]]);
    let mut issuer = [0u8; 20];
    issuer.copy_from_slice(&id[4..24]);
    Some(crate::ledger::NFToken {
        nftoken_id: *id,
        owner: actual_owner,
        issuer,
        uri: page_token.uri.clone(),
        flags,
        transfer_fee,
        taxon: 0,
    })
}

fn is_authorized_nftoken_minter(state: &LedgerState, issuer: &[u8; 20], sender: &[u8; 20]) -> bool {
    let Some(account) = state.get_account(issuer) else {
        return false;
    };
    let Some(raw) = account.raw_sle.as_ref() else {
        return false;
    };
    let sle = crate::ledger::sle::SLE::new(
        crate::ledger::account::shamap_key(issuer),
        crate::ledger::sle::LedgerEntryType::AccountRoot,
        raw.clone(),
    );
    sle.get_field_account(SF_NFTOKEN_MINTER.0, SF_NFTOKEN_MINTER.1)
        .as_ref()
        == Some(sender)
}
