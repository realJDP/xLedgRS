//! PaymentChannel — IMPLEMENTED

use super::{balance_before_fee, owner_reserve_requirement, ApplyResult};
use crate::ledger::account::LSF_REQUIRE_DEST_TAG;
use crate::ledger::directory;
use crate::ledger::LedgerState;
use crate::transaction::ParsedTx;

const LSF_DISALLOW_INCOMING_PAYCHAN: u32 = 0x1000_0000;
const TF_RENEW: u32 = 0x0001_0000;
const TF_CLOSE: u32 = 0x0002_0000;
const TF_UNIVERSAL: u32 = 0xC000_0000;

fn remove_paychan_from_owner_dir(
    state: &mut LedgerState,
    owner: &[u8; 20],
    key: &crate::ledger::Key,
    node: u64,
) -> ApplyResult {
    let root = directory::owner_dir_key(owner);
    if directory::dir_remove_root_page(state, &root, node, &key.0) {
        ApplyResult::Success
    } else if state.get_directory(&root).is_none()
        && state.get_raw(&root).is_none()
        && state.get_committed_raw_owned(&root).is_none()
    {
        ApplyResult::Success
    } else {
        ApplyResult::ClaimedCost("tefBAD_LEDGER")
    }
}

fn remove_paychan_directories(
    state: &mut LedgerState,
    key: &crate::ledger::Key,
    pc: &crate::ledger::PayChannel,
) -> ApplyResult {
    let result = remove_paychan_from_owner_dir(state, &pc.account, key, pc.owner_node);
    if result != ApplyResult::Success {
        return result;
    }
    if pc.destination != pc.account {
        let result =
            remove_paychan_from_owner_dir(state, &pc.destination, key, pc.destination_node);
        if result != ApplyResult::Success {
            return result;
        }
    }
    ApplyResult::Success
}

fn load_paychan(
    state: &mut LedgerState,
    key: &crate::ledger::Key,
) -> Option<crate::ledger::PayChannel> {
    if let Some(existing) = state.get_paychan(key) {
        return Some(existing.clone());
    }
    let raw = state
        .get_raw_owned(key)
        .or_else(|| state.get_committed_raw_owned(key))?;
    let decoded = crate::ledger::PayChannel::from_sle(key, raw)?;
    state.hydrate_paychan(decoded.clone());
    Some(decoded)
}

pub(crate) fn preflight(tx: &ParsedTx) -> Result<(), crate::ledger::ter::TxResult> {
    match tx.tx_type {
        13 => paychan_create_preflight(tx),
        14 => paychan_fund_preflight(tx),
        15 => paychan_claim_preflight(tx),
        _ => Ok(()),
    }
}

fn paychan_create_preflight(tx: &ParsedTx) -> Result<(), crate::ledger::ter::TxResult> {
    if (tx.flags & !TF_UNIVERSAL) != 0 {
        return Err(crate::ledger::ter::TEM_INVALID_FLAG);
    }
    require_xrp_positive_amount(tx)?;
    let Some(destination) = tx.destination else {
        return Err(crate::ledger::ter::TEM_DST_NEEDED);
    };
    if destination == tx.account {
        return Err(crate::ledger::ter::TEM_DST_IS_SRC);
    }
    if tx
        .public_key
        .as_deref()
        .is_none_or(|pk| !crate::ledger::paychan::valid_public_key(pk))
    {
        return Err(crate::ledger::ter::TEM_MALFORMED);
    }
    if tx.settle_delay.is_none() {
        return Err(crate::ledger::ter::TEM_BAD_EXPIRATION);
    }
    Ok(())
}

fn paychan_fund_preflight(tx: &ParsedTx) -> Result<(), crate::ledger::ter::TxResult> {
    if (tx.flags & !TF_UNIVERSAL) != 0 {
        return Err(crate::ledger::ter::TEM_INVALID_FLAG);
    }
    require_xrp_positive_amount(tx)
}

fn paychan_claim_preflight(tx: &ParsedTx) -> Result<(), crate::ledger::ter::TxResult> {
    if (tx.flags & !(TF_UNIVERSAL | TF_RENEW | TF_CLOSE)) != 0 {
        return Err(crate::ledger::ter::TEM_INVALID_FLAG);
    }
    let requested_balance = crate::transaction::parse::parsed_paychan_balance_drops(tx);
    if matches!(requested_balance, Some(0)) || matches!(tx.amount_drops, Some(0)) {
        return Err(crate::ledger::ter::TEM_BAD_AMOUNT);
    }
    if let (Some(balance), Some(amount)) = (requested_balance, tx.amount_drops) {
        if balance > amount {
            return Err(crate::ledger::ter::TEM_BAD_AMOUNT);
        }
    }
    if (tx.flags & TF_RENEW) != 0 && (tx.flags & TF_CLOSE) != 0 {
        return Err(crate::ledger::ter::TEM_MALFORMED);
    }
    if let Some(sig) = &tx.paychan_sig {
        let Some(public_key) = &tx.public_key else {
            return Err(crate::ledger::ter::TEM_MALFORMED);
        };
        let Some(req_balance) = requested_balance else {
            return Err(crate::ledger::ter::TEM_MALFORMED);
        };
        if !crate::ledger::paychan::valid_public_key(public_key) {
            return Err(crate::ledger::ter::TEM_MALFORMED);
        }
        let auth_amount = tx.amount_drops.unwrap_or(req_balance);
        if req_balance > auth_amount {
            return Err(crate::ledger::ter::TEM_BAD_AMOUNT);
        }
        let Some(channel_hash) = tx.channel else {
            return Err(crate::ledger::ter::TEM_MALFORMED);
        };
        if !crate::ledger::paychan::verify_claim_with_public_key(
            public_key,
            &channel_hash,
            auth_amount,
            sig,
        ) {
            return Err(crate::ledger::ter::TEM_BAD_SIGNATURE);
        }
    }
    if let Some(code) = super::credential::check_credential_id_fields(tx) {
        return Err(super::tx_result_from_token(code));
    }
    Ok(())
}

fn require_xrp_positive_amount(tx: &ParsedTx) -> Result<(), crate::ledger::ter::TxResult> {
    match tx.amount {
        Some(crate::transaction::Amount::Xrp(drops)) if drops > 0 => Ok(()),
        _ => Err(crate::ledger::ter::TEM_BAD_AMOUNT),
    }
}

/// Apply PaymentChannelCreate: lock XRP in a channel.
pub(crate) fn apply_paychan_create(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    close_time: u64,
) -> ApplyResult {
    let sequence = super::sequence_proxy(tx);
    let amount = match tx.amount_drops {
        Some(d) if d > 0 => d,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };
    let destination = match tx.destination {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temDST_NEEDED"),
    };
    if destination == tx.account {
        return ApplyResult::ClaimedCost("temDST_IS_SRC");
    }
    let settle_delay = match tx.settle_delay {
        Some(d) => d,
        None => return ApplyResult::ClaimedCost("temBAD_EXPIRATION"),
    };
    let public_key = match &tx.public_key {
        Some(pk) if crate::ledger::paychan::valid_public_key(pk) => pk.clone(),
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
        Some(_) => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let destination_account = match super::load_existing_account(state, &destination) {
        Some(account) => account,
        None => return ApplyResult::ClaimedCost("tecNO_DST"),
    };
    if (destination_account.flags & LSF_DISALLOW_INCOMING_PAYCHAN) != 0 {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if destination_account.sequence == 0 {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }
    if (destination_account.flags & LSF_REQUIRE_DEST_TAG) != 0 && tx.destination_tag.is_none() {
        return ApplyResult::ClaimedCost("tecDST_TAG_NEEDED");
    }
    if matches!(tx.cancel_after, Some(cancel_after) if (close_time as u32) > cancel_after) {
        return ApplyResult::ClaimedCost("tecEXPIRED");
    }

    let pre_fee_balance = balance_before_fee(new_sender.balance, tx.fee);
    let required = owner_reserve_requirement(state, new_sender.owner_count, 1);
    if pre_fee_balance < required {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
    }
    if pre_fee_balance < required.saturating_add(amount) {
        return ApplyResult::ClaimedCost("tecUNFUNDED");
    }

    new_sender.balance = new_sender.balance.saturating_sub(amount);
    new_sender.owner_count += 1;

    let paychan_key = crate::ledger::paychan::shamap_key(&tx.account, &destination, sequence);
    let owner_node = directory::dir_add(state, &tx.account, paychan_key.0);
    // Also add to destination's directory (rippled PaymentChannelCreate.cpp:161)
    let destination_node = if destination != tx.account {
        directory::dir_add(state, &destination, paychan_key.0)
    } else {
        0
    };
    let paychan = crate::ledger::PayChannel {
        account: tx.account,
        destination,
        amount,
        balance: 0,
        settle_delay,
        public_key,
        sequence,
        cancel_after: tx.cancel_after.unwrap_or(0),
        expiration: 0,
        owner_node,
        destination_node,
        source_tag: crate::transaction::parse::parsed_source_tag(tx),
        destination_tag: tx.destination_tag,
        raw_sle: None,
    };
    state.insert_paychan(paychan);

    ApplyResult::Success
}

/// Apply PaymentChannelFund: add XRP to an existing channel.
pub(crate) fn apply_paychan_fund(
    state: &mut LedgerState,
    tx: &ParsedTx,
    new_sender: &mut crate::ledger::AccountRoot,
    close_time: u64,
) -> ApplyResult {
    let channel_hash = match tx.channel {
        Some(h) => h,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };
    let add_amount = match tx.amount_drops {
        Some(d) if d > 0 => d,
        _ => return ApplyResult::ClaimedCost("temBAD_AMOUNT"),
    };

    let key = crate::ledger::Key(channel_hash);
    let mut pc = match load_paychan(state, &key) {
        Some(p) => p,
        None => return ApplyResult::ClaimedCost("tecNO_ENTRY"),
    };

    if paychan_is_expired(&pc, close_time) {
        if pc.account == tx.account {
            state.insert_account(new_sender.clone());
        }
        let result = close_channel(state, &key, &pc);
        if let Some(updated_sender) = state.get_account(&tx.account) {
            *new_sender = updated_sender.clone();
        }
        return result;
    }

    // Only the channel creator can fund it
    if pc.account != tx.account {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    if let Some(extend) = tx.expiration {
        let mut min_expiration = (close_time as u32).saturating_add(pc.settle_delay);
        if pc.expiration != 0 && pc.expiration < min_expiration {
            min_expiration = pc.expiration;
        }
        if extend < min_expiration {
            return ApplyResult::ClaimedCost("temBAD_EXPIRATION");
        }
        pc.expiration = extend;
    }

    let pre_fee_balance = balance_before_fee(new_sender.balance, tx.fee);
    let required = owner_reserve_requirement(state, new_sender.owner_count, 0);
    if pre_fee_balance.saturating_sub(add_amount) < required {
        return ApplyResult::ClaimedCost("tecINSUFFICIENT_RESERVE");
    }
    if pre_fee_balance < required.saturating_add(add_amount) {
        return ApplyResult::ClaimedCost("tecUNFUNDED");
    }

    if super::load_existing_account(state, &pc.destination).is_none() {
        return ApplyResult::ClaimedCost("tecNO_DST");
    }

    new_sender.balance = new_sender.balance.saturating_sub(add_amount);
    pc.amount = pc.amount.saturating_add(add_amount);

    state.insert_paychan(pc);
    ApplyResult::Success
}

/// Apply PaymentChannelClaim: claim XRP from a channel.
pub(crate) fn apply_paychan_claim(
    state: &mut LedgerState,
    tx: &ParsedTx,
    close_time: u64,
) -> ApplyResult {
    if let Some(code) = super::credential::check_credential_id_fields(tx) {
        return ApplyResult::ClaimedCost(code);
    }
    if let Err(code) = super::credential::validate_credential_ids(state, &tx.account, tx) {
        return ApplyResult::ClaimedCost(code);
    }
    if super::credential::remove_expired_credential_ids(state, tx, close_time) {
        return ApplyResult::ClaimedCost("tecEXPIRED");
    }
    let channel_hash = match tx.channel {
        Some(h) => h,
        None => return ApplyResult::ClaimedCost("temMALFORMED"),
    };

    let key = crate::ledger::Key(channel_hash);
    let mut pc = match load_paychan(state, &key) {
        Some(p) => p,
        None => return ApplyResult::ClaimedCost("tecNO_TARGET"),
    };

    if (tx.flags & TF_RENEW) != 0 && (tx.flags & TF_CLOSE) != 0 {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    let requested_balance = crate::transaction::parse::parsed_paychan_balance_drops(tx);
    if matches!(requested_balance, Some(0)) || matches!(tx.amount_drops, Some(0)) {
        return ApplyResult::ClaimedCost("temBAD_AMOUNT");
    }
    if let (Some(balance), Some(amount)) = (requested_balance, tx.amount_drops) {
        if balance > amount {
            return ApplyResult::ClaimedCost("temBAD_AMOUNT");
        }
    }

    if let Some(sig) = &tx.paychan_sig {
        let Some(public_key) = &tx.public_key else {
            return ApplyResult::ClaimedCost("temMALFORMED");
        };
        let Some(req_balance) = requested_balance else {
            return ApplyResult::ClaimedCost("temMALFORMED");
        };
        if !crate::ledger::paychan::valid_public_key(public_key) {
            return ApplyResult::ClaimedCost("temMALFORMED");
        }
        let auth_amount = tx.amount_drops.unwrap_or(req_balance);
        if req_balance > auth_amount {
            return ApplyResult::ClaimedCost("temBAD_AMOUNT");
        }
        if !crate::ledger::paychan::verify_claim_with_public_key(
            public_key,
            &channel_hash,
            auth_amount,
            sig,
        ) {
            return ApplyResult::ClaimedCost("temBAD_SIGNATURE");
        }
    }

    if paychan_is_expired(&pc, close_time) {
        return close_channel(state, &key, &pc);
    }

    if pc.account != tx.account && pc.destination != tx.account {
        return ApplyResult::ClaimedCost("tecNO_PERMISSION");
    }

    // sfBalance is the requested channel balance. sfAmount is only the optional
    // signed authorization ceiling, matching rippled PaymentChannelClaim.
    if let Some(claimed_drops) = requested_balance {
        if pc.destination == tx.account && tx.paychan_sig.is_none() {
            return ApplyResult::ClaimedCost("temBAD_SIGNATURE");
        }
        if let Some(sig) = &tx.paychan_sig {
            if tx.public_key.as_deref() != Some(pc.public_key.as_slice()) {
                return ApplyResult::ClaimedCost("temBAD_SIGNER");
            }
            let authorized_drops = tx.amount_drops.unwrap_or(claimed_drops);
            if claimed_drops > authorized_drops {
                return ApplyResult::ClaimedCost("temBAD_AMOUNT");
            }
            if !pc.verify_claim(authorized_drops, sig) {
                return ApplyResult::ClaimedCost("temBAD_SIGNATURE");
            }
        }
        if claimed_drops > pc.amount {
            return ApplyResult::ClaimedCost("tecUNFUNDED_PAYMENT");
        }
        if claimed_drops <= pc.balance {
            return ApplyResult::ClaimedCost("tecUNFUNDED_PAYMENT");
        }

        let delta = claimed_drops.saturating_sub(pc.balance);
        pc.balance = claimed_drops;

        let Some(dest) = state.get_account(&pc.destination) else {
            return ApplyResult::ClaimedCost("tecNO_DST");
        };
        if dest.flags & crate::ledger::account::LSF_DEPOSIT_AUTH != 0
            && tx.account != pc.destination
            && !has_deposit_preauth(state, &pc.destination, &tx.account)
            && match super::credential::credential_deposit_preauth_authorized(
                state,
                &pc.destination,
                &tx.account,
                tx,
                close_time,
            ) {
                Ok(authorized) => !authorized,
                Err(code) => return ApplyResult::ClaimedCost(code),
            }
        {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
        let mut dest = dest.clone();
        dest.balance = dest.balance.saturating_add(delta);
        state.insert_account(dest);
    } else if tx.paychan_sig.is_some() {
        return ApplyResult::ClaimedCost("temMALFORMED");
    }

    if (tx.flags & TF_RENEW) != 0 {
        if pc.account != tx.account {
            return ApplyResult::ClaimedCost("tecNO_PERMISSION");
        }
        pc.expiration = 0;
    }

    if (tx.flags & TF_CLOSE) != 0 {
        if pc.destination == tx.account || pc.balance >= pc.amount {
            return close_channel(state, &key, &pc);
        }

        let settle_expiration = (close_time as u32).saturating_add(pc.settle_delay);
        if pc.expiration == 0 || pc.expiration > settle_expiration {
            pc.expiration = settle_expiration;
        }
    }

    state.insert_paychan(pc);
    ApplyResult::Success
}

fn paychan_is_expired(pc: &crate::ledger::PayChannel, close_time: u64) -> bool {
    let close_time = close_time as u32;
    (pc.cancel_after != 0 && close_time >= pc.cancel_after)
        || (pc.expiration != 0 && close_time >= pc.expiration)
}

fn close_channel(
    state: &mut LedgerState,
    key: &crate::ledger::Key,
    pc: &crate::ledger::PayChannel,
) -> ApplyResult {
    let result = remove_paychan_directories(state, key, pc);
    if result != ApplyResult::Success {
        return result;
    }

    let refund = pc.amount.saturating_sub(pc.balance);
    if let Some(creator) = state.get_account(&pc.account) {
        let mut creator = creator.clone();
        creator.balance = creator.balance.saturating_add(refund);
        creator.owner_count = creator.owner_count.saturating_sub(1);
        state.insert_account(creator);
    }
    state.remove_paychan(key);

    ApplyResult::Success
}

fn has_deposit_preauth(state: &LedgerState, destination: &[u8; 20], sender: &[u8; 20]) -> bool {
    let key = crate::ledger::deposit_preauth::shamap_key(destination, sender);
    state.has_deposit_preauth(&key)
        || state.get_raw_owned(&key).is_some()
        || state.get_committed_raw_owned(&key).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(byte: u8) -> [u8; 20] {
        [byte; 20]
    }

    fn account(id: [u8; 20], owner_count: u32) -> crate::ledger::AccountRoot {
        crate::ledger::AccountRoot {
            account_id: id,
            balance: 10_000_000,
            sequence: 1,
            owner_count,
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
        }
    }

    fn paychan(owner: [u8; 20], dest: [u8; 20], owner_node: u64) -> crate::ledger::PayChannel {
        crate::ledger::PayChannel {
            account: owner,
            destination: dest,
            amount: 1_000,
            balance: 100,
            settle_delay: 1,
            public_key: vec![0xED; 33],
            sequence: 7,
            cancel_after: 9,
            expiration: 0,
            owner_node,
            destination_node: 0,
            source_tag: None,
            destination_tag: None,
            raw_sle: None,
        }
    }

    fn insert_owner_dir_page(
        state: &mut LedgerState,
        owner: &[u8; 20],
        page_num: u64,
        indexes: Vec<[u8; 32]>,
    ) {
        let root = directory::owner_dir_key(owner);
        let mut dir = if page_num == 0 {
            directory::DirectoryNode::new_owner_root(owner)
        } else {
            directory::DirectoryNode::new_page(&root.0, page_num, Some(*owner))
        };
        dir.indexes = indexes;
        state.insert_directory(dir);
    }

    #[test]
    fn paychan_close_uses_owner_node_hint_with_duplicate_directory_entry() {
        let owner = acct(1);
        let dest = owner;
        let mut state = LedgerState::new();
        state.insert_account(account(owner, 1));
        let pc = paychan(owner, dest, 1);
        let key = pc.key();
        state.insert_paychan(pc);

        let root = directory::owner_dir_key(&owner);
        let mut root_dir = directory::DirectoryNode::new_owner_root(&owner);
        root_dir.indexes.push(key.0);
        root_dir.index_next = 1;
        root_dir.index_previous = 1;
        state.insert_directory(root_dir);
        insert_owner_dir_page(&mut state, &owner, 1, vec![key.0]);

        let tx = ParsedTx {
            account: owner,
            channel: Some(key.0),
            ..Default::default()
        };
        assert_eq!(
            apply_paychan_claim(&mut state, &tx, 9),
            ApplyResult::Success
        );

        assert!(state.get_paychan(&key).is_none());
        assert!(directory::load_directory_fresh(&state, &root)
            .unwrap()
            .indexes
            .contains(&key.0));
        assert!(
            directory::load_directory_fresh(&state, &directory::page_key(&root.0, 1)).is_none()
        );
    }

    #[test]
    fn paychan_close_rejects_stale_owner_node_hint_as_bad_ledger() {
        let owner = acct(1);
        let dest = owner;
        let mut state = LedgerState::new();
        state.insert_account(account(owner, 1));
        let pc = paychan(owner, dest, 1);
        let key = pc.key();
        state.insert_paychan(pc);
        insert_owner_dir_page(&mut state, &owner, 0, vec![key.0]);

        let tx = ParsedTx {
            account: owner,
            channel: Some(key.0),
            ..Default::default()
        };
        assert_eq!(
            apply_paychan_claim(&mut state, &tx, 9),
            ApplyResult::ClaimedCost("tefBAD_LEDGER")
        );
        assert!(state.get_paychan(&key).is_some());
    }

    #[test]
    fn paychan_lookup_hydrates_from_raw_sle() {
        let owner = acct(1);
        let dest = acct(2);
        let mut state = LedgerState::new();
        let pc = paychan(owner, dest, 0);
        let key = pc.key();
        state.insert_raw(key, pc.to_sle_binary());

        let loaded = load_paychan(&mut state, &key).expect("raw paychan hydrates");

        assert_eq!(loaded.account, owner);
        assert_eq!(loaded.destination, dest);
        assert_eq!(loaded.destination_node, 0);
        assert!(state.get_paychan(&key).is_some());
    }
}
