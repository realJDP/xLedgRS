use std::path::PathBuf;

use xrpl::ledger::account::AccountRoot;
use xrpl::ledger::directory::DirectoryNode;
use xrpl::ledger::close::replay_ledger;
use xrpl::ledger::forensic::loader;
use xrpl::ledger::meta::parse_sle;
use xrpl::ledger::offer::Offer;
use xrpl::ledger::{Key, LedgerState};

fn main() {
    let mut args = std::env::args().skip(1);
    let bundle = PathBuf::from(args.next().expect("bundle path"));
    let key_hex = args.next().expect("key hex");
    let include_local = args.next().as_deref() == Some("--replay");

    let key_vec = hex::decode(&key_hex).expect("valid hex key");
    let key: [u8; 32] = key_vec.try_into().expect("32-byte key");

    let prestate = loader::load_prestate(&bundle).expect("load_prestate");
    let reference = loader::load_rippled_reference(&bundle).expect("load_rippled_reference");

    let local = if include_local {
        Some(replay_local_state(&bundle, &prestate))
    } else {
        None
    };

    for (label, map) in [("prestate", &prestate), ("reference", &reference)] {
        println!("== {} ==", label);
        match map.get(&key) {
            Some(raw) => dump_sle(&key, raw),
            None => println!("missing"),
        }
    }
    if let Some(local_state) = local.as_ref() {
        println!("== local_replay ==");
        match local_state.get_raw_owned(&Key(key)) {
            Some(raw) => dump_sle(&key, &raw),
            None => println!("missing"),
        }
    }
}

fn dump_sle(key: &[u8; 32], raw: &[u8]) {
    if raw.len() >= 3 && raw[0] == 0x11 {
        let ty = u16::from_be_bytes([raw[1], raw[2]]);
        println!("type=0x{:04X} len={}", ty, raw.len());
        match ty {
            0x0061 => dump_account_root(raw),
            0x0064 => dump_directory(key, raw),
            0x006F => dump_offer(raw),
            0x0054 => dump_ticket(raw),
            _ => println!("raw_prefix={}", hex::encode_upper(&raw[..raw.len().min(64)])),
        }
    } else {
        println!("non_sle len={} raw_prefix={}", raw.len(), hex::encode_upper(&raw[..raw.len().min(64)]));
    }
}

fn dump_account_root(raw: &[u8]) {
    match AccountRoot::decode(raw) {
        Ok(account) => {
            println!(
                "account={} balance={} sequence={} owner_count={} flags=0x{:08X} ticket_count={} transfer_rate={} prev_lgr={} prev_txn={}",
                hex::encode_upper(account.account_id),
                account.balance,
                account.sequence,
                account.owner_count,
                account.flags,
                account.ticket_count,
                account.transfer_rate,
                account.previous_txn_lgr_seq,
                hex::encode_upper(account.previous_txn_id),
            );
        }
        Err(e) => println!("account_decode_error={e}"),
    }
}

fn dump_directory(key: &[u8; 32], raw: &[u8]) {
    match DirectoryNode::decode(raw, *key) {
        Ok(dir) => {
            println!(
                "key={} root={} owner={:?} prev={} next={} indexes={}",
                hex::encode_upper(dir.key),
                hex::encode_upper(dir.root_index),
                dir.owner.map(hex::encode_upper),
                dir.index_previous,
                dir.index_next,
                dir.indexes.len(),
            );
            for (i, entry) in dir.indexes.iter().enumerate() {
                println!("  [{}] {}", i, hex::encode_upper(entry));
            }
        }
        Err(e) => println!("decode_error={e}"),
    }
}

fn dump_offer(raw: &[u8]) {
    match Offer::decode_from_sle(raw) {
        Some(offer) => {
            println!(
                "account={} sequence={} owner_node={} book_node={} book_dir={} flags=0x{:08X} prev_lgr={} prev_txn={}",
                hex::encode_upper(offer.account),
                offer.sequence,
                offer.owner_node,
                offer.book_node,
                hex::encode_upper(offer.book_directory),
                offer.flags,
                offer.previous_txn_lgr_seq,
                hex::encode_upper(offer.previous_txn_id),
            );
            println!("taker_pays={:?}", offer.taker_pays);
            println!("taker_gets={:?}", offer.taker_gets);
        }
        None => println!("offer_decode_failed"),
    }
}

fn dump_ticket(raw: &[u8]) {
    match parse_sle(raw) {
        Some(parsed) => {
            let mut sequence = None;
            let mut owner_node = None;
            let mut account = None;
            for f in &parsed.fields {
                match (f.type_code, f.field_code) {
                    (2, 41) if f.data.len() >= 4 => {
                        sequence = Some(u32::from_be_bytes(f.data[..4].try_into().unwrap()));
                    }
                    (3, 4) if f.data.len() >= 8 => {
                        owner_node = Some(u64::from_be_bytes(f.data[..8].try_into().unwrap()));
                    }
                    (8, 1) if f.data.len() >= 20 => {
                        account = Some(hex::encode_upper(&f.data[..20]));
                    }
                    _ => {}
                }
            }
            println!(
                "account={} sequence={:?} owner_node={:?} prev_lgr={:?} prev_txn={}",
                account.unwrap_or_else(|| "<missing>".to_string()),
                sequence,
                owner_node,
                parsed.prev_txn_lgrseq,
                parsed.prev_txn_id.map(hex::encode_upper).unwrap_or_else(|| "<none>".to_string()),
            );
        }
        None => println!("ticket_decode_failed"),
    }
}

fn replay_local_state(
    bundle: &std::path::Path,
    prestate: &std::collections::HashMap<[u8; 32], Vec<u8>>,
) -> LedgerState {
    let anchor_header = loader::load_anchor_header(bundle).expect("load_anchor_header");
    let validated_header = loader::load_validated_header(bundle).expect("load_validated_header");
    let tx_blobs = loader::load_tx_blobs(bundle).expect("load_tx_blobs");

    let mut state = LedgerState::new();
    for (k, bytes) in prestate {
        state.insert_raw(Key(*k), bytes.clone());
    }
    let _ = replay_ledger(
        &anchor_header,
        &mut state,
        tx_blobs,
        &validated_header,
        true,
    );
    state
}
