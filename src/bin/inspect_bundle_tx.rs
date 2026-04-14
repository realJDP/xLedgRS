use std::path::PathBuf;

use xrpl::ledger::ter::TxResult;
use xrpl::ledger::close::replay_ledger;
use xrpl::ledger::forensic::loader;
use xrpl::ledger::{Key, LedgerState};
use xrpl::crypto::sha512_first_half;
use xrpl::transaction::amount::Amount;
use xrpl::transaction::parse::parse_blob;
use xrpl::transaction::serialize::PREFIX_TX_ID;

#[derive(Clone)]
struct ReplayOrderedTx {
    tx_index: u32,
    tx_id: [u8; 32],
    blob: Vec<u8>,
    meta: Vec<u8>,
}

fn read_field_header(data: &[u8], pos: usize) -> (u16, u16, usize) {
    if pos >= data.len() {
        return (0, 0, pos);
    }
    let b = data[pos];
    let top = (b >> 4) as u16;
    let bot = (b & 0x0F) as u16;

    if top == 0 && bot == 0 {
        if pos + 3 > data.len() {
            return (0, 0, data.len());
        }
        (data[pos + 1] as u16, data[pos + 2] as u16, pos + 3)
    } else if top == 0 {
        if pos + 2 > data.len() {
            return (0, 0, data.len());
        }
        (data[pos + 1] as u16, bot, pos + 2)
    } else if bot == 0 {
        if pos + 2 > data.len() {
            return (0, 0, data.len());
        }
        (top, data[pos + 1] as u16, pos + 2)
    } else {
        (top, bot, pos + 1)
    }
}

fn decode_vl_length(data: &[u8], pos: usize) -> (usize, usize) {
    if pos >= data.len() {
        return (0, 0);
    }
    let b1 = data[pos] as usize;
    if b1 <= 192 {
        (b1, 1)
    } else if b1 <= 240 {
        if pos + 1 >= data.len() {
            return (0, 1);
        }
        let b2 = data[pos + 1] as usize;
        (193 + ((b1 - 193) * 256) + b2, 2)
    } else if b1 <= 254 {
        if pos + 2 >= data.len() {
            return (0, 1);
        }
        let b2 = data[pos + 1] as usize;
        let b3 = data[pos + 2] as usize;
        (12481 + ((b1 - 241) * 65536) + (b2 * 256) + b3, 3)
    } else {
        (0, 1)
    }
}

fn skip_field_raw(data: &[u8], pos: usize, tc: u16) -> usize {
    if pos >= data.len() {
        return data.len();
    }
    match tc {
        1 => (pos + 2).min(data.len()),
        2 => (pos + 4).min(data.len()),
        3 => (pos + 8).min(data.len()),
        4 => (pos + 16).min(data.len()),
        5 => (pos + 32).min(data.len()),
        6 => {
            if (data[pos] & 0x80) != 0 {
                (pos + 48).min(data.len())
            } else if (data[pos] & 0x20) != 0 {
                (pos + 33).min(data.len())
            } else {
                (pos + 8).min(data.len())
            }
        }
        7 | 8 | 19 => {
            let (vl_len, vl_bytes) = decode_vl_length(data, pos);
            (pos + vl_bytes + vl_len).min(data.len())
        }
        9 => (pos + 8).min(data.len()),
        10 => (pos + 4).min(data.len()),
        11 => (pos + 8).min(data.len()),
        14 => {
            let mut p = pos;
            skip_to_object_end(data, &mut p);
            p
        }
        15 => {
            let mut p = pos;
            skip_to_array_end(data, &mut p);
            p
        }
        16 => (pos + 1).min(data.len()),
        17 => (pos + 20).min(data.len()),
        18 => {
            let mut p = pos;
            while p < data.len() && data[p] != 0x00 {
                if data[p] == 0xFF {
                    p += 1;
                } else {
                    let ptype = data[p];
                    p += 1;
                    if ptype & 0x01 != 0 {
                        p += 20;
                    }
                    if ptype & 0x10 != 0 {
                        p += 20;
                    }
                    if ptype & 0x20 != 0 {
                        p += 20;
                    }
                }
            }
            if p < data.len() {
                p += 1;
            }
            p.min(data.len())
        }
        20 => (pos + 12).min(data.len()),
        21 => (pos + 24).min(data.len()),
        22 => (pos + 48).min(data.len()),
        23 => (pos + 64).min(data.len()),
        24 => {
            if pos + 20 > data.len() {
                return data.len();
            }
            let all_zero = data[pos..pos + 20].iter().all(|&b| b == 0);
            if all_zero {
                (pos + 20).min(data.len())
            } else {
                (pos + 40).min(data.len())
            }
        }
        26 => (pos + 20).min(data.len()),
        _ => data.len(),
    }
}

fn skip_to_object_end(data: &[u8], pos: &mut usize) {
    let mut depth = 1;
    while *pos < data.len() && depth > 0 {
        let (tc, fc, new_pos) = read_field_header(data, *pos);
        *pos = new_pos;

        if tc == 14 && fc == 1 {
            depth -= 1;
        } else if tc == 15 && fc == 1 {
            depth -= 1;
        } else if tc == 14 {
            depth += 1;
        } else if tc == 15 {
            skip_to_array_end(data, pos);
        } else {
            *pos = skip_field_raw(data, *pos, tc);
        }
    }
}

fn skip_to_array_end(data: &[u8], pos: &mut usize) {
    while *pos < data.len() {
        let (tc, fc, new_pos) = read_field_header(data, *pos);
        *pos = new_pos;

        if tc == 15 && fc == 1 {
            return;
        } else if tc == 14 && fc == 1 {
            return;
        } else if tc == 14 {
            skip_to_object_end(data, pos);
        } else if tc == 15 {
            skip_to_array_end(data, pos);
        } else {
            *pos = skip_field_raw(data, *pos, tc);
        }
    }
}

fn metadata_result(meta: &[u8]) -> Option<TxResult> {
    metadata_scan(meta, |type_code, field_code, data| {
        if type_code == 16 && field_code == 3 && !data.is_empty() {
            Some(TxResult::from_code(data[0] as i32))
        } else {
            None
        }
    })
}

fn metadata_amount_fields(meta: &[u8]) -> Vec<(u16, Amount)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < meta.len() {
        let (type_code, field_code, new_pos) = read_field_header(meta, pos);
        if new_pos > meta.len() {
            break;
        }
        pos = new_pos;

        if type_code == 6 {
            if let Ok((amount, consumed)) = Amount::from_bytes(&meta[pos..]) {
                out.push((field_code, amount));
                pos = pos.saturating_add(consumed).min(meta.len());
                continue;
            }
        }

        let next = skip_field_raw(meta, pos, type_code);
        if next <= pos {
            break;
        }
        pos = next;
    }
    out
}

fn metadata_scan<T>(
    meta: &[u8],
    mut visit: impl FnMut(u16, u16, &[u8]) -> Option<T>,
) -> Option<T> {
    let mut pos = 0;
    while pos < meta.len() {
        let (type_code, field_code, new_pos) = read_field_header(meta, pos);
        if new_pos > meta.len() {
            break;
        }
        pos = new_pos;

        let next = skip_field_raw(meta, pos, type_code);
        if next <= pos {
            break;
        }
        if let Some(found) = visit(type_code, field_code, &meta[pos..next]) {
            return Some(found);
        }
        pos = next;
    }
    None
}

fn load_replay_ordered_txs(bundle: &std::path::Path) -> Vec<ReplayOrderedTx> {
    let mut txs = Vec::new();
    for (blob, meta) in loader::load_tx_blobs(bundle).expect("load_tx_blobs") {
        let tx_id = {
            let mut data = Vec::with_capacity(4 + blob.len());
            data.extend_from_slice(&PREFIX_TX_ID);
            data.extend_from_slice(&blob);
            sha512_first_half(&data)
        };
        let (tx_index_opt, _nodes) = xrpl::ledger::meta::parse_metadata_with_index(&meta);
        let tx_index = tx_index_opt.expect("tx metadata must carry sfTransactionIndex");
        txs.push(ReplayOrderedTx { tx_index, tx_id, blob, meta });
    }
    txs.sort_by_key(|tx| tx.tx_index);
    txs
}

fn main() {
    let mut args = std::env::args().skip(1);
    let bundle = PathBuf::from(args.next().expect("bundle path"));
    let selector = args.next().expect("tx index or 'all'");
    let replay_mode = args.next().as_deref() == Some("--replay");

    let replay_txs = load_replay_ordered_txs(&bundle);
    if selector == "all" {
        for txw in &replay_txs {
            let tx = parse_blob(&txw.blob).expect("parse_blob");
            let meta_result = metadata_result(&txw.meta);
            println!(
                "index={} tx_type={} seq={} meta_result={} ticket_count={:?} acct={} txid={} signing_hash={}",
                txw.tx_index,
                tx.tx_type,
                tx.sequence,
                meta_result.map(|result| result.token()).unwrap_or("-"),
                tx.ticket_count,
                hex::encode_upper(tx.account),
                hex::encode_upper(txw.tx_id),
                hex::encode_upper(tx.signing_hash),
            );
        }
        return;
    }

    let index: usize = selector.parse().expect("tx index must be usize");
    let txw = replay_txs.get(index).expect("tx index in range");
    let tx = parse_blob(&txw.blob).expect("parse_blob");

    println!("tx_index={}", txw.tx_index);
    println!("tx_id={}", hex::encode_upper(txw.tx_id));
    println!("tx_type={}", tx.tx_type);
    println!("flags=0x{:08X}", tx.flags);
    println!("sequence={}", tx.sequence);
    println!("ticket_count={:?}", tx.ticket_count);
    println!("ticket_sequence={:?}", tx.ticket_sequence);
    println!("offer_sequence={:?}", tx.offer_sequence);
    println!("last_ledger_seq={:?}", tx.last_ledger_seq);
    println!("account={}", hex::encode_upper(tx.account));
    println!("destination={}", tx.destination.map(hex::encode_upper).unwrap_or_else(|| "-".to_string()));
    println!("amount={:?}", tx.amount);
    println!("send_max={:?}", tx.send_max);
    println!("taker_pays={:?}", tx.taker_pays);
    println!("taker_gets={:?}", tx.taker_gets);
    println!("set_flag={:?}", tx.set_flag);
    println!("clear_flag={:?}", tx.clear_flag);
    println!("transfer_rate={:?}", tx.transfer_rate);
    println!("signing_hash={}", hex::encode_upper(tx.signing_hash));
    let library_meta = xrpl::ledger::meta::parse_metadata_summary(&txw.meta);
    if let Some(result) = metadata_result(&txw.meta) {
        println!("meta_result={} ({})", result.token(), result.code());
    } else {
        println!("meta_result=-");
    }
    println!(
        "library_meta_result={}",
        library_meta
            .result
            .map(|result| format!("{} ({})", result.token(), result.code()))
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "library_delivered={:?}",
        library_meta.delivered_amount
    );
    for (field_code, amount) in metadata_amount_fields(&txw.meta) {
        println!("meta_amount_field=(6,{field_code}) {:?}", amount);
    }

    if replay_mode {
        let anchor_header = loader::load_anchor_header(&bundle).expect("load_anchor_header");
        let validated_header = loader::load_validated_header(&bundle).expect("load_validated_header");
        let prestate = loader::load_prestate(&bundle).expect("load_prestate");
        let tx_blobs: Vec<(Vec<u8>, Vec<u8>)> = replay_txs.iter()
            .map(|tx| (tx.blob.clone(), tx.meta.clone()))
            .collect();

        let mut state = LedgerState::new();
        for (k, bytes) in &prestate {
            state.insert_raw(Key(*k), bytes.clone());
        }

        let replay = replay_ledger(
            &anchor_header,
            &mut state,
            tx_blobs.clone(),
            &validated_header,
            true,
        );
        let row = replay.per_tx_attribution.iter()
            .find(|row| row.tx_index as usize == index)
            .expect("tx attribution row");
        println!("current_ter={}", row.ter_token);
        println!("current_created={}", row.created_keys.len());
        for key in &row.created_keys {
            println!("  created={}", hex::encode_upper(key));
        }
        println!("current_modified={}", row.modified_keys.len());
        for key in &row.modified_keys {
            println!("  modified={}", hex::encode_upper(key));
        }
    }
}
