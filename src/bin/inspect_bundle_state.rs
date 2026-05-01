//! xLedgRS purpose: Inspect Bundle State diagnostic utility for parity investigation.
use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::Parser;
use xrpl::ledger::account;
use xrpl::ledger::directory::DirectoryNode;
use xrpl::ledger::forensic::loader;
use xrpl::ledger::nftoken::NFTokenOffer;
use xrpl::ledger::offer::Offer;
use xrpl::ledger::sle::{LedgerEntryType, SLE};
use xrpl::ledger::trustline::RippleState;
use xrpl::transaction::amount::Amount;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    bundle: PathBuf,

    #[arg(long)]
    key: Option<String>,

    #[arg(long)]
    account: Option<String>,

    #[arg(long)]
    prefix: Vec<String>,

    #[arg(long, default_value_t = 24)]
    limit: usize,
}

fn normalize_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = s.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    Ok(hex::decode(hex)?)
}

fn format_flags(flags: u32, names: &[(&str, u32)]) -> String {
    let mut out = Vec::new();
    for (name, mask) in names {
        if flags & mask != 0 {
            out.push(*name);
        }
    }
    if out.is_empty() {
        "none".to_string()
    } else {
        out.join("|")
    }
}

fn format_account(raw: &[u8]) -> String {
    match account::AccountRoot::decode(raw) {
        Ok(acct) => format!(
            "AccountRoot account={} balance={} sequence={} owner_count={} flags=0x{:08X}[{}] regular_key={} minted={} burned={} transfer_rate={} ticket_count={} prev_txn_lgr_seq={} raw_len={}",
            hex::encode_upper(acct.account_id),
            acct.balance,
            acct.sequence,
            acct.owner_count,
            acct.flags,
            format_flags(
                acct.flags,
                &[
                    ("PASSWORD_SPENT", account::LSF_PASSWORD_SPENT),
                    ("REQUIRE_DEST_TAG", account::LSF_REQUIRE_DEST_TAG),
                    ("REQUIRE_AUTH", account::LSF_REQUIRE_AUTH),
                    ("DISALLOW_XRP", account::LSF_DISALLOW_XRP),
                    ("DISABLE_MASTER", account::LSF_DISABLE_MASTER),
                    ("NO_FREEZE", account::LSF_NO_FREEZE),
                    ("GLOBAL_FREEZE", account::LSF_GLOBAL_FREEZE),
                    ("DEFAULT_RIPPLE", account::LSF_DEFAULT_RIPPLE),
                    ("DEPOSIT_AUTH", account::LSF_DEPOSIT_AUTH),
                ],
            ),
            acct.regular_key
                .map(|key| hex::encode_upper(key))
                .unwrap_or_else(|| "-".to_string()),
            acct.minted_nftokens,
            acct.burned_nftokens,
            acct.transfer_rate,
            acct.ticket_count,
            acct.previous_txn_lgr_seq,
            raw.len(),
        ),
        Err(err) => format!("AccountRoot decode failed: {err:?}"),
    }
}

fn format_currency(raw: &[u8; 20]) -> String {
    let currency = xrpl::transaction::amount::Currency { code: *raw };
    currency.to_ascii()
}

fn format_amount(amount: &Amount) -> String {
    format!("{amount}")
}

fn format_ripple_state(raw: &[u8]) -> String {
    match RippleState::decode_from_sle(raw) {
        Some(state) => format!(
            "RippleState low={} high={} currency={} balance={} low_limit={} high_limit={} flags=0x{:08X}[{}] low_node={} high_node={} low_q_in={} low_q_out={} high_q_in={} high_q_out={} prev_txn_lgr_seq={} raw_len={}",
            hex::encode_upper(state.low_account),
            hex::encode_upper(state.high_account),
            format_currency(&state.currency.code),
            state.balance,
            state.low_limit,
            state.high_limit,
            state.flags,
            format_flags(
                state.flags,
                &[
                    ("LOW_RESERVE", xrpl::ledger::trustline::LSF_LOW_RESERVE),
                    ("HIGH_RESERVE", xrpl::ledger::trustline::LSF_HIGH_RESERVE),
                    ("LOW_AUTH", xrpl::ledger::trustline::LSF_LOW_AUTH),
                    ("HIGH_AUTH", xrpl::ledger::trustline::LSF_HIGH_AUTH),
                    ("LOW_NO_RIPPLE", xrpl::ledger::trustline::LSF_LOW_NO_RIPPLE),
                    ("HIGH_NO_RIPPLE", xrpl::ledger::trustline::LSF_HIGH_NO_RIPPLE),
                    ("LOW_FREEZE", xrpl::ledger::trustline::LSF_LOW_FREEZE),
                    ("HIGH_FREEZE", xrpl::ledger::trustline::LSF_HIGH_FREEZE),
                ],
            ),
            state.low_node,
            state.high_node,
            state.low_quality_in,
            state.low_quality_out,
            state.high_quality_in,
            state.high_quality_out,
            state.previous_txn_lgr_seq,
            raw.len(),
        ),
        None => format!("RippleState decode failed raw_len={}", raw.len()),
    }
}

fn format_directory_node(key: [u8; 32], raw: &[u8]) -> String {
    match DirectoryNode::decode(raw, key) {
        Ok(node) => {
            let preview = node
                .indexes
                .iter()
                .take(3)
                .map(hex::encode_upper)
                .collect::<Vec<_>>()
                .join(",");
            let owner = node
                .owner
                .map(hex::encode_upper)
                .unwrap_or_else(|| "-".to_string());
            let exchange_rate = node
                .exchange_rate
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string());
            format!(
                "DirectoryNode root={} owner={} indexes={} preview=[{}] next={} prev={} exchange_rate={} nftoken_id={} domain_id={} prev_txn_lgr_seq={} raw_len={}",
                hex::encode_upper(node.root_index),
                owner,
                node.indexes.len(),
                preview,
                node.index_next,
                node.index_previous,
                exchange_rate,
                node.nftoken_id
                    .map(hex::encode_upper)
                    .unwrap_or_else(|| "-".to_string()),
                node.domain_id
                    .map(hex::encode_upper)
                    .unwrap_or_else(|| "-".to_string()),
                node.previous_txn_lgr_seq
                    .map(|seq| seq.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                raw.len(),
            )
        }
        Err(err) => format!("DirectoryNode decode failed: {err:?} raw_len={}", raw.len()),
    }
}

fn format_offer(raw: &[u8]) -> String {
    match Offer::decode_from_sle(raw) {
        Some(offer) => format!(
            "Offer account={} sequence={} flags=0x{:08X}[{}] pays={} gets={} book_node={} owner_node={} expiration={} book_directory={} domain_id={} prev_txn_lgr_seq={} raw_len={}",
            hex::encode_upper(offer.account),
            offer.sequence,
            offer.flags,
            format_flags(
                offer.flags,
                &[
                    ("PASSIVE", xrpl::ledger::offer::LSF_PASSIVE),
                    ("SELL", xrpl::ledger::offer::LSF_SELL),
                ],
            ),
            format_amount(&offer.taker_pays),
            format_amount(&offer.taker_gets),
            offer.book_node,
            offer.owner_node,
            offer
                .expiration
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            hex::encode_upper(offer.book_directory),
            offer
                .domain_id
                .map(hex::encode_upper)
                .unwrap_or_else(|| "-".to_string()),
            offer.previous_txn_lgr_seq,
            raw.len(),
        ),
        None => format!("Offer decode failed raw_len={}", raw.len()),
    }
}

fn format_nftoken_offer(raw: &[u8]) -> String {
    match NFTokenOffer::decode_from_sle(raw) {
        Some(offer) => format!(
            "NFTokenOffer account={} sequence={} flags=0x{:08X} amount={} nftoken_id={} owner_node={} nft_offer_node={} destination={} expiration={} prev_txn_lgrseq={} raw_len={}",
            hex::encode_upper(offer.account),
            offer.sequence,
            offer.flags,
            format_amount(&offer.amount),
            hex::encode_upper(offer.nftoken_id),
            offer.owner_node,
            offer.nft_offer_node,
            offer
                .destination
                .map(hex::encode_upper)
                .unwrap_or_else(|| "-".to_string()),
            offer
                .expiration
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            offer.previous_txn_lgrseq,
            raw.len(),
        ),
        None => format!("NFTokenOffer decode failed raw_len={}", raw.len()),
    }
}

fn format_ledger_hashes(key: [u8; 32], raw: &[u8]) -> String {
    match SLE::from_raw(xrpl::ledger::Key(key), raw.to_vec()) {
        Some(sle) => {
            let first_seq = sle
                .get_field_u32(2, 26)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string());
            let last_seq = sle
                .get_field_u32(2, 27)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string());
            let hashes_raw = sle
                .get_field_vl(19, 2)
                .or_else(|| sle.get_field_vl(19, 1))
                .unwrap_or_default();
            let hashes = hashes_raw.len() / 32;
            let preview = hashes_raw
                .chunks_exact(32)
                .take(2)
                .map(hex::encode_upper)
                .collect::<Vec<_>>()
                .join(",");
            let tail = hashes_raw
                .chunks_exact(32)
                .rev()
                .take(2)
                .map(hex::encode_upper)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "LedgerHashes first_seq={} last_seq={} hashes={} preview=[{}] tail=[{}] raw_len={}",
                first_seq,
                last_seq,
                hashes,
                preview,
                tail,
                raw.len(),
            )
        }
        None => format!("LedgerHashes parse failed raw_len={}", raw.len()),
    }
}

fn format_amm(raw: &[u8]) -> String {
    let Some(parsed) = xrpl::ledger::meta::parse_sle(raw) else {
        return format!("AMM parse failed raw_len={}", raw.len());
    };

    let mut fields = Vec::new();
    for field in parsed.fields {
        let value = match (field.type_code, field.field_code) {
            (8, 1) if field.data.len() == 20 => {
                format!("account={}", hex::encode_upper(field.data))
            }
            (24, 3) | (24, 4) => xrpl::transaction::amount::Issue::from_bytes(&field.data)
                .map(|(issue, _)| format!("{issue:?}"))
                .unwrap_or_else(|| format!("raw={}", hex::encode_upper(field.data))),
            (1, 5) | (1, 2) if field.data.len() == 2 => {
                format!("{}", u16::from_be_bytes([field.data[0], field.data[1]]))
            }
            _ => hex::encode_upper(&field.data),
        };
        fields.push(format!(
            "({},{})={}",
            field.type_code, field.field_code, value
        ));
    }

    format!("AMM {} raw_len={}", fields.join(" "), raw.len())
}

fn describe(key: [u8; 32], raw: &[u8]) -> String {
    match SLE::from_raw(xrpl::ledger::Key(key), raw.to_vec()) {
        Some(sle) => match sle.entry_type() {
            LedgerEntryType::AccountRoot => format_account(raw),
            LedgerEntryType::RippleState => format_ripple_state(raw),
            LedgerEntryType::DirectoryNode => format_directory_node(key, raw),
            LedgerEntryType::Offer => format_offer(raw),
            LedgerEntryType::NFTokenOffer => format_nftoken_offer(raw),
            LedgerEntryType::LedgerHashes => format_ledger_hashes(key, raw),
            LedgerEntryType::AMM => format_amm(raw),
            other => format!("{other:?} raw_len={}", raw.len()),
        },
        None => format!("SLE parse failed raw_len={}", raw.len()),
    }
}

fn first_diff(pre: &[u8], refd: &[u8]) -> Option<(usize, u8, u8)> {
    pre.iter()
        .zip(refd.iter())
        .enumerate()
        .find_map(|(idx, (lhs, rhs))| (lhs != rhs).then_some((idx, *lhs, *rhs)))
}

fn prefix_matches(key: &[u8; 32], prefixes: &[Vec<u8>]) -> bool {
    prefixes
        .iter()
        .any(|prefix| key.starts_with(prefix.as_slice()))
}

fn parse_exact_key(args: &Args) -> anyhow::Result<Option<[u8; 32]>> {
    if let Some(key_hex) = args.key.as_deref() {
        let bytes = normalize_hex(key_hex)?;
        anyhow::ensure!(bytes.len() == 32, "--key must be 32 bytes");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(Some(out));
    }
    if let Some(account_hex) = args.account.as_deref() {
        let bytes = normalize_hex(account_hex)?;
        anyhow::ensure!(bytes.len() == 20, "--account must be 20 bytes");
        let mut account_id = [0u8; 20];
        account_id.copy_from_slice(&bytes);
        return Ok(Some(account::shamap_key(&account_id).0));
    }
    Ok(None)
}

fn print_state_line(label: &str, key: [u8; 32], raw: Option<&Vec<u8>>) {
    match raw {
        Some(raw) => println!("  {label}: {}", describe(key, raw)),
        None => println!("  {label}: missing"),
    }
}

fn format_prefixes(prefixes: &[Vec<u8>]) -> String {
    if prefixes.is_empty() {
        "-".to_string()
    } else {
        prefixes
            .iter()
            .map(hex::encode_upper)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let prestate = loader::load_prestate(&args.bundle)?;
    let reference = loader::load_rippled_reference(&args.bundle).unwrap_or_default();

    let exact_key = parse_exact_key(&args)?;
    let prefixes: Vec<Vec<u8>> = args
        .prefix
        .iter()
        .map(|prefix| normalize_hex(prefix))
        .collect::<anyhow::Result<_>>()?;
    for prefix in &prefixes {
        anyhow::ensure!(
            !prefix.is_empty() && prefix.len() <= 32,
            "--prefix must be 1..32 bytes"
        );
    }

    let mut candidates = BTreeSet::new();
    if let Some(key) = exact_key {
        candidates.insert(key);
    }
    if !prefixes.is_empty() {
        for key in prestate.keys().chain(reference.keys()) {
            if prefix_matches(key, &prefixes) {
                candidates.insert(*key);
            }
        }
    }
    if candidates.is_empty() {
        anyhow::bail!("provide --key, --account, or --prefix");
    }

    let candidate_count = candidates.len();
    println!("bundle={}", args.bundle.display());
    println!(
        "query exact={} prefixes={}",
        exact_key
            .map(hex::encode_upper)
            .unwrap_or_else(|| "-".to_string()),
        format_prefixes(&prefixes)
    );
    println!("candidates={} limit={}", candidate_count, args.limit);

    for (idx, key) in candidates.into_iter().take(args.limit).enumerate() {
        println!("candidate #{} key={}", idx + 1, hex::encode_upper(key));
        let pre = prestate.get(&key);
        let refd = reference.get(&key);
        print_state_line("prestate(local)", key, pre);
        print_state_line("reference(rippled)", key, refd);
        match (pre, refd) {
            (Some(pre), Some(refd)) if pre == refd => println!("  status: bytes identical"),
            (Some(pre), Some(refd)) => {
                println!(
                    "  status: bytes differ pre_len={} ref_len={}",
                    pre.len(),
                    refd.len()
                );
                if let Some((offset, pre_byte, ref_byte)) = first_diff(pre, refd) {
                    println!(
                        "  first_diff: offset={} pre=0x{:02X} ref=0x{:02X}",
                        offset, pre_byte, ref_byte
                    );
                } else if pre.len() != refd.len() {
                    println!(
                        "  first_diff: length-only pre_len={} ref_len={}",
                        pre.len(),
                        refd.len()
                    );
                }
            }
            (Some(pre), None) => println!("  status: prestate-only pre_len={}", pre.len()),
            (None, Some(refd)) => println!("  status: reference-only ref_len={}", refd.len()),
            (None, None) => println!("  status: missing from both maps"),
        }
    }

    if candidate_count > args.limit {
        println!(
            "... truncated {} additional candidate(s)",
            candidate_count - args.limit
        );
    }

    Ok(())
}
