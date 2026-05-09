use std::path::PathBuf;

fn repo_file(path: &str) -> String {
    let mut full = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    full.push(path);
    std::fs::read_to_string(&full).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", full.display());
    })
}

fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let needle = format!("fn {name}");
    let start = source
        .find(&needle)
        .unwrap_or_else(|| panic!("missing function {name}"));
    let open = source[start..]
        .find('{')
        .map(|idx| start + idx)
        .unwrap_or_else(|| panic!("missing body for function {name}"));
    let mut depth = 0usize;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[open + 1..open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated body for function {name}");
}

#[test]
fn non_live_transaction_families_have_dual_replay_barriers() {
    let tx_mod = repo_file("src/ledger/tx/mod.rs");
    let required = function_body(&tx_mod, "required_amendment");
    let explicit = function_body(&tx_mod, "requires_explicit_replay_amendment");

    for (label, tx_types, amendment) in [
        (
            "XChainBridge",
            &["41", "42", "43", "44", "45", "46", "47", "48"][..],
            "FEATURE_XCHAIN",
        ),
        (
            "PermissionedDomain",
            &["62", "63"][..],
            "FEATURE_PERMISSIONED_DOMAINS",
        ),
        ("PermissionDelegation", &["64"][..], "FEATURE_DELEGATION"),
        (
            "SingleAssetVault",
            &["65", "66", "67", "68", "69", "70"][..],
            "FEATURE_VAULT",
        ),
        ("Batch", &["71"][..], "FEATURE_BATCH"),
        (
            "LendingProtocol",
            &["74", "75", "76", "77", "78", "80", "81", "82", "84"][..],
            "FEATURE_LENDING",
        ),
    ] {
        assert!(
            tx_types.iter().all(|tx_type| required.contains(tx_type))
                && required.contains(amendment),
            "{label} must stay amendment-gated in required_amendment"
        );
    }

    for pattern in [
        "41..=48",
        "62..=64",
        "65..=70",
        "| 71",
        "74..=78",
        "| 80..=82",
        "| 84",
    ] {
        assert!(
            explicit.contains(pattern),
            "non-live replay barrier missing pattern {pattern}"
        );
    }
}

#[test]
fn validated_replay_checks_non_live_barrier_before_authoritative_metadata() {
    let tx_mod = repo_file("src/ledger/tx/mod.rs");
    let replay_pos = tx_mod
        .find("if trusted_validated_replay")
        .expect("run_tx must have a trusted_validated_replay block");
    let replay_block = &tx_mod[replay_pos..];
    let barrier_pos = replay_block
        .find("requires_explicit_replay_amendment")
        .expect("validated replay must check explicit amendment barrier");
    let metadata_pos = replay_block
        .find("validated_result")
        .expect("validated replay must inspect authoritative metadata");

    assert!(
        barrier_pos < metadata_pos,
        "non-live amendment barrier must run before metadata can claim fees"
    );
}

#[test]
fn group3_source_risks_remain_visible_until_fixed() {
    let close_loop = repo_file("src/node/close_loop.rs");
    let handlers = repo_file("src/rpc/handlers.rs");

    assert!(
        close_loop.contains("Rules::from_amendments(crate::ledger::read_amendments(&ls))"),
        "closed-ledger construction must keep deriving rules from accepted ledger amendments"
    );
    assert!(
        handlers.contains("ledger_enabled_amendment_hashes(ctx)")
            && handlers.contains("closed.get_raw(&crate::ledger::amendments_key())"),
        "feature reporting must stay tied to ledger-derived amendment state"
    );
}
