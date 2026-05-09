use serde_json::{json, Value};

#[test]
fn server_definitions_matches_committed_mainnet_snapshot_exactly() {
    let expected: Value = serde_json::from_str(include_str!(
        "../src/rpc/data/server_definitions_mainnet_3_1_2.json"
    ))
    .expect("committed server_definitions snapshot must parse");

    let actual = xrpl::rpc::handlers::server_definitions(&json!({}))
        .expect("server_definitions must return committed snapshot");

    assert_eq!(
        actual, expected,
        "server_definitions output must be an exact JSON diff match against the committed mainnet snapshot"
    );
}

#[test]
fn server_definitions_hash_short_circuit_is_exact_and_minimal() {
    let expected: Value = serde_json::from_str(include_str!(
        "../src/rpc/data/server_definitions_mainnet_3_1_2.json"
    ))
    .expect("committed server_definitions snapshot must parse");
    let hash = expected
        .get("hash")
        .and_then(Value::as_str)
        .expect("snapshot must expose hash");

    let actual = xrpl::rpc::handlers::server_definitions(&json!({ "hash": hash }))
        .expect("hash short-circuit must succeed");

    assert_eq!(actual, json!({ "hash": hash }));
}
