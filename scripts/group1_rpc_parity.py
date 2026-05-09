#!/usr/bin/env python3
"""Same-ledger RPC parity runner for Group 1 shadow evidence."""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


VOLATILE_KEYS = {
    "id",
    "status",
    "warning",
    "warnings",
    "time",
    "uptime",
    "pubkey_node",
    "pubkey_validator",
    "hostid",
    "build_version",
    "io_latency_ms",
    "jq_trans_overflow",
    "load_factor",
    "load_factor_server",
    "peers",
    "server_state_duration_us",
    "validated_ledger_age",
}


def endpoint(value):
    if ":" not in value:
        raise argparse.ArgumentTypeError("endpoint must be HOST:PORT")
    host, port = value.rsplit(":", 1)
    return host, int(port)


def rpc_call(host, port, method, params=None, timeout=10):
    body = json.dumps({"method": method, "params": [params or {}], "id": 1}).encode()
    req = urllib.request.Request(
        f"http://{host}:{port}/",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"result": {"status": "error", "error": str(exc)}}


def result_status(value):
    result = value.get("result", {})
    if result.get("status") == "error" or "error" in result:
        return "error", result.get("error") or result.get("error_message") or str(result)
    return "success", None


def normalized(value):
    if isinstance(value, dict):
        return {
            key: normalized(item)
            for key, item in sorted(value.items())
            if key not in VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [normalized(item) for item in value]
    return value


def validated_seq(server_info):
    ledger = server_info.get("result", {}).get("info", {}).get("validated_ledger", {})
    seq = ledger.get("seq")
    if isinstance(seq, str) and seq.isdigit():
        return int(seq)
    return seq if isinstance(seq, int) else None


def method_plan(args, ledger_index):
    plan = [
        ("server_info", {}),
        ("server_state", {}),
        ("ledger", {"ledger_index": ledger_index, "transactions": False, "expand": False}),
        ("ledger_data", {"ledger_index": ledger_index, "binary": True, "limit": args.ledger_data_limit}),
    ]
    if args.account:
        plan.append(("account_info", {"account": args.account, "ledger_index": ledger_index}))
        plan.append(("account_tx", {"account": args.account, "ledger_index_min": ledger_index, "ledger_index_max": ledger_index, "binary": True}))
    if args.transaction:
        plan.append(("tx", {"transaction": args.transaction, "binary": True}))
    if args.book_offers_taker_gets and args.book_offers_taker_pays:
        plan.append(
            (
                "book_offers",
                {
                    "ledger_index": ledger_index,
                    "taker_gets": json.loads(args.book_offers_taker_gets),
                    "taker_pays": json.loads(args.book_offers_taker_pays),
                    "limit": args.book_offers_limit,
                },
            )
        )
    return plan


def compare_method(x_endpoint, r_endpoint, method, params, sample_no):
    x_body = rpc_call(*x_endpoint, method, params)
    r_body = rpc_call(*r_endpoint, method, params)
    x_status, x_error = result_status(x_body)
    r_status, r_error = result_status(r_body)
    entry = {
        "kind": "rpc_parity_sample",
        "sample": sample_no,
        "method": method,
        "params": params,
        "xledgrs_status": x_status,
        "rippled_status": r_status,
        "xledgrs_error": x_error,
        "rippled_error": r_error,
        "match": False,
    }
    if x_status != r_status:
        entry["difference"] = "status"
        return entry
    if x_status == "error":
        entry["match"] = x_error == r_error
        entry["difference"] = None if entry["match"] else "error"
        return entry
    x_norm = normalized(x_body.get("result", {}))
    r_norm = normalized(r_body.get("result", {}))
    entry["match"] = x_norm == r_norm
    if not entry["match"]:
        entry["difference"] = "normalized_result"
        entry["xledgrs_normalized"] = x_norm
        entry["rippled_normalized"] = r_norm
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xledgrs", type=endpoint, default=("127.0.0.1", 5005))
    parser.add_argument("--rippled", type=endpoint, default=("127.0.0.1", 51234))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--interval-secs", type=float, default=1.0)
    parser.add_argument("--ledger-data-limit", type=int, default=32)
    parser.add_argument("--account")
    parser.add_argument("--transaction")
    parser.add_argument("--book-offers-taker-gets")
    parser.add_argument("--book-offers-taker-pays")
    parser.add_argument("--book-offers-limit", type=int, default=20)
    parser.add_argument("--allow-ledger-lag", type=int, default=2)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    failures = []
    covered = set()
    skipped = []
    with args.output.open("w", encoding="utf-8") as out:
        header = {
            "kind": "rpc_parity_start",
            "started_unix_ms": int(time.time() * 1000),
            "xledgrs": f"{args.xledgrs[0]}:{args.xledgrs[1]}",
            "rippled": f"{args.rippled[0]}:{args.rippled[1]}",
            "samples": args.samples,
            "allow_ledger_lag": args.allow_ledger_lag,
        }
        out.write(json.dumps(header, sort_keys=True) + "\n")
        if not args.account:
            skipped.extend(["account_info", "account_tx"])
        if not args.transaction:
            skipped.append("tx")
        if not (args.book_offers_taker_gets and args.book_offers_taker_pays):
            skipped.append("book_offers")

        for sample_no in range(1, args.samples + 1):
            x_info = rpc_call(*args.xledgrs, "server_info")
            r_info = rpc_call(*args.rippled, "server_info")
            x_seq = validated_seq(x_info)
            r_seq = validated_seq(r_info)
            if x_seq is None or r_seq is None:
                failures.append("validated sequence unavailable from one or both endpoints")
                ledger_index = "validated"
            else:
                lag = abs(x_seq - r_seq)
                if lag > args.allow_ledger_lag:
                    failures.append(f"validated sequence lag {lag} exceeds {args.allow_ledger_lag}")
                ledger_index = min(x_seq, r_seq)

            for method, params in method_plan(args, ledger_index):
                covered.add(method)
                entry = compare_method(args.xledgrs, args.rippled, method, params, sample_no)
                out.write(json.dumps(entry, sort_keys=True) + "\n")
                if not entry["match"]:
                    failures.append(f"{method}: {entry.get('difference', 'mismatch')}")
            out.flush()
            if sample_no != args.samples:
                time.sleep(args.interval_secs)

        summary = {
            "kind": "rpc_parity_summary",
            "verdict": "pass" if not failures else "fail",
            "covered_methods": sorted(covered),
            "skipped_methods": sorted(set(skipped)),
            "failures": failures,
        }
        out.write(json.dumps(summary, sort_keys=True) + "\n")

    if failures:
        print(f"RPC parity failed with {len(failures)} failure(s): {failures[:5]}", file=sys.stderr)
        return 1
    print(f"RPC parity passed; covered={','.join(sorted(covered))} skipped={','.join(sorted(set(skipped)))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
