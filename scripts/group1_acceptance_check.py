#!/usr/bin/env python3
"""Validate Group 1 shadow archive freshness, coverage, metadata, and verdicts."""

import argparse
import json
import sys
import time
from pathlib import Path


REQUIRED_MANIFEST_KEYS = {
    "git_commit",
    "executable",
    "build_profile",
    "os",
    "kernel",
    "xledgrs_endpoint",
    "rippled_endpoint",
    "xledgrs_version_probe",
    "rippled_version_probe",
}


def read_jsonl(path):
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def last_kind(rows, kind):
    for row in reversed(rows):
        if row.get("kind") == kind:
            return row
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--max-age-secs", type=int, default=24 * 3600)
    parser.add_argument("--require-full-state", action="store_true")
    parser.add_argument("--require-load-soak", action="store_true")
    parser.add_argument("--require-peer-wire", action="store_true")
    parser.add_argument("--min-rpc-methods", type=int, default=4)
    args = parser.parse_args()

    failures = []
    benchmark = args.archive / "benchmark.jsonl"
    rpc = args.archive / "rpc-parity.jsonl"
    if not benchmark.exists():
        failures.append("missing benchmark.jsonl")
    if not rpc.exists():
        failures.append("missing rpc-parity.jsonl")

    now_ms = int(time.time() * 1000)
    if benchmark.exists():
        rows = read_jsonl(benchmark)
        header = rows[0] if rows else {}
        summary = last_kind(rows, "live_sync_benchmark_summary")
        if not summary:
            failures.append("benchmark missing summary")
        elif summary.get("verdict") != "pass":
            failures.append(f"benchmark verdict is {summary.get('verdict')}")
        started = header.get("started_unix_ms")
        if not isinstance(started, int) or (now_ms - started) / 1000 > args.max_age_secs:
            failures.append("benchmark artifact is stale or missing started_unix_ms")
        manifest = header.get("manifest", {})
        missing = sorted(key for key in REQUIRED_MANIFEST_KEYS if key not in manifest)
        if missing:
            failures.append(f"benchmark manifest missing keys: {missing}")
        if not manifest.get("rippled_version_probe"):
            failures.append("rippled version probe missing; no live side-by-side proof")
        if not manifest.get("xledgrs_version_probe"):
            failures.append("xledgrs version probe missing")

    if rpc.exists():
        rows = read_jsonl(rpc)
        summary = last_kind(rows, "rpc_parity_summary")
        if not summary:
            failures.append("RPC parity missing summary")
        else:
            if summary.get("verdict") != "pass":
                failures.append(f"RPC parity verdict is {summary.get('verdict')}")
            covered = summary.get("covered_methods", [])
            if len(covered) < args.min_rpc_methods:
                failures.append(f"RPC coverage too low: {covered}")

    full_state_manifest = args.archive / "full-state" / "full_state_manifest.json"
    if args.require_full_state:
        if not full_state_manifest.exists():
            failures.append("missing required full-state manifest")
        else:
            rows = read_jsonl(full_state_manifest)
            summary = last_kind(rows, "full_state_compare_summary")
            if not summary or summary.get("verdict") != "pass":
                failures.append("full-state compare did not pass")

    load_soak = args.archive / "load-soak.jsonl"
    if args.require_load_soak:
        if not load_soak.exists():
            failures.append("missing required load-soak.jsonl")
        else:
            rows = read_jsonl(load_soak)
            summary = last_kind(rows, "load_soak_parity_summary")
            if not summary or summary.get("verdict") != "pass":
                failures.append("load/soak parity did not pass")

    peer_wire = args.archive / "peer-wire.jsonl"
    if args.require_peer_wire:
        if not peer_wire.exists():
            failures.append("missing required peer-wire.jsonl")
        else:
            rows = read_jsonl(peer_wire)
            summary = last_kind(rows, "peer_wire_probe_summary")
            if not summary or summary.get("verdict") != "pass":
                failures.append("peer-wire probe did not pass")

    verdict = "pass" if not failures else "fail"
    print(json.dumps({"kind": "group1_acceptance_summary", "verdict": verdict, "failures": failures}, sort_keys=True))
    if failures:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
