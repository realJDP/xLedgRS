#!/usr/bin/env python3
"""Side-by-side RPC load/soak parity gate for Group 1 shadow runs."""

import argparse
import concurrent.futures
import json
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def endpoint(value):
    if ":" not in value:
        raise argparse.ArgumentTypeError("endpoint must be HOST:PORT")
    host, port = value.rsplit(":", 1)
    return host, int(port)


def rpc_call(endpoint_value, method, params, timeout):
    host, port = endpoint_value
    body = json.dumps({"method": method, "params": [params], "id": 1}).encode()
    req = urllib.request.Request(
        f"http://{host}:{port}/",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
        elapsed_ms = (time.perf_counter() - started) * 1000
        parsed = json.loads(raw)
        result = parsed.get("result", {})
        ok = result.get("status") != "error" and "error" not in result
        return elapsed_ms, ok, None if ok else result.get("error", "rpc_error")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return (time.perf_counter() - started) * 1000, False, str(exc)


def percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((pct / 100) * (len(ordered) - 1)))))
    return ordered[idx]


def summarize(samples):
    latencies = [sample["latency_ms"] for sample in samples]
    errors = [sample for sample in samples if not sample["ok"]]
    return {
        "requests": len(samples),
        "ok": len(samples) - len(errors),
        "errors": len(errors),
        "error_rate": (len(errors) / len(samples)) if samples else 1.0,
        "p50_ms": percentile(latencies, 50),
        "p95_ms": percentile(latencies, 95),
        "p99_ms": percentile(latencies, 99),
        "max_ms": max(latencies) if latencies else None,
        "mean_ms": statistics.fmean(latencies) if latencies else None,
        "error_examples": sorted({sample["error"] for sample in errors if sample["error"]})[:5],
    }


def next_request(counter, ledger_data_limit):
    methods = (
        ("server_info", {}),
        ("server_state", {}),
        ("ledger", {"ledger_index": "validated", "transactions": False, "expand": False}),
        ("ledger_data", {"ledger_index": "validated", "binary": True, "limit": ledger_data_limit}),
    )
    return methods[counter % len(methods)]


def run_endpoint(label, endpoint_value, args):
    samples = []
    stop_at = time.time() + args.duration_secs
    counter = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {}
        while time.time() < stop_at or futures:
            while time.time() < stop_at and len(futures) < args.concurrency:
                method, params = next_request(counter, args.ledger_data_limit)
                counter += 1
                future = executor.submit(rpc_call, endpoint_value, method, params, args.timeout_secs)
                futures[future] = method
            done, _ = concurrent.futures.wait(
                futures, timeout=0.1, return_when=concurrent.futures.FIRST_COMPLETED
            )
            for future in done:
                method = futures.pop(future)
                latency_ms, ok, error = future.result()
                samples.append(
                    {
                        "endpoint": label,
                        "method": method,
                        "latency_ms": latency_ms,
                        "ok": ok,
                        "error": error,
                    }
                )
    return samples


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xledgrs", type=endpoint, default=("127.0.0.1", 5005))
    parser.add_argument("--rippled", type=endpoint, default=("127.0.0.1", 51234))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration-secs", type=int, default=60)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout-secs", type=float, default=10.0)
    parser.add_argument("--ledger-data-limit", type=int, default=32)
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    parser.add_argument("--max-p95-ms", type=float, default=2500.0)
    parser.add_argument("--max-p95-ratio", type=float, default=2.0)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    started = int(time.time() * 1000)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        x_future = executor.submit(run_endpoint, "xledgrs", args.xledgrs, args)
        r_future = executor.submit(run_endpoint, "rippled", args.rippled, args)
        x_samples = x_future.result()
        r_samples = r_future.result()

    x_summary = summarize(x_samples)
    r_summary = summarize(r_samples)
    failures = []
    for label, summary in (("xledgrs", x_summary), ("rippled", r_summary)):
        if summary["error_rate"] > args.max_error_rate:
            failures.append(f"{label} error_rate {summary['error_rate']:.4f} exceeds {args.max_error_rate}")
        if summary["p95_ms"] is None or summary["p95_ms"] > args.max_p95_ms:
            failures.append(f"{label} p95_ms {summary['p95_ms']} exceeds {args.max_p95_ms}")
    if x_summary["p95_ms"] and r_summary["p95_ms"]:
        ratio = x_summary["p95_ms"] / max(r_summary["p95_ms"], 1.0)
        if ratio > args.max_p95_ratio:
            failures.append(f"xledgrs p95/rippled p95 ratio {ratio:.3f} exceeds {args.max_p95_ratio}")

    result = {
        "kind": "load_soak_parity_summary",
        "started_unix_ms": started,
        "finished_unix_ms": int(time.time() * 1000),
        "verdict": "pass" if not failures else "fail",
        "run": {
            "duration_secs": args.duration_secs,
            "concurrency": args.concurrency,
            "ledger_data_limit": args.ledger_data_limit,
        },
        "thresholds": {
            "max_error_rate": args.max_error_rate,
            "max_p95_ms": args.max_p95_ms,
            "max_p95_ratio": args.max_p95_ratio,
        },
        "xledgrs": x_summary,
        "rippled": r_summary,
        "failures": failures,
    }
    with args.output.open("w", encoding="utf-8") as out:
        out.write(json.dumps(result, sort_keys=True) + "\n")

    print(json.dumps(result, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
