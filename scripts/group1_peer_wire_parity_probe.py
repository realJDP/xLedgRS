#!/usr/bin/env python3
"""Peer-wire handshake parity probe for XRPL Upgrade variants and metadata fields."""

import argparse
import json
import socket
import sys
import time
from pathlib import Path


REQUIRED_HEADERS = {
    "connection",
    "upgrade",
    "server",
}


def read_response(host, port, upgrade, timeout):
    request = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: Upgrade\r\n"
        f"Upgrade: {upgrade}\r\n"
        "Crawl: public\r\n"
        "Network-Time: 0\r\n"
        "\r\n"
    ).encode()
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
    elapsed_ms = (time.perf_counter() - started) * 1000
    text = raw.decode("iso-8859-1", errors="replace")
    head = text.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    status = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return status, headers, elapsed_ms


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=51235)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-secs", type=float, default=5.0)
    parser.add_argument(
        "--upgrade",
        action="append",
        default=["XRPL/2.0", "XRPL/2.2", "RTXP/1.2, XRPL/2.0"],
        help="Upgrade header variant to probe; may be repeated.",
    )
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    failures = []
    rows = []
    for upgrade in args.upgrade:
        try:
            status, headers, elapsed_ms = read_response(
                args.host, args.port, upgrade, args.timeout_secs
            )
            missing = sorted(REQUIRED_HEADERS.difference(headers))
            ok = status.startswith("HTTP/1.1 101") or status.startswith("HTTP/1.0 101")
            if not ok:
                failures.append(f"{upgrade}: expected 101 Switching Protocols, got {status}")
            if missing:
                failures.append(f"{upgrade}: missing headers {missing}")
            rows.append(
                {
                    "kind": "peer_wire_probe",
                    "upgrade": upgrade,
                    "status": status,
                    "headers": headers,
                    "elapsed_ms": elapsed_ms,
                    "missing_required_headers": missing,
                    "ok": ok and not missing,
                }
            )
        except OSError as exc:
            failures.append(f"{upgrade}: {exc}")
            rows.append(
                {
                    "kind": "peer_wire_probe",
                    "upgrade": upgrade,
                    "ok": False,
                    "error": str(exc),
                }
            )

    summary = {
        "kind": "peer_wire_probe_summary",
        "verdict": "pass" if not failures else "fail",
        "failures": failures,
    }
    with args.output.open("w", encoding="utf-8") as out:
        for row in rows:
            out.write(json.dumps(row, sort_keys=True) + "\n")
        out.write(json.dumps(summary, sort_keys=True) + "\n")

    print(json.dumps(summary, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
