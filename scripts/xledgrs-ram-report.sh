#!/usr/bin/env bash
set -euo pipefail

PID="${1:-}"
if [ -z "$PID" ]; then
    PID="$(pidof xledgrs 2>/dev/null | awk '{print $1}')"
fi

if [ -z "$PID" ] || [ ! -r "/proc/$PID/status" ]; then
    echo "usage: $0 [pid]"
    echo "error: xledgrs PID not found or /proc is unavailable"
    exit 1
fi

echo "xledgrs memory report"
echo "pid: $PID"
ps -o pid,etime,%cpu,%mem,rss,vsz,command -p "$PID"

echo
echo "status:"
grep -E 'VmRSS|VmData|VmSwap|Threads' "/proc/$PID/status" || true

echo
echo "smaps_rollup:"
if [ -r "/proc/$PID/smaps_rollup" ]; then
    grep -E 'Rss:|Pss:|Private_Dirty:|Anonymous:|FilePmdMapped:|Swap:' "/proc/$PID/smaps_rollup" || true
else
    echo "smaps_rollup unavailable"
fi

echo
echo "largest writable mappings:"
if [ -r "/proc/$PID/smaps" ]; then
    awk '
        function print_map() {
            if (rss > 0 && map ~ / rw/) {
                printf "%10d KB rss %10d KB anon %10d KB dirty  %s\n", rss, anon, dirty, map
            }
        }
        /^[0-9a-f]+-/ {
            print_map()
            map=$0
            rss=0
            anon=0
            dirty=0
        }
        /^Rss:/ { rss=$2 }
        /^Anonymous:/ { anon=$2 }
        /^Private_Dirty:/ { dirty=$2 }
        END { print_map() }
    ' "/proc/$PID/smaps" | sort -nr | head -20
else
    echo "smaps unavailable"
fi
