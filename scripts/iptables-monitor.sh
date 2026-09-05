#!/bin/bash
#
# iptables-monitor.sh
#
# Run on wazuh-manager while the attack is in progress. Prints a
# timestamped snapshot whenever a DROP or REJECT rule is added to or
# removed from the INPUT chain — used to observe the active-response
# block being inserted and then auto-removed at the configured timeout.
#
# Usage:
#   bash iptables-monitor.sh [poll_interval_seconds]
#
# Stop with Ctrl+C.

set -uo pipefail

POLL_INTERVAL="${1:-1}"
prev=""

trap 'echo ""; echo "[*] Stopped."; exit 0' INT TERM

echo "[*] Watching INPUT chain for DROP/REJECT changes (poll every ${POLL_INTERVAL}s). Ctrl+C to stop."

while true; do
    curr="$(sudo iptables -L INPUT -n 2>/dev/null | grep -E 'DROP|REJECT')"

    if [ "$curr" != "$prev" ]; then
        echo ""
        echo "===== $(date '+%F %T') ====="
        echo "=== IPTABLES ==="
        if [ -z "$curr" ]; then
            echo "(no DROP/REJECT rules)"
        else
            echo "$curr"
        fi
        prev="$curr"
    fi

    sleep "$POLL_INTERVAL"
done
