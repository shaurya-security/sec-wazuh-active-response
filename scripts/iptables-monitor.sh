#!/bin/bash
# iptables-monitor.sh
# Run on wazuh-manager while the attack is in progress.
# Prints a timestamped snapshot whenever a DROP or REJECT
# rule is added or removed from the INPUT chain.

prev=""

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

    sleep 1
done
