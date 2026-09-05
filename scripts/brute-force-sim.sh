#!/bin/bash
#
# brute-force-sim.sh
#
# Run from bastion-host (public subnet). Simulates a sequential SSH
# brute-force attack against a target in the private subnet. Attempts are
# sequential with a short delay between them — this produces one clean
# threshold crossing rather than a burst that Wazuh's active-response
# deduplication (check_keys) would abort (see docs/debugging-notes.md, #2).
#
# Requires: sshpass, PasswordAuthentication enabled on the target's sshd.
#
# Usage:
#   bash brute-force-sim.sh [target_octet] [attempts]
#
#   target_octet   Last octet of the target's private IP (10.0.2.X).
#                  Prompted for interactively if omitted.
#   attempts       Number of failed attempts to send. Default: 6
#                  (one more than the detection threshold of 5).

set -uo pipefail  # no -e: ssh is *expected* to exit non-zero on auth failure

YELLOW='\e[38;5;226m'
NC='\e[0m'
TARGET_SUBNET_PREFIX="10.0.2"
WRONG_PASSWORD="wrongpassword"
TARGET_USER="ec2-user"
ATTEMPT_DELAY=1

prompt() { echo -ne "${YELLOW}$1${NC}"; }
log()    { echo "[*] $*"; }

ensure_sshpass() {
    if command -v sshpass &>/dev/null; then
        return 0
    fi
    log "Installing sshpass..."
    sudo amazon-linux-extras install epel -y >/dev/null 2>&1
    sudo yum install -y sshpass >/dev/null 2>&1
}

resolve_target() {
    local octet="${1:-}"
    if [ -z "$octet" ]; then
        prompt "Enter target octet (e.g. 77 for ${TARGET_SUBNET_PREFIX}.77): "
        read -r octet
    fi
    if ! [[ "$octet" =~ ^[0-9]{1,3}$ ]] || [ "$octet" -gt 255 ]; then
        echo "Error: '$octet' is not a valid octet (expected 0-255)." >&2
        exit 1
    fi
    echo "${TARGET_SUBNET_PREFIX}.${octet}"
}

run_attack() {
    local target="$1"
    local attempts="$2"

    echo "Initiating SSH brute force -> ${target} (${attempts} attempts)"
    echo ""

    for ((i = 1; i <= attempts; i++)); do
        sshpass -p "$WRONG_PASSWORD" ssh \
            -o StrictHostKeyChecking=no \
            -o PreferredAuthentications=password \
            -o PubkeyAuthentication=no \
            -o ConnectTimeout=5 \
            "${TARGET_USER}@${target}" exit 2>&1 | grep -v "^$" || true
        echo "attempt ${i}/${attempts} | $(date '+%F %T')"
        sleep "$ATTEMPT_DELAY"
    done
}

main() {
    ensure_sshpass
    local target
    target="$(resolve_target "${1:-}")"
    local attempts="${2:-6}"

    run_attack "$target" "$attempts"

    echo ""
    log "Done. Check iptables-monitor.sh and active-responses.log on wazuh-manager."
}

main "$@"
