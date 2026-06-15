#!/bin/bash
# brute-force-sim.sh
# Run from bastion-host (public subnet).
# Simulates sequential SSH brute force against a target in the private subnet.
# Sequential with sleep between attempts to produce one clean threshold crossing.
#
# Requires: sshpass, PasswordAuthentication enabled on target sshd

YELLOW='\e[38;5;226m'
NC='\e[0m'

prompt() { echo -ne "${YELLOW}$1${NC}"; }

# Install sshpass if not present
if ! command -v sshpass &>/dev/null; then
    sudo amazon-linux-extras install epel -y >/dev/null 2>&1
    sudo yum install -y sshpass >/dev/null 2>&1
fi

prompt "Enter target octet (e.g. 77 for 10.0.2.77): "
read OCTET
TARGET="10.0.2.$OCTET"

echo "Initiating SSH brute force → $TARGET"
echo ""

for i in {1..6}; do
    sshpass -p wrongpassword ssh \
        -o StrictHostKeyChecking=no \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o ConnectTimeout=5 \
        ec2-user@"$TARGET" exit 2>&1 | grep -v "^$" || true
    echo "attempt $i | $(date '+%F %T')"
    sleep 1
done

echo ""
echo "[+] Done. Check iptables-monitor.sh and active-responses.log on wazuh-manager."
