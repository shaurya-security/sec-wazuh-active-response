#!/bin/bash
#
# manager-bootstrap.sh
#
# Run on wazuh-manager (Amazon Linux 2) after instance launch.
# Installs Wazuh all-in-one, writes the custom brute-force correlation rule,
# configures active response, hardens/prepares iptables, and enables sshd
# password auth so the brute-force simulation can produce real log entries.
#
# Tested: Wazuh 4.14 / Amazon Linux 2 / ap-south-1
#
# Usage:
#   bash manager-bootstrap.sh
#
# Idempotency: safe to re-run. Steps that mutate config check for the
# expected end-state first and skip if already applied.

set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────────
WAZUH_VERSION="4.14"
RULE_ID=100002
DETECTION_THRESHOLD=5     # failed logins
DETECTION_WINDOW=360      # seconds
AR_TIMEOUT=120            # seconds the iptables block stays active
SSHD_CONFIG="/etc/ssh/sshd_config"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"
INSTALL_SCRIPT_URL="https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"

log() { echo "[*] $*"; }
ok()  { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }

# ── Optional: shell prompt for a nicer interactive session ──────────────────
# Cosmetic only — never allowed to fail the bootstrap.
setup_shell_prompt() {
    if command -v starship &>/dev/null; then
        return 0
    fi
    log "Installing starship prompt (optional, non-fatal on failure)..."
    mkdir -p ~/.local/bin ~/.config
    if curl -sS https://starship.rs/install.sh | sh -s -- -b ~/.local/bin -y >/dev/null 2>&1; then
        grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' ~/.bashrc || \
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
        grep -qxF 'eval "$(starship init bash)"' ~/.bashrc || \
            echo 'eval "$(starship init bash)"' >> ~/.bashrc
        cat > ~/.config/starship.toml <<'EOF'
add_newline = false
[hostname]
ssh_only = false
format = "[$hostname](bold green) "
[directory]
truncation_length = 3
EOF
    else
        warn "starship install failed — continuing without it."
    fi
}

# ── Wazuh all-in-one install ─────────────────────────────────────────────────
install_wazuh() {
    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        ok "Wazuh manager already installed and running — skipping install."
        return 0
    fi
    log "Downloading and running Wazuh ${WAZUH_VERSION} all-in-one installer..."
    curl -sO "$INSTALL_SCRIPT_URL"
    chmod +x wazuh-install.sh
    sudo bash wazuh-install.sh -a

    log "Enabling JSON log archiving (required for Wazuh Discover visibility)..."
    sudo sed -i \
        's#<logall_json>no</logall_json>#<logall_json>yes</logall_json>#' \
        "$OSSEC_CONF"
}

# ── Custom brute-force correlation rule ──────────────────────────────────────
install_detection_rule() {
    if sudo grep -q "id=\"${RULE_ID}\"" "$LOCAL_RULES" 2>/dev/null; then
        ok "Rule ${RULE_ID} already present — skipping."
        return 0
    fi
    log "Writing custom correlation rule ${RULE_ID}..."
    local window_minutes=$(( DETECTION_WINDOW / 60 ))
    sudo tee -a "$LOCAL_RULES" >/dev/null <<EOF
<group name="aws_custom,">
<rule id="${RULE_ID}" level="12" frequency="${DETECTION_THRESHOLD}" timeframe="${DETECTION_WINDOW}">
  <if_matched_sid>5760</if_matched_sid>
  <same_source_ip />
  <description>SSH brute force: ${DETECTION_THRESHOLD}+ failures in ${window_minutes} minutes from \$(srcip)</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>syslog,attacks,authentication_failures</group>
</rule>
</group>
EOF
}

# ── Active response config ───────────────────────────────────────────────────
install_active_response() {
    if sudo grep -q "<rules_id>${RULE_ID}</rules_id>" "$OSSEC_CONF" 2>/dev/null; then
        ok "Active response for rule ${RULE_ID} already configured — skipping."
        return 0
    fi
    log "Configuring active response (firewall-drop, ${AR_TIMEOUT}s timeout)..."
    sudo sed -i "/<\/ossec_config>/i\\
<active-response>\\
  <command>firewall-drop</command>\\
  <location>local</location>\\
  <rules_id>${RULE_ID}</rules_id>\\
  <timeout>${AR_TIMEOUT}</timeout>\\
</active-response>
" "$OSSEC_CONF"
}

# ── sshd: enable password authentication ─────────────────────────────────────
# AL2 disables password auth by default. Required for the brute-force
# simulation to produce real sshd failure log entries.
configure_sshd() {
    if grep -qx "PasswordAuthentication yes" "$SSHD_CONFIG"; then
        ok "sshd password authentication already enabled — skipping."
    else
        log "Enabling sshd password authentication..."
        sudo cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
        sudo sed -i '
            s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/;
            s/^#\?PubkeyAuthentication.*/PubkeyAuthentication no/;
        ' "$SSHD_CONFIG"
        sudo sshd -t
        sudo systemctl restart sshd
    fi

    log "Set a known password for ec2-user (required for sshpass in the simulation):"
    sudo passwd ec2-user
}

# ── Tools ─────────────────────────────────────────────────────────────────────
install_tools() {
    if command -v sshpass &>/dev/null; then
        ok "sshpass already installed — skipping."
        return 0
    fi
    log "Installing sshpass..."
    sudo amazon-linux-extras install epel -y
    sudo yum install -y sshpass
}

# ── iptables setup ────────────────────────────────────────────────────────────
# The default /etc/sysconfig/iptables shipped with iptables-services on AL2
# uses '-m state', which is unavailable on the AL2 kernel (only 'conntrack'
# is). Fix: install, flush to a clean ruleset, save (overwrites the broken
# default file), then start the service.
setup_iptables() {
    if systemctl is-active --quiet iptables 2>/dev/null; then
        ok "iptables service already active — skipping setup."
        return 0
    fi
    log "Setting up iptables-services..."
    sudo yum install -y iptables-services
    sudo iptables -F
    sudo service iptables save
    sudo systemctl enable --now iptables
    sudo iptables -L INPUT -n --line-numbers
}

restart_wazuh() {
    log "Restarting Wazuh services to pick up config changes..."
    sudo systemctl restart wazuh-manager wazuh-indexer wazuh-dashboard
}

main() {
    setup_shell_prompt
    install_wazuh
    install_detection_rule
    install_active_response
    configure_sshd
    install_tools
    setup_iptables
    restart_wazuh

    echo ""
    ok "Bootstrap complete."
    ok "Run scripts/iptables-monitor.sh in a separate terminal before starting the attack."
    ok "Dashboard available at https://localhost:8443 (SSH tunnel or port-forward required)."
}

main "$@"
