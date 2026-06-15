#!/bin/bash
# manager-bootstrap.sh
# Run on wazuh-manager (Amazon Linux 2) after instance launch.
# Installs Wazuh all-in-one, writes the custom detection rule,
# configures active response, sets up iptables, and enables
# password auth on sshd for the brute-force simulation.
#
# Tested: Wazuh 4.14 / Amazon Linux 2 / ap-south-1

set -e

# ── Shell prompt (optional) ────────────────────────────────────────────────────
mkdir -p ~/.local/bin ~/.config
curl -sS https://starship.rs/install.sh | sh -s -- -b ~/.local/bin -y >/dev/null 2>&1
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(starship init bash)"' >> ~/.bashrc
cat > ~/.config/starship.toml <<'EOF'
add_newline = false
[hostname]
ssh_only = false
format = "[$hostname](bold green) "
[directory]
truncation_length = 3
EOF
source ~/.bashrc

# ── Wazuh all-in-one install ───────────────────────────────────────────────────
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
chmod +x wazuh-install.sh
sudo bash wazuh-install.sh -a

# Enable JSON log archiving (required for Wazuh Discover visibility)
sudo sed -i \
    's#<logall_json>no</logall_json>#<logall_json>yes</logall_json>#' \
    /var/ossec/etc/ossec.conf

# ── Custom brute-force correlation rule ───────────────────────────────────────
sudo tee -a /var/ossec/etc/rules/local_rules.xml >/dev/null <<'EOF'
<group name="aws_custom,">
<rule id="100002" level="12" frequency="5" timeframe="360">
  <if_matched_sid>5760</if_matched_sid>
  <same_source_ip />
  <description>SSH brute force: 5+ failures in 6 minutes from $(srcip)</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>syslog,attacks,authentication_failures</group>
</rule>
</group>
EOF

# ── Active response config ─────────────────────────────────────────────────────
sudo sed -i '/<\/ossec_config>/i\
<active-response>\
  <command>firewall-drop</command>\
  <location>local</location>\
  <rules_id>100002</rules_id>\
  <timeout>120</timeout>\
</active-response>
' /var/ossec/etc/ossec.conf

# ── sshd: enable password authentication ──────────────────────────────────────
# AL2 disables password auth by default. Required for brute-force simulation
# to produce real sshd failure log entries.
sudo cp /etc/ssh/sshd_config{,.bak}
sudo sed -i '
s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/;
s/^#\?PubkeyAuthentication.*/PubkeyAuthentication no/;
' /etc/ssh/sshd_config
sudo sshd -t
sudo systemctl restart sshd
sudo passwd ec2-user   # set a known password for sshpass

# ── Tools ──────────────────────────────────────────────────────────────────────
sudo amazon-linux-extras install epel -y
sudo yum install -y sshpass

# ── iptables setup ─────────────────────────────────────────────────────────────
# The default /etc/sysconfig/iptables on AL2 uses '-m state' which is not
# available on the AL2 kernel. Fix: install, flush to clean state, save
# (overwrites broken default file), then start.
sudo yum install -y iptables-services
sudo iptables -F
sudo service iptables save
sudo systemctl enable --now iptables
sudo iptables -L INPUT -n --line-numbers

# ── Restart Wazuh to pick up config changes ────────────────────────────────────
sudo systemctl restart wazuh-manager wazuh-indexer wazuh-dashboard

echo ""
echo "[+] Bootstrap complete."
echo "[+] Run scripts/iptables-monitor.sh in a separate terminal before starting the attack."
echo "[+] Dashboard available at https://localhost:8443 (SSH tunnel or port-forward required)"
