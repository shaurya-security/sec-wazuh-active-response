# Debugging Notes

Issues encountered during setup and testing. Root causes and fixes documented as a record.

---

## 1. PasswordAuthentication disabled by default

**Symptom:** Brute-force script ran without errors but no `Failed password` entries appeared in sshd logs. The attack silently produced no log events.

**Root cause:** Amazon Linux 2 disables password authentication in sshd by default. Connections were dropped before any password exchange occurred, so sshd had nothing to log as an authentication failure.

**Fix:**
```bash
sudo sed -i '
s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/;
s/^#\?PubkeyAuthentication.*/PubkeyAuthentication no/;
' /etc/ssh/sshd_config
sudo sshd -t
sudo systemctl restart sshd
sudo passwd ec2-user
```

---

## 2. Active response aborting on concurrent invocations

**Symptom:** `active-responses.log` showed:
```
firewall-drop: Starting
check_keys → keys: ["10.0.x.x"]
firewall-drop: Aborted
```
No DROP rule appeared in iptables. Two minutes later, `firewall-drop: Ended` appeared as cleanup for a block that never happened.

**Root cause:** Parallel burst attack (multiple SSH connections fired simultaneously with `&`) triggered multiple simultaneous threshold crossings for the same IP. Wazuh's `check_keys` deduplication aborted the second invocation to prevent double-blocking. The first invocation also failed silently because iptables-services was not yet running at the time.

**Fix:** Switch to sequential attempts with `sleep 1` between each. Produces one threshold crossing, one active response invocation, one clean block.

---

## 3. iptables-services failing to start

**Symptom:**
```
iptables-restore: Couldn't load match 'state': No such file or directory
Error occurred at line: 8
[FAILED]
```

**Root cause:** The default `/etc/sysconfig/iptables` shipped with `iptables-services` on AL2 contains `-m state --state RELATED,ESTABLISHED`. The `state` module is not available on the AL2 kernel — only `conntrack` is. The service tries to restore this file at startup and fails immediately.

**Fix:**
```bash
sudo yum install -y iptables-services
sudo iptables -F                  # clear current ruleset
sudo service iptables save        # overwrites broken default with clean empty ruleset
sudo systemctl enable --now iptables
```

---

## 4. firewalld conflict

**Symptom:** Enabling `iptables.service` automatically stopped `firewalld`.

**Root cause:** `firewalld` and `iptables.service` both manage the netfilter subsystem and cannot run simultaneously. Systemd stops `firewalld` as part of unit conflict resolution when `iptables.service` is enabled.

**Resolution:** Expected behavior. The `firewall-drop` active response manipulates iptables directly, so `firewalld` being absent is required for it to work correctly.

---

## 5. SSL warning on Wazuh Dashboard

**Symptom:** Browser flagged the Wazuh dashboard as insecure at `https://localhost:8443`.

**Root cause:** Wazuh all-in-one installs a self-signed certificate by default.

**Resolution:** Proceed past the browser warning. Not a configuration issue in a lab environment.
