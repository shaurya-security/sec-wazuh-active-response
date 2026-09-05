<p align="center">
  <img src="evidence/banner_wazuh_active_response.png" alt="Automated SSH Brute-Force Detection and Containment on AWS with Wazuh" width="100%">
</p>

<h1 align="center">Automated SSH Brute-Force Detection and Containment on AWS with Wazuh</h1>

<p align="center">
A hands-on detection engineering project demonstrating automated SSH brute-force detection and containment on AWS using Wazuh. The lab correlates authentication failures, maps alerts to MITRE ATT&amp;CK, triggers automated firewall responses, and validates end-to-end incident detection and recovery.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Wazuh-v4.14-005571?style=flat-square" alt="Wazuh">
  <img src="https://img.shields.io/badge/AWS-VPC-FF9900?style=flat-square&logo=amazonaws&logoColor=white" alt="AWS">
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-T1110-red?style=flat-square" alt="MITRE ATT&amp;CK">
  <img src="https://img.shields.io/badge/Active_Response-firewall--drop-orange?style=flat-square" alt="Active Response">
  <img src="https://img.shields.io/badge/Status-Complete-success?style=flat-square" alt="Status">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="License">
</p>

---

**Stack:** Wazuh 4.14 · Amazon Linux 2 · AWS VPC · iptables
**MITRE ATT&CK:** [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) · Credential Access
**Date:** June 2026

---

## Contents

- [Outcome](#outcome)
- [Skills Demonstrated](#skills-demonstrated)
- [Overview](#overview)
- [Architecture](#architecture)
- [Detection Flow](#detection-flow)
- [Detection Logic](#detection-logic)
- [Detection Performance](#detection-performance)
- [Evidence](#evidence)
- [Challenges](#challenges)
- [Lessons Learned](#lessons-learned)
- [Reproduction](#reproduction)
- [Repository Structure](#repository-structure)
- [Related Projects](#related-projects)
- [License](#license)

---

<a id="outcome"></a>
## ✅ Outcome

| Stage | Result |
|---|---|
| SSH failures generated | ✅ 6 attempts, all logged by sshd |
| Per-failure alert | ✅ Rule 5760 fires on each |
| Brute-force correlation | ✅ Rule 100002 fires at threshold |
| MITRE ATT&CK mapping | ✅ T1110 tagged on alert |
| Active response triggered | ✅ `firewall-drop` invoked automatically |
| Attacker IP blocked | ✅ iptables DROP inserted for source IP |
| Auto-recovery | ✅ DROP removed after 120 seconds |
| Dashboard visibility | ✅ Alert queryable in Wazuh Discover |

---

<a id="skills-demonstrated"></a>
## 🧠 Skills Demonstrated

- AWS Networking (VPC, Public/Private Subnets, NAT)
- Linux Administration
- Wazuh Detection Engineering
- Custom Correlation Rules
- MITRE ATT&CK Mapping
- Active Response Automation
- Incident Containment
- Troubleshooting and Root Cause Analysis

---

<a id="overview"></a>
## 📋 Overview

This project deploys Wazuh on AWS and demonstrates **automated threat containment**: the moment an SSH brute-force attack crosses a detection threshold, Wazuh fires an active response that blocks the attacker at the network layer — no manual intervention required. The block is temporary and auto-removed after a configurable timeout.

This project builds on the detection and investigation work established in the earlier Wazuh detection projects and extends it with automated incident containment and recovery.

---

<a id="architecture"></a>
## 🏗️ Architecture

```
                        Internet
                            │
                    ┌───────┴────────┐
                    │  Public Subnet  │  10.0.1.0/24
                    │  bastion-host   │  ← attacker + NAT gateway
                    └───────┬────────┘
                            │  (SSH jump / NAT)
                    ┌───────┴────────┐
                    │ Private Subnet  │  10.0.2.0/24
                    │                 │
                    │  wazuh-manager  │  ← Wazuh all-in-one
                    │                 │    Manager + Indexer
                    │                 │    + Dashboard
                    │  linux-victim   │  ← monitored host
                    └─────────────────┘

    AWS VPC  ap-south-1  10.0.0.0/16
```

**Security groups:** SSH open between `bastion-host` and the private subnet hosts; Wazuh's own ports (1514, 1515, 443, 9200, 55000) restricted to the private subnet. No inbound access from the public internet beyond the bastion's SSH port.

---

<a id="detection-flow"></a>
## 🔁 Detection Flow

```
sshd logs auth failure
        │
   Rule 5760 fires
   (per-failure, built-in)
        │
   Same source IP?
   5+ events in 360s?
        │
   Rule 100002 fires
   Level 12 · T1110
        │
   firewall-drop executes
        │
   iptables DROP inserted
   for attacker IP
        │
   120 second timeout
        │
   DROP rule removed
   (auto-recovery)
```

---

<a id="detection-logic"></a>
## 🧩 Detection Logic

### Custom Correlation Rule

```xml
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
```

Correlates against Wazuh's built-in rule `5760` (sshd authentication failure). Fires when the same source IP hits the threshold within the window. Level 12 activates the active response command.

### Active Response Config

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100002</rules_id>
  <timeout>120</timeout>
</active-response>
```

`firewall-drop` is a Wazuh built-in that inserts an iptables DROP rule for the source IP. Automatically removed after 120 seconds.

Both the rule and the active response config are written idempotently by [`scripts/manager-bootstrap.sh`](scripts/manager-bootstrap.sh) — safe to re-run without duplicating entries.

---

<a id="detection-performance"></a>
## ⏱️ Detection Performance

| Parameter | Value |
|---|---|
| Detection threshold | 5 failed logins from same source IP |
| Correlation window | 360 seconds |
| Response execution | < 1 second after threshold crossed |
| Containment duration | 120 seconds |
| Auto-recovery | ✅ Yes — DROP rule removed at timeout |

---

<a id="evidence"></a>
## 📸 Evidence

<details open>
<summary><strong>1. Attack Simulation</strong></summary>

Six sequential SSH failures from `bastion-host` targeting `wazuh-manager`. Each attempt uses a wrong password; sshd logs the failure.

![Attack simulation](evidence/01-attack-simulation.png)
</details>

<details open>
<summary><strong>2. Wazuh Dashboard — Alert Confirmed</strong></summary>

Wazuh Discover filtered to `rule.level: 12 to 14`. Single alert: rule.id `100002`, level `12`, srcip `10.0.1.170`, technique `Brute Force`, ATT&CK ID `T1110`.

![Wazuh dashboard alert](evidence/02-wazuh-dashboard-alert.png)
</details>

<details open>
<summary><strong>3. Active Response Triggered</strong></summary>

`/var/ossec/logs/active-responses.log` at the moment rule 100002 fires. Shows `firewall-drop: Starting`, the embedded alert JSON (rule 100002, level 12, T1110), and the prior SSH failure events that built up to the threshold.

![Active response triggered](evidence/03-active-response-trigger.png)
</details>

<details open>
<summary><strong>4. iptables Block Inserted and Auto-Removed</strong></summary>

`iptables-monitor.sh` running in parallel on the manager. Three timestamped snapshots:

| Timestamp | State |
|---|---|
| `18:08:13` | INPUT chain empty, no attack yet |
| `18:10:36` | `DROP all -- 10.0.1.170 0.0.0.0/0` inserted after threshold crossed |
| `18:12:37` | Chain empty again — 120s timeout expired, auto-recovered |

![iptables lifecycle](evidence/04-iptables-block-and-removal.png)
</details>

<details open>
<summary><strong>5. Active Response Lifecycle</strong></summary>

Full sequence in `active-responses.log`: one `Aborted` (Wazuh deduplication rejected a concurrent duplicate invocation), followed by a clean `Starting` → alert processing → `Ended`. Confirms temporary block, not permanent.

![Active response lifecycle](evidence/05-active-response-lifecycle.png)
</details>

<details open>
<summary><strong>6. Rule and Active Response Config Written to Disk</strong></summary>

The exact commands used to write the custom rule and active response block into the Wazuh config during bootstrap.

![Config written](evidence/06-rule-and-ar-config.png)
</details>

<details open>
<summary><strong>7. iptables DROP Confirmed (Earlier Test Run)</strong></summary>

`watch -n1 iptables -L INPUT -n --line-numbers` on the manager during a prior test. Shows `DROP all -- 10.0.1.67 0.0.0.0/0` inserted in real time.

![Drop confirmed](evidence/07-iptables-drop-confirmed.png)
</details>

---

<a id="challenges"></a>
## 🧗 Challenges

> **PasswordAuthentication disabled by default**
> Amazon Linux 2 disables password auth in sshd out of the box. The attack script reached the network layer but sshd rejected connections before any password was exchanged — so no `Failed password` entries appeared in logs. Fixed by enabling `PasswordAuthentication yes` in `sshd_config`.

> **Active response aborting on concurrent invocations**
> Parallel SSH attempts fired simultaneously triggered multiple threshold crossings for the same IP at nearly the same timestamp. Wazuh's `check_keys` deduplication aborted the second invocation to avoid double-blocking. **Fix:** sequential attempts with `sleep 1` between each, producing one clean threshold crossing and one active response invocation.

> **iptables-services failing to start**
> The default `/etc/sysconfig/iptables` shipped with `iptables-services` on AL2 uses `-m state`, which is not available on the AL2 kernel — only `conntrack` is. **Fix:** flush the ruleset, save (overwrites the broken default file with a clean empty ruleset), then start the service.

> **firewalld conflict**
> Enabling `iptables.service` automatically stops `firewalld`. They cannot run simultaneously. Since `firewall-drop` manipulates iptables directly, firewalld being absent is required. Expected behavior, not a misconfiguration.

Full write-up with symptoms, root causes, and exact fix commands for each: [`docs/debugging-notes.md`](docs/debugging-notes.md).

---

<a id="lessons-learned"></a>
## 💡 Lessons Learned

- Active response failures often originate earlier in the pipeline than expected.
- Validate log generation before debugging correlation rules.
- Validate correlation rules before debugging containment actions.
- Sequential attack simulation produces more reliable rule correlation than parallel bursts.

---

<a id="reproduction"></a>
## 🔄 Reproduction

### Prerequisites

- AWS VPC with public and private subnets, NAT routing configured
- Three EC2 instances on Amazon Linux 2: `bastion-host`, `wazuh-manager`, `linux-victim`
- Security groups: SSH between hosts, Wazuh ports (1514, 1515, 443, 9200, 55000) within the private subnet
- `sudo` access on all three hosts

> This lab provisions and modifies real infrastructure (sshd config, iptables, firewalld) on the target hosts. Run it in a disposable lab environment, not production systems.

### Steps

```bash
# On wazuh-manager — run the full bootstrap (idempotent, safe to re-run)
bash scripts/manager-bootstrap.sh

# On wazuh-manager — watch for the block (separate terminal)
bash scripts/iptables-monitor.sh

# On bastion-host — run the attack
bash scripts/brute-force-sim.sh
# Enter target octet when prompted (e.g. 77 for 10.0.2.77),
# or pass it directly: bash scripts/brute-force-sim.sh 77 6

# Verify in Wazuh Dashboard
# https://localhost:8443 → Discover → filter rule.level: 12 to 14
```

> ⏱️ Full cycle from clean instances to confirmed block takes **under 15 minutes**.

---

<a id="repository-structure"></a>
## 🗂️ Repository Structure

```
wazuh-active-response-containment/
├── README.md
├── LICENSE
├── rules/
│   └── local_rules.xml              # custom Wazuh correlation rule (rule 100002)
├── scripts/
│   ├── manager-bootstrap.sh         # Wazuh install + rule + AR + iptables + sshd setup (idempotent)
│   ├── brute-force-sim.sh           # SSH brute-force simulation (run from bastion-host)
│   └── iptables-monitor.sh          # real-time iptables change watcher
├── docs/
│   └── debugging-notes.md           # issues encountered, root causes, fixes
└── evidence/
    ├── banner_wazuh_active_response.png
    ├── 01-attack-simulation.png
    ├── 02-wazuh-dashboard-alert.png
    ├── 03-active-response-trigger.png
    ├── 04-iptables-block-and-removal.png
    ├── 05-active-response-lifecycle.png
    ├── 06-rule-and-ar-config.png
    └── 07-iptables-drop-confirmed.png
```

---

<a id="related-projects"></a>

## 🔗 Related Projects

This project extends the Wazuh detection work established in [`wazuh-custom-rule-detection`](https://github.com/shaurya-security/wazuh-custom-rule-detection).

The earlier project established custom detection and MITRE ATT&CK mapping. This project takes the next step by adding automated active response, firewall-based containment, and timed recovery.

The later [`wazuh-windows-soc-simulation`](https://github.com/shaurya-security/wazuh-windows-soc-simulation) project extends this progression to Windows, building on the detection and response concepts established here.

| Repo | Focus | Status |
|---|---|---|
| [`wazuh-custom-rule-detection`](https://github.com/shaurya-security/wazuh-custom-rule-detection) | Custom Wazuh detection, SSH brute-force detection, MITRE mapping | ✅ Complete |
| `wazuh-active-response-containment` (this repo) | Automated containment, firewall response, timed recovery | ✅ Complete |
| [`wazuh-windows-soc-simulation`](https://github.com/shaurya-security/wazuh-windows-soc-simulation) | Windows telemetry, detection, investigation, and response | 🚧 In progress |

---

<a id="license"></a>
## 📄 License

Released under the [MIT License](LICENSE).
