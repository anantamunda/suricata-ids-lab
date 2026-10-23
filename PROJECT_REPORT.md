# Network Intrusion Detection System Lab Using Suricata and Python

**Submitted by:** <Your Ananta Munda>  
**Institution:** < College GovernmentEngineeringCollegeBokaro>  
**Date:** <Date 23/11/2026>

---

## Abstract
This project builds a small Network Intrusion Detection System (NIDS) lab using Suricata, an open-source detection engine. Two virtual machines on an isolated network simulate an attacker (Kali Linux) and a monitored host (Ubuntu). Custom Suricata rules detect port scanning, ICMP flooding, and insecure Telnet/FTP access. A Python tool then reads Suricata's `eve.json` log and summarizes alerts by type, source and severity. The project shows how detection rules work, how attacks look in logs, and how log analysis helps defenders.

## 1. Introduction
Networks face constant probing and attack attempts. Firewalls allow or block traffic by simple rules, but they do not explain what is happening. An IDS watches traffic and raises alerts on suspicious patterns, giving administrators visibility. This project demonstrates that idea on a small scale in a safe lab.

## 2. Objectives
- Understand how an IDS works and where it fits in network defense
- Install and configure Suricata
- Write custom rules to detect common reconnaissance and policy violations
- Simulate attacks safely in an isolated lab
- Automate alert summarization with Python

## 3. Background: IDS, IPS and Firewall
| Tool | Main job | Action |
|------|----------|--------|
| Firewall | Allows or blocks traffic by address, port, protocol | Blocks |
| IDS | Inspects traffic and raises alerts | Detects and reports only |
| IPS | Same as IDS, but sits inline | Detects and blocks |

Suricata can run in either IDS or IPS mode. This project uses IDS mode.

## 4. Tools Used
| Tool | Purpose |
|------|---------|
| VirtualBox | Runs the lab virtual machines |
| Ubuntu 22.04 | Monitored host running Suricata |
| Kali Linux | Attacker machine (own lab only) |
| Suricata | Intrusion detection engine |
| Nmap, ping, telnet, ftp | Traffic generation for tests |
| Python 3, matplotlib, tabulate | Alert analysis and charts |

## 5. Lab Architecture
Two VMs share a Host-Only network (192.168.56.0/24), isolated from the internet and other devices. Kali (192.168.56.102) sends test traffic to Ubuntu (192.168.56.101), where Suricata inspects packets and writes alerts to `fast.log` and `eve.json`.

[Insert Screenshot 1: Lab architecture diagram or VirtualBox network settings]

## 6. Methodology
1. Created both VMs and confirmed connectivity with `ping`.
2. Installed Suricata and set `HOME_NET` and the capture interface.
3. Updated the rule set with `suricata-update`.
4. Added `local.rules` with four custom rules and validated the configuration with `suricata -T`.
5. Ran attack simulations from Kali.
6. Collected alerts and ran `alert_analyzer.py` on `eve.json`.

[Insert Screenshot 2: Suricata running and configuration test passing]

## 7. Custom Rules Explained
**Rule 1: Nmap SYN scan (SID 1000001).** Matches TCP packets with the SYN flag. A threshold triggers only when one source sends 20 or more within 5 seconds, which is typical of a port scan and avoids alerting on normal connections.

**Rule 2: ICMP flood (SID 1000002).** Matches ICMP echo requests (type 8). Fires if one source sends 50 or more within 5 seconds.

**Rule 3a: Telnet attempt (SID 1000003).** Telnet (port 23) sends data, including passwords, in plain text. Any connection attempt to it is flagged as a policy violation.

**Rule 3b: FTP login (SID 1000004).** FTP (port 21) is also unencrypted. The rule looks for the `USER` command at the start of a client payload, which marks a login attempt.

## 8. Attack Simulation Results
All tests were run from the Kali VM against the Ubuntu VM in the isolated lab.

| Test | Command | Expected alert | Result |
|------|---------|----------------|--------|
| SYN scan | `nmap -sS 192.168.56.101` | LAB Possible Nmap SYN scan detected | <Detected / Not detected> |
| ICMP flood | `ping -f -c 200 192.168.56.101` | LAB ICMP flood detected | <Detected / Not detected> |
| Telnet | `telnet 192.168.56.101 23` | LAB Telnet connection attempt | <Detected / Not detected> |
| FTP login | `ftp 192.168.56.101` | LAB FTP login attempt | <Detected / Not detected> |

[Insert Screenshot 3: Nmap scan running on Kali]  
[Insert Screenshot 4: Alerts in fast.log]  
[Insert Screenshot 5: eve.json alert entries]

## 9. Alert Analysis
The Python analyzer reads `eve.json`, keeps only `alert` events, and counts them by signature, source IP and severity. It exports a CSV and a bar chart. On the included sample data of 56 alerts, SYN scan alerts were the most common (30), followed by ICMP flood (12), Telnet (8) and FTP (6).

[Insert Screenshot 6: Analyzer terminal output]  
[Insert Screenshot 7: Generated chart (alerts_chart.png)]

## 10. False Positives and Limitations
- A network admin running a legitimate scan would trigger Rule 1.
- Thresholds (20 SYN, 50 ICMP) are tuned for a lab and need adjusting on real networks.
- Signature-based detection misses unknown attacks and slow scans designed to stay under thresholds.
- Encrypted traffic (HTTPS, SSH) cannot be inspected by content.
- The analyzer works on saved logs, not live traffic.

## 11. Conclusion
The project met its objectives: Suricata was configured, custom rules detected simulated reconnaissance and insecure-protocol use, and a Python tool turned raw logs into readable summaries. It showed that an IDS gives defenders visibility, but needs tuning and should be combined with firewalls, patching and monitoring.

## 12. Future Scope
- Real-time alerts by email or messaging apps
- ELK or Grafana dashboard
- IPS mode to block attackers automatically
- Additional rules (SSH brute force, DNS tunneling)
- Machine-learning-based anomaly detection

## 13. References
1. Suricata Documentation: https://docs.suricata.io
2. Nmap Reference Guide: https://nmap.org/book/man.html
3. OISF Suricata Rules Format: https://docs.suricata.io/en/latest/rules/
4. Python `json`, `csv`, `argparse` documentation: https://docs.python.org/3/
5. VirtualBox User Manual: https://www.virtualbox.org/manual/
