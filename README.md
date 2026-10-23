# Network Intrusion Detection System Lab (Suricata + Python)

A beginner-friendly cybersecurity project: set up **Suricata** as an IDS in an isolated virtual lab, write **custom detection rules**, simulate basic attacks, and summarize the alerts with a **Python analyzer**.

> **Ethical use:** Run this only on virtual machines and networks you own. Never scan or attack systems without written permission.

## Features
- 4 custom Suricata rules (Nmap SYN scan, ICMP flood, Telnet, FTP login)
- Python tool that parses `eve.json` and counts alerts by signature, source IP and severity
- CSV report and optional bar chart
- Sample data, so the analyzer can be tested without Suricata running

## Architecture
```
 +------------------+        host-only network        +----------------------+
 |  Kali Linux VM   |  ---- scans / pings / logins -> |  Ubuntu VM           |
 |  (attacker)      |        192.168.56.0/24          |  Suricata IDS        |
 |  192.168.56.102  |                                 |  192.168.56.101      |
 +------------------+                                 +----------+-----------+
                                                                 |
                                                     /var/log/suricata/eve.json
                                                                 |
                                                       alert_analyzer.py
                                                      (tables, CSV, chart)
```

## Prerequisites
- VirtualBox, with an Ubuntu 22.04 VM and a Kali Linux VM
- Both VMs on the same **Host-Only** (or Internal) network
- Python 3.10+ on the Ubuntu VM

## Lab Setup
1. **Create the VMs** in VirtualBox. Set both network adapters to *Host-Only Adapter*. Note each VM's IP with `ip a`.
2. **Install Suricata** on Ubuntu:
   ```bash
   sudo add-apt-repository ppa:oisf/suricata-stable
   sudo apt update && sudo apt install suricata -y
   ```
3. **Configure** `/etc/suricata/suricata.yaml`:
   - Set `HOME_NET: "[192.168.56.0/24]"`
   - Under `af-packet`, set `interface:` to your lab interface (find it with `ip a`)
   - Under `rule-files:` add `- local.rules`
4. **Update rules:** `sudo suricata-update`
5. **Load the custom rules:**
   ```bash
   sudo cp rules/local.rules /var/lib/suricata/rules/local.rules
   sudo suricata -T -c /etc/suricata/suricata.yaml -v   # test the config
   sudo systemctl restart suricata
   ```
6. **Watch alerts live:** `sudo tail -f /var/log/suricata/fast.log`

## Attack Simulations (run from Kali, against your own Ubuntu VM only)
```bash
nmap -sS 192.168.56.101                  # triggers Rule 1 (SYN scan)
ping -f -c 200 192.168.56.101            # triggers Rule 2 (ICMP flood)
telnet 192.168.56.101 23                 # triggers Rule 3a (Telnet)
ftp 192.168.56.101                       # type a username: triggers Rule 3b (FTP)
```
Telnet and FTP need a service listening, or at least a reachable port. The SYN packet alone is enough for the Telnet rule. For FTP, run `sudo apt install vsftpd` on Ubuntu inside your lab.

## Running the Analyzer
```bash
pip install -r requirements.txt

# Try it with the included sample data
python alert_analyzer.py --file sample_data/sample_eve.json --chart

# Use your real Suricata log
sudo python alert_analyzer.py --file /var/log/suricata/eve.json --output my_report.csv --chart
```

### Sample Output
```
Total alerts: 56

=== Alerts by Signature ===
+--------------------------------------+---------+
| Signature                            |   Count |
+======================================+=========+
| LAB Possible Nmap SYN scan detected  |      30 |
| LAB ICMP flood detected              |      12 |
| LAB Telnet connection attempt        |       8 |
| LAB FTP login attempt (USER command) |       6 |
+--------------------------------------+---------+
```

## Folder Structure
```
suricata-ids-lab/
├── alert_analyzer.py
├── requirements.txt
├── README.md
├── PROJECT_REPORT.md
├── LICENSE
├── .gitignore
├── rules/local.rules
├── sample_data/sample_eve.json
├── docs/GITHUB_SETUP.md
└── screenshots/
```

## Limitations
- Threshold-based rules can cause false positives (e.g., a legitimate fast scan by an admin)
- Signature-based detection will not catch unknown (zero-day) attacks
- Encrypted traffic content cannot be inspected
- The analyzer works on logs after the fact, not in real time

## Future Improvements
- Real-time alerting by email or Telegram
- Dashboard with ELK or Grafana
- Run Suricata in IPS mode to block attackers
- GeoIP lookup of source addresses
- More rules (DNS tunneling, SSH brute force)

## License
MIT. See `LICENSE`.
