# GitHub Setup

1. Create an empty repository on github.com named **suricata-ids-lab** (no README, no license: they already exist here).
2. In the project folder, run:
```bash
git init
git add .
git commit -m "Initial commit: Suricata IDS lab with Python alert analyzer"
git branch -M main
git remote add origin https://github.com/<your-username>/suricata-ids-lab.git
git push -u origin main
```
3. If GitHub asks for a password, use a **Personal Access Token** (Settings > Developer settings > Personal access tokens), not your account password.

**Description:** Beginner-friendly network IDS lab using Suricata custom rules and a Python eve.json alert analyzer.

**Topics:** `cybersecurity` `suricata` `ids` `network-security` `python` `intrusion-detection` `nmap` `blue-team`

Add your screenshots to `/screenshots`, then:
```bash
git add screenshots && git commit -m "Add lab screenshots" && git push
```
