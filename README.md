# Honeypot SIEM Project

## Overview

This project documents the deployment of a live internet-facing honeypot environment hosted on a **DigitalOcean VPS** and monitored through **Splunk Enterprise**.

The environment combines:

- **Cowrie** for SSH and Telnet emulation
- **Conpot** for ICS / SCADA simulation
- **Splunk** for centralized ingestion, search, enrichment, and dashboarding

The goal of the project was to capture real attacker activity, observe behavior after compromise, and present the data through a modern SOC-style dashboard.

## Technologies Used

- DigitalOcean
- Ubuntu
- Cowrie
- Conpot
- Splunk Enterprise
- UFW
- iptables
- Nmap
- SPL

## Project Goals

- deploy a safe public-facing honeypot
- collect real attacker traffic
- capture brute-force and post-login activity
- simulate infrastructure-facing services
- ingest and analyze logs in Splunk
- build a modern dashboard for attacker monitoring

## Environment Summary

### Cowrie
- SSH honeypot on port `2222`
- Telnet honeypot on port `23`
- port `22` redirected toward Cowrie
- weak credentials enabled for controlled attacker interaction

### Conpot
- ICS / SCADA simulation
- logs collected through local file ingestion

### Splunk
- installed directly on the VPS
- used for searches, dashboarding, and geolocation enrichment

## Key Outcomes

- captured thousands of brute-force attempts
- observed repeated attacker IPs
- recorded successful logins using weak credentials
- captured attacker reconnaissance commands
- visualized event distribution, login outcomes, timelines, and global attack sources

## Repository Layout

- `docs/` – phased project documentation
- `dashboards/` – search logic and dashboard notes
- `configs/` – deployment and service notes
- `screenshots/` – screenshots by phase
- `artifacts/` – findings and summaries

## Resume Summary

Built and deployed a public honeypot environment on a DigitalOcean VPS using Cowrie and Conpot, ingested logs into Splunk SIEM, and analyzed real attacker behavior including brute-force attempts, successful logins, command execution, and global attack distribution.

## Findings & Analysis

### Attacker Volume & Distribution
- Observed activity from **4,624 unique external IP addresses**
- SSH honeypot (Cowrie) received **~950,000 events**, indicating high-volume brute-force and automated scanning activity
- ICS honeypot (Conpot) received **lower volume (~1,100 events)** but more specialized protocol interactions

---

### SSH (Cowrie) Behavior
- **613 successful logins** using weak/default credentials:
  - admin/admin
  - root/root
  - user/password
- **457 attacker-issued commands** observed post-authentication

Common attacker behavior:
- System reconnaissance:
  - `uname -a`
  - `cat /proc/cpuinfo`
  - `ifconfig`
- Malware/miner checks:
  - `ps | grep miner`
- Payload delivery attempts:
  - `wget`, `curl`, `tftp`, `ftpget`

**Conclusion:**  
Attackers were not only scanning but successfully compromising the system and attempting post-exploitation actions.

---

### ICS (Conpot) Behavior
Observed protocol interactions included:
- **S7 (Siemens PLC) connections (~388 events)**
- **Modbus interactions (~12 events)**
- **SNMP enumeration (~12 events)**

Significant portion of traffic consisted of:
- malformed packets
- invalid protocol lengths
- incomplete requests

**Conclusion:**  
ICS activity primarily reflected **reconnaissance and protocol fingerprinting**, rather than full exploitation.

---

### Cross-Targeting Behavior
- **54 attacker IPs interacted with both SSH and ICS services**
- Top cross-targeting IP generated **281 events**

**Conclusion:**  
A subset of attackers probed both traditional IT services and ICS protocols, indicating broader scanning campaigns.

---

### Key Insight
The dataset demonstrates a clear distinction between:

- **IT attacks (SSH):**
  - high volume
  - frequent compromise
  - post-exploitation activity

- **OT/ICS attacks:**
  - lower volume
  - protocol-aware reconnaissance
  - limited deep interaction

This reflects real-world attacker behavior in internet-facing environments.
