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
