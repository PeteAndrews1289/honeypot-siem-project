# Phase 4 – Splunk Installation & Log Ingestion

## Objective

Install Splunk Enterprise on the VPS and centralize logs from Cowrie and Conpot for searching, analysis, and dashboarding.

## Process

Splunk Enterprise was installed directly on the DigitalOcean droplet. Several installation issues were encountered and resolved during this phase, including:

- bad direct download URLs
- downloading the wrong package type initially
- package naming mismatches during installation
- startup warnings related to running as root
- final successful startup using the installed Splunk binaries

Once Splunk was running, port `8000` was opened and the web UI was accessed through the droplet’s public IP.

## Data Inputs

Two main log sources were added:

### Cowrie
Cowrie logs were initially added using a custom sourcetype, but that approach proved less useful than treating the JSON file as standard JSON.

Final input:

`/home/honeypot/cowrie/var/log/cowrie/cowrie.json`

### Conpot
Conpot logs were added from:

`/home/honeypot/conpot/conpot.log`

## Troubleshooting

Several real SIEM engineering issues were encountered:

- file permissions on user-owned log paths
- sourcetype choice for Cowrie JSON
- timestamp parsing quirks for Conpot logs
- file monitor input validation
- confirming whether data was missing or simply mis-timestamped

The Conpot issue turned out to be primarily a timestamp interpretation problem rather than an ingestion failure.

## Result

Splunk successfully ingested:

- Cowrie JSON event data
- Conpot log data

This enabled searches for:

- event counts
- attacker IPs
- successful logins
- command execution
- geolocation enrichment
- time-based patterns

## Insight

This phase demonstrated that SIEM work is not just “install and upload.” The real work included fixing parsing, validating file permissions, selecting the right sourcetype strategy, and proving whether data was actually missing or only misrepresented.
