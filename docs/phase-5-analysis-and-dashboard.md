# Phase 5 – Analysis & Dashboard Development

## Objective

Turn raw honeypot logs into a modern Splunk dashboard capable of showing attacker behavior in a SOC-style format.

## Process

After ingestion was verified, SPL searches were developed to answer key operational questions:

- how many attackers are hitting the environment
- which IPs are the most active
- how many logins fail versus succeed
- what credentials are being used successfully
- whether attackers move from authentication into command execution
- where attacks appear to originate geographically

The dashboard evolved over time as the data quality improved. Early panels focused on event volume and IP counts. Later panels added login outcomes, successful credentials, command activity, attack timelines, and geolocation.

## Key Queries Used

Examples included:

- event distribution by `eventid`
- top attacker IPs
- successful login counts by `src_ip`, `username`, and `password`
- command input counts
- timecharts
- `iplocation` and `geostats` for geographic visualization

## Findings

The retained exports support these exact results:

- 952,393 source-attributed event records across the aggregate source export
- 4,624 distinct source values, including 4,623 globally routable addresses and one loopback artifact
- 613 successful Cowrie authentication events
- 457 Cowrie command-input occurrences, including 433 non-empty values
- 721 ICS-protocol interaction records
- 54 source values observed in both Cowrie and Conpot datasets

Observed post-authentication commands included:

- `uname`
- `id`

These commands are consistent with host discovery and environment inspection inside Cowrie's emulated service. They do not establish attacker identity or execution on the underlying VPS.

## Export Scope

The exports were created from different searches and windows. In particular, the file originally named `master_dataset.csv` is a capped 10,000-row recent-event sample covering 2026-04-23 03:29:50 UTC through 14:11:21.649 UTC. It is not the full event corpus and should not be used as the denominator for the aggregate source totals.

## Dashboard Themes

The main dashboard elements included:

- Event Distribution
- Top Attacking IPs
- Successful Logins
- Login Outcome Comparison
- Attacker Commands
- Attack Timeline
- Geolocation

## Result

The project moved beyond raw logging into structured attacker behavior analysis.

## Insight

The biggest analytical milestone was not the first scan or even the first successful login. It was the first command execution event. That represented the transition from simple internet noise into post-authentication attacker decision-making.
