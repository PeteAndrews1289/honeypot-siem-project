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

By this phase, the environment had captured:

- thousands of events
- repeated attacker IPs
- many brute-force attempts
- successful authentications
- command execution events

Observed post-authentication commands included:

- `uname`
- `id`

These commands indicate initial reconnaissance and privilege verification.

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
