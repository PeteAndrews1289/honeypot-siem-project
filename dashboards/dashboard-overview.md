# Dashboard Overview

The original dashboard was a legacy, last-24-hours operational snapshot. It did not use the same window as the later aggregate evidence exports and contained raw source identifiers, so it is not published on the current branch. The repository instead provides a sanitized overview graphic and machine-readable evidence tables.

## Objective

Build a Splunk dashboard that presents the honeypot environment like a lightweight SOC console.

## Panels Included

- Event Distribution
- Top pseudonymous source IDs
- Successful Logins
- Failed vs Successful Logins
- Attacker Commands
- Attack Timeline
- Sanitized protocol and source-coverage summaries

## What the Dashboard Answers

- How much attack activity is the environment receiving?
- Which pseudonymous sources are most active?
- Are attackers only brute forcing, or are they getting in?
- What credentials are being used successfully?
- What commands are being run after login?
- Which service and protocol categories generated activity?

## Notes

Cowrie provides the majority of volume and post-authentication behavior.

Conpot provides lower-volume but more infrastructure-oriented activity.

Together, they allow the dashboard to compare generic attacker behavior with more specialized infrastructure probing.

## Scope Rules

- Every panel must display its exact UTC time window.
- Aggregate source totals and recent-event samples must not be combined as if they share one window.
- Raw IPs, usernames, passwords, commands, payloads, and host paths must not appear in public images.
- Geolocation is approximate and is excluded until a sanitized country-level aggregate is available.
