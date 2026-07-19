# Query and Metric Index

The complete SPL examples are maintained in [`dashboards/splunk-searches.md`](../dashboards/splunk-searches.md). This index maps each public result to its query and sanitized artifact.

| Analytical question | SPL section | Public result |
|---|---|---|
| How are events distributed by Cowrie event type? | Cowrie Event Distribution | `evidence/metrics.json` recent-sample activity types |
| How many source values targeted Cowrie, Conpot, or both? | Source Summary / Cross-Service Sources | `evidence/attacker_summary_sanitized.csv` and `cross_targeting_sanitized.csv` |
| How many Cowrie logins succeeded? | Successful Cowrie Authentication Events | `evidence/high_severity_summary.csv` |
| How many post-authentication commands were recorded? | Cowrie Command Summary | `evidence/command_categories.csv` |
| Which ICS protocol labels were observed? | ICS Protocol Summary | `evidence/ics_protocol_summary.csv` |

## Privacy Rule

Source IPs, usernames, passwords, raw command strings, URLs, session IDs, and `_raw` payloads are never part of a public query result. The private exports retain those fields for controlled analysis; the public builder releases only aggregate or pseudonymized evidence.

## Interpretation Rules

- A source address is not the same thing as a person or campaign.
- “Successful login” describes authentication to Cowrie’s emulated service, not compromise of the underlying host.
- Command and transfer-tool observations are attempts inside the emulated environment, not proof of successful payload execution.
- Protocol counts describe interactions with simulated services, not exploitation or actor intent.
- IP geolocation is approximate and is excluded from public findings unless a sanitized country aggregate is available.
