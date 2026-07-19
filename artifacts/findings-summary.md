# Findings Summary

This document separates directly observed results from interpretation. All public counts reconcile to the [sanitized evidence package](evidence/README.md); raw identifiers and event payloads are intentionally withheld.

## Evidence-to-Claim Map

| Observation | Result | Public evidence |
|---|---:|---|
| Source-attributed event records | 952,393 | `evidence/attacker_summary_sanitized.csv` |
| Distinct source values | 4,624 | 4,623 globally routable addresses and one loopback artifact |
| Cowrie-only sources | 4,358 sources / 949,972 events | `evidence/attacker_summary_sanitized.csv` |
| Conpot-only sources | 212 sources / 1,104 events | `evidence/attacker_summary_sanitized.csv` |
| Sources observed in both datasets | 54 sources / 1,317 combined events | `evidence/cross_targeting_sanitized.csv` |
| Successful Cowrie authentication events | 613 | `evidence/high_severity_summary.csv` |
| Cowrie command-input events | 457 total / 433 non-empty | `evidence/metrics.json` |
| ICS-protocol interactions | 721 | `evidence/ics_protocol_summary.csv` |

## Observed

### Source activity was highly concentrated

- Median event count per source: **18**.
- Largest source share: **17.3%** of source-attributed events.
- Top-ten source share: **52.9%**.

This means a small number of sources account for much of the volume; total events and distinct sources should be discussed separately.

### Cowrie generated most source-attributed event volume

Cowrie-only sources accounted for 949,972 records. Conpot-only sources accounted for 1,104. The 54 sources observed in both datasets accounted for 1,317 combined records; the retained aggregate does not split those records by honeypot.

### Post-authentication commands were primarily discovery-oriented

The command export reconciles to 457 occurrences across 53 aggregated values. One blank value accounts for 24 occurrences, leaving 433 non-empty occurrences across 52 distinct command strings.

The public taxonomy groups the occurrences as:

| Category | Occurrences |
|---|---:|
| Host discovery | 326 |
| Process or network discovery | 57 |
| Other | 20 |
| Permission change | 13 |
| Payload-transfer utility present | 12 |
| Shell or interpreter | 5 |
| Blank input | 24 |

The private source export includes mentions of `wget` (12 occurrences) and `curl`, `tftp`, and `ftpget` (6 each). These counts can overlap within a command. They show attempted use of transfer utilities inside Cowrie’s emulated environment, not successful download, execution, or compromise of the VPS.

### Conpot recorded several protocol families

| Protocol classification | Records |
|---|---:|
| S7 | 507 |
| Modbus | 157 |
| COTP | 28 |
| SNMP | 12 |
| Other | 17 |

The records demonstrate interaction with simulated industrial services. They do not prove the identity, sophistication, or intent of a source.

## Inference

- The observed distribution is consistent with broad automated scanning: a large number of low-volume sources and a small number of extremely high-volume sources.
- Successful weak-credential authentication events followed by discovery commands show why deception services can produce richer behavioral telemetry than connection logs alone.
- The same source value appearing in both Cowrie and Conpot is useful for correlation and prioritization, but it is not sufficient for campaign attribution.

## Limitations

- Source IPs can represent shared infrastructure, VPNs, proxies, scanners, or spoofed/misattributed activity; they are not equivalent to individual attackers.
- The exports were produced by different searches and windows. The 10,000-row recent-event sample is not the full corpus.
- The file originally named `high_severity.csv` has no retained severity rubric. This repository therefore calls it a **high-signal export**.
- Geolocation is approximate and no retained country aggregate supports a country-level finding.
- Cowrie emulates a compromised service. Command observations do not establish execution on the underlying VPS.
- The project used a single public VPS for collection and Splunk analysis. A production design should separate the collection, management, and analytics planes.
