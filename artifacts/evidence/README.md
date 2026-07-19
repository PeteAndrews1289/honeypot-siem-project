# Sanitized Evidence Package

This directory contains privacy-preserving derivatives of six Splunk CSV exports. The original exports are intentionally excluded because they contain source IP addresses, credentials submitted to the honeypot, raw commands, URLs, session identifiers, timestamps, and local infrastructure paths.

## Verified Results

| Result | Value | Definition |
|---|---:|---|
| Source-attributed event records | 952,393 | Sum of `total_events` in the aggregate source export |
| Distinct source values | 4,624 | 4,623 globally routable addresses plus one loopback artifact with two events |
| Cowrie only / Conpot only / both | 4,358 / 212 / 54 sources | “Both” means an observed source address appeared in both service datasets; it is not actor or campaign attribution |
| Successful Cowrie authentication events | 613 | Records containing `cowrie.login.success` in the high-signal export |
| Cowrie command-input events | 457 | Aggregated `cowrie.command.input` records; 433 contained a non-empty command value |
| ICS-protocol interaction records | 721 | 507 S7, 157 Modbus, 28 COTP, 12 SNMP, and 17 other records |

The activity distribution is highly concentrated: the median source produced 18 records, the largest source produced 17.3% of source-attributed records, and the top ten produced 52.9%.

## Files

- `metrics.json` — machine-readable headline metrics, export windows, and source hashes.
- `dataset_manifest.csv` — row counts, date ranges where available, SHA-256 checksums, and each export’s analytical role.
- `attacker_summary_sanitized.csv` — source-level counts using sequential pseudonyms instead of IP addresses.
- `cross_targeting_sanitized.csv` — the 54 pseudonymous sources observed by both Cowrie and Conpot.
- `command_categories.csv` — command occurrences grouped into behavior categories; raw commands and payload indicators are withheld.
- `ics_protocol_summary.csv` — protocol-level Conpot interaction counts.
- `high_severity_summary.csv` — category counts from the file originally exported as `high_severity.csv`; this repository describes it as high-signal because no formal severity rubric was preserved.
- `high_severity_daily.csv` — daily high-signal counts in UTC.

## Scope and Reconciliation

The source exports were produced by different Splunk searches and do not all cover the same window:

- The aggregate source export has no time column. It supports source and event totals but not a collection start or end date.
- The high-signal export covers 2026-04-02 16:05:15.650 UTC through 2026-04-23 13:10:58 UTC.
- The ICS export covers 2026-04-02 16:05:15.650 UTC through 2026-04-22 23:26:36.931 UTC.
- The file originally named `master_dataset.csv` is a capped 10,000-row recent-event sample covering only 2026-04-23 03:29:50 UTC through 14:11:21.649 UTC. It is not the full event corpus.

All 54 cross-targeting rows reconcile exactly to the source summary. The command-category total reconciles to all 457 command-input occurrences. The ICS protocol categories reconcile to all 721 ICS records.

## Privacy Method

Public attacker IDs are sequential pseudonyms ranked by total event count. The IP-to-ID mapping is never written to this repository. No raw IPs, usernames, passwords, commands, payload URLs, UUIDs, or host paths are published.

The public outputs can be regenerated locally from retained private exports:

```bash
python3 scripts/build_evidence.py \
  --input-dir /path/to/private/exports \
  --output-dir artifacts/evidence

python3 scripts/validate_public_evidence.py artifacts/evidence
```

CI uses synthetic fixtures to test the builder and validates both metric reconciliation and the absence of sensitive field names and identifier patterns in committed public evidence.
