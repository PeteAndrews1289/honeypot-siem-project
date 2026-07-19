#!/usr/bin/env python3
"""Build privacy-preserving evidence artifacts from Splunk CSV exports.

Raw exports can contain source IP addresses, credentials, commands, payloads,
and host paths. This utility validates the six project exports and writes only
aggregate or pseudonymized artifacts suitable for a public portfolio.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


HEADER_ORDER = {
    "master_dataset.csv": ["_time", "honeypot", "attacker_ip", "activity_type", "_raw"],
    "cross_targeting.csv": ["attacker_ip", "systems", "targets", "count"],
    "high_severity.csv": ["_time", "source", "_raw"],
    "ics_activity.csv": ["_time", "_raw"],
    "cowrie_commands.csv": ["input", "count"],
    "attacker_summary.csv": ["attacker_ip", "total_events", "systems_targeted", "targets"],
}
EXPECTED_HEADERS = {name: set(headers) for name, headers in HEADER_ORDER.items()}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True, help="Directory containing the six Splunk CSV exports")
    parser.add_argument("--output-dir", type=Path, required=True, help="Destination for sanitized evidence artifacts")
    return parser.parse_args()


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        actual = set(reader.fieldnames or [])
        expected = EXPECTED_HEADERS[path.name]
        if actual != expected:
            raise ValueError(f"{path.name}: expected headers {sorted(expected)}, found {sorted(actual)}")
        return list(reader)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_time(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def date_range(rows: Iterable[dict[str, str]]) -> tuple[str, str]:
    timestamps = sorted(parse_time(row["_time"]) for row in rows)
    if not timestamps:
        return "", ""
    return timestamps[0].isoformat().replace("+00:00", "Z"), timestamps[-1].isoformat().replace("+00:00", "Z")


def count_keyword(rows: Iterable[dict[str, str]], keyword: str) -> int:
    needle = keyword.casefold()
    return sum(1 for row in rows if needle in row.get("_raw", "").casefold())


def command_category(command: str) -> str:
    value = command.strip().casefold()
    if not value:
        return "blank"
    if re.search(r"\b(?:wget|curl|tftp|ftpget|ftp|scp)\b", value):
        return "payload_transfer"
    if re.search(r"\b(?:uname|id|whoami|hostname|lscpu|dmidecode|cat|ls|pwd|nproc)\b", value):
        return "host_discovery"
    if re.search(r"\b(?:ps|netstat|ss|ifconfig|ip|route)\b", value):
        return "process_or_network_discovery"
    if re.search(r"\b(?:chmod|chattr)\b", value):
        return "permission_change"
    if re.search(r"\b(?:sh|bash|python|perl|busybox|nohup)\b", value):
        return "shell_or_interpreter"
    if re.search(r"\b(?:rm|kill|pkill)\b|history\s+-c", value):
        return "cleanup_or_inhibit"
    if re.search(r"\b(?:crontab|systemctl|service|init\.d)\b", value):
        return "persistence_or_service"
    return "other"


def ics_protocol(raw: str) -> str:
    value = raw.casefold()
    if "modbus" in value:
        return "Modbus"
    if re.search(r"\bs7\b", value):
        return "S7"
    if re.search(r"\bcotp\b", value):
        return "COTP"
    if "snmp" in value:
        return "SNMP"
    return "Other"


def write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def build(input_dir: Path, output_dir: Path) -> dict[str, object]:
    source_paths = {name: input_dir / name for name in EXPECTED_HEADERS}
    missing = [name for name, path in source_paths.items() if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Missing required exports: {', '.join(sorted(missing))}")

    source_rows = {name: read_rows(path) for name, path in source_paths.items()}
    output_dir.mkdir(parents=True, exist_ok=True)

    attacker_rows = source_rows["attacker_summary.csv"]
    ranked_attackers = sorted(
        enumerate(attacker_rows),
        key=lambda pair: (-int(pair[1]["total_events"]), pair[0]),
    )
    attacker_ids: dict[str, str] = {}
    sanitized_attackers: list[dict[str, object]] = []
    global_source_count = 0
    global_event_count = 0
    non_global_source_count = 0
    non_global_event_count = 0

    for rank, (_, row) in enumerate(ranked_attackers, start=1):
        attacker_id = f"A{rank:04d}"
        attacker_ids[row["attacker_ip"]] = attacker_id
        address = ipaddress.ip_address(row["attacker_ip"])
        scope = "global" if address.is_global else "non_global"
        event_count = int(row["total_events"])
        if address.is_global:
            global_source_count += 1
            global_event_count += event_count
        else:
            non_global_source_count += 1
            non_global_event_count += event_count
        sanitized_attackers.append(
            {
                "attacker_id": attacker_id,
                "total_events": event_count,
                "systems_targeted": int(row["systems_targeted"]),
                "targets": row["targets"],
                "address_scope": scope,
            }
        )

    write_csv(
        output_dir / "attacker_summary_sanitized.csv",
        ["attacker_id", "total_events", "systems_targeted", "targets", "address_scope"],
        sanitized_attackers,
    )

    sanitized_cross_targeting = []
    for row in source_rows["cross_targeting.csv"]:
        if row["attacker_ip"] not in attacker_ids:
            raise ValueError("cross_targeting.csv contains a source missing from attacker_summary.csv")
        sanitized_cross_targeting.append(
            {
                "attacker_id": attacker_ids[row["attacker_ip"]],
                "systems": int(row["systems"]),
                "targets": row["targets"],
                "event_count": int(row["count"]),
            }
        )
    sanitized_cross_targeting.sort(key=lambda row: (-int(row["event_count"]), str(row["attacker_id"])))
    write_csv(
        output_dir / "cross_targeting_sanitized.csv",
        ["attacker_id", "systems", "targets", "event_count"],
        sanitized_cross_targeting,
    )

    command_counts: Counter[str] = Counter()
    tool_mentions: Counter[str] = Counter()
    for row in source_rows["cowrie_commands.csv"]:
        occurrences = int(row["count"])
        command_counts[command_category(row["input"])] += occurrences
        normalized_command = row["input"].casefold()
        for tool in ("wget", "curl", "tftp", "ftpget"):
            if re.search(rf"\b{tool}\b", normalized_command):
                tool_mentions[tool] += occurrences
    write_csv(
        output_dir / "command_categories.csv",
        ["category", "occurrences"],
        ({"category": category, "occurrences": count} for category, count in command_counts.most_common()),
    )

    protocol_counts: Counter[str] = Counter(ics_protocol(row["_raw"]) for row in source_rows["ics_activity.csv"])
    write_csv(
        output_dir / "ics_protocol_summary.csv",
        ["protocol", "events"],
        ({"protocol": protocol, "events": count} for protocol, count in protocol_counts.most_common()),
    )

    high_severity = source_rows["high_severity.csv"]
    high_severity_metrics: Counter[str] = Counter()
    for row in high_severity:
        source = row["source"].casefold()
        raw = row["_raw"].casefold()
        if "cowrie" in source and "cowrie.login.success" in raw:
            category = "Cowrie successful login"
        elif "cowrie" in source and "cowrie.command.input" in raw:
            category = "Cowrie command input"
        elif "cowrie" in source:
            category = "Cowrie other high-signal event"
        elif "conpot" in source:
            category = f"Conpot {ics_protocol(raw)}"
        else:
            category = "Other high-signal event"
        high_severity_metrics[category] += 1
    write_csv(
        output_dir / "high_severity_summary.csv",
        ["category", "events"],
        ({"category": category, "events": count} for category, count in high_severity_metrics.most_common()),
    )

    high_daily: dict[str, Counter[str]] = defaultdict(Counter)
    for row in high_severity:
        day = parse_time(row["_time"]).date().isoformat()
        raw = row["_raw"].casefold()
        source = row["source"].casefold()
        if "cowrie" in source and "cowrie.login.success" in raw:
            category = "cowrie_login_success"
        elif "cowrie" in source and "cowrie.command.input" in raw:
            category = "cowrie_command_input"
        elif "cowrie" in source:
            category = "cowrie_other"
        elif "conpot" in source:
            category = f"conpot_{ics_protocol(raw).casefold()}"
        else:
            category = "other"
        high_daily[day][category] += 1
    high_daily_rows = []
    daily_fields = [
        "date",
        "cowrie_login_success",
        "cowrie_command_input",
        "cowrie_other",
        "conpot_s7",
        "conpot_cotp",
        "conpot_modbus",
        "conpot_other",
        "other",
    ]
    for day in sorted(high_daily):
        high_daily_rows.append({"date": day, **{field: high_daily[day][field] for field in daily_fields[1:]}})
    write_csv(output_dir / "high_severity_daily.csv", daily_fields, high_daily_rows)

    master = source_rows["master_dataset.csv"]
    master_start, master_end = date_range(master)
    high_start, high_end = date_range(high_severity)
    ics_start, ics_end = date_range(source_rows["ics_activity.csv"])
    master_honeypots = Counter(row["honeypot"] for row in master)
    master_activities = Counter(row["activity_type"] for row in master)
    total_events = sum(int(row["total_events"]) for row in attacker_rows)
    target_counts = Counter(row["targets"] for row in attacker_rows)
    target_event_counts: Counter[str] = Counter()
    event_counts = []
    for row in attacker_rows:
        event_count = int(row["total_events"])
        event_counts.append(event_count)
        target_event_counts[row["targets"]] += event_count
    descending_event_counts = sorted(event_counts, reverse=True)

    manifest_rows = []
    date_ranges = {
        "master_dataset.csv": (master_start, master_end),
        "high_severity.csv": (high_start, high_end),
        "ics_activity.csv": (ics_start, ics_end),
    }
    roles = {
        "master_dataset.csv": "10,000-row event sample",
        "attacker_summary.csv": "aggregate source and event counts",
        "cross_targeting.csv": "sources observed by both honeypots",
        "high_severity.csv": "successful logins, commands, and high-signal ICS activity",
        "ics_activity.csv": "ICS protocol event export",
        "cowrie_commands.csv": "aggregated Cowrie command counts",
    }
    for name, path in source_paths.items():
        start, end = date_ranges.get(name, ("", ""))
        manifest_rows.append(
            {
                "source_file": name,
                "rows": len(source_rows[name]),
                "start_utc": start,
                "end_utc": end,
                "sha256": sha256_file(path),
                "role": roles[name],
            }
        )
    write_csv(
        output_dir / "dataset_manifest.csv",
        ["source_file", "rows", "start_utc", "end_utc", "sha256", "role"],
        manifest_rows,
    )

    metrics: dict[str, object] = {
        "schema_version": 1,
        "privacy": {
            "raw_source_ips_published": False,
            "raw_commands_or_payloads_published": False,
            "attacker_ids": "Sequential pseudonyms ranked by total event count; no mapping is published.",
        },
        "aggregate_export": {
            "unique_source_values": len(attacker_rows),
            "globally_routable_sources": global_source_count,
            "non_global_sources": non_global_source_count,
            "total_events": total_events,
            "globally_routable_source_events": global_event_count,
            "non_global_source_events": non_global_event_count,
            "cowrie_only_sources": target_counts["Cowrie"],
            "conpot_only_sources": target_counts["Conpot"],
            "cross_targeting_sources": target_counts["Conpot Cowrie"],
            "cowrie_only_source_events": target_event_counts["Cowrie"],
            "conpot_only_source_events": target_event_counts["Conpot"],
            "cross_targeting_source_events": target_event_counts["Conpot Cowrie"],
            "median_events_per_source": statistics.median(event_counts),
            "top_source_event_share": round(descending_event_counts[0] / total_events, 6),
            "top_10_source_event_share": round(sum(descending_event_counts[:10]) / total_events, 6),
        },
        "high_severity_export": {
            "start_utc": high_start,
            "end_utc": high_end,
            "rows": len(high_severity),
            "categories": dict(high_severity_metrics),
        },
        "ics_export": {
            "start_utc": ics_start,
            "end_utc": ics_end,
            "rows": len(source_rows["ics_activity.csv"]),
            "protocols": dict(protocol_counts),
        },
        "command_export": {
            "distinct_rows": len(source_rows["cowrie_commands.csv"]),
            "total_occurrences": sum(int(row["count"]) for row in source_rows["cowrie_commands.csv"]),
            "nonempty_occurrences": sum(
                int(row["count"]) for row in source_rows["cowrie_commands.csv"] if row["input"].strip()
            ),
            "categories": dict(command_counts),
            "tool_mentions": dict(tool_mentions),
        },
        "master_sample": {
            "start_utc": master_start,
            "end_utc": master_end,
            "rows": len(master),
            "unique_nonblank_sources": len({row["attacker_ip"] for row in master if row["attacker_ip"]}),
            "blank_source_rows": sum(1 for row in master if not row["attacker_ip"]),
            "honeypots": dict(master_honeypots),
            "activity_types": dict(master_activities),
        },
        "source_files": {name: sha256_file(path) for name, path in source_paths.items()},
    }
    (output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metrics


def main() -> None:
    args = parse_args()
    metrics = build(args.input_dir, args.output_dir)
    print(json.dumps(metrics, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
