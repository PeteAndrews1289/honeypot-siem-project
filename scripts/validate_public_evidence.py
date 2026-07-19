#!/usr/bin/env python3
"""Validate public honeypot evidence totals and redaction guarantees."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


FORBIDDEN_HEADERS = {"attacker_ip", "src_ip", "username", "password", "_raw", "input"}
FORBIDDEN_PATTERNS = {
    "IPv4 address": re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    "URL": re.compile(r"https?://", re.IGNORECASE),
    "UUID": re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.IGNORECASE),
    "home path": re.compile(r"/(?:home|Users)/"),
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        forbidden = set(reader.fieldnames or []) & FORBIDDEN_HEADERS
        if forbidden:
            raise AssertionError(f"{path.name} contains forbidden columns: {sorted(forbidden)}")
        return list(reader)


def validate(directory: Path) -> None:
    public_files = sorted(path for path in directory.iterdir() if path.suffix in {".csv", ".json"})
    if not public_files:
        raise AssertionError("No public evidence files found")
    for path in public_files:
        text = path.read_text(encoding="utf-8")
        for label, pattern in FORBIDDEN_PATTERNS.items():
            if pattern.search(text):
                raise AssertionError(f"{path.name} contains a forbidden {label}")

    attackers = read_csv(directory / "attacker_summary_sanitized.csv")
    cross_targeting = read_csv(directory / "cross_targeting_sanitized.csv")
    commands = read_csv(directory / "command_categories.csv")
    protocols = read_csv(directory / "ics_protocol_summary.csv")
    high_signal = read_csv(directory / "high_severity_summary.csv")
    metrics = json.loads((directory / "metrics.json").read_text(encoding="utf-8"))

    attacker_ids = {row["attacker_id"] for row in attackers}
    if len(attackers) != 4_624 or len(attacker_ids) != 4_624:
        raise AssertionError("Expected 4,624 unique pseudonymous source IDs")
    if sum(int(row["total_events"]) for row in attackers) != 952_393:
        raise AssertionError("Source-attributed event total must equal 952,393")
    if sum(row["address_scope"] == "global" for row in attackers) != 4_623:
        raise AssertionError("Expected 4,623 globally routable source addresses")

    attacker_totals = {row["attacker_id"]: int(row["total_events"]) for row in attackers}
    if len(cross_targeting) != 54:
        raise AssertionError("Expected 54 cross-targeting source IDs")
    for row in cross_targeting:
        if row["attacker_id"] not in attacker_ids:
            raise AssertionError("Cross-targeting source missing from sanitized attacker summary")
        if int(row["event_count"]) != attacker_totals[row["attacker_id"]]:
            raise AssertionError("Cross-targeting event total does not reconcile")

    if sum(int(row["occurrences"]) for row in commands) != 457:
        raise AssertionError("Command occurrence total must equal 457")
    if sum(int(row["events"]) for row in protocols) != 721:
        raise AssertionError("ICS protocol total must equal 721")
    if sum(int(row["events"]) for row in high_signal) != 1_780:
        raise AssertionError("High-signal event total must equal 1,780")

    aggregate = metrics["aggregate_export"]
    if aggregate["total_events"] != 952_393 or aggregate["cross_targeting_sources"] != 54:
        raise AssertionError("metrics.json headline values do not reconcile")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    validate(args.directory)
    print("Public evidence validation passed")


if __name__ == "__main__":
    main()
