from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from scripts.nvd_normalization.builder import build_database
from utils.maintain_nvd_cves import MaintenanceConfig, run_maintenance


def cve(
    cve_id: str,
    modified: str,
    *,
    status: str = "Analyzed",
    marker: str = "current",
) -> dict:
    return {
        "cve": {
            "id": cve_id,
            "sourceIdentifier": "smoke@example.test",
            "published": "2024-01-01T00:00:00.000Z",
            "lastModified": modified,
            "vulnStatus": status,
            "descriptions": [{"lang": "en", "value": marker}],
        }
    }


def history_event(
    cve_id: str,
    created: str,
    event: str,
    sequence: int,
    details: list[dict] | None = None,
) -> dict:
    return {
        "change": {
            "cveId": cve_id,
            "eventName": event,
            "cveChangeId": f"00000000-0000-0000-0000-{sequence:012d}",
            "sourceIdentifier": "nvd@nist.gov",
            "created": created,
            "details": details or [],
        }
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class MaintainNvdCvesSmokeTest(unittest.TestCase):
    def test_latest_revision_rejection_unrejection_and_stale_removal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.jsonl"
            update = root / "update.jsonl"
            history = root / "history.jsonl"
            output = root / "current.jsonl"
            report = root / "report.json"
            quarantine = root / "quarantine.jsonl"

            write_jsonl(
                base,
                [
                    cve("CVE-2024-0001", "2024-01-01T00:00:00Z", marker="old"),
                    cve("CVE-2024-0002", "2024-01-02T00:00:00Z"),
                    cve("CVE-2024-0003", "2024-01-03T00:00:00Z", status="Rejected"),
                    cve("CVE-2024-0004", "2024-01-05T00:00:00Z"),
                    cve("CVE-2024-0005", "2024-01-01T00:00:00Z"),
                ],
            )
            write_jsonl(
                update,
                [
                    cve("CVE-2024-0001", "2024-01-06T00:00:00Z", marker="new"),
                ],
            )
            write_jsonl(
                history,
                [
                    history_event(
                        "CVE-2024-0001", "2024-01-06T00:00:00Z", "CVE Modified", 1
                    ),
                    history_event(
                        "CVE-2024-0002", "2024-01-03T00:00:00Z", "CVE Rejected", 2
                    ),
                    history_event(
                        "CVE-2024-0004", "2024-01-02T00:00:00Z", "CVE Rejected", 3
                    ),
                    history_event(
                        "CVE-2024-0004", "2024-01-04T00:00:00Z", "CVE Unrejected", 4
                    ),
                    history_event(
                        "CVE-2024-0005",
                        "2024-01-03T00:00:00Z",
                        "Modified Analysis",
                        5,
                        [{"action": "Removed", "type": "CWE", "oldValue": "CWE-79"}],
                    ),
                ],
            )

            result = run_maintenance(
                MaintenanceConfig(
                    inputs=(base, update),
                    history=history,
                    output=output,
                    report=report,
                    quarantine=quarantine,
                    progress_every=0,
                )
            )

            rows = read_jsonl(output)
            by_id = {row["cve"]["id"]: row for row in rows}
            self.assertEqual(set(by_id), {"CVE-2024-0001", "CVE-2024-0004"})
            self.assertEqual(
                by_id["CVE-2024-0001"]["cve"]["descriptions"][0]["value"],
                "new",
            )
            reasons = {
                row["cve_id"]: row["reason"] for row in read_jsonl(quarantine)
            }
            self.assertEqual(reasons["CVE-2024-0002"], "terminal_history_rejected")
            self.assertEqual(reasons["CVE-2024-0003"], "record_status_rejected")
            self.assertEqual(reasons["CVE-2024-0005"], "stale_after_history")
            self.assertEqual(result["output"]["cve_count"], 2)
            self.assertEqual(result["history_summary"]["detail_actions"]["Removed"], 1)

            database = root / "smoke.sqlite"
            build_database(
                input_path=output,
                database_path=database,
                llm_path=None,
                llm_fail_path=None,
                replace_existing=False,
                limit=None,
                progress_every=0,
            )
            with sqlite3.connect(database) as connection:
                database_cves = {
                    row[0] for row in connection.execute("SELECT cve_id FROM raw_cve")
                }
            self.assertEqual(database_cves, set(by_id))

    def test_snapshot_coverage_keeps_record_after_field_removal_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.jsonl"
            history = root / "history.jsonl"
            output = root / "current.jsonl"
            report = root / "report.json"
            quarantine = root / "quarantine.jsonl"
            write_jsonl(
                source,
                [cve("CVE-2024-0010", "2024-01-01T00:00:00Z")],
            )
            write_jsonl(
                history,
                [
                    history_event(
                        "CVE-2024-0010",
                        "2024-01-03T00:00:00Z",
                        "CPE Deprecation Remap",
                        10,
                        [
                            {
                                "action": "Removed",
                                "type": "CPE Configuration",
                                "oldValue": "old CPE",
                            }
                        ],
                    )
                ],
            )

            result = run_maintenance(
                MaintenanceConfig(
                    inputs=(source,),
                    history=history,
                    output=output,
                    report=report,
                    quarantine=quarantine,
                    snapshot_as_of="2024-01-04T00:00:00Z",
                    progress_every=0,
                )
            )

            self.assertEqual(len(read_jsonl(output)), 1)
            self.assertEqual(read_jsonl(quarantine), [])
            self.assertEqual(result["decision_summary"]["current"], 1)


if __name__ == "__main__":
    unittest.main()
