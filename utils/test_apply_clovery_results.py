from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from utils.apply_clovery_results import sync_results


def create_mapping_db(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE cve_info(cve_id TEXT PRIMARY KEY);
            CREATE TABLE repo2cve(
                repo_key TEXT NOT NULL,cve_id TEXT NOT NULL,product_id INTEGER NOT NULL,
                match_method TEXT NOT NULL,manual_review_required INTEGER NOT NULL,
                provisional_llm_identity INTEGER NOT NULL,
                PRIMARY KEY(repo_key,cve_id,product_id)
            );
            CREATE TABLE cve_version_range(
                range_id INTEGER PRIMARY KEY,cve_id TEXT NOT NULL,product_id INTEGER NOT NULL,
                polarity TEXT,lower_bound TEXT,lower_inclusive INTEGER,
                upper_bound TEXT,upper_inclusive INTEGER,exact_value TEXT,
                version_resolution_class TEXT,breadth_class TEXT,is_default_closure INTEGER,
                source_family TEXT,evidence_tier TEXT
            );
            CREATE VIEW repo_cve_version AS
            SELECT r.repo_key,r.cve_id,r.product_id,r.match_method,
                   r.manual_review_required,r.provisional_llm_identity,
                   v.polarity,v.lower_bound,v.lower_inclusive,v.upper_bound,
                   v.upper_inclusive,v.exact_value,v.version_resolution_class,
                   v.breadth_class,v.is_default_closure,v.source_family,v.evidence_tier
            FROM repo2cve r JOIN cve_version_range v
              ON v.cve_id=r.cve_id AND v.product_id=r.product_id;
            INSERT INTO cve_info VALUES('CVE-2024-0001');
            INSERT INTO repo2cve VALUES('owner@repo','CVE-2024-0001',7,'exact',0,0);
            INSERT INTO cve_version_range VALUES(
                1,'CVE-2024-0001',7,'affected',NULL,NULL,'1.9',1,NULL,
                'nvd_range','bounded',0,'nvd','primary'
            );
            """
        )


def write_result(
    root: Path,
    *,
    confidence: str,
    introduced: str = "1.2",
    last_affected: str = "1.4",
    ranges: bool = True,
    mtime_ns: int,
) -> None:
    folder = root / "owner##repo"
    folder.mkdir(parents=True, exist_ok=True)
    proposed_ranges = (
        [
            {
                "introduced": introduced,
                "last_affected": last_affected,
                "fixed": "1.5",
                "fixed_source": "clovery+patch_commit",
            }
        ]
        if ranges
        else []
    )
    payload = {
        "repo": "owner@repo",
        "results": [
            {
                "repo": "owner@repo",
                "cve": "CVE-2024-0001",
                "state": "verified" if ranges else "no_vulnerable_release",
                "tag_count": 10,
                "evaluated_tags": 10,
                "unknown_tags": 0,
                "proposal": {
                    "confidence": confidence,
                    "changed": True,
                    "ranges": proposed_ranges,
                },
            }
        ],
    }
    path = folder / "version_ranges.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.utime(path, ns=(mtime_ns, mtime_ns))


class ApplyCloveryResultsTest(unittest.TestCase):
    def test_duplicate_import_is_idempotent_and_high_overrides_nvd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "repo.sqlite"
            results = root / "results"
            create_mapping_db(database)
            write_result(results, confidence="high", mtime_ns=100)

            first = sync_results(results_root=results, database=database)
            second = sync_results(results_root=results, database=database)

            self.assertEqual(first["inserted_results"], 1)
            self.assertEqual(second["inserted_results"], 0)
            self.assertEqual(second["duplicate_results"], 1)
            with sqlite3.connect(database) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM clovery_result").fetchone()[0], 1)
                row = connection.execute(
                    """SELECT lower_bound,upper_bound,range_source,fixed
                       FROM repo_cve_version_effective"""
                ).fetchone()
            self.assertEqual(row, ("1.2", "1.4", "clovery", "1.5"))

    def test_newer_low_result_becomes_current_but_falls_back_to_nvd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "repo.sqlite"
            results = root / "results"
            create_mapping_db(database)
            write_result(results, confidence="high", mtime_ns=100)
            sync_results(results_root=results, database=database)
            write_result(
                results,
                confidence="low",
                introduced="1.6",
                last_affected="1.7",
                mtime_ns=200,
            )
            sync_results(results_root=results, database=database)

            with sqlite3.connect(database) as connection:
                current = connection.execute(
                    "SELECT confidence FROM clovery_result_current"
                ).fetchone()[0]
                effective = connection.execute(
                    """SELECT upper_bound,range_source
                       FROM repo_cve_version_effective"""
                ).fetchone()
            self.assertEqual(current, "low")
            self.assertEqual(effective, ("1.9", "nvd"))

    def test_accepted_empty_range_suppresses_nvd_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "repo.sqlite"
            results = root / "results"
            create_mapping_db(database)
            write_result(results, confidence="medium", ranges=False, mtime_ns=100)
            sync_results(
                results_root=results,
                database=database,
                min_confidence="medium",
            )
            with sqlite3.connect(database) as connection:
                count = connection.execute(
                    "SELECT COUNT(*) FROM repo_cve_version_effective"
                ).fetchone()[0]
            self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
