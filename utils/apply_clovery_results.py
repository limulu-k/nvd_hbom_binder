#!/usr/bin/env python3
"""Import completed ``clovery_cycle`` results into ``repo_cve.sqlite``.

The importer is deliberately append-only at the evidence layer.  It does not
rewrite the NVD-derived ``cve_version_range`` table.  Instead it stores every
distinct Clovery result, selects the newest result for each repository/CVE,
and exposes the selected override through ``repo_cve_version_effective``.

This makes repeated and concurrent runs safe:

* only repositories with a complete, parseable ``version_ranges.json`` enter;
* a canonical result hash and a UNIQUE constraint deduplicate reruns;
* the source file's nanosecond mtime prevents an older copied result from
  replacing a newer one;
* one ``BEGIN IMMEDIATE`` transaction publishes a whole scan atomically; and
* SQLite's busy timeout waits for another importer instead of partially
  applying a batch.

By default only ``high`` confidence results override the NVD range.  Medium and
low confidence results are still retained for audit.  Use ``--min-confidence``
to change the effective-view policy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


DEFAULT_RESULTS = Path("workspace/clovery/results")
DEFAULT_DATABASE = Path("workspace/repo_cve.sqlite")
SCHEMA_VERSION = "1"
CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


class ImportError(RuntimeError):
    """A stable input or destination database is not suitable for import."""


@dataclass(frozen=True)
class Candidate:
    repo_key: str
    cve_id: str
    result_hash: str
    source_file: str
    source_mtime_ns: int
    state: str
    confidence: str
    changed: bool
    tag_count: int
    evaluated_tags: int
    unknown_tags: int
    proposal_json: str
    result_json: str
    ranges: tuple[Mapping[str, Any], ...]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def table_exists(connection: sqlite3.Connection, name: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def validate_destination(connection: sqlite3.Connection) -> None:
    required = {"repo2cve", "cve_info", "cve_version_range"}
    missing = sorted(name for name in required if not table_exists(connection, name))
    if missing:
        raise ImportError(
            "destination is not repo_cve.sqlite; missing table(s): "
            + ", ".join(missing)
        )


def read_stable_json(path: Path) -> tuple[dict[str, Any] | None, str | None, int]:
    """Read a file only if its identity and size stay stable across the read.

    ``clovery_cycle`` currently writes JSON directly.  A scanner can therefore
    catch it between truncate and close.  Such a file is skipped, not treated as
    a fatal malformed result; the next sync will see the completed file.
    """

    try:
        before = path.stat()
        body = path.read_bytes()
        after = path.stat()
    except OSError as error:
        return None, f"unreadable: {error}", 0
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(body) != after.st_size:
        return None, "changed while being read", after.st_mtime_ns
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return None, f"incomplete or invalid JSON: {error}", after.st_mtime_ns
    if not isinstance(payload, dict):
        return None, "top-level JSON value is not an object", after.st_mtime_ns
    return payload, None, after.st_mtime_ns


def integer_field(entry: Mapping[str, Any], name: str) -> int:
    value = entry.get(name, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ImportError(f"{name} must be a non-negative integer")
    return value


def parse_candidate(
    entry: Mapping[str, Any], *, repo_key: str, source: Path, mtime_ns: int
) -> Candidate:
    cve_id = entry.get("cve")
    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        raise ImportError("result has no valid cve field")
    entry_repo = entry.get("repo", repo_key)
    if entry_repo != repo_key:
        raise ImportError(f"result repo {entry_repo!r} differs from root repo {repo_key!r}")
    proposal = entry.get("proposal")
    if not isinstance(proposal, dict):
        raise ImportError(f"{cve_id}: proposal is not an object")
    confidence = proposal.get("confidence")
    if confidence not in CONFIDENCE_RANK:
        raise ImportError(f"{cve_id}: unsupported confidence {confidence!r}")
    ranges = proposal.get("ranges")
    if not isinstance(ranges, list):
        raise ImportError(f"{cve_id}: proposal.ranges is not an array")
    for ordinal, item in enumerate(ranges):
        if not isinstance(item, dict):
            raise ImportError(f"{cve_id}: range {ordinal} is not an object")
        introduced = item.get("introduced")
        last_affected = item.get("last_affected")
        if not isinstance(introduced, str) or not isinstance(last_affected, str):
            raise ImportError(
                f"{cve_id}: range {ordinal} needs string introduced/last_affected"
            )
        for optional in ("fixed", "fixed_source"):
            if item.get(optional) is not None and not isinstance(item[optional], str):
                raise ImportError(f"{cve_id}: range {ordinal} {optional} must be a string")

    normalized_entry = dict(entry)
    normalized_entry["repo"] = repo_key
    result_json = canonical_json(normalized_entry)
    result_hash = hashlib.sha256(result_json.encode("utf-8")).hexdigest()
    changed = proposal.get("changed", False)
    if not isinstance(changed, bool):
        raise ImportError(f"{cve_id}: proposal.changed must be boolean")
    state = entry.get("state", "unknown")
    if not isinstance(state, str):
        raise ImportError(f"{cve_id}: state must be a string")
    return Candidate(
        repo_key=repo_key,
        cve_id=cve_id,
        result_hash=result_hash,
        source_file=str(source),
        source_mtime_ns=mtime_ns,
        state=state,
        confidence=confidence,
        changed=changed,
        tag_count=integer_field(entry, "tag_count"),
        evaluated_tags=integer_field(entry, "evaluated_tags"),
        unknown_tags=integer_field(entry, "unknown_tags"),
        proposal_json=canonical_json(proposal),
        result_json=result_json,
        ranges=tuple(ranges),
    )


def scan_results(results_root: Path) -> tuple[list[Candidate], list[dict[str, str]]]:
    if not results_root.is_dir():
        raise ImportError(f"results root does not exist: {results_root}")
    candidates: list[Candidate] = []
    skipped: list[dict[str, str]] = []
    for path in sorted(results_root.glob("*/version_ranges.json")):
        payload, problem, mtime_ns = read_stable_json(path)
        if problem:
            skipped.append({"file": str(path), "reason": problem})
            continue
        assert payload is not None
        repo_key = payload.get("repo")
        entries = payload.get("results")
        if not isinstance(repo_key, str) or "@" not in repo_key:
            skipped.append({"file": str(path), "reason": "missing repo key"})
            continue
        if not isinstance(entries, list):
            skipped.append({"file": str(path), "reason": "results is not an array"})
            continue
        try:
            parsed = [
                parse_candidate(entry, repo_key=repo_key, source=path, mtime_ns=mtime_ns)
                for entry in entries
                if isinstance(entry, dict)
            ]
            if len(parsed) != len(entries):
                raise ImportError("results contains a non-object entry")
            candidates.extend(parsed)
        except ImportError as error:
            skipped.append({"file": str(path), "reason": str(error)})
    return candidates, skipped


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS clovery_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS clovery_sync_run (
    sync_id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    results_root TEXT NOT NULL,
    min_confidence TEXT NOT NULL,
    candidate_count INTEGER NOT NULL DEFAULT 0,
    inserted_count INTEGER NOT NULL DEFAULT 0,
    duplicate_count INTEGER NOT NULL DEFAULT 0,
    unmapped_count INTEGER NOT NULL DEFAULT 0,
    skipped_file_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS clovery_result (
    result_id INTEGER PRIMARY KEY,
    repo_key TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    result_sha256 TEXT NOT NULL,
    source_file TEXT NOT NULL,
    source_mtime_ns INTEGER NOT NULL,
    first_imported_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    state TEXT NOT NULL,
    confidence TEXT NOT NULL CHECK (confidence IN ('none','low','medium','high')),
    changed INTEGER NOT NULL CHECK (changed IN (0,1)),
    tag_count INTEGER NOT NULL,
    evaluated_tags INTEGER NOT NULL,
    unknown_tags INTEGER NOT NULL,
    proposal_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    UNIQUE (repo_key,cve_id,result_sha256),
    FOREIGN KEY (cve_id) REFERENCES cve_info(cve_id)
);

CREATE TABLE IF NOT EXISTS clovery_result_range (
    result_id INTEGER NOT NULL REFERENCES clovery_result(result_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    introduced TEXT NOT NULL,
    last_affected TEXT NOT NULL,
    fixed TEXT,
    fixed_source TEXT,
    fixed_conflict_json TEXT,
    PRIMARY KEY (result_id,ordinal)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS clovery_result_repo_cve_idx
    ON clovery_result(repo_key,cve_id,source_mtime_ns DESC,result_id DESC);
"""


VIEW_SQL = """
DROP VIEW IF EXISTS repo_cve_version_effective;
DROP VIEW IF EXISTS clovery_result_effective;
DROP VIEW IF EXISTS clovery_result_current;

CREATE VIEW clovery_result_current AS
SELECT c.*
FROM clovery_result c
WHERE NOT EXISTS (
    SELECT 1
    FROM clovery_result newer
    WHERE newer.repo_key=c.repo_key
      AND newer.cve_id=c.cve_id
      AND (
          newer.source_mtime_ns > c.source_mtime_ns
          OR (newer.source_mtime_ns=c.source_mtime_ns AND newer.result_id > c.result_id)
      )
);

CREATE VIEW clovery_result_effective AS
SELECT c.*
FROM clovery_result_current c
WHERE CASE c.confidence
          WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0
      END >= CASE (SELECT value FROM clovery_config WHERE key='min_confidence')
          WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0
      END;

CREATE VIEW repo_cve_version_effective AS
SELECT r.repo_key,r.cve_id,r.product_id,r.match_method,
       r.manual_review_required,r.provisional_llm_identity,
       'affected' AS polarity,
       v.introduced AS lower_bound,1 AS lower_inclusive,
       v.last_affected AS upper_bound,1 AS upper_inclusive,
       NULL AS exact_value,
       'clovery_derived_range' AS version_resolution_class,
       'bounded' AS breadth_class,0 AS is_default_closure,
       'clovery' AS source_family,c.confidence AS evidence_tier,
       'clovery' AS range_source,
       v.fixed,v.fixed_source,c.confidence AS clovery_confidence,
       c.result_id AS clovery_result_id
FROM repo2cve r
JOIN clovery_result_effective c
  ON c.repo_key=r.repo_key AND c.cve_id=r.cve_id
JOIN clovery_result_range v ON v.result_id=c.result_id
UNION ALL
SELECT b.repo_key,b.cve_id,b.product_id,b.match_method,
       b.manual_review_required,b.provisional_llm_identity,
       b.polarity,b.lower_bound,b.lower_inclusive,
       b.upper_bound,b.upper_inclusive,b.exact_value,
       b.version_resolution_class,b.breadth_class,b.is_default_closure,
       b.source_family,b.evidence_tier,
       'nvd' AS range_source,
       NULL AS fixed,NULL AS fixed_source,NULL AS clovery_confidence,
       NULL AS clovery_result_id
FROM repo_cve_version b
WHERE NOT EXISTS (
    SELECT 1 FROM clovery_result_effective c
    WHERE c.repo_key=b.repo_key AND c.cve_id=b.cve_id
);
"""


def create_schema(connection: sqlite3.Connection, min_confidence: str) -> None:
    # sqlite3.Connection.executescript() implicitly commits any pending
    # transaction. Execute each DDL statement ourselves so schema publication,
    # policy selection and evidence insertion remain in the caller's one
    # BEGIN IMMEDIATE transaction.
    for statement in SCHEMA_SQL.split(";"):
        if statement.strip():
            connection.execute(statement)
    existing = connection.execute(
        "SELECT value FROM clovery_config WHERE key='schema_version'"
    ).fetchone()
    if existing and existing[0] != SCHEMA_VERSION:
        raise ImportError(
            f"unsupported Clovery schema version {existing[0]!r}; expected {SCHEMA_VERSION}"
        )
    connection.execute(
        "INSERT OR REPLACE INTO clovery_config(key,value) VALUES('schema_version',?)",
        (SCHEMA_VERSION,),
    )
    connection.execute(
        "INSERT OR REPLACE INTO clovery_config(key,value) VALUES('min_confidence',?)",
        (min_confidence,),
    )
    for statement in VIEW_SQL.split(";"):
        if statement.strip():
            connection.execute(statement)


def mapped_pair(connection: sqlite3.Connection, candidate: Candidate) -> bool:
    return connection.execute(
        "SELECT 1 FROM repo2cve WHERE repo_key=? AND cve_id=? LIMIT 1",
        (candidate.repo_key, candidate.cve_id),
    ).fetchone() is not None


def insert_candidate(
    connection: sqlite3.Connection, candidate: Candidate, observed_at: str
) -> bool:
    existing = connection.execute(
        """SELECT result_id,source_mtime_ns FROM clovery_result
           WHERE repo_key=? AND cve_id=? AND result_sha256=?""",
        (candidate.repo_key, candidate.cve_id, candidate.result_hash),
    ).fetchone()
    if existing:
        result_id, old_mtime_ns = existing
        if candidate.source_mtime_ns >= old_mtime_ns:
            connection.execute(
                """UPDATE clovery_result
                   SET source_file=?,source_mtime_ns=?,last_observed_at=?
                   WHERE result_id=?""",
                (
                    candidate.source_file,
                    candidate.source_mtime_ns,
                    observed_at,
                    result_id,
                ),
            )
        return False

    cursor = connection.execute(
        """INSERT INTO clovery_result(
               repo_key,cve_id,result_sha256,source_file,source_mtime_ns,
               first_imported_at,last_observed_at,state,confidence,changed,
               tag_count,evaluated_tags,unknown_tags,proposal_json,result_json
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            candidate.repo_key,
            candidate.cve_id,
            candidate.result_hash,
            candidate.source_file,
            candidate.source_mtime_ns,
            observed_at,
            observed_at,
            candidate.state,
            candidate.confidence,
            int(candidate.changed),
            candidate.tag_count,
            candidate.evaluated_tags,
            candidate.unknown_tags,
            candidate.proposal_json,
            candidate.result_json,
        ),
    )
    result_id = int(cursor.lastrowid)
    connection.executemany(
        """INSERT INTO clovery_result_range(
               result_id,ordinal,introduced,last_affected,fixed,fixed_source,
               fixed_conflict_json
           ) VALUES (?,?,?,?,?,?,?)""",
        [
            (
                result_id,
                ordinal,
                item["introduced"],
                item["last_affected"],
                item.get("fixed"),
                item.get("fixed_source"),
                canonical_json(item["fixed_conflict"])
                if item.get("fixed_conflict") is not None
                else None,
            )
            for ordinal, item in enumerate(candidate.ranges)
        ],
    )
    return True


def open_database(path: Path, *, read_only: bool, timeout_s: float) -> sqlite3.Connection:
    if not path.is_file():
        raise ImportError(f"database does not exist: {path}")
    if read_only:
        connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    else:
        connection = sqlite3.connect(path, timeout=timeout_s)
    connection.execute(f"PRAGMA busy_timeout={max(0, int(timeout_s * 1000))}")
    connection.execute("PRAGMA foreign_keys=ON")
    validate_destination(connection)
    return connection


def sync_results(
    *,
    results_root: Path,
    database: Path,
    min_confidence: str = "high",
    timeout_s: float = 30.0,
    dry_run: bool = False,
    strict: bool = False,
) -> dict[str, Any]:
    if min_confidence not in {"low", "medium", "high"}:
        raise ImportError(f"invalid min confidence: {min_confidence}")
    candidates, skipped_files = scan_results(results_root)
    if strict and skipped_files:
        raise ImportError(
            f"{len(skipped_files)} result file(s) were skipped; first: "
            f"{skipped_files[0]['file']}: {skipped_files[0]['reason']}"
        )

    connection = open_database(database, read_only=dry_run, timeout_s=timeout_s)
    started_at = utc_now()
    inserted = duplicates = unmapped = 0
    unmapped_pairs: list[str] = []
    try:
        if not dry_run:
            connection.execute("BEGIN IMMEDIATE")
            create_schema(connection, min_confidence)
            cursor = connection.execute(
                """INSERT INTO clovery_sync_run(
                       started_at,results_root,min_confidence,skipped_file_count
                   ) VALUES (?,?,?,?)""",
                (started_at, str(results_root), min_confidence, len(skipped_files)),
            )
            sync_id = int(cursor.lastrowid)
        else:
            sync_id = None

        for candidate in candidates:
            if not mapped_pair(connection, candidate):
                unmapped += 1
                if len(unmapped_pairs) < 100:
                    unmapped_pairs.append(f"{candidate.repo_key}:{candidate.cve_id}")
                continue
            if dry_run:
                continue
            if insert_candidate(connection, candidate, started_at):
                inserted += 1
            else:
                duplicates += 1

        if strict and unmapped:
            raise ImportError(
                f"{unmapped} result(s) have no repo2cve mapping; first: {unmapped_pairs[0]}"
            )
        completed_at = utc_now()
        if not dry_run:
            connection.execute(
                """UPDATE clovery_sync_run
                   SET completed_at=?,candidate_count=?,inserted_count=?,
                       duplicate_count=?,unmapped_count=?
                   WHERE sync_id=?""",
                (
                    completed_at,
                    len(candidates),
                    inserted,
                    duplicates,
                    unmapped,
                    sync_id,
                ),
            )
            connection.commit()
    except Exception:
        if not dry_run:
            connection.rollback()
        raise
    finally:
        connection.close()

    return {
        "database": str(database),
        "results_root": str(results_root),
        "dry_run": dry_run,
        "min_confidence": min_confidence,
        "completed_result_files": len({item.source_file for item in candidates}),
        "candidate_results": len(candidates),
        "inserted_results": inserted,
        "duplicate_results": duplicates,
        "unmapped_results": unmapped,
        "unmapped_pairs_sample": unmapped_pairs,
        "skipped_files": skipped_files,
    }


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Idempotently import completed Clovery ranges into repo_cve.sqlite"
    )
    result.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    result.add_argument("--db", type=Path, default=DEFAULT_DATABASE)
    result.add_argument(
        "--min-confidence",
        choices=("high", "medium", "low"),
        default="high",
        help="minimum confidence allowed to override NVD in the effective view",
    )
    result.add_argument("--timeout", type=float, default=30.0, help="SQLite lock wait seconds")
    result.add_argument("--dry-run", action="store_true")
    result.add_argument(
        "--strict",
        action="store_true",
        help="roll back if a result file is invalid or a repo/CVE is unmapped",
    )
    result.add_argument("--report", type=Path, help="also atomically write the JSON report")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.timeout < 0:
            raise ImportError("--timeout must be non-negative")
        report = sync_results(
            results_root=args.results,
            database=args.db,
            min_confidence=args.min_confidence,
            timeout_s=args.timeout,
            dry_run=args.dry_run,
            strict=args.strict,
        )
        if args.report:
            write_report(args.report, report)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (ImportError, OSError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
