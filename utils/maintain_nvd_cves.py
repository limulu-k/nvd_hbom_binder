#!/usr/bin/env python3
"""Build a contamination-safe, current-only NVD CVE JSONL snapshot.

The CVE Change History API is an audit log, not a source of complete CVE
documents.  Consequently this program never patches a CVE from
``details[].oldValue/newValue``.  It uses history for three safe operations:

1. choose exactly one local revision per CVE (greatest ``lastModified``),
2. exclude CVEs whose latest terminal event is ``CVE Rejected``, and
3. quarantine a selected record when history proves that it predates a later
   change and no snapshot coverage timestamp proves the local snapshot was
   downloaded after that change.

``details[].action == "Removed"`` means that a field was removed from a CVE;
it does *not* mean that the CVE itself was deleted.  Such an event therefore
participates in freshness checking but does not create a terminal tombstone.

The output is written through a temporary file and atomically replaced only
after all invariants pass.  The input is never modified in place.  Build the
normalization DB from this output with its existing atomic ``--replace`` flow.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import time
from typing import Any, Iterator, Mapping, TextIO


DEFAULT_INPUT = Path("data/nvd-cves.jsonl")
DEFAULT_HISTORY = Path("data/nvd-cve-history/nvd-cve-history.jsonl.gz")
DEFAULT_OUTPUT = Path("data/nvd-cves.current.jsonl")
DEFAULT_REPORT = Path("data/nvd-cves.current.report.json")
DEFAULT_QUARANTINE = Path("data/nvd-cves.current.quarantine.jsonl")
JSON_SEPARATORS = (",", ":")
SCHEMA_VERSION = 1
CVE_ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)
REJECTED_STATUSES = frozenset({"reject", "rejected", "withdrawn"})
TERMINAL_REJECT_EVENTS = frozenset(
    {"cve rejected", "cve deleted", "cve withdrawn"}
)
TERMINAL_ACTIVE_EVENTS = frozenset({"cve unrejected", "cve restored"})


class MaintenanceError(RuntimeError):
    """Raised when producing a trustworthy snapshot is not possible."""


@dataclass(frozen=True, slots=True)
class MaintenanceConfig:
    inputs: tuple[Path, ...]
    history: Path
    output: Path
    report: Path
    quarantine: Path
    snapshot_as_of: str | None = None
    allow_incomplete_history: bool = False
    require_history_manifest: bool = False
    skip_invalid: bool = False
    progress_every: int = 100_000
    work_dir: Path | None = None


@dataclass(frozen=True, slots=True)
class InputRecord:
    root: dict[str, Any]
    cve: dict[str, Any]
    cve_id: str
    last_modified: str
    last_modified_us: int
    vuln_status: str
    digest: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def emit(event: str, **fields: Any) -> None:
    print(
        json.dumps(
            {"event": event, "time": utc_now(), **fields},
            ensure_ascii=False,
            sort_keys=True,
        ),
        file=sys.stderr,
        flush=True,
    )


def parse_timestamp(value: str, *, field: str) -> int:
    if not isinstance(value, str) or not value.strip():
        raise MaintenanceError(f"missing {field} timestamp")
    text = value.strip()
    normalized = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise MaintenanceError(f"invalid {field} timestamp {value!r}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    return int(parsed.timestamp() * 1_000_000)


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=JSON_SEPARATORS)


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=JSON_SEPARATORS,
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def open_text(path: Path) -> TextIO:
    if path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("rt", encoding="utf-8")


def discover_inputs(paths: tuple[Path, ...]) -> tuple[Path, ...]:
    supported_suffixes = (".jsonl", ".jsonl.gz", ".ndjson", ".ndjson.gz")
    discovered: list[Path] = []
    for supplied in paths:
        if supplied.is_file():
            discovered.append(supplied)
            continue
        if supplied.is_dir():
            discovered.extend(
                sorted(
                    candidate
                    for candidate in supplied.rglob("*")
                    if candidate.is_file()
                    and candidate.name.lower().endswith(supported_suffixes)
                )
            )
            continue
        raise MaintenanceError(f"input does not exist: {supplied}")
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in discovered:
        resolved = path.resolve()
        if resolved in seen:
            continue
        if not path.name.lower().endswith(supported_suffixes):
            raise MaintenanceError(
                f"unsupported input format (expected JSONL/JSONL.GZ): {path}"
            )
        seen.add(resolved)
        unique.append(path)
    if not unique:
        raise MaintenanceError("no CVE JSONL inputs were found")
    return tuple(unique)


def iter_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    with open_text(path) as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise MaintenanceError(
                    f"invalid JSON in {path}:{line_number}: {error}"
                ) from error
            if not isinstance(value, dict):
                raise MaintenanceError(
                    f"JSONL row is not an object in {path}:{line_number}"
                )
            yield line_number, value


def parse_input_record(root: dict[str, Any], *, location: str) -> InputRecord:
    cve_value = root.get("cve", root)
    if not isinstance(cve_value, dict):
        raise MaintenanceError(f"missing cve object at {location}")
    raw_id = cve_value.get("id", cve_value.get("cveId", cve_value.get("cve_id")))
    if not isinstance(raw_id, str) or not CVE_ID_RE.fullmatch(raw_id.strip()):
        raise MaintenanceError(f"invalid CVE ID at {location}: {raw_id!r}")
    cve_id = raw_id.strip().upper()
    raw_modified = cve_value.get("lastModified")
    last_modified = raw_modified if isinstance(raw_modified, str) else ""
    last_modified_us = parse_timestamp(
        last_modified,
        field=f"lastModified at {location}",
    )
    vuln_status = str(cve_value.get("vulnStatus") or "Unknown")
    return InputRecord(
        root=root,
        cve=cve_value,
        cve_id=cve_id,
        last_modified=last_modified,
        last_modified_us=last_modified_us,
        vuln_status=vuln_status,
        digest=canonical_digest(root),
    )


def init_state_db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        PRAGMA journal_mode=OFF;
        PRAGMA synchronous=OFF;
        PRAGMA temp_store=FILE;

        CREATE TABLE selected_record (
            cve_id TEXT PRIMARY KEY,
            last_modified TEXT NOT NULL,
            last_modified_us INTEGER NOT NULL,
            vuln_status TEXT NOT NULL,
            input_index INTEGER NOT NULL,
            record_index INTEGER NOT NULL,
            line_number INTEGER NOT NULL,
            digest TEXT NOT NULL
        ) WITHOUT ROWID;

        CREATE TABLE record_variant (
            cve_id TEXT NOT NULL,
            digest TEXT NOT NULL,
            PRIMARY KEY (cve_id,digest)
        ) WITHOUT ROWID;

        CREATE TABLE history_event_seen (
            change_id TEXT PRIMARY KEY
        ) WITHOUT ROWID;

        CREATE TABLE history_state (
            cve_id TEXT PRIMARY KEY,
            event_count INTEGER NOT NULL,
            latest_rank TEXT NOT NULL,
            latest_created TEXT NOT NULL,
            latest_created_us INTEGER NOT NULL,
            latest_event_name TEXT NOT NULL,
            latest_change_id TEXT NOT NULL,
            terminal_rank TEXT,
            terminal_created TEXT,
            terminal_created_us INTEGER,
            terminal_state TEXT,
            terminal_event_name TEXT,
            changed_detail_count INTEGER NOT NULL,
            removed_detail_count INTEGER NOT NULL,
            added_detail_count INTEGER NOT NULL
        ) WITHOUT ROWID;

        CREATE TABLE record_decision (
            cve_id TEXT PRIMARY KEY,
            keep INTEGER NOT NULL,
            reason TEXT NOT NULL,
            coverage_us INTEGER,
            latest_history_created TEXT,
            latest_history_event TEXT,
            terminal_state TEXT,
            record_last_modified TEXT NOT NULL,
            record_status TEXT NOT NULL
        ) WITHOUT ROWID;
        """
    )
    return connection


def ingest_inputs(
    connection: sqlite3.Connection,
    inputs: tuple[Path, ...],
    *,
    skip_invalid: bool,
    progress_every: int,
) -> dict[str, Any]:
    counters: Counter[str] = Counter()
    invalid_examples: list[dict[str, Any]] = []
    for input_index, path in enumerate(inputs):
        source_count = 0
        for record_index, (line_number, root) in enumerate(iter_jsonl(path)):
            source_count += 1
            counters["rows_seen"] += 1
            try:
                record = parse_input_record(
                    root,
                    location=f"{path}:{line_number}",
                )
            except MaintenanceError as error:
                counters["invalid_rows"] += 1
                if len(invalid_examples) < 20:
                    invalid_examples.append(
                        {
                            "path": str(path),
                            "line_number": line_number,
                            "error": str(error),
                        }
                    )
                if not skip_invalid:
                    raise
                continue
            counters["valid_rows"] += 1
            connection.execute(
                "INSERT OR IGNORE INTO record_variant(cve_id,digest) VALUES (?,?)",
                (record.cve_id, record.digest),
            )
            connection.execute(
                """INSERT INTO selected_record(
                       cve_id,last_modified,last_modified_us,vuln_status,
                       input_index,record_index,line_number,digest
                   ) VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(cve_id) DO UPDATE SET
                       last_modified=excluded.last_modified,
                       last_modified_us=excluded.last_modified_us,
                       vuln_status=excluded.vuln_status,
                       input_index=excluded.input_index,
                       record_index=excluded.record_index,
                       line_number=excluded.line_number,
                       digest=excluded.digest
                   WHERE excluded.last_modified_us > selected_record.last_modified_us
                      OR (
                          excluded.last_modified_us=selected_record.last_modified_us
                          AND excluded.input_index > selected_record.input_index
                      )
                      OR (
                          excluded.last_modified_us=selected_record.last_modified_us
                          AND excluded.input_index=selected_record.input_index
                          AND excluded.record_index > selected_record.record_index
                      )""",
                (
                    record.cve_id,
                    record.last_modified,
                    record.last_modified_us,
                    record.vuln_status,
                    input_index,
                    record_index,
                    line_number,
                    record.digest,
                ),
            )
            if progress_every and counters["rows_seen"] % progress_every == 0:
                connection.commit()
                emit("input_progress", rows_seen=counters["rows_seen"])
        connection.commit()
        emit(
            "input_complete",
            path=str(path),
            input_index=input_index,
            rows=source_count,
        )

    counters["selected_cves"] = int(
        connection.execute("SELECT COUNT(*) FROM selected_record").fetchone()[0]
    )
    counters["content_variants"] = int(
        connection.execute("SELECT COUNT(*) FROM record_variant").fetchone()[0]
    )
    counters["cves_with_multiple_content_variants"] = int(
        connection.execute(
            """SELECT COUNT(*) FROM (
                   SELECT cve_id FROM record_variant
                   GROUP BY cve_id HAVING COUNT(*)>1
               )"""
        ).fetchone()[0]
    )
    return {**dict(counters), "invalid_examples": invalid_examples}


def load_history_manifest(
    history_path: Path,
    *,
    require: bool,
    allow_incomplete: bool,
) -> dict[str, Any]:
    manifest_path = history_path.parent / "manifest.json"
    if not manifest_path.is_file():
        if require:
            raise MaintenanceError(
                f"history manifest is required but missing: {manifest_path}"
            )
        return {"status": "absent", "path": str(manifest_path)}
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MaintenanceError(f"invalid history manifest: {manifest_path}") from error
    if not isinstance(payload, dict):
        raise MaintenanceError(f"history manifest is not an object: {manifest_path}")
    complete = payload.get("complete") is True
    if not complete and not allow_incomplete:
        raise MaintenanceError(
            "history download is incomplete; finish it or use "
            "--allow-incomplete-history for a diagnostic run"
        )
    merged = payload.get("merged_output")
    expected_events = (
        int(merged["event_count"])
        if isinstance(merged, dict) and isinstance(merged.get("event_count"), int)
        else None
    )
    return {
        "status": "complete" if complete else "incomplete_allowed",
        "path": str(manifest_path),
        "expected_event_count": expected_events,
        "merged_created_at": (
            merged.get("created_at") if isinstance(merged, dict) else None
        ),
    }


def terminal_state_from_event(
    event_name: str, details: list[dict[str, Any]]
) -> str | None:
    normalized = event_name.strip().casefold()
    if normalized in TERMINAL_REJECT_EVENTS:
        return "rejected"
    if normalized in TERMINAL_ACTIVE_EVENTS:
        return "active"
    if normalized != "cve status change":
        return None
    # Status Change events are often detail-free.  Only infer a terminal state
    # when the payload states it explicitly; otherwise the current CVE record
    # status remains the authoritative status value.
    for detail in details:
        detail_type = str(detail.get("type") or "").strip().casefold()
        if "status" not in detail_type:
            continue
        new_value = str(detail.get("newValue") or "").strip().casefold()
        if new_value in REJECTED_STATUSES:
            return "rejected"
        if new_value and new_value not in REJECTED_STATUSES:
            return "active"
    return None


def ingest_history(
    connection: sqlite3.Connection,
    history_path: Path,
    *,
    skip_invalid: bool,
    progress_every: int,
    expected_event_count: int | None,
) -> dict[str, Any]:
    if not history_path.is_file():
        raise MaintenanceError(f"history JSONL does not exist: {history_path}")
    counters: Counter[str] = Counter()
    event_names: Counter[str] = Counter()
    action_names: Counter[str] = Counter()
    invalid_examples: list[dict[str, Any]] = []

    for line_number, root in iter_jsonl(history_path):
        counters["rows_seen"] += 1
        try:
            change = root.get("change")
            if not isinstance(change, dict):
                raise MaintenanceError("missing change object")
            cve_id_raw = change.get("cveId")
            if not isinstance(cve_id_raw, str) or not CVE_ID_RE.fullmatch(
                cve_id_raw.strip()
            ):
                raise MaintenanceError(f"invalid history CVE ID: {cve_id_raw!r}")
            cve_id = cve_id_raw.strip().upper()
            change_id_raw = change.get("cveChangeId")
            if not isinstance(change_id_raw, str) or not change_id_raw.strip():
                raise MaintenanceError("missing cveChangeId")
            change_id = change_id_raw.strip().upper()
            event_name_raw = change.get("eventName")
            if not isinstance(event_name_raw, str) or not event_name_raw.strip():
                raise MaintenanceError("missing eventName")
            event_name = event_name_raw.strip()
            created_raw = change.get("created")
            if not isinstance(created_raw, str):
                raise MaintenanceError("missing history created timestamp")
            created_us = parse_timestamp(
                created_raw,
                field=f"history created at {history_path}:{line_number}",
            )
            details_raw = change.get("details")
            if not isinstance(details_raw, list):
                raise MaintenanceError("history details is not an array")
            if any(not isinstance(item, dict) for item in details_raw):
                raise MaintenanceError("history details contains a non-object")
            details = list(details_raw)
        except MaintenanceError as error:
            counters["invalid_rows"] += 1
            if len(invalid_examples) < 20:
                invalid_examples.append(
                    {"line_number": line_number, "error": str(error)}
                )
            if not skip_invalid:
                raise MaintenanceError(
                    f"invalid history row {history_path}:{line_number}: {error}"
                ) from error
            continue

        inserted = connection.execute(
            "INSERT OR IGNORE INTO history_event_seen(change_id) VALUES (?)",
            (change_id,),
        ).rowcount
        if not inserted:
            counters["duplicate_change_ids"] += 1
            continue

        counters["unique_events"] += 1
        event_names[event_name] += 1
        actions = [str(item.get("action") or "Unknown").strip() for item in details]
        for action in actions:
            action_names[action] += 1
        changed_count = sum(action.casefold() == "changed" for action in actions)
        removed_count = sum(action.casefold() == "removed" for action in actions)
        added_count = sum(action.casefold() == "added" for action in actions)
        terminal_state = terminal_state_from_event(event_name, details)
        rank = f"{created_us:020d}:{change_id}"
        terminal_rank = rank if terminal_state else None

        connection.execute(
            """INSERT INTO history_state(
                   cve_id,event_count,latest_rank,latest_created,
                   latest_created_us,latest_event_name,latest_change_id,
                   terminal_rank,terminal_created,terminal_created_us,
                   terminal_state,terminal_event_name,
                   changed_detail_count,removed_detail_count,added_detail_count
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(cve_id) DO UPDATE SET
                   event_count=history_state.event_count+1,
                   latest_created=CASE WHEN excluded.latest_rank>history_state.latest_rank
                       THEN excluded.latest_created ELSE history_state.latest_created END,
                   latest_created_us=CASE WHEN excluded.latest_rank>history_state.latest_rank
                       THEN excluded.latest_created_us ELSE history_state.latest_created_us END,
                   latest_event_name=CASE WHEN excluded.latest_rank>history_state.latest_rank
                       THEN excluded.latest_event_name ELSE history_state.latest_event_name END,
                   latest_change_id=CASE WHEN excluded.latest_rank>history_state.latest_rank
                       THEN excluded.latest_change_id ELSE history_state.latest_change_id END,
                   latest_rank=max(history_state.latest_rank,excluded.latest_rank),
                   terminal_created=CASE
                       WHEN excluded.terminal_rank IS NOT NULL AND
                            (history_state.terminal_rank IS NULL OR
                             excluded.terminal_rank>history_state.terminal_rank)
                       THEN excluded.terminal_created ELSE history_state.terminal_created END,
                   terminal_created_us=CASE
                       WHEN excluded.terminal_rank IS NOT NULL AND
                            (history_state.terminal_rank IS NULL OR
                             excluded.terminal_rank>history_state.terminal_rank)
                       THEN excluded.terminal_created_us
                       ELSE history_state.terminal_created_us END,
                   terminal_state=CASE
                       WHEN excluded.terminal_rank IS NOT NULL AND
                            (history_state.terminal_rank IS NULL OR
                             excluded.terminal_rank>history_state.terminal_rank)
                       THEN excluded.terminal_state ELSE history_state.terminal_state END,
                   terminal_event_name=CASE
                       WHEN excluded.terminal_rank IS NOT NULL AND
                            (history_state.terminal_rank IS NULL OR
                             excluded.terminal_rank>history_state.terminal_rank)
                       THEN excluded.terminal_event_name
                       ELSE history_state.terminal_event_name END,
                   terminal_rank=CASE
                       WHEN excluded.terminal_rank IS NOT NULL AND
                            (history_state.terminal_rank IS NULL OR
                             excluded.terminal_rank>history_state.terminal_rank)
                       THEN excluded.terminal_rank ELSE history_state.terminal_rank END,
                   changed_detail_count=history_state.changed_detail_count+
                       excluded.changed_detail_count,
                   removed_detail_count=history_state.removed_detail_count+
                       excluded.removed_detail_count,
                   added_detail_count=history_state.added_detail_count+
                       excluded.added_detail_count""",
            (
                cve_id,
                1,
                rank,
                created_raw,
                created_us,
                event_name,
                change_id,
                terminal_rank,
                created_raw if terminal_state else None,
                created_us if terminal_state else None,
                terminal_state,
                event_name if terminal_state else None,
                changed_count,
                removed_count,
                added_count,
            ),
        )
        if progress_every and counters["rows_seen"] % progress_every == 0:
            connection.commit()
            emit("history_progress", rows_seen=counters["rows_seen"])

    connection.commit()
    if expected_event_count is not None and counters["rows_seen"] != expected_event_count:
        raise MaintenanceError(
            "history event count does not match manifest: "
            f"read={counters['rows_seen']}, expected={expected_event_count}"
        )
    counters["history_cves"] = int(
        connection.execute("SELECT COUNT(*) FROM history_state").fetchone()[0]
    )
    counters["terminal_rejected_cves"] = int(
        connection.execute(
            "SELECT COUNT(*) FROM history_state WHERE terminal_state='rejected'"
        ).fetchone()[0]
    )
    return {
        **dict(counters),
        "event_names": dict(sorted(event_names.items())),
        "detail_actions": dict(sorted(action_names.items())),
        "invalid_examples": invalid_examples,
    }


def make_decisions(
    connection: sqlite3.Connection,
    snapshot_as_of: str | None,
) -> dict[str, Any]:
    snapshot_us = (
        parse_timestamp(snapshot_as_of, field="snapshot-as-of")
        if snapshot_as_of
        else None
    )
    counters: Counter[str] = Counter()
    stale_examples: list[dict[str, Any]] = []
    rows = connection.execute(
        """SELECT s.*,
                  h.latest_created,h.latest_created_us,h.latest_event_name,
                  h.terminal_state,h.terminal_created,h.terminal_event_name
           FROM selected_record s
           LEFT JOIN history_state h USING(cve_id)
           ORDER BY s.cve_id"""
    )
    for row in rows:
        status = str(row["vuln_status"])
        coverage_us = max(int(row["last_modified_us"]), snapshot_us or -1)
        latest_us = row["latest_created_us"]
        terminal_state = row["terminal_state"]
        if status.strip().casefold() in REJECTED_STATUSES:
            keep, reason = False, "record_status_rejected"
        elif terminal_state == "rejected":
            keep, reason = False, "terminal_history_rejected"
        elif latest_us is not None and int(latest_us) > coverage_us:
            keep, reason = False, "stale_after_history"
        else:
            keep, reason = True, "current"
        counters[reason] += 1
        if reason == "stale_after_history" and len(stale_examples) < 20:
            stale_examples.append(
                {
                    "cve_id": str(row["cve_id"]),
                    "record_last_modified": str(row["last_modified"]),
                    "latest_history_created": str(row["latest_created"]),
                    "latest_history_event": str(row["latest_event_name"]),
                }
            )
        connection.execute(
            """INSERT INTO record_decision(
                   cve_id,keep,reason,coverage_us,latest_history_created,
                   latest_history_event,terminal_state,record_last_modified,
                   record_status
               ) VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                row["cve_id"],
                int(keep),
                reason,
                coverage_us,
                row["latest_created"],
                row["latest_event_name"],
                terminal_state,
                row["last_modified"],
                status,
            ),
        )
    connection.commit()
    counters["history_cves_without_local_record"] = int(
        connection.execute(
            """SELECT COUNT(*) FROM history_state h
               LEFT JOIN selected_record s USING(cve_id)
               WHERE s.cve_id IS NULL"""
        ).fetchone()[0]
    )
    counters["active_history_cves_without_local_record"] = int(
        connection.execute(
            """SELECT COUNT(*) FROM history_state h
               LEFT JOIN selected_record s USING(cve_id)
               WHERE s.cve_id IS NULL
                 AND COALESCE(h.terminal_state,'active')<>'rejected'"""
        ).fetchone()[0]
    )
    return {
        **dict(counters),
        "snapshot_as_of": snapshot_as_of,
        "snapshot_as_of_us": snapshot_us,
        "stale_examples": stale_examples,
    }


def _temporary_path(destination: Path) -> tuple[int, Path]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    return descriptor, Path(name)


def write_current_output(
    connection: sqlite3.Connection,
    inputs: tuple[Path, ...],
    output: Path,
    *,
    skip_invalid: bool,
    progress_every: int,
) -> dict[str, Any]:
    descriptor, temporary = _temporary_path(output)
    sha256 = hashlib.sha256()
    written = 0
    try:
        with os.fdopen(descriptor, "wb") as stream:
            for input_index, path in enumerate(inputs):
                selected = {
                    int(row[0]): str(row[1])
                    for row in connection.execute(
                        """SELECT s.record_index,s.cve_id
                           FROM selected_record s
                           JOIN record_decision d USING(cve_id)
                           WHERE s.input_index=? AND d.keep=1""",
                        (input_index,),
                    )
                }
                if not selected:
                    continue
                for record_index, (line_number, root) in enumerate(iter_jsonl(path)):
                    cve_id = selected.get(record_index)
                    if cve_id is None:
                        continue
                    try:
                        parsed = parse_input_record(
                            root,
                            location=f"{path}:{line_number}",
                        )
                    except MaintenanceError:
                        if skip_invalid:
                            continue
                        raise
                    if parsed.cve_id != cve_id:
                        raise MaintenanceError(
                            "input changed between selection and output pass: "
                            f"{path}:{line_number}"
                        )
                    encoded = (compact_json(root) + "\n").encode("utf-8")
                    stream.write(encoded)
                    sha256.update(encoded)
                    written += 1
                    if progress_every and written % progress_every == 0:
                        emit("output_progress", cves_written=written)
            stream.flush()
            os.fsync(stream.fileno())
        expected = int(
            connection.execute(
                "SELECT COUNT(*) FROM record_decision WHERE keep=1"
            ).fetchone()[0]
        )
        if written != expected:
            raise MaintenanceError(
                f"output invariant failed: wrote {written}, expected {expected}"
            )
        os.replace(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return {
        "path": str(output.resolve()),
        "cve_count": written,
        "bytes": output.stat().st_size,
        "sha256": sha256.hexdigest(),
    }


def write_quarantine(connection: sqlite3.Connection, path: Path) -> dict[str, Any]:
    descriptor, temporary = _temporary_path(path)
    count = 0
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            for row in connection.execute(
                """SELECT * FROM record_decision
                   WHERE keep=0 ORDER BY cve_id"""
            ):
                stream.write(compact_json(dict(row)))
                stream.write("\n")
                count += 1
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return {"path": str(path.resolve()), "count": count, "bytes": path.stat().st_size}


def atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    descriptor, temporary = _temporary_path(path)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def validate_paths(config: MaintenanceConfig, inputs: tuple[Path, ...]) -> None:
    input_paths = {path.resolve() for path in inputs}
    destinations = [config.output, config.report, config.quarantine]
    if len({path.resolve() for path in destinations}) != len(destinations):
        raise MaintenanceError("output, report, and quarantine paths must differ")
    for destination in destinations:
        if destination.resolve() in input_paths:
            raise MaintenanceError(
                f"refusing in-place input overwrite: {destination}; choose a new path"
            )
    if config.history.resolve() in {path.resolve() for path in destinations}:
        raise MaintenanceError("history input cannot also be an output path")


def run_maintenance(config: MaintenanceConfig) -> dict[str, Any]:
    started = time.monotonic()
    inputs = discover_inputs(config.inputs)
    validate_paths(config, inputs)
    manifest = load_history_manifest(
        config.history,
        require=config.require_history_manifest,
        allow_incomplete=config.allow_incomplete_history,
    )
    work_dir = (config.work_dir or config.output.parent).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    descriptor, state_name = tempfile.mkstemp(
        dir=work_dir,
        prefix=".nvd-maintenance-state.",
        suffix=".sqlite",
    )
    os.close(descriptor)
    state_path = Path(state_name)
    connection: sqlite3.Connection | None = None
    try:
        connection = init_state_db(state_path)
        input_summary = ingest_inputs(
            connection,
            inputs,
            skip_invalid=config.skip_invalid,
            progress_every=config.progress_every,
        )
        history_summary = ingest_history(
            connection,
            config.history,
            skip_invalid=config.skip_invalid,
            progress_every=config.progress_every,
            expected_event_count=manifest.get("expected_event_count"),
        )
        decision_summary = make_decisions(connection, config.snapshot_as_of)
        output_summary = write_current_output(
            connection,
            inputs,
            config.output,
            skip_invalid=config.skip_invalid,
            progress_every=config.progress_every,
        )
        quarantine_summary = write_quarantine(connection, config.quarantine)
        report: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "created_at": utc_now(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "semantics": {
                "winner": "max lastModified, then later input and row",
                "removed_detail": (
                    "field removal requiring freshness; never a CVE tombstone"
                ),
                "terminal_delete": (
                    "latest CVE Rejected excludes; later CVE Unrejected restores"
                ),
                "stale_policy": (
                    "exclude when latest history event is newer than both the "
                    "record lastModified and --snapshot-as-of"
                ),
                "downstream_llm_alignment": (
                    "LLM rows are joined by cve_id; legacy source_index is provenance "
                    "only, and changed descriptions are quarantined as stale"
                ),
            },
            "inputs": [str(path.resolve()) for path in inputs],
            "history": str(config.history.resolve()),
            "history_manifest": manifest,
            "input_summary": input_summary,
            "history_summary": history_summary,
            "decision_summary": decision_summary,
            "output": output_summary,
            "quarantine": quarantine_summary,
        }
        atomic_write_json(config.report, report)
        emit(
            "maintenance_complete",
            cves_written=output_summary["cve_count"],
            quarantined=quarantine_summary["count"],
            elapsed_seconds=report["elapsed_seconds"],
        )
        return report
    finally:
        if connection is not None:
            connection.close()
        state_path.unlink(missing_ok=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        action="append",
        dest="inputs",
        help=(
            "CVE JSONL/JSONL.GZ file or directory; repeat for update snapshots. "
            f"Default: {DEFAULT_INPUT}"
        ),
    )
    parser.add_argument("--history", type=Path, default=DEFAULT_HISTORY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--quarantine", type=Path, default=DEFAULT_QUARANTINE)
    parser.add_argument(
        "--snapshot-as-of",
        help=(
            "UTC/offset timestamp at which all --input snapshots were current. "
            "Required to prove freshness for history events which do not change "
            "the CVE lastModified field. If omitted, stale checking is conservative."
        ),
    )
    parser.add_argument("--allow-incomplete-history", action="store_true")
    parser.add_argument("--require-history-manifest", action="store_true")
    parser.add_argument(
        "--skip-invalid",
        action="store_true",
        help=(
            "skip semantically invalid object rows; malformed JSON remains fatal "
            "because record boundaries cannot be trusted"
        ),
    )
    parser.add_argument("--progress-every", type=int, default=100_000)
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args(argv)
    if args.progress_every < 0:
        parser.error("--progress-every must be non-negative")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config = MaintenanceConfig(
        inputs=tuple(args.inputs or (DEFAULT_INPUT,)),
        history=args.history,
        output=args.output,
        report=args.report,
        quarantine=args.quarantine,
        snapshot_as_of=args.snapshot_as_of,
        allow_incomplete_history=args.allow_incomplete_history,
        require_history_manifest=args.require_history_manifest,
        skip_invalid=args.skip_invalid,
        progress_every=args.progress_every,
        work_dir=args.work_dir,
    )
    try:
        report = run_maintenance(config)
    except (MaintenanceError, OSError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted; previous published output remains intact", file=sys.stderr)
        return 130
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
