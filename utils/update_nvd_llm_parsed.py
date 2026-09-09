#!/usr/bin/env python3
"""Prepare incremental NVD LLM inference and atomically publish its results.

The ``prepare`` command compares the current NVD snapshot with the existing
parsed JSONL by CVE ID and the exact description used by the inference script.
Only new CVEs and CVEs whose description changed are copied to a pending NVD
JSONL.  The ``apply`` command joins the incremental inference output back to
the snapshot, reuses unchanged rows, drops rows no longer in the snapshot, and
atomically replaces the complete parsed and failure JSONL files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Mapping


CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
FORMAT_VERSION = 1


class UpdateError(RuntimeError):
    """Raised when incremental update inputs cannot be joined safely."""


def compact_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_fingerprint(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "path": str(path.resolve()),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "sha256": sha256_path(path),
    }


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_object(raw: bytes, *, path: Path, line_number: int) -> Mapping[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateError(f"invalid JSON: {path}:{line_number}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise UpdateError(f"JSONL row is not an object: {path}:{line_number}")
    return value


def nvd_identity(
    value: Mapping[str, Any], *, path: Path, line_number: int
) -> tuple[str, str]:
    cve = value.get("cve", value)
    if not isinstance(cve, Mapping):
        raise UpdateError(f"cve is not an object: {path}:{line_number}")
    cve_id = cve.get("id") or value.get("cve_id")
    if not isinstance(cve_id, str) or not CVE_ID_RE.fullmatch(cve_id.strip()):
        raise UpdateError(f"invalid CVE ID at {path}:{line_number}: {cve_id!r}")

    descriptions = cve.get("descriptions")
    if descriptions is None:
        descriptions = value.get("descriptions")
    if not isinstance(descriptions, list):
        raise UpdateError(f"descriptions is not an array: {path}:{line_number}")
    candidates: list[tuple[str, str]] = []
    for item in descriptions:
        if not isinstance(item, Mapping):
            continue
        language = item.get("lang")
        text = item.get("value")
        if isinstance(text, str) and text.strip():
            candidates.append(
                (language.lower() if isinstance(language, str) else "", text.strip())
            )
    if not candidates:
        raise UpdateError(f"no usable description: {path}:{line_number}")
    description = next(
        (text for language, text in candidates if language == "en"),
        next(
            (text for language, text in candidates if language.startswith("en-")),
            candidates[0][1],
        ),
    )
    return cve_id.strip().upper(), description


def parsed_identity(
    value: Mapping[str, Any], *, path: Path, line_number: int
) -> tuple[str, str]:
    cve_id = value.get("cve_id")
    description = value.get("description")
    if not isinstance(cve_id, str) or not CVE_ID_RE.fullmatch(cve_id.strip()):
        raise UpdateError(f"invalid parsed CVE ID at {path}:{line_number}: {cve_id!r}")
    if not isinstance(description, str) or not description:
        raise UpdateError(
            f"invalid parsed description at {path}:{line_number}: {description!r}"
        )
    return cve_id.strip().upper(), description


def temporary_database(parent: Path) -> tuple[sqlite3.Connection, Path]:
    parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".nvd-llm-index.", suffix=".sqlite", dir=parent)
    os.close(descriptor)
    path = Path(name)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute(
        """CREATE TABLE parsed (
               cve_id TEXT PRIMARY KEY,
               description TEXT NOT NULL,
               raw BLOB NOT NULL
           )"""
    )
    return connection, path


def index_parsed(path: Path, connection: sqlite3.Connection) -> int:
    if not path.exists():
        return 0
    count = 0
    with path.open("rb") as source:
        for line_number, raw in enumerate(source, 1):
            if not raw.strip():
                raise UpdateError(f"blank JSONL row: {path}:{line_number}")
            value = load_object(raw, path=path, line_number=line_number)
            cve_id, description = parsed_identity(
                value, path=path, line_number=line_number
            )
            try:
                connection.execute(
                    "INSERT INTO parsed(cve_id,description,raw) VALUES(?,?,?)",
                    (cve_id, description, raw),
                )
            except sqlite3.IntegrityError as exc:
                raise UpdateError(f"duplicate parsed CVE ID: {path}: {cve_id}") from exc
            count += 1
    connection.commit()
    return count


def parsed_row(connection: sqlite3.Connection, cve_id: str) -> tuple[str, bytes] | None:
    row = connection.execute(
        "SELECT description,raw FROM parsed WHERE cve_id=?", (cve_id,)
    ).fetchone()
    if row is None:
        return None
    return str(row[0]), bytes(row[1])


def iter_nvd(path: Path) -> Iterator[tuple[int, bytes, str, str]]:
    seen: set[str] = set()
    with path.open("rb") as source:
        for source_index, raw in enumerate(source):
            if not raw.strip():
                raise UpdateError(f"blank JSONL row: {path}:{source_index + 1}")
            value = load_object(raw, path=path, line_number=source_index + 1)
            cve_id, description = nvd_identity(
                value, path=path, line_number=source_index + 1
            )
            if cve_id in seen:
                raise UpdateError(
                    f"duplicate CVE ID in LLM snapshot: {path}:{source_index + 1}: "
                    f"{cve_id}; use the history-maintained current JSONL"
                )
            seen.add(cve_id)
            yield source_index, raw, cve_id, description


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    if not args.input.is_file():
        raise UpdateError(f"NVD input does not exist: {args.input}")
    if args.pending.resolve() in {args.input.resolve(), args.parsed.resolve()}:
        raise UpdateError("pending output must differ from NVD and parsed inputs")

    connection, database_path = temporary_database(args.pending.parent)
    temporary = args.pending.with_name(f".{args.pending.name}.tmp.{os.getpid()}")
    try:
        parsed_records = index_parsed(args.parsed, connection)
        input_records = 0
        reused_records = 0
        pending_records = 0
        args.pending.parent.mkdir(parents=True, exist_ok=True)
        with temporary.open("wb") as destination:
            for _, raw, cve_id, description in iter_nvd(args.input):
                input_records += 1
                existing = parsed_row(connection, cve_id)
                if existing is not None and existing[0] == description:
                    reused_records += 1
                else:
                    destination.write(raw if raw.endswith(b"\n") else raw + b"\n")
                    pending_records += 1
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, args.pending)
        manifest = {
            "format_version": FORMAT_VERSION,
            "input": file_fingerprint(args.input),
            "parsed": file_fingerprint(args.parsed) if args.parsed.is_file() else None,
            "pending": file_fingerprint(args.pending),
            "counts": {
                "input": input_records,
                "existing_parsed": parsed_records,
                "reused": reused_records,
                "pending": pending_records,
                "obsolete": max(0, parsed_records - reused_records),
            },
        }
        atomic_write_json(args.manifest, manifest)
        return manifest
    finally:
        connection.close()
        if database_path.exists():
            database_path.unlink()
        if temporary.exists():
            temporary.unlink()


def require_fingerprint(path: Path, expected: Mapping[str, Any] | None, label: str) -> None:
    if expected is None:
        if path.exists():
            raise UpdateError(f"{label} appeared after prepare: {path}")
        return
    if not path.is_file():
        raise UpdateError(f"{label} disappeared after prepare: {path}")
    actual = file_fingerprint(path)
    for key in ("path", "size", "sha256"):
        if actual[key] != expected.get(key):
            raise UpdateError(
                f"{label} changed after prepare ({key} mismatch): {path}"
            )


def index_inference(
    path: Path, connection: sqlite3.Connection, expected_records: int
) -> int:
    connection.execute(
        """CREATE TABLE inferred (
               source_index INTEGER PRIMARY KEY,
               cve_id TEXT NOT NULL,
               description TEXT NOT NULL,
               raw BLOB NOT NULL
           )"""
    )
    count = 0
    with path.open("rb") as source:
        for line_number, raw in enumerate(source, 1):
            value = load_object(raw, path=path, line_number=line_number)
            cve_id, description = parsed_identity(
                value, path=path, line_number=line_number
            )
            metadata = value.get("_meta")
            source_index = metadata.get("source_index") if isinstance(metadata, Mapping) else None
            if not isinstance(source_index, int) or not 0 <= source_index < expected_records:
                raise UpdateError(
                    f"invalid inference source_index at {path}:{line_number}: "
                    f"{source_index!r}"
                )
            try:
                connection.execute(
                    "INSERT INTO inferred(source_index,cve_id,description,raw) VALUES(?,?,?,?)",
                    (source_index, cve_id, description, raw),
                )
            except sqlite3.IntegrityError as exc:
                raise UpdateError(
                    f"duplicate inference source_index at {path}:{line_number}: "
                    f"{source_index}"
                ) from exc
            count += 1
    connection.commit()
    if count != expected_records:
        raise UpdateError(
            f"inference row count mismatch: {count} != pending {expected_records}"
        )
    return count


def validate_inference_against_pending(
    pending: Path, connection: sqlite3.Connection
) -> None:
    for source_index, _, cve_id, description in iter_nvd(pending):
        row = connection.execute(
            "SELECT cve_id,description FROM inferred WHERE source_index=?",
            (source_index,),
        ).fetchone()
        if row is None:
            raise UpdateError(f"missing inference result for pending row {source_index}")
        if (str(row[0]), str(row[1])) != (cve_id, description):
            raise UpdateError(
                f"inference result does not match pending row {source_index}: "
                f"{row[0]!r}"
            )


def result_with_provenance(
    raw: bytes, *, source_index: int, update: str
) -> tuple[bytes, bool]:
    value = json.loads(raw)
    metadata = value.get("_meta")
    metadata = dict(metadata) if isinstance(metadata, Mapping) else {}
    previous_index = metadata.get("source_index")
    if isinstance(previous_index, int) and previous_index != source_index:
        key = "previous_source_index" if update == "reused" else "inference_source_index"
        metadata[key] = previous_index
    metadata["source_index"] = source_index
    metadata["nvd_update"] = update
    value["_meta"] = metadata
    status = metadata.get("status")
    return compact_json(value), status != "ok"


def output_temporary(path: Path) -> tuple[BinaryIO, Path]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.tmp.", dir=path.parent)
    return os.fdopen(descriptor, "wb"), Path(name)


def install_outputs(
    parsed_temp: Path,
    parsed_output: Path,
    fail_temp: Path,
    fail_output: Path,
) -> None:
    parsed_mode = parsed_output.stat().st_mode & 0o777 if parsed_output.exists() else 0o644
    fail_mode = fail_output.stat().st_mode & 0o777 if fail_output.exists() else 0o644
    os.chmod(parsed_temp, parsed_mode)
    os.chmod(fail_temp, fail_mode)
    # The failure file is derived from the complete parsed file.  Installing it
    # first ensures the canonical complete file is the final commit point.
    os.replace(fail_temp, fail_output)
    os.replace(parsed_temp, parsed_output)


def apply_results(args: argparse.Namespace) -> dict[str, Any]:
    if not args.manifest.is_file():
        raise UpdateError(f"prepare manifest does not exist: {args.manifest}")
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UpdateError(f"invalid prepare manifest: {args.manifest}: {exc}") from exc
    if manifest.get("format_version") != FORMAT_VERSION:
        raise UpdateError(f"unsupported prepare manifest version: {args.manifest}")
    counts = manifest.get("counts")
    if not isinstance(counts, Mapping) or not isinstance(counts.get("pending"), int):
        raise UpdateError(f"prepare manifest is missing counts.pending: {args.manifest}")
    pending_records = int(counts["pending"])
    require_fingerprint(args.input, manifest.get("input"), "NVD input")
    require_fingerprint(args.parsed, manifest.get("parsed"), "parsed input")
    require_fingerprint(args.pending, manifest.get("pending"), "pending input")
    if not args.inference.is_file():
        raise UpdateError(f"inference output does not exist: {args.inference}")
    if args.output.resolve() == args.fail_output.resolve():
        raise UpdateError("parsed and failure outputs must differ")

    connection, database_path = temporary_database(args.output.parent)
    parsed_handle: BinaryIO | None = None
    fail_handle: BinaryIO | None = None
    parsed_temp: Path | None = None
    fail_temp: Path | None = None
    try:
        index_parsed(args.parsed, connection)
        index_inference(args.inference, connection, pending_records)
        validate_inference_against_pending(args.pending, connection)
        parsed_handle, parsed_temp = output_temporary(args.output)
        fail_handle, fail_temp = output_temporary(args.fail_output)
        reused = 0
        inferred = 0
        failures = 0
        pending_index = 0
        for source_index, _, cve_id, description in iter_nvd(args.input):
            existing = parsed_row(connection, cve_id)
            if existing is not None and existing[0] == description:
                raw = existing[1]
                update = "reused"
                reused += 1
            else:
                row = connection.execute(
                    "SELECT cve_id,description,raw FROM inferred WHERE source_index=?",
                    (pending_index,),
                ).fetchone()
                if row is None or (str(row[0]), str(row[1])) != (cve_id, description):
                    raise UpdateError(
                        f"incremental result order mismatch for {cve_id} "
                        f"at pending row {pending_index}"
                    )
                raw = bytes(row[2])
                update = "inferred"
                inferred += 1
                pending_index += 1
            normalized, failed = result_with_provenance(
                raw, source_index=source_index, update=update
            )
            parsed_handle.write(normalized)
            if failed:
                fail_handle.write(normalized)
                failures += 1
        if pending_index != pending_records:
            raise UpdateError(
                f"not all incremental results were consumed: "
                f"{pending_index} != {pending_records}"
            )
        for handle in (parsed_handle, fail_handle):
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
        parsed_handle = fail_handle = None
        install_outputs(parsed_temp, args.output, fail_temp, args.fail_output)
        parsed_temp = fail_temp = None
        return {
            "input_records": reused + inferred,
            "reused_records": reused,
            "inferred_records": inferred,
            "failure_records": failures,
            "parsed_output": str(args.output),
            "failure_output": str(args.fail_output),
        }
    finally:
        if parsed_handle is not None:
            parsed_handle.close()
        if fail_handle is not None:
            fail_handle.close()
        connection.close()
        for path in (database_path, parsed_temp, fail_temp):
            if path is not None and path.exists():
                path.unlink()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare", help="write pending NVD rows")
    prepare_parser.add_argument("--input", type=Path, required=True)
    prepare_parser.add_argument("--parsed", type=Path, required=True)
    prepare_parser.add_argument("--pending", type=Path, required=True)
    prepare_parser.add_argument("--manifest", type=Path, required=True)

    apply_parser = subparsers.add_parser("apply", help="publish incremental results")
    apply_parser.add_argument("--input", type=Path, required=True)
    apply_parser.add_argument("--parsed", type=Path, required=True)
    apply_parser.add_argument("--pending", type=Path, required=True)
    apply_parser.add_argument("--manifest", type=Path, required=True)
    apply_parser.add_argument("--inference", type=Path, required=True)
    apply_parser.add_argument("--output", type=Path, required=True)
    apply_parser.add_argument("--fail-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        summary = prepare(args) if args.command == "prepare" else apply_results(args)
    except (OSError, sqlite3.Error, UpdateError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
