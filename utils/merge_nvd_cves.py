#!/usr/bin/env python3
"""Merge NVD 2.0 CVE feeds into compact, exact-deduplicated JSON Lines."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Iterator, TextIO


DEFAULT_INPUT_DIR = Path("nvd-json-2.0")
DEFAULT_OUTPUT_FILE = Path("data/nvd-cves.jsonl")
JSON_SEPARATORS = (",", ":")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Merge NVD JSON 2.0 feed files into one compact JSONL file, "
            "deduplicated only when the whole vulnerability object's key/value "
            "content is identical."
        )
    )
    parser.add_argument(
        "-i",
        "--input-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help=f"NVD JSON 2.0 input directory. Default: {DEFAULT_INPUT_DIR}",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_FILE,
        help=f"Output JSONL file. Default: {DEFAULT_OUTPUT_FILE}",
    )
    parser.add_argument(
        "--duplicates-output",
        type=Path,
        default=None,
        help=(
            "JSONL file for duplicate occurrences removed from the main output. "
            "Default: <output stem>.duplicates<output suffix>"
        ),
    )
    parser.add_argument(
        "--duplicate-counts-output",
        type=Path,
        default=None,
        help=(
            "JSONL file for duplicate groups and counts. "
            "Default: <output stem>.duplicate-counts<output suffix>"
        ),
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Search input files recursively. Default searches only input-dir itself.",
    )
    parser.add_argument(
        "--include-gz",
        action="store_true",
        help="Also read .json.gz files. Useful only when needed; backup files are duplicates.",
    )
    parser.add_argument(
        "--sort",
        choices=("id", "first-seen"),
        default="id",
        help="Output ordering. Default: id",
    )
    parser.add_argument(
        "--keep-temp-db",
        action="store_true",
        help="Keep the temporary SQLite dedupe DB next to the output file.",
    )
    return parser.parse_args()


def discover_inputs(input_dir: Path, recursive: bool, include_gz: bool) -> list[Path]:
    if not input_dir.is_dir():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir}")

    patterns = ["*.json"]
    if include_gz:
        patterns.append("*.json.gz")

    files: list[Path] = []
    for pattern in patterns:
        matches = input_dir.rglob(pattern) if recursive else input_dir.glob(pattern)
        files.extend(path for path in matches if path.is_file())

    return sorted(files)


def open_text(path: Path) -> TextIO:
    if path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("rt", encoding="utf-8")


def iter_vulnerabilities(path: Path, chunk_size: int = 1024 * 1024) -> Iterator[dict]:
    """Stream vulnerabilities from an NVD 2.0 feed without loading the file."""
    decoder = json.JSONDecoder()

    with open_text(path) as file:
        buffer = ""
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                raise ValueError(f'Missing "vulnerabilities" array in {path}')

            buffer += chunk
            key_index = buffer.find('"vulnerabilities"')
            if key_index == -1:
                buffer = buffer[-32:]
                continue

            array_index = buffer.find("[", key_index)
            if array_index == -1:
                buffer = buffer[key_index:]
                continue

            buffer = buffer[array_index + 1 :]
            break

        while True:
            buffer = buffer.lstrip()
            if not buffer:
                chunk = file.read(chunk_size)
                if not chunk:
                    raise ValueError(f"Unexpected EOF while reading {path}")
                buffer += chunk
                continue

            if buffer.startswith("]"):
                return

            if buffer.startswith(","):
                buffer = buffer[1:]
                continue

            while True:
                try:
                    vulnerability, end_index = decoder.raw_decode(buffer)
                    if not isinstance(vulnerability, dict):
                        raise ValueError(f"Expected object in vulnerabilities array: {path}")
                    yield vulnerability
                    buffer = buffer[end_index:]
                    break
                except json.JSONDecodeError:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        raise ValueError(f"Unexpected EOF while parsing {path}") from None
                    buffer += chunk


def cve_id(vulnerability: dict) -> str | None:
    cve = vulnerability.get("cve")
    if not isinstance(cve, dict):
        return None

    value = cve.get("id")
    if not isinstance(value, str) or not value:
        return None

    return value


def compact_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, separators=JSON_SEPARATORS)


def canonical_json(value: dict) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=JSON_SEPARATORS,
        sort_keys=True,
    )


def content_signature(value: dict) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def derived_output_path(output: Path, label: str) -> Path:
    if output.suffix:
        return output.with_name(f"{output.stem}.{label}{output.suffix}")
    return output.with_name(f"{output.name}.{label}")


def init_db(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS cves (
            signature TEXT PRIMARY KEY,
            id TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            source_order INTEGER NOT NULL,
            source_file TEXT NOT NULL,
            total_count INTEGER NOT NULL,
            duplicate_count INTEGER NOT NULL,
            line TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS duplicate_occurrences (
            seen_index INTEGER PRIMARY KEY,
            signature TEXT NOT NULL,
            id TEXT NOT NULL,
            source_order INTEGER NOT NULL,
            source_file TEXT NOT NULL,
            line TEXT NOT NULL
        )
        """
    )
    return connection


def insert_vulnerability(
    connection: sqlite3.Connection,
    signature: str,
    vuln_id: str,
    seen_index: int,
    source_order: int,
    source_file: str,
    line: str,
) -> str:
    cursor = connection.execute(
        """
        INSERT INTO cves (
            signature,
            id,
            first_seen,
            source_order,
            source_file,
            total_count,
            duplicate_count,
            line
        )
        VALUES (?, ?, ?, ?, ?, 1, 0, ?)
        ON CONFLICT(signature) DO NOTHING
        """,
        (signature, vuln_id, seen_index, source_order, source_file, line),
    )
    if cursor.rowcount > 0:
        return "unique"

    connection.execute(
        """
        UPDATE cves
        SET
            total_count = total_count + 1,
            duplicate_count = duplicate_count + 1
        WHERE signature = ?
        """,
        (signature,),
    )
    connection.execute(
        """
        INSERT INTO duplicate_occurrences (
            seen_index,
            signature,
            id,
            source_order,
            source_file,
            line
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (seen_index, signature, vuln_id, source_order, source_file, line),
    )
    return "duplicate"


def merge_inputs(
    connection: sqlite3.Connection,
    inputs: Iterable[Path],
) -> tuple[int, int, int, int]:
    total_seen = 0
    missing_id = 0
    unique_inserted = 0
    duplicate_occurrences = 0

    for source_order, path in enumerate(inputs):
        file_seen = 0
        file_unique_inserted = 0
        file_duplicate_occurrences = 0
        print(f"[merge] reading {path}", file=sys.stderr)

        for vulnerability in iter_vulnerabilities(path):
            total_seen += 1
            file_seen += 1

            vuln_id = cve_id(vulnerability)
            if vuln_id is None:
                missing_id += 1
                continue

            result = insert_vulnerability(
                connection=connection,
                signature=content_signature(vulnerability),
                vuln_id=vuln_id,
                seen_index=total_seen,
                source_order=source_order,
                source_file=str(path),
                line=compact_json(vulnerability),
            )
            if result == "unique":
                unique_inserted += 1
                file_unique_inserted += 1
            else:
                duplicate_occurrences += 1
                file_duplicate_occurrences += 1

        connection.commit()
        print(
            (
                f"[merge] {path.name}: seen={file_seen:,}, "
                f"unique={file_unique_inserted:,}, "
                f"duplicates={file_duplicate_occurrences:,}"
            ),
            file=sys.stderr,
        )

    return total_seen, missing_id, unique_inserted, duplicate_occurrences


def write_jsonl(connection: sqlite3.Connection, output: Path, sort: str) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_output = output.with_suffix(output.suffix + ".tmp")

    order_by = "id, first_seen" if sort == "id" else "first_seen"
    count = 0

    with temp_output.open("wt", encoding="utf-8", newline="\n") as file:
        for (line,) in connection.execute(f"SELECT line FROM cves ORDER BY {order_by}"):
            file.write(line)
            file.write("\n")
            count += 1

    os.replace(temp_output, output)
    return count


def compact_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=JSON_SEPARATORS)


def write_duplicate_occurrences(
    connection: sqlite3.Connection,
    output: Path,
    sort: str,
) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_output = output.with_suffix(output.suffix + ".tmp")

    order_by = "id, seen_index" if sort == "id" else "seen_index"
    count = 0

    with temp_output.open("wt", encoding="utf-8", newline="\n") as file:
        for seen_index, signature, vuln_id, source_file, line in connection.execute(
            f"""
            SELECT seen_index, signature, id, source_file, line
            FROM duplicate_occurrences
            ORDER BY {order_by}
            """
        ):
            file.write(
                '{"cveId":'
                + compact_string(vuln_id)
                + ',"duplicateKey":'
                + compact_string(signature)
                + ',"seenIndex":'
                + str(seen_index)
                + ',"sourceFile":'
                + compact_string(source_file)
                + ',"vulnerability":'
                + line
                + "}\n"
            )
            count += 1

    os.replace(temp_output, output)
    return count


def write_duplicate_counts(
    connection: sqlite3.Connection,
    output: Path,
    sort: str,
) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_output = output.with_suffix(output.suffix + ".tmp")

    order_by = "id, first_seen" if sort == "id" else "first_seen"
    count = 0

    with temp_output.open("wt", encoding="utf-8", newline="\n") as file:
        for (
            signature,
            vuln_id,
            first_seen,
            source_file,
            total_count,
            duplicate_count,
            line,
        ) in connection.execute(
            f"""
            SELECT
                signature,
                id,
                first_seen,
                source_file,
                total_count,
                duplicate_count,
                line
            FROM cves
            WHERE duplicate_count > 0
            ORDER BY {order_by}
            """
        ):
            file.write(
                '{"cveId":'
                + compact_string(vuln_id)
                + ',"duplicateKey":'
                + compact_string(signature)
                + ',"totalCount":'
                + str(total_count)
                + ',"duplicateCount":'
                + str(duplicate_count)
                + ',"firstSeen":'
                + str(first_seen)
                + ',"firstSourceFile":'
                + compact_string(source_file)
                + ',"vulnerability":'
                + line
                + "}\n"
            )
            count += 1

    os.replace(temp_output, output)
    return count


def main() -> int:
    args = parse_args()
    inputs = discover_inputs(args.input_dir, args.recursive, args.include_gz)
    if not inputs:
        print(f"No input files found under {args.input_dir}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    duplicates_output = args.duplicates_output or derived_output_path(args.output, "duplicates")
    duplicate_counts_output = args.duplicate_counts_output or derived_output_path(
        args.output,
        "duplicate-counts",
    )
    temp_dir = args.output.parent if args.keep_temp_db else Path(tempfile.mkdtemp(prefix="nvd-merge-"))
    db_path = temp_dir / f"{args.output.name}.dedupe.sqlite"

    print(f"[merge] input_files={len(inputs):,}", file=sys.stderr)
    print(f"[merge] temp_db={db_path}", file=sys.stderr)
    print(f"[merge] output={args.output}", file=sys.stderr)
    print(f"[merge] duplicates_output={duplicates_output}", file=sys.stderr)
    print(f"[merge] duplicate_counts_output={duplicate_counts_output}", file=sys.stderr)

    connection = init_db(db_path)
    try:
        total_seen, missing_id, unique_inserted, duplicate_occurrences = merge_inputs(
            connection,
            inputs,
        )
        unique_count = write_jsonl(connection, args.output, args.sort)
        duplicate_occurrences_written = write_duplicate_occurrences(
            connection,
            duplicates_output,
            args.sort,
        )
        duplicate_groups_written = write_duplicate_counts(
            connection,
            duplicate_counts_output,
            args.sort,
        )
    finally:
        connection.close()
        if not args.keep_temp_db:
            db_path.unlink(missing_ok=True)
            db_path.with_suffix(db_path.suffix + "-wal").unlink(missing_ok=True)
            db_path.with_suffix(db_path.suffix + "-shm").unlink(missing_ok=True)
            try:
                temp_dir.rmdir()
            except OSError:
                pass

    print(f"[merge] total_seen={total_seen:,}", file=sys.stderr)
    print(f"[merge] unique_written={unique_count:,}", file=sys.stderr)
    print(f"[merge] unique_inserted={unique_inserted:,}", file=sys.stderr)
    print(f"[merge] duplicate_occurrences={duplicate_occurrences:,}", file=sys.stderr)
    print(
        f"[merge] duplicate_occurrences_written={duplicate_occurrences_written:,}",
        file=sys.stderr,
    )
    print(f"[merge] duplicate_groups_written={duplicate_groups_written:,}", file=sys.stderr)
    print(f"[merge] missing_id_skipped={missing_id:,}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
