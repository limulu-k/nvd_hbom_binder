"""Command line interface for the compact NVD applicability database."""

from __future__ import annotations

import argparse
import csv
import io
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Mapping, Sequence

from .audit import AuditError, audit_database
from .builder import BuildError, build_database
from .query_engine import ApplicabilityQuery, QueryEngine, QueryError
from .storage import StorageError


DEFAULT_DB = Path("workspace/nvd_applicability_v10.sqlite")
DEFAULT_NVD = Path("data/nvd-cves.current.jsonl")
DEFAULT_LLM = Path("data/nvd-cves-desc_parse.jsonl")
DEFAULT_LLM_FAIL = Path("data/nvd-cves-desc_parse-fail.jsonl")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "NVD Applicability Framework 3.3 identity-alias compiler and query engine "
            "(SQLite schema v5)"
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser(
        "build", help="compile NVD and precomputed LLM JSONL into one published DB"
    )
    build.add_argument("--input", type=Path, default=DEFAULT_NVD)
    build.add_argument("--llm", type=Path, default=DEFAULT_LLM)
    build.add_argument("--llm-fail", type=Path, default=DEFAULT_LLM_FAIL)
    build.add_argument("--without-llm", action="store_true")
    build.add_argument("--db", type=Path, default=DEFAULT_DB)
    build.add_argument(
        "--replace",
        action="store_true",
        help="atomically replace an existing target after the new DB passes audit",
    )
    build.add_argument(
        "--limit",
        type=int,
        help="compile only the first N rows (development/smoke use)",
    )
    build.add_argument("--progress-every", type=int, default=1000)

    query = commands.add_parser(
        "query", help="evaluate all candidate CVEs for a product/version"
    )
    query.add_argument("--db", type=Path, default=DEFAULT_DB)
    query.add_argument("--vendor", required=True)
    query.add_argument("--product", required=True)
    query.add_argument("--version", required=True)
    for axis in (
        "distribution",
        "edition",
        "component",
        "update",
        "language",
        "sw-edition",
        "target-sw",
        "target-hw",
        "other",
    ):
        query.add_argument(f"--{axis}")
    query.add_argument(
        "--axis-policy",
        choices=("operational_strict", "broad_discovery", "platform_strict"),
        default="operational_strict",
    )
    query.add_argument(
        "--prediction-policy",
        choices=("strict", "inclusive", "review-aware"),
        default="inclusive",
    )
    query.add_argument(
        "--history-conflict-policy",
        type=Path,
        help=(
            "optional history adjudication JSONL; overlapping CNA/CPE ranges "
            "use the latest CPE and history Added ranges are accepted"
        ),
    )
    query.add_argument(
        "--all-states",
        action="store_true",
        help="show every candidate state, including negative/non-applicable rows",
    )
    query.add_argument(
        "--trace", action="store_true", help="include assertion-level decision traces"
    )
    query.add_argument("--format", choices=("table", "json", "csv"), default="table")
    query.add_argument("--output", type=Path)

    products = commands.add_parser(
        "products", help="search canonical products and binding counts"
    )
    products.add_argument("text")
    products.add_argument("--db", type=Path, default=DEFAULT_DB)
    products.add_argument("--limit", type=int, default=50)
    products.add_argument("--format", choices=("table", "json", "csv"), default="table")

    identity = commands.add_parser(
        "identity", help="resolve vendor/product through exact and alias tiers"
    )
    identity.add_argument("--db", type=Path, default=DEFAULT_DB)
    identity.add_argument("--vendor", required=True)
    identity.add_argument("--product", required=True)
    identity.add_argument(
        "--axis-policy",
        choices=("operational_strict", "broad_discovery", "platform_strict"),
        default="operational_strict",
    )

    audit = commands.add_parser("audit", help="run schema-v5 semantic publish checks")
    audit.add_argument("--db", type=Path, default=DEFAULT_DB)
    audit.add_argument("--full-integrity", action="store_true")

    return parser


def _clip(value: Any, width: int) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= width else text[: width - 1] + "…"


def _table(rows: Sequence[Mapping[str, Any]], fields: Sequence[str]) -> str:
    if not rows:
        return "(no rows)\n"
    maxima = {
        "description": 70,
        "reason_codes": 48,
        "canonical_product": 42,
        "canonical_vendor": 28,
    }
    widths = {
        field: min(
            maxima.get(field, 28),
            max(len(field), *(len(str(row.get(field, ""))) for row in rows)),
        )
        for field in fields
    }
    output = [
        "  ".join(field.ljust(widths[field]) for field in fields),
        "  ".join("-" * widths[field] for field in fields),
    ]
    output.extend(
        "  ".join(
            _clip(row.get(field), widths[field]).ljust(widths[field])
            for field in fields
        )
        for row in rows
    )
    return "\n".join(output) + "\n"


def _csv(rows: Sequence[Mapping[str, Any]], fields: Sequence[str]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def _render_rows(
    rows: Sequence[Mapping[str, Any]],
    fields: Sequence[str],
    *,
    output_format: str,
    envelope: Mapping[str, Any] | None = None,
) -> str:
    if output_format == "json":
        payload = dict(envelope or {})
        payload["results"] = list(rows)
        payload["result_count"] = len(rows)
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output_format == "csv":
        return _csv(rows, fields)
    return _table(rows, fields)


def _write(path: Path | None, content: str) -> None:
    if path is None:
        sys.stdout.write(content)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def _build(args: argparse.Namespace) -> int:
    if args.limit is not None and args.limit <= 0:
        raise BuildError("--limit must be positive")
    result = build_database(
        input_path=args.input,
        database_path=args.db,
        llm_path=None if args.without_llm else args.llm,
        llm_fail_path=None if args.without_llm else args.llm_fail,
        replace_existing=args.replace,
        limit=args.limit,
        progress_every=args.progress_every,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _query(args: argparse.Namespace) -> int:
    request = ApplicabilityQuery(
        vendor=args.vendor,
        product=args.product,
        version=args.version,
        distribution=args.distribution,
        edition=args.edition,
        component=args.component,
        update=args.update,
        language=args.language,
        sw_edition=args.sw_edition,
        target_sw=args.target_sw,
        target_hw=args.target_hw,
        other=args.other,
        axis_policy=args.axis_policy,
    )
    with QueryEngine(
        args.db,
        history_conflict_policy=args.history_conflict_policy,
    ) as engine:
        payload = engine.query(
            request,
            prediction_policy=args.prediction_policy,
            include_trace=args.trace,
        )
    rows = list(payload["results"])
    if not args.all_states:
        rows = [row for row in rows if row["positive"]]
    flattened = []
    for row in rows:
        selected = dict(row)
        selected["reason_codes"] = ";".join(row["reason_codes"])
        if not args.trace:
            selected.pop("assertions", None)
        flattened.append(selected)
    envelope = {key: value for key, value in payload.items() if key != "results"}
    envelope["returned_count"] = len(flattened)
    fields = (
        "cve_id",
        "state",
        "positive",
        "enrichment_class",
        "manual_review_required",
        "reason_codes",
        "last_modified",
        "description",
    )
    _write(
        args.output,
        _render_rows(
            flattened,
            fields,
            output_format=args.format,
            envelope=envelope,
        ),
    )
    return 0


def _products(args: argparse.Namespace) -> int:
    with QueryEngine(args.db) as engine:
        rows = engine.search_products(args.text, limit=args.limit)
    fields = (
        "product_id",
        "canonical_vendor",
        "canonical_product",
        "part",
        "cluster_id",
        "identity_tier",
        "identity_review_state",
        "cve_count",
    )
    print(_render_rows(rows, fields, output_format=args.format), end="")
    return 0


def _identity(args: argparse.Namespace) -> int:
    with QueryEngine(args.db) as engine:
        result = engine.resolve_identity(
            args.vendor, args.product, axis_policy=args.axis_policy
        )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["state"] == "resolved" else 2


def _audit(args: argparse.Namespace) -> int:
    result = audit_database(args.db, full_integrity=args.full_integrity)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["passed"] else 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            return _build(args)
        if args.command == "query":
            return _query(args)
        if args.command == "products":
            return _products(args)
        if args.command == "identity":
            return _identity(args)
        if args.command == "audit":
            return _audit(args)
        parser.error(f"unsupported command: {args.command}")
    except (
        AuditError,
        BuildError,
        QueryError,
        StorageError,
        OSError,
        sqlite3.Error,
        ValueError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 2
