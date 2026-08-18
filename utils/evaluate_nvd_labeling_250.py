#!/usr/bin/env python3
"""Evaluate an applicability DB with the NVD labeling 250 gold set.

Evaluation artifacts are written under ``workspace/v<dbversion>``. Progress
events are written to stderr and the final metrics JSON is written to stdout,
so stdout can be redirected or piped to another program.
"""

from __future__ import annotations

import os
import argparse
import csv
import json
import math
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DATAFILE = "nvd_labeling_250_v2.jsonl"
DBVERSION = 10
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.nvd_normalization.query_engine import (  # noqa: E402
    ApplicabilityQuery,
    QueryEngine,
)


ERROR_FIELDS = (
    "vendor",
    "product",
    "version",
    "policy",
    "error_type",
    "cve_id",
    "candidate_state",
)


def parse_args() -> argparse.Namespace:
    global DBVERSION

    parser = argparse.ArgumentParser(
        description=(
            "Evaluate an applicability DB against "
            f"data/{DATAFILE}."
        )
    )

    parser.add_argument(
        "--dbversion",
        type=int,
        default=DBVERSION,
        help=f"applicability DB version (default: {DBVERSION})",
    )

    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help=(
            "applicability SQLite DB "
            "(default: workspace/nvd_applicability_v<dbversion>.sqlite)"
        ),
    )

    parser.add_argument(
        "--gold",
        type=Path,
        default=ROOT / "data" / DATAFILE,
        help=f"gold JSONL (default: data/{DATAFILE})",
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "artifact directory "
            "(default: workspace/v<dbversion>)"
        ),
    )

    parser.add_argument(
        "--output-prefix",
        help="output filename prefix (defaults to the goldset filename stem)",
    )

    parser.add_argument(
        "--progress-every",
        type=int,
        default=25,
    )

    args = parser.parse_args()

    # CLI에서 입력된 버전으로 전역변수 변경
    DBVERSION = args.dbversion

    # --db가 지정되지 않았을 때 DBVERSION 기반 기본 경로 생성
    if args.db is None:
        args.db = (
            ROOT
            / "workspace"
            / f"nvd_applicability_v{DBVERSION}.sqlite"
        )

    # --output-dir이 지정되지 않았을 때 DBVERSION 기반 기본 경로 생성
    if args.output_dir is None:
        args.output_dir = (
            ROOT
            / "workspace"
            / f"v{DBVERSION}"
        )

    return args


def load_gold(path: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    raw_labels = 0
    deduplicated_labels = 0
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if set(row) != {"vendor", "product", "version", "cve_id"}:
            raise ValueError(f"line {line_number}: unexpected fields")
        key = (str(row["vendor"]), str(row["product"]), str(row["version"]))
        if key in seen_keys:
            raise ValueError(f"line {line_number}: duplicate query key {key!r}")
        seen_keys.add(key)
        raw = [str(value).strip().upper() for value in row["cve_id"]]
        labels = sorted(set(raw))
        raw_labels += len(raw)
        deduplicated_labels += len(labels)
        rows.append(
            {
                "vendor": key[0],
                "product": key[1],
                "version": key[2],
                "cve_id": labels,
            }
        )
    if not rows:
        raise ValueError("gold set is empty")
    return rows, {
        "raw_label_entries": raw_labels,
        "deduplicated_label_entries": deduplicated_labels,
        "duplicate_label_entries_removed": raw_labels - deduplicated_labels,
    }


def divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def f_score(precision: float, recall: float, beta: float) -> float:
    beta2 = beta * beta
    denominator = beta2 * precision + recall
    return (1.0 + beta2) * precision * recall / denominator if denominator else 0.0


def metrics(gold: set[str], predicted: set[str]) -> dict[str, Any]:
    tp = len(gold & predicted)
    fp = len(predicted - gold)
    fn = len(gold - predicted)
    precision = divide(tp, tp + fp)
    recall = divide(tp, tp + fn)
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "f0_5": f_score(precision, recall, 0.5),
        "f1": f_score(precision, recall, 1.0),
        "f2": f_score(precision, recall, 2.0),
        "jaccard": divide(tp, tp + fp + fn),
        "false_discovery_rate": divide(fp, tp + fp),
        "false_negative_rate": divide(fn, tp + fn),
        "exact_match": gold == predicted,
    }


def aggregate(case_rows: list[dict[str, Any]], prefix: str) -> dict[str, Any]:
    metric_key = "metrics" if prefix == "inclusive" else "strict_metrics"
    result_key = "result" if prefix == "inclusive" else "strict_result"
    values = [row[metric_key] for row in case_rows]
    tp = sum(item["true_positive"] for item in values)
    fp = sum(item["false_positive"] for item in values)
    fn = sum(item["false_negative"] for item in values)
    precision = divide(tp, tp + fp)
    recall = divide(tp, tp + fn)
    count_deltas = [
        len(row[result_key]) - len(row["test_set"])
        for row in case_rows
    ]
    return {
        "case_count": len(case_rows),
        "gold_positive": tp + fn,
        "predicted_positive": tp + fp,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "f0_5": f_score(precision, recall, 0.5),
        "f1": f_score(precision, recall, 1.0),
        "f2": f_score(precision, recall, 2.0),
        "jaccard": divide(tp, tp + fp + fn),
        "false_discovery_rate": divide(fp, tp + fp),
        "false_negative_rate": divide(fn, tp + fn),
        "exact_match_keys": sum(bool(item["exact_match"]) for item in values),
        "exact_match_rate": divide(
            sum(bool(item["exact_match"]) for item in values), len(values)
        ),
        "macro_precision": sum(item["precision"] for item in values) / len(values),
        "macro_recall": sum(item["recall"] for item in values) / len(values),
        "macro_f0_5": sum(item["f0_5"] for item in values) / len(values),
        "macro_f1": sum(item["f1"] for item in values) / len(values),
        "macro_f2": sum(item["f2"] for item in values) / len(values),
        "macro_jaccard": sum(item["jaccard"] for item in values) / len(values),
        "mean_count_bias": sum(count_deltas) / len(count_deltas),
        "count_mae": sum(abs(value) for value in count_deltas) / len(count_deltas),
        "count_rmse": math.sqrt(
            sum(value * value for value in count_deltas) / len(count_deltas)
        ),
    }


def json_compact(value: Iterable[str]) -> str:
    return json.dumps(list(value), ensure_ascii=False, separators=(",", ":"))


def write_error_csv(
    path: Path,
    rows: Iterable[dict[str, str]],
    *,
    include_header: bool,
) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ERROR_FIELDS)
        if include_header:
            writer.writeheader()
        writer.writerows(rows)


def metadata(connection: sqlite3.Connection) -> dict[str, str]:
    wanted = {
        "framework_version",
        "profile_version",
        "publish_health",
        "rule_version",
        "schema_version",
    }
    return {
        str(row[0]): str(row[1])
        for row in connection.execute("SELECT key,value FROM metadata")
        if str(row[0]) in wanted
    }


def snapshot(connection: sqlite3.Connection) -> dict[str, Any]:
    row = connection.execute(
        """SELECT payload_sha256,record_count,coverage_start,coverage_end,is_complete
           FROM source_snapshot_manifest
           ORDER BY snapshot_id DESC LIMIT 1"""
    ).fetchone()
    if row is None:
        return {}
    return {
        "payload_sha256": row[0],
        "record_count": row[1],
        "coverage_start": row[2],
        "coverage_end": row[3],
        "is_complete": row[4],
    }


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    inclusive = summary["overall"]["inclusive"]
    strict = summary["overall"]["strict"]
    dataset = summary["dataset"]
    timing = summary["timing"]
    text = f"""# NVD labeling 250 supplyment evaluation

- Database rule version: `{summary["database_metadata"].get("rule_version", "unknown")}`
- Query keys: {dataset["row_count"]:,} ({dataset["unique_vendor_product_count"]:,} vendor/product pairs × 4 versions)
- Deduplicated label memberships: {dataset["deduplicated_label_entries"]:,}
- Primary CSV result policy: inclusive (`affected` + `potentially_affected` + `conflict_review`)

| policy | TP | FP | FN | precision | recall | F1 | F0.5 | F2 | Jaccard | exact keys |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| inclusive | {inclusive["true_positive"]:,} | {inclusive["false_positive"]:,} | {inclusive["false_negative"]:,} | {inclusive["precision"]:.6f} | {inclusive["recall"]:.6f} | {inclusive["f1"]:.6f} | {inclusive["f0_5"]:.6f} | {inclusive["f2"]:.6f} | {inclusive["jaccard"]:.6f} | {inclusive["exact_match_keys"]:,}/{inclusive["case_count"]:,} |
| strict | {strict["true_positive"]:,} | {strict["false_positive"]:,} | {strict["false_negative"]:,} | {strict["precision"]:.6f} | {strict["recall"]:.6f} | {strict["f1"]:.6f} | {strict["f0_5"]:.6f} | {strict["f2"]:.6f} | {strict["jaccard"]:.6f} | {strict["exact_match_keys"]:,}/{strict["case_count"]:,} |

- Unique-label snapshot coverage: {dataset["snapshot_coverage"]:.6f}
- Per-key candidate recall: {dataset["candidate_recall"]:.6f}
- Evaluation time: {timing["evaluation_seconds"]:.3f} seconds

TN-based accuracy and specificity are omitted because this is an open-world CVE retrieval evaluation.
"""
    path.write_text(text, encoding="utf-8")


def main() -> int:
    args = parse_args()
    if not args.db.is_file():
        raise FileNotFoundError(f"database does not exist: {args.db}")
    if not args.gold.is_file():
        raise FileNotFoundError(f"gold set does not exist: {args.gold}")

    started = time.monotonic()
    gold_rows, label_counts = load_gold(args.gold)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    base = args.output_dir / (args.output_prefix or args.gold.stem)
    query_csv_path = base.with_name(base.name + "_query_results.csv")
    cases_path = base.with_name(base.name + "_evaluation_cases.jsonl")
    errors_path = base.with_name(base.name + "_cve_errors.csv")
    inclusive_errors_path = base.with_name(
        base.name + "_cve_errors_inclusive.csv"
    )
    inclusive_fp_path = base.with_name(
        base.name + "_cve_errors_inclusive_false_positive.csv"
    )
    inclusive_fn_path = base.with_name(
        base.name + "_cve_errors_inclusive_false_negative.csv"
    )
    summary_path = base.with_name(base.name + "_evaluation.json")
    markdown_path = base.with_name(base.name + "_evaluation_summary.md")

    case_rows: list[dict[str, Any]] = []
    error_rows: list[dict[str, str]] = []
    inclusive_fn_states: Counter[str] = Counter()
    strict_fn_states: Counter[str] = Counter()
    query_times: list[float] = []

    with QueryEngine(args.db) as engine:
        db_metadata = metadata(engine.connection)
        db_snapshot = snapshot(engine.connection)
        snapshot_cves = {
            str(row[0]).upper()
            for row in engine.connection.execute("SELECT cve_id FROM raw_cve")
        }
        for index, gold_row in enumerate(gold_rows, 1):
            query_started = time.monotonic()
            payload = engine.query(
                ApplicabilityQuery(
                    vendor=gold_row["vendor"],
                    product=gold_row["product"],
                    version=gold_row["version"],
                ),
                prediction_policy="inclusive",
                include_trace=False,
            )
            query_seconds = time.monotonic() - query_started
            query_times.append(query_seconds)
            states = {
                str(row["cve_id"]).upper(): str(row["state"])
                for row in payload["results"]
            }
            gold = set(gold_row["cve_id"])
            inclusive = {
                cve_id
                for cve_id, state in states.items()
                if state
                in {
                    "affected",
                    "potentially_affected",
                    "conflict_review",
                }
            }
            strict = {
                cve_id for cve_id, state in states.items() if state == "affected"
            }
            inclusive_tp = sorted(gold & inclusive)
            inclusive_fp = sorted(inclusive - gold)
            inclusive_fn = sorted(gold - inclusive)
            strict_tp = sorted(gold & strict)
            strict_fp = sorted(strict - gold)
            strict_fn = sorted(gold - strict)
            for policy, false_positives, false_negatives, counter in (
                ("inclusive", inclusive_fp, inclusive_fn, inclusive_fn_states),
                ("strict", strict_fp, strict_fn, strict_fn_states),
            ):
                for cve_id in false_positives:
                    error_rows.append(
                        {
                            "vendor": gold_row["vendor"],
                            "product": gold_row["product"],
                            "version": gold_row["version"],
                            "policy": policy,
                            "error_type": "false_positive",
                            "cve_id": cve_id,
                            "candidate_state": states[cve_id],
                        }
                    )
                for cve_id in false_negatives:
                    state = states.get(cve_id, "candidate_missing")
                    counter[state] += 1
                    error_rows.append(
                        {
                            "vendor": gold_row["vendor"],
                            "product": gold_row["product"],
                            "version": gold_row["version"],
                            "policy": policy,
                            "error_type": "false_negative",
                            "cve_id": cve_id,
                            "candidate_state": state,
                        }
                    )
            resolved = [
                {
                    "product_id": row["product_id"],
                    "vendor": row["vendor"],
                    "product": row["product"],
                    "part": row["part"],
                }
                for row in payload["resolved_products"]
            ]
            case_rows.append(
                {
                    "vendor": gold_row["vendor"],
                    "product": gold_row["product"],
                    "version": gold_row["version"],
                    "test_set": sorted(gold),
                    "result": sorted(inclusive),
                    "true_positives": inclusive_tp,
                    "false_positives": inclusive_fp,
                    "false_negatives": inclusive_fn,
                    "metrics": metrics(gold, inclusive),
                    "strict_result": sorted(strict),
                    "strict_true_positives": strict_tp,
                    "strict_false_positives": strict_fp,
                    "strict_false_negatives": strict_fn,
                    "strict_metrics": metrics(gold, strict),
                    "candidate_count": int(payload["candidate_count"]),
                    "candidate_state_counts": payload["state_counts"],
                    "query_status": payload["resolution"]["state"],
                    "resolved_products": resolved,
                    "query_seconds": query_seconds,
                }
            )
            if args.progress_every and (
                index % args.progress_every == 0 or index == len(gold_rows)
            ):
                print(
                    json.dumps(
                        {
                            "event": "evaluation_progress",
                            "completed": index,
                            "total": len(gold_rows),
                            "elapsed_seconds": round(time.monotonic() - started, 3),
                        },
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                    flush=True,
                )

    unique_labels = {
        cve_id for row in gold_rows for cve_id in row["cve_id"]
    }
    missing_candidate_count = inclusive_fn_states["candidate_missing"]
    dataset = {
        "row_count": len(gold_rows),
        "unique_key_count": len(
            {
                (row["vendor"], row["product"], row["version"])
                for row in gold_rows
            }
        ),
        "unique_vendor_product_count": len(
            {(row["vendor"], row["product"]) for row in gold_rows}
        ),
        **label_counts,
        "unique_labeled_cves": len(unique_labels),
        "unique_labeled_cves_in_snapshot": len(unique_labels & snapshot_cves),
        "snapshot_coverage": divide(
            len(unique_labels & snapshot_cves), len(unique_labels)
        ),
        "candidate_recall": 1.0
        - divide(missing_candidate_count, label_counts["deduplicated_label_entries"]),
    }
    overall = {
        "inclusive": aggregate(case_rows, "inclusive"),
        "strict": aggregate(case_rows, "strict"),
    }
    elapsed = time.monotonic() - started
    summary = {
        "input": str(args.gold),
        "database": str(args.db),
        "primary_result_policy": "inclusive",
        "result_policy_note": (
            "CSV/JSONL result includes affected, potentially_affected, and "
            "conflict_review; "
            "strict_result includes affected only."
        ),
        "metric_note": (
            "Open-world retrieval has no closed negative-CVE universe, so "
            "TN-based accuracy and specificity are omitted."
        ),
        "database_metadata": db_metadata,
        "snapshot": db_snapshot,
        "dataset": dataset,
        "overall": overall,
        "false_negative_state_totals": {
            "inclusive": dict(sorted(inclusive_fn_states.items())),
            "strict": dict(sorted(strict_fn_states.items())),
        },
        "timing": {
            "evaluation_seconds": elapsed,
            "mean_query_seconds": sum(query_times) / len(query_times),
            "max_query_seconds": max(query_times),
        },
        "files": {
            "query_results_csv": str(query_csv_path),
            "evaluation_cases_jsonl": str(cases_path),
            "cve_errors_csv": str(errors_path),
            "inclusive_cve_errors_csv": str(inclusive_errors_path),
            "inclusive_false_positive_cve_errors_csv": str(
                inclusive_fp_path
            ),
            "inclusive_false_negative_cve_errors_csv": str(
                inclusive_fn_path
            ),
            "evaluation_summary_json": str(summary_path),
            "evaluation_summary_markdown": str(markdown_path),
        },
    }

    with query_csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=("vendor", "product", "version", "test_set", "result")
        )
        writer.writeheader()
        for row in case_rows:
            writer.writerow(
                {
                    "vendor": row["vendor"],
                    "product": row["product"],
                    "version": row["version"],
                    "test_set": json_compact(row["test_set"]),
                    "result": json_compact(row["result"]),
                }
            )
    with cases_path.open("w", encoding="utf-8") as handle:
        for row in case_rows:
            handle.write(
                json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
            )
    write_error_csv(errors_path, error_rows, include_header=True)
    inclusive_error_rows = [
        row for row in error_rows if row["policy"] == "inclusive"
    ]
    write_error_csv(
        inclusive_errors_path,
        inclusive_error_rows,
        include_header=False,
    )
    write_error_csv(
        inclusive_fp_path,
        (
            row
            for row in inclusive_error_rows
            if row["error_type"] == "false_positive"
        ),
        include_header=False,
    )
    write_error_csv(
        inclusive_fn_path,
        (
            row
            for row in inclusive_error_rows
            if row["error_type"] == "false_negative"
        ),
        include_header=False,
    )
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_markdown(markdown_path, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
