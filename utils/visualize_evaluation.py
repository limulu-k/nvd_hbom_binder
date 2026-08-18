#!/usr/bin/env python3
"""Analyze and visualize the v10 NVD labeling evaluation artifacts."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import statistics
from typing import Any, Iterable

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402


POLICIES = {
    "inclusive": "metrics",
    "strict": "strict_metrics",
}

STATE_COLORS = {
    "affected": "#2563eb",
    "potentially_affected": "#f59e0b",
    "candidate_missing": "#64748b",
    "not_affected_out_of_range": "#ef4444",
    "conflict_review": "#8b5cf6",
    "not_affected_asserted": "#14b8a6",
    "not_applicable": "#84cc16",
    "product_only_observation": "#a16207",
}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--evaluation",
        type=Path,
        default=Path(
            "workspace/v10/nvd_labeling_250_v2_evaluation.json"
        ),
    )
    parser.add_argument(
        "--cases",
        type=Path,
        default=Path(
            "workspace/v10/nvd_labeling_250_v2_evaluation_cases.jsonl"
        ),
    )
    parser.add_argument(
        "--errors",
        type=Path,
        default=Path(
            "workspace/v10/nvd_labeling_250_v2_cve_errors.csv"
        ),
    )
    parser.add_argument(
        "--previous-evaluation",
        type=Path,
        default=Path(
            "workspace/v7/nvd_labeling_250_v2_evaluation.json"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("workspace/v10/visualizations"),
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as source:
        return [json.loads(line) for line in source if line.strip()]


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as source:
        return list(csv.DictReader(source))


def percentile(values: Iterable[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (
        ordered[upper] - ordered[lower]
    ) * (position - lower)


def pearson(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or not left:
        return 0.0
    left_mean = statistics.mean(left)
    right_mean = statistics.mean(right)
    numerator = sum(
        (a - left_mean) * (b - right_mean)
        for a, b in zip(left, right)
    )
    denominator = (
        sum((value - left_mean) ** 2 for value in left)
        * sum((value - right_mean) ** 2 for value in right)
    ) ** 0.5
    return numerator / denominator if denominator else 0.0


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def key_label(case: dict[str, Any]) -> str:
    return (
        f"{case['vendor']}/{case['product']}"
        f" @ {case['version']}"
    )


def policy_rows(
    cases: list[dict[str, Any]],
    metric_key: str,
) -> list[dict[str, Any]]:
    rows = []
    for case in cases:
        metric = case[metric_key]
        rows.append(
            {
                "vendor": case["vendor"],
                "product": case["product"],
                "version": case["version"],
                "gold_count": len(case["test_set"]),
                "predicted_count": (
                    len(case["result"])
                    if metric_key == "metrics"
                    else len(case["strict_result"])
                ),
                "true_positive": metric["true_positive"],
                "false_positive": metric["false_positive"],
                "false_negative": metric["false_negative"],
                "precision": metric["precision"],
                "recall": metric["recall"],
                "f1": metric["f1"],
                "jaccard": metric["jaccard"],
                "error_count": (
                    metric["false_positive"]
                    + metric["false_negative"]
                ),
                "count_bias": (
                    len(case["result"])
                    if metric_key == "metrics"
                    else len(case["strict_result"])
                )
                - len(case["test_set"]),
                "candidate_count": case["candidate_count"],
                "query_seconds": case["query_seconds"],
            }
        )
    return rows


def top_products(
    rows: list[dict[str, Any]],
    limit: int = 15,
) -> list[dict[str, Any]]:
    aggregates: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (str(row["vendor"]), str(row["product"]))
        item = aggregates.setdefault(
            key,
            {
                "vendor": key[0],
                "product": key[1],
                "false_positive": 0,
                "false_negative": 0,
                "error_count": 0,
            },
        )
        for field in (
            "false_positive",
            "false_negative",
            "error_count",
        ):
            item[field] += int(row[field])
    return sorted(
        aggregates.values(),
        key=lambda item: (
            item["error_count"],
            item["false_positive"],
        ),
        reverse=True,
    )[:limit]


def b3_summary(
    database_path: Path,
    cases: list[dict[str, Any]],
) -> dict[str, Any]:
    if not database_path.is_file():
        return {
            "available": False,
            "accepted_edges": 0,
            "evaluation_endpoint_overlaps": 0,
            "edges": [],
        }
    connection = sqlite3.connect(
        database_path.resolve().as_uri() + "?mode=ro",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    rows = list(
        connection.execute(
            """SELECT e.status,e.strict_eligible,
                      l.scope_kind AS scope,
                      l.vendor_key AS left_vendor,
                      l.product_key AS left_product,
                      l.part AS left_part,
                      r.vendor_key AS right_vendor,
                      r.product_key AS right_product,
                      r.part AS right_part
               FROM identity_alias_edge e
               JOIN identity_node l ON l.node_id=e.left_node_id
               JOIN identity_node r ON r.node_id=e.right_node_id
               WHERE e.alias_class='B3_TYPO'
                 AND e.status='accepted'
                 AND e.strict_eligible=1
               ORDER BY l.scope_kind,l.vendor_key,l.product_key"""
        )
    )
    connection.close()
    evaluation_keys = {
        (str(case["vendor"]), str(case["product"]))
        for case in cases
    }
    edges = [dict(row) for row in rows]
    overlap_count = 0
    for row in rows:
        if str(row["scope"]) == "vendor":
            vendors = {
                str(row["left_vendor"]),
                str(row["right_vendor"]),
            }
            if any(vendor in vendors for vendor, _ in evaluation_keys):
                overlap_count += 1
        else:
            endpoints = {
                (
                    str(row["left_vendor"]),
                    str(row["left_product"]),
                ),
                (
                    str(row["right_vendor"]),
                    str(row["right_product"]),
                ),
            }
            if endpoints & evaluation_keys:
                overlap_count += 1
    return {
        "available": True,
        "accepted_edges": len(edges),
        "vendor_edges": sum(
            item["scope"] == "vendor" for item in edges
        ),
        "product_edges": sum(
            item["scope"] == "product" for item in edges
        ),
        "evaluation_endpoint_overlaps": overlap_count,
        "edges": edges,
    }


def compare_previous(
    current: dict[str, Any],
    previous_path: Path,
) -> dict[str, Any]:
    if not previous_path.is_file():
        return {"available": False}
    previous = load_json(previous_path)
    current_files = current.get("files", {})
    previous_files = previous.get("files", {})
    pairs = {}
    for name in ("query_results_csv", "cve_errors_csv"):
        current_path = Path(str(current_files.get(name, "")))
        previous_file = Path(str(previous_files.get(name, "")))
        if current_path.is_file() and previous_file.is_file():
            current_hash = sha256(current_path)
            previous_hash = sha256(previous_file)
            pairs[name] = {
                "identical": current_hash == previous_hash,
                "current_sha256": current_hash,
                "previous_sha256": previous_hash,
            }
    current_timing = current["timing"]
    previous_timing = previous["timing"]
    return {
        "available": True,
        "overall_metrics_identical": (
            current["overall"] == previous["overall"]
        ),
        "error_state_totals_identical": (
            current["false_negative_state_totals"]
            == previous["false_negative_state_totals"]
        ),
        "artifact_comparison": pairs,
        "evaluation_seconds_delta": (
            current_timing["evaluation_seconds"]
            - previous_timing["evaluation_seconds"]
        ),
        "mean_query_seconds_delta": (
            current_timing["mean_query_seconds"]
            - previous_timing["mean_query_seconds"]
        ),
        "max_query_seconds_delta": (
            current_timing["max_query_seconds"]
            - previous_timing["max_query_seconds"]
        ),
    }


def save_per_key_csv(
    destination: Path,
    rows_by_policy: dict[str, list[dict[str, Any]]],
) -> None:
    fields = [
        "policy",
        "vendor",
        "product",
        "version",
        "gold_count",
        "predicted_count",
        "true_positive",
        "false_positive",
        "false_negative",
        "precision",
        "recall",
        "f1",
        "jaccard",
        "error_count",
        "count_bias",
        "candidate_count",
        "query_seconds",
    ]
    with destination.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for policy in ("inclusive", "strict"):
            for row in rows_by_policy[policy]:
                writer.writerow({"policy": policy, **row})


def plot_metrics(
    destination: Path,
    evaluation: dict[str, Any],
) -> None:
    inclusive = evaluation["overall"]["inclusive"]
    strict = evaluation["overall"]["strict"]
    names = ["Precision", "Recall", "F1", "Jaccard"]
    fields = ["precision", "recall", "f1", "jaccard"]
    x = np.arange(len(names))
    width = 0.35

    figure, axes = plt.subplots(1, 2, figsize=(14, 5.8))
    left = axes[0]
    inclusive_values = [inclusive[field] for field in fields]
    strict_values = [strict[field] for field in fields]
    first = left.bar(
        x - width / 2,
        inclusive_values,
        width,
        label="Inclusive",
        color="#2563eb",
    )
    second = left.bar(
        x + width / 2,
        strict_values,
        width,
        label="Strict",
        color="#f59e0b",
    )
    left.set_ylim(0, 1.06)
    left.set_xticks(x, names)
    left.set_ylabel("Score")
    left.set_title("Overall Retrieval Metrics")
    left.grid(axis="y", alpha=0.25)
    left.legend()
    left.bar_label(first, fmt="%.3f", padding=3, fontsize=9)
    left.bar_label(second, fmt="%.3f", padding=3, fontsize=9)

    right = axes[1]
    affected_tp = strict["true_positive"]
    affected_fp = strict["false_positive"]
    potential_tp = (
        inclusive["true_positive"] - strict["true_positive"]
    )
    potential_fp = (
        inclusive["false_positive"] - strict["false_positive"]
    )
    labels = ["Affected-only", "Potential-only added"]
    true_values = [affected_tp, potential_tp]
    false_values = [affected_fp, potential_fp]
    bars = right.bar(
        labels,
        true_values,
        label="True positive",
        color="#16a34a",
    )
    false_bars = right.bar(
        labels,
        false_values,
        bottom=true_values,
        label="False positive",
        color="#dc2626",
    )
    right.set_ylabel("Predicted CVE memberships")
    right.set_title("Contribution of Inclusive Policy")
    right.grid(axis="y", alpha=0.25)
    right.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.10),
        ncol=2,
    )
    right.bar_label(bars, labels=[f"{value:,}" for value in true_values])
    right.bar_label(
        false_bars,
        labels=[f"+{value:,} FP" for value in false_values],
        label_type="center",
        color="white",
        fontsize=9,
    )
    for index, (tp, fp) in enumerate(
        zip(true_values, false_values)
    ):
        predicted = tp + fp
        precision = tp / predicted if predicted else 0.0
        right.text(
            index,
            predicted + max(1, int(0.01 * max(true_values + false_values))),
            f"Precision {precision:.3%}",
            ha="center",
            fontsize=9,
        )
    right.set_ylim(
        0,
        max(1, max(tp + fp for tp, fp in zip(true_values, false_values)))
        * 1.10,
    )
    figure.suptitle("v10 Evaluation Policy Comparison", fontsize=15)
    figure.tight_layout()
    figure.savefig(destination, dpi=180, bbox_inches="tight")
    plt.close(figure)


def plot_error_composition(
    destination: Path,
    errors: list[dict[str, str]],
) -> None:
    groups = [
        ("inclusive", "false_positive"),
        ("inclusive", "false_negative"),
        ("strict", "false_positive"),
        ("strict", "false_negative"),
    ]
    labels = ["Inclusive FP", "Inclusive FN", "Strict FP", "Strict FN"]
    counts = {}
    states: set[str] = set()
    for group in groups:
        counter = Counter(
            row["candidate_state"]
            for row in errors
            if row["policy"] == group[0]
            and row["error_type"] == group[1]
        )
        counts[group] = counter
        states.update(counter)
    state_order = [
        "affected",
        "potentially_affected",
        "candidate_missing",
        "not_affected_out_of_range",
        "conflict_review",
        "not_affected_asserted",
        "not_applicable",
        "product_only_observation",
    ]
    state_order = [state for state in state_order if state in states]
    figure, axis = plt.subplots(figsize=(12, 6.5))
    y = np.arange(len(groups))
    left = np.zeros(len(groups))
    totals = np.array([sum(counts[group].values()) for group in groups])
    for state in state_order:
        raw = np.array([counts[group][state] for group in groups])
        percentages = np.divide(
            raw,
            totals,
            out=np.zeros_like(raw, dtype=float),
            where=totals != 0,
        )
        axis.barh(
            y,
            percentages,
            left=left,
            label=state,
            color=STATE_COLORS.get(state, "#94a3b8"),
        )
        for index, (start, width, value) in enumerate(
            zip(left, percentages, raw)
        ):
            if width >= 0.075:
                axis.text(
                    start + width / 2,
                    index,
                    f"{value:,}\n{width:.1%}",
                    ha="center",
                    va="center",
                    color="white",
                    fontsize=8,
                )
        left += percentages
    axis.set_yticks(y, labels)
    axis.set_xlim(0, 1)
    axis.invert_yaxis()
    axis.set_xlabel("Share within each error group")
    axis.set_title("v10 Error-State Composition")
    axis.grid(axis="x", alpha=0.2)
    for index, total in enumerate(totals):
        axis.text(
            1.005,
            index,
            f"n={total:,}",
            va="center",
            fontsize=9,
        )
    axis.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.12),
        ncol=3,
        fontsize=8,
    )
    figure.tight_layout()
    figure.savefig(destination, dpi=180, bbox_inches="tight")
    plt.close(figure)


def plot_top_error_keys(
    destination: Path,
    rows: list[dict[str, Any]],
) -> None:
    selected = sorted(
        rows,
        key=lambda row: row["error_count"],
        reverse=True,
    )[:15]
    selected.reverse()
    labels = [
        f"{row['vendor']}/{row['product']} @ {row['version']}"
        for row in selected
    ]
    false_positive = [row["false_positive"] for row in selected]
    false_negative = [row["false_negative"] for row in selected]
    y = np.arange(len(selected))
    figure, axis = plt.subplots(figsize=(13, 8))
    axis.barh(
        y,
        false_positive,
        label="False positive",
        color="#dc2626",
    )
    axis.barh(
        y,
        false_negative,
        left=false_positive,
        label="False negative",
        color="#2563eb",
    )
    axis.set_yticks(y, labels)
    axis.set_xlabel("Inclusive error memberships")
    axis.set_title("Top 15 Inclusive Error Keys")
    axis.grid(axis="x", alpha=0.25)
    axis.legend()
    for index, row in enumerate(selected):
        axis.text(
            row["error_count"] + 1,
            index,
            f"{row['error_count']:,}",
            va="center",
            fontsize=8,
        )
    figure.tight_layout()
    figure.savefig(destination, dpi=180, bbox_inches="tight")
    plt.close(figure)


def plot_query_performance(
    destination: Path,
    cases: list[dict[str, Any]],
) -> None:
    candidate_counts = [
        int(case["candidate_count"]) for case in cases
    ]
    query_milliseconds = [
        float(case["query_seconds"]) * 1000 for case in cases
    ]
    correlation = pearson(candidate_counts, query_milliseconds)
    figure, axes = plt.subplots(1, 2, figsize=(14, 5.5))
    left = axes[0]
    left.scatter(
        candidate_counts,
        query_milliseconds,
        alpha=0.42,
        s=18,
        color="#2563eb",
        edgecolors="none",
    )
    left.set_xlabel("Candidate CVE count")
    left.set_ylabel("Query time (ms)")
    left.set_title(f"Candidate Count vs Query Time (r={correlation:.3f})")
    left.grid(alpha=0.22)

    right = axes[1]
    right.hist(
        query_milliseconds,
        bins=40,
        color="#0f766e",
        alpha=0.85,
    )
    p50 = percentile(query_milliseconds, 0.50)
    p95 = percentile(query_milliseconds, 0.95)
    p99 = percentile(query_milliseconds, 0.99)
    for value, label, color in (
        (p50, "P50", "#16a34a"),
        (p95, "P95", "#f59e0b"),
        (p99, "P99", "#dc2626"),
    ):
        right.axvline(value, color=color, linestyle="--", label=f"{label} {value:.1f} ms")
    right.set_xlabel("Query time (ms)")
    right.set_ylabel("Query keys")
    right.set_title("Query-Time Distribution")
    right.grid(axis="y", alpha=0.22)
    right.legend()
    figure.suptitle("v10 Query Performance", fontsize=15)
    figure.tight_layout()
    figure.savefig(destination, dpi=180, bbox_inches="tight")
    plt.close(figure)


def main() -> int:
    options = arguments()
    evaluation = load_json(options.evaluation)
    cases = load_jsonl(options.cases)
    errors = load_csv(options.errors)
    options.output_dir.mkdir(parents=True, exist_ok=True)

    rows_by_policy = {
        policy: policy_rows(cases, metric_key)
        for policy, metric_key in POLICIES.items()
    }
    error_state_counts: dict[str, dict[str, dict[str, int]]] = {}
    for policy in POLICIES:
        error_state_counts[policy] = {}
        for error_type in ("false_positive", "false_negative"):
            error_state_counts[policy][error_type] = dict(
                sorted(
                    Counter(
                        row["candidate_state"]
                        for row in errors
                        if row["policy"] == policy
                        and row["error_type"] == error_type
                    ).items()
                )
            )

    inclusive = evaluation["overall"]["inclusive"]
    strict = evaluation["overall"]["strict"]
    potential_count = (
        inclusive["predicted_positive"] - strict["predicted_positive"]
    )
    potential_true_positive = (
        inclusive["true_positive"] - strict["true_positive"]
    )
    potential_false_positive = (
        inclusive["false_positive"] - strict["false_positive"]
    )
    query_seconds = [
        float(case["query_seconds"]) for case in cases
    ]
    candidate_counts = [
        float(case["candidate_count"]) for case in cases
    ]
    resolution_statuses = Counter(
        str(case["query_status"]) for case in cases
    )
    resolved_product_counts = Counter(
        len(case["resolved_products"]) for case in cases
    )
    database_path = Path(str(evaluation["database"]))

    summary = {
        "evaluation": str(options.evaluation),
        "case_count": len(cases),
        "database": evaluation["database"],
        "database_metadata": evaluation["database_metadata"],
        "snapshot": evaluation["snapshot"],
        "overall": evaluation["overall"],
        "dataset": evaluation["dataset"],
        "potential_only": {
            "predicted_positive": potential_count,
            "true_positive": potential_true_positive,
            "false_positive": potential_false_positive,
            "precision": (
                potential_true_positive / potential_count
                if potential_count
                else 0.0
            ),
            "inclusive_prediction_share": (
                potential_count / inclusive["predicted_positive"]
                if inclusive["predicted_positive"]
                else 0.0
            ),
        },
        "error_state_counts": error_state_counts,
        "top_error_keys": {
            policy: sorted(
                rows,
                key=lambda row: row["error_count"],
                reverse=True,
            )[:15]
            for policy, rows in rows_by_policy.items()
        },
        "top_error_products": {
            policy: top_products(rows)
            for policy, rows in rows_by_policy.items()
        },
        "error_concentration": {
            policy: {
                "top_10_key_share": (
                    sum(
                        sorted(
                            (
                                row["error_count"]
                                for row in rows
                            ),
                            reverse=True,
                        )[:10]
                    )
                    / sum(row["error_count"] for row in rows)
                ),
                "top_25_key_share": (
                    sum(
                        sorted(
                            (
                                row["error_count"]
                                for row in rows
                            ),
                            reverse=True,
                        )[:25]
                    )
                    / sum(row["error_count"] for row in rows)
                ),
            }
            for policy, rows in rows_by_policy.items()
        },
        "query_performance": {
            "evaluation_seconds": evaluation["timing"][
                "evaluation_seconds"
            ],
            "mean_seconds": statistics.mean(query_seconds),
            "p50_seconds": percentile(query_seconds, 0.50),
            "p90_seconds": percentile(query_seconds, 0.90),
            "p95_seconds": percentile(query_seconds, 0.95),
            "p99_seconds": percentile(query_seconds, 0.99),
            "max_seconds": max(query_seconds),
            "candidate_count": {
                "min": min(candidate_counts),
                "median": percentile(candidate_counts, 0.50),
                "p95": percentile(candidate_counts, 0.95),
                "max": max(candidate_counts),
            },
            "candidate_count_correlation": pearson(
                candidate_counts,
                query_seconds,
            ),
            "slowest_keys": [
                {
                    "vendor": case["vendor"],
                    "product": case["product"],
                    "version": case["version"],
                    "candidate_count": case["candidate_count"],
                    "query_seconds": case["query_seconds"],
                }
                for case in sorted(
                    cases,
                    key=lambda item: item["query_seconds"],
                    reverse=True,
                )[:10]
            ],
        },
        "resolution": {
            "query_statuses": dict(sorted(resolution_statuses.items())),
            "resolved_product_counts": {
                str(key): value
                for key, value in sorted(
                    resolved_product_counts.items()
                )
            },
        },
        "b3_typo": b3_summary(database_path, cases),
        "previous_version_comparison": compare_previous(
            evaluation,
            options.previous_evaluation,
        ),
    }

    analysis_path = options.output_dir / "v10_analysis_summary.json"
    analysis_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    save_per_key_csv(
        options.output_dir / "v10_per_key_metrics.csv",
        rows_by_policy,
    )
    plot_metrics(
        options.output_dir / "v10_metrics_overview.png",
        evaluation,
    )
    plot_error_composition(
        options.output_dir / "v10_error_composition.png",
        errors,
    )
    plot_top_error_keys(
        options.output_dir / "v10_top_inclusive_error_keys.png",
        rows_by_policy["inclusive"],
    )
    plot_query_performance(
        options.output_dir / "v10_query_performance.png",
        cases,
    )
    print(
        json.dumps(
            {
                "output_dir": str(options.output_dir),
                "analysis_summary": str(analysis_path),
                "cases": len(cases),
                "inclusive_f1": inclusive["f1"],
                "strict_f1": strict["f1"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
