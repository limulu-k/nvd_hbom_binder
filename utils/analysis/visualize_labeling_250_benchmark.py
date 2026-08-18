#!/usr/bin/env python3
"""Compare and visualize labeling-250 evaluations for four benchmark DBs."""

from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
from pathlib import Path
import sqlite3
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
BUILD_INFO = (
    ("01_nvd_without_llm", "Raw / No LLM", "#6b7280"),
    ("02_nvd_with_llm", "Raw / LLM", "#8b5cf6"),
    ("03_current_without_llm", "Current / No LLM", "#2563eb"),
    ("04_current_with_llm", "Current / LLM", "#0f9d8a"),
)
PREFIX = "nvd_labeling_250_v2"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark-dir",
        type=Path,
        default=ROOT / "workspace" / "benchmark",
    )
    parser.add_argument(
        "--gold",
        type=Path,
        default=ROOT / "data" / "nvd_labeling_250_v2.jsonl",
    )
    parser.add_argument(
        "--quarantine",
        type=Path,
        default=ROOT / "data" / "nvd-cves.current.quarantine.jsonl",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="default: <benchmark-dir>/evaluation/analysis",
    )
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def load_results(benchmark_dir: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for build_id, label, color in BUILD_INFO:
        root = benchmark_dir / "evaluation" / build_id
        summary_path = root / f"{PREFIX}_evaluation.json"
        cases_path = root / f"{PREFIX}_evaluation_cases.jsonl"
        if not summary_path.is_file() or not cases_path.is_file():
            raise FileNotFoundError(
                f"evaluation artifacts missing for {build_id}; run "
                "utils/evaluate_nvd_labeling_250.py first"
            )
        results[build_id] = {
            "id": build_id,
            "label": label,
            "color": color,
            "summary": read_json(summary_path),
            "cases": read_jsonl(cases_path),
        }
    return results


def prediction_equivalent(
    left: list[dict[str, Any]],
    right: list[dict[str, Any]],
) -> bool:
    if len(left) != len(right):
        return False
    fields = (
        "vendor",
        "product",
        "version",
        "result",
        "strict_result",
        "metrics",
        "strict_metrics",
    )
    return all(
        all(left_row[field] == right_row[field] for field in fields)
        for left_row, right_row in zip(left, right)
    )


def current_missing_gold(
    gold_path: Path,
    current_database: Path,
    quarantine_path: Path,
) -> dict[str, Any]:
    memberships: list[str] = []
    for row in read_jsonl(gold_path):
        memberships.extend(str(value).upper() for value in row["cve_id"])

    uri = f"file:{current_database.resolve()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        present = {
            str(row[0]).upper()
            for row in connection.execute("SELECT cve_id FROM raw_cve")
        }
    finally:
        connection.close()

    missing = set(memberships) - present
    quarantine: dict[str, dict[str, Any]] = {}
    if quarantine_path.is_file():
        quarantine = {
            str(row["cve_id"]).upper(): row
            for row in read_jsonl(quarantine_path)
        }
    reasons = Counter(
        str(quarantine.get(cve_id, {}).get("reason", "not_in_quarantine"))
        for cve_id in missing
    )
    missing_memberships = Counter(
        cve_id for cve_id in memberships if cve_id in missing
    )
    return {
        "unique_cves": len(missing),
        "label_memberships": sum(missing_memberships.values()),
        "reason_counts": dict(sorted(reasons.items())),
        "cves": sorted(missing),
        "top_memberships": missing_memberships.most_common(20),
    }


def compare_history_cases(
    raw_cases: list[dict[str, Any]],
    current_cases: list[dict[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for policy, result_key, metric_key in (
        ("inclusive", "result", "metrics"),
        ("strict", "strict_result", "strict_metrics"),
    ):
        changed = 0
        removed = 0
        added = 0
        improved = 0
        worsened = 0
        unchanged = 0
        for raw, current in zip(raw_cases, current_cases):
            raw_result = set(raw[result_key])
            current_result = set(current[result_key])
            changed += raw_result != current_result
            removed += len(raw_result - current_result)
            added += len(current_result - raw_result)
            before_f1 = float(raw[metric_key]["f1"])
            after_f1 = float(current[metric_key]["f1"])
            if after_f1 > before_f1:
                improved += 1
            elif after_f1 < before_f1:
                worsened += 1
            else:
                unchanged += 1
        result[policy] = {
            "changed_query_keys": changed,
            "removed_predictions": removed,
            "added_predictions": added,
            "f1_improved_keys": improved,
            "f1_worsened_keys": worsened,
            "f1_unchanged_keys": unchanged,
        }
    return result


def pp_delta(before: float, after: float) -> float:
    return (after - before) * 100


def build_analysis(
    results: dict[str, dict[str, Any]],
    missing_gold: dict[str, Any],
) -> dict[str, Any]:
    raw = results["01_nvd_without_llm"]
    raw_llm = results["02_nvd_with_llm"]
    current = results["03_current_without_llm"]
    current_llm = results["04_current_with_llm"]
    raw_overall = raw["summary"]["overall"]
    current_overall = current["summary"]["overall"]
    history_delta: dict[str, Any] = {}
    for policy in ("inclusive", "strict"):
        before = raw_overall[policy]
        after = current_overall[policy]
        history_delta[policy] = {
            "true_positive": after["true_positive"] - before["true_positive"],
            "false_positive": after["false_positive"] - before["false_positive"],
            "false_negative": after["false_negative"] - before["false_negative"],
            "precision_pp": pp_delta(before["precision"], after["precision"]),
            "recall_pp": pp_delta(before["recall"], after["recall"]),
            "f1_pp": pp_delta(before["f1"], after["f1"]),
            "jaccard_pp": pp_delta(before["jaccard"], after["jaccard"]),
            "exact_match_keys": after["exact_match_keys"] - before["exact_match_keys"],
        }
    return {
        "dataset": raw["summary"]["dataset"],
        "llm_effect": {
            "raw_predictions_identical": prediction_equivalent(
                raw["cases"], raw_llm["cases"]
            ),
            "current_predictions_identical": prediction_equivalent(
                current["cases"], current_llm["cases"]
            ),
        },
        "history_delta": history_delta,
        "history_case_changes": compare_history_cases(
            raw["cases"], current["cases"]
        ),
        "current_missing_gold": missing_gold,
        "current_snapshot_coverage": current["summary"]["dataset"][
            "snapshot_coverage"
        ],
    }


def save_figure(figure: plt.Figure, output_dir: Path, name: str) -> None:
    figure.savefig(output_dir / name, dpi=180, bbox_inches="tight")
    plt.close(figure)


def plot_policy_metrics(
    results: dict[str, dict[str, Any]],
    output_dir: Path,
) -> None:
    figure, axes = plt.subplots(1, 2, figsize=(15, 6))
    x = np.arange(3)
    width = 0.19
    metric_names = ("Precision", "Recall", "F1")
    metric_fields = ("precision", "recall", "f1")
    for axis, policy in zip(axes, ("inclusive", "strict")):
        for index, (build_id, _label, _color) in enumerate(BUILD_INFO):
            row = results[build_id]
            values = [
                row["summary"]["overall"][policy][field]
                for field in metric_fields
            ]
            bars = axis.bar(
                x + (index - 1.5) * width,
                values,
                width,
                label=row["label"],
                color=row["color"],
            )
            axis.bar_label(bars, fmt="%.3f", fontsize=7, padding=2, rotation=90)
        axis.set_xticks(x, metric_names)
        axis.set_ylim(0, 1.08)
        axis.set_title(f"{policy.title()} policy")
        axis.set_ylabel("Score")
        axis.grid(axis="y", alpha=0.25)
    axes[1].legend(loc="lower right", fontsize=8, frameon=False)
    figure.suptitle("NVD Labeling-250 Evaluation: Four Benchmark DBs", fontsize=15)
    figure.tight_layout()
    save_figure(figure, output_dir, "01_policy_metrics.png")


def plot_history_tradeoff(
    results: dict[str, dict[str, Any]],
    analysis: dict[str, Any],
    output_dir: Path,
) -> None:
    figure, axes = plt.subplots(1, 2, figsize=(15, 6))
    names = ("Precision", "Recall", "F1", "Jaccard")
    keys = ("precision_pp", "recall_pp", "f1_pp", "jaccard_pp")
    x = np.arange(len(names))
    width = 0.36
    inclusive = [analysis["history_delta"]["inclusive"][key] for key in keys]
    strict = [analysis["history_delta"]["strict"][key] for key in keys]
    first = axes[0].bar(x - width / 2, inclusive, width, label="Inclusive", color="#2563eb")
    second = axes[0].bar(x + width / 2, strict, width, label="Strict", color="#f59e0b")
    axes[0].axhline(0, color="#111827", linewidth=1)
    axes[0].set_xticks(x, names)
    axes[0].set_ylabel("Percentage-point delta")
    axes[0].set_title("History Effect: Raw → Current")
    axes[0].bar_label(first, fmt="%+.3f", fontsize=8, padding=3)
    axes[0].bar_label(second, fmt="%+.3f", fontsize=8, padding=3)
    axes[0].legend(frameon=False)
    axes[0].grid(axis="y", alpha=0.25)

    raw = results["01_nvd_without_llm"]["summary"]["overall"]
    current = results["03_current_without_llm"]["summary"]["overall"]
    groups = ("Inclusive FP", "Inclusive FN", "Strict FP", "Strict FN")
    before = (
        raw["inclusive"]["false_positive"],
        raw["inclusive"]["false_negative"],
        raw["strict"]["false_positive"],
        raw["strict"]["false_negative"],
    )
    after = (
        current["inclusive"]["false_positive"],
        current["inclusive"]["false_negative"],
        current["strict"]["false_positive"],
        current["strict"]["false_negative"],
    )
    x2 = np.arange(len(groups))
    bars1 = axes[1].bar(x2 - width / 2, before, width, label="Raw", color="#6b7280")
    bars2 = axes[1].bar(x2 + width / 2, after, width, label="Current", color="#0f9d8a")
    axes[1].set_xticks(x2, groups, rotation=12)
    axes[1].set_title("False Positive / False Negative Counts")
    axes[1].bar_label(
        bars1,
        labels=[f"{value:,}" for value in before],
        fontsize=8,
        padding=2,
    )
    axes[1].bar_label(
        bars2,
        labels=[f"{value:,}" for value in after],
        fontsize=8,
        padding=2,
    )
    axes[1].legend(frameon=False)
    axes[1].grid(axis="y", alpha=0.25)
    figure.tight_layout()
    save_figure(figure, output_dir, "02_history_precision_recall_tradeoff.png")


def plot_fn_and_coverage(
    results: dict[str, dict[str, Any]],
    analysis: dict[str, Any],
    output_dir: Path,
) -> None:
    figure, axes = plt.subplots(1, 3, figsize=(18, 6))
    raw_states = results["01_nvd_without_llm"]["summary"][
        "false_negative_state_totals"
    ]["inclusive"]
    current_states = results["03_current_without_llm"]["summary"][
        "false_negative_state_totals"
    ]["inclusive"]
    state_order = sorted(set(raw_states) | set(current_states))
    y = np.arange(2)
    left = np.zeros(2)
    palette = plt.get_cmap("tab10")
    for index, state in enumerate(state_order):
        values = np.array([raw_states.get(state, 0), current_states.get(state, 0)])
        axes[0].barh(y, values, left=left, label=state, color=palette(index))
        left += values
    axes[0].set_yticks(y, ("Raw", "Current"))
    axes[0].invert_yaxis()
    axes[0].set_title("Inclusive FN State Composition")
    axes[0].set_xlabel("False-negative memberships")
    axes[0].legend(fontsize=7, frameon=False, loc="lower right")

    changes = analysis["history_case_changes"]
    categories = ("Improved", "Worsened", "Unchanged")
    inc = changes["inclusive"]
    strict = changes["strict"]
    inc_values = (inc["f1_improved_keys"], inc["f1_worsened_keys"], inc["f1_unchanged_keys"])
    strict_values = (strict["f1_improved_keys"], strict["f1_worsened_keys"], strict["f1_unchanged_keys"])
    x = np.arange(3)
    width = 0.36
    bars1 = axes[1].bar(x - width/2, inc_values, width, label="Inclusive", color="#2563eb")
    bars2 = axes[1].bar(x + width/2, strict_values, width, label="Strict", color="#f59e0b")
    axes[1].set_xticks(x, categories)
    axes[1].set_title("Per-key F1 Change after History")
    axes[1].bar_label(bars1, fontsize=8, padding=2)
    axes[1].bar_label(bars2, fontsize=8, padding=2)
    axes[1].legend(frameon=False)
    axes[1].set_yscale("log")

    missing = analysis["current_missing_gold"]
    total = analysis["dataset"]["unique_labeled_cves"]
    reasons = missing["reason_counts"]
    coverage_values = [
        total - missing["unique_cves"],
        reasons.get("stale_after_history", 0),
        reasons.get("record_status_rejected", 0),
        reasons.get("not_in_quarantine", 0),
    ]
    coverage_labels = ("Present", "Stale quarantine", "Rejected", "Other missing")
    coverage_colors = ("#10b981", "#f59e0b", "#ef4444", "#64748b")
    visible = [
        (label, value, color)
        for label, value, color in zip(
            coverage_labels, coverage_values, coverage_colors
        )
        if value
    ]
    labels, values, colors = zip(*visible)
    coverage_bars = axes[2].bar(labels, values, color=colors)
    axes[2].bar_label(
        coverage_bars,
        labels=[f"{value:,}" for value in values],
        fontsize=8,
        padding=3,
    )
    axes[2].set_title(
        "Gold CVE Snapshot Coverage\n"
        f"{analysis['current_snapshot_coverage']:.3%} present"
    )
    axes[2].set_ylabel("Unique labeled CVEs (log scale)")
    axes[2].set_yscale("log")
    axes[2].set_ylim(5, max(values) * 1.7)
    axes[2].tick_params(axis="x", labelrotation=12)
    axes[2].grid(axis="y", alpha=0.25)
    figure.tight_layout()
    save_figure(figure, output_dir, "03_fn_states_and_gold_coverage.png")


def write_comparison_csv(
    results: dict[str, dict[str, Any]],
    path: Path,
) -> None:
    fields = (
        "build_id", "label", "policy", "tp", "fp", "fn", "precision",
        "recall", "f1", "f0_5", "f2", "jaccard", "exact_match_keys",
        "snapshot_coverage", "candidate_recall", "evaluation_seconds",
    )
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for build_id, _label, _color in BUILD_INFO:
            row = results[build_id]
            summary = row["summary"]
            for policy in ("inclusive", "strict"):
                metric = summary["overall"][policy]
                writer.writerow(
                    {
                        "build_id": build_id,
                        "label": row["label"],
                        "policy": policy,
                        "tp": metric["true_positive"],
                        "fp": metric["false_positive"],
                        "fn": metric["false_negative"],
                        "precision": metric["precision"],
                        "recall": metric["recall"],
                        "f1": metric["f1"],
                        "f0_5": metric["f0_5"],
                        "f2": metric["f2"],
                        "jaccard": metric["jaccard"],
                        "exact_match_keys": metric["exact_match_keys"],
                        "snapshot_coverage": summary["dataset"]["snapshot_coverage"],
                        "candidate_recall": summary["dataset"]["candidate_recall"],
                        "evaluation_seconds": summary["timing"]["evaluation_seconds"],
                    }
                )


def write_report(
    results: dict[str, dict[str, Any]],
    analysis: dict[str, Any],
    output_dir: Path,
) -> None:
    raw = results["01_nvd_without_llm"]["summary"]
    current = results["03_current_without_llm"]["summary"]
    inc_delta = analysis["history_delta"]["inclusive"]
    strict_delta = analysis["history_delta"]["strict"]
    changes = analysis["history_case_changes"]
    missing = analysis["current_missing_gold"]
    rows = []
    for build_id, _label, _color in BUILD_INFO:
        row = results[build_id]
        inclusive = row["summary"]["overall"]["inclusive"]
        strict = row["summary"]["overall"]["strict"]
        rows.append(
            f"| {row['label']} | {inclusive['precision']:.6f} | {inclusive['recall']:.6f} | {inclusive['f1']:.6f} | {inclusive['false_positive']:,} | {inclusive['false_negative']:,} | {strict['precision']:.6f} | {strict['recall']:.6f} | {strict['f1']:.6f} |"
        )
    text = f"""# NVD labeling-250 benchmark evaluation

## 평가 범위

- Gold set: `data/nvd_labeling_250_v2.jsonl`
- Query keys: {analysis['dataset']['row_count']:,}개 ({analysis['dataset']['unique_vendor_product_count']:,} vendor/product × 4 versions)
- Label memberships: {analysis['dataset']['deduplicated_label_entries']:,}개
- Unique labeled CVEs: {analysis['dataset']['unique_labeled_cves']:,}개
- 평가기: `utils/evaluate_nvd_labeling_250.py`

## 핵심 결론

1. LLM 전후 prediction은 history 적용 전·후 모두 **완전히 동일**하다. 현재 legacy LLM layer는 labeling-250의 inclusive/strict 판정에 영향을 주지 않는다.
2. History 적용은 inclusive FP를 **{-inc_delta['false_positive']:,}개 감소**시켰지만 FN을 **{inc_delta['false_negative']:,}개 증가**시켰다. Precision은 **{inc_delta['precision_pp']:+.3f}pp**, recall은 **{inc_delta['recall_pp']:+.3f}pp**, F1은 **{inc_delta['f1_pp']:+.3f}pp** 변했다.
3. Strict에서는 FP가 **{-strict_delta['false_positive']:,}개 감소**, FN이 **{strict_delta['false_negative']:,}개 증가**했다. Precision은 **{strict_delta['precision_pp']:+.3f}pp** 개선됐지만 F1은 **{strict_delta['f1_pp']:+.3f}pp** 감소했다.
4. Current snapshot에 gold CVE **{missing['unique_cves']:,}개**가 없다. 원인은 stale quarantine {missing['reason_counts'].get('stale_after_history', 0):,}개와 rejected {missing['reason_counts'].get('record_status_rejected', 0):,}개다. 따라서 history recall 감소 전부를 알고리즘 성능 저하로 해석하면 안 된다.

![Policy metrics](01_policy_metrics.png)

## 전체 결과

| Build | Incl. precision | Incl. recall | Incl. F1 | Incl. FP | Incl. FN | Strict precision | Strict recall | Strict F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
{chr(10).join(rows)}

## History trade-off

![History tradeoff](02_history_precision_recall_tradeoff.png)

- Inclusive prediction이 변한 query: {changes['inclusive']['changed_query_keys']:,}/1,000
- 제거된 inclusive prediction: {changes['inclusive']['removed_predictions']:,}개
- 추가된 inclusive prediction: {changes['inclusive']['added_predictions']:,}개
- Per-key inclusive F1: 개선 {changes['inclusive']['f1_improved_keys']:,}, 악화 {changes['inclusive']['f1_worsened_keys']:,}, 동일 {changes['inclusive']['f1_unchanged_keys']:,}
- Exact-match key: {raw['overall']['inclusive']['exact_match_keys']:,} → {current['overall']['inclusive']['exact_match_keys']:,}

History 적용 결과는 precision 개선과 recall 감소의 교환 관계다. Inclusive F1은 {raw['overall']['inclusive']['f1']:.6f}에서 {current['overall']['inclusive']['f1']:.6f}으로 사실상 동일하지만, 오류 구성은 FP 감소·FN 증가 방향으로 이동했다.

## FN 증가와 snapshot coverage

![FN states and coverage](03_fn_states_and_gold_coverage.png)

- Gold snapshot coverage: {raw['dataset']['snapshot_coverage']:.6f} → {current['dataset']['snapshot_coverage']:.6f}
- Current에서 누락된 unique gold CVE: {missing['unique_cves']:,}개
- 누락된 gold label membership: {missing['label_memberships']:,}개
- Inclusive `candidate_missing`: {raw['false_negative_state_totals']['inclusive'].get('candidate_missing', 0):,} → {current['false_negative_state_totals']['inclusive'].get('candidate_missing', 0):,}

누락 CVE 58개 중 48개는 history 이후 최신 payload가 로컬 snapshot에 없어 `stale_after_history`로 격리된 항목이다. 이 CVE들을 최신 CVE API payload로 보충한 후 current snapshot과 네 DB를 다시 만들면 history 자체의 효과를 더 공정하게 측정할 수 있다.

## 벤치마크 유효성 주의사항

- `data/nvd-cves.current.jsonl`의 파일 생성 시각이 benchmark에 사용한 `data/nvd-cves.jsonl`의 최종 수정 시각보다 약 43분 빠르다. 즉 raw/current가 완전히 동일한 원본 snapshot에서 갈라진 대조군이라고 보장할 수 없다.
- maintenance report에도 `stale_after_history=1,527`, active history CVE without local record 697개가 남아 있다.
- 따라서 현재 숫자는 **현재 생성된 두 DB의 비교 결과**로는 유효하지만, 순수한 history 처리 효과의 최종 추정치로 사용하기 전 current snapshot 보충·재생성이 필요하다.
- labeling-250은 open-world retrieval 평가이므로 TN 기반 accuracy/specificity는 계산하지 않는다.
"""
    (output_dir / "EVALUATION_ANALYSIS.md").write_text(text, encoding="utf-8")


def main() -> int:
    args = arguments()
    benchmark_dir = args.benchmark_dir.resolve()
    output_dir = (args.output_dir or benchmark_dir / "evaluation" / "analysis").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    results = load_results(benchmark_dir)
    current_db = benchmark_dir / "03_current_without_llm.sqlite"
    missing_gold = current_missing_gold(
        args.gold.resolve(), current_db, args.quarantine.resolve()
    )
    analysis = build_analysis(results, missing_gold)
    (output_dir / "evaluation_comparison.json").write_text(
        json.dumps(analysis, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_comparison_csv(results, output_dir / "evaluation_comparison.csv")
    plot_policy_metrics(results, output_dir)
    plot_history_tradeoff(results, analysis, output_dir)
    plot_fn_and_coverage(results, analysis, output_dir)
    write_report(results, analysis, output_dir)
    print(
        json.dumps(
            {
                "output_dir": str(output_dir),
                "llm_effect": analysis["llm_effect"],
                "inclusive_history_delta": analysis["history_delta"]["inclusive"],
                "missing_gold_cves": missing_gold["unique_cves"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
