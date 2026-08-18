#!/usr/bin/env python3
"""Build and evaluate deterministic string variants from TP benchmark cases.

The generated JSONL groups all variants under their original benchmark query so
the (potentially large) expected CVE sets are not repeated for every mutation.
Evaluation uses the same ``QueryEngine`` that backs ``query_nvd_cves.py`` and
compares each mutated query with a freshly executed, unmodified baseline.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.nvd_normalization.query_engine import (  # noqa: E402
    ApplicabilityQuery,
    QueryEngine,
)
from scripts.nvd_normalization.rules import normalize_key  # noqa: E402


DEFAULT_SOURCE = (
    ROOT / "workspace/v10/nvd_labeling_250_v2_evaluation_cases.jsonl"
)
DEFAULT_DB = ROOT / "workspace/nvd_applicability_v10.sqlite"
DEFAULT_DATASET = ROOT / "data/nvd_labeling_250_v2_tp_string_variants.jsonl"
DEFAULT_RESULTS = (
    ROOT / "workspace/v10/nvd_labeling_250_v2_tp_string_variant_results.jsonl"
)
DEFAULT_SUMMARY = (
    ROOT / "workspace/v10/nvd_labeling_250_v2_tp_string_variant_summary.json"
)

INCLUSIVE_STATES = {
    "affected",
    "potentially_affected",
    "conflict_review",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument(
        "--generate-only",
        action="store_true",
        help="write the dataset without executing the query comparison",
    )
    parser.add_argument("--progress-every", type=int, default=1_000)
    parser.add_argument(
        "--workers",
        type=int,
        default=min(8, os.cpu_count() or 1),
        help="read-only query worker processes (default: up to 8)",
    )
    return parser.parse_args()


def _middle_index(indices: Iterable[int], length: int) -> int | None:
    values = list(indices)
    if not values:
        return None
    midpoint = (length - 1) / 2
    return min(values, key=lambda index: (abs(index - midpoint), index))


def _alpha_index(value: str) -> int | None:
    return _middle_index(
        (index for index, character in enumerate(value) if character.isalpha()),
        len(value),
    )


def _case_variant(value: str) -> str | None:
    candidate = value.upper()
    return candidate if candidate != value else None


def _separator_removed(value: str) -> str | None:
    candidate = re.sub(r"[_\s-]+", "", value)
    return candidate if candidate != value else None


def _char_delete(value: str) -> str | None:
    if sum(character.isalnum() for character in value) < 4:
        return None
    index = _alpha_index(value)
    if index is None:
        return None
    return value[:index] + value[index + 1 :]


def _char_insert(value: str) -> str | None:
    index = _alpha_index(value)
    if index is None:
        return None
    return value[: index + 1] + value[index] + value[index + 1 :]


def _char_substitute(value: str) -> str | None:
    index = _alpha_index(value)
    if index is None:
        return None
    original = value[index]
    replacement = "x" if original.casefold() != "x" else "q"
    if original.isupper():
        replacement = replacement.upper()
    return value[:index] + replacement + value[index + 1 :]


def _adjacent_transpose(value: str) -> str | None:
    index = _middle_index(
        (
            index
            for index in range(len(value) - 1)
            if value[index].isalnum()
            and value[index + 1].isalnum()
            and value[index] != value[index + 1]
        ),
        len(value),
    )
    if index is None:
        return None
    return (
        value[:index]
        + value[index + 1]
        + value[index]
        + value[index + 2 :]
    )


def _tokens(value: str) -> list[str]:
    return [token for token in re.split(r"[_\s-]+", value.strip()) if token]


def _token_swap(value: str) -> str | None:
    tokens = _tokens(value)
    if len(tokens) < 2 or tokens[0] == tokens[1]:
        return None
    tokens[0], tokens[1] = tokens[1], tokens[0]
    return "_".join(tokens)


def _token_acronym(value: str) -> str | None:
    tokens = _tokens(value)
    if len(tokens) < 2:
        return None
    candidate = "".join(token[0] for token in tokens if token)
    return candidate if len(candidate) >= 2 else None


MUTATORS = {
    "case_upper": _case_variant,
    "separator_removed": _separator_removed,
    "char_delete": _char_delete,
    "char_insert": _char_insert,
    "char_substitute": _char_substitute,
    "adjacent_transpose": _adjacent_transpose,
    "token_swap": _token_swap,
    "token_acronym": _token_acronym,
}


def variants_for(value: str) -> dict[str, str]:
    original_key = normalize_key(value)
    output: dict[str, str] = {}
    seen: set[str] = set()
    for kind, mutator in MUTATORS.items():
        candidate = mutator(value)
        if candidate is None or candidate == value or candidate in seen:
            continue
        # Case changes are deliberately allowed to retain the same normalized
        # key. Every other mutation must change identity input after normalize.
        if kind != "case_upper" and normalize_key(candidate) == original_key:
            continue
        seen.add(candidate)
        output[kind] = candidate
    return output


def build_variants(vendor: str, product: str) -> list[dict[str, Any]]:
    vendor_variants = variants_for(vendor)
    product_variants = variants_for(product)
    variants: list[dict[str, Any]] = []
    for kind, candidate in vendor_variants.items():
        variants.append(
            {
                "variant_id": f"vendor_only:{kind}",
                "scope": "vendor_only",
                "mutation_kind": kind,
                "vendor": candidate,
                "product": product,
            }
        )
    for kind, candidate in product_variants.items():
        variants.append(
            {
                "variant_id": f"product_only:{kind}",
                "scope": "product_only",
                "mutation_kind": kind,
                "vendor": vendor,
                "product": candidate,
            }
        )
    for kind in MUTATORS:
        if kind not in vendor_variants or kind not in product_variants:
            continue
        variants.append(
            {
                "variant_id": f"both:{kind}",
                "scope": "both",
                "mutation_kind": kind,
                "vendor": vendor_variants[kind],
                "product": product_variants[kind],
            }
        )
    return variants


def digest(values: Iterable[str]) -> str:
    payload = "\n".join(sorted(values)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_tp_cases(path: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for source_index, line in enumerate(handle, 1):
            row = json.loads(line)
            true_positives = sorted(set(row.get("true_positives", [])))
            if not true_positives:
                continue
            original_result = sorted(set(row["result"]))
            resolved_product_ids = sorted(
                int(product["product_id"])
                for product in row.get("resolved_products", [])
            )
            variants = build_variants(str(row["vendor"]), str(row["product"]))
            cases.append(
                {
                    "case_id": f"tp-{source_index:04d}",
                    "source_case_index": source_index,
                    "original_query": {
                        "vendor": str(row["vendor"]),
                        "product": str(row["product"]),
                        "version": str(row["version"]),
                    },
                    "expected": {
                        "query_status": str(row["query_status"]),
                        "true_positives": true_positives,
                        "inclusive_result": original_result,
                        "inclusive_result_sha256": digest(original_result),
                        "resolved_product_ids": resolved_product_ids,
                    },
                    "variants": variants,
                }
            )
    return cases


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def query_payload(
    engine: QueryEngine,
    query: Mapping[str, str],
) -> tuple[Mapping[str, Any], set[str]]:
    payload = engine.query(
        ApplicabilityQuery(
            vendor=query["vendor"],
            product=query["product"],
            version=query["version"],
        ),
        prediction_policy="inclusive",
        include_trace=False,
    )
    result = {
        str(row["cve_id"]).upper()
        for row in payload["results"]
        if str(row["state"]) in INCLUSIVE_STATES
    }
    return payload, result


def _counter() -> defaultdict[str, int]:
    return defaultdict(int)


def record_metric(counter: defaultdict[str, int], result: Mapping[str, Any]) -> None:
    counter["total"] += 1
    for field in (
        "resolved",
        "tp_preserved",
        "exact_result_match",
        "resolved_products_match",
    ):
        counter[field] += int(bool(result[field]))


def with_rates(values: Mapping[str, int]) -> dict[str, int | float]:
    total = int(values.get("total", 0))
    output: dict[str, int | float] = dict(values)
    for field in (
        "resolved",
        "tp_preserved",
        "exact_result_match",
        "resolved_products_match",
    ):
        output[f"{field}_rate"] = (
            int(values.get(field, 0)) / total if total else 0.0
        )
    return output


def evaluate_case(
    engine: QueryEngine,
    case: Mapping[str, Any],
) -> tuple[dict[str, bool], list[dict[str, Any]]]:
    expected = case["expected"]
    expected_tp = set(expected["true_positives"])
    stored_result = set(expected["inclusive_result"])
    stored_products = set(expected["resolved_product_ids"])
    baseline_payload, live_result = query_payload(engine, case["original_query"])
    live_products = {
        int(product["product_id"])
        for product in baseline_payload["resolved_products"]
    }
    baseline_result = {
        "source_result_match": live_result == stored_result,
        "source_tp_preserved": expected_tp <= live_result,
        "source_products_match": live_products == stored_products,
    }
    result_rows: list[dict[str, Any]] = []
    for variant in case["variants"]:
        query = {
            "vendor": variant["vendor"],
            "product": variant["product"],
            "version": case["original_query"]["version"],
        }
        payload, actual_result = query_payload(engine, query)
        actual_products = {
            int(product["product_id"])
            for product in payload["resolved_products"]
        }
        missing_tp = sorted(expected_tp - actual_result)
        result_rows.append(
            {
                "case_id": case["case_id"],
                "source_case_index": case["source_case_index"],
                "variant_id": variant["variant_id"],
                "scope": variant["scope"],
                "mutation_kind": variant["mutation_kind"],
                "original_query": case["original_query"],
                "mutated_query": query,
                "resolution_state": payload["resolution"]["state"],
                "resolution_reason": payload["resolution"]["reason"],
                "expected_tp_count": len(expected_tp),
                "actual_inclusive_count": len(actual_result),
                "missing_tp_count": len(missing_tp),
                "missing_tp_examples": missing_tp[:20],
                "expected_result_sha256": digest(live_result),
                "actual_result_sha256": digest(actual_result),
                "expected_resolved_product_ids": sorted(live_products),
                "actual_resolved_product_ids": sorted(actual_products),
                "resolved": payload["resolution"]["state"] == "resolved",
                "tp_preserved": not missing_tp,
                "exact_result_match": actual_result == live_result,
                "resolved_products_match": actual_products == live_products,
            }
        )
    return baseline_result, result_rows


_WORKER_ENGINE: QueryEngine | None = None


def init_worker(database: str) -> None:
    global _WORKER_ENGINE
    _WORKER_ENGINE = QueryEngine(database)


def evaluate_case_worker(
    case: Mapping[str, Any],
) -> tuple[dict[str, bool], list[dict[str, Any]]]:
    if _WORKER_ENGINE is None:
        raise RuntimeError("query worker was not initialized")
    return evaluate_case(_WORKER_ENGINE, case)


def evaluate(
    *,
    cases: list[dict[str, Any]],
    database: Path,
    results_path: Path,
    progress_every: int,
    workers: int,
) -> dict[str, Any]:
    overall = _counter()
    baseline = _counter()
    by_scope: dict[str, defaultdict[str, int]] = defaultdict(_counter)
    by_kind: dict[str, defaultdict[str, int]] = defaultdict(_counter)
    by_scope_kind: dict[str, defaultdict[str, int]] = defaultdict(_counter)
    expected_variants = sum(len(case["variants"]) for case in cases)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    completed = 0
    next_progress = progress_every

    if workers <= 1:
        engine = QueryEngine(database)

        def sequential_results() -> Iterable[
            tuple[dict[str, bool], list[dict[str, Any]]]
        ]:
            try:
                for case in cases:
                    yield evaluate_case(engine, case)
            finally:
                engine.close()

        executor = None
        case_results = sequential_results()
    else:
        executor = ProcessPoolExecutor(
            max_workers=workers,
            initializer=init_worker,
            initargs=(str(database),),
        )
        case_results = executor.map(evaluate_case_worker, cases, chunksize=1)

    try:
        with results_path.open("w", encoding="utf-8") as output:
            for baseline_result, result_rows in case_results:
                baseline["total"] += 1
                for key, value in baseline_result.items():
                    baseline[key] += int(value)

                for result_row in result_rows:
                    output.write(
                        json.dumps(
                            result_row, ensure_ascii=False, sort_keys=True
                        )
                        + "\n"
                    )
                    record_metric(overall, result_row)
                    scope = str(result_row["scope"])
                    kind = str(result_row["mutation_kind"])
                    record_metric(by_scope[scope], result_row)
                    record_metric(by_kind[kind], result_row)
                    record_metric(by_scope_kind[f"{scope}:{kind}"], result_row)
                    completed += 1
                if progress_every and completed >= next_progress:
                    print(
                        json.dumps(
                            {
                                "event": "variant_evaluation_progress",
                                "completed": completed,
                                "total": expected_variants,
                                "elapsed_seconds": round(
                                    time.monotonic() - started, 3
                                ),
                            },
                            sort_keys=True,
                        ),
                        file=sys.stderr,
                        flush=True,
                    )
                    while next_progress <= completed:
                        next_progress += progress_every
    finally:
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)

    return {
        "dataset_version": "tp-string-variants-v1",
        "source_case_count": len(cases),
        "variant_count": expected_variants,
        "database": str(database.resolve()),
        "results": str(results_path.resolve()),
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "workers": workers,
        "baseline_reproduction": dict(baseline),
        "overall": with_rates(overall),
        "by_scope": {
            key: with_rates(value) for key, value in sorted(by_scope.items())
        },
        "by_mutation_kind": {
            key: with_rates(value) for key, value in sorted(by_kind.items())
        },
        "by_scope_and_mutation_kind": {
            key: with_rates(value)
            for key, value in sorted(by_scope_kind.items())
        },
    }


def main() -> int:
    options = parse_args()
    cases = load_tp_cases(options.source)
    write_jsonl(options.dataset, cases)
    variant_count = sum(len(case["variants"]) for case in cases)
    dataset_summary = {
        "event": "dataset_written",
        "dataset": str(options.dataset.resolve()),
        "source": str(options.source.resolve()),
        "case_count": len(cases),
        "variant_count": variant_count,
        "true_positive_memberships": sum(
            len(case["expected"]["true_positives"]) for case in cases
        ),
    }
    print(json.dumps(dataset_summary, ensure_ascii=False, sort_keys=True))
    if options.generate_only:
        return 0
    summary = evaluate(
        cases=cases,
        database=options.db,
        results_path=options.results,
        progress_every=max(0, options.progress_every),
        workers=max(1, options.workers),
    )
    summary.update(
        {
            "source": str(options.source.resolve()),
            "dataset": str(options.dataset.resolve()),
        }
    )
    options.summary.parent.mkdir(parents=True, exist_ok=True)
    options.summary.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
