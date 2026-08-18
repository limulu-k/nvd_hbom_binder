#!/usr/bin/env python3
"""Explain labeling-250 benchmark changes at query/CVE membership granularity.

The evaluator reports aggregate retrieval metrics.  This program joins those
artifacts back to query traces, LLM claims, the maintenance quarantine, the
current/previous databases, and (when available) the previous gold revision.
It writes auditable intermediate CSV/JSON files plus a concise Markdown report
under ``workspace/benchmark/analysis``.

No benchmark database or source dataset is modified.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import re
import sqlite3
import sys
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.nvd_normalization.query_engine import (  # noqa: E402
    ApplicabilityQuery,
    QueryEngine,
)


BUILDS = (
    "01_nvd_without_llm",
    "02_nvd_with_llm",
    "03_current_without_llm",
    "04_current_with_llm",
)
PREFIX = "nvd_labeling_250_v2"
KEY_FIELDS = ("vendor", "product", "version")
NUMERIC_MAJOR = re.compile(r"^\s*[vV]?([0-9]+)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark-dir",
        type=Path,
        default=ROOT / "workspace" / "benchmark",
    )
    parser.add_argument(
        "--previous-benchmark-dir",
        type=Path,
        default=ROOT / "workspace" / "prev" / "benchmark copy",
    )
    parser.add_argument(
        "--history",
        type=Path,
        default=ROOT / "data" / "nvd-cve-history" / "nvd-cve-history.jsonl.gz",
    )
    parser.add_argument(
        "--maintenance-report",
        type=Path,
        default=ROOT / "data" / "nvd-cves.current.report.json",
    )
    parser.add_argument(
        "--quarantine",
        type=Path,
        default=ROOT / "data" / "nvd-cves.current.quarantine.jsonl",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "workspace" / "benchmark" / "analysis",
    )
    parser.add_argument("--progress-every", type=int, default=100)
    parser.add_argument(
        "--skip-history-scan",
        action="store_true",
        help="skip the 2.2M-row change-history scan",
    )
    return parser.parse_args()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_csv(path: Path, rows: Iterable[Mapping[str, Any]], fields: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: scalar(row.get(key)) for key in fields})


def scalar(value: Any) -> Any:
    if isinstance(value, (list, tuple, set, dict)):
        if isinstance(value, set):
            value = sorted(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return value


def load_cases(directory: Path, build: str) -> dict[tuple[str, str, str], dict[str, Any]]:
    path = directory / "evaluation" / build / f"{PREFIX}_evaluation_cases.jsonl"
    output: dict[tuple[str, str, str], dict[str, Any]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            key = tuple(str(row[field]) for field in KEY_FIELDS)
            output[key] = row
    return output


def state_for(case: Mapping[str, Any], cve_id: str, policy: str) -> str:
    if policy == "inclusive":
        if cve_id in case["result"]:
            if cve_id in case["false_positives"] or cve_id in case["true_positives"]:
                # Evaluation cases do not retain each positive state.  The caller
                # replaces this value with a query trace when it needs exact state.
                return "positive"
        return next(
            (
                value
                for value in case["candidate_state_counts"]
                if cve_id in case.get("false_negatives", [])
            ),
            "candidate_missing",
        )
    return "affected" if cve_id in case["strict_result"] else "not_strict_positive"


def metric_snapshot(cases: Mapping[tuple[str, str, str], Mapping[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for policy, result_key in (("inclusive", "result"), ("strict", "strict_result")):
        counts = Counter()
        exact = 0
        for row in cases.values():
            gold = set(row["test_set"])
            predicted = set(row[result_key])
            counts["tp"] += len(gold & predicted)
            counts["fp"] += len(predicted - gold)
            counts["fn"] += len(gold - predicted)
            counts["predicted"] += len(predicted)
            exact += gold == predicted
        precision = counts["tp"] / (counts["tp"] + counts["fp"])
        recall = counts["tp"] / (counts["tp"] + counts["fn"])
        result[policy] = {
            **dict(counts),
            "precision": precision,
            "recall": recall,
            "f1": 2 * precision * recall / (precision + recall),
            "exact_keys": exact,
        }
    return result


def compare_predictions(
    before: Mapping[tuple[str, str, str], Mapping[str, Any]],
    after: Mapping[tuple[str, str, str], Mapping[str, Any]],
    *,
    label: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    summary: dict[str, Any] = {"label": label, "policies": {}}
    for policy, result_key in (("inclusive", "result"), ("strict", "strict_result")):
        transitions = Counter()
        changed_keys: set[tuple[str, str, str]] = set()
        unique_cves: set[str] = set()
        for key, left in before.items():
            right = after[key]
            gold = set(right["test_set"])
            left_result, right_result = set(left[result_key]), set(right[result_key])
            for direction, values in (
                ("added", right_result - left_result),
                ("removed", left_result - right_result),
            ):
                for cve_id in sorted(values):
                    truth = "gold" if cve_id in gold else "non_gold"
                    transitions[f"{direction}_{truth}"] += 1
                    changed_keys.add(key)
                    unique_cves.add(cve_id)
                    rows.append(
                        {
                            "comparison": label,
                            "policy": policy,
                            "direction": direction,
                            "gold_membership": truth,
                            "vendor": key[0],
                            "product": key[1],
                            "version": key[2],
                            "cve_id": cve_id,
                        }
                    )
        summary["policies"][policy] = {
            **dict(transitions),
            "changed_query_keys": len(changed_keys),
            "unique_changed_cves": len(unique_cves),
        }
    return summary, rows


def query_targets(
    db_path: Path,
    targets: Mapping[tuple[str, str, str], set[str]],
    *,
    progress_every: int,
) -> dict[tuple[tuple[str, str, str], str], dict[str, Any]]:
    output: dict[tuple[tuple[str, str, str], str], dict[str, Any]] = {}
    with QueryEngine(db_path) as engine:
        total = len(targets)
        for index, (key, cves) in enumerate(sorted(targets.items()), 1):
            payload = engine.query(
                ApplicabilityQuery(vendor=key[0], product=key[1], version=key[2]),
                prediction_policy="inclusive",
                include_trace=True,
            )
            by_cve = {str(row["cve_id"]): row for row in payload["results"]}
            for cve_id in cves:
                row = by_cve.get(cve_id)
                if row is None:
                    output[(key, cve_id)] = {
                        "cve_id": cve_id,
                        "state": "candidate_missing",
                        "reason_codes": ["candidate_missing"],
                        "assertions": [],
                    }
                else:
                    output[(key, cve_id)] = row
            if progress_every and (index % progress_every == 0 or index == total):
                print(
                    json.dumps(
                        {"event": "trace_progress", "db": str(db_path), "done": index, "total": total}
                    ),
                    file=sys.stderr,
                    flush=True,
                )
    return output


def true_assertions(trace: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [
        item
        for item in trace.get("assertions", [])
        if item.get("polarity") == "affected"
        and item.get("version_result") == "true"
        and item.get("scope_result") != "false"
        and item.get("configuration_result") != "false"
        and item.get("role_result") != "false"
    ]


def compact_trace(trace: Mapping[str, Any]) -> dict[str, Any]:
    assertions = list(trace.get("assertions", []))
    matched = true_assertions(trace)
    uncertain = [
        item
        for item in assertions
        if item.get("polarity") in {"affected", "unknown"}
        and (
            item.get("version_result") == "unknown"
            or item.get("scope_result") == "unknown"
            or item.get("configuration_result") == "unknown"
            or item.get("role_result") == "unknown"
        )
    ]
    llm_true = [item for item in matched if item.get("source_family") == "llm_description"]
    structured_true = [item for item in matched if item.get("source_family") != "llm_description"]
    identity_tiers = sorted(
        {
            str(item.get("identity", {}).get("tier"))
            for item in assertions
            if item.get("identity", {}).get("tier")
        }
    )
    return {
        "state": trace.get("state"),
        "reason_codes": trace.get("reason_codes", []),
        "matched_source_families": sorted({str(item.get("source_family")) for item in matched}),
        "matched_version_classes": sorted({str(item.get("version_class")) for item in matched}),
        "matched_version_reasons": sorted({str(item.get("version_reason")) for item in matched}),
        "llm_true_count": len(llm_true),
        "structured_true_count": len(structured_true),
        "uncertain_assertion_count": len(uncertain),
        "identity_tiers": identity_tiers,
        "llm_source_claim_ids": sorted({int(item["source_claim_id"]) for item in llm_true}),
    }


def claim_metadata(connection: sqlite3.Connection, claim_ids: set[int]) -> dict[int, dict[str, Any]]:
    output: dict[int, dict[str, Any]] = {}
    ids = sorted(claim_ids)
    for offset in range(0, len(ids), 800):
        batch = ids[offset : offset + 800]
        marks = ",".join("?" for _ in batch)
        rows = connection.execute(
            f"""SELECT sc.source_claim_id,sc.cve_id,sc.product_id,
                       p.vendor_key,p.product_key,sc.version_raw,
                       sc.version_start_including,sc.version_start_excluding,
                       sc.version_end_including,sc.version_end_excluding,
                       a.max_result_state,e.profile_name
                  FROM source_claim sc
                  JOIN product_entity p USING(product_id)
                  JOIN applicability_assertion a USING(source_claim_id)
                  LEFT JOIN version_expression e USING(expression_id)
                 WHERE sc.source_claim_id IN ({marks})""",
            tuple(batch),
        )
        for row in rows:
            output[int(row["source_claim_id"])] = dict(row)
    return output


def bound_value(claim: Mapping[str, Any], prefix: str) -> str | None:
    for suffix in ("including", "excluding"):
        value = claim.get(f"version_{prefix}_{suffix}")
        if value is not None:
            return str(value)
    return None


def major(value: str | None) -> int | None:
    match = NUMERIC_MAJOR.match(value or "")
    return int(match.group(1)) if match else None


def llm_added_cause(
    key: tuple[str, str, str],
    trace: Mapping[str, Any],
    claims: Mapping[int, Mapping[str, Any]],
    all_llm_claims: Mapping[tuple[str, int], list[Mapping[str, Any]]],
) -> str:
    compact = compact_trace(trace)
    matched = [claims[item] for item in compact["llm_source_claim_ids"] if item in claims]
    if not matched:
        if compact["identity_tiers"] and "T3_PROVISIONAL" in compact["identity_tiers"]:
            return "provisional_identity_expansion"
        return "non_llm_indirect_change"
    query_major = major(key[2])
    for claim in matched:
        start, end = bound_value(claim, "start"), bound_value(claim, "end")
        siblings = all_llm_claims.get((str(claim["cve_id"]), int(claim["product_id"])), [])
        sibling_end_majors = {major(bound_value(item, "end")) for item in siblings}
        end_major = major(end)
        if start is None and end is not None:
            if query_major is not None and end_major is not None and query_major != end_major:
                if query_major in sibling_end_majors:
                    return "unbounded_range_cross_branch_bleed"
                return "unbounded_range_cross_major_or_release_scheme"
            if len(siblings) > 1:
                return "unbounded_range_multirange_overlap"
            return "unbounded_range_too_broad"
        if start is not None and end is not None:
            return "bounded_llm_range_disagrees_with_gold"
        if start is not None and end is None:
            return "lower_unbounded_direction_or_open_ended"
        if claim.get("version_raw"):
            return "exact_or_unparsed_llm_constraint"
    return "llm_constraint_other"


def error_cause(policy: str, error_type: str, trace: Mapping[str, Any]) -> str:
    compact = compact_trace(trace)
    state = str(compact["state"])
    if error_type == "false_negative":
        return {
            "candidate_missing": "identity_or_candidate_retrieval_missing",
            "not_affected_out_of_range": "version_range_excludes_gold",
            "not_affected_asserted": "explicit_unaffected_overrides_gold",
            "not_applicable": "scope_or_configuration_excludes_gold",
            "product_only_observation": "product_observed_without_active_assertion",
            "conflict_review": "strict_policy_rejects_source_conflict",
            "potentially_affected": "strict_policy_rejects_uncertain_or_provisional",
            "insufficient_data": "insufficient_or_rejected_record",
        }.get(state, f"other_fn:{state}")
    if state == "conflict_review":
        return "inclusive_accepts_authoritative_conflict"
    if state == "potentially_affected":
        if compact["llm_true_count"]:
            return "inclusive_accepts_llm_preliminary"
        if "T3_PROVISIONAL" in compact["identity_tiers"]:
            return "inclusive_accepts_provisional_identity"
        if compact["uncertain_assertion_count"]:
            return "inclusive_accepts_unknown_scope_or_version"
        return "inclusive_accepts_other_potential"
    if state == "affected":
        sources = set(compact["matched_source_families"])
        if sources & {"nvd_cpe", "cna_structured"}:
            return "structured_evidence_disagrees_with_gold"
        return "positive_evidence_disagrees_with_gold"
    return f"other_fp:{state}"


def database_integrity(benchmark: Path) -> dict[str, Any]:
    raw_path = benchmark / "01_nvd_without_llm.sqlite"
    current_path = benchmark / "03_current_without_llm.sqlite"
    raw = sqlite3.connect(raw_path)
    current = sqlite3.connect(current_path)
    try:
        raw.row_factory = current.row_factory = sqlite3.Row
        raw_counts = {
            "raw_cves": raw.execute("SELECT COUNT(*) FROM raw_cve").fetchone()[0],
            "rejected_cves": raw.execute(
                "SELECT COUNT(*) FROM raw_cve WHERE admission_status='rejected_upstream'"
            ).fetchone()[0],
            "source_claims": raw.execute("SELECT COUNT(*) FROM source_claim").fetchone()[0],
            "assertions": raw.execute("SELECT COUNT(*) FROM applicability_assertion").fetchone()[0],
            "bindings": raw.execute("SELECT COUNT(*) FROM current_binding").fetchone()[0],
            "rejected_source_claims": raw.execute(
                """SELECT COUNT(*) FROM source_claim s JOIN raw_cve c USING(cve_id)
                     WHERE c.admission_status='rejected_upstream'"""
            ).fetchone()[0],
            "rejected_assertions": raw.execute(
                """SELECT COUNT(*) FROM applicability_assertion a JOIN raw_cve c USING(cve_id)
                     WHERE c.admission_status='rejected_upstream'"""
            ).fetchone()[0],
            "rejected_bindings": raw.execute(
                """SELECT COUNT(*) FROM current_binding b JOIN raw_cve c USING(cve_id)
                     WHERE c.admission_status='rejected_upstream'"""
            ).fetchone()[0],
        }
        current_counts = {
            "raw_cves": current.execute("SELECT COUNT(*) FROM raw_cve").fetchone()[0],
            "source_claims": current.execute("SELECT COUNT(*) FROM source_claim").fetchone()[0],
            "assertions": current.execute("SELECT COUNT(*) FROM applicability_assertion").fetchone()[0],
            "bindings": current.execute("SELECT COUNT(*) FROM current_binding").fetchone()[0],
        }
        raw_rows = {
            str(row["cve_id"]): str(row["raw_sha256"])
            for row in raw.execute(
                "SELECT cve_id,raw_sha256 FROM raw_cve WHERE admission_status<>'rejected_upstream'"
            )
        }
        current_rows = {
            str(row["cve_id"]): str(row["raw_sha256"])
            for row in current.execute("SELECT cve_id,raw_sha256 FROM raw_cve")
        }
        return {
            "raw": raw_counts,
            "current": current_counts,
            "accepted_cves_missing_from_current": len(set(raw_rows) - set(current_rows)),
            "current_cves_missing_from_raw_accepted": len(set(current_rows) - set(raw_rows)),
            "common_record_digest_mismatches": sum(
                raw_rows[cve_id] != current_rows[cve_id]
                for cve_id in set(raw_rows) & set(current_rows)
            ),
        }
    finally:
        raw.close()
        current.close()


def database_cve_ids(path: Path, where: str = "1=1") -> set[str]:
    connection = sqlite3.connect(path)
    try:
        return {str(row[0]) for row in connection.execute(f"SELECT cve_id FROM raw_cve WHERE {where}")}
    finally:
        connection.close()


def database_snapshot_stats(path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        manifest = connection.execute(
            """SELECT payload_sha256,record_count,downloaded_at
                 FROM source_snapshot_manifest ORDER BY snapshot_id DESC LIMIT 1"""
        ).fetchone()
        bounds = connection.execute(
            "SELECT MIN(last_modified),MAX(last_modified) FROM raw_cve"
        ).fetchone()
        return {
            "payload_sha256": manifest["payload_sha256"] if manifest else None,
            "record_count": manifest["record_count"] if manifest else None,
            "database_built_at": manifest["downloaded_at"] if manifest else None,
            "min_cve_last_modified": bounds[0],
            "max_cve_last_modified": bounds[1],
        }
    finally:
        connection.close()


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def scan_history(
    path: Path,
    *,
    gold_cves: set[str],
    previous_stale_candidates: set[str],
    raw_modified: Mapping[str, str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    counters = Counter()
    gold_history_cves: set[str] = set()
    gold_changed_cves: set[str] = set()
    gold_version_cves: set[str] = set()
    latest_for_old_missing: dict[str, tuple[datetime, str, str]] = {}
    samples: list[dict[str, Any]] = []
    opener = gzip.open if path.name.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            change = json.loads(line).get("change", {})
            cve_id = str(change.get("cveId") or "").upper()
            if cve_id not in gold_cves and cve_id not in previous_stale_candidates:
                continue
            created_text = str(change.get("created") or "")
            created = parse_time(created_text)
            details = change.get("details") if isinstance(change.get("details"), list) else []
            if cve_id in gold_cves:
                gold_history_cves.add(cve_id)
                counters["gold_history_events"] += 1
                actions = {str(item.get("action") or "") for item in details if isinstance(item, dict)}
                if "Changed" in actions:
                    counters["gold_changed_events"] += 1
                    gold_changed_cves.add(cve_id)
                relevant = [
                    item
                    for item in details
                    if isinstance(item, dict)
                    and any(token in str(item.get("type") or "").casefold() for token in ("cpe", "affected", "version"))
                ]
                if relevant:
                    counters["gold_version_or_configuration_events"] += 1
                    gold_version_cves.add(cve_id)
                    if len(samples) < 100:
                        samples.append(
                            {
                                "cve_id": cve_id,
                                "event_name": change.get("eventName"),
                                "created": created_text,
                                "details": relevant,
                            }
                        )
            if cve_id in previous_stale_candidates and created is not None:
                previous = latest_for_old_missing.get(cve_id)
                candidate = (created, str(change.get("eventName") or ""), created_text)
                if previous is None or candidate[0] > previous[0]:
                    latest_for_old_missing[cve_id] = candidate
    newer_than_record = 0
    with_history = 0
    for cve_id in previous_stale_candidates:
        latest = latest_for_old_missing.get(cve_id)
        if latest is None:
            continue
        with_history += 1
        modified = parse_time(raw_modified.get(cve_id))
        if modified is not None and latest[0] > modified:
            newer_than_record += 1
    return (
        {
            **dict(counters),
            "gold_cves_with_history": len(gold_history_cves),
            "gold_cves_with_changed_detail": len(gold_changed_cves),
            "gold_cves_with_version_or_configuration_event": len(gold_version_cves),
            "saved_version_or_configuration_samples": len(samples),
            "previously_missing_accepted_cves": len(previous_stale_candidates),
            "previously_missing_with_history": with_history,
            "previously_missing_latest_history_newer_than_record": newer_than_record,
        },
        samples,
    )


def top_counts(rows: Iterable[Mapping[str, Any]], fields: Sequence[str], limit: int = 20) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, ...]] = Counter(
        tuple(str(row.get(field, "")) for field in fields) for row in rows
    )
    return [
        {**dict(zip(fields, key)), "count": count}
        for key, count in counts.most_common(limit)
    ]


def main() -> int:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    current_cases = {build: load_cases(args.benchmark_dir, build) for build in BUILDS}
    metrics = {build: metric_snapshot(current_cases[build]) for build in BUILDS}

    llm_summary, llm_transitions = compare_predictions(
        current_cases["01_nvd_without_llm"],
        current_cases["02_nvd_with_llm"],
        label="llm_raw_01_to_02",
    )
    history_summary, history_transitions = compare_predictions(
        current_cases["01_nvd_without_llm"],
        current_cases["03_current_without_llm"],
        label="history_no_llm_01_to_03",
    )
    history_llm_summary, history_llm_transitions = compare_predictions(
        current_cases["02_nvd_with_llm"],
        current_cases["04_current_with_llm"],
        label="history_with_llm_02_to_04",
    )

    all_transition_rows = llm_transitions + history_transitions + history_llm_transitions
    write_csv(
        args.output_dir / "01_prediction_transitions.csv",
        all_transition_rows,
        ("comparison", "policy", "direction", "gold_membership", *KEY_FIELDS, "cve_id"),
    )
    write_json(
        args.output_dir / "01_prediction_transition_summary.json",
        {
            "metrics_recomputed_from_cases": metrics,
            "llm": llm_summary,
            "history_without_llm": history_summary,
            "history_with_llm": history_llm_summary,
        },
    )

    # Query exact traces for every error in the LLM build and all LLM transitions.
    llm_targets: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    llm_cases = current_cases["02_nvd_with_llm"]
    for key, row in llm_cases.items():
        for field in ("false_positives", "false_negatives", "strict_false_positives", "strict_false_negatives"):
            llm_targets[key].update(str(value) for value in row[field])
    for row in llm_transitions:
        llm_targets[(row["vendor"], row["product"], row["version"])].add(str(row["cve_id"]))
    llm_traces = query_targets(
        args.benchmark_dir / "02_nvd_with_llm.sqlite",
        llm_targets,
        progress_every=args.progress_every,
    )

    baseline_targets: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for row in llm_transitions:
        baseline_targets[(row["vendor"], row["product"], row["version"])].add(str(row["cve_id"]))
    baseline_traces = query_targets(
        args.benchmark_dir / "01_nvd_without_llm.sqlite",
        baseline_targets,
        progress_every=args.progress_every,
    )

    llm_claim_ids = {
        claim_id
        for trace in llm_traces.values()
        for claim_id in compact_trace(trace)["llm_source_claim_ids"]
    }
    llm_connection = sqlite3.connect(args.benchmark_dir / "02_nvd_with_llm.sqlite")
    llm_connection.row_factory = sqlite3.Row
    claims = claim_metadata(llm_connection, llm_claim_ids)
    all_llm_claims: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in llm_connection.execute(
        """SELECT sc.cve_id,sc.product_id,sc.version_raw,
                  sc.version_start_including,sc.version_start_excluding,
                  sc.version_end_including,sc.version_end_excluding
             FROM source_claim sc
            WHERE sc.source_family='llm_description'"""
    ):
        all_llm_claims[(str(row["cve_id"]), int(row["product_id"]))].append(dict(row))

    llm_detail_rows: list[dict[str, Any]] = []
    cause_counts: Counter[str] = Counter()
    strict_demotion_counts: Counter[str] = Counter()
    for transition in llm_transitions:
        key = tuple(str(transition[field]) for field in KEY_FIELDS)
        cve_id = str(transition["cve_id"])
        before_trace = baseline_traces[(key, cve_id)]
        after_trace = llm_traces[(key, cve_id)]
        before_compact = compact_trace(before_trace)
        after_compact = compact_trace(after_trace)
        cause = ""
        if transition["policy"] == "inclusive" and transition["direction"] == "added":
            cause = llm_added_cause(key, after_trace, claims, all_llm_claims)
            cause_counts[cause] += 1
        elif transition["policy"] == "strict" and transition["direction"] == "removed":
            if after_compact["llm_true_count"] and after_compact["structured_true_count"]:
                cause = "provisional_llm_match_caps_structured_match"
            elif after_compact["llm_true_count"]:
                cause = "llm_only_provisional_positive"
            else:
                cause = "indirect_identity_or_reconciliation_change"
            strict_demotion_counts[cause] += 1
        llm_detail_rows.append(
            {
                **transition,
                "before_state": before_compact["state"],
                "after_state": after_compact["state"],
                "after_reason_codes": after_compact["reason_codes"],
                "after_matched_sources": after_compact["matched_source_families"],
                "after_matched_version_classes": after_compact["matched_version_classes"],
                "llm_true_count": after_compact["llm_true_count"],
                "structured_true_count": after_compact["structured_true_count"],
                "identity_tiers": after_compact["identity_tiers"],
                "cause": cause,
            }
        )
    llm_connection.close()
    transition_fields = (
        "policy", "direction", "gold_membership", *KEY_FIELDS, "cve_id",
        "before_state", "after_state", "after_reason_codes", "after_matched_sources",
        "after_matched_version_classes", "llm_true_count", "structured_true_count",
        "identity_tiers", "cause",
    )
    write_csv(args.output_dir / "02_llm_transition_details.csv", llm_detail_rows, transition_fields)
    write_json(
        args.output_dir / "02_llm_cause_summary.json",
        {
            "inclusive_added_causes": dict(cause_counts),
            "inclusive_added_false_positive_causes": dict(
                Counter(
                    row["cause"]
                    for row in llm_detail_rows
                    if row["policy"] == "inclusive"
                    and row["direction"] == "added"
                    and row["gold_membership"] == "non_gold"
                )
            ),
            "inclusive_added_true_positive_causes": dict(
                Counter(
                    row["cause"]
                    for row in llm_detail_rows
                    if row["policy"] == "inclusive"
                    and row["direction"] == "added"
                    and row["gold_membership"] == "gold"
                )
            ),
            "strict_removed_causes": dict(strict_demotion_counts),
            "inclusive_added_top_queries": top_counts(
                (row for row in llm_detail_rows if row["policy"] == "inclusive" and row["direction"] == "added"),
                KEY_FIELDS,
            ),
            "inclusive_added_top_cves": top_counts(
                (row for row in llm_detail_rows if row["policy"] == "inclusive" and row["direction"] == "added"),
                ("cve_id",),
            ),
        },
    )

    # Detailed FP/FN taxonomy for the LLM build.  Memberships are intentionally
    # retained (rather than unique CVEs) because the benchmark metrics use them.
    error_rows: list[dict[str, Any]] = []
    error_counts: Counter[tuple[str, str, str, str]] = Counter()
    for key, case in llm_cases.items():
        for policy, fp_field, fn_field in (
            ("inclusive", "false_positives", "false_negatives"),
            ("strict", "strict_false_positives", "strict_false_negatives"),
        ):
            for error_type, field in (("false_positive", fp_field), ("false_negative", fn_field)):
                for cve_id in case[field]:
                    trace = llm_traces[(key, str(cve_id))]
                    compact = compact_trace(trace)
                    cause = error_cause(policy, error_type, trace)
                    error_counts[(policy, error_type, str(compact["state"]), cause)] += 1
                    error_rows.append(
                        {
                            "policy": policy,
                            "error_type": error_type,
                            "vendor": key[0],
                            "product": key[1],
                            "version": key[2],
                            "cve_id": cve_id,
                            "state": compact["state"],
                            "reason_codes": compact["reason_codes"],
                            "matched_sources": compact["matched_source_families"],
                            "matched_version_classes": compact["matched_version_classes"],
                            "llm_true_count": compact["llm_true_count"],
                            "structured_true_count": compact["structured_true_count"],
                            "uncertain_assertion_count": compact["uncertain_assertion_count"],
                            "identity_tiers": compact["identity_tiers"],
                            "cause": cause,
                        }
                    )
    error_fields = (
        "policy", "error_type", *KEY_FIELDS, "cve_id", "state", "reason_codes",
        "matched_sources", "matched_version_classes", "llm_true_count",
        "structured_true_count", "uncertain_assertion_count", "identity_tiers", "cause",
    )
    write_csv(args.output_dir / "03_llm_build_error_details.csv", error_rows, error_fields)
    error_summary_rows = [
        {"policy": key[0], "error_type": key[1], "state": key[2], "cause": key[3], "count": count}
        for key, count in sorted(error_counts.items())
    ]
    write_csv(
        args.output_dir / "03_llm_build_error_summary.csv",
        error_summary_rows,
        ("policy", "error_type", "state", "cause", "count"),
    )
    write_json(
        args.output_dir / "03_llm_build_error_top.json",
        {
            "top_error_queries": top_counts(error_rows, ("policy", "error_type", *KEY_FIELDS)),
            "top_error_cves": top_counts(error_rows, ("policy", "error_type", "cve_id")),
        },
    )
    state_comparison_rows: list[dict[str, Any]] = []
    for build in ("01_nvd_without_llm", "02_nvd_with_llm"):
        error_path = (
            args.benchmark_dir / "evaluation" / build / f"{PREFIX}_cve_errors.csv"
        )
        counts: Counter[tuple[str, str, str]] = Counter()
        with error_path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                counts[(row["policy"], row["error_type"], row["candidate_state"])] += 1
        for key, count in sorted(counts.items()):
            state_comparison_rows.append(
                {
                    "build": build,
                    "policy": key[0],
                    "error_type": key[1],
                    "state": key[2],
                    "count": count,
                }
            )
    write_csv(
        args.output_dir / "03_error_state_before_after_llm.csv",
        state_comparison_rows,
        ("build", "policy", "error_type", "state", "count"),
    )

    integrity = database_integrity(args.benchmark_dir)
    maintenance = read_json(args.maintenance_report)
    quarantine_rows = [json.loads(line) for line in args.quarantine.read_text(encoding="utf-8").splitlines() if line.strip()]
    gold_memberships = {
        (key, cve_id)
        for key, case in current_cases["01_nvd_without_llm"].items()
        for cve_id in case["test_set"]
    }
    gold_cves = {cve_id for _key, cve_id in gold_memberships}
    quarantine_cves = {str(row["cve_id"]) for row in quarantine_rows}
    removed_gold_rows = [
        {"vendor": key[0], "product": key[1], "version": key[2], "cve_id": cve_id,
         "raw_inclusive_positive": cve_id in current_cases["01_nvd_without_llm"][key]["result"],
         "raw_strict_positive": cve_id in current_cases["01_nvd_without_llm"][key]["strict_result"]}
        for key, cve_id in sorted(gold_memberships)
        if cve_id in quarantine_cves
    ]
    write_csv(
        args.output_dir / "04_history_removed_gold_memberships.csv",
        removed_gold_rows,
        (*KEY_FIELDS, "cve_id", "raw_inclusive_positive", "raw_strict_positive"),
    )

    previous_summary: dict[str, Any] = {"available": False}
    gold_change_rows: list[dict[str, Any]] = []
    old_missing_accepted: set[str] = set()
    raw_modified: dict[str, str] = {}
    if args.previous_benchmark_dir.is_dir():
        previous_summary["available"] = True
        previous_raw_cases = load_cases(args.previous_benchmark_dir, "01_nvd_without_llm")
        previous_current_cases = load_cases(args.previous_benchmark_dir, "03_current_without_llm")
        old_history_summary, old_history_rows = compare_predictions(
            previous_raw_cases,
            previous_current_cases,
            label="previous_history_no_llm",
        )
        current_revision_summary, current_revision_rows = compare_predictions(
            previous_current_cases,
            current_cases["03_current_without_llm"],
            label="previous_current_to_rerun_current",
        )
        for key, old_case in previous_raw_cases.items():
            old_gold, new_gold = set(old_case["test_set"]), set(current_cases["01_nvd_without_llm"][key]["test_set"])
            for direction, values in (("added", new_gold - old_gold), ("removed", old_gold - new_gold)):
                for cve_id in sorted(values):
                    gold_change_rows.append(
                        {
                            "direction": direction,
                            "vendor": key[0], "product": key[1], "version": key[2], "cve_id": cve_id,
                            "raw_inclusive_prediction": cve_id in current_cases["01_nvd_without_llm"][key]["result"],
                            "raw_strict_prediction": cve_id in current_cases["01_nvd_without_llm"][key]["strict_result"],
                        }
                    )
        old_raw_db = args.previous_benchmark_dir / "01_nvd_without_llm.sqlite"
        old_current_db = args.previous_benchmark_dir / "03_current_without_llm.sqlite"
        old_raw_accepted = database_cve_ids(old_raw_db, "admission_status='accepted_raw'")
        old_current_ids = database_cve_ids(old_current_db)
        old_missing_accepted = old_raw_accepted - old_current_ids
        old_current_extra = old_current_ids - old_raw_accepted
        connection = sqlite3.connect(old_raw_db)
        raw_modified = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT cve_id,last_modified FROM raw_cve WHERE admission_status='accepted_raw'"
            )
        }
        connection.close()
        restored_rows = [
            row for row in current_revision_rows
            if row["policy"] == "inclusive" and row["direction"] == "added"
        ]
        previous_summary.update(
            {
                "old_metrics": {
                    "raw": metric_snapshot(previous_raw_cases),
                    "current": metric_snapshot(previous_current_cases),
                },
                "old_raw_to_old_current": old_history_summary,
                "old_current_to_rerun_current": current_revision_summary,
                "old_raw_accepted_count": len(old_raw_accepted),
                "old_current_count": len(old_current_ids),
                "old_accepted_cves_missing_from_old_current": len(old_missing_accepted),
                "old_current_cves_not_in_old_raw_accepted": len(old_current_extra),
                "old_missing_last_modified_days": dict(
                    sorted(
                        Counter(raw_modified[cve_id][:10] for cve_id in old_missing_accepted).items()
                    )
                ),
                "old_raw_snapshot": database_snapshot_stats(old_raw_db),
                "old_current_snapshot": database_snapshot_stats(old_current_db),
                "rerun_current_restored_inclusive_memberships": len(restored_rows),
                "rerun_current_restored_unique_cves": len({row["cve_id"] for row in restored_rows}),
                "restored_memberships_from_previously_missing_cves": sum(
                    row["cve_id"] in old_missing_accepted for row in restored_rows
                ),
            }
        )
        write_csv(
            args.output_dir / "05_previous_vs_current_prediction_transitions.csv",
            old_history_rows + current_revision_rows,
            ("comparison", "policy", "direction", "gold_membership", *KEY_FIELDS, "cve_id"),
        )
    write_csv(
        args.output_dir / "05_gold_revision_changes.csv",
        gold_change_rows,
        ("direction", *KEY_FIELDS, "cve_id", "raw_inclusive_prediction", "raw_strict_prediction"),
    )
    gold_revision_summary = {
        "changed_memberships": len(gold_change_rows),
        "added": sum(row["direction"] == "added" for row in gold_change_rows),
        "removed": sum(row["direction"] == "removed" for row in gold_change_rows),
        "added_already_predicted_inclusive": sum(
            row["direction"] == "added" and bool(row["raw_inclusive_prediction"])
            for row in gold_change_rows
        ),
        "added_already_predicted_strict": sum(
            row["direction"] == "added" and bool(row["raw_strict_prediction"])
            for row in gold_change_rows
        ),
        "changed_query_keys": len({tuple(row[field] for field in KEY_FIELDS) for row in gold_change_rows}),
    }
    write_json(args.output_dir / "05_previous_run_and_gold_revision_summary.json", {
        "previous_run": previous_summary,
        "gold_revision": gold_revision_summary,
    })

    history_scan_summary: dict[str, Any] = {"skipped": True}
    history_samples: list[dict[str, Any]] = []
    if not args.skip_history_scan and args.history.is_file():
        history_scan_summary, history_samples = scan_history(
            args.history,
            gold_cves=gold_cves,
            previous_stale_candidates=old_missing_accepted,
            raw_modified=raw_modified,
        )
        history_scan_summary["skipped"] = False
    with (args.output_dir / "06_gold_history_version_configuration_samples.jsonl").open("w", encoding="utf-8") as handle:
        for row in history_samples:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    history_effect = {
        "maintenance_report": {
            "created_at": maintenance.get("created_at"),
            "snapshot_as_of": maintenance.get("decision_summary", {}).get("snapshot_as_of"),
            "decision_summary": maintenance.get("decision_summary"),
            "semantics": maintenance.get("semantics"),
        },
        "database_integrity": integrity,
        "quarantine": {
            "rows": len(quarantine_rows),
            "reason_counts": dict(Counter(str(row.get("reason")) for row in quarantine_rows)),
            "unique_gold_cves": len(gold_cves & quarantine_cves),
            "gold_memberships": len(removed_gold_rows),
            "removed_gold_inclusive_positive_in_raw": sum(bool(row["raw_inclusive_positive"]) for row in removed_gold_rows),
        },
        "prediction_comparison": {
            "without_llm": history_summary,
            "with_llm": history_llm_summary,
        },
        "history_scan": history_scan_summary,
    }
    write_json(args.output_dir / "06_history_effect_summary.json", history_effect)

    # Preserve one concrete conflict that motivated history maintenance.
    image_magick: dict[str, Any] = {"cve_id": "CVE-2024-41817", "query_version": "7.0.10-58"}
    for build in ("01_nvd_without_llm", "03_current_without_llm"):
        with QueryEngine(args.benchmark_dir / f"{build}.sqlite") as engine:
            payload = engine.query(
                ApplicabilityQuery(vendor="imagemagick", product="imagemagick", version="7.0.10-58"),
                prediction_policy="inclusive",
                include_trace=True,
            )
            row = next((item for item in payload["results"] if item["cve_id"] == "CVE-2024-41817"), None)
            image_magick[build] = compact_trace(row or {"state": "candidate_missing"})
    raw_conn = sqlite3.connect(args.benchmark_dir / "01_nvd_without_llm.sqlite")
    raw_conn.row_factory = sqlite3.Row
    image_magick["source_claims"] = [
        dict(row)
        for row in raw_conn.execute(
            """SELECT source_family,vendor_raw,product_raw,version_raw,
                      version_start_including,version_start_excluding,
                      version_end_including,version_end_excluding
                 FROM source_claim WHERE cve_id='CVE-2024-41817'
                 ORDER BY source_family,source_claim_id"""
        )
    ]
    raw_conn.close()
    write_json(args.output_dir / "07_cve_2024_41817_case.json", image_magick)

    checks: list[dict[str, Any]] = []

    def check(name: str, actual: Any, expected: Any) -> None:
        checks.append(
            {
                "name": name,
                "passed": actual == expected,
                "actual": actual,
                "expected": expected,
            }
        )

    for build in BUILDS:
        published = read_json(
            args.benchmark_dir / "evaluation" / build / f"{PREFIX}_evaluation.json"
        )["overall"]
        for policy in ("inclusive", "strict"):
            for short, long_name in (
                ("tp", "true_positive"),
                ("fp", "false_positive"),
                ("fn", "false_negative"),
                ("predicted", "predicted_positive"),
            ):
                check(
                    f"{build}.{policy}.{short}",
                    metrics[build][policy][short],
                    published[policy][long_name],
                )
    fp_causes = Counter(
        row["cause"]
        for row in llm_detail_rows
        if row["policy"] == "inclusive"
        and row["direction"] == "added"
        and row["gold_membership"] == "non_gold"
    )
    tp_causes = Counter(
        row["cause"]
        for row in llm_detail_rows
        if row["policy"] == "inclusive"
        and row["direction"] == "added"
        and row["gold_membership"] == "gold"
    )
    check("llm_added_fp_cause_sum", sum(fp_causes.values()), 358)
    check("llm_added_tp_cause_sum", sum(tp_causes.values()), 17)
    check("llm_strict_removed_cause_sum", sum(strict_demotion_counts.values()), 408)
    check("history_without_llm_changed_queries", history_summary["policies"]["inclusive"]["changed_query_keys"], 0)
    check("history_with_llm_changed_queries", history_llm_summary["policies"]["inclusive"]["changed_query_keys"], 0)
    check("current_contains_all_raw_accepted", integrity["accepted_cves_missing_from_current"], 0)
    check("current_common_digest_mismatches", integrity["common_record_digest_mismatches"], 0)
    check("rejected_assertions", integrity["raw"]["rejected_assertions"], 0)
    check("gold_added_inclusive_predictions", gold_revision_summary["added_already_predicted_inclusive"], gold_revision_summary["added"])
    validation = {
        "all_passed": all(item["passed"] for item in checks),
        "check_count": len(checks),
        "checks": checks,
    }
    write_json(args.output_dir / "08_validation.json", validation)
    if not validation["all_passed"]:
        failed = [item["name"] for item in checks if not item["passed"]]
        raise RuntimeError(f"analysis validation failed: {failed}")

    report = f"""# Benchmark 세부 원인 분석

생성 기준: 현재 `workspace/benchmark`의 4개 evaluation case를 query/CVE membership
단위로 재계산하고, schema-v5 query trace와 LLM source claim을 결합했다.

## 검증된 핵심 수치

- LLM inclusive: +{llm_summary['policies']['inclusive'].get('added_gold', 0)} TP,
  +{llm_summary['policies']['inclusive'].get('added_non_gold', 0)} FP.
- LLM strict: -{llm_summary['policies']['strict'].get('removed_gold', 0)} TP,
  -{llm_summary['policies']['strict'].get('removed_non_gold', 0)} FP.
- raw/current 예측 차이: LLM 미사용 {sum(history_summary['policies']['inclusive'].values()) if False else history_summary['policies']['inclusive'].get('changed_query_keys', 0)}개 query,
  LLM 사용 {history_llm_summary['policies']['inclusive'].get('changed_query_keys', 0)}개 query.
- current가 제거한 CVE: {len(quarantine_rows):,}; 그 CVE에서 생성된 raw assertion/binding:
  {integrity['raw']['rejected_assertions']}/{integrity['raw']['rejected_bindings']}.
- 이전 gold 대비 membership 추가/제거: {gold_revision_summary['added']}/{gold_revision_summary['removed']}.

## LLM 오탐의 직접 원인

LLM 설명 추출 범위는 preliminary assertion으로 materialize된다. 설명에 여러 release
branch가 열거될 때 각각의 상한 범위가 product branch 조건 없이 OR 결합된다. 따라서
예를 들어 8.5.x query가 9.x 상한보다 작다는 이유로 다른 branch 범위에 들어가는
cross-branch bleed가 발생한다. 상세 집계는 `02_llm_cause_summary.json`, 개별 근거는
`02_llm_transition_details.csv`에 있다.

또한 query finalizer는 authoritative assertion과 preliminary LLM assertion이 함께
TRUE여도, TRUE assertion 중 하나라도 `max_result_state=potentially_affected`이면 전체
결과를 potentially_affected로 낮춘다. 이 때문에 strict TP가 LLM 적용 후 감소한다.

## History 결과가 같은 이유

current 생성기는 change detail을 CVE JSON에 패치하지 않는다. 최신 feed의 coverage를
검증하고 rejected/stale 레코드를 제외한다. 이번 report는 stale 0건이고 rejected만
제외했다. 정규화 builder도 raw의 rejected CVE에는 source claim/assertion/binding을
생성하지 않으므로 두 DB의 검색 가능한 의미 데이터가 같다. 공통 accepted CVE의 raw
digest 불일치도 {integrity['common_record_digest_mismatches']}건이다.

이전 비교의 raw/current는 같은 시점의 입력이 아니었다. 이전 raw의 CVE
`lastModified` 최댓값은 {previous_summary.get('old_raw_snapshot', {}).get('max_cve_last_modified')}인데
이전 current는 {previous_summary.get('old_current_snapshot', {}).get('max_cve_last_modified')}에서
끝난다. raw에는 있지만 current에는 없던 accepted CVE
{previous_summary.get('old_accepted_cves_missing_from_old_current', 0):,}건은 모두 그 이후
수정분이다. 반대로 이전 current에만 있고 raw에서는 이미 rejected인 CVE도
{previous_summary.get('old_current_cves_not_in_old_raw_accepted', 0)}건이었다. 즉 이전 차이는
history 필터의 정확도 효과가 아니라 갱신 시점이 다른 두 파일을 비교한 결과다. 현재는
merge 직후 current를 다시 만들었고 accepted CVE 집합과 공통 record digest가 일치한다.

## Gold 수정 효과

이전 gold에서 현재 gold로 {gold_revision_summary['added']} memberships가 추가됐고 제거는
{gold_revision_summary['removed']}건이다. 추가된 것 중 이미 raw inclusive가 반환하던 것이
{gold_revision_summary['added_already_predicted_inclusive']}건이므로, 이 부분은 알고리즘 개선이
아니라 기존 FP가 TP로 재분류된 성능 상승이다.
"""
    (args.output_dir / "ANALYSIS_REPORT.md").write_text(report, encoding="utf-8")
    print(json.dumps({
        "output_dir": str(args.output_dir),
        "llm_causes": dict(cause_counts),
        "strict_demotion_causes": dict(strict_demotion_counts),
        "history_integrity": integrity,
        "gold_revision": gold_revision_summary,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
