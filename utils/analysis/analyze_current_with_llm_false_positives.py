#!/usr/bin/env python3
"""Classify every inclusive false positive in benchmark build 04.

The evaluator calls every prediction absent from the supplied gold set a false
positive.  This script explains the *mechanism* that made the query engine
positive; it does not assume that absence from gold proves the NVD assertion is
factually wrong.  Results are emitted at query/CVE membership granularity.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import re
import sqlite3
import sys
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.nvd_normalization.query_engine import (  # noqa: E402
    ApplicabilityQuery,
    QueryEngine,
)


DEFAULT_BUILD = "04_current_with_llm"
FP_NAME = "nvd_labeling_250_v2_cve_errors_inclusive_false_positive.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark-dir", type=Path, default=ROOT / "workspace" / "benchmark"
    )
    parser.add_argument("--build", default=DEFAULT_BUILD)
    parser.add_argument(
        "--fp-csv",
        type=Path,
        help=(
            "False-positive CSV to analyse. Defaults to the selected build's "
            "evaluation output."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "workspace" / "benchmark" / "analysis" / "04_fp",
    )
    parser.add_argument("--progress-every", type=int, default=100)
    return parser.parse_args()


def load_fp(path: Path) -> list[dict[str, str]]:
    fields = ("vendor", "product", "version", "policy", "error_type", "cve_id", "state")
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return [dict(zip(fields, row)) for row in csv.reader(handle) if row]


def query_traces(
    db: Path,
    rows: list[dict[str, str]],
    *,
    progress_every: int,
) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    targets: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for row in rows:
        targets[(row["vendor"], row["product"], row["version"])].add(row["cve_id"])
    output: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    with QueryEngine(db) as engine:
        for index, (key, cves) in enumerate(sorted(targets.items()), 1):
            payload = engine.query(
                ApplicabilityQuery(vendor=key[0], product=key[1], version=key[2]),
                prediction_policy="inclusive",
                include_trace=True,
            )
            by_cve = {str(item["cve_id"]): item for item in payload["results"]}
            for cve_id in cves:
                output[(*key, cve_id)] = by_cve.get(
                    cve_id,
                    {
                        "cve_id": cve_id,
                        "state": "candidate_missing",
                        "reason_codes": ["candidate_missing_during_recheck"],
                        "assertions": [],
                    },
                )
            if progress_every and (index % progress_every == 0 or index == len(targets)):
                print(f"trace {index}/{len(targets)}", file=sys.stderr, flush=True)
    return output


def chunks(values: list[int], size: int = 700) -> Iterable[list[int]]:
    for offset in range(0, len(values), size):
        yield values[offset : offset + size]


def load_claims(
    connection: sqlite3.Connection, claim_ids: set[int]
) -> dict[int, dict[str, Any]]:
    output: dict[int, dict[str, Any]] = {}
    sql = """SELECT sc.source_claim_id,sc.cve_id,sc.source_family,
                    sc.vendor_raw,sc.product_raw,sc.version_raw,sc.version_kind,
                    sc.version_resolution_class,sc.cpe_criteria,
                    sc.version_start_including,sc.version_start_excluding,
                    sc.version_end_including,sc.version_end_excluding,
                    e.parse_status,e.parse_error_code,e.raw_expression,
                    GROUP_CONCAT(DISTINCT
                      COALESCE(v.exact_value,'') || '|' ||
                      COALESCE(v.lower_bound,'') || '|' ||
                      COALESCE(v.upper_bound,'') || '|' ||
                      COALESCE(v.breadth_class,'')) AS segments
               FROM source_claim sc
               LEFT JOIN version_expression e USING(source_claim_id)
               LEFT JOIN version_segment v USING(expression_id)
              WHERE sc.source_claim_id IN ({marks})
              GROUP BY sc.source_claim_id"""
    for batch in chunks(sorted(claim_ids)):
        marks = ",".join("?" for _ in batch)
        for row in connection.execute(sql.format(marks=marks), tuple(batch)):
            output[int(row["source_claim_id"])] = dict(row)
    return output


def causal_assertions(trace: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    assertions = list(trace.get("assertions", []))
    state = str(trace.get("state"))
    if state == "affected":
        selected = [
            item for item in assertions
            if item.get("polarity") == "affected"
            and item.get("version_result") == "true"
            and item.get("scope_result") != "false"
            and item.get("configuration_result") != "false"
            and item.get("role_result") != "false"
        ]
    elif state == "potentially_affected":
        selected = [
            item for item in assertions
            if item.get("polarity") in {"affected", "unknown"}
            and item.get("version_result") in {"true", "unknown"}
            and item.get("scope_result") != "false"
            and item.get("configuration_result") != "false"
            and item.get("role_result") != "false"
        ]
    else:
        selected = [
            item for item in assertions
            if item.get("scope_result") != "false"
            and item.get("configuration_result") != "false"
            and item.get("role_result") != "false"
        ]
    return selected or assertions


def cpe_version(criteria: Any) -> str | None:
    if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
        return None
    fields = criteria.split(":")
    return fields[5] if len(fields) > 5 else None


def claim_flags(claim: Mapping[str, Any]) -> set[str]:
    flags: set[str] = set()
    version_class = str(claim.get("version_resolution_class") or "")
    raw = claim.get("version_raw")
    raw_text = "" if raw is None else str(raw).strip()
    bounds = [
        claim.get("version_start_including"),
        claim.get("version_start_excluding"),
        claim.get("version_end_including"),
        claim.get("version_end_excluding"),
    ]
    has_bound = any(value not in {None, "", "*", "-"} for value in bounds)
    criterion_version = cpe_version(claim.get("cpe_criteria"))
    literal_wildcard = raw_text == "*" or criterion_version == "*"
    if literal_wildcard and not has_bound:
        flags.add("literal_wildcard_only")
    if version_class == "CPE_ANY_UNCORROBORATED":
        flags.add("uncorroborated_cpe_wildcard")
    if version_class in {"UNSPECIFIED", "UNPARSED"}:
        flags.add("missing_or_unusable_version")
    if not raw_text and not has_bound and version_class not in {
        "EXPLICIT_ALL", "CPE_ANY_UNCORROBORATED", "NOT_APPLICABLE"
    }:
        flags.add("missing_or_unusable_version")
    if version_class == "EXPLICIT_ALL":
        flags.add("explicit_all_versions")
    if version_class == "UNBOUNDED_RANGE":
        flags.add("one_sided_open_range")
    if version_class == "BOUNDED_RANGE":
        flags.add("bounded_range")
    if version_class == "EXACT":
        flags.add("exact_version")
    if str(claim.get("parse_status") or "") not in {"", "parsed"}:
        flags.add("parse_failure")
    return flags


def classify(
    trace: Mapping[str, Any], claims: Mapping[int, Mapping[str, Any]]
) -> tuple[str, str, set[str], list[Mapping[str, Any]]]:
    state = str(trace.get("state"))
    reasons = {str(value) for value in trace.get("reason_codes", [])}
    causal = causal_assertions(trace)
    causal_claims = [
        claims[int(item["source_claim_id"])]
        for item in causal
        if item.get("source_claim_id") is not None
        and int(item["source_claim_id"]) in claims
    ]
    flags: set[str] = set()
    for claim in causal_claims:
        flags.update(claim_flags(claim))
    tiers = {
        str(item.get("identity", {}).get("tier") or "") for item in causal
    }
    sources = {str(item.get("source_family") or "") for item in causal}
    unknown_scope = any(item.get("unknown_scope_axes") for item in causal)
    unknown_configuration = any(
        item.get("configuration_result") == "unknown" for item in causal
    )
    unknown_role = any(item.get("role_result") == "unknown" for item in causal)
    unknown_version = any(item.get("version_result") == "unknown" for item in causal)
    version_reasons = {str(item.get("version_reason") or "") for item in causal}
    provisional = "T3_PROVISIONAL" in tiers or any(
        not bool(item.get("identity", {}).get("strict_eligible", True))
        for item in causal
    )

    if state == "conflict_review":
        if "nvd_cna_result_conflict" in reasons:
            return (
                "C1_STRUCTURED_SOURCE_CONFLICT",
                "NVD CPE와 CNA affected 범위가 현재 질의 버전에 서로 반대 결론",
                flags,
                causal,
            )
        if "source_family_internal_conflict" in reasons:
            return (
                "C2_INTERNAL_SOURCE_CONFLICT",
                "같은 source family 내부의 affected/unaffected 또는 범위가 충돌",
                flags,
                causal,
            )
        return (
            "C3_RECONCILIATION_CONFLICT",
            "활성 assertion의 polarity 또는 authoritative reconciliation 충돌",
            flags,
            causal,
        )

    if state == "potentially_affected":
        if provisional:
            return (
                "P1_PROVISIONAL_IDENTITY",
                "제품 식별자가 잠정 alias(T3)로만 연결되어 inclusive가 후보로 수용",
                flags,
                causal,
            )
        if unknown_version and (
            "uncorroborated_cpe_wildcard" in flags
            or "literal_wildcard_only" in flags
        ):
            return (
                "P2_WILDCARD_ONLY",
                "CPE version '*'에 구체 범위 근거가 없어 모든 버전을 배제하지 못함",
                flags,
                causal,
            )
        if unknown_version and (
            "missing_or_unusable_version" in flags or "parse_failure" in flags
        ):
            return (
                "P3_VERSION_INFORMATION_MISSING",
                "버전 값이 없거나 파싱할 수 없어 해당 버전을 제외할 근거가 없음",
                flags,
                causal,
            )
        if unknown_version and version_reasons & {
            "branch_lateral_uncovered",
            "branch_below_coverage",
            "branch_above_coverage",
        }:
            return (
                "P4_BRANCH_COVERAGE_UNCERTAIN",
                "기록된 affected branch 밖의 버전을 안전하게 unaffected로 단정할 수 없음",
                flags,
                causal,
            )
        if unknown_scope or unknown_configuration:
            return (
                "P5_SCOPE_OR_CONFIGURATION_MISSING",
                "edition/component/platform 또는 AND configuration 정보가 부족해 배제 불가",
                flags,
                causal,
            )
        if unknown_role:
            return (
                "P6_CPE_ROLE_UNCERTAIN",
                "CPE leaf의 vulnerable/required 역할이 확정되지 않아 inclusive가 후보로 수용",
                flags,
                causal,
            )
        return (
            "P7_EVIDENCE_CONFIDENCE_CAP",
            "범위는 일치하지만 assertion의 최대 신뢰 상태가 potentially_affected로 제한",
            flags,
            causal,
        )

    if state == "affected":
        if provisional or (tiers and "T0_EXACT" not in tiers):
            return (
                "A1_NON_EXACT_IDENTITY_MATCH",
                "exact key가 아닌 registry/alias/cluster 경로의 positive assertion과 결합; 과병합 여부 검토 필요",
                flags,
                causal,
            )
        if "explicit_all_versions" in flags or "literal_wildcard_only" in flags:
            return (
                "A2_ALL_VERSIONS_ASSERTED",
                "source가 모든 버전 affected로 명시하여 concrete query도 포함",
                flags,
                causal,
            )
        if sources == {"llm_description"}:
            return (
                "A3_LLM_ONLY_RANGE",
                "structured 근거 없이 LLM 범위만 질의 버전을 포함",
                flags,
                causal,
            )
        return (
            "A4_STRUCTURED_RANGE_GOLD_DISAGREEMENT",
            "CNA/CPE의 exact·bounded·open range는 질의 버전을 포함하지만 Gold에는 없음",
            flags,
            causal,
        )

    return (
        "Z_OTHER_STATE",
        f"예상하지 못한 positive state: {state}",
        flags,
        causal,
    )


def evidence_rows(
    assertions: Iterable[Mapping[str, Any]],
    claims: Mapping[int, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in assertions:
        claim_id = item.get("source_claim_id")
        claim = claims.get(int(claim_id)) if claim_id is not None else None
        key = (
            claim_id,
            item.get("version_result"),
            item.get("scope_result"),
            item.get("configuration_result"),
        )
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "source": item.get("source_family"),
                "claim_id": claim_id,
                "polarity": item.get("polarity"),
                "version_result": item.get("version_result"),
                "version_reason": item.get("version_reason"),
                "version_class": item.get("version_class"),
                "scope_result": item.get("scope_result"),
                "configuration_result": item.get("configuration_result"),
                "role_result": item.get("role_result"),
                "identity_tier": item.get("identity", {}).get("tier"),
                "version_raw": claim.get("version_raw") if claim else None,
                "start_including": claim.get("version_start_including") if claim else None,
                "start_excluding": claim.get("version_start_excluding") if claim else None,
                "end_including": claim.get("version_end_including") if claim else None,
                "end_excluding": claim.get("version_end_excluding") if claim else None,
                "cpe": claim.get("cpe_criteria") if claim else None,
            }
        )
    return rows


def single_line(value: Any, *, limit: int | None = None) -> str:
    """Make prose safe to scan in a spreadsheet without embedded row breaks."""

    text = re.sub(r"\s+", " ", "" if value is None else str(value)).strip()
    if limit is not None and len(text) > limit:
        return text[: max(0, limit - 1)].rstrip() + "…"
    return text


def range_summary(item: Mapping[str, Any]) -> str:
    exact = single_line(item.get("version_raw"), limit=100)
    bounds = []
    for key, symbol in (
        ("start_including", ">="),
        ("start_excluding", ">"),
        ("end_including", "<="),
        ("end_excluding", "<"),
    ):
        value = single_line(item.get(key), limit=80)
        if value:
            bounds.append(f"{symbol}{value}")
    if bounds:
        return ",".join(bounds)
    return exact or "(version 없음)"


def compact_source_evidence(
    rows: Iterable[Mapping[str, Any]], source: str, *, max_items: int = 4
) -> str:
    """Render only a few causal assertions; full evidence lives in JSONL."""

    matching = [item for item in rows if item.get("source") == source]
    snippets: list[str] = []
    for item in matching[:max_items]:
        result = single_line(item.get("version_result")) or "?"
        reason = single_line(item.get("version_reason"), limit=80)
        if reason:
            result += f"({reason})"
        snippet = (
            f"{single_line(item.get('polarity')) or '?'} "
            f"{single_line(item.get('version_class')) or '?'} "
            f"version={result} range={range_summary(item)}"
        )
        cpe = single_line(item.get("cpe"), limit=180)
        if cpe:
            snippet += f" cpe={cpe}"
        snippets.append(single_line(snippet, limit=450))
    if len(matching) > max_items:
        snippets.append(f"(+{len(matching) - max_items}개 원본 evidence 생략)")
    return " ; ".join(snippets)


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(
            {field: single_line(row.get(field)) for field in fields} for row in rows
        )


def write_evidence_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    """Keep complete descriptions/assertions outside the human review CSV."""

    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(
                json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
            )


def write_manual_queue(
    path: Path,
    rows: list[dict[str, Any]],
    fields: list[str],
    annotation_fields: tuple[str, ...],
) -> None:
    """Rewrite evidence while preserving annotations from an earlier review."""

    key_fields = ("vendor", "product", "version", "cve_id")
    annotations: dict[tuple[str, ...], dict[str, str]] = {}
    if path.is_file():
        with path.open(newline="", encoding="utf-8-sig") as handle:
            for old in csv.DictReader(handle):
                key = tuple(str(old.get(field, "")) for field in key_fields)
                annotations[key] = {
                    field: str(old.get(field, "")) for field in annotation_fields
                }
    output: list[dict[str, Any]] = []
    for row in rows:
        key = tuple(str(row.get(field, "")) for field in key_fields)
        output.append(
            {
                **row,
                **annotations.get(
                    key, {field: "" for field in annotation_fields}
                ),
            }
        )
    write_csv(path, output, fields)


def main() -> int:
    args = parse_args()
    evaluation = args.benchmark_dir / "evaluation" / args.build
    fp_path = args.fp_csv or (evaluation / FP_NAME)
    db_path = args.benchmark_dir / f"{args.build}.sqlite"
    rows = load_fp(fp_path)
    traces = query_traces(db_path, rows, progress_every=args.progress_every)

    claim_ids = {
        int(item["source_claim_id"])
        for trace in traces.values()
        for item in trace.get("assertions", [])
        if item.get("source_claim_id") is not None
    }
    connection = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    claims = load_claims(connection, claim_ids)
    connection.close()

    detailed: list[dict[str, Any]] = []
    raw_evidence: list[dict[str, Any]] = []
    for row in rows:
        key = (row["vendor"], row["product"], row["version"], row["cve_id"])
        trace = traces[key]
        category, explanation, flags, causal = classify(trace, claims)
        sources = sorted({str(item.get("source_family")) for item in causal})
        evidence = evidence_rows(causal, claims)
        detailed.append(
            {
                **row,
                "primary_category": category,
                "explanation": explanation,
                "reason_codes": "|".join(map(str, trace.get("reason_codes", []))),
                "mechanism_flags": "|".join(sorted(flags)),
                "causal_sources": "|".join(sources),
                "last_modified": trace.get("last_modified"),
                "description_summary": single_line(
                    trace.get("description"), limit=500
                ),
                "nvd_evidence": compact_source_evidence(evidence, "nvd_cpe"),
                "cna_evidence": compact_source_evidence(
                    evidence, "cna_structured"
                ),
                "llm_evidence": compact_source_evidence(
                    evidence, "llm_description"
                ),
            }
        )
        raw_evidence.append(
            {
                "vendor": row["vendor"],
                "product": row["product"],
                "version": row["version"],
                "cve_id": row["cve_id"],
                "state": row["state"],
                "primary_category": category,
                "description": trace.get("description"),
                "evidence": evidence,
            }
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    detail_fields = [
        "vendor", "product", "version", "cve_id", "state",
        "primary_category", "explanation", "reason_codes", "mechanism_flags",
        "causal_sources", "last_modified", "description_summary",
        "nvd_evidence", "cna_evidence", "llm_evidence",
    ]
    detail_path = args.output_dir / "false_positive_details.csv"
    evidence_path = args.output_dir / "false_positive_evidence.jsonl"
    write_csv(detail_path, detailed, detail_fields)
    write_evidence_jsonl(evidence_path, raw_evidence)

    category_counts = Counter(row["primary_category"] for row in detailed)
    category_cves: dict[str, set[str]] = defaultdict(set)
    flag_counts: Counter[str] = Counter()
    flag_cves: dict[str, set[str]] = defaultdict(set)
    state_counts = Counter(row["state"] for row in detailed)
    source_counts = Counter(row["causal_sources"] for row in detailed)
    for row in detailed:
        category_cves[row["primary_category"]].add(row["cve_id"])
        for flag in filter(None, row["mechanism_flags"].split("|")):
            flag_counts[flag] += 1
            flag_cves[flag].add(row["cve_id"])

    if args.fp_csv is None:
        no_llm_fp_path = (
            args.benchmark_dir / "evaluation" / "03_current_without_llm" / FP_NAME
        )
        no_llm = {
            tuple(row)
            for row in csv.reader(
                no_llm_fp_path.open(newline="", encoding="utf-8-sig")
            )
            if row
        }
        with_llm = {
            (row["vendor"], row["product"], row["version"], row["policy"],
             row["error_type"], row["cve_id"], row["state"])
            for row in rows
        }
        llm_comparison: dict[str, Any] = {
            "same_memberships_as_03_without_llm": with_llm == no_llm,
            "only_in_04": len(with_llm - no_llm),
            "only_in_03": len(no_llm - with_llm),
        }
    else:
        llm_comparison = {
            "skipped": True,
            "reason": (
                "custom --fp-csv may use different evaluator/code state than the "
                "stored build 03 result"
            ),
        }
    summary = {
        "build": args.build,
        "definition": (
            "query-CVE predictions absent from gold; category explains the engine "
            "mechanism and is not an external factual adjudication"
        ),
        "total_fp_memberships": len(detailed),
        "unique_fp_cves": len({row["cve_id"] for row in detailed}),
        "affected_query_keys": len({(row["vendor"], row["product"], row["version"]) for row in detailed}),
        "state_counts": dict(state_counts),
        "category_counts": [
            {
                "category": category,
                "memberships": count,
                "ratio": count / len(detailed),
                "unique_cves": len(category_cves[category]),
            }
            for category, count in category_counts.most_common()
        ],
        "overlapping_mechanism_flags": [
            {
                "flag": flag,
                "memberships": count,
                "ratio": count / len(detailed),
                "unique_cves": len(flag_cves[flag]),
            }
            for flag, count in flag_counts.most_common()
        ],
        "causal_source_combinations": dict(source_counts.most_common()),
        "llm_comparison": llm_comparison,
        "files": {
            "input_false_positives": str(fp_path),
            "details": str(detail_path),
            "full_evidence": str(evidence_path),
        },
    }
    top = sorted(
        detailed,
        key=lambda row: (row["primary_category"], row["vendor"], row["product"], row["version"], row["cve_id"]),
    )
    samples: list[dict[str, Any]] = []
    sample_counts: Counter[str] = Counter()
    for row in top:
        category = row["primary_category"]
        if sample_counts[category] >= 5:
            continue
        sample_counts[category] += 1
        samples.append(row)
    write_csv(args.output_dir / "category_samples.csv", samples, detail_fields)

    queue_fields = detail_fields + [
        "review_decision", "review_notes", "reviewed_by", "reviewed_at"
    ]
    annotations = (
        "review_decision", "review_notes", "reviewed_by", "reviewed_at"
    )
    gold_candidates = [
        row
        for row in detailed
        if row["primary_category"]
        == "A4_STRUCTURED_RANGE_GOLD_DISAGREEMENT"
    ]
    nvd_cna_conflicts = [
        row
        for row in detailed
        if row["primary_category"] == "C1_STRUCTURED_SOURCE_CONFLICT"
    ]
    # This is intentionally the only missing-data review queue.  Do not add a
    # catch-all review bucket: every other mechanism keeps its explicit class.
    missing_version_review = [
        row
        for row in detailed
        if row["primary_category"] == "P3_VERSION_INFORMATION_MISSING"
    ]
    queue_paths = {
        "gold_candidates": args.output_dir / "structured_range_gold_candidates.csv",
        "nvd_cna_conflicts": args.output_dir / "nvd_cna_conflicts.csv",
        "missing_version_review": args.output_dir / "missing_version_review.csv",
    }
    write_manual_queue(
        queue_paths["gold_candidates"], gold_candidates, queue_fields, annotations
    )
    write_manual_queue(
        queue_paths["nvd_cna_conflicts"], nvd_cna_conflicts, queue_fields, annotations
    )
    write_manual_queue(
        queue_paths["missing_version_review"],
        missing_version_review,
        queue_fields,
        annotations,
    )
    summary["manual_queues"] = {
        "structured_range_gold_candidates": {
            "memberships": len(gold_candidates),
            "unique_cves": len({row["cve_id"] for row in gold_candidates}),
            "path": str(queue_paths["gold_candidates"]),
        },
        "nvd_cna_conflicts": {
            "memberships": len(nvd_cna_conflicts),
            "unique_cves": len({row["cve_id"] for row in nvd_cna_conflicts}),
            "path": str(queue_paths["nvd_cna_conflicts"]),
        },
        "missing_version_review": {
            "memberships": len(missing_version_review),
            "unique_cves": len({row["cve_id"] for row in missing_version_review}),
            "closed_category_set": True,
            "path": str(queue_paths["missing_version_review"]),
        },
    }
    # The queues are part of the summary, so persist it after queue creation.
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
