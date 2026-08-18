#!/usr/bin/env python3
"""Find CNA/CPE version conflicts that NVD Change History resolved.

The history API renders CPE Configuration values as human-readable text.  This
script parses the common NVD forms, compares each event's old/new CPE ranges to
the *current* CNA affected ranges with the same interval engine used by
``cve_cpe_conflicts.py``, and verifies whether the current snapshot still has
an equal range.  Results are evidence about NVD analyst CPE corrections; they
do not imply that CNA text was edited or that either source is authoritative.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import gzip
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.analysis.cve_cpe_conflicts import (  # noqa: E402
    CpeProduct,
    Interval,
    _tokens,
    _undecidable_reason,
    compare_interval_sets,
    extract_cna_products,
    match_identity,
    parse_cpe_criteria,
    segment_to_interval,
)
from scripts.nvd_normalization.rules import normalize_key  # noqa: E402
from scripts.nvd_normalization.versioning import (  # noqa: E402
    compile_nvd,
    profile_for,
)


CPE_RE = re.compile(
    r"(?P<criteria>cpe:2\.3:\S+?)(?=(?:\s+versions\b)|(?:\s*$))",
    re.IGNORECASE,
)
BETWEEN_RE = re.compile(
    r"versions\s+from\s+\((including|excluding)\)\s+(\S+)\s+"
    r"up\s+to\s+\((including|excluding)\)\s+(\S+)",
    re.IGNORECASE,
)
UPPER_RE = re.compile(
    r"versions\s+up\s+to\s+\((including|excluding)\)\s+(\S+)",
    re.IGNORECASE,
)
LOWER_RE = re.compile(
    r"versions\s+from\s+\((including|excluding)\)\s+(\S+)",
    re.IGNORECASE,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", type=Path, default=ROOT / "data" / "nvd-cves.jsonl"
    )
    parser.add_argument(
        "--history",
        type=Path,
        default=ROOT / "data" / "nvd-cve-history" / "nvd-cve-history.jsonl.gz",
    )
    parser.add_argument(
        "--current-conflicts",
        type=Path,
        default=(
            ROOT
            / "workspace"
            / "benchmark"
            / "analysis"
            / "09_cve_cpe_conflicts_current.jsonl"
        ),
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=(
            ROOT
            / "workspace"
            / "benchmark"
            / "analysis"
            / "10_history_cpe_resolution_summary.json"
        ),
    )
    parser.add_argument(
        "--details-out",
        type=Path,
        default=(
            ROOT
            / "workspace"
            / "benchmark"
            / "analysis"
            / "10_history_cpe_resolution_details.jsonl"
        ),
    )
    return parser.parse_args()


def open_text(path: Path):
    return gzip.open(path, "rt", encoding="utf-8") if path.name.endswith(".gz") else path.open(encoding="utf-8")


def record_of(root: dict[str, Any]) -> dict[str, Any] | None:
    value = root.get("cve", root)
    return value if isinstance(value, dict) else None


def parse_configuration_texts(texts: Iterable[str]) -> tuple[list[CpeProduct], Counter[str]]:
    grouped: dict[tuple[str, str], CpeProduct] = {}
    diagnostics: Counter[str] = Counter()
    for text in texts:
        if not isinstance(text, str):
            diagnostics["non_string"] += 1
            continue
        for line in text.splitlines():
            match = CPE_RE.search(line.strip())
            if match is None:
                continue
            criteria = match.group("criteria").rstrip(",.;")
            parsed = parse_cpe_criteria(criteria)
            if parsed is None:
                diagnostics["invalid_cpe"] += 1
                continue
            _part, vendor, product, version = parsed
            tail = line[match.end() :]
            start_including = start_excluding = None
            end_including = end_excluding = None
            bounded = BETWEEN_RE.search(tail)
            upper = UPPER_RE.search(tail)
            lower = LOWER_RE.search(tail)
            if bounded:
                lower_kind, lower_value, upper_kind, upper_value = bounded.groups()
                if lower_kind.casefold() == "including":
                    start_including = lower_value
                else:
                    start_excluding = lower_value
                if upper_kind.casefold() == "including":
                    end_including = upper_value
                else:
                    end_excluding = upper_value
            elif upper:
                kind, value = upper.groups()
                if kind.casefold() == "including":
                    end_including = value
                else:
                    end_excluding = value
            elif lower:
                kind, value = lower.groups()
                if kind.casefold() == "including":
                    start_including = value
                else:
                    start_excluding = value
            elif "versions" in tail.casefold():
                diagnostics["unsupported_version_phrase"] += 1

            vendor_key, product_key = normalize_key(vendor), normalize_key(product)
            compiled = compile_nvd(
                cpe_version=version,
                status="affected",
                product_key=product_key,
                version_start_including=start_including,
                version_start_excluding=start_excluding,
                version_end_including=end_including,
                version_end_excluding=end_excluding,
            )
            bucket = grouped.get((vendor_key, product_key))
            if bucket is None:
                bucket = CpeProduct(
                    vendor_key=vendor_key,
                    product_key=product_key,
                    tokens=_tokens(vendor, product),
                    intervals=[],
                    blockers=Counter(),
                )
                grouped[(vendor_key, product_key)] = bucket
            if compiled.parse_status != "parsed":
                bucket.blockers["unparsed_expression"] += 1
                diagnostics["compile_unparsed"] += 1
                continue
            for segment in compiled.segments:
                interval = segment_to_interval(segment)
                if interval is None:
                    bucket.blockers[compiled.version_class.casefold()] += 1
                    diagnostics["interval_unusable"] += 1
                else:
                    bucket.intervals.append(interval)
            diagnostics["parsed_cpe_lines"] += 1
    return list(grouped.values()), diagnostics


def pair_verdict(cna: Any, cpes: list[CpeProduct]) -> tuple[str, str]:
    level, matched = match_identity(cna, cpes)
    if level == "none" or not matched:
        return "not_compared", level
    intervals: list[Interval] = [item for product in matched for item in product.intervals]
    blockers: Counter[str] = Counter()
    for product in matched:
        blockers.update(product.blockers)
    reason = _undecidable_reason(cna, intervals, blockers)
    if reason is not None:
        return f"undecidable:{reason}", level
    profile = profile_for(
        [
            bound
            for interval in (*cna.intervals, *intervals)
            for bound in (interval.lower, interval.upper)
        ],
        version_type=None,
        product_key=cna.product_key,
    )
    return compare_interval_sets(cna.intervals, intervals, profile), level


def history_events(path: Path) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    output: dict[str, list[dict[str, Any]]] = defaultdict(list)
    counters: Counter[str] = Counter()
    with open_text(path) as handle:
        for line in handle:
            if not line.strip():
                continue
            counters["history_rows"] += 1
            change = json.loads(line).get("change")
            if not isinstance(change, dict):
                continue
            details = change.get("details")
            if not isinstance(details, list):
                continue
            old_values: list[str] = []
            new_values: list[str] = []
            detail_rows: list[dict[str, Any]] = []
            for detail in details:
                if not isinstance(detail, dict) or str(detail.get("type")) != "CPE Configuration":
                    continue
                action = str(detail.get("action") or "")
                old = detail.get("oldValue")
                new = detail.get("newValue")
                if action in {"Changed", "Removed"} and isinstance(old, str):
                    old_values.append(old)
                if action in {"Changed", "Added"} and isinstance(new, str):
                    new_values.append(new)
                detail_rows.append(detail)
            if not old_values or not new_values:
                continue
            cve_id = str(change.get("cveId") or "").upper()
            output[cve_id].append(
                {
                    "created": change.get("created"),
                    "event_name": change.get("eventName"),
                    "old_values": old_values,
                    "new_values": new_values,
                    "details": detail_rows,
                }
            )
            counters["replacement_events"] += 1
    counters["replacement_cves"] = len(output)
    return output, dict(counters)


def current_pair_verdicts(path: Path) -> dict[tuple[str, str, str], str]:
    output: dict[tuple[str, str, str], str] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            cve_id = str(row["cve_id"])
            for pair in row.get("pairs", []):
                output[(cve_id, normalize_key(pair.get("cna_vendor")), normalize_key(pair.get("cna_product")))] = str(
                    pair.get("version_verdict")
                )
    return output


def main() -> int:
    args = parse_args()
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.details_out.parent.mkdir(parents=True, exist_ok=True)
    events, history_summary = history_events(args.history)
    wanted = set(events)
    records: dict[str, dict[str, Any]] = {}
    with args.input.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = record_of(json.loads(line))
            if record is None:
                continue
            cve_id = str(record.get("id") or "").upper()
            if cve_id in wanted:
                records[cve_id] = record
    current_verdicts = current_pair_verdicts(args.current_conflicts)

    transition_counts: Counter[str] = Counter()
    diagnostics: Counter[str] = Counter()
    details_out: list[dict[str, Any]] = []
    strict_resolved_cves: set[str] = set()
    strict_version_resolved_cves: set[str] = set()
    strict_version_resolved_events = 0
    ever_resolved_cves: set[str] = set()
    for cve_id, cve_events in sorted(events.items()):
        record = records.get(cve_id)
        if record is None:
            diagnostics["current_record_missing"] += 1
            continue
        cna_products = extract_cna_products(record)
        if not cna_products:
            diagnostics["current_cna_missing"] += 1
            continue
        for event in sorted(cve_events, key=lambda item: str(item["created"])):
            old_cpes, old_diag = parse_configuration_texts(event["old_values"])
            new_cpes, new_diag = parse_configuration_texts(event["new_values"])
            diagnostics.update({f"old_{key}": value for key, value in old_diag.items()})
            diagnostics.update({f"new_{key}": value for key, value in new_diag.items()})
            if not old_cpes or not new_cpes:
                diagnostics["event_unparsed"] += 1
                continue
            for cna in cna_products:
                old_verdict, old_identity = pair_verdict(cna, old_cpes)
                new_verdict, new_identity = pair_verdict(cna, new_cpes)
                if old_verdict == "not_compared" and new_verdict == "not_compared":
                    continue
                current = current_verdicts.get(
                    (cve_id, cna.vendor_key, cna.product_key), "missing"
                )
                if old_verdict != "equal" and new_verdict == "equal":
                    transition = "conflict_to_equal"
                    ever_resolved_cves.add(cve_id)
                    if current == "equal":
                        strict_resolved_cves.add(cve_id)
                        if (
                            old_verdict
                            in {
                                "cpe_broader",
                                "cna_broader",
                                "partial_overlap",
                                "disjoint",
                                "scheme_mismatch",
                            }
                            and old_identity != "none"
                            and new_identity != "none"
                        ):
                            strict_version_resolved_cves.add(cve_id)
                            strict_version_resolved_events += 1
                elif old_verdict == "equal" and new_verdict != "equal":
                    transition = "equal_to_conflict"
                elif old_verdict == "equal" and new_verdict == "equal":
                    transition = "equal_to_equal"
                elif old_verdict != new_verdict:
                    transition = "conflict_changed_not_equal"
                else:
                    transition = "conflict_unchanged"
                transition_counts[transition] += 1
                details_out.append(
                    {
                        "cve_id": cve_id,
                        "created": event["created"],
                        "event_name": event["event_name"],
                        "cna_vendor": cna.vendor,
                        "cna_product": cna.product,
                        "old_identity_level": old_identity,
                        "new_identity_level": new_identity,
                        "old_verdict": old_verdict,
                        "new_verdict": new_verdict,
                        "current_verdict": current,
                        "transition": transition,
                        "old_values": event["old_values"],
                        "new_values": event["new_values"],
                    }
                )

    with args.details_out.open("w", encoding="utf-8") as handle:
        for row in details_out:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    strict_examples = [
        row
        for row in details_out
        if row["transition"] == "conflict_to_equal" and row["current_verdict"] == "equal"
    ][:50]
    strict_version_examples = [
        row
        for row in details_out
        if row["transition"] == "conflict_to_equal"
        and row["current_verdict"] == "equal"
        and row["old_verdict"]
        in {
            "cpe_broader",
            "cna_broader",
            "partial_overlap",
            "disjoint",
            "scheme_mismatch",
        }
        and row["old_identity_level"] != "none"
        and row["new_identity_level"] != "none"
    ][:50]
    report = {
        "definition": {
            "history_resolved_event": "old CPE vs current CNA is non-equal; new CPE vs current CNA is equal",
            "strict_current_resolution": "history_resolved_event and current CNA/CPE pair remains equal",
            "caveat": "current CNA is used as the comparison anchor; CNA may itself have changed after the event",
        },
        "history": history_summary,
        "current_records_loaded": len(records),
        "evaluated_pair_events": len(details_out),
        "transition_counts": dict(transition_counts),
        "ever_resolved_unique_cves": len(ever_resolved_cves),
        "strict_current_resolved_unique_cves": len(strict_resolved_cves),
        "strict_current_resolved_cve_ids": sorted(strict_resolved_cves),
        "strict_version_conflict_resolved_pair_events": strict_version_resolved_events,
        "strict_version_conflict_resolved_unique_cves": len(
            strict_version_resolved_cves
        ),
        "strict_version_conflict_resolved_cve_ids": sorted(
            strict_version_resolved_cves
        ),
        "diagnostics": dict(diagnostics),
        "strict_examples": strict_examples,
        "strict_version_examples": strict_version_examples,
        "files": {"details": str(args.details_out)},
    }
    args.json_out.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
