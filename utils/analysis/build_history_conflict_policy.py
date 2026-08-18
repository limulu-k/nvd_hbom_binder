#!/usr/bin/env python3
"""Build a query-time CNA/CPE conflict policy from NVD history.

The generated JSONL does not mutate CVE records or the applicability DB:

* overlapping range disagreements prefer the current (freshness-checked) CPE;
* a disjoint range is accepted only when CPE Configuration history proves that
  the product configuration was Added and not subsequently Removed;
* undecidable or otherwise unsupported conflicts remain review-only.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.nvd_normalization.history_policy import (  # noqa: E402
    POLICY_SCHEMA_VERSION,
)
from scripts.nvd_normalization.rules import normalize_key  # noqa: E402
from utils.analysis.analyze_history_cpe_version_resolutions import (  # noqa: E402
    open_text,
    parse_configuration_texts,
)


OVERLAP_RELATIONS = frozenset(
    {"cpe_broader", "cna_broader", "partial_overlap"}
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--conflicts",
        type=Path,
        required=True,
        help="cve_cpe_conflicts.py --details JSONL",
    )
    parser.add_argument(
        "--history",
        type=Path,
        default=ROOT / "data" / "nvd-cve-history" / "nvd-cve-history.jsonl.gz",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=None)
    return parser.parse_args()


def _configuration_identities(value: Any) -> set[tuple[str, str]]:
    if not isinstance(value, str):
        return set()
    products, _diagnostics = parse_configuration_texts([value])
    return {
        (product.vendor_key, product.product_key)
        for product in products
        if product.product_key
    }


def _configuration_ranges(
    value: Any,
) -> set[tuple[str, str, str | None, bool, str | None, bool]]:
    if not isinstance(value, str):
        return set()
    products, _diagnostics = parse_configuration_texts([value])
    return {
        (
            product.vendor_key,
            product.product_key,
            interval.lower,
            interval.lower_inclusive,
            interval.upper,
            interval.upper_inclusive,
        )
        for product in products
        for interval in product.intervals
        if product.product_key
    }


def _load_conflicts(path: Path) -> tuple[list[dict[str, Any]], set[str]]:
    entries: list[dict[str, Any]] = []
    wanted: set[str] = set()
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            cve_id = str(row.get("cve_id") or "").upper()
            if not cve_id:
                continue
            for pair in row.get("pairs", []):
                if not isinstance(pair, dict):
                    continue
                relation = str(pair.get("version_verdict") or "")
                if relation in {"", "equal"}:
                    continue
                cpe_identities: set[tuple[str, str]] = set()
                for raw in pair.get("cpe_identities", []):
                    if not isinstance(raw, str) or ":" not in raw:
                        continue
                    vendor, product = raw.split(":", 1)
                    normalized_identity = (
                        normalize_key(vendor),
                        normalize_key(product),
                    )
                    if normalized_identity[1]:
                        cpe_identities.add(normalized_identity)
                cna_vendor = pair.get("cna_vendor")
                cna_product = pair.get("cna_product")
                cna_identity = (
                    normalize_key(
                        None if cna_vendor is None else str(cna_vendor)
                    ),
                    normalize_key(
                        None if cna_product is None else str(cna_product)
                    ),
                )
                identities = set(cpe_identities)
                if cna_identity[1]:
                    identities.add(cna_identity)
                if not identities:
                    continue
                entries.append(
                    {
                        "cve_id": cve_id,
                        "relation": relation,
                        "identities": identities,
                        "cpe_identities": cpe_identities,
                        "cpe_ranges": {
                            (
                                normalize_key(str(item.get("vendor") or "")),
                                normalize_key(str(item.get("product") or "")),
                                item.get("lower"),
                                bool(item.get("lower_inclusive")),
                                item.get("upper"),
                                bool(item.get("upper_inclusive")),
                            )
                            for item in pair.get("cpe_ranges", [])
                            if isinstance(item, dict)
                            and normalize_key(str(item.get("product") or ""))
                        },
                        "source_line": line_number,
                    }
                )
                wanted.add(cve_id)
    return entries, wanted


def _update_rank(
    states: dict[tuple[Any, ...], dict[str, tuple[str, str]]],
    *,
    cve_id: str,
    identities: Iterable[tuple[Any, ...]],
    operation: str,
    rank: tuple[str, str],
) -> None:
    for identity in identities:
        key = (cve_id, *identity)
        state = states.setdefault(key, {})
        if rank > state.get(operation, ("", "")):
            state[operation] = rank


def _scan_active_additions(
    path: Path,
    wanted: set[str],
) -> tuple[set[tuple[Any, ...]], set[tuple[Any, ...]], Counter[str]]:
    identity_states: dict[tuple[Any, ...], dict[str, tuple[str, str]]] = {}
    range_states: dict[tuple[Any, ...], dict[str, tuple[str, str]]] = {}
    counters: Counter[str] = Counter()
    with open_text(path) as handle:
        for line in handle:
            if not line.strip():
                continue
            counters["history_rows"] += 1
            root = json.loads(line)
            change = root.get("change")
            if not isinstance(change, dict):
                continue
            cve_id = str(change.get("cveId") or "").upper()
            if cve_id not in wanted:
                continue
            created = str(change.get("created") or "")
            change_id = str(change.get("cveChangeId") or "")
            rank = (created, change_id)
            details = change.get("details")
            if not isinstance(details, list):
                continue
            for detail in details:
                if not isinstance(detail, dict):
                    continue
                if str(detail.get("type") or "") != "CPE Configuration":
                    continue
                action = str(detail.get("action") or "")
                old = _configuration_identities(detail.get("oldValue"))
                new = _configuration_identities(detail.get("newValue"))
                old_ranges = _configuration_ranges(detail.get("oldValue"))
                new_ranges = _configuration_ranges(detail.get("newValue"))
                if action == "Added":
                    _update_rank(
                        identity_states,
                        cve_id=cve_id,
                        identities=new,
                        operation="added",
                        rank=rank,
                    )
                    _update_rank(
                        range_states,
                        cve_id=cve_id,
                        identities=new_ranges,
                        operation="added",
                        rank=rank,
                    )
                    counters["added_details"] += 1
                elif action == "Removed":
                    _update_rank(
                        identity_states,
                        cve_id=cve_id,
                        identities=old,
                        operation="removed",
                        rank=rank,
                    )
                    _update_rank(
                        range_states,
                        cve_id=cve_id,
                        identities=old_ranges,
                        operation="removed",
                        rank=rank,
                    )
                    counters["removed_details"] += 1
                elif action == "Changed":
                    _update_rank(
                        identity_states,
                        cve_id=cve_id,
                        identities=new - old,
                        operation="added",
                        rank=rank,
                    )
                    _update_rank(
                        identity_states,
                        cve_id=cve_id,
                        identities=old - new,
                        operation="removed",
                        rank=rank,
                    )
                    _update_rank(
                        range_states,
                        cve_id=cve_id,
                        identities=new_ranges - old_ranges,
                        operation="added",
                        rank=rank,
                    )
                    _update_rank(
                        range_states,
                        cve_id=cve_id,
                        identities=old_ranges - new_ranges,
                        operation="removed",
                        rank=rank,
                    )
                    counters["changed_details"] += 1
    active_identities = {
        key
        for key, state in identity_states.items()
        if state.get("added", ("", "")) > state.get("removed", ("", ""))
    }
    active_ranges = {
        key
        for key, state in range_states.items()
        if state.get("added", ("", "")) > state.get("removed", ("", ""))
    }
    counters["active_added_product_configurations"] = len(active_identities)
    counters["active_added_version_ranges"] = len(active_ranges)
    return active_identities, active_ranges, counters


def build_policy(
    conflicts: Path,
    history: Path,
    output: Path,
    report: Path | None,
) -> dict[str, Any]:
    entries, wanted = _load_conflicts(conflicts)
    active_additions, active_added_ranges, history_counts = (
        _scan_active_additions(history, wanted)
    )
    action_counts: Counter[str] = Counter()
    decisions: list[dict[str, Any]] = []
    product_actions: dict[tuple[str, str], set[str]] = defaultdict(set)
    for entry in entries:
        relation = entry["relation"]
        if relation in OVERLAP_RELATIONS:
            action = "prefer_latest_cpe"
            basis = "history_current_cpe_overlap"
        else:
            ranges_available = bool(entry["cpe_ranges"])
            added = (
                any(
                    (entry["cve_id"], *version_range) in active_added_ranges
                    for version_range in entry["cpe_ranges"]
                )
                if ranges_available
                else any(
                    (entry["cve_id"], vendor, product) in active_additions
                    for vendor, product in entry["cpe_identities"]
                )
            )
            if relation == "disjoint" and added:
                action = "accept_added_range"
                basis = (
                    "history_cpe_version_range_added"
                    if ranges_available
                    else "history_cpe_configuration_added_identity_fallback"
                )
            else:
                action = "conflict_review"
                basis = "history_evidence_insufficient"
        action_counts[action] += 1
        decision = dict(entry)
        decision["action"] = action
        decision["basis"] = basis
        decisions.append(decision)
        for _vendor, product in entry["identities"]:
            product_actions[(entry["cve_id"], product)].add(action)

    safe_product_counts: Counter[str] = Counter()
    for actions in product_actions.values():
        if len(actions) == 1:
            action = next(iter(actions))
            if action != "conflict_review":
                safe_product_counts[action] += 1

    output.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    suppressed_rows = 0
    suppressed_identities = 0
    temporary_output = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        with temporary_output.open("x", encoding="utf-8") as handle:
            for entry in decisions:
                relation = entry["relation"]
                action = entry["action"]
                basis = entry["basis"]
                if action == "conflict_review":
                    suppressed_rows += 1
                    continue
                # Query lookup deliberately has a product-only fallback for
                # vendor spelling drift.  Therefore a decision is safe only
                # when every conflict pair for this CVE/product reaches the
                # same actionable result.  A sibling undecidable/disjoint/
                # overlap decision must not adjudicate an unrelated range.
                safe_identities = {
                    (vendor, product)
                    for vendor, product in entry["identities"]
                    if product_actions[(entry["cve_id"], product)] == {action}
                }
                suppressed_identities += len(entry["identities"]) - len(
                    safe_identities
                )
                if not safe_identities:
                    suppressed_rows += 1
                    continue
                row = {
                    "schema_version": POLICY_SCHEMA_VERSION,
                    "cve_id": entry["cve_id"],
                    "action": action,
                    "relation": relation,
                    "basis": basis,
                    "identities": [
                        {"vendor": vendor, "product": product}
                        for vendor, product in sorted(safe_identities)
                    ],
                }
                handle.write(
                    json.dumps(
                        row, ensure_ascii=False, separators=(",", ":")
                    )
                    + "\n"
                )
                written += 1
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_output, output)
    except BaseException:
        temporary_output.unlink(missing_ok=True)
        raise
    summary = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "conflicts": str(conflicts),
        "history": str(history),
        "output": str(output),
        "wanted_cves": len(wanted),
        "policy_rows": written,
        "conflict_pairs_seen": len(entries),
        "actions": dict(action_counts),
        "safe_actionable_products": dict(safe_product_counts),
        "suppressed_policy_rows": suppressed_rows,
        "suppressed_policy_identities": suppressed_identities,
        "history_scan": dict(history_counts),
    }
    if report is not None:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return summary


def main() -> int:
    args = parse_args()
    if not args.conflicts.is_file():
        raise FileNotFoundError(args.conflicts)
    if not args.history.is_file():
        raise FileNotFoundError(args.history)
    summary = build_policy(
        args.conflicts,
        args.history,
        args.output,
        args.report,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
