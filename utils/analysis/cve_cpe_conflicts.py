#!/usr/bin/env python3
"""Count CNA(CVE) vs NVD(CPE) conflicts across an NVD JSON 2.0 JSONL dump.

Two conflict families are measured, per CVE record:

1. Identity conflict
   ``affected[].affectedData[].vendor/product`` (CNA-declared identifier)
   versus the vendor/product fields of ``configurations[].nodes[].cpeMatch[]``
   criteria (NVD-assigned CPE identifier).  Matching is graded:
   ``exact`` -> ``product_only`` -> ``vendor_only`` -> ``loose`` (token
   containment) -> ``none``.  The levels are also projected onto independent
   vendor/product conflict flags, yielding the mutually exclusive CVE classes
   ``none`` / ``vendor_only`` / ``product_only`` / ``vendor_and_product``.

2. Version-range conflict
   ``affected[].affectedData[].versions[]`` (version / lessThan /
   lessThanOrEqual / comparator expressions) versus the CPE version axis
   (``versionStartIncluding`` etc.).  Both sides are compiled into intervals
   with the pipeline compilers in ``scripts.nvd_normalization.versioning`` and
   compared as interval sets: ``equal`` / ``cpe_broader`` / ``cna_broader`` /
   ``partial_overlap`` / ``disjoint``.

Version ranges are only compared for product entries that could be paired by
identity, since comparing ranges of two different products is meaningless.

Usage:
    python3 utils/analysis/cve_cpe_conflicts.py
    python3 utils/analysis/cve_cpe_conflicts.py --limit 20000 --samples 5
    python3 utils/analysis/cve_cpe_conflicts.py --json-out report.json \
        --details data/cve_cpe_conflicts.jsonl
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import re
import sys
from collections import Counter
from dataclasses import dataclass
from functools import cmp_to_key
from itertools import islice
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.nvd_normalization.rules import (  # noqa: E402
    is_placeholder,
    normalize_key,
)
from scripts.nvd_normalization.builder import (  # noqa: E402
    _duplicate_loser_indexes,
)
from scripts.nvd_normalization.versioning import (  # noqa: E402
    Segment,
    compare_versions,
    compile_cna,
    compile_nvd,
    profile_for,
    version_kind,
)

DEFAULT_INPUT = Path("data/nvd-cves.jsonl")
CHUNK_LINES = 2_000

IDENTITY_LEVELS = ("exact", "product_only", "vendor_only", "loose", "none")
IDENTITY_RANK = {level: index for index, level in enumerate(IDENTITY_LEVELS)}
IDENTITY_CONFLICT_CLASSES = (
    "none",
    "vendor_only",
    "product_only",
    "vendor_and_product",
)

# Worst-first: the CVE-level verdict is the worst verdict among its pairs.
VERSION_VERDICTS = (
    "scheme_mismatch",
    "disjoint",
    "partial_overlap",
    "cna_broader",
    "cpe_broader",
    "equal",
)
VERSION_RANK = {verdict: index for index, verdict in enumerate(VERSION_VERDICTS)}
CONFLICTING_VERDICTS = frozenset(VERSION_VERDICTS) - {"equal"}
HARD_CONFLICT_VERDICTS = frozenset({"disjoint", "partial_overlap", "scheme_mismatch"})

_CPE_ESCAPE_RE = re.compile(r"\\(.)")
# "10.0.19042.1706" and "1.5.20-7" are numeric scales; "20h2" and "sp1" are not.
_NUMERIC_SCALE_RE = re.compile(r"(?i)^v?\d+([._+-].*)?$")
_TOKEN_SPLIT_RE = re.compile(r"[^0-9a-z]+")
# Vendor/product words that carry no identifying signal for loose matching.
_STOP_TOKENS = frozenset(
    {
        "co",
        "corp",
        "corporation",
        "foundation",
        "gmbh",
        "group",
        "inc",
        "labs",
        "limited",
        "llc",
        "ltd",
        "open",
        "project",
        "software",
        "solutions",
        "source",
        "systems",
        "technologies",
        "technology",
    }
)


# --------------------------------------------------------------------------
# intervals
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Interval:
    """Half-open/closed version interval; ``None`` bound means unbounded."""

    lower: str | None
    lower_inclusive: bool
    upper: str | None
    upper_inclusive: bool


UNBOUNDED = Interval(None, False, None, False)


def _cmp_lower(left: Interval, right: Interval, profile: str) -> int:
    if left.lower is None or right.lower is None:
        if left.lower is None and right.lower is None:
            return 0
        return -1 if left.lower is None else 1
    decided = compare_versions(left.lower, right.lower, profile)
    if decided:
        return decided
    if left.lower_inclusive == right.lower_inclusive:
        return 0
    # An inclusive lower bound starts before an exclusive one at the same value.
    return -1 if left.lower_inclusive else 1


def _cmp_upper(left: Interval, right: Interval, profile: str) -> int:
    if left.upper is None or right.upper is None:
        if left.upper is None and right.upper is None:
            return 0
        return 1 if left.upper is None else -1
    decided = compare_versions(left.upper, right.upper, profile)
    if decided:
        return decided
    if left.upper_inclusive == right.upper_inclusive:
        return 0
    # An inclusive upper bound ends after an exclusive one at the same value.
    return 1 if left.upper_inclusive else -1


def _touches_or_overlaps(current: Interval, following: Interval, profile: str) -> bool:
    """True when ``following`` (sorted after ``current``) continues it."""

    if current.upper is None or following.lower is None:
        return True
    decided = compare_versions(following.lower, current.upper, profile)
    if decided < 0:
        return True
    if decided > 0:
        return False
    return current.upper_inclusive or following.lower_inclusive


def merge_intervals(intervals: Sequence[Interval], profile: str) -> list[Interval]:
    """Sort and coalesce into a disjoint, non-touching interval set."""

    if not intervals:
        return []
    ordered = sorted(
        intervals,
        key=cmp_to_key(
            lambda left, right: _cmp_lower(left, right, profile)
            or _cmp_upper(left, right, profile)
        ),
    )
    merged = [ordered[0]]
    for candidate in ordered[1:]:
        current = merged[-1]
        if not _touches_or_overlaps(current, candidate, profile):
            merged.append(candidate)
            continue
        if _cmp_upper(candidate, current, profile) > 0:
            merged[-1] = Interval(
                current.lower,
                current.lower_inclusive,
                candidate.upper,
                candidate.upper_inclusive,
            )
    return merged


def _contains(outer: Interval, inner: Interval, profile: str) -> bool:
    return (
        _cmp_lower(outer, inner, profile) <= 0
        and _cmp_upper(outer, inner, profile) >= 0
    )


def covers(merged: Sequence[Interval], inner: Interval, profile: str) -> bool:
    """True when a merged (disjoint) interval set fully contains ``inner``."""

    return any(_contains(outer, inner, profile) for outer in merged)


def _overlaps(left: Interval, right: Interval, profile: str) -> bool:
    lower, upper = (left, right) if _cmp_lower(left, right, profile) <= 0 else (right, left)
    return _touches_or_overlaps(lower, upper, profile)


def _version_scales(intervals: Iterable[Interval]) -> frozenset[str]:
    return frozenset(
        "numeric" if _NUMERIC_SCALE_RE.match(bound) else "token"
        for interval in intervals
        for bound in (interval.lower, interval.upper)
        if bound is not None
    )


def _scheme_mismatch(cna: Sequence[Interval], cpe: Sequence[Interval]) -> bool:
    """True when the two sides number their releases on incompatible scales.

    Microsoft states ``10.0.0 <= v < 10.0.19042.1706`` while its CPE says
    ``20h2``: the ordering between them is undefined, so their emptiness of
    intersection is an artefact of the scale, not a range disagreement.
    """

    left, right = _version_scales(cna), _version_scales(cpe)
    return bool(left) and bool(right) and not (left & right)


def compare_interval_sets(
    cna: Sequence[Interval], cpe: Sequence[Interval], profile: str
) -> str:
    """Classify how the CNA interval set relates to the CPE interval set."""

    cna_merged = merge_intervals(cna, profile)
    cpe_merged = merge_intervals(cpe, profile)
    cna_covered = all(covers(cpe_merged, item, profile) for item in cna_merged)
    cpe_covered = all(covers(cna_merged, item, profile) for item in cpe_merged)
    if cna_covered and cpe_covered:
        return "equal"
    if cna_covered:
        return "cpe_broader"
    if cpe_covered:
        return "cna_broader"
    for left in cna_merged:
        for right in cpe_merged:
            if _overlaps(left, right, profile):
                return "partial_overlap"
    return "scheme_mismatch" if _scheme_mismatch(cna, cpe) else "disjoint"


def segment_to_interval(segment: Segment) -> Interval | None:
    """Map a compiled segment to an interval, or ``None`` when it carries none."""

    if segment.exact is not None:
        return Interval(segment.exact, True, segment.exact, True)
    if segment.lower is not None or segment.upper is not None:
        return Interval(
            segment.lower,
            bool(segment.lower_inclusive),
            segment.upper,
            bool(segment.upper_inclusive),
        )
    if segment.breadth_class == "unbounded":
        return UNBOUNDED
    return None


def interval_state(interval: Interval, profile: str) -> str:
    """``ok``, or the reason this interval cannot be compared honestly.

    Free text such as ``"before 1.5.20-7"`` or ``"all 5.3.x releases"`` is
    stored in the same ``version`` field as real versions; comparing it as if
    it were a version number manufactures conflicts, so it is fenced off here.
    """

    for bound in (interval.lower, interval.upper):
        if bound is not None and version_kind(bound) != "exact":
            return "unsupported_version_token"
    if interval.lower is None or interval.upper is None:
        return "ok"
    decided = compare_versions(interval.lower, interval.upper, profile)
    if decided > 0:
        return "inverted_bounds"
    if decided == 0 and not (interval.lower_inclusive and interval.upper_inclusive):
        # e.g. Google CNA emits ``version == lessThan``, an empty range.
        return "degenerate_empty_range"
    return "ok"


# --------------------------------------------------------------------------
# record extraction
# --------------------------------------------------------------------------


@dataclass(slots=True)
class CnaProduct:
    vendor: str | None
    product: str | None
    vendor_key: str
    product_key: str
    tokens: frozenset[str]
    intervals: list[Interval]
    blockers: Counter
    inverted_default_status: bool


@dataclass(slots=True)
class CpeProduct:
    vendor_key: str
    product_key: str
    tokens: frozenset[str]
    intervals: list[Interval]
    blockers: Counter


def _tokens(*values: str | None) -> frozenset[str]:
    collected: set[str] = set()
    for value in values:
        if not value:
            continue
        for token in _TOKEN_SPLIT_RE.split(normalize_key(value)):
            if token and token not in _STOP_TOKENS:
                collected.add(token)
    return frozenset(collected)


def parse_cpe_criteria(criteria: str) -> tuple[str, str, str, str] | None:
    """Return ``(part, vendor, product, version)`` from a cpe:2.3 URI."""

    if not criteria.startswith("cpe:2.3:"):
        return None
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in criteria[len("cpe:2.3:") :]:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    if len(fields) < 4:
        return None
    part, vendor, product = fields[0], fields[1], fields[2]
    version = fields[3] if len(fields) > 3 else "*"
    unescape = lambda value: _CPE_ESCAPE_RE.sub(r"\1", value)  # noqa: E731
    return part, unescape(vendor), unescape(product), unescape(version)


def extract_cna_products(record: dict[str, Any]) -> list[CnaProduct]:
    products: list[CnaProduct] = []
    for container in record.get("affected") or []:
        for entry in container.get("affectedData") or []:
            vendor = entry.get("vendor")
            product = entry.get("product")
            product_key = normalize_key(product)
            default_status = (entry.get("defaultStatus") or "").casefold()
            intervals: list[Interval] = []
            blockers: Counter = Counter()
            for version in entry.get("versions") or []:
                status = (version.get("status") or "").casefold()
                if status != "affected":
                    continue
                compiled = compile_cna(
                    version=version.get("version"),
                    status=status,
                    product_key=product_key,
                    less_than=version.get("lessThan"),
                    less_than_or_equal=version.get("lessThanOrEqual"),
                    version_type=version.get("versionType"),
                    changes=version.get("changes") or [],
                )
                if compiled.parse_status != "parsed":
                    blockers["unparsed_expression"] += 1
                    continue
                for segment in compiled.segments:
                    interval = segment_to_interval(segment)
                    if interval is None:
                        blockers[compiled.version_class.casefold()] += 1
                        continue
                    state = interval_state(interval, compiled.profile)
                    if state != "ok":
                        blockers[state] += 1
                        continue
                    intervals.append(interval)
            products.append(
                CnaProduct(
                    vendor=vendor,
                    product=product,
                    vendor_key=normalize_key(vendor),
                    product_key=product_key,
                    tokens=_tokens(vendor, product),
                    intervals=intervals,
                    blockers=blockers,
                    # ``defaultStatus: affected`` means "everything except the
                    # listed unaffected versions", which the listed intervals
                    # alone cannot express.
                    inverted_default_status=default_status == "affected",
                )
            )
    return products


def extract_cpe_products(record: dict[str, Any]) -> list[CpeProduct]:
    grouped: dict[tuple[str, str], CpeProduct] = {}
    for configuration in record.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", True):
                    continue
                parsed = parse_cpe_criteria(match.get("criteria") or "")
                if parsed is None:
                    continue
                _, vendor, product, version = parsed
                vendor_key = normalize_key(vendor)
                product_key = normalize_key(product)
                compiled = compile_nvd(
                    cpe_version=version,
                    status="affected",
                    product_key=product_key,
                    version_start_including=match.get("versionStartIncluding"),
                    version_start_excluding=match.get("versionStartExcluding"),
                    version_end_including=match.get("versionEndIncluding"),
                    version_end_excluding=match.get("versionEndExcluding"),
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
                for segment in compiled.segments:
                    interval = segment_to_interval(segment)
                    if interval is None:
                        bucket.blockers[compiled.version_class.casefold()] += 1
                        continue
                    state = interval_state(interval, compiled.profile)
                    if state != "ok":
                        bucket.blockers[state] += 1
                        continue
                    bucket.intervals.append(interval)
    return list(grouped.values())


# --------------------------------------------------------------------------
# identity matching
# --------------------------------------------------------------------------


def _loose_match(cna: CnaProduct, cpe: CpeProduct) -> bool:
    if not cna.tokens or not cpe.tokens:
        return False
    return cna.tokens <= cpe.tokens or cpe.tokens <= cna.tokens


def match_identity(
    cna: CnaProduct, cpe_products: Sequence[CpeProduct]
) -> tuple[str, list[CpeProduct]]:
    """Best identity level for one CNA product plus the CPE entries it hits."""

    exact = [
        item
        for item in cpe_products
        if item.vendor_key == cna.vendor_key and item.product_key == cna.product_key
    ]
    if exact:
        return "exact", exact
    product_only = [
        item for item in cpe_products if item.product_key == cna.product_key
    ]
    if product_only:
        return "product_only", product_only
    vendor_only = [
        item for item in cpe_products if item.vendor_key == cna.vendor_key
    ]
    if vendor_only:
        return "vendor_only", vendor_only
    loose = [item for item in cpe_products if _loose_match(cna, item)]
    if loose:
        return "loose", loose
    return "none", []


def identity_conflict_axes(level: str) -> tuple[bool, bool]:
    """Return ``(vendor_conflict, product_conflict)`` for a match level.

    ``product_only`` means that only the product matched, hence the vendor is
    the conflicting axis.  Conversely ``vendor_only`` means a product-axis
    conflict.  A loose or absent match leaves both identifiers inconsistent.
    """

    if level == "exact":
        return False, False
    if level == "product_only":
        return True, False
    if level == "vendor_only":
        return False, True
    return True, True


def identity_conflict_class(vendor_conflict: bool, product_conflict: bool) -> str:
    if vendor_conflict and product_conflict:
        return "vendor_and_product"
    if vendor_conflict:
        return "vendor_only"
    if product_conflict:
        return "product_only"
    return "none"


# --------------------------------------------------------------------------
# per-record analysis
# --------------------------------------------------------------------------


def _undecidable_reason(
    cna: CnaProduct, cpe_intervals: Sequence[Interval], cpe_blockers: Counter
) -> str | None:
    """Why this pair's ranges cannot be compared, or ``None`` if they can.

    A single unusable version entry disqualifies the whole product entry: a
    partially-read CNA range set would look narrower than it is, and the
    verdict would be an artefact rather than a finding.
    """

    if cna.inverted_default_status:
        # defaultStatus=affected means "all versions except the listed
        # unaffected ones", which the listed intervals do not express.
        return "cna_inverted_default_status"
    if cna.blockers:
        return f"cna_{cna.blockers.most_common(1)[0][0]}"
    if not cna.intervals:
        return "cna_no_affected_versions"
    if cpe_blockers:
        return f"cpe_{cpe_blockers.most_common(1)[0][0]}"
    if not cpe_intervals:
        return "cpe_no_version_axis"
    return None


def analyze_record(record: dict[str, Any]) -> dict[str, Any]:
    cve_id = record.get("id") or ""
    cna_products = extract_cna_products(record)
    cpe_products = extract_cpe_products(record)
    named_cna = [
        item
        for item in cna_products
        if item.product_key and not is_placeholder(item.product)
    ]

    result: dict[str, Any] = {
        "cve_id": cve_id,
        "cna_product_count": len(cna_products),
        "named_cna_product_count": len(named_cna),
        "cpe_product_count": len(cpe_products),
        "comparable": bool(named_cna and cpe_products),
        "identity_level": None,
        "identity_levels": Counter(),
        "identity_conflict": False,
        "vendor_conflict": False,
        "product_conflict": False,
        "identity_conflict_class": None,
        "version_verdict": None,
        "version_verdicts": Counter(),
        "undecidable_reasons": Counter(),
        "version_conflict": False,
        "version_hard_conflict": False,
        "version_undecidable": False,
        "skip_reason": None,
        "pairs": [],
    }

    if not named_cna and not cpe_products:
        result["skip_reason"] = "no_cna_and_no_cpe"
        return result
    if not named_cna:
        result["skip_reason"] = "no_named_cna_product"
        return result
    if not cpe_products:
        result["skip_reason"] = "no_cpe"
        return result

    worst_identity = "exact"
    worst_version: str | None = None
    undecidable = False
    vendor_conflict = False
    product_conflict = False

    for cna in named_cna:
        level, matched = match_identity(cna, cpe_products)
        pair_vendor_conflict, pair_product_conflict = identity_conflict_axes(level)
        vendor_conflict = vendor_conflict or pair_vendor_conflict
        product_conflict = product_conflict or pair_product_conflict
        result["identity_levels"][level] += 1
        if IDENTITY_RANK[level] > IDENTITY_RANK[worst_identity]:
            worst_identity = level
        pair: dict[str, Any] = {
            "cna_vendor": cna.vendor,
            "cna_product": cna.product,
            "identity_level": level,
            "vendor_conflict": pair_vendor_conflict,
            "product_conflict": pair_product_conflict,
            "cpe_identities": [
                f"{item.vendor_key}:{item.product_key}" for item in matched
            ],
            "version_verdict": None,
        }
        if level == "none" or not matched:
            result["pairs"].append(pair)
            continue

        cpe_intervals = [
            interval for item in matched for interval in item.intervals
        ]
        cpe_blockers: Counter = Counter()
        for item in matched:
            cpe_blockers.update(item.blockers)
        reason = _undecidable_reason(cna, cpe_intervals, cpe_blockers)
        if reason is not None:
            undecidable = True
            pair["version_verdict"] = "undecidable"
            pair["undecidable_reason"] = reason
            result["undecidable_reasons"][reason] += 1
            result["pairs"].append(pair)
            continue

        # One profile for both sides: the endpoints are only comparable when
        # they are ordered under the same version scheme.
        profile = profile_for(
            [
                bound
                for interval in (*cna.intervals, *cpe_intervals)
                for bound in (interval.lower, interval.upper)
            ],
            version_type=None,
            product_key=cna.product_key,
        )
        verdict = compare_interval_sets(cna.intervals, cpe_intervals, profile)
        pair["version_verdict"] = verdict
        result["version_verdicts"][verdict] += 1
        if worst_version is None or VERSION_RANK[verdict] < VERSION_RANK[worst_version]:
            worst_version = verdict
        result["pairs"].append(pair)

    result["identity_level"] = worst_identity
    result["vendor_conflict"] = vendor_conflict
    result["product_conflict"] = product_conflict
    result["identity_conflict"] = vendor_conflict or product_conflict
    result["identity_conflict_class"] = identity_conflict_class(
        vendor_conflict,
        product_conflict,
    )
    result["version_verdict"] = worst_version
    result["version_conflict"] = worst_version in CONFLICTING_VERDICTS
    result["version_hard_conflict"] = worst_version in HARD_CONFLICT_VERDICTS
    result["version_undecidable"] = undecidable
    return result


# --------------------------------------------------------------------------
# aggregation
# --------------------------------------------------------------------------


class Report:
    """Mutable accumulator so workers and the parent share one shape."""

    def __init__(self, sample_size: int = 0) -> None:
        self.sample_size = sample_size
        self.counters: dict[str, Counter] = {
            "totals": Counter(),
            "identity_cve": Counter(),
            "identity_conflict_class": Counter(),
            "identity_product": Counter(),
            "version_cve": Counter(),
            "version_pair": Counter(),
            "conflict_matrix": Counter(),
            "undecidable_reason": Counter(),
            "skipped": Counter(),
        }
        self.samples: dict[str, list[str]] = {}

    def _sample(self, bucket: str, cve_id: str) -> None:
        if not self.sample_size or not cve_id:
            return
        holder = self.samples.setdefault(bucket, [])
        if len(holder) < self.sample_size:
            holder.append(cve_id)

    def add(self, analysis: dict[str, Any]) -> None:
        totals = self.counters["totals"]
        totals["records"] += 1
        if analysis["cna_product_count"]:
            totals["with_cna_affected"] += 1
        if analysis["cpe_product_count"]:
            totals["with_cpe"] += 1
        if not analysis["comparable"]:
            self.counters["skipped"][analysis["skip_reason"] or "unknown"] += 1
            return

        totals["comparable"] += 1
        self.counters["identity_product"].update(analysis["identity_levels"])
        level = analysis["identity_level"]
        self.counters["identity_cve"][level] += 1
        conflict_class = analysis["identity_conflict_class"]
        self.counters["identity_conflict_class"][conflict_class] += 1
        if analysis["identity_conflict"]:
            totals["identity_conflict"] += 1
            self._sample(f"identity_{level}", analysis["cve_id"])
            self._sample(f"identity_class_{conflict_class}", analysis["cve_id"])
        if analysis["vendor_conflict"]:
            totals["vendor_conflict"] += 1
        if analysis["product_conflict"]:
            totals["product_conflict"] += 1
        if conflict_class != "none":
            totals[f"identity_{conflict_class}"] += 1

        self.counters["version_pair"].update(analysis["version_verdicts"])
        self.counters["undecidable_reason"].update(analysis["undecidable_reasons"])
        verdict = analysis["version_verdict"]
        if verdict is None:
            self.counters["version_cve"]["undecidable" if analysis["version_undecidable"] else "not_compared"] += 1
            self.counters["conflict_matrix"][
                f"version_unassessed__{conflict_class}"
            ] += 1
            return
        totals["version_compared"] += 1
        self.counters["version_cve"][verdict] += 1
        if analysis["version_undecidable"]:
            self.counters["version_cve"]["partially_undecidable"] += 1
        version_class = (
            "version_conflict" if analysis["version_conflict"] else "version_equal"
        )
        self.counters["conflict_matrix"][
            f"{version_class}__{conflict_class}"
        ] += 1
        if analysis["version_conflict"]:
            totals["version_conflict"] += 1
            self._sample(f"version_{verdict}", analysis["cve_id"])
            if analysis["identity_conflict"]:
                totals["version_and_identity_conflict"] += 1
                # Compatibility name used by the original report.
                totals["both_conflicts"] += 1
            if analysis["vendor_conflict"]:
                totals["version_and_vendor_conflict"] += 1
            if analysis["product_conflict"]:
                totals["version_and_product_conflict"] += 1
            if conflict_class != "none":
                totals[f"version_and_identity_{conflict_class}"] += 1
            if analysis["vendor_conflict"] and analysis["product_conflict"]:
                totals["all_three_conflicts"] += 1
        if analysis["version_hard_conflict"]:
            totals["version_hard_conflict"] += 1

    def merge(self, other: "Report") -> None:
        for name, counter in other.counters.items():
            self.counters[name].update(counter)
        for bucket, values in other.samples.items():
            holder = self.samples.setdefault(bucket, [])
            holder.extend(values[: max(0, self.sample_size - len(holder))])

    def to_dict(self) -> dict[str, Any]:
        totals = self.counters["totals"]
        records = totals["records"]
        comparable = totals["comparable"]
        version_compared = totals["version_compared"]

        def metric(count: int, denominator: int) -> dict[str, int | float | None]:
            return {
                "count": count,
                "denominator": denominator,
                "ratio": count / denominator if denominator else None,
                "percentage": 100.0 * count / denominator if denominator else None,
                "all_current_cves_denominator": records,
                "all_current_cves_ratio": count / records if records else None,
                "all_current_cves_percentage": (
                    100.0 * count / records if records else None
                ),
            }

        return {
            "summary": {
                "denominators": {
                    "source_rows": totals["source_rows"],
                    "current_cves": records,
                    "comparable_cves": comparable,
                    "version_compared_cves": version_compared,
                    "duplicate_revision_rows_skipped": totals[
                        "duplicate_revision_rows_skipped"
                    ],
                    "duplicate_cves": totals["duplicate_cves"],
                },
                "conflicts": {
                    "version": metric(totals["version_conflict"], version_compared),
                    "vendor_any": metric(totals["vendor_conflict"], comparable),
                    "product_any": metric(totals["product_conflict"], comparable),
                    "vendor_only": metric(
                        totals["identity_vendor_only"], comparable
                    ),
                    "product_only": metric(
                        totals["identity_product_only"], comparable
                    ),
                    "vendor_and_product": metric(
                        totals["identity_vendor_and_product"], comparable
                    ),
                },
                "intersections": {
                    "version_and_any_identity": metric(
                        totals["version_and_identity_conflict"], version_compared
                    ),
                    "version_and_vendor_only": metric(
                        totals["version_and_identity_vendor_only"], version_compared
                    ),
                    "version_and_product_only": metric(
                        totals["version_and_identity_product_only"], version_compared
                    ),
                    "version_and_vendor_and_product": metric(
                        totals["all_three_conflicts"], version_compared
                    ),
                },
            },
            "counters": {
                name: dict(counter.most_common())
                for name, counter in self.counters.items()
            },
            "samples": self.samples,
        }


def _iter_lines(
    path: Path,
    limit: int | None,
    excluded_indexes: set[int] | None = None,
) -> Iterator[str]:
    excluded = excluded_indexes or set()
    with path.open("r", encoding="utf-8") as handle:
        for source_index, line in enumerate(handle):
            if limit is not None and source_index >= limit:
                break
            if source_index not in excluded:
                yield line


def _chunks(lines: Iterable[str], size: int) -> Iterator[list[str]]:
    iterator = iter(lines)
    while True:
        chunk = list(islice(iterator, size))
        if not chunk:
            return
        yield chunk


def _record_of(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    payload = json.loads(line)
    record = payload.get("cve", payload)
    return record if isinstance(record, dict) else None


_WORKER_SAMPLES = 0


def _init_worker(sample_size: int) -> None:
    global _WORKER_SAMPLES
    _WORKER_SAMPLES = sample_size


def _process_chunk(chunk: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    report = Report(_WORKER_SAMPLES)
    details: list[dict[str, Any]] = []
    for line in chunk:
        record = _record_of(line)
        if record is None:
            continue
        analysis = analyze_record(record)
        report.add(analysis)
        details.append(_detail_row(analysis))
    return report.to_dict(), details


def _detail_row(analysis: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": analysis["cve_id"],
        "comparable": analysis["comparable"],
        "skip_reason": analysis["skip_reason"],
        "identity_level": analysis["identity_level"],
        "identity_conflict": analysis["identity_conflict"],
        "vendor_conflict": analysis["vendor_conflict"],
        "product_conflict": analysis["product_conflict"],
        "identity_conflict_class": analysis["identity_conflict_class"],
        "version_verdict": analysis["version_verdict"],
        "version_conflict": analysis["version_conflict"],
        "version_undecidable": analysis["version_undecidable"],
        "pairs": analysis["pairs"],
    }


def _report_from_dict(payload: dict[str, Any], sample_size: int) -> Report:
    report = Report(sample_size)
    for name, counter in payload["counters"].items():
        report.counters.setdefault(name, Counter()).update(counter)
    report.samples = {
        bucket: list(values) for bucket, values in payload["samples"].items()
    }
    return report


def run(
    path: Path,
    *,
    limit: int | None,
    jobs: int,
    sample_size: int,
    details_out: Path | None,
    deduplicate: bool = True,
) -> Report:
    report = Report(sample_size)
    if deduplicate:
        loser_indexes, source_rows, duplicate_cves, _examples = (
            _duplicate_loser_indexes(path, limit=limit)
        )
    else:
        loser_indexes = set()
        source_rows = sum(1 for _ in _iter_lines(path, limit))
        duplicate_cves = 0
    report.counters["totals"].update(
        {
            "source_rows": source_rows,
            "duplicate_revision_rows_skipped": len(loser_indexes),
            "duplicate_cves": duplicate_cves,
        }
    )
    if details_out is not None:
        details_out.parent.mkdir(parents=True, exist_ok=True)
    details_handle = details_out.open("w", encoding="utf-8") if details_out else None
    try:
        chunks = _chunks(_iter_lines(path, limit, loser_indexes), CHUNK_LINES)
        if jobs > 1:
            with multiprocessing.Pool(
                jobs, initializer=_init_worker, initargs=(sample_size,)
            ) as pool:
                for payload, details in pool.imap(_process_chunk, chunks):
                    report.merge(_report_from_dict(payload, sample_size))
                    _write_details(details_handle, details)
        else:
            _init_worker(sample_size)
            for chunk in chunks:
                payload, details = _process_chunk(chunk)
                report.merge(_report_from_dict(payload, sample_size))
                _write_details(details_handle, details)
    finally:
        if details_handle is not None:
            details_handle.close()
    return report


def _write_details(handle: Any, details: list[dict[str, Any]]) -> None:
    if handle is None:
        return
    for row in details:
        handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------


def _percent(part: int, whole: int) -> str:
    return f"{100.0 * part / whole:6.2f}%" if whole else "     -"


def _print_table(title: str, counter: Counter, whole: int, order: Sequence[str] | None = None) -> None:
    print(f"\n== {title} ==")
    keys = list(order) if order else [key for key, _ in counter.most_common()]
    for key in keys:
        if key not in counter and order:
            continue
        value = counter[key]
        print(f"  {key:<28} {value:>9,}  {_percent(value, whole)}")


def render(report: Report) -> None:
    totals = report.counters["totals"]
    records = totals["records"]
    comparable = totals["comparable"]

    print("=" * 68)
    print("CNA(CVE) vs NVD(CPE) conflict analysis")
    print("=" * 68)
    print(f"  source JSONL rows             {totals['source_rows']:>9,}")
    print(f"  duplicate revisions skipped  {totals['duplicate_revision_rows_skipped']:>9,}")
    print(f"  duplicate CVE IDs             {totals['duplicate_cves']:>9,}")
    print(f"  records                      {records:>9,}")
    print(f"  with CNA affected[]          {totals['with_cna_affected']:>9,}  {_percent(totals['with_cna_affected'], records)}")
    print(f"  with CPE configurations[]    {totals['with_cpe']:>9,}  {_percent(totals['with_cpe'], records)}")
    print(f"  comparable (both sides)      {comparable:>9,}  {_percent(comparable, records)}")

    _print_table("skipped (not comparable)", report.counters["skipped"], records)
    _print_table(
        "identity match level, per CVE (worst product)",
        report.counters["identity_cve"],
        comparable,
        IDENTITY_LEVELS,
    )
    _print_table(
        "identity match level, per CNA product entry",
        report.counters["identity_product"],
        sum(report.counters["identity_product"].values()),
        IDENTITY_LEVELS,
    )
    _print_table(
        "identifier conflict class, per CVE",
        report.counters["identity_conflict_class"],
        comparable,
        IDENTITY_CONFLICT_CLASSES,
    )
    _print_table(
        "version range verdict, per CVE (worst pair)",
        report.counters["version_cve"],
        comparable,
    )
    pairs_total = sum(report.counters["version_pair"].values()) + sum(
        report.counters["undecidable_reason"].values()
    )
    _print_table(
        "version range verdict, per matched product pair",
        report.counters["version_pair"],
        pairs_total,
        VERSION_VERDICTS,
    )
    _print_table(
        "undecidable pairs, by reason",
        report.counters["undecidable_reason"],
        pairs_total,
    )

    print("\n== headline ==")
    print(f"  identity conflict CVEs       {totals['identity_conflict']:>9,}  {_percent(totals['identity_conflict'], comparable)}  (of comparable)")
    print(f"    vendor conflict (any)      {totals['vendor_conflict']:>9,}  {_percent(totals['vendor_conflict'], comparable)}")
    print(f"    product conflict (any)     {totals['product_conflict']:>9,}  {_percent(totals['product_conflict'], comparable)}")
    print(f"    vendor only                {totals['identity_vendor_only']:>9,}  {_percent(totals['identity_vendor_only'], comparable)}")
    print(f"    product only               {totals['identity_product_only']:>9,}  {_percent(totals['identity_product_only'], comparable)}")
    print(f"    vendor + product           {totals['identity_vendor_and_product']:>9,}  {_percent(totals['identity_vendor_and_product'], comparable)}")
    print(f"  version-comparable CVEs      {totals['version_compared']:>9,}  {_percent(totals['version_compared'], comparable)}  (of comparable)")
    print(f"  version conflict CVEs        {totals['version_conflict']:>9,}  {_percent(totals['version_conflict'], totals['version_compared'])}  (of version-comparable)")
    print(f"    of which hard conflicts    {totals['version_hard_conflict']:>9,}  {_percent(totals['version_hard_conflict'], totals['version_compared'])}")

    print("\n== report-ready totals (ratio of all current CVEs) ==")
    for label, key in (
        ("version conflict", "version_conflict"),
        ("vendor-only conflict", "identity_vendor_only"),
        ("product-only conflict", "identity_product_only"),
        ("vendor + product conflict", "identity_vendor_and_product"),
        ("any identifier conflict", "identity_conflict"),
    ):
        print(f"  {label:<28} {totals[key]:>9,}  {_percent(totals[key], records)}")

    print("\n== intersections ==")
    print(f"  version ∩ any identifier    {totals['version_and_identity_conflict']:>9,}  {_percent(totals['version_and_identity_conflict'], totals['version_compared'])}")
    print(f"  version ∩ vendor-only       {totals['version_and_identity_vendor_only']:>9,}  {_percent(totals['version_and_identity_vendor_only'], totals['version_compared'])}")
    print(f"  version ∩ product-only      {totals['version_and_identity_product_only']:>9,}  {_percent(totals['version_and_identity_product_only'], totals['version_compared'])}")
    print(f"  version ∩ vendor ∩ product {totals['all_three_conflicts']:>9,}  {_percent(totals['all_three_conflicts'], totals['version_compared'])}")

    _print_table(
        "complete conflict matrix",
        report.counters["conflict_matrix"],
        comparable,
    )

    if report.samples:
        print("\n== samples ==")
        for bucket in sorted(report.samples):
            print(f"  {bucket:<28} {', '.join(report.samples[bucket])}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"NVD JSONL dump. Default: {DEFAULT_INPUT}",
    )
    parser.add_argument("--limit", type=int, default=None, help="Only read N lines.")
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=min(8, multiprocessing.cpu_count()),
        help="Worker processes (1 disables multiprocessing).",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=5,
        help="Example CVE IDs to keep per conflict bucket. 0 disables.",
    )
    parser.add_argument(
        "--json-out", type=Path, default=None, help="Write the full report as JSON."
    )
    parser.add_argument(
        "--details",
        type=Path,
        default=None,
        help="Write one JSON line per CVE with its verdicts.",
    )
    parser.add_argument(
        "--include-duplicate-revisions",
        action="store_true",
        help=(
            "Count every JSONL row instead of selecting one current row per CVE. "
            "By default the greatest lastModified revision wins."
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.input.exists():
        print(f"input not found: {args.input}", file=sys.stderr)
        return 1
    report = run(
        args.input,
        limit=args.limit,
        jobs=max(1, args.jobs),
        sample_size=max(0, args.samples),
        details_out=args.details,
        deduplicate=not args.include_duplicate_revisions,
    )
    render(report)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(report.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\nreport written to {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
