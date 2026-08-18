"""Apply newer NVD Change History CPE details to a CVE 2.0 record.

Change History renders CPE configurations as text instead of CVE JSON.  This
module intentionally supports only the stable CPE/range forms published by
NVD.  Unparseable lines are counted and left untouched; they are never used to
delete data.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import re
from typing import Any, Iterable, Mapping

from scripts.nvd_normalization.nvd import iter_cna_affected, parse_cpe23
from scripts.nvd_normalization.rules import is_placeholder, normalize_key
from scripts.nvd_normalization.versioning import (
    Segment,
    compare_versions,
    compile_cna,
    profile_for,
)


_CPE_LINE_RE = re.compile(
    r"(?P<marker>\*)?(?P<criteria>cpe:2\.3:\S+?)"
    r"(?=(?:\s+versions\b)|(?:\s+\(and previous\))|(?:\s*$))",
    re.IGNORECASE,
)
_BETWEEN_RE = re.compile(
    r"versions\s+from\s+\((including|excluding)\)\s+(\S+)\s+"
    r"up\s+to\s+\((including|excluding)\)\s+(\S+)",
    re.IGNORECASE,
)
_UPPER_RE = re.compile(
    r"versions\s+up\s+to\s+\((including|excluding)\)\s+(\S+)",
    re.IGNORECASE,
)
_LOWER_RE = re.compile(
    r"versions\s+from\s+\((including|excluding)\)\s+(\S+)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class VersionInterval:
    lower: str | None
    lower_inclusive: bool
    upper: str | None
    upper_inclusive: bool


@dataclass(frozen=True, slots=True)
class MatchRef:
    matches: list[Any]
    value: dict[str, Any]


def _criteria_with_wildcard_version(criteria: str) -> str:
    cpe = parse_cpe23(criteria)
    components = list(cpe.raw_components)
    components[3] = "*"
    return "cpe:2.3:" + ":".join(components)


def _identity_components(criteria: str) -> tuple[str, ...]:
    cpe = parse_cpe23(criteria)
    return (
        cpe.part,
        cpe.vendor,
        cpe.product,
        "*",
        cpe.update,
        cpe.edition,
        cpe.language,
        cpe.sw_edition,
        cpe.target_sw,
        cpe.target_hw,
        cpe.other,
    )


def parse_configuration_text(
    value: Any, counters: Counter[str]
) -> list[dict[str, Any]]:
    """Convert supported history CPE lines to CVE 2.0 ``cpeMatch`` objects."""

    if not isinstance(value, str):
        if value is not None:
            counters["non_string_values"] += 1
        return []
    output: list[dict[str, Any]] = []
    cpe_like_lines = 0
    for raw_line in value.splitlines():
        line = raw_line.strip()
        if "cpe:2.3:" not in line.casefold():
            continue
        cpe_like_lines += 1
        match = _CPE_LINE_RE.search(line)
        if match is None:
            counters["unparsed_cpe_lines"] += 1
            continue
        criteria = match.group("criteria").rstrip(",.;")
        try:
            cpe = parse_cpe23(criteria)
        except (ValueError, UnicodeError):
            counters["invalid_cpe_lines"] += 1
            continue
        result: dict[str, Any] = {
            "vulnerable": bool(match.group("marker")),
            "criteria": criteria,
        }
        tail = line[match.end() :]
        bounded = _BETWEEN_RE.search(tail)
        upper = _UPPER_RE.search(tail)
        lower = _LOWER_RE.search(tail)
        if bounded:
            lower_kind, lower_value, upper_kind, upper_value = bounded.groups()
            result[
                "versionStartIncluding"
                if lower_kind.casefold() == "including"
                else "versionStartExcluding"
            ] = lower_value
            result[
                "versionEndIncluding"
                if upper_kind.casefold() == "including"
                else "versionEndExcluding"
            ] = upper_value
        elif upper:
            kind, endpoint = upper.groups()
            result[
                "versionEndIncluding"
                if kind.casefold() == "including"
                else "versionEndExcluding"
            ] = endpoint
        elif lower:
            kind, endpoint = lower.groups()
            result[
                "versionStartIncluding"
                if kind.casefold() == "including"
                else "versionStartExcluding"
            ] = endpoint
        elif "(and previous)" in tail.casefold() and cpe.version not in {"", "*", "-"}:
            result["criteria"] = _criteria_with_wildcard_version(criteria)
            result["versionEndIncluding"] = cpe.version
        elif "versions" in tail.casefold():
            counters["unsupported_version_phrases"] += 1
            continue
        output.append(result)
        counters["parsed_cpe_lines"] += 1
    if cpe_like_lines == 0 and value.strip():
        counters["values_without_cpe"] += 1
    return output


def _identity(match: Mapping[str, Any]) -> tuple[str, ...] | None:
    criteria = match.get("criteria")
    if not isinstance(criteria, str):
        return None
    try:
        components = _identity_components(criteria)
    except (ValueError, UnicodeError):
        return None
    # A non-vulnerable platform CPE in an AND graph must never be replaced by
    # a vulnerable product range (or vice versa), even when the CPE name is
    # otherwise identical.
    prefix = "vulnerable" if match.get("vulnerable") is True else "platform"
    return (prefix,) + tuple(item.casefold() for item in components)


def _product_identity(match: Mapping[str, Any]) -> tuple[str, str] | None:
    criteria = match.get("criteria")
    if not isinstance(criteria, str):
        return None
    try:
        cpe = parse_cpe23(criteria)
    except (ValueError, UnicodeError):
        return None
    vendor, product = normalize_key(cpe.vendor), normalize_key(cpe.product)
    return (vendor, product) if product else None


def _interval(match: Mapping[str, Any]) -> VersionInterval | None:
    criteria = match.get("criteria")
    if not isinstance(criteria, str):
        return None
    try:
        cpe = parse_cpe23(criteria)
    except (ValueError, UnicodeError):
        return None
    lower_including = match.get("versionStartIncluding")
    lower_excluding = match.get("versionStartExcluding")
    upper_including = match.get("versionEndIncluding")
    upper_excluding = match.get("versionEndExcluding")
    lower = lower_including or lower_excluding
    upper = upper_including or upper_excluding
    if lower is not None or upper is not None:
        return VersionInterval(
            str(lower) if lower is not None else None,
            lower_including is not None,
            str(upper) if upper is not None else None,
            upper_including is not None,
        )
    if cpe.version in {"", "*"}:
        return VersionInterval(None, False, None, False)
    if cpe.version == "-":
        return None
    return VersionInterval(cpe.version, True, cpe.version, True)


def _same_match(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    fields = (
        "vulnerable",
        "criteria",
        "versionStartIncluding",
        "versionStartExcluding",
        "versionEndIncluding",
        "versionEndExcluding",
    )
    return all(left.get(field) == right.get(field) for field in fields)


def _overlaps(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    identity = _identity(left)
    if identity is None or identity != _identity(right):
        return False
    left_interval, right_interval = _interval(left), _interval(right)
    if left_interval is None or right_interval is None:
        return _same_match(left, right)
    product_key = identity[3] if len(identity) > 3 else ""
    profile = profile_for(
        (
            left_interval.lower,
            left_interval.upper,
            right_interval.lower,
            right_interval.upper,
        ),
        version_type=None,
        product_key=product_key,
    )
    if left_interval.upper is not None and right_interval.lower is not None:
        compared = compare_versions(left_interval.upper, right_interval.lower, profile)
        if compared < 0 or (
            compared == 0
            and not (left_interval.upper_inclusive and right_interval.lower_inclusive)
        ):
            return False
    if right_interval.upper is not None and left_interval.lower is not None:
        compared = compare_versions(right_interval.upper, left_interval.lower, profile)
        if compared < 0 or (
            compared == 0
            and not (right_interval.upper_inclusive and left_interval.lower_inclusive)
        ):
            return False
    return True


def _match_refs(cve: Mapping[str, Any]) -> list[MatchRef]:
    output: list[MatchRef] = []

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return
        matches = node.get("cpeMatch")
        if isinstance(matches, list):
            for item in matches:
                if isinstance(item, dict):
                    output.append(MatchRef(matches=matches, value=item))
        children = node.get("children")
        if isinstance(children, list):
            for child in children:
                visit(child)

    configurations = cve.get("configurations")
    if isinstance(configurations, list):
        for configuration in configurations:
            if not isinstance(configuration, dict):
                continue
            nodes = configuration.get("nodes")
            if isinstance(nodes, list):
                for node in nodes:
                    visit(node)
    return output


def _remove_ref(ref: MatchRef) -> bool:
    for index, item in enumerate(ref.matches):
        if item is ref.value:
            del ref.matches[index]
            return True
    return False


def _remove_exact(cve: dict[str, Any], old_matches: Iterable[dict[str, Any]]) -> int:
    removed = 0
    for old in old_matches:
        for ref in list(_match_refs(cve)):
            if _same_match(ref.value, old) and _remove_ref(ref):
                removed += 1
    return removed


def _append_new_configuration(cve: dict[str, Any], match: dict[str, Any]) -> None:
    configurations = cve.setdefault("configurations", [])
    if not isinstance(configurations, list):
        configurations = []
        cve["configurations"] = configurations
    configurations.append(
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [match],
                }
            ]
        }
    )


def _apply_additions(
    cve: dict[str, Any], additions: Iterable[dict[str, Any]], counters: Counter[str]
) -> None:
    for addition in additions:
        refs = _match_refs(cve)
        if any(_same_match(ref.value, addition) for ref in refs):
            counters["already_current_matches"] += 1
            continue
        identity = _identity(addition)
        same_identity = [
            ref
            for ref in refs
            if identity is not None and _identity(ref.value) == identity
        ]
        overlapping = [ref for ref in same_identity if _overlaps(ref.value, addition)]
        if overlapping:
            target = overlapping[0]
            replacement = dict(addition)
            if "matchCriteriaId" in target.value:
                replacement["matchCriteriaId"] = target.value["matchCriteriaId"]
            target.value.clear()
            target.value.update(replacement)
            for duplicate in overlapping[1:]:
                _remove_ref(duplicate)
            counters["overlapping_ranges_replaced"] += 1
            counters["overlapping_duplicates_removed"] += max(0, len(overlapping) - 1)
            continue
        if same_identity:
            same_identity[0].matches.append(dict(addition))
            counters["disjoint_ranges_added"] += 1
        else:
            _append_new_configuration(cve, dict(addition))
            counters["new_cpe_identities_added"] += 1


def _affected_identities(value: Any) -> set[tuple[str, str]]:
    """Return product identities mentioned by one history Affected value."""

    output: set[tuple[str, str]] = set()

    def visit(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if not isinstance(node, Mapping):
            return
        vendor, product = node.get("vendor"), node.get("product")
        if isinstance(product, str) and not is_placeholder(product):
            vendor_text = (
                product
                if not isinstance(vendor, str) or is_placeholder(vendor)
                else vendor
            )
            output.add((normalize_key(vendor_text), normalize_key(product)))
        for key in ("affected", "affectedData"):
            if key in node:
                visit(node.get(key))

    visit(value)
    return output


def _rank_for_identity(
    identity: tuple[str, str],
    ranks: Mapping[tuple[str, str], str],
) -> str | None:
    exact = ranks.get(identity)
    if exact is not None:
        return exact
    # CNA and CPE vendor spellings frequently differ.  Product-only fallback
    # is allowed only when the history identity is unique for that product.
    candidates = {
        rank for (_vendor, product), rank in ranks.items() if product == identity[1]
    }
    return next(iter(candidates)) if len(candidates) == 1 else None


def _segment_interval(segment: Segment) -> VersionInterval | None:
    if segment.status.strip().casefold() != "affected":
        return None
    if segment.exact is not None:
        return VersionInterval(segment.exact, True, segment.exact, True)
    if segment.lower is None and segment.upper is None:
        return None
    return VersionInterval(
        segment.lower,
        bool(segment.lower_inclusive),
        segment.upper,
        bool(segment.upper_inclusive),
    )


def _current_affected_ranges(
    cve: Mapping[str, Any], counters: Counter[str]
) -> dict[tuple[str, str], list[VersionInterval]]:
    output: dict[tuple[str, str], list[VersionInterval]] = {}
    seen: dict[tuple[str, str], set[VersionInterval]] = {}
    for item in iter_cna_affected(cve):
        if is_placeholder(item.product):
            continue
        vendor = item.product if is_placeholder(item.vendor) else item.vendor
        identity = (normalize_key(vendor), normalize_key(item.product))
        for raw_version in item.versions:
            version = raw_version.get("version")
            status = raw_version.get("status")
            if not isinstance(version, str) or not isinstance(status, str):
                counters["affected_ranges_unparsed"] += 1
                continue
            less_than = raw_version.get("lessThan")
            less_equal = raw_version.get("lessThanOrEqual")
            version_type = raw_version.get("versionType")
            changes_value = raw_version.get("changes")
            changes = (
                [dict(value) for value in changes_value if isinstance(value, Mapping)]
                if isinstance(changes_value, list)
                else []
            )
            compiled = compile_cna(
                version=version,
                status=status.strip().casefold(),
                product_key=identity[1],
                less_than=less_than if isinstance(less_than, str) else None,
                less_than_or_equal=(
                    less_equal if isinstance(less_equal, str) else None
                ),
                version_type=version_type if isinstance(version_type, str) else None,
                changes=changes,
            )
            if compiled.parse_status != "parsed":
                counters["affected_ranges_unparsed"] += 1
                continue
            for segment in compiled.segments:
                interval = _segment_interval(segment)
                if interval is None:
                    continue
                bucket = output.setdefault(identity, [])
                identity_seen = seen.setdefault(identity, set())
                if interval in identity_seen:
                    continue
                identity_seen.add(interval)
                bucket.append(interval)
                counters["affected_ranges_compiled"] += 1
    return output


def _interval_match(criteria: str, interval: VersionInterval) -> dict[str, Any]:
    result: dict[str, Any] = {
        "vulnerable": True,
        "criteria": _criteria_with_wildcard_version(criteria),
    }
    if interval.lower is not None:
        result[
            "versionStartIncluding"
            if interval.lower_inclusive
            else "versionStartExcluding"
        ] = interval.lower
    if interval.upper is not None:
        result[
            "versionEndIncluding" if interval.upper_inclusive else "versionEndExcluding"
        ] = interval.upper
    return result


def resolve_history_version_conflicts(
    cve: dict[str, Any], details: Iterable[Mapping[str, Any]]
) -> dict[str, int]:
    """Resolve current CNA/CPE ranges using field-specific history freshness.

    The latest field does not blindly replace the other source.  A current
    Affected range is admitted only when history proves that Affected was
    touched after CPE Configuration for the same product.  It then follows the
    same interval policy as CPE replay: overlapping ranges are replaced and
    disjoint ranges are retained as additional ranges.
    """

    counters: Counter[str] = Counter()
    cpe_ranks: dict[tuple[str, str], str] = {}
    affected_ranks: dict[tuple[str, str], str] = {}
    rank_parse: Counter[str] = Counter()
    for detail in details:
        rank = str(detail.get("rank") or "")
        field_type = str(detail.get("field_type") or "").strip().casefold()
        old_value, new_value = detail.get("old_value"), detail.get("new_value")
        if field_type == "cpe_configuration":
            matches = [
                *parse_configuration_text(old_value, rank_parse),
                *parse_configuration_text(new_value, rank_parse),
            ]
            for match in matches:
                identity = _product_identity(match)
                if identity is not None and rank > cpe_ranks.get(identity, ""):
                    cpe_ranks[identity] = rank
        elif field_type == "affected":
            counters["affected_details_considered"] += 1
            for identity in _affected_identities(old_value) | _affected_identities(
                new_value
            ):
                if rank > affected_ranks.get(identity, ""):
                    affected_ranks[identity] = rank
    counters.update({f"history_rank_{key}": value for key, value in rank_parse.items()})
    if not cpe_ranks or not affected_ranks:
        return dict(counters)

    affected_ranges = _current_affected_ranges(cve, counters)
    refs_by_product: dict[tuple[str, str], list[MatchRef]] = {}
    for ref in _match_refs(cve):
        if ref.value.get("vulnerable") is not True:
            continue
        identity = _product_identity(ref.value)
        if identity is not None:
            refs_by_product.setdefault(identity, []).append(ref)

    before = repr(cve.get("configurations"))
    for affected_identity, intervals in affected_ranges.items():
        affected_rank = _rank_for_identity(affected_identity, affected_ranks)
        if affected_rank is None:
            continue
        targets = (
            [affected_identity]
            if affected_identity in refs_by_product
            else [
                identity
                for identity in refs_by_product
                if identity[1] == affected_identity[1]
            ]
        )
        if len(targets) != 1:
            counters["affected_products_without_matching_cpe"] += 1
            continue
        target_identity = targets[0]
        cpe_rank = _rank_for_identity(target_identity, cpe_ranks)
        if cpe_rank is None:
            counters["affected_products_without_cpe_history"] += 1
            continue
        if affected_rank <= cpe_rank:
            continue
        counters["affected_products_newer_than_cpe"] += 1

        # Apply the affected union to every distinct current CPE scope for this
        # product while preserving part/edition/target axes from each template.
        templates: dict[tuple[str, ...], str] = {}
        for ref in refs_by_product[target_identity]:
            full_identity = _identity(ref.value)
            criteria = ref.value.get("criteria")
            if full_identity is not None and isinstance(criteria, str):
                templates.setdefault(full_identity, criteria)
        before_counts = Counter(counters)
        for criteria in templates.values():
            additions: list[dict[str, Any]] = []
            for interval in intervals:
                try:
                    additions.append(_interval_match(criteria, interval))
                except (ValueError, UnicodeError):
                    counters["affected_ranges_unparsed"] += 1
            _apply_additions(cve, additions, counters)
        counters["affected_overlapping_ranges_replaced"] += (
            counters["overlapping_ranges_replaced"]
            - before_counts["overlapping_ranges_replaced"]
        )
        counters["affected_disjoint_ranges_added"] += (
            counters["disjoint_ranges_added"] - before_counts["disjoint_ranges_added"]
        )
        counters["affected_already_current_matches"] += (
            counters["already_current_matches"]
            - before_counts["already_current_matches"]
        )
    if repr(cve.get("configurations")) != before:
        counters["affected_conflict_cves_modified"] = 1
        counters["cves_modified"] = 1
    return dict(counters)


def _apply_changed(
    cve: dict[str, Any],
    old_matches: list[dict[str, Any]],
    new_matches: list[dict[str, Any]],
    counters: Counter[str],
) -> None:
    """Replace exact old matches in place, then use range-aware fallback.

    In-place replacement preserves the surrounding AND/OR graph.  This is
    especially important for non-vulnerable platform CPEs in a deprecation
    remap, which must not be moved into a standalone OR configuration.
    """

    applied_new: set[int] = set()
    paired_old: set[int] = set()
    for old_index, old in enumerate(old_matches):
        ref = next(
            (item for item in _match_refs(cve) if _same_match(item.value, old)),
            None,
        )
        if ref is None:
            continue
        candidates = [
            index
            for index, new in enumerate(new_matches)
            if index not in applied_new
            and new.get("vulnerable") == old.get("vulnerable")
        ]
        new_index = next(
            (
                index
                for index in candidates
                if _identity(new_matches[index]) == _identity(old)
            ),
            candidates[0] if candidates else None,
        )
        if new_index is None:
            continue
        new = new_matches[new_index]
        replacement = dict(new)
        if "matchCriteriaId" in ref.value:
            replacement["matchCriteriaId"] = ref.value["matchCriteriaId"]
        old_identity, new_identity = _identity(old), _identity(new)
        ref.value.clear()
        ref.value.update(replacement)
        applied_new.add(new_index)
        paired_old.add(old_index)
        if old_identity == new_identity:
            counters["overlapping_ranges_replaced"] += 1
        else:
            counters["cpe_remap_replacements_applied"] += 1

    _apply_additions(
        cve,
        (new for index, new in enumerate(new_matches) if index not in applied_new),
        counters,
    )
    remaining_old = [
        old
        for index, old in enumerate(old_matches)
        if index not in paired_old
        and not any(_same_match(old, new) for new in new_matches)
    ]
    counters["matches_removed"] += _remove_exact(cve, remaining_old)


def apply_history_cpe_details(
    cve: dict[str, Any], details: Iterable[Mapping[str, Any]]
) -> dict[str, int]:
    """Replay ordered CPE details and return mutation/diagnostic counters."""

    counters: Counter[str] = Counter()
    before = repr(cve.get("configurations"))
    for detail in details:
        action = str(detail.get("action") or "").strip().casefold()
        event_name = str(detail.get("event_name") or "").strip().casefold()
        old_matches = parse_configuration_text(detail.get("old_value"), counters)
        new_matches = parse_configuration_text(detail.get("new_value"), counters)
        counters["details_considered"] += 1
        if action == "added":
            _apply_additions(cve, new_matches, counters)
        elif action == "removed":
            counters["matches_removed"] += _remove_exact(cve, old_matches)
        elif action == "changed":
            _apply_changed(cve, old_matches, new_matches, counters)
            old_identities = {_identity(item) for item in old_matches}
            new_identities = {_identity(item) for item in new_matches}
            if old_identities - {None} != new_identities - {None}:
                counters["cpe_identities_remapped"] += 1
        else:
            counters["unsupported_actions"] += 1
        if "deprecation" in event_name:
            counters["deprecation_details_considered"] += 1
    if repr(cve.get("configurations")) != before:
        counters["cves_modified"] = 1
    return dict(counters)
