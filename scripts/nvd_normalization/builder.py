"""Staged compiler from merged NVD + precomputed LLM JSONL to schema v5."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from typing import Any, Callable, Collection, Iterable, Mapping, Sequence

from .identity import materialize_identity_resolution, reclassify_alias_roles
from .llm import (
    LEGACY_SCHEMA_HASH,
    GroundedLLMBinding,
    GroundedLLMRange,
    LLMResultStream,
    ingest_llm_result,
)
from .nvd import (
    CPE23,
    CPEMatch,
    CNAAffected,
    ParseError,
    descriptions,
    iter_cna_affected,
    parse_configurations,
    parse_cpe23,
    parse_json_line,
    raw_fragment_hash,
)
from .rules import (
    DISTRIBUTION_PRODUCTS,
    DISTRIBUTION_PACKAGE_VENDORS,
    DISTRIBUTION_VENDORS,
    FRAMEWORK_VERSION,
    RULE_CONFIGURATION_SHA256,
    RULE_VERSION,
    canonical_json,
    evidence_tuple,
    evidence_wins,
    is_placeholder,
    normalize_key,
    stable_hash,
)
from .storage import StorageError, Store
from .versioning import (
    CompiledExpression,
    Segment,
    arity_semantics,
    compile_cna,
    compile_nvd,
    compare_versions,
    version_kind,
)


class BuildError(RuntimeError):
    pass


_FAST_CVE_ID_RE = re.compile(rb'"id"\s*:\s*"(CVE-[0-9]{4}-[0-9]+)"')


def _duplicate_loser_indexes(
    path: Path, *, limit: int | None
) -> tuple[set[int], int, int, list[dict[str, Any]]]:
    """Select one deterministic current row per CVE before append-only ingest.

    Merged annual/modified feeds can contain adjacent or non-adjacent revisions
    of the same CVE.  The greatest ``lastModified`` wins; source position is the
    stable tie-breaker.  Only loser indexes are retained for the build pass, so
    the full winner map does not remain resident while SQLite caches grow.
    """

    # winner value: (last_modified, source_index, byte_offset, byte_length).
    # ``last_modified is None`` means the fast-path row has not needed a full
    # JSON parse yet.
    winners: dict[str, tuple[str | None, int, int, int]] = {}
    losers: set[int] = set()
    duplicate_cves: set[str] = set()
    examples: list[dict[str, Any]] = []
    input_rows = 0
    byte_offset = 0

    def parsed_identity(
        raw: bytes, *, source_index: int
    ) -> tuple[str, str] | None:
        try:
            cve = parse_json_line(raw, line_number=source_index + 1)
        except ParseError:
            return None
        cve_id = str(cve.get("id", cve.get("cveId", cve.get("cve_id"))))
        last_modified = cve.get("lastModified")
        return (
            cve_id,
            last_modified if isinstance(last_modified, str) else "",
        )

    with path.open("rb") as source, path.open("rb") as validation_source:
        def consider_valid(
            *,
            cve_id: str,
            last_modified: str,
            source_index: int,
            offset: int,
            byte_length: int,
        ) -> None:
            previous = winners.get(cve_id)
            if previous is None:
                winners[cve_id] = (
                    last_modified,
                    source_index,
                    offset,
                    byte_length,
                )
                return
            previous_modified, previous_index, previous_offset, previous_length = (
                previous
            )
            if previous_modified is None:
                validation_source.seek(previous_offset)
                previous_raw = validation_source.read(previous_length)
                previous_identity = parsed_identity(
                    previous_raw,
                    source_index=previous_index,
                )
                if (
                    previous_identity is None
                    or previous_identity[0] != cve_id
                ):
                    winners[cve_id] = (
                        last_modified,
                        source_index,
                        offset,
                        byte_length,
                    )
                    return
                previous_modified = previous_identity[1]
                winners[cve_id] = (
                    previous_modified,
                    previous_index,
                    previous_offset,
                    previous_length,
                )
            duplicate_cves.add(cve_id)
            previous_rank = (previous_modified, previous_index)
            rank = (last_modified, source_index)
            if rank > previous_rank:
                loser, winner = previous_index, source_index
                winners[cve_id] = (
                    last_modified,
                    source_index,
                    offset,
                    byte_length,
                )
            else:
                loser, winner = source_index, previous_index
            losers.add(loser)
            if len(examples) < 20:
                examples.append(
                    {
                        "cve_id": cve_id,
                        "winner_line": winner + 1,
                        "loser_line": loser + 1,
                        "selection": "max_lastModified_then_source_index",
                    }
                )

        for source_index, raw in enumerate(source):
            if limit is not None and source_index >= limit:
                break
            input_rows += 1
            match = _FAST_CVE_ID_RE.search(raw, 0, min(len(raw), 512))
            fast_cve_id = (
                match.group(1).decode("ascii") if match is not None else None
            )
            if fast_cve_id is not None and fast_cve_id not in winners:
                winners[fast_cve_id] = (
                    None,
                    source_index,
                    byte_offset,
                    len(raw),
                )
            else:
                identity = parsed_identity(raw, source_index=source_index)
                if identity is not None:
                    consider_valid(
                        cve_id=identity[0],
                        last_modified=identity[1],
                        source_index=source_index,
                        offset=byte_offset,
                        byte_length=len(raw),
                    )
            byte_offset += len(raw)
    return losers, input_rows, len(duplicate_cves), examples


@dataclass(slots=True)
class AssertionInfo:
    assertion_id: int
    product_id: int
    source_family: str
    polarity: str
    scope_id: int
    semantic_fingerprint: str
    constraint_fingerprint: str
    version_class: str
    comparison_tuple: tuple[int, int, int, int, int, int, int]
    role: str | None
    is_default: bool
    parse_status: str
    reconciliation: str = "active"
    winner_id: int | None = None
    reason: str = "admitted"


def _status(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    normalized = value.strip().casefold()
    if normalized in {"affected", "unaffected", "unknown"}:
        return normalized
    return "unknown"


def _marker_axis(raw: str, decoded: str | None = None) -> tuple[str, str | None]:
    if raw == "*":
        return "ANY", None
    if raw == "-":
        return "NOT_APPLICABLE", None
    if raw == "":
        return "UNKNOWN", None
    return "EXACT", decoded if decoded is not None else raw


def _set_axis(values: Iterable[str]) -> tuple[str, str | None]:
    selected = sorted({item for item in values if item})
    if not selected:
        return "UNKNOWN", None
    if "*" in selected:
        return "ANY", None
    if len(selected) == 1:
        if selected[0] == "-":
            return "NOT_APPLICABLE", None
        return "EXACT", selected[0]
    return "SET", canonical_json(selected)


def _cpe_axes(cpe: CPE23, role: str) -> dict[str, tuple[str, str | None]]:
    axes = {
        "part": _marker_axis(cpe.raw_value("part"), cpe.part),
        "edition": _marker_axis(cpe.raw_value("edition"), cpe.edition),
        "update": _marker_axis(cpe.raw_value("update"), cpe.update),
        "language": _marker_axis(cpe.raw_value("language"), cpe.language),
        "sw_edition": _marker_axis(
            cpe.raw_value("sw_edition"), cpe.sw_edition
        ),
        "target_sw": _marker_axis(cpe.raw_value("target_sw"), cpe.target_sw),
        "target_hw": _marker_axis(cpe.raw_value("target_hw"), cpe.target_hw),
        "other": _marker_axis(cpe.raw_value("other"), cpe.other),
        "distribution": ("ANY", None),
        "component": ("ANY", None),
    }
    if role in {"DOWNSTREAM_DISTRIBUTION", "DOWNSTREAM_PACKAGE"}:
        axes["distribution"] = (
            "EXACT",
            f"{normalize_key(cpe.vendor)}:{normalize_key(cpe.product)}",
        )
    if role == "BUNDLED_COMPONENT":
        axes["component"] = (
            "EXACT",
            f"{normalize_key(cpe.vendor)}:{normalize_key(cpe.product)}",
        )
    return axes


def _is_distribution_product(vendor_key: str, product_key: str) -> bool:
    return (
        vendor_key in DISTRIBUTION_VENDORS
        and product_key in DISTRIBUTION_PRODUCTS
    )


def _canonical_cna_identity(item: CNAAffected) -> tuple[str, str] | None:
    if is_placeholder(item.product):
        return None
    vendor = item.product if is_placeholder(item.vendor) else item.vendor
    return vendor, item.product


def _cna_axes(
    item: CNAAffected,
    *,
    vendor_key: str,
    product_key: str,
) -> dict[str, tuple[str, str | None]]:
    axes: dict[str, tuple[str, str | None]] = {
        "part": ("ANY", None),
        "distribution": ("ANY", None),
        "edition": ("ANY", None),
        "component": ("ANY", None),
        "update": ("ANY", None),
        "language": ("ANY", None),
        "sw_edition": ("ANY", None),
        "target_sw": _set_axis(item.platforms),
        "target_hw": ("ANY", None),
        "other": ("ANY", None),
    }
    if not item.platforms:
        axes["target_sw"] = ("ANY", None)
    parsed_cpes: list[CPE23] = []
    for raw in item.cpes:
        try:
            parsed_cpes.append(parse_cpe23(raw))
        except (ValueError, UnicodeError):
            continue
    if parsed_cpes:
        for name in (
            "part",
            "edition",
            "update",
            "language",
            "sw_edition",
            "target_sw",
            "target_hw",
            "other",
        ):
            states = [
                _marker_axis(cpe.raw_value(name), getattr(cpe, name))
                for cpe in parsed_cpes
            ]
            if any(state == "ANY" for state, _ in states):
                axes[name] = ("ANY", None)
            else:
                concrete = [value for state, value in states if state == "EXACT" and value]
                if concrete:
                    axes[name] = _set_axis(concrete)
                elif states and all(state == "NOT_APPLICABLE" for state, _ in states):
                    axes[name] = ("NOT_APPLICABLE", None)
    if _is_distribution_product(vendor_key, product_key):
        axes["distribution"] = ("EXACT", f"{vendor_key}:{product_key}")
    return axes


def _cna_claim_group(
    item: CNAAffected,
    *,
    vendor_key: str,
    product_key: str,
) -> str:
    """Group one source's parallel product ranges before default closure.

    A source can split one product into branch-specific ``affectedData`` rows.
    Their explicit ranges form a union before ``defaultStatus`` is applied.
    Assertion scopes remain independent predicates, but CPE marker differences
    must not split that default-closure set.
    """

    return "cna:" + stable_hash(
        {
            "source_identifier": item.source_identifier,
            "vendor_key": vendor_key,
            "product_key": product_key,
        }
    )


def _scope_specificity(axes: Mapping[str, tuple[str, str | None]]) -> int:
    return sum(state in {"EXACT", "SET", "NOT_APPLICABLE"} for state, _ in axes.values())


def _scope_status(axes: Mapping[str, tuple[str, str | None]]) -> str:
    return (
        "unresolved"
        if any(state == "UNKNOWN" for state, _ in axes.values())
        else "resolved"
    )


def _role(
    match: CPEMatch,
    *,
    direct_products: Collection[tuple[str, str]],
) -> tuple[str, str]:
    if not match.vulnerable:
        if match.cpe.part == "h":
            return "REQUIRED_HARDWARE", "vulnerable_flag_false"
        return "REQUIRED_PLATFORM", "vulnerable_flag_false"
    vendor_key = normalize_key(match.cpe.vendor)
    product_key = normalize_key(match.cpe.product)
    identity = (vendor_key, product_key)
    if _is_distribution_product(vendor_key, product_key):
        return "DOWNSTREAM_DISTRIBUTION", "known_distribution_product"
    if identity in direct_products:
        # Non-exact aliases are deliberately deferred until the global
        # collision-aware identity clusters have been materialized.
        return "DIRECT_UPSTREAM", "cna_structured_target"
    if vendor_key in DISTRIBUTION_PACKAGE_VENDORS:
        return "DOWNSTREAM_PACKAGE", "known_distribution_vendor"
    return "UNRESOLVED", "none"


def _can_index(
    *,
    role: str | None,
    version_class: str,
    scope_status: str,
    parse_status: str,
) -> bool:
    return (
        role in {"DIRECT_UPSTREAM", "DIRECT_ALTERNATIVE_PRODUCT"}
        and version_class
        in {"EXACT", "BOUNDED_RANGE", "UNBOUNDED_RANGE", "BRANCH_RANGE"}
        and scope_status == "resolved"
        and parse_status == "parsed"
    )


def _max_result(role: str | None, version_class: str) -> str | None:
    if role == "UNRESOLVED" or version_class in {
        "CPE_ANY_UNCORROBORATED",
        "UNSPECIFIED",
        "UNPARSED",
    }:
        return "potentially_affected"
    return None


def _split_expression(
    compiled: CompiledExpression,
) -> tuple[CompiledExpression, ...]:
    split: list[CompiledExpression] = []
    for segment in compiled.segments:
        resolution = compiled.version_class
        if resolution not in {
            "EXPLICIT_ALL",
            "CPE_ANY_UNCORROBORATED",
            "UNSPECIFIED",
            "NOT_APPLICABLE",
            "UNPARSED",
            "BRANCH_RANGE",
        }:
            if segment.exact is not None:
                resolution = "EXACT"
            elif segment.lower is not None and segment.upper is not None:
                resolution = "BOUNDED_RANGE"
            elif segment.lower is not None or segment.upper is not None:
                resolution = "UNBOUNDED_RANGE"
        split.append(
            replace(
                compiled,
                version_class=resolution,
                segments=(segment,),
            )
        )
    return tuple(split)


def _llm_axes() -> dict[str, tuple[str, str | None]]:
    """Return the context-free scope used by a description binding."""

    return {
        "part": ("ANY", None),
        "distribution": ("ANY", None),
        "edition": ("ANY", None),
        "component": ("ANY", None),
        "update": ("ANY", None),
        "language": ("ANY", None),
        "sw_edition": ("ANY", None),
        "target_sw": ("ANY", None),
        "target_hw": ("ANY", None),
        "other": ("ANY", None),
    }


def _compile_llm_range(
    value: GroundedLLMRange,
    *,
    product_key: str,
) -> CompiledExpression | None:
    """Compile one span-grounded legacy range without inventing bounds."""

    terms: list[str] = []
    if value.start is not None:
        if value.start_inclusive is None:
            return None
        terms.append(
            f"{'>=' if value.start_inclusive else '>'} {value.start}"
        )
    if value.end is not None:
        if value.end_inclusive is None:
            return None
        terms.append(f"{'<=' if value.end_inclusive else '<'} {value.end}")
    if not terms:
        return None
    compiled = compile_cna(
        version=", ".join(terms),
        status="affected",
        product_key=product_key,
        less_than=None,
        less_than_or_equal=None,
        version_type=None,
        changes=(),
    )
    if compiled.parse_status != "parsed":
        return None
    return compiled


_STRUCTURED_DECISION_VERSION_CLASSES = frozenset(
    {
        "EXACT",
        "BOUNDED_RANGE",
        "UNBOUNDED_RANGE",
        "BRANCH_RANGE",
        "EXPLICIT_ALL",
        "NOT_APPLICABLE",
    }
)


def _has_structured_version_decision(
    assertions: Sequence[AssertionInfo],
) -> bool:
    """Return whether structured evidence already supplies a usable decision.

    Legacy LLM output is derived from the same NVD description and therefore
    cannot independently arbitrate or improve an already parsed CNA/CPE range.
    Keep its claims for audit, but only materialize an applicability assertion
    when structured evidence for the resolved product is genuinely absent.
    """

    return any(
        item.source_family != "llm_description"
        and item.parse_status == "parsed"
        and item.polarity in {"affected", "unaffected"}
        and item.version_class in _STRUCTURED_DECISION_VERSION_CLASSES
        and item.reconciliation not in {
            "suppressed_lower_priority",
            "unparsed_review",
        }
        for item in assertions
    )


def _legacy_llm_range_rejection_reason(
    value: GroundedLLMRange,
) -> str | None:
    """Apply the safe subset supported by the legacy LLM schema.

    The legacy JSONL has no branch, component, relation, or clause grouping.
    An end-only range such as ``<9.0.87`` can therefore absorb unrelated 8.x
    queries when several maintenance lines occur in one description.  Only a
    range with explicit lower and upper bounds is safe enough to become a
    provisional applicability assertion.  Rejected ranges remain preserved in
    ``llm_claim`` and ``llm_result`` for audit and future reprocessing.
    """

    if value.start is None or value.end is None:
        return "legacy_unbounded_range_without_branch_context"
    if value.start_inclusive is None or value.end_inclusive is None:
        return "missing_bound_inclusivity"
    return None


def _anchor_cna_zero_lower(
    compiled: CompiledExpression,
    *,
    raw_version: str,
    status: str,
    identity_key: tuple[str, str],
    nvd_ranges: Mapping[tuple[str, str], Sequence[Segment]],
    parallel_zero_upper_count: int = 0,
) -> tuple[CompiledExpression, int]:
    """Narrow a CNA ``0 .. upper`` range with a corroborating NVD lower bound.

    CNA records sometimes encode parallel maintenance lines as multiple
    ``version: 0, lessThan: ...`` entries for the same product. Interpreting
    each zero as negative infinity lets a broad 7.x endpoint absorb older
    ImageMagick release lines. NVD CPE enrichment can carry the missing branch
    start.

    A single zero-lower range is not sufficient evidence of a missing branch
    start: it may intentionally cover every earlier release (for example,
    Moodle ``0 .. 4.1.12``). Only copy an NVD start when the CNA record has at
    least two distinct zero-lower upper endpoints for the same identity and the
    normalized product, upper endpoint, and upper inclusivity agree.
    """

    if (
        raw_version.strip() != "0"
        or _status(status) != "affected"
        or compiled.parse_status != "parsed"
        or compiled.profile == "opaque"
        or parallel_zero_upper_count < 2
    ):
        return compiled, 0

    available = nvd_ranges.get(identity_key, ())
    if not available:
        return compiled, 0

    output: list[Segment] = []
    anchored = 0
    for segment in compiled.segments:
        if (
            segment.lower is not None
            or segment.upper is None
            or segment.exact is not None
        ):
            output.append(segment)
            continue

        candidates: dict[tuple[str, bool], Segment] = {}
        unbounded_match = False
        for nvd_segment in available:
            if (
                nvd_segment.upper is None
                or bool(nvd_segment.upper_inclusive)
                != bool(segment.upper_inclusive)
            ):
                continue
            try:
                same_upper = (
                    compare_versions(
                        segment.upper,
                        nvd_segment.upper,
                        compiled.profile,
                    )
                    == 0
                )
            except ValueError:
                continue
            if not same_upper:
                continue
            if nvd_segment.lower is None:
                unbounded_match = True
                continue
            try:
                valid_interval = (
                    compare_versions(
                        nvd_segment.lower,
                        segment.upper,
                        compiled.profile,
                    )
                    < 0
                )
            except ValueError:
                continue
            if valid_interval:
                candidates[
                    (
                        nvd_segment.lower,
                        bool(nvd_segment.lower_inclusive),
                    )
                ] = nvd_segment

        if unbounded_match or len(candidates) != 1:
            output.append(segment)
            continue

        (lower, lower_inclusive), _ = next(iter(candidates.items()))
        output.append(
            replace(
                segment,
                lower=lower,
                lower_inclusive=lower_inclusive,
                lower_arity=arity_semantics(
                    lower,
                    compiled.profile,
                    explicit_type=True,
                ),
                transition_source="nvd_cpe_matching_upper_bound",
                closure_origin="cna_zero_lower_anchored",
                breadth_class="bounded",
            )
        )
        anchored += 1

    if not anchored:
        return compiled, 0
    version_class = (
        "BOUNDED_RANGE"
        if len(output) == 1
        and output[0].lower is not None
        and output[0].upper is not None
        else compiled.version_class
    )
    return (
        replace(
            compiled,
            version_class=version_class,
            segments=tuple(output),
        ),
        anchored,
    )


def _insert_assertion(
    store: Store,
    *,
    cve_id: str,
    product_id: int,
    scope_id: int,
    source_claim_id: int,
    source_family: str,
    claim_group: str,
    compiled: CompiledExpression,
    entity_basis: str,
    default_inferred: bool,
    default_effective: str,
    is_default: bool,
    branch_coverage: str,
    branch_basis: str,
    role: str | None,
    role_basis: str | None,
    axes: Mapping[str, tuple[str, str | None]],
    llm_claim_id: int | None = None,
    provisional: bool = False,
) -> AssertionInfo:
    expression_id, _ = store.add_expression(source_claim_id, compiled)
    segment = compiled.segments[0]
    polarity = _status(segment.status)
    scope_status = _scope_status(axes)
    rank = evidence_tuple(
        source_family=source_family,
        version_class=compiled.version_class,
        role=role,
        scope_specificity=_scope_specificity(axes),
    )
    initial_reconciliation = (
        "unparsed_review"
        if compiled.parse_status != "parsed"
        else "active"
    )
    assertion_id = store.add_assertion(
        cve_id=cve_id,
        scope_id=scope_id,
        expression_id=expression_id,
        source_claim_id=source_claim_id,
        source_family=source_family,
        claim_group=claim_group,
        polarity=polarity,
        evidence_tier=compiled.evidence_tier,
        entity_basis=entity_basis,
        llm_claim_id=llm_claim_id,
        default_inferred=default_inferred,
        default_effective=default_effective,
        is_default_closure=is_default,
        branch_coverage=branch_coverage,
        branch_coverage_basis=branch_basis,
        version_class=compiled.version_class,
        max_result_state=(
            "potentially_affected"
            if provisional
            else _max_result(role, compiled.version_class)
        ),
        cpe_role=role,
        role_basis=role_basis,
        use_for_version_index=(
            False
            if provisional
            else _can_index(
                role=role,
                version_class=compiled.version_class,
                scope_status=scope_status,
                parse_status=compiled.parse_status,
            )
        ),
        corroboration_independence="single_source",
        comparison_tuple=rank,
        breadth_class=segment.breadth_class,
        scope_status=scope_status,
        version_status=(
            "resolved"
            if compiled.parse_status == "parsed"
            and compiled.version_class
            not in {"UNSPECIFIED", "UNPARSED", "CPE_ANY_UNCORROBORATED"}
            else "unresolved"
        ),
        reconciliation_status=initial_reconciliation,
    )
    return AssertionInfo(
        assertion_id=assertion_id,
        product_id=product_id,
        source_family=source_family,
        polarity=polarity,
        scope_id=scope_id,
        semantic_fingerprint=compiled.semantic_fingerprint,
        constraint_fingerprint=compiled.constraint_fingerprint,
        version_class=compiled.version_class,
        comparison_tuple=rank,
        role=role,
        is_default=is_default,
        parse_status=compiled.parse_status,
        reconciliation=initial_reconciliation,
        reason=(
            compiled.parse_error or "unparsed"
            if initial_reconciliation == "unparsed_review"
            else "admitted"
        ),
    )


def _reconcile(assertions: list[AssertionInfo]) -> None:
    def preferred(values: Sequence[AssertionInfo]) -> AssertionInfo:
        # A single-pass legacy LLM extraction may supplement structured data,
        # but it must never suppress or override NVD/CNA evidence.
        authoritative = [
            item for item in values if item.source_family != "llm_description"
        ]
        return max(
            authoritative or list(values),
            key=lambda item: item.comparison_tuple,
        )

    by_product: dict[int, list[AssertionInfo]] = defaultdict(list)
    for item in assertions:
        by_product[item.product_id].append(item)
    for product_assertions in by_product.values():
        active = [
            item for item in product_assertions if item.reconciliation == "active"
        ]
        duplicate_groups: dict[
            tuple[int, str, str, bool], list[AssertionInfo]
        ] = defaultdict(list)
        for item in active:
            duplicate_groups[
                (
                    item.scope_id,
                    item.semantic_fingerprint,
                    item.polarity,
                    item.is_default,
                )
            ].append(item)
        for duplicates in duplicate_groups.values():
            if len(duplicates) < 2:
                continue
            winner = preferred(duplicates)
            for loser in duplicates:
                if loser is winner:
                    continue
                loser.reconciliation = "corroborating"
                loser.winner_id = winner.assertion_id
                loser.reason = "semantic_duplicate"

        active = [
            item for item in product_assertions if item.reconciliation == "active"
        ]
        has_concrete_cna = any(
            item.source_family == "cna_structured"
            and item.version_class
            in {"EXACT", "BOUNDED_RANGE", "UNBOUNDED_RANGE", "BRANCH_RANGE"}
            and not item.is_default
            for item in active
        )
        if has_concrete_cna:
            winners = [
                item
                for item in active
                if item.source_family == "cna_structured"
                and item.version_class
                in {"EXACT", "BOUNDED_RANGE", "UNBOUNDED_RANGE", "BRANCH_RANGE"}
            ]
            winner = max(winners, key=lambda item: item.comparison_tuple)
            for item in active:
                if (
                    item.source_family == "nvd_cpe"
                    and item.version_class == "CPE_ANY_UNCORROBORATED"
                ):
                    item.reconciliation = "suppressed_lower_priority"
                    item.winner_id = winner.assertion_id
                    item.reason = "specificity_override"

        active = [
            item for item in product_assertions if item.reconciliation == "active"
        ]
        conflict_groups: dict[
            tuple[int, str, bool], list[AssertionInfo]
        ] = defaultdict(list)
        for item in active:
            if item.polarity in {"affected", "unaffected"}:
                conflict_groups[
                    (
                        item.scope_id,
                        item.constraint_fingerprint,
                        item.is_default,
                    )
                ].append(item)
        for values in conflict_groups.values():
            affected = [
                item for item in values if item.polarity == "affected"
            ]
            unaffected = [
                item for item in values if item.polarity == "unaffected"
            ]
            if not affected or not unaffected:
                continue
            left = preferred(affected)
            right = preferred(unaffected)
            if (
                left.source_family == "llm_description"
                and right.source_family != "llm_description"
            ):
                left.reconciliation = "suppressed_lower_priority"
                left.winner_id = right.assertion_id
                left.reason = "llm_preliminary_lower_priority"
                continue
            if (
                right.source_family == "llm_description"
                and left.source_family != "llm_description"
            ):
                right.reconciliation = "suppressed_lower_priority"
                right.winner_id = left.assertion_id
                right.reason = "llm_preliminary_lower_priority"
                continue
            if evidence_wins(left.comparison_tuple, right.comparison_tuple):
                right.reconciliation = "suppressed_lower_priority"
                right.winner_id = left.assertion_id
                right.reason = "polarity_conflict_lower_priority"
            elif evidence_wins(right.comparison_tuple, left.comparison_tuple):
                left.reconciliation = "suppressed_lower_priority"
                left.winner_id = right.assertion_id
                left.reason = "polarity_conflict_lower_priority"
            else:
                left.reconciliation = right.reconciliation = "conflict_review"
                left.reason = right.reason = "equal_rank_polarity_conflict"


def _assertion_reconciliation_rows(
    store: Store, assertions: Sequence[AssertionInfo]
) -> None:
    for item in assertions:
        store.reconcile(
            item.assertion_id,
            status=item.reconciliation,
            winner=item.winner_id,
            reason=item.reason,
            triggering_axis=(
                "version"
                if item.reason
                in {
                    "specificity_override",
                    "polarity_conflict_lower_priority",
                    "equal_rank_polarity_conflict",
                    "llm_preliminary_lower_priority",
                }
                else None
            ),
            triggering_tier="primary",
            comparison_tuple=item.comparison_tuple,
        )


def _default_expression(effective: str, inferred: bool) -> CompiledExpression:
    if effective in {"affected", "unaffected"}:
        resolution = "EXPLICIT_ALL"
        segment = Segment(
            status=effective,
            transition_source="defaultStatus_closure",
            closure_origin=f"default_{effective}",
            breadth_class="unbounded",
        )
        kind = "all_token"
    else:
        resolution = "UNSPECIFIED"
        segment = Segment(
            status="unknown",
            transition_source="defaultStatus_closure",
            closure_origin=(
                "default_status_omitted"
                if inferred
                else "default_status_unknown"
            ),
            breadth_class="unbounded",
        )
        kind = "missing"
    return CompiledExpression(
        raw_expression=canonical_json(
            {
                "defaultStatus": None if inferred else effective,
                "effective": effective,
                "inferred": inferred,
            }
        ),
        version_kind=kind,
        version_class=resolution,
        parse_status="parsed",
        parse_error=None,
        profile="opaque",
        segments=(segment,),
    )


def _primary_description(
    parsed_descriptions: Sequence[tuple[str, str | None, bytes, str]]
) -> tuple[str | None, str | None]:
    for description_id, language, raw_bytes, _ in parsed_descriptions:
        if (language or "").casefold() == "en":
            return description_id, raw_bytes.decode("utf-8")
    if parsed_descriptions:
        description_id, _, raw_bytes, _ = parsed_descriptions[0]
        return description_id, raw_bytes.decode("utf-8")
    return None, None


def _record_issue(
    store: Store,
    *,
    cve_id: str | None,
    stage: str,
    issue: tuple[str, str, str],
) -> None:
    code, pointer, message = issue
    store.add_issue(
        code=code,
        stage=stage,
        severity="medium",
        cve_id=cve_id,
        details={"pointer": pointer, "message": message},
    )


def _publish_audit(
    connection: sqlite3.Connection,
    *,
    progress: Callable[[str, Mapping[str, Any]], None] | None = None,
) -> dict[str, int]:
    checks = {
        "binding_without_assertion": """
            SELECT COUNT(*) FROM cve_applicability_binding b
            LEFT JOIN binding_assertion_member m USING(binding_id)
            WHERE m.binding_id IS NULL
        """,
        "binding_manual_review_drift": """
            WITH expected(binding_id) AS MATERIALIZED (
              SELECT DISTINCT m.binding_id
              FROM binding_assertion_member m
              JOIN applicability_assertion a USING(assertion_id)
              WHERE m.is_active=1
                AND (
                  a.cpe_match_role='UNRESOLVED'
                  OR a.reconciliation_status IN (
                    'conflict_review','unparsed_review'
                  )
                )
            )
            SELECT COUNT(*)
            FROM cve_applicability_binding b
            LEFT JOIN expected e USING(binding_id)
            WHERE b.manual_review_required<>(e.binding_id IS NOT NULL)
        """,
        "llm_version_active": """
            SELECT COUNT(*) FROM applicability_assertion a
            JOIN source_claim c USING(source_claim_id)
            WHERE c.source_family='llm_description'
              AND a.reconciliation_status IN ('active','conflict_review')
              AND (
                a.max_result_state IS NOT 'potentially_affected'
                OR a.use_for_version_index<>0
                OR a.llm_claim_id IS NULL
              )
        """,
        "cpe_any_strict_index": """
            SELECT COUNT(*) FROM applicability_assertion
            WHERE version_resolution_class='CPE_ANY_UNCORROBORATED'
              AND use_for_version_index=1
        """,
        "cpe_any_result_ceiling": """
            SELECT COUNT(*) FROM applicability_assertion
            WHERE version_resolution_class='CPE_ANY_UNCORROBORATED'
              AND max_result_state IS NOT 'potentially_affected'
        """,
        "downstream_upstream_index": """
            SELECT COUNT(*) FROM applicability_assertion
            WHERE cpe_match_role LIKE 'DOWNSTREAM_%'
              AND use_for_version_index=1
        """,
        "unresolved_strict_index": """
            SELECT COUNT(*) FROM applicability_assertion
            WHERE cpe_match_role='UNRESOLVED' AND use_for_version_index=1
        """,
        "cpe_role_missing": """
            SELECT COUNT(*) FROM applicability_assertion
            WHERE source_family='nvd_cpe'
              AND reconciliation_status IN ('active','conflict_review')
              AND (cpe_match_role IS NULL OR role_basis IS NULL)
        """,
        "unspecified_strict_index": """
            SELECT COUNT(*) FROM applicability_assertion
            WHERE version_resolution_class='UNSPECIFIED'
              AND use_for_version_index=1
        """,
        "unknown_default_assertion": """
            SELECT COUNT(*) FROM applicability_assertion
            WHERE source_family='cna_structured'
              AND is_default_closure=1
              AND default_status_effective='unknown'
        """,
        "vulnerable_false_positive": """
            SELECT COUNT(*) FROM applicability_assertion a
            JOIN source_claim c USING(source_claim_id)
            WHERE c.vulnerable_flag=0 AND a.assertion_polarity='affected'
        """,
        "omitted_default_unaffected": """
            SELECT COUNT(*) FROM applicability_assertion a
            JOIN source_claim c USING(source_claim_id)
            WHERE c.source_family='cna_structured'
              AND c.default_status_raw IS NULL
              AND a.default_status_inferred=1
              AND a.default_status_effective='unaffected'
        """,
        "comparator_stored_exact": """
            SELECT COUNT(*) FROM version_segment
            WHERE exact_value GLOB '<*' OR exact_value GLOB '>*'
               OR exact_value GLOB '=*' OR exact_value GLOB '!*'
        """,
        "legacy_wildcard_kind": """
            SELECT COUNT(*) FROM version_expression WHERE version_kind='wildcard'
        """,
        "cpe_range_field_loss": """
            SELECT COUNT(*) FROM source_claim c
            WHERE c.source_family='nvd_cpe' AND c.version_raw='*'
              AND CASE
                WHEN (
                  (c.version_start_including IS NOT NULL) +
                  (c.version_start_excluding IS NOT NULL) +
                  (c.version_end_including IS NOT NULL) +
                  (c.version_end_excluding IS NOT NULL)
                ) = 0
                THEN c.version_resolution_class
                     <> 'CPE_ANY_UNCORROBORATED'
                ELSE c.version_resolution_class
                     NOT IN ('BOUNDED_RANGE','UNBOUNDED_RANGE','UNPARSED')
              END
        """,
        "cpe_range_segment_loss": """
            SELECT COUNT(*)
            FROM source_claim c
            JOIN version_expression e USING(source_claim_id)
            JOIN version_segment v USING(expression_id)
            WHERE c.source_family='nvd_cpe'
              AND c.version_resolution_class
                  IN ('BOUNDED_RANGE','UNBOUNDED_RANGE')
              AND (
                ((c.version_start_including IS NOT NULL
                  OR c.version_start_excluding IS NOT NULL)
                 AND v.lower_bound IS NULL)
                OR
                ((c.version_end_including IS NOT NULL
                  OR c.version_end_excluding IS NOT NULL)
                 AND v.upper_bound IS NULL)
              )
        """,
        "cna_scope_resolution_collapse": """
            SELECT CASE
              WHEN NOT EXISTS (
                SELECT 1 FROM source_snapshot_manifest WHERE is_complete=1
              ) THEN 0
              WHEN COUNT(*)=0 THEN 0
              WHEN 100 * SUM(scope_resolution_status='resolved')
                   < 95 * COUNT(*) THEN 1
              ELSE 0
            END
            FROM applicability_assertion
            WHERE source_family='cna_structured'
              AND reconciliation_status <> 'unparsed_review'
        """,
        "cpe_role_resolution_collapse": """
            SELECT CASE
              WHEN NOT EXISTS (
                SELECT 1 FROM source_snapshot_manifest WHERE is_complete=1
              ) THEN 0
              WHEN COUNT(*)=0 THEN 0
              WHEN 100 * SUM(cpe_match_role='UNRESOLVED')
                   > 90 * COUNT(*) THEN 1
              ELSE 0
            END
            FROM applicability_assertion
            WHERE source_family='nvd_cpe'
              AND reconciliation_status IN ('active','conflict_review')
        """,
        "eligible_version_index_empty": """
            SELECT CASE
              WHEN NOT EXISTS (
                SELECT 1 FROM source_snapshot_manifest WHERE is_complete=1
              ) THEN 0
              WHEN COUNT(*)=0 THEN 0
              WHEN SUM(use_for_version_index)=0 THEN 1
              ELSE 0
            END
            FROM applicability_assertion
            WHERE cpe_match_role IN (
                    'DIRECT_UPSTREAM','DIRECT_ALTERNATIVE_PRODUCT'
                  )
              AND source_family<>'llm_description'
              AND scope_resolution_status='resolved'
              AND version_resolution_status='resolved'
              AND reconciliation_status IN ('active','conflict_review')
        """,
        "changes_outside_upper_discarded": """
            SELECT COUNT(*) FROM normalization_issue
            WHERE details_json LIKE '%changes_outside_upper_bound%'
        """,
        "comparator_token_in_bound": """
            SELECT COUNT(*) FROM version_segment
            WHERE lower_bound GLOB '*[<>=!]*'
               OR upper_bound GLOB '*[<>=!]*'
        """,
        "alias_hard_distinct_cluster": """
            SELECT COUNT(*)
            FROM identity_hard_distinct d
            JOIN identity_cluster_member l ON l.node_id=d.left_node_id
            JOIN identity_cluster_member r ON r.node_id=d.right_node_id
            WHERE l.cluster_id=r.cluster_id
        """,
        "alias_missing_evidence": """
            SELECT COUNT(*) FROM identity_alias_edge
            WHERE evidence_tier IS NULL OR evidence_tier=''
               OR basis_json IS NULL OR basis_json=''
        """,
        "alias_basis_envelope_invalid": """
            SELECT COALESCE(SUM(
              CASE
                WHEN json_valid(basis_json)=0 THEN 1
                WHEN json_extract(basis_json,'$.format')
                     IS NOT 'bounded_evidence_v1' THEN 1
                WHEN json_type(basis_json,'$.evidence') IS NOT 'array' THEN 1
                WHEN json_type(basis_json,'$.evidence_count')
                     IS NOT 'integer' THEN 1
                WHEN json_type(basis_json,'$.evidence_examples_limit')
                     IS NOT 'integer' THEN 1
                WHEN json_extract(basis_json,'$.evidence_examples_limit')
                     <>32 THEN 1
                WHEN json_type(basis_json,'$.evidence_truncated')
                     NOT IN ('true','false') THEN 1
                WHEN json_array_length(basis_json,'$.evidence')>32 THEN 1
                WHEN json_extract(basis_json,'$.evidence_count')
                     <json_array_length(basis_json,'$.evidence') THEN 1
                ELSE 0
              END
            ),0)
            FROM identity_alias_edge
        """,
        "alias_llm_accepted": """
            SELECT COUNT(*) FROM identity_alias_edge
            WHERE evidence_tier='E4' AND status='accepted'
        """,
        "alias_nonaccepted_cluster_edge": """
            SELECT COUNT(*) FROM identity_cluster_edge ce
            JOIN identity_alias_edge e USING(edge_id)
            WHERE e.status<>'accepted'
        """,
        "alias_oversize_not_review": """
            SELECT COUNT(*) FROM identity_cluster
            WHERE member_count>8 AND review_state='ok'
        """,
        "alias_strict_cluster_contaminated": """
            SELECT COUNT(*) FROM identity_cluster c
            WHERE c.strict_eligible=1 AND EXISTS (
                SELECT 1 FROM identity_cluster_edge ce
                JOIN identity_alias_edge e USING(edge_id)
                WHERE ce.cluster_id=c.cluster_id AND e.strict_eligible=0
            )
        """,
        "identity_digest_missing": """
            SELECT COUNT(*) FROM binding_revision
            WHERE state='draft' AND identity_cluster_digest IS NULL
        """,
        "identity_role_reconciliation_drift": """
            SELECT COUNT(*)
            FROM applicability_assertion a
            JOIN assertion_reconciliation r USING(assertion_id)
            WHERE a.comparison_tuple_json<>r.comparison_tuple_json
        """,
        "identity_raw_key_provenance": """
            SELECT COUNT(*)
            FROM identity_key k
            LEFT JOIN product_alias a
              ON a.product_alias_id=k.source_alias_id
            WHERE k.origin='raw_alias_observation'
              AND a.product_alias_id IS NULL
        """,
    }
    results: dict[str, int] = {}

    # These checks previously performed independent full scans of the
    # assertion table. Conditional aggregation preserves every predicate
    # while bounding the work to one pass.
    assertion_started = time.perf_counter()
    assertion = connection.execute(
        """SELECT
             SUM(CASE
                   WHEN version_resolution_class='CPE_ANY_UNCORROBORATED'
                    AND use_for_version_index=1 THEN 1 ELSE 0
                 END) AS cpe_any_strict_index,
             SUM(CASE
                   WHEN version_resolution_class='CPE_ANY_UNCORROBORATED'
                    AND max_result_state IS NOT 'potentially_affected'
                   THEN 1 ELSE 0
                 END) AS cpe_any_result_ceiling,
             SUM(CASE
                   WHEN cpe_match_role LIKE 'DOWNSTREAM_%'
                    AND use_for_version_index=1 THEN 1 ELSE 0
                 END) AS downstream_upstream_index,
             SUM(CASE
                   WHEN cpe_match_role='UNRESOLVED'
                    AND use_for_version_index=1 THEN 1 ELSE 0
                 END) AS unresolved_strict_index,
             SUM(CASE
                   WHEN source_family='nvd_cpe'
                    AND reconciliation_status IN ('active','conflict_review')
                    AND (cpe_match_role IS NULL OR role_basis IS NULL)
                   THEN 1 ELSE 0
                 END) AS cpe_role_missing,
             SUM(CASE
                   WHEN version_resolution_class='UNSPECIFIED'
                    AND use_for_version_index=1 THEN 1 ELSE 0
                 END) AS unspecified_strict_index,
             SUM(CASE
                   WHEN source_family='cna_structured'
                    AND is_default_closure=1
                    AND default_status_effective='unknown'
                   THEN 1 ELSE 0
                 END) AS unknown_default_assertion,
             SUM(CASE
                   WHEN source_family='cna_structured'
                    AND reconciliation_status<>'unparsed_review'
                   THEN 1 ELSE 0
                 END) AS cna_total,
             SUM(CASE
                   WHEN source_family='cna_structured'
                    AND reconciliation_status<>'unparsed_review'
                    AND scope_resolution_status='resolved'
                   THEN 1 ELSE 0
                 END) AS cna_resolved,
             SUM(CASE
                   WHEN source_family='nvd_cpe'
                    AND reconciliation_status IN ('active','conflict_review')
                   THEN 1 ELSE 0
                 END) AS cpe_total,
             SUM(CASE
                   WHEN source_family='nvd_cpe'
                    AND reconciliation_status IN ('active','conflict_review')
                    AND cpe_match_role='UNRESOLVED'
                   THEN 1 ELSE 0
                 END) AS cpe_unresolved,
             SUM(CASE
                   WHEN cpe_match_role IN (
                          'DIRECT_UPSTREAM','DIRECT_ALTERNATIVE_PRODUCT'
                        )
                    AND source_family<>'llm_description'
                    AND scope_resolution_status='resolved'
                    AND version_resolution_status='resolved'
                    AND reconciliation_status IN ('active','conflict_review')
                   THEN 1 ELSE 0
                 END) AS eligible_total,
             SUM(CASE
                   WHEN cpe_match_role IN (
                          'DIRECT_UPSTREAM','DIRECT_ALTERNATIVE_PRODUCT'
                        )
                    AND source_family<>'llm_description'
                    AND scope_resolution_status='resolved'
                    AND version_resolution_status='resolved'
                    AND reconciliation_status IN ('active','conflict_review')
                   THEN use_for_version_index ELSE 0
                 END) AS eligible_indexed
           FROM applicability_assertion"""
    ).fetchone()
    assert assertion is not None
    for name in (
        "cpe_any_strict_index",
        "cpe_any_result_ceiling",
        "downstream_upstream_index",
        "unresolved_strict_index",
        "cpe_role_missing",
        "unspecified_strict_index",
        "unknown_default_assertion",
    ):
        results[name] = int(assertion[name] or 0)
        checks.pop(name)
    complete_manifest = bool(
        connection.execute(
            """SELECT EXISTS(
                   SELECT 1 FROM source_snapshot_manifest WHERE is_complete=1
               )"""
        ).fetchone()[0]
    )
    cna_total = int(assertion["cna_total"] or 0)
    cpe_total = int(assertion["cpe_total"] or 0)
    eligible_total = int(assertion["eligible_total"] or 0)
    results["cna_scope_resolution_collapse"] = int(
        complete_manifest
        and cna_total > 0
        and 100 * int(assertion["cna_resolved"] or 0) < 95 * cna_total
    )
    results["cpe_role_resolution_collapse"] = int(
        complete_manifest
        and cpe_total > 0
        and 100 * int(assertion["cpe_unresolved"] or 0) > 90 * cpe_total
    )
    results["eligible_version_index_empty"] = int(
        complete_manifest
        and eligible_total > 0
        and int(assertion["eligible_indexed"] or 0) == 0
    )
    for name in (
        "cna_scope_resolution_collapse",
        "cpe_role_resolution_collapse",
        "eligible_version_index_empty",
    ):
        checks.pop(name)
    if progress is not None:
        progress(
            "assertion_checks_complete",
            {
                "checks": 10,
                "elapsed_seconds": round(
                    time.perf_counter() - assertion_started, 3
                ),
            },
        )

    # Likewise, all assertion/source-claim invariants share the same primary
    # key join and can be evaluated in one pass.
    claim_started = time.perf_counter()
    claim = connection.execute(
        """SELECT
             SUM(CASE
                   WHEN c.source_family='llm_description'
                    AND a.reconciliation_status IN ('active','conflict_review')
                    AND (
                      a.max_result_state IS NOT 'potentially_affected'
                      OR a.use_for_version_index<>0
                      OR a.llm_claim_id IS NULL
                    )
                   THEN 1 ELSE 0
                 END) AS llm_version_active,
             SUM(CASE
                   WHEN c.vulnerable_flag=0
                    AND a.assertion_polarity='affected'
                   THEN 1 ELSE 0
                 END) AS vulnerable_false_positive,
             SUM(CASE
                   WHEN c.source_family='cna_structured'
                    AND c.default_status_raw IS NULL
                    AND a.default_status_inferred=1
                    AND a.default_status_effective='unaffected'
                   THEN 1 ELSE 0
                 END) AS omitted_default_unaffected
           FROM applicability_assertion a
           JOIN source_claim c USING(source_claim_id)"""
    ).fetchone()
    assert claim is not None
    for name in (
        "llm_version_active",
        "vulnerable_false_positive",
        "omitted_default_unaffected",
    ):
        results[name] = int(claim[name] or 0)
        checks.pop(name)
    if progress is not None:
        progress(
            "source_claim_checks_complete",
            {
                "checks": 3,
                "elapsed_seconds": round(
                    time.perf_counter() - claim_started, 3
                ),
            },
        )

    for name, sql in checks.items():
        check_started = time.perf_counter()
        results[name] = int(connection.execute(sql).fetchone()[0])
        if progress is not None:
            progress(
                "check_complete",
                {
                    "check": name,
                    "count": results[name],
                    "elapsed_seconds": round(
                        time.perf_counter() - check_started, 3
                    ),
                },
            )
    return results


def build_database(
    *,
    input_path: Path,
    database_path: Path,
    llm_path: Path | None,
    llm_fail_path: Path | None,
    replace_existing: bool,
    limit: int | None,
    progress_every: int,
) -> Mapping[str, Any]:
    if not input_path.is_file():
        raise BuildError(f"NVD input does not exist: {input_path}")
    if llm_path is not None and not llm_path.is_file():
        raise BuildError(f"LLM input does not exist: {llm_path}")
    if llm_fail_path is not None and not llm_fail_path.is_file():
        raise BuildError(f"LLM failure input does not exist: {llm_fail_path}")
    database_path.parent.mkdir(parents=True, exist_ok=True)
    if database_path.exists() and not replace_existing:
        raise BuildError(
            f"database already exists (pass --replace to atomically replace it): "
            f"{database_path}"
        )
    temporary = database_path.with_name(
        f".{database_path.name}.tmp.{os.getpid()}"
    )
    if temporary.exists():
        temporary.unlink()
    store = Store(temporary)
    llm_stream: LLMResultStream | None = None
    input_stat = input_path.stat()
    counters: dict[str, int] = defaultdict(int)
    first_cve: str | None = None
    last_cve: str | None = None
    build_started = time.perf_counter()
    stage_seconds: dict[str, float] = {}

    def emit_stage(
        stage: str,
        event: str,
        *,
        started: float | None = None,
        **details: Any,
    ) -> None:
        if not progress_every:
            return
        payload: dict[str, Any] = {
            "stage": stage,
            "event": event,
            **details,
        }
        if started is not None:
            payload["elapsed_seconds"] = round(time.perf_counter() - started, 3)
        print(canonical_json(payload), file=sys.stderr, flush=True)

    def begin_stage(stage: str, **details: Any) -> float:
        emit_stage(stage, "start", **details)
        return time.perf_counter()

    def end_stage(stage: str, started: float, **details: Any) -> None:
        elapsed = time.perf_counter() - started
        stage_seconds[stage] = round(elapsed, 3)
        emit_stage(stage, "complete", started=started, **details)

    try:
        (
            duplicate_losers,
            input_row_count,
            duplicate_cve_count,
            duplicate_examples,
        ) = _duplicate_loser_indexes(input_path, limit=limit)
        counters["input_rows"] = input_row_count
        counters["deduplicated_rows"] = len(duplicate_losers)
        counters["duplicate_cves"] = duplicate_cve_count
        store.initialize()
        snapshot_id = store.create_snapshot(
            input_path, is_complete=limit is None
        )
        reinterpretation_token = stable_hash(
            {
                "rule": RULE_CONFIGURATION_SHA256,
                "framework": FRAMEWORK_VERSION,
                "llm_schema": LEGACY_SCHEMA_HASH if llm_path else None,
            }
        )
        run_uuid = stable_hash(
            {
                "snapshot_path": str(input_path.resolve()),
                "input_size": input_stat.st_size,
                "input_mtime_ns": input_stat.st_mtime_ns,
                "reinterpretation": reinterpretation_token,
                "limit": limit,
            }
        )
        pipeline_run_id, revision_id = store.create_run(
            snapshot_id, run_uuid, reinterpretation_token
        )
        llm_run_id: int | None = None
        if llm_path is not None:
            llm_run_id = store.create_llm_run(
                snapshot_id=snapshot_id,
                source_path=llm_path,
                model_id="unavailable_in_supplied_jsonl",
                model_revision="unavailable",
                prompt_hash="unavailable",
                schema_hash=LEGACY_SCHEMA_HASH,
                self_consistency_k=1,
            )
            store.connection.execute(
                """UPDATE binding_revision SET llm_extraction_run_id=?
                   WHERE binding_revision_id=?""",
                (llm_run_id, revision_id),
            )
            store.add_issue(
                code="F-LLM-04",
                stage="llm_run_manifest",
                severity="high",
                cve_id=None,
                details={
                    "reason": "model_prompt_and_self_consistency_metadata_missing",
                    "effect": (
                        "claims are restricted to provisional inclusive "
                        "applicability and cannot produce strict positives"
                    ),
                },
            )
            llm_stream = LLMResultStream(llm_path, llm_fail_path)
        if duplicate_losers:
            store.add_issue(
                code="duplicate_source_revision",
                stage="raw_ingest",
                severity="medium",
                cve_id=None,
                details={
                    "duplicate_cves": duplicate_cve_count,
                    "discarded_rows": len(duplicate_losers),
                    "selection": "max_lastModified_then_source_index",
                    "examples": duplicate_examples,
                },
            )

        input_hasher = hashlib.sha256()
        consumed_bytes = 0
        with input_path.open("rb") as source:
            source_index = 0
            while limit is None or source_index < limit:
                byte_offset = source.tell()
                raw = source.readline()
                if not raw:
                    break
                input_hasher.update(raw)
                consumed_bytes += len(raw)
                line_number = source_index + 1
                if source_index in duplicate_losers:
                    source_index += 1
                    continue
                try:
                    cve = parse_json_line(raw, line_number=line_number)
                except ParseError as error:
                    counters["parse_failures"] += 1
                    store.add_issue(
                        code=error.code,
                        stage="raw_ingest",
                        severity="high",
                        cve_id=None,
                        details={
                            "line_number": line_number,
                            "pointer": error.pointer,
                            "message": str(error),
                            "raw_sha256": hashlib.sha256(raw).hexdigest(),
                        },
                    )
                    source_index += 1
                    continue
                cve_id = str(cve.get("id", cve.get("cveId", cve.get("cve_id"))))
                first_cve = first_cve or cve_id
                last_cve = cve_id
                parsed_descriptions = descriptions(cve_id, cve)
                description_id, primary_description = _primary_description(
                    parsed_descriptions
                )
                cna_items = tuple(iter_cna_affected(cve))
                parsed_configurations = tuple(parse_configurations(cve))
                has_cpe = any(item.matches for item in parsed_configurations)
                has_cna = bool(cna_items)
                vuln_status = str(cve.get("vulnStatus") or "Unknown")
                rejected = vuln_status.casefold() == "rejected"
                enrichment = (
                    "rejected"
                    if rejected
                    else "nvd_enriched"
                    if has_cpe
                    else "cna_only"
                    if has_cna
                    else "unenriched"
                )
                llm_record: Mapping[str, Any] | None = None
                if llm_stream is not None and llm_run_id is not None:
                    llm_record = llm_stream.for_cve(
                        cve_id,
                        primary_description,
                    )
                    if llm_record is None:
                        counters["llm_missing"] += 1
                llm_metadata = (
                    llm_record.get("_meta")
                    if isinstance(llm_record, Mapping)
                    else None
                )
                llm_bindings_value = (
                    llm_record.get("bindings")
                    if isinstance(llm_record, Mapping)
                    else None
                )
                has_llm_identity = bool(
                    llm_record is not None
                    and llm_record.get("description") == primary_description
                    and isinstance(llm_metadata, Mapping)
                    and llm_metadata.get("status") == "ok"
                    and isinstance(llm_bindings_value, list)
                    and llm_bindings_value
                )
                store.add_raw_cve(
                    cve_id=cve_id,
                    snapshot_id=snapshot_id,
                    line_number=line_number,
                    byte_offset=byte_offset,
                    byte_length=len(raw),
                    raw_sha256=hashlib.sha256(raw).hexdigest(),
                    source_identifier=(
                        cve.get("sourceIdentifier")
                        if isinstance(cve.get("sourceIdentifier"), str)
                        else None
                    ),
                    vuln_status=vuln_status,
                    published=(
                        cve.get("published")
                        if isinstance(cve.get("published"), str)
                        else None
                    ),
                    last_modified=(
                        cve.get("lastModified")
                        if isinstance(cve.get("lastModified"), str)
                        else None
                    ),
                    primary_description=primary_description,
                    has_cpe=has_cpe,
                    has_cna=has_cna,
                    has_llm_identity=has_llm_identity,
                    enrichment_class=enrichment,
                    admission_status=(
                        "rejected_upstream" if rejected else "accepted_raw"
                    ),
                )
                for desc_id, language, desc_bytes, pointer in parsed_descriptions:
                    store.add_description(
                        description_id=desc_id,
                        cve_id=cve_id,
                        language=language,
                        raw_bytes=desc_bytes,
                        pointer=pointer,
                    )
                grounded_llm_bindings: list[GroundedLLMBinding] = []
                if llm_record is not None and llm_run_id is not None:
                    llm_counts = ingest_llm_result(
                        store,
                        run_id=llm_run_id,
                        record=llm_record,
                        expected_cve_id=cve_id,
                        source_index=source_index,
                        description_id=description_id,
                        description=primary_description,
                        grounded_bindings=grounded_llm_bindings,
                    )
                    for key, value in llm_counts.items():
                        counters[f"llm_{key}"] += value
                assertions: list[AssertionInfo] = []
                assertions_by_product: dict[int, list[AssertionInfo]] = defaultdict(list)
                product_basis: dict[int, tuple[str, int]] = {}
                direct_products: set[tuple[str, str]] = set()
                cna_product_ids: dict[str, int] = {}
                cna_identity_keys: dict[str, tuple[str, str]] = {}
                cna_zero_lower_uppers: dict[
                    tuple[str, str], set[tuple[str, bool]]
                ] = defaultdict(set)
                if not rejected:
                    for cna_index, item in enumerate(cna_items):
                        canonical_identity = _canonical_cna_identity(item)
                        if canonical_identity is None:
                            continue
                        canonical_vendor, canonical_product = canonical_identity
                        product_id = store.product_id(
                            canonical_vendor,
                            canonical_product,
                            part="unknown",
                            source_family="cna_structured",
                            evidence_basis="authoritative_structured",
                            label_priority=1,
                        )
                        store.add_product_alias(
                            product_id=product_id,
                            vendor=item.vendor,
                            product=item.product,
                            source_family="cna_structured",
                            evidence_basis="authoritative_structured_raw",
                        )
                        identity_key = (
                            normalize_key(canonical_vendor),
                            normalize_key(canonical_product),
                        )
                        direct_products.add(identity_key)
                        cna_product_ids[item.pointer] = product_id
                        cna_identity_keys[item.pointer] = identity_key
                        product_basis[product_id] = (
                            "authoritative_structured",
                            1,
                        )
                        for raw_version in item.versions:
                            raw_value = raw_version.get("version")
                            raw_status = raw_version.get("status")
                            less_than = raw_version.get("lessThan")
                            less_equal = raw_version.get("lessThanOrEqual")
                            if (
                                isinstance(raw_value, str)
                                and raw_value.strip() == "0"
                                and isinstance(raw_status, str)
                                and _status(raw_status) == "affected"
                            ):
                                if isinstance(less_than, str):
                                    cna_zero_lower_uppers[identity_key].add(
                                        (less_than, False)
                                    )
                                elif isinstance(less_equal, str):
                                    cna_zero_lower_uppers[identity_key].add(
                                        (less_equal, True)
                                    )

                    configuration_ids: dict[int, int] = {}
                    nvd_direct_ranges: dict[
                        tuple[str, str], list[Segment]
                    ] = defaultdict(list)
                    for parsed_configuration in parsed_configurations:
                        configuration_id = store.add_configuration(
                            cve_id=cve_id,
                            index=parsed_configuration.configuration_index,
                            graph=parsed_configuration.graph,
                        )
                        configuration_ids[
                            parsed_configuration.configuration_index
                        ] = configuration_id
                        for issue in parsed_configuration.issues:
                            _record_issue(
                                store,
                                cve_id=cve_id,
                                stage="configuration_parse",
                                issue=issue,
                            )
                        for match in parsed_configuration.matches:
                            if is_placeholder(match.cpe.vendor) or is_placeholder(
                                match.cpe.product
                            ):
                                compiled = compile_nvd(
                                    cpe_version=match.cpe.version,
                                    status=(
                                        "affected"
                                        if match.vulnerable
                                        else "unknown"
                                    ),
                                    product_key=normalize_key(match.cpe.product),
                                    version_start_including=(
                                        match.version_start_including
                                    ),
                                    version_start_excluding=(
                                        match.version_start_excluding
                                    ),
                                    version_end_including=match.version_end_including,
                                    version_end_excluding=match.version_end_excluding,
                                )
                                store.add_source_claim(
                                    snapshot_id=snapshot_id,
                                    cve_id=cve_id,
                                    product_id=None,
                                    source_family="nvd_cpe",
                                    source_identifier=match.match_criteria_id,
                                    pointer=match.pointer,
                                    raw_fragment_sha256=raw_fragment_hash(match.raw),
                                    vendor=match.cpe.vendor,
                                    product=match.cpe.product,
                                    version=match.cpe.version,
                                    status=(
                                        "affected"
                                        if match.vulnerable
                                        else "condition"
                                    ),
                                    default_status=None,
                                    version_kind=compiled.version_kind,
                                    version_class=compiled.version_class,
                                    cpe_criteria=match.criteria,
                                    cpe_match_id=match.match_criteria_id,
                                    vulnerable=match.vulnerable,
                                    node_path=match.node_path,
                                    start_including=match.version_start_including,
                                    start_excluding=match.version_start_excluding,
                                    end_including=match.version_end_including,
                                    end_excluding=match.version_end_excluding,
                                    admission_status="quarantined_placeholder",
                                )
                                counters["source_claims"] += 1
                                counters["placeholder_cpe"] += 1
                                continue
                            product_id = store.product_id(
                                match.cpe.vendor,
                                match.cpe.product,
                                part=match.cpe.part,
                                source_family="nvd_cpe",
                                evidence_basis="cpe_dictionary_match",
                                label_priority=4,
                            )
                            product_basis.setdefault(
                                product_id, ("cpe_dictionary_match", 4)
                            )
                            role, role_basis = _role(
                                match,
                                direct_products=direct_products,
                            )
                            compiled = compile_nvd(
                                cpe_version=match.cpe.version,
                                status="affected" if match.vulnerable else "unknown",
                                product_key=normalize_key(match.cpe.product),
                                version_start_including=match.version_start_including,
                                version_start_excluding=match.version_start_excluding,
                                version_end_including=match.version_end_including,
                                version_end_excluding=match.version_end_excluding,
                            )
                            conflicting_bounds = bool(
                                (
                                    match.version_start_including
                                    and match.version_start_excluding
                                )
                                or (
                                    match.version_end_including
                                    and match.version_end_excluding
                                )
                            )
                            if conflicting_bounds:
                                compiled = replace(
                                    compiled,
                                    version_class="UNPARSED",
                                    parse_status="accepted_unparsed",
                                    parse_error="conflicting_nvd_bounds",
                                    segments=(Segment(status="unknown"),),
                                )
                            if (
                                match.vulnerable
                                and role == "DIRECT_UPSTREAM"
                                and compiled.parse_status == "parsed"
                            ):
                                nvd_identity = (
                                    normalize_key(match.cpe.vendor),
                                    normalize_key(match.cpe.product),
                                )
                                nvd_direct_ranges[nvd_identity].extend(
                                    segment
                                    for segment in compiled.segments
                                    if segment.upper is not None
                                )
                            source_claim_id = store.add_source_claim(
                                snapshot_id=snapshot_id,
                                cve_id=cve_id,
                                product_id=product_id,
                                source_family="nvd_cpe",
                                source_identifier=match.match_criteria_id,
                                pointer=match.pointer,
                                raw_fragment_sha256=raw_fragment_hash(match.raw),
                                vendor=match.cpe.vendor,
                                product=match.cpe.product,
                                version=match.cpe.version,
                                status=(
                                    "affected" if match.vulnerable else "condition"
                                ),
                                default_status=None,
                                version_kind=compiled.version_kind,
                                version_class=compiled.version_class,
                                cpe_criteria=match.criteria,
                                cpe_match_id=match.match_criteria_id,
                                vulnerable=match.vulnerable,
                                node_path=match.node_path,
                                start_including=match.version_start_including,
                                start_excluding=match.version_start_excluding,
                                end_including=match.version_end_including,
                                end_excluding=match.version_end_excluding,
                                admission_status=(
                                    "accepted_unparsed"
                                    if compiled.parse_status != "parsed"
                                    else "accepted_raw"
                                ),
                            )
                            counters["source_claims"] += 1
                            if not match.vulnerable:
                                counters["configuration_conditions"] += 1
                                continue
                            axes = _cpe_axes(match.cpe, role)
                            scope_id = store.scope_id(
                                product_id=product_id,
                                axes=axes,
                                configuration_id=configuration_id,
                                configuration_match_id=match.match_path,
                                cpe_role=role,
                                exclusive_scope=(
                                    "distribution_only"
                                    if role
                                    in {
                                        "DOWNSTREAM_DISTRIBUTION",
                                        "DOWNSTREAM_PACKAGE",
                                    }
                                    else None
                                ),
                            )
                            for split in _split_expression(compiled):
                                info = _insert_assertion(
                                    store,
                                    cve_id=cve_id,
                                    product_id=product_id,
                                    scope_id=scope_id,
                                    source_claim_id=source_claim_id,
                                    source_family="nvd_cpe",
                                    claim_group=(
                                        f"nvd:{parsed_configuration.configuration_index}:"
                                        f"{match.node_path}"
                                    ),
                                    compiled=split,
                                    entity_basis="cpe_dictionary_match",
                                    default_inferred=True,
                                    default_effective="unknown",
                                    is_default=False,
                                    branch_coverage="unknown",
                                    branch_basis="none",
                                    role=role,
                                    role_basis=role_basis,
                                    axes=axes,
                                )
                                assertions.append(info)
                                assertions_by_product[product_id].append(info)
                                counters["assertions"] += 1

                    for affected_index, item in enumerate(cna_items):
                        product_id = cna_product_ids.get(item.pointer)
                        identity_key = cna_identity_keys.get(item.pointer)
                        if product_id is None:
                            store.add_source_claim(
                                snapshot_id=snapshot_id,
                                cve_id=cve_id,
                                product_id=None,
                                source_family="cna_structured",
                                source_identifier=item.source_identifier,
                                pointer=item.pointer,
                                raw_fragment_sha256=raw_fragment_hash(item.raw),
                                vendor=item.vendor,
                                product=item.product,
                                version=None,
                                status="unknown",
                                default_status=item.default_status,
                                version_kind="missing",
                                version_class="UNSPECIFIED",
                                cpe_criteria=None,
                                cpe_match_id=None,
                                vulnerable=None,
                                node_path=None,
                                start_including=None,
                                start_excluding=None,
                                end_including=None,
                                end_excluding=None,
                                admission_status="quarantined_placeholder",
                            )
                            counters["source_claims"] += 1
                            counters["placeholder_cna"] += 1
                            continue
                        if identity_key is None:
                            raise BuildError(
                                f"missing canonical CNA identity for {item.pointer}"
                            )
                        vendor_key, product_key = identity_key
                        axes = _cna_axes(
                            item,
                            vendor_key=vendor_key,
                            product_key=product_key,
                        )
                        is_distribution = _is_distribution_product(
                            vendor_key, product_key
                        )
                        scope_id = store.scope_id(
                            product_id=product_id,
                            axes=axes,
                            configuration_id=None,
                            configuration_match_id=None,
                            cpe_role="DIRECT_UPSTREAM",
                            exclusive_scope=(
                                "distribution_only" if is_distribution else None
                            ),
                        )
                        effective_default = _status(item.default_status)
                        inferred_default = item.default_status is None
                        coverage = (
                            "complete"
                            if effective_default in {"affected", "unaffected"}
                            and item.default_status is not None
                            else "unknown"
                        )
                        coverage_basis = (
                            "defaultStatus_closure"
                            if coverage == "complete"
                            else "none"
                        )
                        claim_group = _cna_claim_group(
                            item,
                            vendor_key=vendor_key,
                            product_key=product_key,
                        )
                        if not item.versions and item.default_status is None:
                            store.add_source_claim(
                                snapshot_id=snapshot_id,
                                cve_id=cve_id,
                                product_id=product_id,
                                source_family="cna_structured",
                                source_identifier=item.source_identifier,
                                pointer=item.pointer,
                                raw_fragment_sha256=raw_fragment_hash(item.raw),
                                vendor=item.vendor,
                                product=item.product,
                                version=None,
                                status="unknown",
                                default_status=None,
                                version_kind="missing",
                                version_class="UNSPECIFIED",
                                cpe_criteria=None,
                                cpe_match_id=None,
                                vulnerable=True,
                                node_path=None,
                                start_including=None,
                                start_excluding=None,
                                end_including=None,
                                end_excluding=None,
                                admission_status="quarantined_malformed",
                            )
                            counters["source_claims"] += 1
                            store.add_issue(
                                code="quarantined_malformed",
                                stage="claim_admission",
                                severity="high",
                                cve_id=cve_id,
                                details={
                                    "pointer": item.pointer,
                                    "reason": "versions_and_defaultStatus_both_missing",
                                },
                            )
                        for version_index, raw_version in enumerate(item.versions):
                            raw_value = raw_version.get("version")
                            raw_status = raw_version.get("status")
                            if not isinstance(raw_value, str) or not isinstance(
                                raw_status, str
                            ):
                                store.add_issue(
                                    code="quarantined_malformed",
                                    stage="claim_admission",
                                    severity="high",
                                    cve_id=cve_id,
                                    details={
                                        "pointer": (
                                            f"{item.pointer}/versions/{version_index}"
                                        ),
                                        "reason": "version_and_status_required",
                                    },
                                )
                                continue
                            less_than = raw_version.get("lessThan")
                            less_equal = raw_version.get("lessThanOrEqual")
                            version_type = raw_version.get("versionType")
                            changes_value = raw_version.get("changes")
                            changes = (
                                [
                                    dict(value)
                                    for value in changes_value
                                    if isinstance(value, Mapping)
                                ]
                                if isinstance(changes_value, list)
                                else []
                            )
                            compiled = compile_cna(
                                version=raw_value,
                                status=_status(raw_status),
                                product_key=product_key,
                                less_than=(
                                    less_than
                                    if isinstance(less_than, str)
                                    else None
                                ),
                                less_than_or_equal=(
                                    less_equal
                                    if isinstance(less_equal, str)
                                    else None
                                ),
                                version_type=(
                                    version_type
                                    if isinstance(version_type, str)
                                    else None
                                ),
                                changes=changes,
                            )
                            compiled, anchored_count = _anchor_cna_zero_lower(
                                compiled,
                                raw_version=raw_value,
                                status=raw_status,
                                identity_key=identity_key,
                                nvd_ranges=nvd_direct_ranges,
                                parallel_zero_upper_count=len(
                                    cna_zero_lower_uppers.get(
                                        identity_key,
                                        (),
                                    )
                                ),
                            )
                            counters[
                                "cna_zero_lower_anchored_from_nvd"
                            ] += anchored_count
                            pointer = f"{item.pointer}/versions/{version_index}"
                            source_claim_id = store.add_source_claim(
                                snapshot_id=snapshot_id,
                                cve_id=cve_id,
                                product_id=product_id,
                                source_family="cna_structured",
                                source_identifier=item.source_identifier,
                                pointer=pointer,
                                raw_fragment_sha256=raw_fragment_hash(raw_version),
                                vendor=item.vendor,
                                product=item.product,
                                version=raw_value,
                                status=raw_status,
                                default_status=item.default_status,
                                version_kind=compiled.version_kind,
                                version_class=compiled.version_class,
                                cpe_criteria=None,
                                cpe_match_id=None,
                                vulnerable=True,
                                node_path=None,
                                start_including=None,
                                start_excluding=None,
                                end_including=None,
                                end_excluding=None,
                                admission_status=(
                                    "accepted_unparsed"
                                    if compiled.parse_status != "parsed"
                                    else "accepted_raw"
                                ),
                            )
                            counters["source_claims"] += 1
                            if compiled.parse_status != "parsed":
                                store.add_issue(
                                    code="F-VPARSE-01",
                                    stage="constraint_compile",
                                    severity="medium",
                                    cve_id=cve_id,
                                    source_claim_id=source_claim_id,
                                    details={
                                        "pointer": pointer,
                                        "error": compiled.parse_error,
                                        "raw_version": raw_value,
                                    },
                                )
                            for split in _split_expression(compiled):
                                info = _insert_assertion(
                                    store,
                                    cve_id=cve_id,
                                    product_id=product_id,
                                    scope_id=scope_id,
                                    source_claim_id=source_claim_id,
                                    source_family="cna_structured",
                                    claim_group=claim_group,
                                    compiled=split,
                                    entity_basis="authoritative_structured",
                                    default_inferred=inferred_default,
                                    default_effective=effective_default,
                                    is_default=False,
                                    branch_coverage=coverage,
                                    branch_basis=coverage_basis,
                                    role="DIRECT_UPSTREAM",
                                    role_basis="cna_structured_target",
                                    axes=axes,
                                )
                                assertions.append(info)
                                assertions_by_product[product_id].append(info)
                                counters["assertions"] += 1
                        if item.versions or item.default_status is not None:
                            default_compiled = _default_expression(
                                effective_default, inferred_default
                            )
                            # ``unknown`` describes the source's lack of a
                            # default verdict; it is not an applicability
                            # predicate.  Preserve it for provenance, but do
                            # not turn it into an unbounded UNSPECIFIED
                            # assertion that can override fully evaluated
                            # explicit ranges/exact versions at query time.
                            materialize_default = effective_default in {
                                "affected",
                                "unaffected",
                            }
                            default_pointer = f"{item.pointer}/defaultStatus"
                            default_fragment = {
                                "defaultStatus": item.default_status,
                                "versions_present": bool(item.versions),
                            }
                            source_claim_id = store.add_source_claim(
                                snapshot_id=snapshot_id,
                                cve_id=cve_id,
                                product_id=product_id,
                                source_family="cna_structured",
                                source_identifier=item.source_identifier,
                                pointer=default_pointer,
                                raw_fragment_sha256=raw_fragment_hash(default_fragment),
                                vendor=item.vendor,
                                product=item.product,
                                version=None,
                                status=effective_default,
                                default_status=item.default_status,
                                version_kind=default_compiled.version_kind,
                                version_class=default_compiled.version_class,
                                cpe_criteria=None,
                                cpe_match_id=None,
                                vulnerable=True,
                                node_path=None,
                                start_including=None,
                                start_excluding=None,
                                end_including=None,
                                end_excluding=None,
                                admission_status=(
                                    "accepted_raw"
                                    if materialize_default
                                    else "preserved_metadata_only"
                                ),
                            )
                            counters["source_claims"] += 1
                            if materialize_default:
                                info = _insert_assertion(
                                    store,
                                    cve_id=cve_id,
                                    product_id=product_id,
                                    scope_id=scope_id,
                                    source_claim_id=source_claim_id,
                                    source_family="cna_structured",
                                    claim_group=claim_group,
                                    compiled=default_compiled,
                                    entity_basis="authoritative_structured",
                                    default_inferred=inferred_default,
                                    default_effective=effective_default,
                                    is_default=True,
                                    branch_coverage=coverage,
                                    branch_basis=coverage_basis,
                                    role="DIRECT_UPSTREAM",
                                    role_basis="cna_structured_target",
                                    axes=axes,
                                )
                                assertions.append(info)
                                assertions_by_product[product_id].append(info)
                                counters["assertions"] += 1
                            else:
                                counters["default_metadata_only"] += 1

                    for llm_binding in grounded_llm_bindings:
                        if (
                            is_placeholder(llm_binding.vendor)
                            or is_placeholder(llm_binding.product)
                        ):
                            counters["llm_bindings_rejected_identity"] += 1
                            continue
                        product_key = normalize_key(llm_binding.product)
                        product_id = store.product_id(
                            llm_binding.vendor,
                            llm_binding.product,
                            part="unknown",
                            source_family="llm_description",
                            evidence_basis="description_span_grounded_preliminary",
                            label_priority=6,
                        )
                        store.add_product_alias(
                            product_id=product_id,
                            vendor=llm_binding.vendor,
                            product=llm_binding.product,
                            source_family="llm_description",
                            evidence_basis="description_span_grounded_preliminary",
                        )
                        current_basis = product_basis.get(product_id)
                        if current_basis is None or current_basis[1] > 6:
                            product_basis[product_id] = (
                                "llm_description_grounded_preliminary",
                                6,
                            )
                        if _has_structured_version_decision(
                            assertions_by_product.get(product_id, ())
                        ):
                            # The extraction was already admitted to llm_claim
                            # above.  Do not duplicate same-description evidence
                            # as an active applicability assertion.
                            counters[
                                "llm_bindings_suppressed_structured"
                            ] += 1
                            continue
                        axes = _llm_axes()
                        scope_id = store.scope_id(
                            product_id=product_id,
                            axes=axes,
                            configuration_id=None,
                            configuration_match_id=None,
                            cpe_role="DIRECT_UPSTREAM",
                            exclusive_scope=None,
                        )
                        admitted_ranges = 0
                        for llm_range in llm_binding.version_ranges:
                            legacy_rejection = _legacy_llm_range_rejection_reason(
                                llm_range
                            )
                            if legacy_rejection is not None:
                                counters[
                                    "llm_ranges_rejected_unsafe_legacy"
                                ] += 1
                                store.add_issue(
                                    code="F-LLM-RANGE-02",
                                    stage="llm_constraint_admission",
                                    severity="medium",
                                    cve_id=cve_id,
                                    llm_claim_id=llm_range.claim_id,
                                    details={
                                        "pointer": (
                                            f"/llm/bindings/"
                                            f"{llm_binding.binding_index}/"
                                            f"version_ranges/"
                                            f"{llm_range.range_index}"
                                        ),
                                        "reason": legacy_rejection,
                                    },
                                )
                                continue
                            compiled = _compile_llm_range(
                                llm_range,
                                product_key=product_key,
                            )
                            pointer = (
                                f"/llm/bindings/{llm_binding.binding_index}"
                                f"/version_ranges/{llm_range.range_index}"
                            )
                            if compiled is None:
                                counters["llm_ranges_rejected_ambiguous"] += 1
                                store.add_issue(
                                    code="F-LLM-RANGE-01",
                                    stage="llm_constraint_compile",
                                    severity="medium",
                                    cve_id=cve_id,
                                    llm_claim_id=llm_range.claim_id,
                                    details={
                                        "pointer": pointer,
                                        "reason": "missing_bound_inclusivity_or_unparsed",
                                    },
                                )
                                continue
                            fragment = {
                                "start": llm_range.start,
                                "start_inclusive": llm_range.start_inclusive,
                                "end": llm_range.end,
                                "end_inclusive": llm_range.end_inclusive,
                            }
                            source_claim_id = store.add_source_claim(
                                snapshot_id=snapshot_id,
                                cve_id=cve_id,
                                product_id=product_id,
                                source_family="llm_description",
                                source_identifier=f"llm-run:{llm_run_id}",
                                pointer=pointer,
                                raw_fragment_sha256=raw_fragment_hash(fragment),
                                vendor=llm_binding.vendor,
                                product=llm_binding.product,
                                version=compiled.raw_expression,
                                status="affected",
                                default_status=None,
                                version_kind=compiled.version_kind,
                                version_class=compiled.version_class,
                                cpe_criteria=None,
                                cpe_match_id=None,
                                vulnerable=True,
                                node_path=None,
                                start_including=(
                                    llm_range.start
                                    if llm_range.start_inclusive is True
                                    else None
                                ),
                                start_excluding=(
                                    llm_range.start
                                    if llm_range.start_inclusive is False
                                    else None
                                ),
                                end_including=(
                                    llm_range.end
                                    if llm_range.end_inclusive is True
                                    else None
                                ),
                                end_excluding=(
                                    llm_range.end
                                    if llm_range.end_inclusive is False
                                    else None
                                ),
                                admission_status="accepted_preliminary",
                            )
                            info = _insert_assertion(
                                store,
                                cve_id=cve_id,
                                product_id=product_id,
                                scope_id=scope_id,
                                source_claim_id=source_claim_id,
                                source_family="llm_description",
                                claim_group=(
                                    f"llm:{llm_run_id}:"
                                    f"{llm_binding.binding_index}"
                                ),
                                compiled=compiled,
                                entity_basis="llm_description_grounded_preliminary",
                                default_inferred=False,
                                default_effective="unknown",
                                is_default=False,
                                branch_coverage="unknown",
                                branch_basis="legacy_llm_binding",
                                role="DIRECT_UPSTREAM",
                                role_basis="description_binding_preliminary",
                                axes=axes,
                                llm_claim_id=llm_range.claim_id,
                                provisional=True,
                            )
                            assertions.append(info)
                            assertions_by_product[product_id].append(info)
                            counters["source_claims"] += 1
                            counters["assertions"] += 1
                            counters["llm_assertions_preliminary"] += 1
                            admitted_ranges += 1
                        if admitted_ranges:
                            counters["llm_bindings_materialized"] += 1

                    _reconcile(assertions)
                    _assertion_reconciliation_rows(store, assertions)
                    for product_id, product_assertions in assertions_by_product.items():
                        if not product_assertions:
                            continue
                        basis, _ = product_basis.get(
                            product_id, ("unresolved", 99)
                        )
                        active_members = [
                            (
                                item.assertion_id,
                                item.reconciliation
                                in {"active", "conflict_review"},
                            )
                            for item in product_assertions
                        ]
                        # This matches the final materialized binding rule:
                        # inactive/unparsed assertions are not active members.
                        # Alias-role promotion can therefore only clear this
                        # flag, never introduce a new review requirement.
                        manual_review = any(
                            item.reconciliation
                            in {"active", "conflict_review"}
                            and (
                                item.role == "UNRESOLVED"
                                or item.reconciliation == "conflict_review"
                            )
                            for item in product_assertions
                        )
                        has_llm_assertion = any(
                            item.source_family == "llm_description"
                            for item in product_assertions
                        )
                        llm_only_binding = has_llm_assertion and all(
                            item.source_family == "llm_description"
                            for item in product_assertions
                        )
                        store.add_binding(
                            revision_id=revision_id,
                            cve_id=cve_id,
                            product_id=product_id,
                            entity_basis=basis,
                            corroboration_independence="single_source",
                            enrichment_class=enrichment,
                            provisional=llm_only_binding,
                            manual_review=manual_review,
                            llm_run_id=(llm_run_id if has_llm_assertion else None),
                            assertion_ids=active_members,
                        )
                        counters["bindings"] += 1
                counters["records"] += 1
                source_index += 1
                if progress_every and counters["records"] % progress_every == 0:
                    print(
                        canonical_json(
                            {
                                "stage": "build",
                                "records": counters["records"],
                                "cve_id": cve_id,
                                "claims": counters["source_claims"],
                                "assertions": counters["assertions"],
                                "bindings": counters["bindings"],
                            }
                        ),
                        file=sys.stderr,
                        flush=True,
                    )

        final_stat = input_path.stat()
        if (
            final_stat.st_size != input_stat.st_size
            or final_stat.st_mtime_ns != input_stat.st_mtime_ns
        ):
            raise BuildError("NVD input changed while the database was being built")
        if limit is not None:
            # The digest explicitly identifies the consumed prefix.
            nvd_digest = f"prefix:{input_hasher.hexdigest()}"
            byte_size = consumed_bytes
        else:
            nvd_digest = input_hasher.hexdigest()
            byte_size = input_stat.st_size
        store.finalize_snapshot(
            snapshot_id=snapshot_id,
            payload_sha256=nvd_digest,
            byte_size=byte_size,
            record_count=input_row_count,
            coverage_start=first_cve,
            coverage_end=last_cve,
        )
        llm_hashes: dict[str, str] = {}
        if llm_stream is not None and llm_run_id is not None:
            combined_hash, llm_count, llm_hashes = llm_stream.finish()
            llm_join = llm_stream.join_summary()
            counters.update(
                {
                    f"llm_join_{key}": value
                    for key, value in llm_join.items()
                    if isinstance(value, int)
                }
            )
            store.finalize_llm_run(
                run_id=llm_run_id,
                source_sha256=combined_hash,
                record_count=llm_count,
                status="metadata_incomplete",
            )
            if llm_join["unmatched_count"] or llm_join["unkeyed_count"]:
                store.add_issue(
                    code="F-LLM-04",
                    stage="llm_join",
                    severity="medium",
                    cve_id=None,
                    details={
                        "reason": "llm_rows_not_joined_by_cve_id",
                        **llm_join,
                    },
                )
        stage_seconds["source_ingest"] = round(
            time.perf_counter() - build_started, 3
        )
        emit_stage(
            "source_ingest",
            "complete",
            started=build_started,
            records=counters["records"],
            claims=counters["source_claims"],
            assertions=counters["assertions"],
        )

        index_started = begin_stage("post_ingest_indexes")
        store.create_post_ingest_indexes()
        end_stage("post_ingest_indexes", index_started)

        identity_started = begin_stage("identity_materialization")

        def identity_progress(
            phase: str, details: Mapping[str, Any]
        ) -> None:
            emit_stage(
                "identity_materialization",
                "progress",
                started=identity_started,
                phase=phase,
                **dict(details),
            )

        progress_callback = identity_progress if progress_every else None
        identity_summary = dict(
            materialize_identity_resolution(
                store.connection,
                progress=progress_callback,
            )
        )
        end_stage(
            "identity_materialization",
            identity_started,
            evidence_observations=identity_summary.get(
                "cna_cpe_alias_candidates", 0
            ),
        )

        role_started = begin_stage("alias_role_reclassification")

        def role_progress(
            phase: str, details: Mapping[str, Any]
        ) -> None:
            emit_stage(
                "alias_role_reclassification",
                "progress",
                started=role_started,
                phase=phase,
                **dict(details),
            )

        role_reclassification = reclassify_alias_roles(
            store.connection,
            progress=role_progress if progress_every else None,
        )
        end_stage(
            "alias_role_reclassification",
            role_started,
            **role_reclassification,
        )
        identity_summary["role_reclassification"] = role_reclassification
        counters.update(
            {f"identity_{key}": value for key, value in identity_summary.items()
             if isinstance(value, int)}
        )
        counters.update(
            {f"identity_role_{key}": value
             for key, value in role_reclassification.items()}
        )
        store.set_identity_cluster_digest(
            revision_id=revision_id,
            cluster_digest=str(identity_summary["cluster_digest"]),
        )
        audit_started = begin_stage("publish_audit")

        def audit_progress(
            phase: str, details: Mapping[str, Any]
        ) -> None:
            emit_stage(
                "publish_audit",
                "progress",
                started=audit_started,
                phase=phase,
                **dict(details),
            )

        audit = _publish_audit(
            store.connection,
            progress=audit_progress if progress_every else None,
        )
        end_stage("publish_audit", audit_started)
        critical = {name: count for name, count in audit.items() if count}
        if critical:
            raise BuildError(f"publish audit failed: {critical}")
        health = (
            "degraded_llm_provisional"
            if llm_run_id is not None
            else "healthy"
        )
        summary = {
            **dict(counters),
            "audit": audit,
            "nvd_sha256": nvd_digest,
            "llm_sha256": llm_hashes,
            "publish_health": health,
            "identity": identity_summary,
            "stage_seconds": dict(stage_seconds),
            "framework_version": FRAMEWORK_VERSION,
            "rule_version": RULE_VERSION,
        }
        store.publish(
            pipeline_run_id=pipeline_run_id,
            revision_id=revision_id,
            record_count=counters["records"],
            summary=summary,
            health=health,
        )
        store.drop_post_ingest_indexes()
        store.commit_base()
        permanent_index_started = begin_stage("permanent_indexes")
        store.create_indexes()
        end_stage("permanent_indexes", permanent_index_started)
        integrity_started = begin_stage("integrity_check")
        store.verify_integrity()
        end_stage("integrity_check", integrity_started)
        store.close()
        if llm_stream is not None:
            llm_stream.close()
        os.replace(temporary, database_path)
        return {
            **summary,
            "database": str(database_path),
            "database_bytes": database_path.stat().st_size,
        }
    except BaseException:
        if llm_stream is not None:
            llm_stream.close()
        try:
            store.close()
        finally:
            if temporary.exists():
                temporary.unlink()
        raise
