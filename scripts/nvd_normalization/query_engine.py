"""Public offline query engine for materialized schema-v5 assertions."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, replace
import heapq
import itertools
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable, Mapping, Sequence
import unicodedata

from .identity import QueryIdentityResolver, IdentityResolution, resolve_query_products
from .history_policy import HistoryConflictPolicy, HistoryPolicyDecision, HistoryPolicyError
from .rules import AXES, CONTEXT_AXES, SCHEMA_VERSION, is_placeholder, normalize_key
from .versioning import (
    Segment,
    Tri,
    evaluate_segment,
    profile_for,
    tri_and,
    tri_or,
)


class QueryError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ApplicabilityQuery:
    vendor: str
    product: str
    version: str
    distribution: str | None = None
    edition: str | None = None
    component: str | None = None
    update: str | None = None
    language: str | None = None
    sw_edition: str | None = None
    target_sw: str | None = None
    target_hw: str | None = None
    other: str | None = None
    axis_policy: str = "operational_strict"


@dataclass(slots=True)
class _AssertionResult:
    assertion_id: int
    claim_group: str
    source_family: str
    polarity: str
    reconciliation: str
    is_default: bool
    predicate: Tri
    role: Tri
    scope: Tri
    configuration: Tri
    version: Tri
    version_reason: str
    branch_relation: str | None
    max_result_state: str | None
    source_claim_id: int
    product_id: int
    identity_provisional: bool
    trace: dict[str, Any] = field(default_factory=dict)


def _query_axis(value: str | None, *, axis: str, policy: str) -> tuple[str, str | None]:
    if value is not None:
        stripped = value.strip()
        if stripped == "*":
            return "ANY", None
        if stripped.casefold() == "unknown":
            return "UNKNOWN", None
        if stripped.casefold() in {"-", "n/a"}:
            return "NOT_APPLICABLE", None
        if stripped:
            return "EXACT", stripped
    if axis == "language":
        return "ANY", None
    if policy == "broad_discovery":
        return "ANY", None
    if policy == "platform_strict":
        if axis in {"distribution", "target_sw", "target_hw"}:
            return "UNKNOWN", None
        return "ANY", None
    return "UNKNOWN", None


def _normalized_joined_axis_text(value: str) -> str:
    """Normalize presentation differences without changing version tokens."""

    return " ".join(unicodedata.normalize("NFKC", value).split()).casefold()


def _scope_axis(
    query: tuple[str, str | None],
    assertion: tuple[str, str | None],
    *,
    broad: bool,
) -> Tri:
    query_state, query_value = query
    assertion_state, assertion_value = assertion
    if assertion_state == "UNKNOWN":
        return Tri.UNKNOWN
    if assertion_state == "ANY":
        return Tri.TRUE
    if assertion_state == "NOT_APPLICABLE":
        if query_state == "NOT_APPLICABLE":
            return Tri.TRUE
        if query_state in {"ANY", "UNKNOWN"}:
            return Tri.UNKNOWN
        return Tri.FALSE
    if assertion_state == "EXACT":
        if query_state == "EXACT":
            return (
                Tri.TRUE
                if normalize_key(query_value) == normalize_key(assertion_value)
                else Tri.FALSE
            )
        if query_state == "NOT_APPLICABLE":
            return Tri.FALSE
        if query_state == "ANY" and broad:
            return Tri.TRUE
        return Tri.UNKNOWN
    if assertion_state == "SET":
        try:
            values = json.loads(assertion_value or "[]")
        except json.JSONDecodeError:
            return Tri.UNKNOWN
        normalized = {normalize_key(item) for item in values if isinstance(item, str)}
        if query_state == "EXACT":
            return (
                Tri.TRUE if normalize_key(query_value) in normalized else Tri.FALSE
            )
        if query_state == "NOT_APPLICABLE":
            return Tri.FALSE
        if query_state == "ANY" and broad:
            return Tri.TRUE
        return Tri.UNKNOWN
    return Tri.UNKNOWN


def _role(role: str | None) -> Tri:
    if role in {
        None,
        "DIRECT_UPSTREAM",
        "DIRECT_ALTERNATIVE_PRODUCT",
        "DOWNSTREAM_DISTRIBUTION",
        "DOWNSTREAM_PACKAGE",
    }:
        return Tri.TRUE
    if role in {"UNRESOLVED", "BUNDLED_COMPONENT"}:
        return Tri.UNKNOWN
    return Tri.FALSE


def _closure_claim_group(row: Mapping[str, Any], product_id: int) -> str:
    """Return the effective default-closure group, including legacy DBs."""

    stored = str(row["claim_group"])
    if str(row["source_family"]) != "cna_structured":
        return stored
    source_identifier = row["claim_source_identifier"]
    return (
        "cna_source_product:"
        f"{product_id}:"
        f"{'' if source_identifier is None else str(source_identifier)}"
    )


def _tri_not(value: Tri) -> Tri:
    if value is Tri.TRUE:
        return Tri.FALSE
    if value is Tri.FALSE:
        return Tri.TRUE
    return Tri.UNKNOWN


def _condition_leaf(
    leaf: Mapping[str, Any],
    axes: Mapping[str, tuple[str, str | None]],
) -> Tri:
    part = leaf.get("part")
    vendor = str(leaf.get("vendor") or "")
    product = str(leaf.get("product") or "")
    identity_values = {
        normalize_key(product),
        normalize_key(f"{vendor}:{product}"),
        normalize_key(f"{vendor}_{product}"),
    }
    if part == "h":
        query_axis = axes["target_hw"]
    elif part == "o":
        # Distribution is the more specific operational representation; if
        # absent, target_sw can still satisfy the platform condition.
        candidates = (axes["distribution"], axes["target_sw"])
        results = []
        for query_axis in candidates:
            if query_axis[0] == "EXACT":
                results.append(
                    Tri.TRUE
                    if normalize_key(query_axis[1]) in identity_values
                    else Tri.FALSE
                )
            elif query_axis[0] in {"ANY", "UNKNOWN"}:
                results.append(Tri.UNKNOWN)
            else:
                results.append(Tri.FALSE)
        identity = tri_or(results)
        if identity is not Tri.TRUE:
            return identity
        # One matching operational platform axis is sufficient.  Re-checking
        # target_sw here would turn an exact distribution match into UNKNOWN
        # whenever target_sw was omitted.
        identity = Tri.TRUE
    else:
        query_axis = axes["component"]
    if part != "o":
        if query_axis[0] == "EXACT":
            identity = (
                Tri.TRUE
                if normalize_key(query_axis[1]) in identity_values
                else Tri.FALSE
            )
        elif query_axis[0] in {"ANY", "UNKNOWN"}:
            identity = Tri.UNKNOWN
        else:
            identity = Tri.FALSE
        if identity is not Tri.TRUE:
            return identity
    version = leaf.get("version")
    has_bounds = any(
        leaf.get(key)
        for key in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
    )
    if (isinstance(version, str) and version not in {"*", "-"}) or has_bounds:
        # Platform version is a distinct axis and is not present in the public
        # query contract; product version must never be substituted.
        return Tri.UNKNOWN
    return Tri.TRUE


def _evaluate_graph_all(
    graph: Mapping[str, Any],
    *,
    axes: Mapping[str, tuple[str, str | None]],
) -> Mapping[str, Tri]:
    """Evaluate every possible selected vulnerable leaf in one graph pass."""

    def combine(operator: str, counts: Mapping[Tri, int]) -> Tri:
        if operator == "AND":
            if counts[Tri.FALSE]:
                return Tri.FALSE
            if counts[Tri.UNKNOWN]:
                return Tri.UNKNOWN
            return Tri.TRUE
        if counts[Tri.TRUE]:
            return Tri.TRUE
        if counts[Tri.UNKNOWN]:
            return Tri.UNKNOWN
        return Tri.FALSE

    def node(value: Mapping[str, Any]) -> tuple[Tri, dict[str, Tri]]:
        operands: list[tuple[Tri, Mapping[str, Tri]]] = []
        matches = value.get("matches")
        if isinstance(matches, list):
            for leaf in matches:
                if not isinstance(leaf, Mapping):
                    operands.append((Tri.UNKNOWN, {}))
                elif leaf.get("vulnerable") is False:
                    operands.append((_condition_leaf(leaf, axes), {}))
                else:
                    match_id = leaf.get("id")
                    selections = (
                        {str(match_id): Tri.TRUE}
                        if isinstance(match_id, str)
                        else {}
                    )
                    operands.append((Tri.UNKNOWN, selections))
        children = value.get("children")
        if isinstance(children, list):
            operands.extend(
                node(child)
                if isinstance(child, Mapping)
                else (Tri.UNKNOWN, {})
                for child in children
            )
        if not operands:
            return Tri.UNKNOWN, {}
        operator = str(value.get("operator") or "OR").upper()
        operator = operator if operator in {"AND", "OR"} else "OR"
        counts = {
            state: sum(baseline is state for baseline, _ in operands)
            for state in Tri
        }
        baseline_result = combine(operator, counts)
        selected_results: dict[str, Tri] = {}
        for operand_baseline, selections in operands:
            for match_id, selected_value in selections.items():
                adjusted = dict(counts)
                adjusted[operand_baseline] -= 1
                adjusted[selected_value] += 1
                selected_results[match_id] = combine(operator, adjusted)
        if value.get("negate") is True:
            baseline_result = _tri_not(baseline_result)
            selected_results = {
                match_id: _tri_not(result)
                for match_id, result in selected_results.items()
            }
        return baseline_result, selected_results

    return node(graph)[1]


class QueryEngine:
    """Read-only applicability engine.

    The engine never imports the LLM extraction package; it only reads
    materialized claims for optional trace display.
    """

    def __init__(
        self,
        database: str | Path,
        *,
        history_conflict_policy: str | Path | None = None,
    ) -> None:
        self.path = Path(database)
        if not self.path.is_file():
            raise QueryError(f"database does not exist: {self.path}")
        self.connection = sqlite3.connect(
            self.path.resolve().as_uri() + "?mode=ro", uri=True
        )
        self.connection.row_factory = sqlite3.Row
        version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        if version != SCHEMA_VERSION:
            self.connection.close()
            raise QueryError(f"schema v{SCHEMA_VERSION} database required, found v{version}")
        health = self.connection.execute(
            "SELECT value FROM metadata WHERE key='publish_health'"
        ).fetchone()
        if health is None or str(health[0]).startswith("blocked_"):
            self.connection.close()
            raise QueryError(
                "database has no published healthy/degraded binding revision"
            )
        self._graph_cache: dict[int, Mapping[str, Any]] = {}
        self._configuration_result_cache: dict[int, Mapping[str, Tri]] = {}
        self._identity_resolver = QueryIdentityResolver(self.connection)
        self._identity_resolution_cache: dict[
            tuple[str, str, str], IdentityResolution
        ] = {}
        try:
            self.history_conflict_policy = (
                None
                if history_conflict_policy is None
                else HistoryConflictPolicy(history_conflict_policy)
            )
        except HistoryPolicyError as error:
            self.connection.close()
            raise QueryError(str(error)) from error

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "QueryEngine":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _products(
        self, vendor: str, product: str, *, axis_policy: str
    ) -> IdentityResolution:
        cache_key = (normalize_key(vendor), normalize_key(product), axis_policy)
        cached = self._identity_resolution_cache.get(cache_key)
        if cached is not None:
            return cached
        resolution = resolve_query_products(
            self.connection,
            vendor=vendor,
            product=product,
            axis_policy=axis_policy,
            query_resolver=self._identity_resolver,
        )
        if len(self._identity_resolution_cache) >= 16_384:
            self._identity_resolution_cache.clear()
        self._identity_resolution_cache[cache_key] = resolution
        return resolution

    def _recover_cpe_update_query(
        self,
        query: ApplicabilityQuery,
        product_ids: Sequence[int],
    ) -> tuple[ApplicabilityQuery, Mapping[str, str] | None]:
        """Recover a flattened CPE update only when the DB proves the tuple."""

        if query.update is not None or not product_ids:
            return query, None
        normalized_input = _normalized_joined_axis_text(query.version)
        if " " not in normalized_input:
            return query, None

        marks = ",".join("?" for _ in product_ids)
        rows = self.connection.execute(
            f"""SELECT DISTINCT a.source_family,v.exact_value,
                                s.update_state,s.update_value
                FROM current_binding b
                JOIN binding_assertion_member m USING(binding_id)
                JOIN applicability_assertion a USING(assertion_id)
                JOIN applicability_scope s USING(scope_id)
                JOIN version_segment v USING(expression_id)
                WHERE b.product_id IN ({marks})
                  AND m.is_active=1
                  AND v.exact_value IS NOT NULL""",
            tuple(product_ids),
        )
        matches: set[tuple[str, str]] = set()
        literal_exact_supported = False
        for row in rows:
            exact_value = str(row["exact_value"])
            if _normalized_joined_axis_text(exact_value) == normalized_input:
                literal_exact_supported = True
            if str(row["source_family"]) != "nvd_cpe":
                continue
            if str(row["update_state"]) != "EXACT":
                continue
            update_value = row["update_value"]
            if update_value is None:
                continue
            update_text = str(update_value)
            if (
                _normalized_joined_axis_text(
                    f"{exact_value} {update_text}"
                )
                == normalized_input
            ):
                matches.add((exact_value, update_text))

        if literal_exact_supported or len(matches) != 1:
            return query, None
        effective_version, effective_update = next(iter(matches))
        return (
            replace(
                query,
                version=effective_version,
                update=effective_update,
            ),
            {
                "status": "cpe_update_recovered",
                "input_version": query.version,
                "effective_version": effective_version,
                "effective_update": effective_update,
                "basis": "unique_active_nvd_cpe_exact_tuple",
            },
        )

    def _query_axes(
        self,
        query: ApplicabilityQuery,
        products: Sequence[sqlite3.Row],
    ) -> dict[str, tuple[str, str | None]]:
        if query.axis_policy not in {
            "operational_strict",
            "broad_discovery",
            "platform_strict",
        }:
            raise QueryError(f"unsupported axis_policy: {query.axis_policy}")
        exact_anchors = [
            row for row in products
            if row.get("identity", {}).get("tier") == "T0_EXACT"
            or (row.get("identity", {}).get("query_match") or {}).get("kind")
            == "query_fuzzy"
        ]
        strict_sources = [
            row for row in products
            if row.get("identity", {}).get("strict_eligible", True)
        ]
        exact_parts = {
            str(row["part"])
            for row in exact_anchors
            if row["part"] in {"a", "o", "h"}
        }
        # A CNA entity commonly has part=unknown while its strict alias-equivalent
        # CPE entity supplies the concrete part.  An exact anchor with no usable
        # value must not prevent the accepted cluster consensus fallback.
        consensus_parts = {
            str(row["part"])
            for row in strict_sources
            if row["part"] in {"a", "o", "h"}
        }
        concrete_parts = exact_parts or consensus_parts
        axis_sources = exact_anchors if exact_parts else strict_sources
        if not axis_sources:
            axis_sources = exact_anchors
        axes = {
            name: _query_axis(
                getattr(query, name, None),
                axis=name,
                policy=query.axis_policy,
            )
            for name in AXES
            if name != "part"
        }
        axes["part"] = (
            ("EXACT", next(iter(concrete_parts)))
            if len(concrete_parts) == 1
            else ("UNKNOWN", None)
        )
        # A downstream product query names its distribution by construction.
        if axes["distribution"][0] == "UNKNOWN":
            distribution_keys = {
                f"{row['vendor_key']}:{row['product_key']}"
                for row in axis_sources
                if row["part"] == "o"
            }
            if len(distribution_keys) == 1:
                axes["distribution"] = (
                    "EXACT",
                    next(iter(distribution_keys)),
                )
        return axes

    def _graph(self, configuration_id: int) -> Mapping[str, Any]:
        cached = self._graph_cache.get(configuration_id)
        if cached is not None:
            return cached
        row = self.connection.execute(
            "SELECT graph_json FROM configuration WHERE configuration_id=?",
            (configuration_id,),
        ).fetchone()
        if row is None:
            return {}
        parsed = json.loads(str(row[0]))
        if not isinstance(parsed, Mapping):
            parsed = {}
        self._graph_cache[configuration_id] = parsed
        return parsed

    def _load_rows(self, product_ids: Sequence[int]) -> Iterable[sqlite3.Row]:
        sql = """SELECT b.product_id,b.cve_id,b.enrichment_class,
                           b.provisional_llm_identity,b.manual_review_required,
                           a.assertion_id,a.claim_group,a.assertion_polarity,
                           a.source_family,a.reconciliation_status,
                           a.is_default_closure,
                           a.branch_coverage_completeness,
                           a.version_resolution_class,a.max_result_state,
                           a.cpe_match_role,a.scope_resolution_status,
                           a.version_resolution_status,a.source_claim_id,
                           sc.source_identifier AS claim_source_identifier,
                           s.scope_id,s.part_state,s.part_value,
                           s.distribution_state,s.distribution_value,
                           s.edition_state,s.edition_value,
                           s.component_state,s.component_value,
                           s.update_state,s.update_value,
                           s.language_state,s.language_value,
                           s.sw_edition_state,s.sw_edition_value,
                           s.target_sw_state,s.target_sw_value,
                           s.target_hw_state,s.target_hw_value,
                           s.other_state,s.other_value,
                           s.configuration_id,s.configuration_match_id,
                           e.profile_name,
                           v.status AS segment_status,v.branch_key,
                           v.lower_bound,v.lower_inclusive,
                           v.lower_arity_semantics,
                           v.upper_bound,v.upper_inclusive,
                           v.upper_arity_semantics,v.exact_value,
                           c.last_modified,c.primary_description
                    FROM current_binding b
                    JOIN raw_cve c USING(cve_id)
                    JOIN binding_assertion_member m USING(binding_id)
                    JOIN applicability_assertion a USING(assertion_id)
                    JOIN source_claim sc
                      ON sc.source_claim_id=a.source_claim_id
                    JOIN applicability_scope s USING(scope_id)
                    LEFT JOIN version_expression e USING(expression_id)
                    LEFT JOIN version_segment v USING(expression_id)
                    WHERE b.product_id=? AND m.is_active=1
                    ORDER BY b.cve_id"""
        cursors = [
            self.connection.execute(sql, (product_id,))
            for product_id in product_ids
        ]
        return heapq.merge(
            *cursors,
            key=lambda row: str(row["cve_id"]),
        )

    def _configuration_results(
        self,
        configuration_id: int,
        axes: Mapping[str, tuple[str, str | None]],
    ) -> Mapping[str, Tri]:
        cached = self._configuration_result_cache.get(configuration_id)
        if cached is not None:
            return cached
        results = _evaluate_graph_all(
            self._graph(configuration_id),
            axes=axes,
        )
        self._configuration_result_cache[configuration_id] = results
        return results

    def _load_product_observations(
        self, product_ids: Sequence[int]
    ) -> dict[str, sqlite3.Row]:
        marks = ",".join("?" for _ in product_ids)
        rows = self.connection.execute(
            f"""SELECT c.cve_id,c.enrichment_class,c.vuln_status,
                       c.last_modified,c.primary_description
                FROM source_claim s
                JOIN raw_cve c USING(cve_id)
                WHERE s.product_id IN ({marks})
                  AND COALESCE(s.vulnerable_flag,1)=1
                GROUP BY c.cve_id
                ORDER BY c.cve_id""",
            tuple(product_ids),
        )
        return {str(row["cve_id"]): row for row in rows}

    def _scope(
        self,
        row: sqlite3.Row,
        axes: Mapping[str, tuple[str, str | None]],
        *,
        broad: bool,
    ) -> tuple[Tri, list[str]]:
        unknown_axes: list[str] = []
        for axis in AXES:
            state = str(row[f"{axis}_state"])
            if state == "ANY":
                continue
            value = row[f"{axis}_value"]
            result = _scope_axis(
                axes[axis],
                (state, None if value is None else str(value)),
                broad=broad,
            )
            if result is Tri.FALSE:
                return Tri.FALSE, unknown_axes
            if result is Tri.UNKNOWN:
                unknown_axes.append(axis)
        return (
            Tri.UNKNOWN if unknown_axes else Tri.TRUE,
            unknown_axes,
        )

    def _assertion_results(
        self,
        rows: Sequence[sqlite3.Row],
        query: ApplicabilityQuery,
        axes: Mapping[str, tuple[str, str | None]],
        identity_meta: Mapping[int, Mapping[str, Any]],
        *,
        include_trace: bool,
    ) -> list[_AssertionResult]:
        branch_keys_by_group: dict[str, list[str]] = defaultdict(list)
        for row in rows:
            if row["branch_key"]:
                product_id = int(row["product_id"])
                branch_keys_by_group[
                    _closure_claim_group(row, product_id)
                ].append(
                    str(row["branch_key"])
                )
        output: list[_AssertionResult] = []
        for row in rows:
            product_id = int(row["product_id"])
            stored_claim_group = str(row["claim_group"])
            claim_group = _closure_claim_group(row, product_id)
            source_family = str(row["source_family"])
            identity = identity_meta.get(product_id, {})
            identity_provisional = not bool(identity.get("strict_eligible", True))
            role_result = _role(
                None if row["cpe_match_role"] is None else str(row["cpe_match_role"])
            )
            scope_result, unknown_axes = self._scope(
                row, axes, broad=query.axis_policy == "broad_discovery"
            )
            configuration_id = row["configuration_id"]
            if configuration_id is None:
                configuration_result = Tri.TRUE
            else:
                configuration_result = self._configuration_results(
                    int(configuration_id),
                    axes,
                ).get(
                    str(row["configuration_match_id"]),
                    Tri.UNKNOWN,
                )
            segment = Segment(
                status=str(row["segment_status"] or row["assertion_polarity"]),
                lower=(
                    None
                    if row["lower_bound"] is None
                    or is_placeholder(str(row["lower_bound"]))
                    else str(row["lower_bound"])
                ),
                lower_inclusive=(
                    None
                    if row["lower_inclusive"] is None
                    else bool(row["lower_inclusive"])
                ),
                lower_arity=str(
                    row["lower_arity_semantics"] or "not_applicable"
                ),
                upper=(
                    None
                    if row["upper_bound"] is None
                    or is_placeholder(str(row["upper_bound"]))
                    else str(row["upper_bound"])
                ),
                upper_inclusive=(
                    None
                    if row["upper_inclusive"] is None
                    else bool(row["upper_inclusive"])
                ),
                upper_arity=str(
                    row["upper_arity_semantics"] or "not_applicable"
                ),
                exact=(
                    None if row["exact_value"] is None else str(row["exact_value"])
                ),
                branch_key=(
                    None if row["branch_key"] is None else str(row["branch_key"])
                ),
            )
            stored_profile = str(row["profile_name"] or "opaque")
            effective_profile = stored_profile
            if stored_profile == "opaque" and any(
                (segment.lower, segment.upper, segment.exact)
            ):
                inferred_profile = profile_for(
                    (
                        query.version,
                        segment.lower,
                        segment.upper,
                        segment.exact,
                    ),
                    version_type=None,
                    product_key="",
                )
                if inferred_profile != "opaque":
                    effective_profile = inferred_profile
            version_result = evaluate_segment(
                candidate=query.version,
                version_class=str(row["version_resolution_class"]),
                profile=effective_profile,
                segment=segment,
                branch_coverage=str(row["branch_coverage_completeness"]),
                all_branch_keys=branch_keys_by_group[claim_group],
            )
            predicate = tri_and(
                (role_result, scope_result, configuration_result, version_result.state)
            )
            output.append(
                _AssertionResult(
                    assertion_id=int(row["assertion_id"]),
                    claim_group=claim_group,
                    source_family=source_family,
                    polarity=str(row["assertion_polarity"]),
                    reconciliation=str(row["reconciliation_status"]),
                    is_default=bool(row["is_default_closure"]),
                    predicate=predicate,
                    role=role_result,
                    scope=scope_result,
                    configuration=configuration_result,
                    version=version_result.state,
                    version_reason=version_result.reason,
                    branch_relation=version_result.branch_relation,
                    max_result_state=(
                        None
                        if row["max_result_state"] is None
                        else str(row["max_result_state"])
                    ),
                    source_claim_id=int(row["source_claim_id"]),
                    product_id=product_id,
                    identity_provisional=identity_provisional,
                    trace=(
                        {
                            "assertion_id": int(row["assertion_id"]),
                            "source_family": source_family,
                            "claim_group": claim_group,
                            "stored_claim_group": stored_claim_group,
                            "source_identifier": (
                                None
                                if row["claim_source_identifier"] is None
                                else str(row["claim_source_identifier"])
                            ),
                            "polarity": str(row["assertion_polarity"]),
                            "scope_result": scope_result.value,
                            "unknown_scope_axes": unknown_axes,
                            "configuration_result": configuration_result.value,
                            "role_result": role_result.value,
                            "version_result": version_result.state.value,
                            "version_reason": version_result.reason,
                            "version_class": str(
                                row["version_resolution_class"]
                            ),
                            "version_profile": str(
                                effective_profile
                            ),
                            "stored_version_profile": stored_profile,
                            "branch_relation": version_result.branch_relation,
                            "branch_coverage": str(
                                row["branch_coverage_completeness"]
                            ),
                            "reconciliation": str(
                                row["reconciliation_status"]
                            ),
                            "source_claim_id": int(row["source_claim_id"]),
                            "product_id": product_id,
                            "identity": dict(identity),
                        }
                        if include_trace
                        else {}
                    ),
                )
            )
        return output

    @staticmethod
    def _apply_default_closure(
        assertions: Sequence[_AssertionResult],
    ) -> list[_AssertionResult]:
        groups: dict[str, list[_AssertionResult]] = defaultdict(list)
        for assertion in assertions:
            groups[assertion.claim_group].append(assertion)
        selected: list[_AssertionResult] = []
        for values in groups.values():
            defaults = [item for item in values if item.is_default]
            explicit = [item for item in values if not item.is_default]
            if not defaults:
                selected.extend(explicit)
                continue
            coverage = [item.predicate for item in explicit]
            if Tri.TRUE in coverage:
                selected.extend(explicit)
                continue
            selected.extend(explicit)
            for default in defaults:
                if Tri.UNKNOWN in coverage and default.predicate is Tri.TRUE:
                    default.predicate = Tri.UNKNOWN
                    default.version_reason = "explicit_coverage_unknown"
                    if default.trace:
                        default.trace["version_result"] = Tri.UNKNOWN.value
                        default.trace["version_reason"] = (
                            "explicit_coverage_unknown"
                        )
                selected.append(default)
        return selected

    @staticmethod
    def _source_result(
        assertions: Sequence[_AssertionResult],
    ) -> str | None:
        """OR version assertions within one source family before reconciliation."""

        relevant = [
            item
            for item in assertions
            if item.role is not Tri.FALSE
            and item.scope is not Tri.FALSE
            and item.configuration is not Tri.FALSE
        ]
        if not relevant:
            return None
        affected = any(
            item.polarity == "affected" and item.predicate is Tri.TRUE
            for item in relevant
        )
        unaffected = any(
            item.polarity == "unaffected" and item.predicate is Tri.TRUE
            for item in relevant
        )
        if affected and unaffected:
            return "conflict"
        if affected:
            return "affected"
        if unaffected:
            return "unaffected"
        if any(
            item.predicate is Tri.UNKNOWN
            and item.polarity in {"affected", "unknown"}
            for item in relevant
        ):
            return "unknown"
        if all(item.version is Tri.FALSE for item in relevant):
            return "out_of_range"
        return None

    @staticmethod
    def _finalize(
        assertions: Sequence[_AssertionResult],
        *,
        enrichment: str,
        provisional: bool,
        history_decision: HistoryPolicyDecision | None = None,
    ) -> tuple[str, list[str]]:
        reasons: set[str] = set()
        relevant = list(assertions)
        if enrichment == "rejected":
            return "insufficient_data", ["rejected_upstream"]
        if not relevant:
            return "product_only_observation", ["no_active_assertion"]
        conflicts = [
            item
            for item in relevant
            if item.reconciliation == "conflict_review"
            and item.predicate is not Tri.FALSE
        ]
        if conflicts:
            return "conflict_review", ["authoritative_source_conflict"]
        by_source: dict[str, list[_AssertionResult]] = defaultdict(list)
        for item in relevant:
            by_source[item.source_family].append(item)
        source_results = {
            source_family: QueryEngine._source_result(values)
            for source_family, values in by_source.items()
        }
        nvd_result = source_results.get("nvd_cpe")
        cna_result = source_results.get("cna_structured")
        if "conflict" in {nvd_result, cna_result}:
            return "conflict_review", ["source_family_internal_conflict"]
        source_truth = {
            "affected": True,
            "unaffected": False,
            "out_of_range": False,
        }
        if nvd_result in source_truth and cna_result in source_truth:
            if source_truth[nvd_result] != source_truth[cna_result]:
                if history_decision is not None:
                    if history_decision.action == "prefer_latest_cpe":
                        if nvd_result == "affected":
                            return "affected", [
                                "history_latest_cpe_affected",
                                history_decision.basis,
                            ]
                        if nvd_result == "unaffected":
                            return "not_affected_asserted", [
                                "history_latest_cpe_unaffected",
                                history_decision.basis,
                            ]
                        if nvd_result == "out_of_range":
                            return "not_affected_out_of_range", [
                                "history_latest_cpe_out_of_range",
                                history_decision.basis,
                            ]
                    elif history_decision.action == "accept_added_range":
                        if "affected" in {nvd_result, cna_result}:
                            return "affected", [
                                "history_added_range_accepted",
                                history_decision.basis,
                            ]
                return "conflict_review", ["nvd_cna_result_conflict"]

        # A legacy description extraction is supporting evidence, not an
        # independent authority.  Once CNA/NVD structured evidence can answer
        # this concrete query, exclude LLM assertions from final-state
        # aggregation.  Otherwise an overlapping preliminary LLM range can
        # incorrectly cap an authoritative ``affected`` result at
        # ``potentially_affected`` or turn an authoritative out-of-range result
        # into a positive.  LLM-only bindings remain available for gaps where
        # neither structured source can decide.
        structured_decisions = {"affected", "unaffected", "out_of_range"}
        if nvd_result in structured_decisions or cna_result in structured_decisions:
            relevant = [
                item
                for item in relevant
                if item.source_family != "llm_description"
            ]
        matched_affected = [
            item
            for item in relevant
            if item.polarity == "affected" and item.predicate is Tri.TRUE
        ]
        matched_unaffected = [
            item
            for item in relevant
            if item.polarity == "unaffected" and item.predicate is Tri.TRUE
        ]
        if matched_affected and matched_unaffected:
            return "conflict_review", ["active_polarity_conflict"]
        if matched_unaffected:
            reasons.update(item.version_reason for item in matched_unaffected)
            return "not_affected_asserted", sorted(reasons)
        if matched_affected:
            reasons.update(item.version_reason for item in matched_affected)
            if provisional or any(
                item.max_result_state == "potentially_affected"
                or item.identity_provisional
                for item in matched_affected
            ):
                if any(item.identity_provisional for item in matched_affected):
                    reasons.add("identity_alias_provisional")
                return "potentially_affected", sorted(reasons)
            return "affected", sorted(reasons)
        uncertain = [
            item
            for item in relevant
            if item.predicate is Tri.UNKNOWN
            and item.polarity in {"affected", "unknown"}
        ]
        if uncertain:
            reasons.update(item.version_reason for item in uncertain)
            return "potentially_affected", sorted(reasons)
        scope_false = [
            item
            for item in relevant
            if item.scope is Tri.FALSE or item.configuration is Tri.FALSE
        ]
        version_false = [
            item
            for item in relevant
            if item.version is Tri.FALSE
            and item.scope is not Tri.FALSE
            and item.configuration is not Tri.FALSE
        ]
        if version_false and len(version_false) + len(scope_false) == len(relevant):
            reasons.update(item.version_reason for item in version_false)
            if all(item.version_reason == "version_not_applicable" for item in version_false):
                return "not_applicable", sorted(reasons)
            return "not_affected_out_of_range", sorted(reasons)
        if scope_false:
            return "not_applicable", ["scope_or_configuration_false"]
        if enrichment == "unenriched":
            return "insufficient_data", ["nvd_unenriched"]
        return "product_only_observation", ["no_positive_assertion"]

    def query(
        self,
        query: ApplicabilityQuery,
        *,
        prediction_policy: str = "strict",
        include_trace: bool = True,
    ) -> Mapping[str, Any]:
        if not query.vendor.strip() or not query.product.strip():
            raise QueryError("vendor and product are required")
        if not query.version.strip() or query.version.strip() in {"*", "-", "n/a"}:
            raise QueryError("version must be a concrete value")
        if prediction_policy not in {"strict", "inclusive", "review-aware"}:
            raise QueryError(f"unsupported prediction policy: {prediction_policy}")
        resolution = self._products(
            query.vendor, query.product, axis_policy=query.axis_policy
        )
        if resolution.state != "resolved":
            products = ()
            axes = self._query_axes(query, products)
            snapshot = self.connection.execute(
                """SELECT payload_sha256,upstream_last_modified,downloaded_at,
                          record_count,coverage_start,coverage_end,is_complete
                   FROM source_snapshot_manifest
                   ORDER BY snapshot_id DESC LIMIT 1"""
            ).fetchone()
            health = self.connection.execute(
                "SELECT value FROM metadata WHERE key='publish_health'"
            ).fetchone()
            return {
                "query": {
                    "vendor": query.vendor,
                    "product": query.product,
                    "version": query.version,
                    "axis_policy": query.axis_policy,
                    "prediction_policy": prediction_policy,
                    "axes": {
                        key: {"state": value[0], "value": value[1]}
                        for key, value in axes.items()
                    },
                },
                "resolved_products": [],
                "resolution": {
                    "state": "insufficient_data",
                    "reason": resolution.reason,
                    "detail": resolution.reason,
                    "ambiguous_clusters": list(resolution.ambiguous_clusters),
                    "suggestions": list(resolution.suggestions),
                },
                "snapshot": dict(snapshot) if snapshot is not None else None,
                "publish_health": str(health[0]) if health else "unknown",
                "candidate_count": 0,
                "positive_count": 0,
                "state_counts": {"insufficient_data": 1},
                "results": [],
            }
        products = resolution.products
        product_ids = tuple(int(row.product_id) for row in products)
        product_rows = tuple(
            {
                "product_id": row.product_id,
                "vendor_key": row.vendor_key,
                "product_key": row.product_key,
                "part": row.part,
                "canonical_vendor": row.canonical_vendor,
                "canonical_product": row.canonical_product,
                "identity": dict(row.identity),
            }
            for row in products
        )
        identity_meta = {row.product_id: row.identity for row in products}
        policy_identities = tuple(
            (str(row["vendor_key"]), str(row["product_key"]))
            for row in product_rows
        )
        effective_query, version_interpretation = (
            self._recover_cpe_update_query(query, product_ids)
        )
        axes = self._query_axes(effective_query, product_rows)
        observations = self._load_product_observations(product_ids)
        results: list[dict[str, Any]] = []
        state_counts: dict[str, int] = defaultdict(int)
        evaluated_cves: set[str] = set()
        rows = self._load_rows(product_ids)
        for cve_id, grouped_rows in itertools.groupby(
            rows,
            key=lambda row: str(row["cve_id"]),
        ):
            cve_rows = list(grouped_rows)
            evaluated_cves.add(cve_id)
            evaluated = self._assertion_results(
                cve_rows,
                effective_query,
                axes,
                identity_meta,
                include_trace=include_trace,
            )
            selected = self._apply_default_closure(evaluated)
            history_decision = (
                None
                if self.history_conflict_policy is None
                else self.history_conflict_policy.resolve(
                    cve_id,
                    policy_identities,
                )
            )
            state, reasons = self._finalize(
                selected,
                enrichment=str(cve_rows[0]["enrichment_class"]),
                provisional=bool(cve_rows[0]["provisional_llm_identity"]),
                history_decision=history_decision,
            )
            state_counts[state] += 1
            positive = (
                state == "affected"
                if prediction_policy in {"strict", "review-aware"}
                else state
                in {
                    "affected",
                    "potentially_affected",
                    "conflict_review",
                }
            )
            result: dict[str, Any] = {
                "cve_id": cve_id,
                "state": state,
                "positive": positive,
                "reason_codes": reasons,
                "enrichment_class": str(cve_rows[0]["enrichment_class"]),
                "manual_review_required": bool(
                    cve_rows[0]["manual_review_required"]
                ),
                "last_modified": cve_rows[0]["last_modified"],
                "description": cve_rows[0]["primary_description"],
            }
            if history_decision is not None:
                result["history_conflict_decision"] = {
                    "action": history_decision.action,
                    "relation": history_decision.relation,
                    "basis": history_decision.basis,
                }
            if include_trace:
                result["assertions"] = [item.trace for item in selected]
            results.append(result)
            # Configuration IDs are CVE-local, so retaining their parsed graphs
            # after this group only increases peak memory.
            self._graph_cache.clear()
            self._configuration_result_cache.clear()
        for cve_id in sorted(set(observations).difference(evaluated_cves)):
            observation = observations[cve_id]
            enrichment = str(observation["enrichment_class"])
            if enrichment == "rejected":
                state = "insufficient_data"
                reasons = ["rejected_upstream"]
            else:
                state = "product_only_observation"
                reasons = ["raw_product_observation_without_active_assertion"]
            state_counts[state] += 1
            result = {
                "cve_id": cve_id,
                "state": state,
                "positive": False,
                "reason_codes": reasons,
                "enrichment_class": enrichment,
                "manual_review_required": True,
                "last_modified": observation["last_modified"],
                "description": observation["primary_description"],
            }
            if include_trace:
                result["assertions"] = []
            results.append(result)
        results.sort(key=lambda item: item["cve_id"])
        snapshot = self.connection.execute(
            """SELECT payload_sha256,upstream_last_modified,downloaded_at,
                      record_count,coverage_start,coverage_end,is_complete
               FROM source_snapshot_manifest
               ORDER BY snapshot_id DESC LIMIT 1"""
        ).fetchone()
        health = self.connection.execute(
            "SELECT value FROM metadata WHERE key='publish_health'"
        ).fetchone()
        query_payload: dict[str, Any] = {
            "vendor": query.vendor,
            "product": query.product,
            "version": query.version,
            "axis_policy": query.axis_policy,
            "prediction_policy": prediction_policy,
            "axes": {
                key: {"state": value[0], "value": value[1]}
                for key, value in axes.items()
            },
        }
        if version_interpretation is not None:
            query_payload["version_interpretation"] = version_interpretation
        return {
            "query": query_payload,
            "resolution": {
                "state": resolution.state,
                "reason": resolution.reason,
                "ambiguous_clusters": list(resolution.ambiguous_clusters),
            },
            "resolved_products": [
                {
                    "product_id": row.product_id,
                    "vendor": row.canonical_vendor,
                    "product": row.canonical_product,
                    "part": row.part,
                    "identity": dict(row.identity),
                }
                for row in products
            ],
            "snapshot": dict(snapshot) if snapshot is not None else None,
            "publish_health": str(health[0]) if health else "unknown",
            "candidate_count": len(results),
            "positive_count": sum(bool(item["positive"]) for item in results),
            "state_counts": dict(sorted(state_counts.items())),
            "results": results,
        }

    def resolve_identity(
        self, vendor: str, product: str, *, axis_policy: str = "operational_strict"
    ) -> Mapping[str, Any]:
        resolution = self._products(vendor, product, axis_policy=axis_policy)
        return {
            "state": resolution.state,
            "reason": resolution.reason,
            "ambiguous_clusters": list(resolution.ambiguous_clusters),
            "suggestions": list(resolution.suggestions),
            "resolved_products": [
                {
                    "product_id": row.product_id,
                    "vendor": row.canonical_vendor,
                    "product": row.canonical_product,
                    "part": row.part,
                    "identity": dict(row.identity),
                }
                for row in resolution.products
            ],
        }

    def search_products(self, text: str, *, limit: int = 50) -> list[dict[str, Any]]:
        key = normalize_key(text)
        rows = self.connection.execute(
            """SELECT p.product_id,p.canonical_vendor,p.canonical_product,p.part,
                      c.cluster_id,c.max_tier AS identity_tier,
                      c.review_state AS identity_review_state,
                      COUNT(DISTINCT b.cve_id) AS cve_count
               FROM product_entity p
               LEFT JOIN current_binding b USING(product_id)
               LEFT JOIN identity_cluster_member m USING(product_id)
               LEFT JOIN identity_cluster c USING(cluster_id)
               WHERE p.vendor_key LIKE ? OR p.product_key LIKE ?
               GROUP BY p.product_id
               ORDER BY cve_count DESC,p.vendor_key,p.product_key
               LIMIT ?""",
            (f"%{key}%", f"%{key}%", limit),
        )
        return [dict(row) for row in rows]
