#!/usr/bin/env python3
"""Query version applicability from a Clovery-enhanced repo_cve.sqlite.

The repository mapping DB is a flattened repository/product/version projection,
not the complete schema-v5 applicability graph.  This command deliberately uses
``repo_cve_version_effective`` so accepted Clovery ranges override NVD ranges,
and reports uncertainty instead of turning missing projection data into a false
negative.

Inclusive mode is the default: ``affected``, ``potentially_affected`` and
``conflict_review`` are positive findings.  Use ``--policy strict`` when only a
definite ``affected`` result should be positive.

Examples::

    python scripts/query_repo_cve.py HDFGroup@hdf5 --version 1.8.10
    python scripts/query_repo_cve.py HDFGroup@hdf5 --version 1.14.6 --all-states
    python scripts/query_repo_cve.py wolfSSL@wolfssl --version 5.7.0 \
        --format json
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Iterable, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from nvd_normalization.rules import normalize_key  # noqa: E402
from nvd_normalization.versioning import compare_versions, profile_for  # noqa: E402


DEFAULT_DB = REPO_ROOT / "workspace" / "repo_cve.sqlite"
POSITIVE_STATES = {
    "inclusive": {"affected", "potentially_affected", "conflict_review"},
    "strict": {"affected"},
}


class QueryError(RuntimeError):
    """Raised when the mapping DB or query is not usable."""


def table_exists(connection: sqlite3.Connection, name: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE name=? LIMIT 1", (name,)
    ).fetchone() is not None


def resolve_repo_key(connection: sqlite3.Connection, requested: str) -> str | None:
    """Resolve exact or normalized ``owner@repo`` input to a stored key."""

    if requested.count("@") != 1:
        raise QueryError("repository must be written as owner@repo")
    owner, repo = requested.split("@", 1)
    row = connection.execute(
        """SELECT repo_key
             FROM repo_product_map
            WHERE repo_key=? OR (owner_key=? AND repo_name_key=?)
            ORDER BY CASE WHEN repo_key=? THEN 0 ELSE 1 END, repo_key
            LIMIT 1""",
        (requested, normalize_key(owner), normalize_key(repo), requested),
    ).fetchone()
    return None if row is None else str(row[0])


def _truth(value: bool | None) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown"


def _branch_prefix(exact: str | None) -> str | None:
    if not exact:
        return None
    value = exact.strip()
    if value.endswith(".*") or value.lower().endswith(".x"):
        return value[:-2]
    return None


def evaluate_range(version: str, row: Mapping[str, Any]) -> tuple[str, str, str]:
    """Evaluate one flattened version segment.

    Returns ``(truth, reason, comparison_profile)``.  Special resolution
    classes follow the normalization engine's fail-safe behavior; ordinary
    exact and bounded ranges reuse its version comparator.
    """

    version_class = str(row.get("version_resolution_class") or "")
    product_key = str(row.get("product_key") or "")
    exact = row.get("exact_value")
    lower = row.get("lower_bound")
    upper = row.get("upper_bound")
    profile = profile_for(
        (version, exact, lower, upper), version_type=None, product_key=product_key
    )

    if version_class == "EXPLICIT_ALL":
        return "true", "explicit_all", profile
    if version_class in {"CPE_ANY_UNCORROBORATED", "UNSPECIFIED", "UNPARSED"}:
        return "unknown", version_class.casefold(), profile
    if version_class == "NOT_APPLICABLE":
        return "false", "version_not_applicable", profile
    if version_class == "BRANCH_RANGE":
        prefix = _branch_prefix(None if exact is None else str(exact))
        if prefix is None:
            return "unknown", "branch_parse_failed", profile
        matched = version == prefix or version.startswith(prefix + ".")
        return _truth(matched), "branch_prefix_match" if matched else "branch_mismatch", profile

    if exact is not None:
        matched = compare_versions(version, str(exact), profile) == 0
        return _truth(matched), "exact_match" if matched else "exact_mismatch", profile

    if lower is not None:
        comparison = compare_versions(version, str(lower), profile)
        inclusive = bool(row.get("lower_inclusive"))
        if comparison < 0 or (comparison == 0 and not inclusive):
            return "false", "lower_bound_not_met", profile
    if upper is not None:
        comparison = compare_versions(version, str(upper), profile)
        inclusive = bool(row.get("upper_inclusive"))
        if comparison > 0 or (comparison == 0 and not inclusive):
            return "false", "upper_bound_exceeded", profile
    return "true", "range_match", profile


def format_range(row: Mapping[str, Any]) -> str:
    exact = row.get("exact_value")
    if exact is not None:
        return f"={exact}"
    lower = row.get("lower_bound")
    upper = row.get("upper_bound")
    if lower is None and upper is None:
        return "*"
    left = "" if lower is None else ("[" if row.get("lower_inclusive") else "(") + str(lower)
    right = "" if upper is None else str(upper) + ("]" if row.get("upper_inclusive") else ")")
    if lower is None:
        return f"(-inf,{right}"
    if upper is None:
        return f"{left},+inf)"
    return f"{left},{right}"


def _apply_default_closure(
    evaluated: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Apply the best closure approximation available in the flat DB.

    The full claim group is not copied into repo_cve.sqlite.  Product/source is
    the narrowest safe grouping retained by the projection.
    """

    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for item in evaluated:
        row = item["row"]
        groups[(row.get("product_id"), row.get("source_family"))].append(item)

    selected: list[dict[str, Any]] = []
    for values in groups.values():
        defaults = [item for item in values if item["row"].get("is_default_closure")]
        explicit = [item for item in values if not item["row"].get("is_default_closure")]
        if not defaults:
            selected.extend(explicit)
            continue
        selected.extend(explicit)
        coverage = {item["truth"] for item in explicit}
        if "true" in coverage:
            continue
        for item in defaults:
            if "unknown" in coverage and item["truth"] == "true":
                item = {**item, "truth": "unknown", "reason": "explicit_coverage_unknown"}
            selected.append(item)
    return selected


def evaluate_cve(
    candidate: Mapping[str, Any],
    ranges: Sequence[Mapping[str, Any]],
    clovery: Mapping[str, Any] | None,
    *,
    version: str,
    policy: str,
) -> dict[str, Any]:
    """Return the inclusive/strict verdict for one repository CVE."""

    if clovery and clovery.get("state") == "no_vulnerable_release":
        state = "not_affected_clovery"
        reasons = ["high_confidence_no_vulnerable_release"]
        selected: list[dict[str, Any]] = []
    else:
        evaluated = []
        for row in ranges:
            truth, reason, profile = evaluate_range(version, row)
            evaluated.append(
                {
                    "row": dict(row),
                    "truth": truth,
                    "reason": reason,
                    "profile": profile,
                }
            )
        selected = _apply_default_closure(evaluated)
        affected = [
            item for item in selected
            if item["truth"] == "true" and item["row"].get("polarity") == "affected"
        ]
        unaffected = [
            item for item in selected
            if item["truth"] == "true" and item["row"].get("polarity") == "unaffected"
        ]
        uncertain = [
            item for item in selected
            if item["truth"] == "unknown"
            and item["row"].get("polarity") in {"affected", "unknown"}
        ]
        if affected and unaffected:
            state = "conflict_review"
            reasons = ["active_polarity_conflict"]
        elif unaffected:
            state = "not_affected_asserted"
            reasons = sorted({item["reason"] for item in unaffected})
        elif affected:
            provisional = bool(candidate.get("any_provisional_llm_identity"))
            manual = bool(candidate.get("any_manual_review_required"))
            state = "potentially_affected" if provisional or manual else "affected"
            reasons = sorted({item["reason"] for item in affected})
            if provisional:
                reasons.append("identity_alias_provisional")
            if manual:
                reasons.append("repository_mapping_needs_review")
        elif uncertain:
            state = "potentially_affected"
            reasons = sorted({item["reason"] for item in uncertain})
        elif selected:
            state = "not_affected_out_of_range"
            reasons = sorted({item["reason"] for item in selected})
        else:
            state = "potentially_affected"
            reasons = ["no_effective_version_range"]

    matched_ranges = [
        {
            "polarity": item["row"].get("polarity"),
            "range": format_range(item["row"]),
            "source": item["row"].get("range_source"),
            "truth": item["truth"],
            "reason": item["reason"],
            "profile": item["profile"],
            "product_id": item["row"].get("product_id"),
        }
        for item in selected
        if item["truth"] in {"true", "unknown"}
    ]
    sources = sorted(
        {str(row.get("range_source")) for row in ranges if row.get("range_source")}
    )
    if clovery and not sources:
        sources = ["clovery"]
    return {
        "cve_id": str(candidate["cve_id"]),
        "state": state,
        "positive": state in POSITIVE_STATES[policy],
        "reason_codes": reasons,
        "range_sources": sources or ["none"],
        "clovery_confidence": None if clovery is None else clovery.get("confidence"),
        "clovery_changed": None if clovery is None else bool(clovery.get("changed")),
        "manual_review_required": bool(candidate.get("any_manual_review_required")),
        "provisional_identity": bool(candidate.get("any_provisional_llm_identity")),
        "product_path_count": int(candidate.get("product_path_count") or 0),
        "matched_ranges": matched_ranges,
        "vuln_status": candidate.get("vuln_status"),
        "last_modified": candidate.get("last_modified"),
        "description": candidate.get("primary_description"),
    }


def query_database(
    database: Path,
    repo_key: str,
    version: str,
    *,
    policy: str = "inclusive",
    cve_ids: Iterable[str] = (),
) -> dict[str, Any]:
    if policy not in POSITIVE_STATES:
        raise QueryError(f"unsupported policy: {policy}")
    if not database.is_file():
        raise QueryError(f"database not found: {database}")
    if not version.strip() or version.strip() in {"*", "-", "n/a", "unknown"}:
        raise QueryError("version must be a concrete value")

    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        required = {
            "repo_product_map",
            "repo_cve",
            "cve_info",
            "repo_cve_version_effective",
            "clovery_result_effective",
        }
        missing = sorted(name for name in required if not table_exists(connection, name))
        if missing:
            raise QueryError(
                "database is missing Clovery sync objects: "
                + ", ".join(missing)
                + "; run utils/apply_clovery_results.py first"
            )
        resolved = resolve_repo_key(connection, repo_key)
        if resolved is None:
            raise QueryError(f"repository not mapped: {repo_key}")

        requested_cves = {value.strip().upper() for value in cve_ids if value.strip()}
        candidate_rows = [
            dict(row)
            for row in connection.execute(
                """SELECT rc.repo_key,rc.cve_id,rc.product_path_count,
                          rc.any_manual_review_required,
                          rc.any_provisional_llm_identity,
                          ci.vuln_status,ci.last_modified,
                          ci.primary_description
                     FROM repo_cve rc
                     JOIN cve_info ci USING(cve_id)
                    WHERE rc.repo_key=?
                    ORDER BY rc.cve_id""",
                (resolved,),
            )
            if not requested_cves or str(row["cve_id"]).upper() in requested_cves
        ]

        ranges_by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in connection.execute(
            """SELECT e.*,m.product_key,m.canonical_vendor,m.canonical_product
                 FROM repo_cve_version_effective e
                 LEFT JOIN repo_product_map m
                   ON m.repo_key=e.repo_key AND m.product_id=e.product_id
                WHERE e.repo_key=?
                ORDER BY e.cve_id,e.product_id,e.polarity,
                         e.lower_bound,e.upper_bound,e.exact_value""",
            (resolved,),
        ):
            ranges_by_cve[str(row["cve_id"])].append(dict(row))

        clovery_by_cve = {
            str(row["cve_id"]): dict(row)
            for row in connection.execute(
                """SELECT cve_id,state,confidence,changed,tag_count,
                          evaluated_tags,unknown_tags,result_id
                     FROM clovery_result_effective
                    WHERE repo_key=?""",
                (resolved,),
            )
        }
        results = [
            evaluate_cve(
                candidate,
                ranges_by_cve.get(str(candidate["cve_id"]), []),
                clovery_by_cve.get(str(candidate["cve_id"])),
                version=version.strip(),
                policy=policy,
            )
            for candidate in candidate_rows
        ]
        state_counts: dict[str, int] = defaultdict(int)
        for item in results:
            state_counts[item["state"]] += 1
        return {
            "database": str(database),
            "requested_repo_key": repo_key,
            "repo_key": resolved,
            "version": version.strip(),
            "policy": policy,
            "projection": "repo_cve_version_effective",
            "candidate_count": len(results),
            "positive_count": sum(bool(item["positive"]) for item in results),
            "state_counts": dict(sorted(state_counts.items())),
            "results": results,
            "limitations": [
                "repo_cve.sqlite is a flattened projection without the full configuration graph",
                "default closure is approximated per product/source because claim_group is not stored",
            ],
        }
    finally:
        connection.close()


def _compact_range(result: Mapping[str, Any]) -> str:
    matched = result.get("matched_ranges") or []
    values = [
        f"{item['polarity']}:{item['range']}"
        for item in matched
        if item.get("truth") == "true"
    ]
    return ",".join(values[:2]) + ("…" if len(values) > 2 else "")


def render_table(payload: Mapping[str, Any], *, all_states: bool) -> str:
    rows = [
        item for item in payload["results"] if all_states or bool(item["positive"])
    ]
    columns = ("CVE", "STATE", "SOURCE", "CONF", "MATCHED RANGE", "REVIEW")
    rendered = []
    for item in rows:
        rendered.append(
            (
                str(item["cve_id"]),
                str(item["state"]),
                ",".join(item["range_sources"]),
                str(item["clovery_confidence"] or "-"),
                _compact_range(item) or "-",
                "yes" if item["manual_review_required"] else "no",
            )
        )
    widths = [len(value) for value in columns]
    for row in rendered:
        widths = [max(width, len(value)) for width, value in zip(widths, row)]
    line = "  ".join(value.ljust(width) for value, width in zip(columns, widths))
    divider = "  ".join("-" * width for width in widths)
    body = [line, divider]
    body.extend(
        "  ".join(value.ljust(width) for value, width in zip(row, widths))
        for row in rendered
    )
    body.append("")
    shown = len(rendered)
    body.append(
        f"{payload['repo_key']} {payload['version']}: "
        f"{payload['positive_count']} positive / {payload['candidate_count']} candidates; "
        f"showing {shown} ({payload['policy']})"
    )
    if not rows:
        body.insert(2, "(no rows)")
    return "\n".join(body)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_key", help="repository identity as owner@repo")
    parser.add_argument("--version", required=True, help="concrete release version")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument(
        "--policy", choices=tuple(POSITIVE_STATES), default="inclusive"
    )
    parser.add_argument("--cve", action="append", default=[], help="restrict to a CVE")
    parser.add_argument(
        "--all-states", action="store_true", help="show negative states too"
    )
    parser.add_argument("--format", choices=("table", "json"), default="table")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        payload = query_database(
            arguments.db,
            arguments.repo_key,
            arguments.version,
            policy=arguments.policy,
            cve_ids=arguments.cve,
        )
    except (QueryError, sqlite3.Error, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if arguments.format == "json":
        selected = payload["results"] if arguments.all_states else [
            item for item in payload["results"] if item["positive"]
        ]
        print(json.dumps({**payload, "results": selected}, indent=2, ensure_ascii=False))
    else:
        print(render_table(payload, all_states=arguments.all_states))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
