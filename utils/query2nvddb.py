#!/usr/bin/env python3
"""Product-oriented query CLI for nvd_applicability.sqlite."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Mapping, Sequence

# Direct execution sets sys.path[0] to utils/, not the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.nvd_normalization.query_engine import (
    ApplicabilityQuery,
    QueryEngine,
    QueryError,
)
from scripts.nvd_normalization.rules import normalize_key


STATE_RANK = {
    "affected": 5,
    "potentially_affected": 4,
    "conflict_review": 3,
    "product_only_observation": 2,
    "insufficient_data": 1,
    "not_affected_out_of_range": 0,
    "not_applicable": 0,
}


def _args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "PRODUCT만 지정하면 제품과 affected 버전 규칙을 확인하고, "
            "PRODUCT VERSION을 지정하면 해당 버전에 적용되는 CVE를 확인합니다."
        )
    )
    parser.add_argument("product", help="제품 이름")
    parser.add_argument("version", nargs="?", help="조회할 구체 버전")
    parser.add_argument("--vendor", help="동명 제품을 구분할 vendor")
    parser.add_argument(
        "--db", type=Path, default=Path("workspace/nvd_applicability.sqlite")
    )
    parser.add_argument("--format", choices=("table", "json"), default="table")
    parser.add_argument(
        "--limit", type=int, default=100, help="출력 행 제한 (0: 제한 없음)"
    )
    parser.add_argument(
        "--prediction-policy",
        choices=("strict", "inclusive", "review-aware"),
        default="inclusive",
    )
    parser.add_argument(
        "--axis-policy",
        choices=("operational_strict", "broad_discovery", "platform_strict"),
        default="operational_strict",
    )
    parser.add_argument(
        "--all-states",
        action="store_true",
        help="범위 밖/정보 부족 CVE까지 모두 출력",
    )
    return parser.parse_args(argv)


def _member_ids(
    connection: sqlite3.Connection, cluster_id: int | None, product_id: int
) -> list[int]:
    if cluster_id is None:
        return [product_id]
    rows = connection.execute(
        """SELECT product_id FROM identity_cluster_member
            WHERE cluster_id=? AND product_id IS NOT NULL""",
        (cluster_id,),
    )
    return [int(row[0]) for row in rows] or [product_id]


def _make_group(
    engine: QueryEngine,
    row: Mapping[str, Any],
    *,
    query_vendor: str,
    query_product: str,
    product_ids: list[int] | None = None,
) -> dict[str, Any]:
    product_id = int(row["product_id"])
    cluster_id = row.get("cluster_id")
    ids = product_ids or _member_ids(engine.connection, cluster_id, product_id)
    marks = ",".join("?" for _ in ids)
    cve_count = int(
        engine.connection.execute(
            f"""SELECT COUNT(DISTINCT cve_id) FROM current_binding
                 WHERE product_id IN ({marks})""",
            ids,
        ).fetchone()[0]
    )
    return {
        "vendor": str(row["vendor"]),
        "product": str(row["product"]),
        "part": str(row["part"]),
        "cluster_id": cluster_id,
        "identity_tier": row.get("identity_tier"),
        "product_ids": ids,
        "cve_count": cve_count,
        "_query_vendor": query_vendor,
        "_query_product": query_product,
    }


def _find_groups(
    engine: QueryEngine, vendor: str | None, product: str, axis_policy: str
) -> tuple[list[dict[str, Any]], Mapping[str, Any] | None]:
    if vendor:
        resolution = engine.resolve_identity(
            vendor, product, axis_policy=axis_policy
        )
        if resolution["state"] != "resolved":
            return [], resolution
        by_cluster: dict[tuple[str, int], list[Mapping[str, Any]]] = defaultdict(list)
        for item in resolution["resolved_products"]:
            cluster_id = item["identity"].get("cluster_id")
            key = (
                ("cluster", int(cluster_id))
                if cluster_id is not None
                else ("product", int(item["product_id"]))
            )
            by_cluster[key].append(item)
        groups = []
        for items in by_cluster.values():
            first = items[0]
            groups.append(
                _make_group(
                    engine,
                    {
                        "product_id": first["product_id"],
                        "vendor": first["vendor"],
                        "product": first["product"],
                        "part": first["part"],
                        "cluster_id": first["identity"].get("cluster_id"),
                        "identity_tier": first["identity"].get("tier"),
                    },
                    query_vendor=vendor,
                    query_product=product,
                    product_ids=sorted(
                        {int(item["product_id"]) for item in items}
                    ),
                )
            )
        return groups, resolution

    rows = engine.connection.execute(
        """SELECT p.product_id,p.canonical_vendor AS vendor,
                  p.canonical_product AS product,p.part,m.cluster_id,
                  c.max_tier AS identity_tier,
                  COUNT(DISTINCT b.cve_id) AS direct_cve_count
             FROM product_entity p
             LEFT JOIN identity_cluster_member m USING(product_id)
             LEFT JOIN identity_cluster c USING(cluster_id)
             LEFT JOIN current_binding b USING(product_id)
            WHERE p.product_key=?
            GROUP BY p.product_id
            ORDER BY direct_cve_count DESC,p.vendor_key""",
        (normalize_key(product),),
    ).fetchall()
    selected: dict[tuple[str, int], sqlite3.Row] = {}
    for row in rows:
        key = (
            ("cluster", int(row["cluster_id"]))
            if row["cluster_id"] is not None
            else ("product", int(row["product_id"]))
        )
        selected.setdefault(key, row)
    groups = [
        _make_group(
            engine,
            dict(row),
            query_vendor=str(row["vendor"]),
            query_product=str(row["product"]),
        )
        for row in selected.values()
    ]
    groups.sort(key=lambda item: (-item["cve_count"], _label(item)))
    return groups, None


def _label(group: Mapping[str, Any]) -> str:
    return f"{group['vendor']}/{group['product']}"


def _public(group: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in group.items() if not key.startswith("_")}


def _version_text(row: Mapping[str, Any]) -> str:
    if row["exact_value"] is not None:
        return f"= {row['exact_value']}"
    parts = []
    if row["lower_bound"] is not None:
        parts.append(
            f"{'>=' if row['lower_inclusive'] else '>'} {row['lower_bound']}"
        )
    if row["upper_bound"] is not None:
        parts.append(
            f"{'<=' if row['upper_inclusive'] else '<'} {row['upper_bound']}"
        )
    return " and ".join(parts) or "all/unspecified versions"


def _version_rules(
    connection: sqlite3.Connection, groups: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    output = []
    for group in groups:
        ids = list(group["product_ids"])
        marks = ",".join("?" for _ in ids)
        rows = connection.execute(
            f"""SELECT a.assertion_polarity,e.profile_name,
                       v.lower_bound,v.lower_inclusive,
                       v.upper_bound,v.upper_inclusive,v.exact_value,
                       GROUP_CONCAT(DISTINCT a.source_family) source_families,
                       COUNT(DISTINCT a.cve_id) cve_count
                  FROM current_binding b
                  JOIN binding_assertion_member m USING(binding_id)
                  JOIN applicability_assertion a USING(assertion_id)
                  JOIN version_expression e USING(expression_id)
                  JOIN version_segment v USING(expression_id)
                 WHERE b.product_id IN ({marks}) AND m.is_active=1
                 GROUP BY a.assertion_polarity,e.profile_name,
                          v.lower_bound,v.lower_inclusive,
                          v.upper_bound,v.upper_inclusive,v.exact_value""",
            ids,
        )
        for row in rows:
            item = dict(row)
            item["identity"] = _label(group)
            item["version_rule"] = _version_text(row)
            output.append(item)
    output.sort(
        key=lambda row: (
            -int(row["cve_count"]),
            str(row["identity"]),
            str(row["version_rule"]),
        )
    )
    return output


def _query_cves(
    engine: QueryEngine,
    groups: Sequence[Mapping[str, Any]],
    version: str,
    *,
    prediction_policy: str,
    axis_policy: str,
    all_states: bool,
) -> tuple[list[dict[str, Any]], int, int, list[dict[str, Any]]]:
    merged: dict[str, dict[str, Any]] = {}
    candidate_ids: set[str] = set()
    positive_ids: set[str] = set()
    failures = []
    for group in groups:
        payload = engine.query(
            ApplicabilityQuery(
                vendor=str(group["_query_vendor"]),
                product=str(group["_query_product"]),
                version=version,
                axis_policy=axis_policy,
            ),
            prediction_policy=prediction_policy,
            include_trace=False,
        )
        if payload["resolution"]["state"] != "resolved":
            failures.append(
                {"identity": _label(group), "resolution": payload["resolution"]}
            )
            continue
        for row in payload["results"]:
            cve_id = str(row["cve_id"])
            candidate_ids.add(cve_id)
            if row["positive"]:
                positive_ids.add(cve_id)
            if not all_states and not row["positive"]:
                continue
            match = {
                "identity": _label(group),
                "state": row["state"],
                "reason_codes": row["reason_codes"],
            }
            if cve_id not in merged:
                merged[cve_id] = {
                    "cve_id": cve_id,
                    "state": row["state"],
                    "positive": bool(row["positive"]),
                    "identities": [_label(group)],
                    "matches": [match],
                    "manual_review_required": bool(
                        row["manual_review_required"]
                    ),
                    "last_modified": row["last_modified"],
                    "description": row["description"],
                }
            else:
                current = merged[cve_id]
                current["matches"].append(match)
                if _label(group) not in current["identities"]:
                    current["identities"].append(_label(group))
                current["positive"] = bool(current["positive"] or row["positive"])
                current["manual_review_required"] = bool(
                    current["manual_review_required"]
                    or row["manual_review_required"]
                )
                if STATE_RANK.get(str(row["state"]), 0) > STATE_RANK.get(
                    str(current["state"]), 0
                ):
                    current["state"] = row["state"]
    return (
        sorted(merged.values(), key=lambda row: row["cve_id"]),
        len(candidate_ids),
        len(positive_ids),
        failures,
    )


def _clip(value: Any, width: int) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= width else text[: width - 1] + "…"


def _table(rows: Sequence[Mapping[str, Any]], fields: Sequence[str]) -> str:
    if not rows:
        return "(no rows)\n"
    caps = {"identity": 34, "version_rule": 48, "description": 68}
    widths = {
        field: min(
            caps.get(field, 28),
            max(len(field), *(len(str(row.get(field, ""))) for row in rows)),
        )
        for field in fields
    }
    lines = [
        "  ".join(field.ljust(widths[field]) for field in fields),
        "  ".join("-" * widths[field] for field in fields),
    ]
    lines.extend(
        "  ".join(
            _clip(row.get(field), widths[field]).ljust(widths[field])
            for field in fields
        )
        for row in rows
    )
    return "\n".join(lines) + "\n"


def _limit(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    return rows if limit == 0 else rows[:limit]


def _render(payload: Mapping[str, Any], limit: int) -> str:
    if payload["mode"] == "product":
        lines = [
            f"제품 존재: {'yes' if payload['product_exists'] else 'no'}",
            "주의: 아래 버전 정보는 NVD affected 규칙이며 전체 릴리스 목록이 아닙니다.",
        ]
        if payload["products"]:
            lines.extend(
                [
                    "",
                    _table(
                        payload["products"],
                        (
                            "vendor",
                            "product",
                            "part",
                            "cluster_id",
                            "identity_tier",
                            "cve_count",
                        ),
                    ).rstrip(),
                ]
            )
        rules = payload["version_rules"]
        shown = _limit(rules, limit)
        if rules:
            lines.extend(
                [
                    "",
                    f"버전 규칙: {len(rules)}개 (출력 {len(shown)}개)",
                    _table(
                        shown,
                        (
                            "identity",
                            "assertion_polarity",
                            "version_rule",
                            "profile_name",
                            "source_families",
                            "cve_count",
                        ),
                    ).rstrip(),
                ]
            )
    else:
        lines = [
            f"질의 유효: {'yes' if payload['input_valid'] else 'no'}",
            f"제품 존재: {'yes' if payload['product_exists'] else 'no'}",
            "실제 릴리스 존재 여부: NVD DB만으로 확인 불가",
        ]
        if payload["product_exists"]:
            lines.append(
                f"적용 CVE: {payload['positive_count']}개 / "
                f"후보 {payload['candidate_count']}개"
            )
        shown = _limit(payload["results"], limit)
        if shown:
            rows = []
            for row in shown:
                item = dict(row)
                item["identity"] = ",".join(row["identities"])
                rows.append(item)
            lines.extend(
                [
                    "",
                    f"CVE 결과: {len(payload['results'])}개 "
                    f"(출력 {len(shown)}개)",
                    _table(
                        rows,
                        (
                            "cve_id",
                            "state",
                            "identity",
                            "manual_review_required",
                            "last_modified",
                            "description",
                        ),
                    ).rstrip(),
                ]
            )
        elif payload["product_exists"]:
            lines.extend(["", "조건에 해당하는 CVE가 없습니다."])
    if not payload["product_exists"] and payload.get("suggestions"):
        lines.extend(
            [
                "",
                "유사 검색 결과:",
                _table(
                    payload["suggestions"],
                    (
                        "canonical_vendor",
                        "canonical_product",
                        "part",
                        "cve_count",
                    ),
                ).rstrip(),
            ]
        )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    args = _args(argv)
    if args.limit < 0:
        print("error: --limit must be zero or positive", file=sys.stderr)
        return 2
    try:
        with QueryEngine(args.db) as engine:
            groups, resolution = _find_groups(
                engine, args.vendor, args.product, args.axis_policy
            )
            suggestions = (
                [] if groups else engine.search_products(args.product, limit=10)
            )
            if args.version is None:
                rules = _version_rules(engine.connection, groups) if groups else []
                payload = {
                    "mode": "product",
                    "query": {"vendor": args.vendor, "product": args.product},
                    "product_exists": bool(groups),
                    "resolution": resolution,
                    "products": [_public(group) for group in groups],
                    "version_rule_count": len(rules),
                    "version_rules": rules,
                    "suggestions": suggestions,
                }
            else:
                if (
                    not args.version.strip()
                    or args.version.strip().casefold() in {"*", "-", "n/a"}
                ):
                    raise QueryError("version must be a concrete value")
                results, candidates, positives, failures = _query_cves(
                    engine,
                    groups,
                    args.version,
                    prediction_policy=args.prediction_policy,
                    axis_policy=args.axis_policy,
                    all_states=args.all_states,
                )
                payload = {
                    "mode": "product_version",
                    "query": {
                        "vendor": args.vendor,
                        "product": args.product,
                        "version": args.version,
                        "prediction_policy": args.prediction_policy,
                        "axis_policy": args.axis_policy,
                    },
                    "input_valid": bool(groups) and len(failures) < len(groups),
                    "product_exists": bool(groups),
                    "release_existence": "not_verifiable_from_nvd",
                    "products": [_public(group) for group in groups],
                    "candidate_count": candidates,
                    "positive_count": positives,
                    "result_count": len(results),
                    "results": results,
                    "failed_identities": failures,
                    "suggestions": suggestions,
                }
    except (OSError, sqlite3.Error, QueryError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    exit_code = 0 if payload["product_exists"] else 3
    if args.format == "json":
        output = dict(payload)
        key = "version_rules" if payload["mode"] == "product" else "results"
        output[f"returned_{key}"] = _limit(payload[key], args.limit)
        output.pop(key)
        print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(_render(payload, args.limit), end="")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
