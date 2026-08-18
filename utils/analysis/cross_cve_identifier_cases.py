#!/usr/bin/env python3
"""Count consolidated cross-CVE vendor/product identifier cases.

This analyzer intentionally reuses the identity evidence produced by the
normalization pipeline.  Alias admission and mismatch taxonomy are separate:
an edge may remain a non-strict candidate while its spelling/relationship
type is still countable in an inclusive report.

* ``identity_alias_edge`` supplies aliases and review candidates.
* ``identity_hard_distinct`` supplies confirmed non-equivalent identities.
* ``product_relation`` supplies relation-only product pairs.
* a small, versioned JSON registry supplies semantic facts which cannot be
  established from spelling alone (ownership transfer, plugin authorship,
  and similar cases).

The headline CVE count is the number of distinct affected CVEs which use at
least one endpoint of a classified pair.  ``--with-cooccurrence`` additionally
counts CVEs in which both endpoints occur; that diagnostic is slower and is
not a replacement for the headline count because cross-CVE inconsistencies do
not have to co-occur in one CVE.
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any, Iterable, Iterator


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.nvd_normalization.rules import (  # noqa: E402
    DISTRIBUTION_PACKAGE_VENDORS,
    normalize_key,
)


DEFAULT_DB = REPO_ROOT / "workspace" / "nvd_applicability_v10.sqlite"
DEFAULT_REGISTRY = Path(__file__).with_name("identifier_case_registry_v1.json")

CATEGORIES: "OrderedDict[str, dict[str, str]]" = OrderedDict(
    [
        (
            "V1",
            {
                "axis": "vendor",
                "type": "표기·정규화 차이",
                "decision": "ALIAS",
                "includes": "typo, acronym, separator",
            },
        ),
        (
            "V2",
            {
                "axis": "vendor",
                "type": "조직·소유·프로젝트 주체 혼용",
                "decision": "ALIAS",
                "includes": (
                    "ownership_transfer, project_as_vendor, repository_owner, "
                    "foundation_company"
                ),
            },
        ),
        (
            "V3",
            {
                "axis": "vendor",
                "type": "배포·패키징 주체 혼용",
                "decision": "RELATION_ONLY",
                "includes": "distributor, packager",
            },
        ),
        (
            "V4",
            {
                "axis": "vendor",
                "type": "컴포넌트·플러그인 제작자 혼용",
                "decision": "RELATION_ONLY",
                "includes": "plugin_author, component_author",
            },
        ),
        (
            "V5",
            {
                "axis": "vendor",
                "type": "동명이인·서로 다른 프로젝트",
                "decision": "NO_MERGE",
                "includes": "homonym_distinct_project",
            },
        ),
        (
            "V0",
            {
                "axis": "vendor",
                "type": "판별 불가·검토 필요",
                "decision": "REVIEW",
                "includes": "unresolved alias candidate",
            },
        ),
        (
            "P1",
            {
                "axis": "product",
                "type": "표기오류·정규화 차이",
                "decision": "ALIAS",
                "includes": "separator, suffix, typo, alternate name",
            },
        ),
        (
            "P2",
            {
                "axis": "product",
                "type": "실제 하위 제품·서버·관련 산출물",
                "decision": "RELATION_ONLY",
                "includes": "component, server, plugin, related artifact",
            },
        ),
        (
            "P3",
            {
                "axis": "product",
                "type": "에디션·상업용 변형",
                "decision": "RELATION_ONLY",
                "includes": "edition, enterprise, commercial variant",
            },
        ),
        (
            "P4",
            {
                "axis": "product",
                "type": "동명이거나 비슷하지만 서로 다른 제품",
                "decision": "NO_MERGE",
                "includes": "homonym or misleadingly similar product",
            },
        ),
        (
            "P5",
            {
                "axis": "product",
                "type": "축약어·두문자어",
                "decision": "ALIAS",
                "includes": "acronym and expanded product name",
            },
        ),
        (
            "P0",
            {
                "axis": "product",
                "type": "판별 불가·문맥 의존",
                "decision": "REVIEW",
                "includes": "unresolved alias candidate",
            },
        ),
    ]
)

ALIAS_SUBTYPES = {
    "A1_SEPARATOR": "separator",
    "A2_LEGAL_SUFFIX": "legal_suffix",
    "A3_ORG_SUFFIX": "organization_suffix",
    "B1_ACRONYM": "acronym",
    "B2_BRAND_ALIAS": "brand_or_alternate_name",
    "B3_TYPO": "typo",
}

COMPONENT_RELATION_WORDS = ("plugin", "component", "module", "addon", "add_on")
DISTRIBUTION_RELATION_WORDS = ("package", "packaged", "distribution", "distributed")
ORGANIZATION_RELATION_WORDS = ("rename", "renamed", "ownership", "maintainer")
EDITION_RELATION_WORDS = (
    "edition",
    "enterprise",
    "commercial",
    "professional",
    "community",
)

CLAIM_FILTER = """
(
    (sc.source_family='nvd_cpe' AND sc.vulnerable_flag=1)
    OR
    (sc.source_family='cna_structured'
     AND lower(COALESCE(sc.status_raw,''))='affected')
)
"""


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument(
        "--statuses",
        default="accepted,provisional,candidate",
        help="comma-separated identity_alias_edge statuses to analyze",
    )
    parser.add_argument(
        "--classification-policy",
        choices=("inclusive", "strict"),
        default="inclusive",
        help=(
            "inclusive classifies candidate/provisional edges by alias class; "
            "strict leaves non-accepted edges in V0/P0"
        ),
    )
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--csv-out", type=Path)
    parser.add_argument(
        "--pairs-out",
        type=Path,
        help="optional JSONL dump of every classified identity pair",
    )
    parser.add_argument(
        "--with-cooccurrence",
        action="store_true",
        help="also count CVEs containing both endpoints (slower)",
    )
    parser.add_argument("--sample-size", type=int, default=5)
    return parser.parse_args()


def _connect(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise FileNotFoundError(f"normalization database not found: {path}")
    uri = f"file:{path.resolve()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA temp_store=FILE")
    return connection


def _require_tables(connection: sqlite3.Connection) -> None:
    required = {
        "raw_cve",
        "product_entity",
        "identity_node",
        "identity_alias_edge",
        "identity_hard_distinct",
        "product_relation",
        "source_claim",
    }
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    missing = sorted(required - present)
    if missing:
        raise RuntimeError(
            "database is not a schema-v5 normalization DB; missing tables: "
            + ", ".join(missing)
        )


def _create_temp_tables(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TEMP TABLE classified_pair (
            axis TEXT NOT NULL,
            class_code TEXT NOT NULL,
            subtype TEXT NOT NULL,
            decision TEXT NOT NULL,
            left_node_id INTEGER NOT NULL,
            right_node_id INTEGER NOT NULL,
            origin TEXT NOT NULL,
            confidence TEXT NOT NULL,
            priority INTEGER NOT NULL,
            basis TEXT NOT NULL,
            PRIMARY KEY (axis,left_node_id,right_node_id)
        ) WITHOUT ROWID;

        CREATE TEMP TABLE category_cve (
            axis TEXT NOT NULL,
            class_code TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            PRIMARY KEY (axis,class_code,cve_id)
        ) WITHOUT ROWID;

        CREATE TEMP TABLE cooccurrence_cve (
            axis TEXT NOT NULL,
            class_code TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            PRIMARY KEY (axis,class_code,cve_id)
        ) WITHOUT ROWID;
        """
    )


def _insert_case(
    connection: sqlite3.Connection,
    *,
    axis: str,
    class_code: str,
    subtype: str,
    left_node_id: int,
    right_node_id: int,
    origin: str,
    confidence: str,
    basis: str,
) -> None:
    if class_code not in CATEGORIES:
        raise ValueError(f"unknown class code: {class_code}")
    if CATEGORIES[class_code]["axis"] != axis:
        raise ValueError(f"{class_code} is not a {axis} class")
    left, right = sorted((int(left_node_id), int(right_node_id)))
    if left == right:
        return
    priority = {
        "manual_registry": 100,
        "identity_hard_distinct": 90,
        "product_relation": 80,
    }.get(origin, 0)
    if not priority:
        priority = {
            "algorithm_accepted": 70,
            "bounded_heuristic": 60,
            "inclusive_provisional": 55,
            "inclusive_candidate": 50,
            "review_candidate": 10,
        }.get(confidence, 20)
    connection.execute(
        """INSERT INTO classified_pair(
               axis,class_code,subtype,decision,left_node_id,right_node_id,
               origin,confidence,priority,basis
           ) VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(axis,left_node_id,right_node_id) DO UPDATE SET
               class_code=excluded.class_code,
               subtype=excluded.subtype,
               decision=excluded.decision,
               origin=excluded.origin,
               confidence=excluded.confidence,
               priority=excluded.priority,
               basis=excluded.basis
           WHERE excluded.priority > classified_pair.priority""",
        (
            axis,
            class_code,
            subtype,
            CATEGORIES[class_code]["decision"],
            left,
            right,
            origin,
            confidence,
            priority,
            basis,
        ),
    )


def _normalize_endpoint(endpoint: dict[str, Any]) -> dict[str, str]:
    result = {"vendor": normalize_key(str(endpoint.get("vendor", "")))}
    if "product" in endpoint:
        result["product"] = normalize_key(str(endpoint["product"]))
        result["part"] = str(endpoint.get("part", "*")).lower()
    return result


def _resolve_endpoint_nodes(
    connection: sqlite3.Connection,
    *,
    scope: str,
    endpoint: dict[str, Any],
) -> list[int]:
    value = _normalize_endpoint(endpoint)
    if scope == "vendor":
        return [
            int(row[0])
            for row in connection.execute(
                """SELECT node_id FROM identity_node
                   WHERE scope_kind='vendor' AND vendor_key=?""",
                (value["vendor"],),
            )
        ]
    if scope != "product" or "product" not in value:
        raise ValueError(f"invalid registry endpoint for scope={scope}: {endpoint}")
    sql = """SELECT node_id FROM identity_node
             WHERE scope_kind='product' AND vendor_key=? AND product_key=?"""
    params: list[Any] = [value["vendor"], value["product"]]
    if value["part"] != "*":
        sql += " AND part=?"
        params.append(value["part"])
    sql += " ORDER BY node_id"
    return [int(row[0]) for row in connection.execute(sql, params)]


def _registry_nodes_are_compatible(
    connection: sqlite3.Connection, scope: str, left: int, right: int
) -> bool:
    if scope == "vendor":
        return True
    rows = list(
        connection.execute(
            "SELECT node_id,part FROM identity_node WHERE node_id IN (?,?)",
            (left, right),
        )
    )
    if len(rows) != 2:
        return False
    parts = {int(row["node_id"]): str(row["part"]) for row in rows}
    return parts[left] == parts[right] or "unknown" in {parts[left], parts[right]}


def _load_registry(
    connection: sqlite3.Connection, path: Path
) -> tuple[str, list[dict[str, Any]]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if int(payload.get("schema_version", 0)) != 1:
        raise ValueError(f"unsupported registry schema in {path}")
    unresolved: list[dict[str, Any]] = []
    for item in payload.get("classifications", []):
        code = str(item["class_code"])
        axis = str(item.get("axis", CATEGORIES.get(code, {}).get("axis", "")))
        scope = str(item.get("scope", "product"))
        left_nodes = _resolve_endpoint_nodes(
            connection, scope=scope, endpoint=item["left"]
        )
        right_nodes = _resolve_endpoint_nodes(
            connection, scope=scope, endpoint=item["right"]
        )
        if not left_nodes or not right_nodes:
            unresolved.append(
                {
                    "class_code": code,
                    "left": item["left"],
                    "right": item["right"],
                    "reason": "one_or_both_endpoints_absent",
                }
            )
            continue
        for left in left_nodes:
            for right in right_nodes:
                if not _registry_nodes_are_compatible(
                    connection, scope, left, right
                ):
                    continue
                _insert_case(
                    connection,
                    axis=axis,
                    class_code=code,
                    subtype=str(item["subtype"]),
                    left_node_id=left,
                    right_node_id=right,
                    origin="manual_registry",
                    confidence=str(item.get("confidence", "manual_confirmed")),
                    basis=str(item.get("basis", "manual_registry")),
                )
    return str(payload.get("registry_version", "unknown")), unresolved


def _basis_kinds(raw: str) -> set[str]:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return set()
    found: set[str] = set()

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            kind = node.get("kind")
            if isinstance(kind, str):
                found.add(kind)
            for child in node.values():
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return found


def _iter_rows(
    cursor: sqlite3.Cursor, batch_size: int = 10_000
) -> Iterator[sqlite3.Row]:
    while True:
        rows = cursor.fetchmany(batch_size)
        if not rows:
            return
        yield from rows


def _is_distribution_pair(left_vendor: str, right_vendor: str) -> bool:
    # The narrow set is safe for automatic classification.  The broader set
    # is accepted only when the other endpoint is a self-brand upstream.
    if (left_vendor in DISTRIBUTION_PACKAGE_VENDORS) != (
        right_vendor in DISTRIBUTION_PACKAGE_VENDORS
    ):
        return True
    return False


def _inclusive_confidence(status: str) -> str:
    if status == "accepted":
        return "algorithm_accepted"
    if status == "provisional":
        return "inclusive_provisional"
    if status == "candidate":
        return "inclusive_candidate"
    return "review_candidate"


def _vendor_alias_class(
    alias_class: str,
    status: str,
    classification_policy: str,
) -> tuple[str, str]:
    admitted = status == "accepted"
    inclusive = classification_policy == "inclusive" and status in {
        "provisional",
        "candidate",
    }
    if not (admitted or inclusive):
        return "V0", "review_candidate"
    if alias_class in {
        "A1_SEPARATOR",
        "A2_LEGAL_SUFFIX",
        "B1_ACRONYM",
        "B3_TYPO",
    }:
        return "V1", _inclusive_confidence(status)
    if alias_class in {"A3_ORG_SUFFIX", "B2_BRAND_ALIAS"}:
        return "V2", _inclusive_confidence(status)
    return "V0", "review_candidate"


def _product_alias_class(
    alias_class: str,
    status: str,
    classification_policy: str,
) -> tuple[str, str]:
    admitted = status == "accepted"
    inclusive = classification_policy == "inclusive" and status in {
        "provisional",
        "candidate",
    }
    if not (admitted or inclusive):
        return "P0", "review_candidate"
    if alias_class == "B1_ACRONYM":
        return "P5", _inclusive_confidence(status)
    if alias_class in {
        "A1_SEPARATOR",
        "A2_LEGAL_SUFFIX",
        "A3_ORG_SUFFIX",
        "B2_BRAND_ALIAS",
        "B3_TYPO",
    }:
        return "P1", _inclusive_confidence(status)
    return "P0", "review_candidate"


def _classify_alias_edges(
    connection: sqlite3.Connection,
    statuses: set[str],
    classification_policy: str,
) -> dict[str, int]:
    placeholders = ",".join("?" for _ in statuses)
    cursor = connection.execute(
        f"""SELECT e.left_node_id,e.right_node_id,e.alias_class,e.status,
                   e.basis_json,
                   l.scope_kind AS scope,
                   l.vendor_key AS left_vendor,l.product_key AS left_product,
                   r.vendor_key AS right_vendor,r.product_key AS right_product
            FROM identity_alias_edge e
            JOIN identity_node l ON l.node_id=e.left_node_id
            JOIN identity_node r ON r.node_id=e.right_node_id
            WHERE e.status IN ({placeholders})
              AND l.scope_kind=r.scope_kind
            ORDER BY e.edge_id""",
        tuple(sorted(statuses)),
    )
    seen = 0
    for row in _iter_rows(cursor):
        seen += 1
        alias_class = str(row["alias_class"])
        status = str(row["status"])
        accepted = status == "accepted"
        inclusive_candidate = (
            classification_policy == "inclusive"
            and status in {"provisional", "candidate"}
        )
        scope = str(row["scope"])
        subtype = ALIAS_SUBTYPES.get(alias_class, alias_class.lower())
        basis_kinds = _basis_kinds(str(row["basis_json"]))
        basis = ",".join(sorted(basis_kinds)) or alias_class
        left = int(row["left_node_id"])
        right = int(row["right_node_id"])

        if scope == "vendor":
            code, confidence = _vendor_alias_class(
                alias_class,
                status,
                classification_policy,
            )
            _insert_case(
                connection,
                axis="vendor",
                class_code=code,
                subtype=subtype,
                left_node_id=left,
                right_node_id=right,
                origin="identity_alias_edge",
                confidence=confidence,
                basis=basis,
            )
            continue

        left_vendor = str(row["left_vendor"])
        right_vendor = str(row["right_vendor"])
        left_product = str(row["left_product"])
        right_product = str(row["right_product"])
        vendor_differs = left_vendor != right_vendor
        product_differs = left_product != right_product

        if vendor_differs:
            if (
                _is_distribution_pair(left_vendor, right_vendor)
                and left_product == right_product
            ):
                vendor_code, vendor_subtype = "V3", "distributor_packager"
                vendor_confidence = "bounded_heuristic"
            elif (
                accepted
                or inclusive_candidate
                or "validated_self_brand_product_bridge" in basis_kinds
            ):
                vendor_code, vendor_subtype = "V2", "organization_project_identity"
                vendor_confidence = _inclusive_confidence(status)
                if (
                    not accepted
                    and not inclusive_candidate
                    and "validated_self_brand_product_bridge" in basis_kinds
                ):
                    vendor_confidence = "bounded_heuristic"
            else:
                vendor_code, vendor_subtype = "V0", "unresolved_vendor_pair"
                vendor_confidence = "review_candidate"
            _insert_case(
                connection,
                axis="vendor",
                class_code=vendor_code,
                subtype=vendor_subtype,
                left_node_id=left,
                right_node_id=right,
                origin="identity_alias_edge",
                confidence=vendor_confidence,
                basis=basis,
            )

        if product_differs:
            product_code, product_confidence = _product_alias_class(
                alias_class,
                status,
                classification_policy,
            )
            _insert_case(
                connection,
                axis="product",
                class_code=product_code,
                subtype=(
                    subtype
                    if product_code != "P0"
                    else "unresolved_product_pair"
                ),
                left_node_id=left,
                right_node_id=right,
                origin="identity_alias_edge",
                confidence=product_confidence,
                basis=basis,
            )
    return {"alias_edges_considered": seen}


def _classify_hard_distinct(connection: sqlite3.Connection) -> dict[str, int]:
    seen = 0
    cursor = connection.execute(
        """SELECT h.left_node_id,h.right_node_id,h.basis,
                  l.scope_kind AS scope,
                  l.vendor_key AS left_vendor,l.product_key AS left_product,
                  r.vendor_key AS right_vendor,r.product_key AS right_product
           FROM identity_hard_distinct h
           JOIN identity_node l ON l.node_id=h.left_node_id
           JOIN identity_node r ON r.node_id=h.right_node_id
           ORDER BY h.left_node_id,h.right_node_id"""
    )
    for row in cursor:
        seen += 1
        left = int(row["left_node_id"])
        right = int(row["right_node_id"])
        basis = str(row["basis"])
        if str(row["scope"]) == "vendor":
            _insert_case(
                connection,
                axis="vendor",
                class_code="V5",
                subtype="homonym_distinct_project",
                left_node_id=left,
                right_node_id=right,
                origin="identity_hard_distinct",
                confidence="hard_distinct",
                basis=basis,
            )
            continue

        vendor_differs = str(row["left_vendor"]) != str(row["right_vendor"])
        product_differs = str(row["left_product"]) != str(row["right_product"])
        if vendor_differs:
            distribution_basis = any(
                word in basis.lower() for word in DISTRIBUTION_RELATION_WORDS
            )
            _insert_case(
                connection,
                axis="vendor",
                class_code="V3" if distribution_basis else "V5",
                subtype=(
                    "distributor_packager"
                    if distribution_basis
                    else "homonym_distinct_project"
                ),
                left_node_id=left,
                right_node_id=right,
                origin="identity_hard_distinct",
                confidence="hard_distinct",
                basis=basis,
            )
        if product_differs:
            _insert_case(
                connection,
                axis="product",
                class_code="P4",
                subtype="distinct_product",
                left_node_id=left,
                right_node_id=right,
                origin="identity_hard_distinct",
                confidence="hard_distinct",
                basis=basis,
            )
    return {"hard_distinct_pairs_considered": seen}


def _contains_any(value: str, words: Iterable[str]) -> bool:
    lowered = value.lower()
    return any(word in lowered for word in words)


def _classify_relations(connection: sqlite3.Connection) -> dict[str, int]:
    seen = 0
    cursor = connection.execute(
        """SELECT pr.relation_type,pr.evidence_basis,
                  l.node_id AS left_node_id,r.node_id AS right_node_id,
                  l.vendor_key AS left_vendor,r.vendor_key AS right_vendor,
                  l.product_key AS left_product,r.product_key AS right_product
           FROM product_relation pr
           JOIN identity_node l
             ON l.scope_kind='product' AND l.product_id=pr.from_product_id
           JOIN identity_node r
             ON r.scope_kind='product' AND r.product_id=pr.to_product_id
           ORDER BY pr.relation_id"""
    )
    for row in cursor:
        seen += 1
        relation = str(row["relation_type"])
        left = int(row["left_node_id"])
        right = int(row["right_node_id"])
        vendor_differs = str(row["left_vendor"]) != str(row["right_vendor"])
        product_differs = str(row["left_product"]) != str(row["right_product"])
        basis = str(row["evidence_basis"])

        if vendor_differs:
            if _contains_any(relation, COMPONENT_RELATION_WORDS):
                vendor_code, subtype = "V4", "component_or_plugin_author"
            elif _contains_any(relation, DISTRIBUTION_RELATION_WORDS):
                vendor_code, subtype = "V3", "distributor_packager"
            elif _contains_any(relation, ORGANIZATION_RELATION_WORDS):
                vendor_code, subtype = "V2", "ownership_or_maintainer_change"
            else:
                vendor_code, subtype = "V0", "unmapped_relation"
            _insert_case(
                connection,
                axis="vendor",
                class_code=vendor_code,
                subtype=subtype,
                left_node_id=left,
                right_node_id=right,
                origin="product_relation",
                confidence="explicit_relation",
                basis=f"{relation}: {basis}",
            )

        if product_differs:
            product_code = (
                "P3"
                if _contains_any(relation, EDITION_RELATION_WORDS)
                else "P2"
            )
            _insert_case(
                connection,
                axis="product",
                class_code=product_code,
                subtype=relation,
                left_node_id=left,
                right_node_id=right,
                origin="product_relation",
                confidence="explicit_relation",
                basis=basis,
            )
    return {"product_relations_considered": seen}


def _populate_category_cves(connection: sqlite3.Connection) -> None:
    # Product-scope endpoints.
    for side in ("left", "right"):
        connection.execute(
            f"""INSERT OR IGNORE INTO category_cve(axis,class_code,cve_id)
                SELECT cp.axis,cp.class_code,sc.cve_id
                FROM classified_pair cp
                JOIN identity_node n ON n.node_id=cp.{side}_node_id
                JOIN source_claim sc ON sc.product_id=n.product_id
                WHERE n.scope_kind='product' AND {CLAIM_FILTER}"""
        )
        # Vendor-scope endpoints expand to every product under that vendor.
        connection.execute(
            f"""INSERT OR IGNORE INTO category_cve(axis,class_code,cve_id)
                SELECT cp.axis,cp.class_code,sc.cve_id
                FROM classified_pair cp
                JOIN identity_node n ON n.node_id=cp.{side}_node_id
                JOIN product_entity pe ON pe.vendor_key=n.vendor_key
                JOIN source_claim sc ON sc.product_id=pe.product_id
                WHERE n.scope_kind='vendor' AND {CLAIM_FILTER}"""
        )


def _populate_cooccurrence_cves(connection: sqlite3.Connection) -> None:
    # Product-node pairs.
    connection.execute(
        f"""INSERT OR IGNORE INTO cooccurrence_cve(axis,class_code,cve_id)
            SELECT cp.axis,cp.class_code,a.cve_id
            FROM classified_pair cp
            JOIN identity_node l ON l.node_id=cp.left_node_id
            JOIN identity_node r ON r.node_id=cp.right_node_id
            JOIN source_claim a ON a.product_id=l.product_id
            JOIN source_claim b
              ON b.product_id=r.product_id AND b.cve_id=a.cve_id
            WHERE l.scope_kind='product' AND r.scope_kind='product'
              AND {CLAIM_FILTER.replace('sc.', 'a.')}
              AND {CLAIM_FILTER.replace('sc.', 'b.')}"""
    )
    # Vendor-node pairs.  Product-scope vendor differences are already covered
    # by the product-node query above.
    connection.execute(
        f"""INSERT OR IGNORE INTO cooccurrence_cve(axis,class_code,cve_id)
            SELECT cp.axis,cp.class_code,a.cve_id
            FROM classified_pair cp
            JOIN identity_node l ON l.node_id=cp.left_node_id
            JOIN identity_node r ON r.node_id=cp.right_node_id
            JOIN product_entity lp ON lp.vendor_key=l.vendor_key
            JOIN product_entity rp ON rp.vendor_key=r.vendor_key
            JOIN source_claim a ON a.product_id=lp.product_id
            JOIN source_claim b
              ON b.product_id=rp.product_id AND b.cve_id=a.cve_id
            WHERE l.scope_kind='vendor' AND r.scope_kind='vendor'
              AND {CLAIM_FILTER.replace('sc.', 'a.')}
              AND {CLAIM_FILTER.replace('sc.', 'b.')}"""
    )


def _fetch_count_map(
    connection: sqlite3.Connection, table: str
) -> dict[str, int]:
    return {
        str(row[0]): int(row[1])
        for row in connection.execute(
            f"SELECT class_code,COUNT(*) FROM {table} GROUP BY class_code"
        )
    }


def _build_report(
    connection: sqlite3.Connection,
    *,
    db_path: Path,
    registry_path: Path,
    registry_version: str,
    unresolved_registry: list[dict[str, Any]],
    statuses: set[str],
    classification_policy: str,
    counters: dict[str, int],
    with_cooccurrence: bool,
    sample_size: int,
) -> dict[str, Any]:
    total_cves = int(connection.execute("SELECT COUNT(*) FROM raw_cve").fetchone()[0])
    pair_counts = _fetch_count_map(connection, "classified_pair")
    cve_counts = _fetch_count_map(connection, "category_cve")
    co_counts = (
        _fetch_count_map(connection, "cooccurrence_cve")
        if with_cooccurrence
        else {}
    )
    rows: list[dict[str, Any]] = []
    for code, definition in CATEGORIES.items():
        cve_count = cve_counts.get(code, 0)
        samples = [
            str(row[0])
            for row in connection.execute(
                """SELECT cve_id FROM category_cve
                   WHERE class_code=? ORDER BY cve_id LIMIT ?""",
                (code, max(sample_size, 0)),
            )
        ]
        rows.append(
            {
                "code": code,
                **definition,
                "pair_count": pair_counts.get(code, 0),
                "cve_count": cve_count,
                "ratio_of_all_cves": (
                    round(cve_count / total_cves, 8) if total_cves else 0.0
                ),
                "cooccurrence_cve_count": (
                    co_counts.get(code, 0) if with_cooccurrence else None
                ),
                "sample_cves": samples,
            }
        )

    classified_any = int(
        connection.execute("SELECT COUNT(DISTINCT cve_id) FROM category_cve").fetchone()[0]
    )
    axis_totals: dict[str, dict[str, Any]] = {}
    for axis in ("vendor", "product"):
        count = int(
            connection.execute(
                """SELECT COUNT(DISTINCT cve_id) FROM category_cve
                   WHERE axis=?""",
                (axis,),
            ).fetchone()[0]
        )
        axis_totals[axis] = {
            "unique_cve_count": count,
            "ratio_of_all_cves": round(count / total_cves, 8) if total_cves else 0.0,
        }

    return {
        "metadata": {
            "analyzer": "cross_cve_identifier_cases.py",
            "classification_version": "consolidated-identifier-cases-1.1.0",
            "database": str(db_path.resolve()),
            "registry": str(registry_path.resolve()),
            "registry_version": registry_version,
            "alias_statuses": sorted(statuses),
            "classification_policy": classification_policy,
            "inclusive_policy_note": (
                "candidate/provisional edges are assigned a taxonomy code from "
                "alias_class while their non-strict confidence is preserved"
                if classification_policy == "inclusive"
                else "only accepted alias edges receive a non-zero taxonomy code"
            ),
            "cve_count_semantics": (
                "distinct affected CVEs using either endpoint of a classified pair"
            ),
            "ratios_denominator": "all rows in raw_cve",
            "category_overlap_note": (
                "a CVE may belong to multiple classes; category counts are not additive"
            ),
            "cooccurrence_enabled": with_cooccurrence,
        },
        "totals": {
            "all_cves": total_cves,
            "classified_any_unique_cves": classified_any,
            "classified_any_ratio": (
                round(classified_any / total_cves, 8) if total_cves else 0.0
            ),
            "by_axis": axis_totals,
            "classified_pairs": int(
                connection.execute("SELECT COUNT(*) FROM classified_pair").fetchone()[0]
            ),
        },
        "pipeline_inputs": counters,
        "unresolved_registry_entries": unresolved_registry,
        "categories": rows,
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "code",
        "axis",
        "type",
        "decision",
        "pair_count",
        "cve_count",
        "ratio_of_all_cves",
        "cooccurrence_cve_count",
        "includes",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _write_pairs(connection: sqlite3.Connection, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cursor = connection.execute(
        """SELECT cp.*,
                  l.scope_kind AS scope,
                  l.vendor_key AS left_vendor,l.product_key AS left_product,
                  l.part AS left_part,
                  r.vendor_key AS right_vendor,r.product_key AS right_product,
                  r.part AS right_part
           FROM classified_pair cp
           JOIN identity_node l ON l.node_id=cp.left_node_id
           JOIN identity_node r ON r.node_id=cp.right_node_id
           ORDER BY cp.axis,cp.class_code,cp.left_node_id,cp.right_node_id"""
    )
    with path.open("w", encoding="utf-8") as stream:
        for row in cursor:
            stream.write(json.dumps(dict(row), ensure_ascii=False) + "\n")


def _print_report(report: dict[str, Any]) -> None:
    metadata = report["metadata"]
    print(
        f"classification policy={metadata['classification_policy']} "
        f"statuses={','.join(metadata['alias_statuses'])}"
    )
    if metadata["classification_policy"] == "inclusive":
        print(
            "note: candidate/provisional pairs are taxonomy-counted but remain "
            "non-strict; see confidence in --pairs-out"
        )
    print(
        "code\taxis\ttype\tpairs\tCVEs\tratio(all CVEs)\tco-occurrence"
    )
    for row in report["categories"]:
        co = "-" if row["cooccurrence_cve_count"] is None else str(
            row["cooccurrence_cve_count"]
        )
        print(
            f"{row['code']}\t{row['axis']}\t{row['type']}\t"
            f"{row['pair_count']}\t{row['cve_count']}\t"
            f"{row['ratio_of_all_cves'] * 100:.4f}%\t{co}"
        )
    totals = report["totals"]
    print(
        f"all CVEs={totals['all_cves']}, "
        f"classified unique CVEs={totals['classified_any_unique_cves']} "
        f"({totals['classified_any_ratio'] * 100:.4f}%)"
    )
    unresolved = report["unresolved_registry_entries"]
    if unresolved:
        print(
            f"warning: {len(unresolved)} registry entries could not be resolved; "
            "see JSON output for details",
            file=sys.stderr,
        )


def main() -> int:
    args = _parse_args()
    statuses = {item.strip() for item in args.statuses.split(",") if item.strip()}
    allowed_statuses = {
        "accepted",
        "provisional",
        "candidate",
        "rejected",
        "superseded",
    }
    if not statuses or not statuses <= allowed_statuses:
        raise ValueError(f"invalid --statuses: {sorted(statuses)}")
    if not args.registry.is_file():
        raise FileNotFoundError(f"classification registry not found: {args.registry}")

    connection = _connect(args.db)
    try:
        _require_tables(connection)
        _create_temp_tables(connection)

        # Registry entries are inserted first and therefore override automatic
        # rules through the temp table's (axis,left,right) primary key.
        registry_version, unresolved = _load_registry(connection, args.registry)
        counters: dict[str, int] = {}
        counters.update(
            _classify_alias_edges(
                connection,
                statuses,
                args.classification_policy,
            )
        )
        counters.update(_classify_hard_distinct(connection))
        counters.update(_classify_relations(connection))

        _populate_category_cves(connection)
        if args.with_cooccurrence:
            _populate_cooccurrence_cves(connection)

        report = _build_report(
            connection,
            db_path=args.db,
            registry_path=args.registry,
            registry_version=registry_version,
            unresolved_registry=unresolved,
            statuses=statuses,
            classification_policy=args.classification_policy,
            counters=counters,
            with_cooccurrence=args.with_cooccurrence,
            sample_size=args.sample_size,
        )
        _print_report(report)
        if args.json_out:
            _write_json(args.json_out, report)
        if args.csv_out:
            _write_csv(args.csv_out, report["categories"])
        if args.pairs_out:
            _write_pairs(connection, args.pairs_out)
    finally:
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
