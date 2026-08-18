"""Evidence-backed identity alias materialization and query resolution.

The raw ``product_entity`` table remains immutable.  This module derives
comparison keys, evidence-bearing alias edges and deterministic clusters used
only by the read path and alias-aware role classification.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
import sqlite3
from typing import Any, Callable, Iterable, Mapping, Sequence

from .rules import (
    DISTRIBUTION_VENDORS,
    HARD_GENERIC_ANCHORS,
    IDENTITY_ALIAS_BUCKET_SIZE_LIMIT,
    IDENTITY_CLUSTER_SIZE_LIMIT,
    IDENTITY_REGISTRY,
    IDENTITY_REGISTRY_SHA256,
    IDENTITY_REGISTRY_VERSION,
    IDENTITY_TYPO_POLICY,
    LEGAL_SUFFIXES,
    ORG_SUFFIXES,
    P1_PRODUCT_KEY_REWRITES,
    RULE_VERSION,
    SOFT_GENERIC_ANCHORS,
    canonical_json,
    normalize_key,
    stable_hash,
)

ALIAS_CLASSES = frozenset(
    {
        "A1_SEPARATOR",
        "A2_LEGAL_SUFFIX",
        "A3_ORG_SUFFIX",
        "B1_ACRONYM",
        "B2_BRAND_ALIAS",
        "B3_TYPO",
    }
)

TIER_RANK = {
    "T0_EXACT": 0,
    "T1_FORMAT": 1,
    "T2_REGISTRY": 2,
    "T3_PROVISIONAL": 3,
    "T4_UNRESOLVED": 4,
}

_EDGE_EVIDENCE_FORMAT = "bounded_evidence_v1"
_MAX_EDGE_EVIDENCE_EXAMPLES = 32
_EDGE_INSERT_BATCH_SIZE = 2_000
_IDENTITY_PROGRESS_EVERY = 25_000
_SELF_BRAND_MIN_COMPACT_LENGTH = 5
_SELF_BRAND_MIN_SHARED_VERSIONS = 3

IdentityProgress = Callable[[str, Mapping[str, Any]], None]


def _report_identity_progress(
    progress: IdentityProgress | None,
    phase: str,
    **details: Any,
) -> None:
    if progress is not None:
        progress(phase, details)


@dataclass(slots=True)
class _CooccurrenceEvidence:
    count: int = 0
    cve_examples: list[str] = field(default_factory=list)

    def observe(self, cve_id: str) -> None:
        self.count += 1
        if len(self.cve_examples) < _MAX_EDGE_EVIDENCE_EXAMPLES:
            self.cve_examples.append(cve_id)

    def envelope(self) -> dict[str, Any]:
        return {
            "format": _EDGE_EVIDENCE_FORMAT,
            "evidence_count": self.count,
            "evidence_examples_limit": _MAX_EDGE_EVIDENCE_EXAMPLES,
            "evidence_truncated": self.count > len(self.cve_examples),
            "evidence": [
                {
                    "kind": "cna_nvd_same_cve_cooccurrence",
                    "cve_id": cve_id,
                    "warning": "cooccurrence_is_not_identity_proof",
                }
                for cve_id in self.cve_examples
            ],
        }


def _tokens(value: str) -> tuple[str, ...]:
    return tuple(item for item in normalize_key(value).split("_") if item)


def separator_key(value: str | None) -> str:
    return normalize_key(value).replace("_", "")


def strip_suffix(value: str | None, suffixes: frozenset[str]) -> str:
    tokens = list(_tokens(value or ""))
    if len(tokens) >= 2 and tokens[-1] in suffixes:
        tokens.pop()
    return "_".join(tokens)


def acronym_key(value: str | None) -> str:
    tokens = _tokens(value or "")
    if len(tokens) < 2:
        return ""
    return "".join(item[0] for item in tokens if item)


def digit_signature(value: str | None) -> str:
    values = sorted(re.findall(r"\d+", normalize_key(value)))
    return canonical_json(values)


def _compact_typo_key(value: str | None) -> str:
    """Return the separator-insensitive string used only by the B3 funnel."""

    return "".join(
        character
        for character in normalize_key(value)
        if character.isalnum()
    )


def _exactly_one_edit_apart(left: str, right: str) -> bool:
    """Recognize one substitution, insertion or deletion (no transposition)."""

    if left == right or abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) == 1
    shorter, longer = (left, right) if len(left) < len(right) else (right, left)
    short_index = long_index = edits = 0
    while short_index < len(shorter) and long_index < len(longer):
        if shorter[short_index] == longer[long_index]:
            short_index += 1
            long_index += 1
            continue
        edits += 1
        if edits > 1:
            return False
        long_index += 1
    return True


def _bigram_jaccard(left: str, right: str) -> float:
    def grams(value: str) -> set[str]:
        if len(value) < 2:
            return {value} if value else set()
        return {value[index : index + 2] for index in range(len(value) - 1)}

    left_grams, right_grams = grams(left), grams(right)
    union = left_grams | right_grams
    return 1.0 if not union else len(left_grams & right_grams) / len(union)


def _lcs_ratio(left: str, right: str) -> float:
    """Return LCS/max-length with O(min(length)) memory."""

    if not left and not right:
        return 1.0
    if len(left) < len(right):
        left, right = right, left
    previous = [0] * (len(right) + 1)
    for left_character in left:
        current = [0]
        for index, right_character in enumerate(right, start=1):
            if left_character == right_character:
                current.append(previous[index - 1] + 1)
            else:
                current.append(max(previous[index], current[-1]))
        previous = current
    return previous[-1] / max(len(left), len(right))


def _single_edit_candidate_pairs(
    compact_by_node: Mapping[int, str],
) -> tuple[set[tuple[int, int]], int]:
    """Generate one-edit candidates through deletion signatures.

    Large signatures are skipped rather than expanded into an O(n²) clique.
    They cannot yield an automatic B3 merge, but the pre-existing B2 review
    path remains available.
    """

    buckets: dict[str, set[int]] = defaultdict(set)
    for node_id, compact in compact_by_node.items():
        signatures = {compact}
        signatures.update(
            compact[:index] + compact[index + 1 :]
            for index in range(len(compact))
        )
        for signature in signatures:
            buckets[signature].add(node_id)
    pairs: set[tuple[int, int]] = set()
    skipped = 0
    for nodes in buckets.values():
        if len(nodes) > IDENTITY_ALIAS_BUCKET_SIZE_LIMIT:
            skipped += 1
            continue
        ordered = sorted(nodes)
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                pairs.add((left, right))
    return pairs, skipped


def token_multiset(value: str | None) -> str:
    return canonical_json(sorted(_tokens(value or "")))


def derived_keys(value: str | None) -> dict[str, str]:
    safe = normalize_key(value)
    keys = {
        "safe": safe,
        "separator": separator_key(safe),
        "legal_root": strip_suffix(safe, LEGAL_SUFFIXES),
        "org_root": strip_suffix(safe, ORG_SUFFIXES),
        "acronym": acronym_key(safe),
        "digit_signature": digit_signature(safe),
        "token_multiset": token_multiset(safe),
    }
    return {name: key for name, key in keys.items() if key != ""}


def _legacy_rewrite(identity: tuple[str, str]) -> tuple[str, str]:
    vendor, product = identity
    policy = P1_PRODUCT_KEY_REWRITES.get(vendor)
    if policy is None:
        return identity
    for source, target in policy["prefixes"].items():
        if product.startswith(source):
            product = target + product[len(source) :]
            break
    for suffix in policy["suffixes"]:
        if product.endswith(suffix):
            product = product[: -len(suffix)]
            break
    return vendor, product


def _contains_generic_anchor(value: str) -> bool:
    tokens = set(_tokens(value))
    return bool(tokens.intersection(HARD_GENERIC_ANCHORS)) or normalize_key(value) in SOFT_GENERIC_ANCHORS


def _self_brand_relation(vendor: str, product: str) -> str | None:
    """Describe a deterministic vendor-name/product-name brand relation."""

    vendor_key = normalize_key(vendor)
    product_key = normalize_key(product)
    if vendor_key == product_key:
        return "exact"
    if separator_key(vendor_key) == separator_key(product_key):
        return "separator"
    for suffixes, relation in (
        (LEGAL_SUFFIXES, "legal_root"),
        (ORG_SUFFIXES, "org_root"),
    ):
        root = strip_suffix(vendor_key, suffixes)
        if (
            root
            and root != vendor_key
            and separator_key(root) == separator_key(product_key)
        ):
            return relation
    return None


def _identity_version_token(value: Any) -> str | None:
    if value is None:
        return None
    token = str(value).strip().casefold()
    if token in {"", "*", "-", "0", "n/a", "unknown", "unspecified"}:
        return None
    return token


def _guard_alias_bucket_size(
    *, scope: str, key: str, member_count: int
) -> None:
    """Fail atomically instead of materializing an unbounded alias clique."""

    if member_count > IDENTITY_ALIAS_BUCKET_SIZE_LIMIT:
        raise RuntimeError(
            "identity alias collision bucket exceeds safety limit: "
            f"scope={scope!r}, key={key!r}, members={member_count}, "
            f"limit={IDENTITY_ALIAS_BUCKET_SIZE_LIMIT}"
        )


class _UnionFind:
    def __init__(self, values: Iterable[int]) -> None:
        self.parent = {value: value for value in values}
        self.rank = {value: 0 for value in values}

    def find(self, value: int) -> int:
        root = value
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[value] != value:
            parent = self.parent[value]
            self.parent[value] = root
            value = parent
        return root

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root == right_root:
            return
        if self.rank[left_root] < self.rank[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1


def _node_key(scope: str, vendor: str, product: str | None, part: str | None) -> str:
    if scope == "vendor":
        return f"vendor|{vendor}"
    return f"product|{vendor}|{product or ''}|{part or 'unknown'}"


def _ensure_node(
    connection: sqlite3.Connection,
    *,
    scope: str,
    vendor_key: str,
    product_key: str | None = None,
    part: str | None = None,
    product_id: int | None = None,
) -> int:
    key = _node_key(scope, vendor_key, product_key, part)
    connection.execute(
        """INSERT OR IGNORE INTO identity_node(
               node_key,scope_kind,vendor_key,product_key,part,product_id
           ) VALUES (?,?,?,?,?,?)""",
        (key, scope, vendor_key, product_key, part, product_id),
    )
    row = connection.execute(
        "SELECT node_id FROM identity_node WHERE node_key=?", (key,)
    ).fetchone()
    assert row is not None
    return int(row[0])


def _add_key(
    connection: sqlite3.Connection,
    *,
    node_id: int,
    key_kind: str,
    key_value: str,
    origin: str,
    source_alias_id: int = 0,
) -> None:
    if not key_value:
        return
    connection.execute(
        """INSERT OR IGNORE INTO identity_key(
               node_id,key_kind,key_value,origin,source_alias_id,derivation_rule
           ) VALUES (?,?,?,?,?,?)""",
        (
            node_id,
            key_kind,
            key_value,
            origin,
            source_alias_id,
            f"identity-3.3.1:{key_kind}",
        ),
    )


def _basis_parts(value: Any) -> tuple[list[dict[str, Any]], int, bool]:
    """Decode current and legacy edge evidence without recursive traversal."""

    if (
        isinstance(value, Mapping)
        and value.get("format") == _EDGE_EVIDENCE_FORMAT
        and isinstance(value.get("evidence"), list)
    ):
        raw_examples = list(value["evidence"])
        examples = [
            dict(item) if isinstance(item, Mapping) else {"value": item}
            for item in raw_examples[:_MAX_EDGE_EVIDENCE_EXAMPLES]
        ]
        raw_count = value.get("evidence_count")
        count = (
            int(raw_count)
            if isinstance(raw_count, int) and not isinstance(raw_count, bool)
            else len(raw_examples)
        )
        count = max(count, len(raw_examples))
        truncated = bool(value.get("evidence_truncated")) or (
            len(raw_examples) > len(examples)
        )
        return examples, count, truncated

    # v3.3.1-identity-alias.2 stored {"evidence": [old, new]} and nested
    # the complete previous object on every update. Flatten that legacy shape
    # iteratively so even an imported deeply nested value cannot consume the
    # Python call stack.
    stack = [value]
    examples: list[dict[str, Any]] = []
    seen: set[str] = set()
    count = 0
    truncated = False
    while stack:
        current = stack.pop()
        if (
            isinstance(current, Mapping)
            and isinstance(current.get("evidence"), list)
        ):
            stack.extend(reversed(list(current["evidence"])))
            continue
        normalized = (
            dict(current)
            if isinstance(current, Mapping)
            else {"value": current}
        )
        count += 1
        fingerprint = canonical_json(normalized)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        if len(examples) < _MAX_EDGE_EVIDENCE_EXAMPLES:
            examples.append(normalized)
        else:
            truncated = True
    return examples, count, truncated


def _merge_basis(existing: Any | None, incoming: Mapping[str, Any]) -> dict[str, Any]:
    """Return a fixed-depth, size-bounded evidence envelope."""

    old_examples, old_count, old_truncated = (
        _basis_parts(existing) if existing is not None else ([], 0, False)
    )
    new_examples, new_count, new_truncated = _basis_parts(dict(incoming))
    examples: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in (*old_examples, *new_examples):
        fingerprint = canonical_json(item)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        if len(examples) < _MAX_EDGE_EVIDENCE_EXAMPLES:
            examples.append(item)
    total_count = old_count + new_count
    return {
        "format": _EDGE_EVIDENCE_FORMAT,
        "evidence_count": total_count,
        "evidence_examples_limit": _MAX_EDGE_EVIDENCE_EXAMPLES,
        "evidence_truncated": (
            old_truncated
            or new_truncated
            or total_count > len(examples)
        ),
        "evidence": examples,
    }


def _edge(
    connection: sqlite3.Connection,
    *,
    left: int,
    right: int,
    alias_class: str,
    evidence_tier: str,
    status: str,
    strict_eligible: bool,
    basis: Mapping[str, Any],
    corroboration: str = "none",
) -> int | None:
    if left == right or alias_class not in ALIAS_CLASSES:
        return None
    left, right = sorted((left, right))
    existing = connection.execute(
        """SELECT * FROM identity_alias_edge
           WHERE left_node_id=? AND right_node_id=? AND alias_class=?
             AND registry_version=?""",
        (left, right, alias_class, IDENTITY_REGISTRY_VERSION),
    ).fetchone()
    if existing is None:
        cursor = connection.execute(
            """INSERT INTO identity_alias_edge(
                   left_node_id,right_node_id,alias_class,evidence_tier,
                   corroboration_independence,status,strict_eligible,basis_json,
                   registry_version,rule_version
               ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                left,
                right,
                alias_class,
                evidence_tier,
                corroboration,
                status,
                int(strict_eligible),
                canonical_json(_merge_basis(None, basis)),
                IDENTITY_REGISTRY_VERSION,
                RULE_VERSION,
            ),
        )
        return int(cursor.lastrowid)

    edge_id = int(existing["edge_id"])
    if str(existing["status"]) in {"rejected", "superseded"}:
        return edge_id
    status_rank = {
        "accepted": 0,
        "provisional": 1,
        "candidate": 2,
        "rejected": 3,
        "superseded": 4,
    }
    tier_rank = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4}
    existing_status = str(existing["status"])
    selected_status = min(
        (existing_status, status), key=lambda item: status_rank.get(item, 99)
    )
    existing_tier = str(existing["evidence_tier"])
    selected_tier = min(
        (existing_tier, evidence_tier), key=lambda item: tier_rank.get(item, 99)
    )
    selected_strict = bool(existing["strict_eligible"]) or bool(strict_eligible)
    try:
        existing_basis = json.loads(str(existing["basis_json"]))
    except (json.JSONDecodeError, RecursionError):
        existing_basis = {"raw": str(existing["basis_json"])}
    selected_basis = _merge_basis(existing_basis, basis)
    selected_corroboration = (
        "independent"
        if "independent" in {str(existing["corroboration_independence"]), corroboration}
        else "single_source"
        if "single_source" in {str(existing["corroboration_independence"]), corroboration}
        else "none"
    )
    connection.execute(
        """UPDATE identity_alias_edge
           SET evidence_tier=?,corroboration_independence=?,status=?,
               strict_eligible=?,basis_json=?,rule_version=?
           WHERE edge_id=?""",
        (
            selected_tier,
            selected_corroboration,
            selected_status,
            int(selected_strict and selected_status == "accepted"),
            canonical_json(selected_basis),
            RULE_VERSION,
            edge_id,
        ),
    )
    return edge_id


def _registry_nodes(
    connection: sqlite3.Connection,
    endpoint: Mapping[str, Any],
    *,
    scope: str,
) -> list[int]:
    vendor = normalize_key(endpoint.get("vendor"))
    if scope == "vendor":
        rows = connection.execute(
            "SELECT node_id FROM identity_node WHERE scope_kind='vendor' AND vendor_key=?",
            (vendor,),
        )
        return [int(row[0]) for row in rows]
    product = normalize_key(endpoint.get("product"))
    part = str(endpoint.get("part") or "*")
    sql = """SELECT node_id FROM identity_node
             WHERE scope_kind='product' AND vendor_key=? AND product_key=?"""
    params: list[Any] = [vendor, product]
    if part != "*":
        sql += " AND part IN (?, 'unknown')"
        params.append(part)
    return [int(row[0]) for row in connection.execute(sql, tuple(params))]


def _node_part(connection: sqlite3.Connection, node_id: int) -> str | None:
    row = connection.execute(
        "SELECT part FROM identity_node WHERE node_id=?", (node_id,)
    ).fetchone()
    return None if row is None or row[0] is None else str(row[0])


def _alias_nodes_compatible(
    connection: sqlite3.Connection, left: int, right: int, scope: str
) -> bool:
    if scope == "vendor":
        return True
    left_part, right_part = _node_part(connection, left), _node_part(connection, right)
    return left_part == right_part or "unknown" in {left_part, right_part}


def _registry_alias_keys(
    connection: sqlite3.Connection,
    *,
    target_nodes: Sequence[int],
    endpoint: Mapping[str, Any],
    scope: str,
    strict_eligible: bool,
) -> None:
    raw = endpoint.get("vendor") if scope == "vendor" else endpoint.get("product")
    origin = "registry_strict" if strict_eligible else "registry_non_strict"
    for node_id in target_nodes:
        for kind, value in derived_keys(None if raw is None else str(raw)).items():
            if kind not in {"safe", "separator"}:
                continue
            _add_key(
                connection, node_id=node_id, key_kind=kind, key_value=value, origin=origin
            )


def _insert_registry(connection: sqlite3.Connection) -> dict[str, int]:
    counters: dict[str, int] = defaultdict(int)
    for item in IDENTITY_REGISTRY.get("hard_distinct", []):
        scope = str(item.get("scope"))
        left_nodes = _registry_nodes(connection, item.get("left", {}), scope=scope)
        right_nodes = _registry_nodes(connection, item.get("right", {}), scope=scope)
        for left in left_nodes:
            for right in right_nodes:
                if left == right:
                    continue
                a, b = sorted((left, right))
                connection.execute(
                    """INSERT OR IGNORE INTO identity_hard_distinct(
                           left_node_id,right_node_id,basis,rule_version
                       ) VALUES (?,?,?,?)""",
                    (a, b, str(item.get("basis") or "registry"), RULE_VERSION),
                )
                counters["hard_distinct"] += 1
    for item in IDENTITY_REGISTRY.get("aliases", []):
        scope = str(item.get("scope"))
        left_endpoint = item.get("left", {})
        right_endpoint = item.get("right", {})
        left_nodes = _registry_nodes(connection, left_endpoint, scope=scope)
        right_nodes = _registry_nodes(connection, right_endpoint, scope=scope)
        strict_eligible = bool(item.get("strict_eligible"))
        _registry_alias_keys(
            connection, target_nodes=right_nodes, endpoint=left_endpoint,
            scope=scope, strict_eligible=strict_eligible
        )
        _registry_alias_keys(
            connection, target_nodes=left_nodes, endpoint=right_endpoint,
            scope=scope, strict_eligible=strict_eligible
        )
        for left in left_nodes:
            for right in right_nodes:
                if not _alias_nodes_compatible(connection, left, right, scope):
                    continue
                edge_id = _edge(
                    connection,
                    left=left,
                    right=right,
                    alias_class=str(item.get("alias_class")),
                    evidence_tier=str(item.get("evidence_tier") or "E0"),
                    status=str(item.get("status") or "candidate"),
                    strict_eligible=strict_eligible,
                    basis={
                        "kind": "adjudicated_registry",
                        "basis": item.get("basis"),
                        "registry_sha256": IDENTITY_REGISTRY_SHA256,
                    },
                    corroboration="single_source",
                )
                if edge_id is not None:
                    counters["registry_edges"] += 1
    return counters


def _auto_vendor_edges(connection: sqlite3.Connection) -> dict[str, int]:
    counters: dict[str, int] = defaultdict(int)
    blocked_pairs = {
        (int(row["left_node_id"]), int(row["right_node_id"]))
        for row in connection.execute(
            "SELECT left_node_id,right_node_id FROM identity_hard_distinct"
        )
    }
    groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    rows = connection.execute(
        """SELECT n.node_id,n.vendor_key,k.key_value AS separator
           FROM identity_node n
           JOIN identity_key k USING(node_id)
           WHERE n.scope_kind='vendor' AND k.key_kind='separator'
             AND k.origin='canonical_entity'"""
    )
    for row in rows:
        key = str(row["separator"])
        groups[(key, digit_signature(str(row["vendor_key"])))].append(int(row["node_id"]))
    for (key, _digits), nodes in sorted(groups.items()):
        unique = sorted(set(nodes))
        if len(unique) < 2 or len(key) < 3:
            continue
        _guard_alias_bucket_size(
            scope="vendor",
            key=key,
            member_count=len(unique),
        )
        status = "accepted" if len(unique) == 2 else "provisional"
        for index, left in enumerate(unique):
            for right in unique[index + 1 :]:
                if tuple(sorted((left, right))) in blocked_pairs:
                    continue
                _edge(
                    connection,
                    left=left,
                    right=right,
                    alias_class="A1_SEPARATOR",
                    evidence_tier="E1",
                    status=status,
                    strict_eligible=status == "accepted",
                    basis={
                        "kind": "deterministic_separator_key",
                        "separator_key": key,
                        "collision_count": len(unique),
                    },
                )
                counters[f"vendor_a1_{status}"] += 1
    return counters


def _accepted_scope_components(
    connection: sqlite3.Connection,
    *,
    scope: str,
) -> tuple[dict[int, int], dict[int, set[int]], set[int]]:
    """Describe the accepted graph before adding a semantic B3 edge."""

    nodes = [
        int(row["node_id"])
        for row in connection.execute(
            "SELECT node_id FROM identity_node WHERE scope_kind=?",
            (scope,),
        )
    ]
    union_find = _UnionFind(nodes)
    accepted_edges = list(
        connection.execute(
            """SELECT e.left_node_id,e.right_node_id,e.alias_class
               FROM identity_alias_edge e
               JOIN identity_node l ON l.node_id=e.left_node_id
               JOIN identity_node r ON r.node_id=e.right_node_id
               WHERE e.status='accepted'
                 AND l.scope_kind=? AND r.scope_kind=?""",
            (scope, scope),
        )
    )
    for row in accepted_edges:
        union_find.union(int(row["left_node_id"]), int(row["right_node_id"]))
    root_by_node = {node: union_find.find(node) for node in nodes}
    members_by_root: dict[int, set[int]] = defaultdict(set)
    for node, root in root_by_node.items():
        members_by_root[root].add(node)
    semantic_roots = {
        root_by_node[int(row["left_node_id"])]
        for row in accepted_edges
        if str(row["alias_class"]) in {
            "B1_ACRONYM",
            "B2_BRAND_ALIAS",
            "B3_TYPO",
        }
    }
    return root_by_node, members_by_root, semantic_roots


def _component_pair_is_safe(
    *,
    left_root: int,
    right_root: int,
    members_by_root: Mapping[int, set[int]],
    semantic_roots: set[int],
    blocked_by_node: Mapping[int, set[int]],
) -> bool:
    """Prevent B3 chaining, hard-distinct crossings and oversized clusters."""

    if left_root == right_root:
        return False
    if left_root in semantic_roots or right_root in semantic_roots:
        return False
    left_members = members_by_root[left_root]
    right_members = members_by_root[right_root]
    if len(left_members) + len(right_members) > IDENTITY_CLUSTER_SIZE_LIMIT:
        return False
    return not any(
        blocked_by_node.get(node, set()) & right_members
        for node in left_members
    )


def _mutually_unique_component_pairs(
    candidates: Mapping[tuple[int, int], Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    neighbors: dict[int, set[int]] = defaultdict(set)
    for left_root, right_root in candidates:
        neighbors[left_root].add(right_root)
        neighbors[right_root].add(left_root)
    return [
        candidate
        for (left_root, right_root), candidate in sorted(candidates.items())
        if len(neighbors[left_root]) == 1 and len(neighbors[right_root]) == 1
    ]


def _auto_vendor_typo_edges(connection: sqlite3.Connection) -> dict[str, int]:
    """Accept only mutually unique one-edit vendors with shared products."""

    policy = IDENTITY_TYPO_POLICY["vendor"]
    rows = list(
        connection.execute(
            """SELECT node_id,vendor_key
               FROM identity_node
               WHERE scope_kind='vendor'
               ORDER BY node_id"""
        )
    )
    vendor_by_node = {
        int(row["node_id"]): str(row["vendor_key"])
        for row in rows
    }
    compact_by_node = {
        node_id: _compact_typo_key(vendor)
        for node_id, vendor in vendor_by_node.items()
    }
    generated_pairs, skipped_buckets = _single_edit_candidate_pairs(
        compact_by_node
    )
    product_identities_by_vendor: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for row in connection.execute(
        """SELECT vendor_key,product_key,part
           FROM product_entity
           ORDER BY vendor_key,product_key,part"""
    ):
        product_key = str(row["product_key"])
        if _contains_generic_anchor(product_key):
            continue
        product_identities_by_vendor[str(row["vendor_key"])].add(
            (product_key, str(row["part"]))
        )

    root_by_node, members_by_root, semantic_roots = (
        _accepted_scope_components(connection, scope="vendor")
    )
    blocked_by_node: dict[int, set[int]] = defaultdict(set)
    for row in connection.execute(
        "SELECT left_node_id,right_node_id FROM identity_hard_distinct"
    ):
        left, right = int(row["left_node_id"]), int(row["right_node_id"])
        blocked_by_node[left].add(right)
        blocked_by_node[right].add(left)

    component_candidates: dict[tuple[int, int], Mapping[str, Any]] = {}
    for left, right in sorted(generated_pairs):
        left_compact, right_compact = compact_by_node[left], compact_by_node[right]
        if min(len(left_compact), len(right_compact)) < int(
            policy["min_compact_length"]
        ):
            continue
        if digit_signature(left_compact) != digit_signature(right_compact):
            continue
        if not _exactly_one_edit_apart(left_compact, right_compact):
            continue
        jaccard = _bigram_jaccard(left_compact, right_compact)
        lcs = _lcs_ratio(left_compact, right_compact)
        if jaccard < float(policy["min_bigram_jaccard"]):
            continue
        if lcs < float(policy["min_lcs_ratio"]):
            continue
        left_vendor, right_vendor = vendor_by_node[left], vendor_by_node[right]
        shared_products = (
            product_identities_by_vendor[left_vendor]
            & product_identities_by_vendor[right_vendor]
        )
        if len(shared_products) < int(policy["min_shared_product_identities"]):
            continue
        left_root, right_root = root_by_node[left], root_by_node[right]
        if not _component_pair_is_safe(
            left_root=left_root,
            right_root=right_root,
            members_by_root=members_by_root,
            semantic_roots=semantic_roots,
            blocked_by_node=blocked_by_node,
        ):
            continue
        root_pair = tuple(sorted((left_root, right_root)))
        candidate = {
            "left": left,
            "right": right,
            "left_key": left_vendor,
            "right_key": right_vendor,
            "left_root": root_pair[0],
            "right_root": root_pair[1],
            "jaccard": jaccard,
            "lcs": lcs,
            "shared_products": sorted(shared_products),
        }
        previous = component_candidates.get(root_pair)
        if previous is None or (
            len(shared_products),
            jaccard,
            lcs,
            -left,
            -right,
        ) > (
            len(previous["shared_products"]),
            float(previous["jaccard"]),
            float(previous["lcs"]),
            -int(previous["left"]),
            -int(previous["right"]),
        ):
            component_candidates[root_pair] = candidate

    accepted = _mutually_unique_component_pairs(component_candidates)
    for candidate in accepted:
        _edge(
            connection,
            left=int(candidate["left"]),
            right=int(candidate["right"]),
            alias_class="B3_TYPO",
            evidence_tier="E1",
            status="accepted",
            strict_eligible=True,
            corroboration="single_source",
            basis={
                "kind": "validated_vendor_typo",
                "left_key": candidate["left_key"],
                "right_key": candidate["right_key"],
                "compact_edit_distance": 1,
                "bigram_jaccard": round(float(candidate["jaccard"]), 6),
                "lcs_ratio": round(float(candidate["lcs"]), 6),
                "shared_product_identity_count": len(
                    candidate["shared_products"]
                ),
                "shared_product_identity_examples": list(
                    candidate["shared_products"]
                )[:10],
                "policy": policy,
                "guards": IDENTITY_TYPO_POLICY["common_guards"],
            },
        )
    return {
        "vendor_b3_typo_accepted": len(accepted),
        "vendor_b3_typo_qualified": len(component_candidates),
        "vendor_b3_typo_ambiguous": len(component_candidates) - len(accepted),
        "vendor_b3_typo_buckets_skipped": skipped_buckets,
    }


def _build_clusters(connection: sqlite3.Connection, *, scope: str) -> dict[str, Any]:
    node_rows = list(
        connection.execute(
            """SELECT node_id,product_id
               FROM identity_node
               WHERE scope_kind=?
               ORDER BY node_id""",
            (scope,),
        )
    )
    nodes = [int(row["node_id"]) for row in node_rows]
    product_id_by_node = {
        int(row["node_id"]): (
            None if row["product_id"] is None else int(row["product_id"])
        )
        for row in node_rows
    }
    uf = _UnionFind(nodes)
    blocked_pairs = {
        (int(row["left_node_id"]), int(row["right_node_id"]))
        for row in connection.execute(
            "SELECT left_node_id,right_node_id FROM identity_hard_distinct"
        )
    }
    blocked_by_node: dict[int, set[int]] = defaultdict(set)
    for left, right in blocked_pairs:
        blocked_by_node[left].add(right)
        blocked_by_node[right].add(left)
    accepted_edges: list[sqlite3.Row] = []
    for row in connection.execute(
        """SELECT e.* FROM identity_alias_edge e
           JOIN identity_node l ON l.node_id=e.left_node_id
           JOIN identity_node r ON r.node_id=e.right_node_id
           WHERE e.status='accepted' AND l.scope_kind=? AND r.scope_kind=?
           ORDER BY e.left_node_id,e.right_node_id,e.alias_class""",
        (scope, scope),
    ):
        left, right = int(row["left_node_id"]), int(row["right_node_id"])
        if tuple(sorted((left, right))) in blocked_pairs:
            continue
        accepted_edges.append(row)
        uf.union(left, right)
    groups: dict[int, list[int]] = defaultdict(list)
    for node in nodes:
        groups[uf.find(node)].append(node)
    edges_by_root: dict[int, list[sqlite3.Row]] = defaultdict(list)
    for row in accepted_edges:
        left = int(row["left_node_id"])
        right = int(row["right_node_id"])
        root = uf.find(left)
        if root == uf.find(right):
            edges_by_root[root].append(row)
    cluster_map: dict[int, int] = {}
    cluster_rows: list[dict[str, Any]] = []
    ordered_groups = sorted(
        ((root, sorted(values)) for root, values in groups.items()),
        key=lambda item: item[1][0],
    )
    for root, members in ordered_groups:
        canonical = members[0]
        member_set = set(members)
        hard_conflict = any(
            blocked_by_node.get(node, set()) & member_set
            for node in members
        )
        member_edges = edges_by_root.get(root, [])
        semantic_edges = [
            row for row in member_edges
            if str(row["alias_class"]) in {"B1_ACRONYM", "B2_BRAND_ALIAS", "B3_TYPO"}
        ]
        semantic_anchor_ok = True
        if len(semantic_edges) > 1:
            shared = set(
                (int(semantic_edges[0]["left_node_id"]),
                 int(semantic_edges[0]["right_node_id"]))
            )
            for row in semantic_edges[1:]:
                shared.intersection_update(
                    {int(row["left_node_id"]), int(row["right_node_id"])}
                )
            semantic_anchor_ok = bool(shared)
        review = (
            hard_conflict
            or len(members) > IDENTITY_CLUSTER_SIZE_LIMIT
            or not semantic_anchor_ok
        )
        max_tier = "T0_EXACT"
        strict = not review
        for row in member_edges:
            edge_tier = (
                "T1_FORMAT"
                if str(row["alias_class"]) in {"A1_SEPARATOR", "A2_LEGAL_SUFFIX"}
                else "T2_REGISTRY"
            )
            if TIER_RANK[edge_tier] > TIER_RANK[max_tier]:
                max_tier = edge_tier
            strict = strict and bool(row["strict_eligible"])
        digest = stable_hash(
            {
                "scope": scope,
                "members": members,
                "edges": [int(row["edge_id"]) for row in member_edges],
                "registry": IDENTITY_REGISTRY_SHA256,
                "rule": RULE_VERSION,
            }
        )
        cursor = connection.execute(
            """INSERT INTO identity_cluster(
                   scope_kind,canonical_node_id,member_count,max_tier,
                   strict_eligible,review_state,cluster_digest
               ) VALUES (?,?,?,?,?,?,?)""",
            (
                scope,
                canonical,
                len(members),
                max_tier,
                int(strict),
                "cluster_review" if review else "ok",
                digest,
            ),
        )
        cluster_id = int(cursor.lastrowid)
        for node in members:
            cluster_map[node] = cluster_id
        connection.executemany(
            """INSERT INTO identity_cluster_member(
                   cluster_id,node_id,product_id,join_tier,strict_eligible
               ) VALUES (?,?,?,?,?)""",
            (
                (
                    cluster_id,
                    node,
                    product_id_by_node[node],
                    "T0_EXACT" if node == canonical else max_tier,
                    int(strict if node != canonical else not review),
                )
                for node in members
            ),
        )
        connection.executemany(
            """INSERT OR IGNORE INTO identity_cluster_edge(cluster_id,edge_id)
               VALUES (?,?)""",
            (
                (cluster_id, int(row["edge_id"]))
                for row in member_edges
            ),
        )
        cluster_rows.append(
            {
                "cluster_id": cluster_id,
                "members": members,
                "review": review,
                "strict": strict,
                "digest": digest,
            }
        )
    return {
        "cluster_map": cluster_map,
        "clusters": len(groups),
        "review_clusters": sum(bool(item["review"]) for item in cluster_rows),
        "digest": stable_hash([item["digest"] for item in cluster_rows]),
    }


def _compatible_parts(left: str, right: str) -> bool:
    return left == right or "unknown" in {left, right}


def _auto_product_edges(
    connection: sqlite3.Connection,
    vendor_cluster_map: Mapping[int, int],
) -> dict[str, int]:
    counters: dict[str, int] = defaultdict(int)
    blocked_pairs = {
        (int(row["left_node_id"]), int(row["right_node_id"]))
        for row in connection.execute(
            "SELECT left_node_id,right_node_id FROM identity_hard_distinct"
        )
    }
    vendor_node_by_key = {
        str(row["vendor_key"]): int(row["node_id"])
        for row in connection.execute(
            "SELECT node_id,vendor_key FROM identity_node WHERE scope_kind='vendor'"
        )
    }
    rows = list(
        connection.execute(
            """SELECT n.node_id,n.vendor_key,n.product_key,n.part,
                      sep.key_value AS separator,
                      legal.key_value AS legal_root,
                      org.key_value AS org_root,
                      acr.key_value AS acronym
               FROM identity_node n
               JOIN identity_key sep ON sep.node_id=n.node_id AND sep.key_kind='separator'
                    AND sep.origin='canonical_entity'
               LEFT JOIN identity_key legal ON legal.node_id=n.node_id
                    AND legal.key_kind='legal_root' AND legal.origin='canonical_entity'
               LEFT JOIN identity_key org ON org.node_id=n.node_id
                    AND org.key_kind='org_root' AND org.origin='canonical_entity'
               LEFT JOIN identity_key acr ON acr.node_id=n.node_id
                    AND acr.key_kind='acronym' AND acr.origin='canonical_entity'
               WHERE n.scope_kind='product'"""
        )
    )
    by_separator: dict[tuple[int, str, str], list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        vendor_node = vendor_node_by_key[str(row["vendor_key"])]
        vendor_cluster = vendor_cluster_map[vendor_node]
        by_separator[(vendor_cluster, str(row["separator"]), digit_signature(str(row["product_key"])))].append(row)
    for (vendor_cluster, key, _digits), values in sorted(by_separator.items()):
        if len(values) < 2 or len(key) < 3:
            continue
        _guard_alias_bucket_size(
            scope=f"product:vendor_cluster:{vendor_cluster}",
            key=key,
            member_count=len(values),
        )
        for index, left in enumerate(values):
            for right in values[index + 1 :]:
                if not _compatible_parts(str(left["part"]), str(right["part"])):
                    continue
                left_id, right_id = int(left["node_id"]), int(right["node_id"])
                if tuple(sorted((left_id, right_id))) in blocked_pairs:
                    continue
                collision_count = len(values)
                status = "accepted" if collision_count == 2 else "provisional"
                _edge(
                    connection,
                    left=left_id,
                    right=right_id,
                    alias_class="A1_SEPARATOR",
                    evidence_tier="E1",
                    status=status,
                    strict_eligible=status == "accepted",
                    basis={
                        "kind": "deterministic_separator_key",
                        "vendor_cluster": vendor_cluster,
                        "separator_key": key,
                        "collision_count": collision_count,
                    },
                )
                counters[f"product_a1_{status}"] += 1

    # Legacy Microsoft rewrites are migrated as explicit E0 aliases.
    by_rewrite: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for row in rows:
        vendor, product, part = str(row["vendor_key"]), str(row["product_key"]), str(row["part"])
        rewritten = _legacy_rewrite((vendor, product))
        by_rewrite[(rewritten[0], rewritten[1], part)].append(int(row["node_id"]))
    for key, nodes in by_rewrite.items():
        unique = sorted(set(nodes))
        _guard_alias_bucket_size(
            scope="product:legacy_rewrite",
            key=canonical_json(key),
            member_count=len(unique),
        )
        for index, left in enumerate(unique):
            for right in unique[index + 1 :]:
                if tuple(sorted((left, right))) in blocked_pairs:
                    continue
                _edge(
                    connection,
                    left=left,
                    right=right,
                    alias_class="B2_BRAND_ALIAS",
                    evidence_tier="E0",
                    status="accepted",
                    strict_eligible=True,
                    basis={"kind": "migrated_v3_2_key_rewrite", "key": key},
                    corroboration="single_source",
                )
                counters["legacy_rewrite_accepted"] += 1

    # Non-deterministic roots and acronyms only create review candidates.
    by_scope_part: dict[tuple[int, str], list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        vendor_node = vendor_node_by_key[str(row["vendor_key"])]
        by_scope_part[(vendor_cluster_map[vendor_node], str(row["part"]))].append(row)
    for (vendor_cluster, part), values in by_scope_part.items():
        safe_map = {str(row["product_key"]): row for row in values}
        for row in values:
            node_id = int(row["node_id"])
            product_key = str(row["product_key"])
            if _contains_generic_anchor(product_key):
                continue
            for field, alias_class in (
                ("legal_root", "A2_LEGAL_SUFFIX"),
                ("org_root", "A3_ORG_SUFFIX"),
            ):
                root = row[field]
                if root is None or str(root) == product_key:
                    continue
                target = safe_map.get(str(root))
                if target is None:
                    continue
                _edge(
                    connection,
                    left=node_id,
                    right=int(target["node_id"]),
                    alias_class=alias_class,
                    evidence_tier="E4",
                    status="candidate",
                    strict_eligible=False,
                    basis={
                        "kind": "string_candidate",
                        "vendor_cluster": vendor_cluster,
                        "part": part,
                        "root": str(root),
                    },
                )
                counters[f"{alias_class.lower()}_candidate"] += 1
            acronym = str(row["acronym"] or "")
            if not acronym or acronym in SOFT_GENERIC_ANCHORS or acronym in HARD_GENERIC_ANCHORS:
                continue
            target = safe_map.get(acronym)
            if target is None:
                continue
            _edge(
                connection,
                left=node_id,
                right=int(target["node_id"]),
                alias_class="B1_ACRONYM",
                evidence_tier="E4",
                status="candidate",
                strict_eligible=False,
                basis={
                    "kind": "acronym_candidate",
                    "vendor_cluster": vendor_cluster,
                    "part": part,
                    "acronym": acronym,
                },
            )
            counters["b1_acronym_candidate"] += 1
    return counters


def _auto_self_brand_product_edges(
    connection: sqlite3.Connection,
) -> dict[str, int]:
    """Bridge owner-vendor and self-branded product namespaces safely.

    A product such as ``automattic:wordpress`` can be the same target as the
    self-branded CPE identity ``wordpress:wordpress``.  Exact name equality
    alone is insufficient because distributions and bundled components often
    reuse upstream product names.  Accepted edges therefore require a bounded,
    unique self-brand anchor, complementary NVD/CNA provenance, compatible
    application parts and at least three concrete version tokens in common.
    """

    counters: dict[str, int] = defaultdict(int)
    rows = [
        dict(row)
        for row in connection.execute(
            """SELECT n.node_id,n.vendor_key,n.product_key,n.part,n.product_id,
                      MAX(CASE WHEN a.source_family='nvd_cpe'
                               THEN 1 ELSE 0 END) AS has_nvd,
                      MAX(CASE WHEN a.source_family='cna_structured'
                               THEN 1 ELSE 0 END) AS has_cna
               FROM identity_node n
               LEFT JOIN product_alias a USING(product_id)
               WHERE n.scope_kind='product'
               GROUP BY n.node_id
               ORDER BY n.node_id"""
        )
    ]
    by_product_separator: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_product_separator[
            separator_key(str(row["product_key"]))
        ].append(row)

    distribution_keys = {
        separator_key(value) for value in DISTRIBUTION_VENDORS
    }
    preliminary: list[
        tuple[
            str,
            dict[str, Any],
            str,
            list[dict[str, Any]],
        ]
    ] = []
    for product_separator, values in sorted(by_product_separator.items()):
        if len(product_separator) < _SELF_BRAND_MIN_COMPACT_LENGTH:
            continue
        if len(values) < 2:
            continue
        if len(values) > IDENTITY_CLUSTER_SIZE_LIMIT:
            counters["self_brand_b2_oversized_buckets"] += 1
            continue
        if any(
            _contains_generic_anchor(str(row["product_key"]))
            for row in values
        ):
            counters["self_brand_b2_generic_buckets"] += 1
            continue

        anchors: list[tuple[dict[str, Any], str]] = []
        for row in values:
            relation = _self_brand_relation(
                str(row["vendor_key"]),
                str(row["product_key"]),
            )
            if (
                relation is not None
                and str(row["part"]) == "a"
                and bool(row["has_nvd"])
            ):
                anchors.append((row, relation))
        if len(anchors) != 1:
            if anchors:
                counters["self_brand_b2_ambiguous_anchors"] += 1
            continue
        anchor, anchor_relation = anchors[0]
        targets = [
            row
            for row in values
            if int(row["node_id"]) != int(anchor["node_id"])
            and str(row["vendor_key"]) != str(anchor["vendor_key"])
            and str(row["part"]) == "unknown"
            and bool(row["has_cna"])
            and not bool(row["has_nvd"])
            and separator_key(str(row["vendor_key"]))
            not in distribution_keys
        ]
        if not targets:
            continue
        preliminary.append(
            (
                product_separator,
                anchor,
                anchor_relation,
                targets,
            )
        )

    product_ids = sorted(
        {
            int(row["product_id"])
            for _key, anchor, _relation, targets in preliminary
            for row in (anchor, *targets)
        }
    )
    version_tokens: dict[int, set[str]] = defaultdict(set)
    for offset in range(0, len(product_ids), 800):
        batch = product_ids[offset : offset + 800]
        marks = ",".join("?" for _ in batch)
        for row in connection.execute(
            f"""SELECT product_id,version_raw,version_start_including,
                       version_start_excluding,version_end_including,
                       version_end_excluding
                FROM source_claim
                WHERE product_id IN ({marks})""",
            tuple(batch),
        ):
            product_id = int(row["product_id"])
            for column in (
                "version_raw",
                "version_start_including",
                "version_start_excluding",
                "version_end_including",
                "version_end_excluding",
            ):
                token = _identity_version_token(row[column])
                if token is not None:
                    version_tokens[product_id].add(token)

    root_by_node, members_by_root, semantic_roots = (
        _accepted_scope_components(connection, scope="product")
    )
    blocked_by_node: dict[int, set[int]] = defaultdict(set)
    for row in connection.execute(
        "SELECT left_node_id,right_node_id FROM identity_hard_distinct"
    ):
        left, right = int(row["left_node_id"]), int(row["right_node_id"])
        blocked_by_node[left].add(right)
        blocked_by_node[right].add(left)

    for product_separator, anchor, anchor_relation, targets in preliminary:
        anchor_node = int(anchor["node_id"])
        anchor_root = root_by_node[anchor_node]
        if anchor_root in semantic_roots:
            counters["self_brand_b2_semantic_chain_blocked"] += len(targets)
            continue
        combined_members = set(members_by_root[anchor_root])
        accepted_targets: list[
            tuple[dict[str, Any], int, set[str]]
        ] = []
        ranked_targets: list[
            tuple[int, int, dict[str, Any], int, set[str]]
        ] = []
        for target in targets:
            target_node = int(target["node_id"])
            target_root = root_by_node[target_node]
            if target_root == anchor_root or target_root in semantic_roots:
                counters["self_brand_b2_semantic_chain_blocked"] += 1
                continue
            shared_versions = (
                version_tokens[int(anchor["product_id"])]
                & version_tokens[int(target["product_id"])]
            )
            if len(shared_versions) < _SELF_BRAND_MIN_SHARED_VERSIONS:
                counters["self_brand_b2_version_evidence_rejected"] += 1
                continue
            ranked_targets.append(
                (
                    -len(shared_versions),
                    target_node,
                    target,
                    target_root,
                    shared_versions,
                )
            )
        for _negative_count, _target_node, target, target_root, shared in sorted(
            ranked_targets,
            key=lambda item: (item[0], item[1]),
        ):
            target_members = members_by_root[target_root]
            if len(combined_members | target_members) > IDENTITY_CLUSTER_SIZE_LIMIT:
                counters["self_brand_b2_cluster_limit_rejected"] += 1
                continue
            if any(
                blocked_by_node.get(node, set()) & target_members
                for node in combined_members
            ):
                counters["self_brand_b2_hard_distinct_rejected"] += 1
                continue
            accepted_targets.append((target, target_root, shared))
            combined_members.update(target_members)

        for target, _target_root, shared_versions in accepted_targets:
            product_match = (
                "exact"
                if str(anchor["product_key"]) == str(target["product_key"])
                else "separator"
            )
            edge_id = _edge(
                connection,
                left=anchor_node,
                right=int(target["node_id"]),
                alias_class="B2_BRAND_ALIAS",
                evidence_tier="E1" if product_match == "exact" else "E2",
                status="accepted",
                strict_eligible=True,
                corroboration="independent",
                basis={
                    "kind": "validated_self_brand_product_bridge",
                    "anchor_relation": anchor_relation,
                    "product_match": product_match,
                    "product_separator_key": product_separator,
                    "shared_version_token_count": len(shared_versions),
                    "shared_version_token_examples": sorted(
                        shared_versions
                    )[:10],
                    "anchor": {
                        "vendor_key": str(anchor["vendor_key"]),
                        "product_key": str(anchor["product_key"]),
                        "part": str(anchor["part"]),
                        "source_family": "nvd_cpe",
                    },
                    "target": {
                        "vendor_key": str(target["vendor_key"]),
                        "product_key": str(target["product_key"]),
                        "part": str(target["part"]),
                        "source_family": "cna_structured",
                    },
                    "guards": {
                        "unique_self_brand_anchor": True,
                        "bounded_product_bucket": True,
                        "application_to_unknown_part": True,
                        "complementary_source_families": True,
                        "distribution_vendor_excluded": True,
                        "generic_product_excluded": True,
                        "semantic_chaining": False,
                        "minimum_shared_version_tokens": (
                            _SELF_BRAND_MIN_SHARED_VERSIONS
                        ),
                    },
                },
            )
            if edge_id is not None:
                counters["self_brand_b2_accepted"] += 1
        if accepted_targets:
            counters["self_brand_b2_groups"] += 1
    counters["self_brand_b2_preliminary_groups"] = len(preliminary)
    return counters


def _mine_cna_cpe_candidates(
    connection: sqlite3.Connection,
    vendor_cluster_map: Mapping[int, int],
    *,
    progress: IdentityProgress | None = None,
) -> int:
    """Mine same-CVE CNA/NVD pairs as review candidates only.

    The candidate semantics are unchanged: every qualifying observation counts
    as E1 evidence and co-occurrence never becomes an accepted alias by itself.
    Evidence is accumulated by node pair first, however, so a pair observed in
    thousands of CVEs performs one bounded JSON merge/write rather than one
    merge/write per CVE.
    """

    vendor_node_by_key = {
        str(row["vendor_key"]): int(row["node_id"])
        for row in connection.execute(
            "SELECT node_id,vendor_key FROM identity_node WHERE scope_kind='vendor'"
        )
    }
    product_node_by_id = {
        int(row["product_id"]): int(row["node_id"])
        for row in connection.execute(
            """SELECT node_id,product_id FROM identity_node
               WHERE scope_kind='product' AND product_id IS NOT NULL"""
        )
    }
    blocked_pairs = {
        (int(row["left_node_id"]), int(row["right_node_id"]))
        for row in connection.execute(
            "SELECT left_node_id,right_node_id FROM identity_hard_distinct"
        )
    }
    existing_status_by_pair = {
        (int(row["left_node_id"]), int(row["right_node_id"])): str(row["status"])
        for row in connection.execute(
            """SELECT left_node_id,right_node_id,status
               FROM identity_alias_edge
               WHERE alias_class='B2_BRAND_ALIAS'
                 AND registry_version=?""",
            (IDENTITY_REGISTRY_VERSION,),
        )
    }
    nonwritable_pairs = {
        pair
        for pair, status in existing_status_by_pair.items()
        if status in {"rejected", "superseded"}
    }
    evidence_by_pair: dict[tuple[int, int], _CooccurrenceEvidence] = {}
    observation_count = 0
    cve_count = 0

    def flush(
        cve_id: str | None,
        sources: Mapping[str, set[int]],
        product_info: Mapping[int, tuple[str, str, str]],
    ) -> int:
        if cve_id is None:
            return 0
        observed = 0
        by_source_cluster: dict[
            str, dict[int, list[int]]
        ] = defaultdict(lambda: defaultdict(list))
        for source_family in ("cna_structured", "nvd_cpe"):
            for product_id in sources.get(source_family, set()):
                vendor, product, _part = product_info[product_id]
                if _contains_generic_anchor(product):
                    continue
                vendor_node = vendor_node_by_key[vendor]
                cluster_id = vendor_cluster_map[vendor_node]
                by_source_cluster[source_family][cluster_id].append(product_id)
        cna_clusters = by_source_cluster.get("cna_structured", {})
        nvd_clusters = by_source_cluster.get("nvd_cpe", {})
        for cluster_id in cna_clusters.keys() & nvd_clusters.keys():
            for left_product in cna_clusters[cluster_id]:
                for right_product in nvd_clusters[cluster_id]:
                    if left_product == right_product:
                        continue
                    _lv, _lp, lpart = product_info[left_product]
                    _rv, _rp, rpart = product_info[right_product]
                    if not _compatible_parts(lpart, rpart):
                        continue
                    left_node = product_node_by_id[left_product]
                    right_node = product_node_by_id[right_product]
                    pair = tuple(sorted((left_node, right_node)))
                    if pair in blocked_pairs or pair in nonwritable_pairs:
                        continue
                    accumulator = evidence_by_pair.get(pair)
                    if accumulator is None:
                        accumulator = _CooccurrenceEvidence()
                        evidence_by_pair[pair] = accumulator
                    accumulator.observe(cve_id)
                    observed += 1
        return observed

    cursor = connection.execute(
        """SELECT c.cve_id,c.source_family,c.product_id,
                      p.vendor_key,p.product_key,p.part
           FROM source_claim c
           JOIN product_entity p USING(product_id)
           WHERE c.source_family IN ('cna_structured','nvd_cpe')
             AND COALESCE(c.vulnerable_flag,1)=1
           ORDER BY c.cve_id,c.source_family,c.product_id"""
    )
    current_cve: str | None = None
    sources: dict[str, set[int]] = defaultdict(set)
    product_info: dict[int, tuple[str, str, str]] = {}
    for row in cursor:
        cve_id = str(row["cve_id"])
        if current_cve is not None and cve_id != current_cve:
            observation_count += flush(current_cve, sources, product_info)
            cve_count += 1
            if cve_count % _IDENTITY_PROGRESS_EVERY == 0:
                _report_identity_progress(
                    progress,
                    "cna_cpe_evidence_scan",
                    cves=cve_count,
                    evidence_observations=observation_count,
                    distinct_pairs=len(evidence_by_pair),
                )
            sources = defaultdict(set)
            product_info = {}
        current_cve = cve_id
        product_id = int(row["product_id"])
        sources[str(row["source_family"])].add(product_id)
        product_info[product_id] = (
            str(row["vendor_key"]),
            str(row["product_key"]),
            str(row["part"]),
        )
    if current_cve is not None:
        observation_count += flush(current_cve, sources, product_info)
        cve_count += 1

    _report_identity_progress(
        progress,
        "cna_cpe_evidence_aggregated",
        cves=cve_count,
        evidence_observations=observation_count,
        distinct_pairs=len(evidence_by_pair),
    )

    existing_pairs = set(existing_status_by_pair)
    pending: list[tuple[Any, ...]] = []
    written = 0
    reported_write_bucket = 0

    def report_writes() -> None:
        nonlocal reported_write_bucket
        bucket = written // _IDENTITY_PROGRESS_EVERY
        if bucket <= reported_write_bucket:
            return
        reported_write_bucket = bucket
        _report_identity_progress(
            progress,
            "cna_cpe_edge_write",
            written_pairs=written,
            total_pairs=len(evidence_by_pair),
            evidence_observations=observation_count,
        )

    def flush_pending() -> None:
        nonlocal written
        if not pending:
            return
        connection.executemany(
            """INSERT INTO identity_alias_edge(
                   left_node_id,right_node_id,alias_class,evidence_tier,
                   corroboration_independence,status,strict_eligible,basis_json,
                   registry_version,rule_version
               ) VALUES (?,?,'B2_BRAND_ALIAS','E1','single_source',
                         'candidate',0,?,?,?)""",
            pending,
        )
        written += len(pending)
        pending.clear()
        report_writes()

    for pair, evidence in sorted(evidence_by_pair.items()):
        envelope = evidence.envelope()
        if pair in existing_pairs:
            _edge(
                connection,
                left=pair[0],
                right=pair[1],
                alias_class="B2_BRAND_ALIAS",
                evidence_tier="E1",
                status="candidate",
                strict_eligible=False,
                basis=envelope,
                corroboration="single_source",
            )
            written += 1
            report_writes()
        else:
            pending.append(
                (
                    pair[0],
                    pair[1],
                    canonical_json(envelope),
                    IDENTITY_REGISTRY_VERSION,
                    RULE_VERSION,
                )
            )
            if len(pending) >= _EDGE_INSERT_BATCH_SIZE:
                flush_pending()
    flush_pending()
    _report_identity_progress(
        progress,
        "cna_cpe_edge_write_complete",
        written_pairs=written,
        evidence_observations=observation_count,
    )
    return observation_count


def _promote_product_typo_edges(
    connection: sqlite3.Connection,
) -> dict[str, int]:
    """Promote a tiny, guarded subset of B2 review evidence to B3.

    The existing B2 edge is retained unchanged.  B3 acceptance additionally
    requires a one-character edit, high Jaccard/LCS similarity, identical
    numeric identity, mutually exclusive CNA/NVD provenance, at least three
    CVEs, compatible application parts and a unique safe component match.
    """

    policy = IDENTITY_TYPO_POLICY["product"]
    product_by_node = {
        int(row["node_id"]): {
            "vendor_key": str(row["vendor_key"]),
            "product_key": str(row["product_key"]),
            "part": str(row["part"]),
        }
        for row in connection.execute(
            """SELECT node_id,vendor_key,product_key,part
               FROM identity_node
               WHERE scope_kind='product'"""
        )
    }
    source_families_by_node: dict[int, set[str]] = defaultdict(set)
    for row in connection.execute(
        """SELECT n.node_id,c.source_family
           FROM identity_node n
           JOIN source_claim c USING(product_id)
           WHERE n.scope_kind='product'
             AND c.source_family IN ('cna_structured','nvd_cpe')
             AND COALESCE(c.vulnerable_flag,1)=1
           GROUP BY n.node_id,c.source_family"""
    ):
        source_families_by_node[int(row["node_id"])].add(
            str(row["source_family"])
        )

    root_by_node, members_by_root, semantic_roots = (
        _accepted_scope_components(connection, scope="product")
    )
    blocked_by_node: dict[int, set[int]] = defaultdict(set)
    for row in connection.execute(
        "SELECT left_node_id,right_node_id FROM identity_hard_distinct"
    ):
        left, right = int(row["left_node_id"]), int(row["right_node_id"])
        blocked_by_node[left].add(right)
        blocked_by_node[right].add(left)

    component_candidates: dict[tuple[int, int], Mapping[str, Any]] = {}
    structurally_qualified = 0
    candidate_rows = connection.execute(
        """SELECT e.edge_id,e.left_node_id,e.right_node_id
           FROM identity_alias_edge e
           JOIN identity_node l ON l.node_id=e.left_node_id
           JOIN identity_node r ON r.node_id=e.right_node_id
           WHERE e.alias_class='B2_BRAND_ALIAS'
             AND e.status='candidate'
             AND l.scope_kind='product' AND r.scope_kind='product'
           ORDER BY e.edge_id"""
    )
    for row in candidate_rows:
        edge_id = int(row["edge_id"])
        left, right = int(row["left_node_id"]), int(row["right_node_id"])
        left_product = product_by_node[left]
        right_product = product_by_node[right]
        left_part, right_part = (
            str(left_product["part"]),
            str(right_product["part"]),
        )
        allowed_parts = set(policy["allowed_parts"])
        if left_part not in allowed_parts or right_part not in allowed_parts:
            continue
        if "a" not in {left_part, right_part}:
            continue

        left_key, right_key = (
            str(left_product["product_key"]),
            str(right_product["product_key"]),
        )
        left_compact = _compact_typo_key(left_key)
        right_compact = _compact_typo_key(right_key)
        if min(len(left_compact), len(right_compact)) < int(
            policy["min_compact_length"]
        ):
            continue
        if digit_signature(left_compact) != digit_signature(right_compact):
            continue
        if not _exactly_one_edit_apart(left_compact, right_compact):
            continue
        left_tokens, right_tokens = _tokens(left_key), _tokens(right_key)
        if len(left_tokens) != len(right_tokens):
            continue
        changed_tokens = [
            (left_token, right_token)
            for left_token, right_token in zip(left_tokens, right_tokens)
            if left_token != right_token
        ]
        if len(changed_tokens) != 1:
            continue
        if any(
            re.search(r"\d", token)
            for changed_pair in changed_tokens
            for token in changed_pair
        ):
            continue

        left_sources = source_families_by_node.get(left, set())
        right_sources = source_families_by_node.get(right, set())
        cross_exclusive_sources = (
            left_sources == {"cna_structured"}
            and right_sources == {"nvd_cpe"}
        ) or (
            left_sources == {"nvd_cpe"}
            and right_sources == {"cna_structured"}
        )
        if not cross_exclusive_sources:
            continue
        jaccard = _bigram_jaccard(left_compact, right_compact)
        lcs = _lcs_ratio(left_compact, right_compact)
        if jaccard < float(policy["min_bigram_jaccard"]):
            continue
        if lcs < float(policy["min_lcs_ratio"]):
            continue

        evidence_row = connection.execute(
            "SELECT basis_json FROM identity_alias_edge WHERE edge_id=?",
            (edge_id,),
        ).fetchone()
        if evidence_row is None:
            continue
        try:
            basis = json.loads(str(evidence_row["basis_json"]))
        except (json.JSONDecodeError, RecursionError):
            continue
        evidence_examples, evidence_count, evidence_truncated = _basis_parts(
            basis
        )
        if evidence_count < int(policy["min_distinct_cves"]):
            continue
        structurally_qualified += 1

        left_root, right_root = root_by_node[left], root_by_node[right]
        if not _component_pair_is_safe(
            left_root=left_root,
            right_root=right_root,
            members_by_root=members_by_root,
            semantic_roots=semantic_roots,
            blocked_by_node=blocked_by_node,
        ):
            continue
        root_pair = tuple(sorted((left_root, right_root)))
        candidate = {
            "left": left,
            "right": right,
            "left_key": left_key,
            "right_key": right_key,
            "left_root": root_pair[0],
            "right_root": root_pair[1],
            "jaccard": jaccard,
            "lcs": lcs,
            "evidence_count": evidence_count,
            "evidence_examples": evidence_examples,
            "evidence_truncated": evidence_truncated,
            "source_edge_id": edge_id,
            "changed_tokens": changed_tokens,
        }
        previous = component_candidates.get(root_pair)
        if previous is None or (
            evidence_count,
            jaccard,
            lcs,
            -edge_id,
        ) > (
            int(previous["evidence_count"]),
            float(previous["jaccard"]),
            float(previous["lcs"]),
            -int(previous["source_edge_id"]),
        ):
            component_candidates[root_pair] = candidate

    accepted = _mutually_unique_component_pairs(component_candidates)
    for candidate in accepted:
        _edge(
            connection,
            left=int(candidate["left"]),
            right=int(candidate["right"]),
            alias_class="B3_TYPO",
            evidence_tier="E1",
            status="accepted",
            strict_eligible=True,
            corroboration="single_source",
            basis={
                "kind": "validated_product_typo",
                "left_key": candidate["left_key"],
                "right_key": candidate["right_key"],
                "compact_edit_distance": 1,
                "bigram_jaccard": round(float(candidate["jaccard"]), 6),
                "lcs_ratio": round(float(candidate["lcs"]), 6),
                "changed_tokens": candidate["changed_tokens"],
                "distinct_cve_count": candidate["evidence_count"],
                "source_b2_edge_id": candidate["source_edge_id"],
                "evidence_truncated": candidate["evidence_truncated"],
                "evidence_examples": candidate["evidence_examples"],
                "source_guard": "cna_only_to_nvd_cpe_only",
                "policy": policy,
                "guards": IDENTITY_TYPO_POLICY["common_guards"],
            },
        )
    return {
        "product_b3_typo_accepted": len(accepted),
        "product_b3_typo_structurally_qualified": structurally_qualified,
        "product_b3_typo_qualified": len(component_candidates),
        "product_b3_typo_ambiguous": len(component_candidates) - len(accepted),
    }


def _queue_llm_identity_candidates(connection: sqlite3.Connection) -> int:
    """Create review issues from legacy LLM claims without changing identity.

    The legacy JSONL does not retain a binding index.  We therefore only pair
    claims when a CVE has exactly one grounded vendor and one grounded product
    claim.  The result is a review queue entry, never an accepted edge.
    """

    separator_candidates: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    exact_products: set[tuple[str, str]] = set()
    for product_row in connection.execute(
        """SELECT product_id,vendor_key,product_key,canonical_vendor,
                      canonical_product,part
           FROM product_entity ORDER BY product_id"""
    ):
        vendor_key = str(product_row['vendor_key'])
        product_key = str(product_row['product_key'])
        exact_products.add((vendor_key, product_key))
        separator_candidates[(separator_key(vendor_key), separator_key(product_key))].append(
            {
                'product_id': int(product_row['product_id']),
                'canonical_vendor': str(product_row['canonical_vendor']),
                'canonical_product': str(product_row['canonical_product']),
                'part': str(product_row['part']),
            }
        )

    rows = connection.execute(
        """SELECT llm_claim_id,cve_id,axis,extracted_value
           FROM llm_claim
           WHERE axis IN ('vendor','product')
             AND admission_status='below_agreement'
           ORDER BY cve_id,llm_claim_id"""
    )
    current: str | None = None
    claims: dict[str, list[sqlite3.Row]] = defaultdict(list)
    inserted = 0
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def flush(cve_id: str | None, values: Mapping[str, list[sqlite3.Row]]) -> int:
        if cve_id is None or len(values.get('vendor', [])) != 1 or len(values.get('product', [])) != 1:
            return 0
        vendor_claim = values['vendor'][0]
        product_claim = values['product'][0]
        vendor = str(vendor_claim['extracted_value'])
        product = str(product_claim['extracted_value'])
        vendor_key = normalize_key(vendor)
        product_key = normalize_key(product)
        if (vendor_key, product_key) in exact_products:
            return 0
        candidates = separator_candidates.get(
            (separator_key(vendor_key), separator_key(product_key)), []
        )[:10]
        details = canonical_json(
            {
                'vendor': vendor,
                'product': product,
                'vendor_claim_id': int(vendor_claim['llm_claim_id']),
                'product_claim_id': int(product_claim['llm_claim_id']),
                'candidate_products': candidates,
                'admission': 'candidate_only',
            }
        )
        connection.execute(
            """INSERT INTO normalization_issue(
                   failure_code,stage,severity,cve_id,llm_claim_id,
                   details_json,status,created_at
               ) VALUES ('F-ID-LLM-CANDIDATE','identity_alias_candidate',
                         'low',?,?,?,'open',?)""",
            (
                cve_id,
                int(product_claim['llm_claim_id']),
                details,
                created_at,
            ),
        )
        return 1

    for row in rows:
        cve_id = str(row['cve_id'])
        if current is not None and cve_id != current:
            inserted += flush(current, claims)
            claims = defaultdict(list)
        current = cve_id
        claims[str(row['axis'])].append(row)
    inserted += flush(current, claims)
    return inserted


def materialize_identity_resolution(
    connection: sqlite3.Connection,
    *,
    progress: IdentityProgress | None = None,
) -> Mapping[str, Any]:
    """Create L1 keys, L2 edges and L3 clusters after all raw entities exist."""

    for table in (
        "identity_cluster_edge",
        "identity_cluster_member",
        "identity_cluster",
        "identity_alias_edge",
        "identity_hard_distinct",
        "identity_key",
        "identity_node",
    ):
        connection.execute(f"DELETE FROM {table}")
    _report_identity_progress(progress, "reset_complete")

    counters: dict[str, int] = defaultdict(int)
    vendor_nodes: dict[str, int] = {}
    product_nodes: dict[int, int] = {}
    product_vendor_nodes: dict[int, int] = {}
    for row in connection.execute(
        """SELECT product_id,vendor_key,product_key,part,
                  canonical_vendor,canonical_product
           FROM product_entity ORDER BY product_id"""
    ):
        vendor_key = str(row["vendor_key"])
        vendor_node = vendor_nodes.get(vendor_key)
        if vendor_node is None:
            vendor_node = _ensure_node(
                connection, scope="vendor", vendor_key=vendor_key
            )
            vendor_nodes[vendor_key] = vendor_node
            for kind, value in derived_keys(str(row["canonical_vendor"])).items():
                _add_key(
                    connection,
                    node_id=vendor_node,
                    key_kind=kind,
                    key_value=value,
                    origin="canonical_entity",
                )
        product_id = int(row["product_id"])
        product_node = _ensure_node(
            connection,
            scope="product",
            vendor_key=vendor_key,
            product_key=str(row["product_key"]),
            part=str(row["part"]),
            product_id=product_id,
        )
        product_nodes[product_id] = product_node
        product_vendor_nodes[product_id] = vendor_node
        for kind, value in derived_keys(str(row["canonical_product"])).items():
            _add_key(
                connection,
                node_id=product_node,
                key_kind=kind,
                key_value=value,
                origin="canonical_entity",
            )
        counters["product_nodes"] += 1
    counters["vendor_nodes"] = len(vendor_nodes)
    _report_identity_progress(
        progress,
        "canonical_keys_complete",
        product_nodes=counters["product_nodes"],
        vendor_nodes=counters["vendor_nodes"],
    )

    # Every raw spelling is retained as an additional L1 observation.
    for row in connection.execute(
        """SELECT product_alias_id,product_id,vendor_raw,product_raw
           FROM product_alias
           ORDER BY product_id,vendor_raw,product_raw,source_family"""
    ):
        product_id = int(row["product_id"])
        product_node = product_nodes[product_id]
        vendor_node = product_vendor_nodes[product_id]
        alias_id = int(row["product_alias_id"])
        for kind, value in derived_keys(str(row["vendor_raw"])).items():
            _add_key(
                connection,
                node_id=vendor_node,
                key_kind=kind,
                key_value=value,
                origin="raw_alias_observation",
                source_alias_id=alias_id,
            )
        for kind, value in derived_keys(str(row["product_raw"])).items():
            _add_key(
                connection,
                node_id=product_node,
                key_kind=kind,
                key_value=value,
                origin="raw_alias_observation",
                source_alias_id=alias_id,
            )
    _report_identity_progress(progress, "raw_alias_keys_complete")

    counters["llm_identity_candidates"] = _queue_llm_identity_candidates(connection)
    counters.update(_insert_registry(connection))
    counters.update(_auto_vendor_edges(connection))
    counters.update(_auto_vendor_typo_edges(connection))
    _report_identity_progress(
        progress,
        "vendor_typo_edges_complete",
        accepted=counters["vendor_b3_typo_accepted"],
        qualified=counters["vendor_b3_typo_qualified"],
        ambiguous=counters["vendor_b3_typo_ambiguous"],
    )
    vendor_result = _build_clusters(connection, scope="vendor")
    counters["vendor_clusters"] = int(vendor_result["clusters"])
    counters["vendor_cluster_review"] = int(vendor_result["review_clusters"])
    _report_identity_progress(
        progress,
        "vendor_clusters_complete",
        vendor_clusters=counters["vendor_clusters"],
        review_clusters=counters["vendor_cluster_review"],
    )
    counters.update(
        _auto_product_edges(connection, vendor_result["cluster_map"])
    )
    _report_identity_progress(progress, "product_format_edges_complete")
    counters.update(_auto_self_brand_product_edges(connection))
    _report_identity_progress(
        progress,
        "self_brand_product_edges_complete",
        accepted=counters["self_brand_b2_accepted"],
        groups=counters["self_brand_b2_groups"],
        preliminary_groups=counters["self_brand_b2_preliminary_groups"],
    )
    counters["cna_cpe_alias_candidates"] = _mine_cna_cpe_candidates(
        connection,
        vendor_result["cluster_map"],
        progress=progress,
    )
    counters.update(_promote_product_typo_edges(connection))
    _report_identity_progress(
        progress,
        "product_typo_edges_complete",
        accepted=counters["product_b3_typo_accepted"],
        qualified=counters["product_b3_typo_qualified"],
        ambiguous=counters["product_b3_typo_ambiguous"],
    )
    product_result = _build_clusters(connection, scope="product")
    counters["product_clusters"] = int(product_result["clusters"])
    counters["product_cluster_review"] = int(product_result["review_clusters"])
    _report_identity_progress(
        progress,
        "product_clusters_complete",
        product_clusters=counters["product_clusters"],
        review_clusters=counters["product_cluster_review"],
    )
    digest = stable_hash(
        {
            "registry": IDENTITY_REGISTRY_SHA256,
            "vendor": vendor_result["digest"],
            "product": product_result["digest"],
            "counters": dict(sorted(counters.items())),
        }
    )
    connection.execute(
        "INSERT OR REPLACE INTO metadata(key,value) VALUES ('identity_cluster_digest',?)",
        (digest,),
    )
    connection.execute(
        "INSERT OR REPLACE INTO metadata(key,value) VALUES ('identity_registry_version',?)",
        (IDENTITY_REGISTRY_VERSION,),
    )
    connection.execute(
        "INSERT OR REPLACE INTO metadata(key,value) VALUES ('identity_registry_sha256',?)",
        (IDENTITY_REGISTRY_SHA256,),
    )
    return {**dict(counters), "cluster_digest": digest}


def _direct_scope_clone(connection: sqlite3.Connection, scope_id: int) -> int:
    row = connection.execute(
        "SELECT * FROM applicability_scope WHERE scope_id=?", (scope_id,)
    ).fetchone()
    if row is None:
        raise RuntimeError(f"missing applicability scope {scope_id}")
    axes = {}
    for name in (
        "part", "distribution", "edition", "component", "update",
        "language", "sw_edition", "target_sw", "target_hw", "other",
    ):
        axes[name] = [row[f"{name}_state"], row[f"{name}_value"]]
    payload = {
        "product_id": int(row["product_id"]),
        "axes": {key: value for key, value in sorted(axes.items())},
        "configuration_id": row["configuration_id"],
        "configuration_match_id": row["configuration_match_id"],
        "cpe_role": "DIRECT_UPSTREAM",
        "exclusive_scope": row["exclusive_scope"],
        "rule_version": RULE_VERSION,
    }
    fingerprint = stable_hash(payload)
    existing = connection.execute(
        "SELECT scope_id FROM applicability_scope WHERE scope_fingerprint=?",
        (fingerprint,),
    ).fetchone()
    if existing is not None:
        return int(existing[0])
    columns = [
        "product_id",
        "part_state", "part_value",
        "distribution_state", "distribution_value",
        "edition_state", "edition_value",
        "component_state", "component_value",
        "update_state", "update_value",
        "language_state", "language_value",
        "sw_edition_state", "sw_edition_value",
        "target_sw_state", "target_sw_value",
        "target_hw_state", "target_hw_value",
        "other_state", "other_value",
        "configuration_id", "configuration_match_id",
        "exclusive_scope", "is_maximal", "subsumption_depth",
    ]
    values = [row[column] for column in columns]
    cursor = connection.execute(
        """INSERT INTO applicability_scope(
               product_id,part_state,part_value,distribution_state,distribution_value,
               edition_state,edition_value,component_state,component_value,
               update_state,update_value,language_state,language_value,
               sw_edition_state,sw_edition_value,target_sw_state,target_sw_value,
               target_hw_state,target_hw_value,other_state,other_value,
               configuration_id,configuration_match_id,cpe_match_role,
               exclusive_scope,scope_fingerprint,is_maximal,subsumption_depth
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            *values[:23],
            "DIRECT_UPSTREAM",
            values[23],
            fingerprint,
            values[24],
            values[25],
        ),
    )
    return int(cursor.lastrowid)


def reclassify_alias_roles(
    connection: sqlite3.Connection,
    *,
    progress: IdentityProgress | None = None,
) -> Mapping[str, int]:
    """Finalize CPE roles after collision-aware alias clusters exist.

    Streaming ingest only grants direct role to exact CNA/CPE identities.  This
    pass promotes an unresolved NVD CPE when it has a strict accepted path to a
    CNA affected product in the same CVE.  Candidate/provisional/non-strict
    registry edges cannot promote role.
    """

    product_nodes = {
        int(row["product_id"]): int(row["node_id"])
        for row in connection.execute(
            """SELECT product_id,node_id FROM identity_node
               WHERE scope_kind='product' AND product_id IS NOT NULL"""
        )
    }

    # Materialize the CNA side by cluster.  The WITHOUT ROWID primary key is
    # also the lookup index used by the candidate scan below; this prevents
    # SQLite from enumerating every CNA x NVD pair for a CVE and filtering the
    # cluster only afterwards.
    connection.execute("DROP TABLE IF EXISTS temp.cna_role_cluster")
    connection.execute(
        """CREATE TEMP TABLE cna_role_cluster(
               cve_id TEXT NOT NULL,
               cluster_id INTEGER NOT NULL,
               product_id INTEGER NOT NULL,
               PRIMARY KEY(cve_id,cluster_id,product_id)
           ) WITHOUT ROWID"""
    )
    connection.execute(
        """INSERT OR IGNORE INTO temp.cna_role_cluster(
               cve_id,cluster_id,product_id
           )
           SELECT claim.cve_id,member.cluster_id,claim.product_id
           FROM source_claim AS claim
           JOIN identity_node AS node
             ON node.scope_kind='product'
            AND node.product_id=claim.product_id
           JOIN identity_cluster_member AS member
             ON member.node_id=node.node_id
           WHERE claim.source_family='cna_structured'
             AND claim.product_id IS NOT NULL
             AND COALESCE(claim.vulnerable_flag,1)=1"""
    )
    cna_cluster_rows = int(
        connection.execute(
            "SELECT COUNT(*) FROM temp.cna_role_cluster"
        ).fetchone()[0]
    )
    _report_identity_progress(
        progress,
        "role_cna_clusters_complete",
        cna_cluster_rows=cna_cluster_rows,
    )

    # CROSS JOIN fixes the intended loop order: filtered unresolved assertions
    # -> their NVD claim/node/cluster -> an indexed cna_role_cluster seek.
    # There is intentionally no ORDER BY and no wide comparison JSON here.
    candidate_sql = """SELECT a.assertion_id,
                              nvd_node.node_id AS nvd_node_id,
                              cna.product_id AS cna_product_id
                       FROM applicability_assertion AS a
                            INDEXED BY build_assertion_role_claim_idx
                       CROSS JOIN source_claim AS nvd
                       CROSS JOIN identity_node AS nvd_node
                       CROSS JOIN identity_cluster_member AS nvd_member
                       CROSS JOIN temp.cna_role_cluster AS cna
                       WHERE a.source_family='nvd_cpe'
                         AND a.cpe_match_role='UNRESOLVED'
                         AND nvd.source_claim_id=a.source_claim_id
                         AND nvd.product_id IS NOT NULL
                         AND nvd_node.scope_kind='product'
                         AND nvd_node.product_id=nvd.product_id
                         AND nvd_member.node_id=nvd_node.node_id
                         AND cna.cve_id=nvd.cve_id
                         AND cna.cluster_id=nvd_member.cluster_id"""
    if progress is not None:
        plan = [
            str(row["detail"])
            for row in connection.execute(
                f"EXPLAIN QUERY PLAN {candidate_sql}"
            )
        ]
        _report_identity_progress(
            progress,
            "role_candidate_plan",
            plan=plan,
        )
    rows = connection.execute(candidate_sql)
    path_cache: dict[int, dict[int, dict[str, Any]]] = {}
    selected_by_assertion: dict[int, str] = {}
    examined = 0
    for row in rows:
        examined += 1
        assertion_id = int(row["assertion_id"])
        nvd_node = int(row["nvd_node_id"])
        paths = path_cache.get(nvd_node)
        if paths is None:
            paths = _path_candidates(
                connection,
                nvd_node,
                include_provisional=False,
            )
            path_cache[nvd_node] = paths
        cna_node = product_nodes.get(int(row["cna_product_id"]))
        if cna_node is not None:
            meta = paths.get(cna_node)
            if (
                meta is not None
                and bool(meta.get("strict"))
                and str(meta.get("tier")) != "T3_PROVISIONAL"
            ):
                tier = str(meta["tier"])
                previous = selected_by_assertion.get(assertion_id)
                if (
                    previous is None
                    or TIER_RANK[tier] < TIER_RANK[previous]
                ):
                    selected_by_assertion[assertion_id] = tier
        if examined % 10_000 == 0:
            _report_identity_progress(
                progress,
                "role_reclassification_scan",
                examined_pairs=examined,
                selected_assertions=len(selected_by_assertion),
                cached_products=len(path_cache),
            )
    _report_identity_progress(
        progress,
        "role_reclassification_scan_complete",
        examined_pairs=examined,
        selected_assertions=len(selected_by_assertion),
        cached_products=len(path_cache),
    )

    connection.execute("DROP TABLE IF EXISTS temp.role_promotion")
    connection.execute(
        """CREATE TEMP TABLE role_promotion(
               assertion_id INTEGER PRIMARY KEY,
               tier TEXT NOT NULL
           ) WITHOUT ROWID"""
    )
    connection.executemany(
        "INSERT INTO temp.role_promotion(assertion_id,tier) VALUES (?,?)",
        sorted(selected_by_assertion.items()),
    )

    assertion_updates: list[tuple[Any, ...]] = []
    reconciliation_updates: list[tuple[str, int]] = []
    scope_cache: dict[int, int] = {}
    selected_rows = connection.execute(
        """SELECT a.assertion_id,a.scope_id,a.version_resolution_class,
                  a.scope_resolution_status,a.version_resolution_status,
                  a.comparison_tuple_json,p.tier
           FROM temp.role_promotion AS p
           JOIN applicability_assertion AS a USING(assertion_id)"""
    )
    for row in selected_rows:
        old_scope_id = int(row["scope_id"])
        direct_scope_id = scope_cache.get(old_scope_id)
        if direct_scope_id is None:
            direct_scope_id = _direct_scope_clone(connection, old_scope_id)
            scope_cache[old_scope_id] = direct_scope_id
        try:
            comparison = json.loads(str(row["comparison_tuple_json"]))
        except json.JSONDecodeError:
            comparison = [0, 0, 0, 0, 0, 0, 0]
        while len(comparison) < 7:
            comparison.append(0)
        comparison[4] = 2
        comparison_json = canonical_json(comparison)
        version_class = str(row["version_resolution_class"])
        max_state = (
            "potentially_affected"
            if version_class in {
                "CPE_ANY_UNCORROBORATED", "UNSPECIFIED", "UNPARSED"
            }
            else None
        )
        can_index = (
            version_class in {
                "EXACT", "BOUNDED_RANGE", "UNBOUNDED_RANGE", "BRANCH_RANGE"
            }
            and str(row["scope_resolution_status"]) == "resolved"
            and str(row["version_resolution_status"]) == "resolved"
        )
        assertion_id = int(row["assertion_id"])
        assertion_updates.append(
            (
                direct_scope_id,
                f"identity_cluster_alias:{row['tier']}",
                max_state,
                int(can_index),
                comparison_json,
                assertion_id,
            )
        )
        reconciliation_updates.append((comparison_json, assertion_id))

    connection.executemany(
        """UPDATE applicability_assertion
           SET scope_id=?,cpe_match_role='DIRECT_UPSTREAM',
               role_basis=?,max_result_state=?,use_for_version_index=?,
               comparison_tuple_json=?
           WHERE assertion_id=?""",
        assertion_updates,
    )
    connection.executemany(
        """UPDATE assertion_reconciliation
           SET comparison_tuple_json=?
           WHERE assertion_id=?""",
        reconciliation_updates,
    )
    promoted = len(assertion_updates)
    _report_identity_progress(
        progress,
        "role_reclassification_updates_complete",
        promoted_assertions=promoted,
        cloned_scopes=len(scope_cache),
    )

    # Role promotion can only clear an existing review requirement.  Restrict
    # the recheck to bindings containing a promoted assertion and write only
    # rows whose final flag changes.
    connection.execute(
        """UPDATE cve_applicability_binding AS b
           SET manual_review_required=0
           WHERE b.manual_review_required=1
             AND b.binding_id IN (
               SELECT m.binding_id
               FROM temp.role_promotion p
               JOIN binding_assertion_member m USING(assertion_id)
             )
             AND NOT EXISTS (
               SELECT 1
               FROM binding_assertion_member m
               JOIN applicability_assertion a USING(assertion_id)
               WHERE m.binding_id=b.binding_id
                 AND m.is_active=1
                 AND (
                   a.cpe_match_role='UNRESOLVED'
                   OR a.reconciliation_status IN (
                     'conflict_review','unparsed_review'
                   )
                 )
             )"""
    )
    manual_review_updates = int(
        connection.execute("SELECT changes()").fetchone()[0]
    )
    connection.execute("DROP TABLE temp.role_promotion")
    connection.execute("DROP TABLE temp.cna_role_cluster")
    _report_identity_progress(
        progress,
        "manual_review_flags_complete",
        updated_bindings=manual_review_updates,
    )
    return {
        "cna_cluster_rows": cna_cluster_rows,
        "examined_pairs": examined,
        "promoted_assertions": promoted,
        "manual_review_updates": manual_review_updates,
    }


@dataclass(frozen=True, slots=True)
class ResolvedProduct:
    product_id: int
    vendor_key: str
    product_key: str
    part: str
    canonical_vendor: str
    canonical_product: str
    identity: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class IdentityResolution:
    state: str
    reason: str
    products: tuple[ResolvedProduct, ...]
    ambiguous_clusters: tuple[int, ...] = ()
    suggestions: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class _QueryName:
    safe: str
    compact: str
    tokens: tuple[str, ...]
    token_bag: tuple[str, ...]
    acronym: str
    digits: str


@dataclass(frozen=True, slots=True)
class _QueryNameMatch:
    kind: str
    score: float
    bigram_jaccard: float
    lcs_ratio: float


@dataclass(frozen=True, slots=True)
class _QueryVendorCandidate:
    node_id: int
    cluster_id: int
    vendor_key: str
    name: _QueryName


@dataclass(frozen=True, slots=True)
class _QueryProductCandidate:
    node_id: int
    product_id: int
    vendor_cluster_id: int
    product_cluster_id: int
    vendor_key: str
    product_key: str
    part: str
    canonical_vendor: str
    canonical_product: str
    name: _QueryName


def _query_name(value: str | None) -> _QueryName:
    safe = normalize_key(value)
    tokens = _tokens(safe)
    return _QueryName(
        safe=safe,
        compact=_compact_typo_key(safe),
        tokens=tokens,
        token_bag=tuple(sorted(tokens)),
        acronym=("" if len(tokens) < 2 else "".join(token[0] for token in tokens)),
        digits=digit_signature(safe),
    )


def _single_query_edit_kind(left: str, right: str) -> str | None:
    """Return a single-edit class, including adjacent transposition."""

    if left == right or abs(len(left) - len(right)) > 1:
        return None
    if len(left) != len(right):
        return "insertion_or_deletion" if _exactly_one_edit_apart(left, right) else None
    mismatches = [
        index for index, (a, b) in enumerate(zip(left, right)) if a != b
    ]
    if len(mismatches) == 1:
        return "substitution"
    if len(mismatches) != 2 or mismatches[1] != mismatches[0] + 1:
        return None
    first, second = mismatches
    if left[first] == right[second] and left[second] == right[first]:
        return "adjacent_transposition"
    return None


def _query_name_match(
    query: _QueryName,
    candidate: _QueryName,
) -> _QueryNameMatch | None:
    if not query.safe or not candidate.safe:
        return None
    if query.safe == candidate.safe:
        return _QueryNameMatch("exact", 1.0, 1.0, 1.0)
    if query.compact == candidate.compact:
        return _QueryNameMatch("separator", 0.99, 1.0, 1.0)
    if (
        len(query.tokens) >= 2
        and len(candidate.tokens) >= 2
        and query.token_bag == candidate.token_bag
    ):
        jaccard = _bigram_jaccard(query.compact, candidate.compact)
        lcs = _lcs_ratio(query.compact, candidate.compact)
        return _QueryNameMatch("token_order", 0.95, jaccard, lcs)
    if (
        2 <= len(query.compact) <= 16
        and candidate.acronym
        and query.compact == candidate.acronym
    ):
        return _QueryNameMatch("acronym", 0.88, 0.0, _lcs_ratio(query.compact, candidate.compact))
    if (
        2 <= len(candidate.compact) <= 16
        and query.acronym
        and candidate.compact == query.acronym
    ):
        return _QueryNameMatch("acronym", 0.88, 0.0, _lcs_ratio(query.compact, candidate.compact))
    if min(len(query.compact), len(candidate.compact)) < 3:
        return None
    if query.digits != candidate.digits:
        return None
    edit_kind = _single_query_edit_kind(query.compact, candidate.compact)
    if edit_kind is None:
        return None
    jaccard = _bigram_jaccard(query.compact, candidate.compact)
    lcs = _lcs_ratio(query.compact, candidate.compact)
    # One-edit recognition is the hard gate. Jaccard/LCS rank candidates and
    # are exposed for audit; they are not trusted as identity proof alone.
    score = 0.88 + 0.06 * jaccard + 0.06 * lcs
    if query.safe.isascii() != candidate.safe.isascii():
        score -= 0.07
    return _QueryNameMatch(f"typo_{edit_kind}", score, jaccard, lcs)


class QueryIdentityResolver:
    """Stateful query-time fuzzy candidate resolver for one read-only DB."""

    _VENDOR_LIMIT = 256
    _SCORE_MARGIN = 0.025

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self._vendor_candidates: tuple[_QueryVendorCandidate, ...] | None = None
        self._vendor_prefix_index: dict[
            tuple[int, str], list[_QueryVendorCandidate]
        ] = defaultdict(list)
        self._vendor_suffix_index: dict[
            tuple[int, str], list[_QueryVendorCandidate]
        ] = defaultdict(list)
        self._vendor_compact_index: dict[
            str, list[_QueryVendorCandidate]
        ] = defaultdict(list)
        self._vendor_token_index: dict[
            tuple[str, ...], list[_QueryVendorCandidate]
        ] = defaultdict(list)
        self._vendor_acronym_index: dict[
            str, list[_QueryVendorCandidate]
        ] = defaultdict(list)
        self._vendor_match_cache: dict[
            str, tuple[tuple[_QueryVendorCandidate, _QueryNameMatch], ...]
        ] = {}
        self._product_cache: dict[
            tuple[int, ...], tuple[_QueryProductCandidate, ...]
        ] = {}

    def _vendors(self) -> tuple[_QueryVendorCandidate, ...]:
        if self._vendor_candidates is None:
            candidates = tuple(
                _QueryVendorCandidate(
                    node_id=int(row["node_id"]),
                    cluster_id=int(row["cluster_id"]),
                    vendor_key=str(row["vendor_key"]),
                    name=_query_name(str(row["vendor_key"])),
                )
                for row in self.connection.execute(
                    """SELECT n.node_id,n.vendor_key,m.cluster_id
                       FROM identity_node n
                       JOIN identity_cluster_member m USING(node_id)
                       WHERE n.scope_kind='vendor'
                       ORDER BY n.node_id"""
                )
            )
            for candidate in candidates:
                compact = candidate.name.compact
                if compact:
                    self._vendor_prefix_index[(len(compact), compact[0])].append(
                        candidate
                    )
                    self._vendor_suffix_index[(len(compact), compact[-1])].append(
                        candidate
                    )
                    self._vendor_compact_index[compact].append(candidate)
                if len(candidate.name.tokens) >= 2:
                    self._vendor_token_index[candidate.name.token_bag].append(candidate)
                if candidate.name.acronym:
                    self._vendor_acronym_index[candidate.name.acronym].append(candidate)
            self._vendor_candidates = candidates
        return self._vendor_candidates

    def vendor_matches(
        self,
        vendor: str,
    ) -> tuple[tuple[_QueryVendorCandidate, _QueryNameMatch], ...]:
        key = normalize_key(vendor)
        cached = self._vendor_match_cache.get(key)
        if cached is not None:
            return cached
        query = _query_name(key)
        self._vendors()
        candidate_by_node: dict[int, _QueryVendorCandidate] = {}
        compact = query.compact
        if compact:
            for length in range(max(1, len(compact) - 1), len(compact) + 2):
                for candidate in self._vendor_prefix_index.get(
                    (length, compact[0]), ()
                ):
                    candidate_by_node[candidate.node_id] = candidate
                for candidate in self._vendor_suffix_index.get(
                    (length, compact[-1]), ()
                ):
                    candidate_by_node[candidate.node_id] = candidate
            for candidate in self._vendor_compact_index.get(compact, ()):
                candidate_by_node[candidate.node_id] = candidate
            for candidate in self._vendor_acronym_index.get(compact, ()):
                candidate_by_node[candidate.node_id] = candidate
        if len(query.tokens) >= 2:
            for candidate in self._vendor_token_index.get(query.token_bag, ()):
                candidate_by_node[candidate.node_id] = candidate
            if query.acronym:
                for candidate in self._vendor_compact_index.get(query.acronym, ()):
                    candidate_by_node[candidate.node_id] = candidate
        by_cluster: dict[int, tuple[_QueryVendorCandidate, _QueryNameMatch]] = {}
        for candidate in candidate_by_node.values():
            match = _query_name_match(query, candidate.name)
            if match is None:
                continue
            previous = by_cluster.get(candidate.cluster_id)
            if previous is None or match.score > previous[1].score:
                by_cluster[candidate.cluster_id] = (candidate, match)
        ranked = sorted(
            by_cluster.values(),
            key=lambda item: (-item[1].score, item[0].vendor_key, item[0].node_id),
        )
        if ranked:
            best = ranked[0][1].score
            ranked = [item for item in ranked if item[1].score >= best - 0.15]
        result = tuple(ranked[: self._VENDOR_LIMIT])
        if len(self._vendor_match_cache) >= 16_384:
            self._vendor_match_cache.clear()
        self._vendor_match_cache[key] = result
        return result

    def products_for_vendor_clusters(
        self,
        cluster_ids: Iterable[int],
    ) -> tuple[_QueryProductCandidate, ...]:
        key = tuple(sorted(set(cluster_ids)))
        cached = self._product_cache.get(key)
        if cached is not None:
            return cached
        if not key:
            return ()
        marks = ",".join("?" for _ in key)
        rows = self.connection.execute(
            f"""SELECT DISTINCT pn.node_id,pn.product_id,pn.vendor_key,
                               pn.product_key,pn.part,
                               pm.cluster_id AS product_cluster_id,
                               vm.cluster_id AS vendor_cluster_id,
                               p.canonical_vendor,p.canonical_product
                FROM identity_node pn
                JOIN identity_cluster_member pm ON pm.node_id=pn.node_id
                JOIN product_entity p USING(product_id)
                JOIN identity_node vn
                  ON vn.scope_kind='vendor' AND vn.vendor_key=pn.vendor_key
                JOIN identity_cluster_member vm ON vm.node_id=vn.node_id
                WHERE pn.scope_kind='product'
                  AND vm.cluster_id IN ({marks})
                ORDER BY pn.node_id""",
            key,
        )
        result = tuple(
            _QueryProductCandidate(
                node_id=int(row["node_id"]),
                product_id=int(row["product_id"]),
                vendor_cluster_id=int(row["vendor_cluster_id"]),
                product_cluster_id=int(row["product_cluster_id"]),
                vendor_key=str(row["vendor_key"]),
                product_key=str(row["product_key"]),
                part=str(row["part"]),
                canonical_vendor=str(row["canonical_vendor"]),
                canonical_product=str(row["canonical_product"]),
                name=_query_name(str(row["product_key"])),
            )
            for row in rows
        )
        if len(self._product_cache) >= 4_096:
            self._product_cache.clear()
        self._product_cache[key] = result
        return result

    def fuzzy_product_seeds(
        self,
        *,
        vendor: str,
        product: str,
        exact_vendor_clusters: Mapping[int, str],
    ) -> tuple[dict[int, dict[str, Any]], tuple[Mapping[str, Any], ...], bool]:
        vendor_match_map: dict[
            int, tuple[_QueryVendorCandidate, _QueryNameMatch]
        ] = {
            cluster_id: (
                    _QueryVendorCandidate(
                        node_id=-1,
                        cluster_id=cluster_id,
                        vendor_key=normalize_key(vendor),
                        name=_query_name(vendor),
                    ),
                    _QueryNameMatch("exact", 1.0, 1.0, 1.0),
                )
            for cluster_id in sorted(exact_vendor_clusters)
        }
        # A misspelled query can itself collide with another real vendor. Once
        # the exact (vendor, product) cascade has failed, consider nearby vendor
        # clusters jointly with the product instead of locking onto that vendor.
        for candidate, match in self.vendor_matches(vendor):
            previous = vendor_match_map.get(candidate.cluster_id)
            if previous is None or match.score > previous[1].score:
                vendor_match_map[candidate.cluster_id] = (candidate, match)
        vendor_matches = tuple(vendor_match_map.values())
        if not vendor_matches:
            return {}, (), False
        vendor_by_cluster = {
            candidate.cluster_id: match for candidate, match in vendor_matches
        }
        product_query = _query_name(product)
        vendor_query = _query_name(vendor)
        grouped: dict[tuple[int, str], dict[str, Any]] = {}
        for row in self.products_for_vendor_clusters(vendor_by_cluster):
            product_match = _query_name_match(product_query, row.name)
            if product_match is None:
                continue
            vendor_match = vendor_by_cluster[row.vendor_cluster_id]
            # Product is the more discriminating axis in this data model. An
            # exact product also disambiguates a vendor spelling that happens
            # to collide with another real vendor key.
            score = 0.4 * vendor_match.score + 0.6 * product_match.score
            vendor_anchor_bonus = (
                0.08 if row.vendor_cluster_id in exact_vendor_clusters else 0.0
            )
            score += vendor_anchor_bonus
            product_anchor_bonus = 0.03 if product_match.kind == "exact" else 0.0
            score += product_anchor_bonus
            coherence_bonus = 0.0
            if row.vendor_key == row.product_key and (
                vendor_query.compact == product_query.compact
                or product_query.safe == row.vendor_key
                or vendor_query.safe == row.product_key
            ):
                coherence_bonus = 0.04
                score += coherence_bonus
            group_key = (row.vendor_cluster_id, row.product_key)
            group = grouped.setdefault(
                group_key,
                {
                    "score": score,
                    "vendor_match": vendor_match,
                    "product_match": product_match,
                    "vendor_anchor_bonus": vendor_anchor_bonus,
                    "product_anchor_bonus": product_anchor_bonus,
                    "coherence_bonus": coherence_bonus,
                    "rows": [],
                },
            )
            group["rows"].append(row)
            if score > float(group["score"]):
                group["score"] = score
                group["vendor_match"] = vendor_match
                group["product_match"] = product_match
                group["vendor_anchor_bonus"] = vendor_anchor_bonus
                group["product_anchor_bonus"] = product_anchor_bonus
                group["coherence_bonus"] = coherence_bonus
        ranked = sorted(
            grouped.values(),
            key=lambda item: (
                -float(item["score"]),
                str(item["rows"][0].vendor_key),
                str(item["rows"][0].product_key),
            ),
        )
        suggestions = tuple(
            {
                "product_id": int(item["rows"][0].product_id),
                "canonical_vendor": str(item["rows"][0].canonical_vendor),
                "canonical_product": str(item["rows"][0].canonical_product),
                "part": str(item["rows"][0].part),
                "score": round(float(item["score"]), 6),
                "vendor_match_kind": str(item["vendor_match"].kind),
                "product_match_kind": str(item["product_match"].kind),
            }
            for item in ranked[:10]
        )
        if not ranked:
            return {}, suggestions, False
        if (
            len(ranked) > 1
            and float(ranked[0]["score"]) - float(ranked[1]["score"])
            < self._SCORE_MARGIN
        ):
            return {}, suggestions, True
        selected = ranked[0]
        vendor_match = selected["vendor_match"]
        product_match = selected["product_match"]
        basis = {
            "kind": "query_fuzzy",
            "score": round(float(selected["score"]), 6),
            "score_margin": (
                None
                if len(ranked) == 1
                else round(
                    float(selected["score"]) - float(ranked[1]["score"]),
                    6,
                )
            ),
            "coherence_bonus": round(float(selected["coherence_bonus"]), 6),
            "vendor_anchor_bonus": round(
                float(selected["vendor_anchor_bonus"]), 6
            ),
            "product_anchor_bonus": round(
                float(selected["product_anchor_bonus"]), 6
            ),
            "vendor": {
                "match_kind": vendor_match.kind,
                "bigram_jaccard": round(vendor_match.bigram_jaccard, 6),
                "lcs_ratio": round(vendor_match.lcs_ratio, 6),
            },
            "product": {
                "match_kind": product_match.kind,
                "bigram_jaccard": round(product_match.bigram_jaccard, 6),
                "lcs_ratio": round(product_match.lcs_ratio, 6),
            },
        }
        seeds = {
            int(row.node_id): {
                "tier": "T3_PROVISIONAL",
                "strict": False,
                "matched_key_kind": "query_fuzzy",
                "query_match": basis,
            }
            for row in selected["rows"]
        }
        return seeds, suggestions, False


def _edge_tier(alias_class: str) -> str:
    return (
        "T1_FORMAT"
        if alias_class in {"A1_SEPARATOR", "A2_LEGAL_SUFFIX"}
        else "T2_REGISTRY"
    )


def _path_candidates(
    connection: sqlite3.Connection,
    seed_node: int,
    *,
    include_provisional: bool = True,
) -> dict[int, dict[str, Any]]:
    seed_cluster = connection.execute(
        """SELECT c.cluster_id,c.review_state,c.strict_eligible
           FROM identity_cluster_member m
           JOIN identity_cluster c USING(cluster_id)
           WHERE m.node_id=? AND c.scope_kind='product'""",
        (seed_node,),
    ).fetchone()
    if seed_cluster is None:
        return {seed_node: {"tier": "T0_EXACT", "strict": True, "edge_ids": []}}
    cluster_id = int(seed_cluster["cluster_id"])
    review = str(seed_cluster["review_state"]) != "ok"
    adjacency: dict[int, list[sqlite3.Row]] = defaultdict(list)
    for row in connection.execute(
        """SELECT e.* FROM identity_cluster_edge ce
           JOIN identity_alias_edge e USING(edge_id)
           WHERE ce.cluster_id=?""",
        (cluster_id,),
    ):
        adjacency[int(row["left_node_id"])].append(row)
        adjacency[int(row["right_node_id"])].append(row)
    result: dict[int, dict[str, Any]] = {
        seed_node: {
            "tier": "T0_EXACT",
            "strict": not review,
            "edge_ids": [],
            "cluster_id": cluster_id,
        }
    }
    queue: deque[int] = deque([seed_node])
    while queue:
        current = queue.popleft()
        current_meta = result[current]
        for edge in adjacency.get(current, []):
            left, right = int(edge["left_node_id"]), int(edge["right_node_id"])
            target = right if left == current else left
            edge_tier = _edge_tier(str(edge["alias_class"]))
            tier = max(
                (current_meta["tier"], edge_tier),
                key=lambda item: TIER_RANK[item],
            )
            strict = (
                bool(current_meta["strict"])
                and bool(edge["strict_eligible"])
                and not review
            )
            candidate = {
                "tier": tier,
                "strict": strict,
                "edge_ids": [*current_meta["edge_ids"], int(edge["edge_id"])],
                "cluster_id": cluster_id,
                "alias_class": str(edge["alias_class"]),
                "evidence_tier": str(edge["evidence_tier"]),
            }
            previous = result.get(target)
            if previous is None or (
                TIER_RANK[tier], not strict, len(candidate["edge_ids"])
            ) < (
                TIER_RANK[str(previous["tier"])],
                not bool(previous["strict"]),
                len(previous["edge_ids"]),
            ):
                result[target] = candidate
                queue.append(target)
    if not include_provisional:
        return result
    # Provisional edges are one-hop only and never become cluster members.
    cluster_nodes = tuple(result)
    for node in cluster_nodes:
        for edge in connection.execute(
            """SELECT * FROM identity_alias_edge
               WHERE status='provisional'
                 AND (left_node_id=? OR right_node_id=?)""",
            (node, node),
        ):
            target = (
                int(edge["right_node_id"])
                if int(edge["left_node_id"]) == node
                else int(edge["left_node_id"])
            )
            if target not in result:
                result[target] = {
                    "tier": "T3_PROVISIONAL",
                    "strict": False,
                    "edge_ids": [int(edge["edge_id"])],
                    "cluster_id": cluster_id,
                    "alias_class": str(edge["alias_class"]),
                    "evidence_tier": str(edge["evidence_tier"]),
                }
    return result


def _matching_vendor_clusters(
    connection: sqlite3.Connection, vendor: str
) -> dict[int, str]:
    keys = derived_keys(vendor)
    rows = list(
        connection.execute(
            """SELECT DISTINCT n.node_id,c.cluster_id,k.key_kind,n.vendor_key
               FROM identity_key k
               JOIN identity_node n USING(node_id)
               JOIN identity_cluster_member m USING(node_id)
               JOIN identity_cluster c USING(cluster_id)
               WHERE n.scope_kind='vendor'
                 AND ((k.key_kind='safe' AND k.key_value=?)
                   OR (k.key_kind='separator' AND k.key_value=?))""",
            (keys.get("safe", ""), keys.get("separator", "")),
        )
    )
    output: dict[int, str] = {}
    for row in rows:
        tier = (
            "T0_EXACT"
            if str(row["vendor_key"]) == keys.get("safe")
            else "T1_FORMAT"
        )
        cluster_id = int(row["cluster_id"])
        previous = output.get(cluster_id)
        if previous is None or TIER_RANK[tier] < TIER_RANK[previous]:
            output[cluster_id] = tier
    return output


def resolve_query_products(
    connection: sqlite3.Connection,
    *,
    vendor: str,
    product: str,
    axis_policy: str,
    query_resolver: QueryIdentityResolver | None = None,
) -> IdentityResolution:
    vendor_key, product_key = normalize_key(vendor), normalize_key(product)
    vendor_clusters = _matching_vendor_clusters(connection, vendor)
    product_keys = derived_keys(product)
    seeds: dict[int, dict[str, Any]] = {}
    fuzzy_suggestions: tuple[Mapping[str, Any], ...] = ()
    query_fuzzy = False

    # T0: exact raw entity key.
    for row in connection.execute(
        """SELECT n.node_id,p.* FROM product_entity p
           JOIN identity_node n USING(product_id)
           WHERE p.vendor_key=? AND p.product_key=?
           ORDER BY p.product_id""",
        (vendor_key, product_key),
    ):
        seeds[int(row["node_id"])] = {
            "tier": "T0_EXACT",
            "strict": True,
            "matched_key_kind": "safe",
        }

    # T0 is defined by the exact (vendor_key, product_key) pair, not by part.
    # The same exact product can legitimately have separate a/o/unknown
    # entities and clusters because part is evaluated later as an
    # applicability axis.  Remember that the cascade found a direct anchor so
    # those part-specific clusters are not mistaken for alias ambiguity.
    has_exact_anchor = bool(seeds)

    # T1 raw observation or separator match, constrained by vendor cluster.
    if not seeds and vendor_clusters:
        marks = ",".join("?" for _ in vendor_clusters)
        sql = f"""SELECT DISTINCT n.node_id,p.*,vc.cluster_id AS vendor_cluster,
                          k.key_kind,k.origin
                   FROM identity_key k
                   JOIN identity_node n USING(node_id)
                   JOIN product_entity p USING(product_id)
                   JOIN identity_node vn
                     ON vn.scope_kind='vendor' AND vn.vendor_key=p.vendor_key
                   JOIN identity_cluster_member vm ON vm.node_id=vn.node_id
                   JOIN identity_cluster vc ON vc.cluster_id=vm.cluster_id
                   WHERE n.scope_kind='product'
                     AND vc.cluster_id IN ({marks})
                     AND ((k.key_kind='safe' AND k.key_value=?)
                       OR (k.key_kind='separator' AND k.key_value=?))"""
        params = [*vendor_clusters, product_keys.get("safe", ""), product_keys.get("separator", "")]
        for row in connection.execute(sql, tuple(params)):
            vendor_tier = vendor_clusters[int(row["vendor_cluster"])]
            origin = str(row["origin"])
            if str(row["key_kind"]) == "safe" and origin == "canonical_entity":
                key_tier, key_strict = "T0_EXACT", True
            elif origin == "registry_strict":
                key_tier, key_strict = "T2_REGISTRY", True
            elif origin == "registry_non_strict":
                key_tier, key_strict = "T2_REGISTRY", False
            else:
                key_tier, key_strict = "T1_FORMAT", True
            tier = max((vendor_tier, key_tier), key=lambda item: TIER_RANK[item])
            seeds[int(row["node_id"])] = {
                "tier": tier,
                "strict": key_strict,
                "matched_key_kind": str(row["key_kind"]),
            }

    if not seeds:
        resolver = query_resolver or QueryIdentityResolver(connection)
        seeds, fuzzy_suggestions, fuzzy_ambiguous = resolver.fuzzy_product_seeds(
            vendor=vendor,
            product=product,
            exact_vendor_clusters=vendor_clusters,
        )
        if fuzzy_ambiguous:
            return IdentityResolution(
                state="insufficient_data",
                reason="product_fuzzy_ambiguous",
                products=(),
                suggestions=fuzzy_suggestions,
            )
        if seeds:
            # One unique logical fuzzy anchor may legitimately fan out to
            # part-specific clusters, just like a T0 (vendor, product) pair.
            has_exact_anchor = True
            query_fuzzy = True

    if not seeds:
        suggestions = fuzzy_suggestions or tuple(
            dict(row)
            for row in connection.execute(
                """SELECT p.product_id,p.canonical_vendor,p.canonical_product,p.part
                   FROM product_entity p
                   WHERE p.product_key LIKE ? OR p.vendor_key LIKE ?
                   ORDER BY p.product_key LIMIT 10""",
                (f"%{product_keys.get('safe','')}%", f"%{vendor_key}%"),
            )
        )
        return IdentityResolution(
            state="insufficient_data",
            reason="product_unresolved",
            products=(),
            suggestions=suggestions,
        )

    seed_clusters: set[int] = set()
    expanded: dict[int, dict[str, Any]] = {}
    for seed, seed_meta in seeds.items():
        path = _path_candidates(connection, seed)
        for node, meta in path.items():
            tier = max(
                (str(seed_meta["tier"]), str(meta["tier"])),
                key=lambda item: TIER_RANK[item],
            )
            strict = bool(seed_meta["strict"]) and bool(meta["strict"])
            candidate = {
                **meta,
                "tier": tier,
                "strict": strict,
                "matched_key_kind": seed_meta["matched_key_kind"],
                "seed_node_id": seed,
                "query_match": seed_meta.get("query_match"),
            }
            cluster_id = meta.get("cluster_id")
            if cluster_id is not None:
                seed_clusters.add(int(cluster_id))
            previous = expanded.get(node)
            if previous is None or (
                TIER_RANK[tier], not strict, len(candidate.get("edge_ids", []))
            ) < (
                TIER_RANK[str(previous["tier"])],
                not bool(previous["strict"]),
                len(previous.get("edge_ids", [])),
            ):
                expanded[node] = candidate

    # Multiple clusters are ambiguous only when they were reached through
    # alias/key expansion.  Direct T0 matches that differ only by entity/part
    # materialization remain one exact query identity; _query_axes handles a
    # multi-part result conservatively by setting the part axis to UNKNOWN.
    ambiguous = not has_exact_anchor and len(seed_clusters) > 1
    if ambiguous and axis_policy != "broad_discovery":
        return IdentityResolution(
            state="insufficient_data",
            reason="product_ambiguous",
            products=(),
            ambiguous_clusters=tuple(sorted(seed_clusters)),
        )

    products: list[ResolvedProduct] = []
    for node, meta in sorted(expanded.items()):
        row = connection.execute(
            """SELECT p.* FROM identity_node n
               JOIN product_entity p USING(product_id)
               WHERE n.node_id=? AND n.scope_kind='product'""",
            (node,),
        ).fetchone()
        if row is None:
            continue
        strict = bool(meta["strict"]) and not ambiguous
        tier = str(meta["tier"])
        products.append(
            ResolvedProduct(
                product_id=int(row["product_id"]),
                vendor_key=str(row["vendor_key"]),
                product_key=str(row["product_key"]),
                part=str(row["part"]),
                canonical_vendor=str(row["canonical_vendor"]),
                canonical_product=str(row["canonical_product"]),
                identity={
                    "tier": tier,
                    "strict_eligible": strict,
                    "max_result_state": None if strict else "potentially_affected",
                    "cluster_id": meta.get("cluster_id"),
                    "matched_key_kind": meta.get("matched_key_kind"),
                    "alias_class": meta.get("alias_class"),
                    "evidence_tier": meta.get("evidence_tier"),
                    "edge_ids": list(meta.get("edge_ids", [])),
                    "ambiguous": ambiguous,
                    "query_match": meta.get("query_match"),
                },
            )
        )
    return IdentityResolution(
        state="resolved",
        reason=("identity_fuzzy_resolved" if query_fuzzy else "identity_resolved"),
        products=tuple(products),
        ambiguous_clusters=tuple(sorted(seed_clusters)) if ambiguous else (),
    )
