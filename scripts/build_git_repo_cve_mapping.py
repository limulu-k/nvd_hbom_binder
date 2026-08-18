#!/usr/bin/env python3
"""Build a conservative GitHub repository -> CVE lookup database.

This program intentionally separates two problems:

1. NVD normalization/binding: already solved inside ``nvd_applicability.sqlite``.
2. GitHub repository matching: solved here by direct names and NVD references.

The matcher does *not* perform a corpus-wide fuzzy/Jaccard/LCS sweep.  It creates
repository/product anchors in the following order:

1. exact ``vendor_key@product_key == owner@repo``;
2. NVD-reference-backed product-name/alias/acronym anchors;
3. strict identity-cluster expansion, only when the repository has reference
   evidence for that cluster;
4. vendor-identity-backed same-product-key propagation.  A shared product key
   is only a candidate; the source and target vendor must also be connected by
   a strict DB identity, a product-scoped registry rule, a raw alias on the
   same product entity, or a conservative legal/organisation suffix variant.

The output database is self-contained and queryable by ``owner@repo``.  The
critical ``repo_product_map`` table is kept in addition to ``repo2cve`` and
``cve_info`` because without it there is no way to audit why a CVE was inherited
or to remove one bad repository/product bridge without rebuilding everything.

Examples
--------

Build::

    python3 scripts/build_git_repo_cve_mapping.py build \
      --db workspace/nvd_applicability.sqlite \
      --git-dir git \
      --output-db workspace/repo_cve.sqlite

The NVD JSONL is normally discovered from ``source_snapshot_manifest.source_path``.
Use ``--nvd-jsonl`` when that file moved after the normalization DB was built.

Query::

    python3 scripts/build_git_repo_cve_mapping.py query \
      --mapping-db workspace/repo_cve.sqlite \
      mongodb@mongo

The returned CVEs are the product-level candidate universe.  ``cve_version_range``
carries the active version assertions copied from the normalization DB so a
concrete version can be filtered here; the normalization query engine remains
authoritative for full axis/policy evaluation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence
from urllib.parse import unquote, urlparse

SCRIPT_VERSION = "repo-cve-direct-reference-1.3.0"
DEFAULT_SOURCE_DB = Path("workspace/nvd_applicability.sqlite")
DEFAULT_GIT_DIR = Path("git")
DEFAULT_OUTPUT_DB = Path("workspace/repo_cve.sqlite")
DEFAULT_IDENTITY_REGISTRY = Path(__file__).with_name("repo_identity_registry_v1.json")

# A small high-confidence seed is embedded so copying only this script does not
# silently disable the identity registry.  An external registry is merged on top.
BUILTIN_IDENTITY_REGISTRY: dict[str, Any] = {
    "registry_version": "repo-identity-registry-built-in-1.2.0",
    "vendor_aliases": [
        {"left": "mysql", "right": "oracle_corporation", "product_keys": ["mysql", "mysql_server"], "basis": "Oracle ownership of MySQL; product-scoped"},
        {"left": "mysql", "right": "oracle", "product_keys": ["mysql", "mysql_server"], "basis": "Oracle ownership of MySQL; product-scoped"},
        {"left": "curl", "right": "haxx", "product_keys": ["curl"], "basis": "official curl project vendor namespace"},
        {"left": "libvirt", "right": "redhat", "product_keys": ["libvirt"], "basis": "official libvirt namespace relation"},
        {"left": "libvirt", "right": "red_hat", "product_keys": ["libvirt"], "basis": "official libvirt namespace relation"},
        {"left": "mupdf", "right": "artifex", "product_keys": ["mupdf"], "basis": "MuPDF is maintained by Artifex"},
        {"left": "artifexsoftware", "right": "artifex", "product_keys": ["mupdf"], "basis": "GitHub organization and NVD vendor namespace variant"},
        {"left": "mediawiki", "right": "wikimedia_foundation", "product_keys": ["mediawiki"], "basis": "MediaWiki project and Wikimedia Foundation namespace"},
        {"left": "mailman", "right": "gnu", "product_keys": ["mailman"], "basis": "GNU Mailman project namespace"},
        {"left": "bento4", "right": "axiosys", "product_keys": ["bento4"], "basis": "official Bento4 vendor namespace"},
        {"left": "openssh", "right": "openbsd", "product_keys": ["openssh"], "basis": "OpenSSH is maintained by the OpenBSD project"},
        {"left": "mongodb_js", "right": "mongodb", "product_keys": ["mongosh"], "basis": "official MongoDB JavaScript organization namespace"},
        {"left": "gnome", "right": "xmlsoft", "product_keys": ["libxml2"], "basis": "official libxml2 upstream namespace"},
        {"left": "keycloak", "right": "redhat", "product_keys": ["keycloak"], "basis": "official Keycloak and Red Hat namespace relation"},
        {"left": "xen_project", "right": "xen", "product_keys": ["xen"], "basis": "official Xen Project namespace"},
        {"left": "xenproject", "right": "xen", "product_keys": ["xen"], "basis": "official Xen Project namespace"},
        {"left": "asterisk", "right": "digium", "product_keys": ["asterisk"], "basis": "official Asterisk/Digium namespace relation"}
    ],
    "repo_product_aliases": [
        {"repo_key": "apache@httpd", "vendor": "apache", "product": "http_server", "basis": "official Apache HTTP Server repository name"},
        {"repo_key": "apache@httpd", "vendor": "apache_software_foundation", "product": "http_server", "basis": "official Apache HTTP Server repository and ASF vendor namespace"},
        {"repo_key": "openssh@openssh-portable", "vendor": "openbsd", "product": "openssh", "basis": "official portable OpenSSH source repository"}
    ],
    "blocked_repo_products": [
        {"repo_key": "jina-ai@reader", "vendor": "adobe", "product": "reader", "basis": "unrelated Adobe Reader product"},
        {"repo_key": "jina-ai@reader", "vendor": "foxit", "product": "reader", "basis": "unrelated Foxit Reader product"},
        {"repo_key": "jina-ai@reader", "vendor": "foxitsoftware", "product": "reader", "basis": "unrelated Foxit Reader product"},
        {"repo_key": "nextcloud@android", "vendor": "google", "product": "android", "basis": "Nextcloud Android app is not Android OS"},
        {"repo_key": "nextcloud@android", "vendor": "samsung", "product": "android", "basis": "Nextcloud Android app is not Samsung Android OS"},
        {"repo_key": "chrome-php@chrome", "vendor": "google", "product": "chrome", "basis": "PHP package is not Google Chrome"},
        {"repo_key": "edge-js@edge", "vendor": "microsoft", "product": "edge", "basis": "JavaScript bridge is not Microsoft Edge"},
        {"repo_key": "redwoodjs@sdk", "vendor": "sun", "product": "sdk", "basis": "RedwoodJS SDK is not Sun SDK"},
        {"repo_key": "golang@net", "vendor": "microsoft", "product": "net", "basis": "Go net package is not Microsoft .NET"}
    ]
}

REQUIRED_SOURCE_OBJECTS = {
    "raw_cve",
    "product_entity",
    "current_binding",
    "source_snapshot_manifest",
}

# Strong artifact-role words denote a separate deliverable rather than a mere
# spelling variant.  They are never removed during matching.
ARTIFACT_ROLE_TOKENS = frozenset(
    {
        "driver",
        "drivers",
        "binding",
        "bindings",
        "sdk",
        "plugin",
        "plugins",
        "module",
        "modules",
        "operator",
        "operators",
        "shell",
        "cli",
        "agent",
        "proxy",
        "connector",
        "adapter",
        "wrapper",
        "extension",
        "extensions",
        "library",
        "libraries",
        "lib",
        "tool",
        "tools",
        "toolkit",
        "docs",
        "examples",
        "samples",
        "demo",
        "app",
        "apps",
        "mobile",
        "desktop",
        "theme",
        "themes",
        "wordpress",
        "wp",
        "frontend",
        "backend",
    }
)
LANGUAGE_TOKENS = frozenset(
    {
        "c",
        "cpp",
        "cxx",
        "go",
        "golang",
        "java",
        "javascript",
        "js",
        "typescript",
        "ts",
        "python",
        "py",
        "ruby",
        "rb",
        "php",
        "rust",
        "dotnet",
        "net",
        "node",
        "nodejs",
        "android",
        "ios",
    }
)
GENERIC_PRODUCT_KEYS = frozenset(
    {
        "app",
        "application",
        "client",
        "core",
        "driver",
        "firmware",
        "framework",
        "library",
        "linux",
        "manager",
        "module",
        "plugin",
        "server",
        "service",
        "software",
        "system",
        "tool",
        "web",
        # Collision-heavy real product names.  These are not inherently
        # invalid, but same-key propagation requires an explicit curated
        # vendor identity for them.
        "reader",
        "android",
        "commerce",
        "java",
        "connect",
        "notes",
        "echo",
        "fabric",
        "discovery",
        "terminal",
    }
)

VENDOR_ORG_SUFFIX_TOKENS = frozenset(
    {
        "project",
        "projects",
        "foundation",
        "inc",
        "incorporated",
        "corporation",
        "corp",
        "company",
        "co",
        "ltd",
        "limited",
        "llc",
        "gmbh",
        "org",
        "organization",
        "organisation",
        "team",
        "group",
    }
)
VENDOR_ORG_SUFFIX_SEQUENCES = (
    ("software", "foundation"),
    ("open", "source", "project"),
)
REFERENCE_VARIANT_TOKENS = frozenset({"portable", "source", "src"})
BLOCKING_RELATION_WORDS = (
    "component",
    "plugin",
    "module",
    "driver",
    "binding",
    "sdk",
    "fork",
    "mirror",
    "downstream",
    "packag",
    "distribution",
    "edition",
    "variant",
    "client_of",
    "server_of",
)
GITHUB_HOSTS = {
    "github.com",
    "www.github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "codeload.github.com",
}
GITHUB_NON_REPO_ROOTS = {
    "about",
    "advisories",
    "apps",
    "collections",
    "contact",
    "customer-stories",
    "enterprise",
    "events",
    "explore",
    "features",
    "gist",
    "git-guides",
    "issues",
    "marketplace",
    "new",
    "notifications",
    "orgs",
    "pricing",
    "pulls",
    "search",
    "security",
    "settings",
    "site",
    "sponsors",
    "topics",
    "trending",
    "users",
}

MATCH_PRIORITY = {
    "exact_pair": 100,
    "reference_exact_product": 95,
    "reference_separator_alias": 92,
    "reference_strict_alias": 90,
    "reference_owner_product_composition": 88,
    "reference_acronym": 85,
    "reference_curated_product_alias": 84,
    "reference_product_variant": 83,
    "reference_prefix_abbreviation": 82,
    "strict_cluster_expansion": 75,
    "vendor_identity_product_key_bridge": 65,
}


class BuildError(RuntimeError):
    """Raised when an input contract is violated."""


def normalize_key(value: str | None) -> str:
    """NFKC + casefold + separator folding, matching the normalization DB."""

    if value is None:
        return ""
    normalized = unicodedata.normalize("NFKC", value).casefold().strip()
    normalized = re.sub(r"[^\w]+", "_", normalized, flags=re.UNICODE)
    return normalized.strip("_")


def compact_key(value: str | None) -> str:
    return normalize_key(value).replace("_", "")


def name_tokens(value: str | None) -> tuple[str, ...]:
    return tuple(token for token in normalize_key(value).split("_") if token)


def acronym(value: str | None) -> str:
    tokens = name_tokens(value)
    if len(tokens) < 2:
        return ""
    return "".join(token[0] for token in tokens if token)


def unordered_pair(left: str, right: str) -> tuple[str, str]:
    return tuple(sorted((normalize_key(left), normalize_key(right))))


def strip_vendor_organisation_suffix(value: str | None) -> str:
    """Return a conservative vendor core for legal/organisation variants.

    Only trailing legal or project markers are removed.  Brand-bearing words
    such as ``software``, ``ai`` and ``io`` are not removed on their own.
    """

    tokens = list(name_tokens(value))
    if tokens and tokens[0] == "the":
        tokens.pop(0)
    changed = True
    while tokens and changed:
        changed = False
        for sequence in VENDOR_ORG_SUFFIX_SEQUENCES:
            if len(tokens) >= len(sequence) and tuple(tokens[-len(sequence) :]) == sequence:
                del tokens[-len(sequence) :]
                changed = True
                break
        if tokens and tokens[-1] in VENDOR_ORG_SUFFIX_TOKENS:
            tokens.pop()
            changed = True
    return "_".join(tokens)


def strip_reference_variant_tokens(value: str | None) -> str:
    tokens = [token for token in name_tokens(value) if token not in REFERENCE_VARIANT_TOKENS]
    return "_".join(tokens)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def chunked(items: Sequence[Any], size: int) -> Iterator[Sequence[Any]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


@dataclass(slots=True)
class Repository:
    repo_key: str
    owner: str
    name: str
    owner_key: str
    name_key: str
    languages: set[str] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class Product:
    product_id: int
    vendor_key: str
    product_key: str
    part: str
    canonical_vendor: str
    canonical_product: str


@dataclass(slots=True)
class Candidate:
    repo_key: str
    product_id: int
    method: str
    evidence_cves: set[str] = field(default_factory=set)
    reference_urls: set[str] = field(default_factory=set)
    anchor_product_id: int | None = None
    cluster_id: int | None = None
    vendor_identity_basis: str = ""
    reason: str = ""

    @property
    def priority(self) -> int:
        return MATCH_PRIORITY[self.method]

    @property
    def evidence_count(self) -> int:
        return len(self.evidence_cves)


@dataclass(slots=True)
class IdentityData:
    product_to_cluster: dict[int, int] = field(default_factory=dict)
    cluster_to_products: dict[int, set[int]] = field(default_factory=lambda: defaultdict(set))
    strict_clusters: set[int] = field(default_factory=set)
    hard_distinct: set[tuple[int, int]] = field(default_factory=set)
    relation_blockers: set[tuple[int, int]] = field(default_factory=set)
    strict_vendor_pairs: set[tuple[str, str]] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class VendorAliasRule:
    left: str
    right: str
    product_keys: frozenset[str]
    basis: str


@dataclass(slots=True)
class RepoIdentityRegistry:
    vendor_alias_rules: list[VendorAliasRule] = field(default_factory=list)
    repo_product_aliases: dict[tuple[str, str, str], str] = field(default_factory=dict)
    blocked_repo_products: dict[tuple[str, str, str], str] = field(default_factory=dict)
    source_labels: list[str] = field(default_factory=list)


def table_exists(connection: sqlite3.Connection, name: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name=? AND type IN ('table','view')",
            (name,),
        ).fetchone()
        is not None
    )


def table_columns(connection: sqlite3.Connection, name: str) -> set[str]:
    return {str(row[1]) for row in connection.execute(f"PRAGMA table_info({name})")}


def validate_source_db(connection: sqlite3.Connection) -> None:
    present = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
        )
    }
    missing = sorted(REQUIRED_SOURCE_OBJECTS - present)
    if missing:
        raise BuildError("normalization DB is missing required objects: " + ", ".join(missing))

    health = None
    if "metadata" in present:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key='publish_health'"
        ).fetchone()
        health = None if row is None else str(row[0])
    if health and health.startswith("blocked_"):
        raise BuildError(f"normalization DB publish health is blocked: {health}")


def infer_language(path: Path) -> str:
    stem = path.stem.casefold()
    match = re.search(r"(?:sample_)?([a-z0-9+#]+)_git$", stem)
    if match:
        return match.group(1)
    return stem


def load_repositories(git_dir: Path) -> dict[str, Repository]:
    if not git_dir.is_dir():
        raise BuildError(f"git corpus directory does not exist: {git_dir}")

    repositories: dict[str, Repository] = {}
    normalized_owner_repo: dict[tuple[str, str], str] = {}
    for path in sorted(git_dir.glob("*.txt")):
        language = infer_language(path)
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, raw in enumerate(handle, 1):
                value = raw.strip()
                if not value or value.startswith("#"):
                    continue
                if value.count("@") != 1:
                    raise BuildError(f"invalid owner@repo at {path}:{line_number}: {value!r}")
                owner, name = value.split("@", 1)
                owner = owner.strip()
                name = name.strip()
                if not owner or not name:
                    raise BuildError(f"empty owner/repo at {path}:{line_number}")
                owner_key, name_key = normalize_key(owner), normalize_key(name)
                pair = (owner_key, name_key)
                canonical_key = normalized_owner_repo.get(pair)
                if canonical_key is None:
                    canonical_key = f"{owner}@{name}"
                    normalized_owner_repo[pair] = canonical_key
                    repositories[canonical_key] = Repository(
                        repo_key=canonical_key,
                        owner=owner,
                        name=name,
                        owner_key=owner_key,
                        name_key=name_key,
                    )
                repositories[canonical_key].languages.add(language)
    return repositories


def corpus_lookup(repositories: Mapping[str, Repository]) -> dict[tuple[str, str], str]:
    return {(repo.owner_key, repo.name_key): key for key, repo in repositories.items()}


def github_repo_from_url(url: str) -> tuple[str, str] | None:
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return None
    host = parsed.netloc.casefold().split(":", 1)[0]
    if host not in GITHUB_HOSTS:
        return None
    segments = [unquote(item) for item in parsed.path.split("/") if item]
    if host == "api.github.com":
        if len(segments) < 3 or segments[0].casefold() != "repos":
            return None
        owner, repo = segments[1], segments[2]
    else:
        if len(segments) < 2:
            return None
        owner, repo = segments[0], segments[1]
    if owner.casefold() in GITHUB_NON_REPO_ROOTS:
        return None
    repo = repo.removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner):
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", repo):
        return None
    return normalize_key(owner), normalize_key(repo)


def iter_reference_urls(value: Any) -> Iterator[str]:
    """Yield URL strings found specifically below keys named references."""

    def urls_from_reference_node(node: Any) -> Iterator[str]:
        if isinstance(node, str):
            if "://" in node:
                yield node
            return
        if isinstance(node, list):
            for child in node:
                yield from urls_from_reference_node(child)
            return
        if isinstance(node, dict):
            for key, child in node.items():
                if key.casefold() in {"url", "href"} and isinstance(child, str):
                    yield child
                elif isinstance(child, (dict, list)):
                    yield from urls_from_reference_node(child)

    if isinstance(value, dict):
        for key, child in value.items():
            if key.casefold() == "references":
                yield from urls_from_reference_node(child)
            elif isinstance(child, (dict, list)):
                yield from iter_reference_urls(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_reference_urls(child)


def record_cve_id(record: Mapping[str, Any]) -> str | None:
    cve = record.get("cve")
    if isinstance(cve, dict):
        value = cve.get("id")
        if isinstance(value, str):
            return value
    metadata = record.get("cveMetadata")
    if isinstance(metadata, dict):
        value = metadata.get("cveId")
        if isinstance(value, str):
            return value
    for key in ("cve_id", "cveId", "id"):
        value = record.get(key)
        if isinstance(value, str) and value.startswith("CVE-"):
            return value
    return None


def discover_nvd_jsonl(connection: sqlite3.Connection, override: Path | None) -> Path:
    if override is not None:
        if not override.is_file():
            raise BuildError(f"--nvd-jsonl does not exist: {override}")
        return override
    row = connection.execute(
        """SELECT source_path FROM source_snapshot_manifest
           ORDER BY snapshot_id DESC LIMIT 1"""
    ).fetchone()
    if row is None or not row[0]:
        raise BuildError("source_snapshot_manifest has no source_path; pass --nvd-jsonl")
    path = Path(str(row[0]))
    if not path.is_file():
        raise BuildError(
            f"snapshot JSONL from manifest is unavailable: {path}; pass --nvd-jsonl"
        )
    return path


def scan_github_references(
    jsonl_path: Path,
    repositories: Mapping[str, Repository],
    valid_cves: set[str],
) -> tuple[
    dict[str, set[str]],
    dict[tuple[str, str], set[str]],
    dict[str, int],
]:
    """Return CVE->repo, (CVE,repo)->URLs, and scan statistics."""

    lookup = corpus_lookup(repositories)
    repos_by_cve: dict[str, set[str]] = defaultdict(set)
    urls_by_cve_repo: dict[tuple[str, str], set[str]] = defaultdict(set)
    stats = Counter()
    out_of_corpus_repositories: set[tuple[str, str]] = set()

    github_markers = (
        b"github.com",
        b"api.github.com",
        b"raw.githubusercontent.com",
        b"codeload.github.com",
    )
    with jsonl_path.open("rb") as handle:
        for line_number, raw in enumerate(handle, 1):
            stats["lines"] += 1
            lowered = raw.lower()
            if not any(marker in lowered for marker in github_markers):
                continue
            stats["github_candidate_lines"] += 1
            try:
                record = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                stats["json_errors"] += 1
                continue
            if not isinstance(record, dict):
                continue
            cve_id = record_cve_id(record)
            if not cve_id or cve_id not in valid_cves:
                stats["not_current_cve"] += 1
                continue
            found_for_record: set[str] = set()
            for url in iter_reference_urls(record):
                pair = github_repo_from_url(url)
                if pair is None:
                    continue
                repo_key = lookup.get(pair)
                if repo_key is None:
                    stats["github_repo_not_in_corpus"] += 1
                    out_of_corpus_repositories.add(pair)
                    continue
                found_for_record.add(repo_key)
                bucket = urls_by_cve_repo[(cve_id, repo_key)]
                if len(bucket) < 5:
                    bucket.add(url)
            if found_for_record:
                repos_by_cve[cve_id].update(found_for_record)
    # These are distinct-CVE and distinct-(CVE,repo) metrics.  Older builds
    # incremented per JSONL record, which over-counted duplicate revisions.
    stats["cves_with_corpus_github_reference"] = len(repos_by_cve)
    stats["cve_repo_reference_pairs"] = sum(len(repos) for repos in repos_by_cve.values())
    stats["unique_github_repos_not_in_corpus"] = len(out_of_corpus_repositories)
    return repos_by_cve, urls_by_cve_repo, dict(stats)


def load_products(
    connection: sqlite3.Connection,
) -> tuple[dict[int, Product], dict[tuple[str, str], list[int]], dict[str, list[int]]]:
    products: dict[int, Product] = {}
    by_pair: dict[tuple[str, str], list[int]] = defaultdict(list)
    by_product: dict[str, list[int]] = defaultdict(list)
    cursor = connection.execute(
        """SELECT product_id,vendor_key,product_key,part,
                  canonical_vendor,canonical_product
           FROM product_entity
           ORDER BY product_id"""
    )
    for row in cursor:
        product = Product(
            product_id=int(row[0]),
            vendor_key=str(row[1]),
            product_key=str(row[2]),
            part=str(row[3]),
            canonical_vendor=str(row[4]),
            canonical_product=str(row[5]),
        )
        products[product.product_id] = product
        by_pair[(product.vendor_key, product.product_key)].append(product.product_id)
        by_product[product.product_key].append(product.product_id)
    return products, by_pair, by_product


def load_identity_data(
    connection: sqlite3.Connection,
    products: Mapping[int, Product],
) -> IdentityData:
    data = IdentityData()

    if table_exists(connection, "identity_cluster") and table_exists(
        connection, "identity_cluster_member"
    ):
        cluster_columns = table_columns(connection, "identity_cluster")
        member_columns = table_columns(connection, "identity_cluster_member")
        select_columns = ["m.cluster_id", "m.product_id"]
        select_columns.append(
            "COALESCE(c.strict_eligible,0)" if "strict_eligible" in cluster_columns else "1"
        )
        select_columns.append(
            "c.review_state" if "review_state" in cluster_columns else "'ok'"
        )
        if "strict_eligible" in member_columns:
            select_columns.append("COALESCE(m.strict_eligible,0)")
        elif "join_tier" in member_columns:
            select_columns.append("CASE WHEN m.join_tier='T3_PROVISIONAL' THEN 0 ELSE 1 END")
        else:
            select_columns.append("1")
        scope_clause = "AND c.scope_kind='product'" if "scope_kind" in cluster_columns else ""
        sql = f"""SELECT {','.join(select_columns)}
                  FROM identity_cluster_member m
                  JOIN identity_cluster c USING(cluster_id)
                  WHERE m.product_id IS NOT NULL {scope_clause}"""
        for cluster_id, product_id, cluster_strict, review_state, member_strict in connection.execute(sql):
            cid, pid = int(cluster_id), int(product_id)
            data.product_to_cluster[pid] = cid
            if bool(cluster_strict) and str(review_state) == "ok" and bool(member_strict):
                data.cluster_to_products[cid].add(pid)
                data.strict_clusters.add(cid)

        # Some DB revisions also contain strict vendor-scope clusters.  The
        # member schema varies across revisions, so recover vendor keys from
        # whichever stable column is available.
        if "scope_kind" in cluster_columns:
            strict_expr = (
                "COALESCE(strict_eligible,0)=1"
                if "strict_eligible" in cluster_columns
                else "1=1"
            )
            review_expr = (
                "COALESCE(review_state,'ok')='ok'"
                if "review_state" in cluster_columns
                else "1=1"
            )
            strict_vendor_clusters = {
                int(row[0])
                for row in connection.execute(
                    f"""SELECT cluster_id FROM identity_cluster
                        WHERE scope_kind='vendor'
                          AND {strict_expr}
                          AND {review_expr}"""
                )
            }
            vendors_by_cluster: dict[int, set[str]] = defaultdict(set)
            if strict_vendor_clusters:
                if "vendor_key" in member_columns:
                    placeholders = ",".join("?" for _ in strict_vendor_clusters)
                    for cluster_id, vendor_key in connection.execute(
                        f"""SELECT cluster_id,vendor_key
                            FROM identity_cluster_member
                            WHERE cluster_id IN ({placeholders})
                              AND vendor_key IS NOT NULL""",
                        tuple(sorted(strict_vendor_clusters)),
                    ):
                        vendors_by_cluster[int(cluster_id)].add(normalize_key(str(vendor_key)))
                elif "product_id" in member_columns:
                    placeholders = ",".join("?" for _ in strict_vendor_clusters)
                    for cluster_id, product_id in connection.execute(
                        f"""SELECT cluster_id,product_id
                            FROM identity_cluster_member
                            WHERE cluster_id IN ({placeholders})
                              AND product_id IS NOT NULL""",
                        tuple(sorted(strict_vendor_clusters)),
                    ):
                        product = products.get(int(product_id))
                        if product is not None:
                            vendors_by_cluster[int(cluster_id)].add(product.vendor_key)
            for vendors in vendors_by_cluster.values():
                ordered = sorted(vendor for vendor in vendors if vendor)
                for index, left in enumerate(ordered):
                    for right in ordered[index + 1 :]:
                        data.strict_vendor_pairs.add(unordered_pair(left, right))

    if table_exists(connection, "identity_hard_distinct") and table_exists(
        connection, "identity_node"
    ):
        hard_columns = table_columns(connection, "identity_hard_distinct")
        if {"left_node_id", "right_node_id"}.issubset(hard_columns):
            sql = """SELECT l.product_id,r.product_id
                     FROM identity_hard_distinct h
                     JOIN identity_node l ON l.node_id=h.left_node_id
                     JOIN identity_node r ON r.node_id=h.right_node_id
                     WHERE l.product_id IS NOT NULL AND r.product_id IS NOT NULL"""
            for left, right in connection.execute(sql):
                data.hard_distinct.add(tuple(sorted((int(left), int(right)))))

    if table_exists(connection, "product_relation"):
        columns = table_columns(connection, "product_relation")
        if {"from_product_id", "to_product_id", "relation_type"}.issubset(columns):
            for left, right, relation_type in connection.execute(
                "SELECT from_product_id,to_product_id,relation_type FROM product_relation"
            ):
                relation = str(relation_type).casefold()
                if any(word in relation for word in BLOCKING_RELATION_WORDS):
                    data.relation_blockers.add(tuple(sorted((int(left), int(right)))))
    return data


def load_raw_alias_pairs(
    connection: sqlite3.Connection,
    products: Mapping[int, Product],
) -> tuple[dict[tuple[str, str], set[int]], set[tuple[str, tuple[str, str]]]]:
    result: dict[tuple[str, str], set[int]] = defaultdict(set)
    vendor_aliases: set[tuple[str, tuple[str, str]]] = set()
    if not table_exists(connection, "product_alias"):
        return result, vendor_aliases
    columns = table_columns(connection, "product_alias")
    if not {"product_id", "vendor_raw", "product_raw"}.issubset(columns):
        return result, vendor_aliases
    for product_id, vendor_raw, product_raw in connection.execute(
        "SELECT product_id,vendor_raw,product_raw FROM product_alias"
    ):
        pid = int(product_id)
        raw_vendor = normalize_key(str(vendor_raw))
        raw_product = normalize_key(str(product_raw))
        result[(raw_vendor, raw_product)].add(pid)
        product = products.get(pid)
        if product is not None and raw_vendor and raw_vendor != product.vendor_key:
            vendor_aliases.add(
                (product.product_key, unordered_pair(product.vendor_key, raw_vendor))
            )
    return result, vendor_aliases


def _merge_repo_identity_payload(
    registry: RepoIdentityRegistry, payload: Mapping[str, Any], source_label: str
) -> None:
    if source_label not in registry.source_labels:
        registry.source_labels.append(source_label)

    existing_vendor_rules = {
        (unordered_pair(rule.left, rule.right), rule.product_keys)
        for rule in registry.vendor_alias_rules
    }
    for raw_rule in payload.get("vendor_aliases", []):
        if not isinstance(raw_rule, dict):
            continue
        left = normalize_key(str(raw_rule.get("left", "")))
        right = normalize_key(str(raw_rule.get("right", "")))
        normalized_product_keys: set[str] = set()
        for value in raw_rule.get("product_keys", ["*"]):
            raw_value = str(value).strip()
            if raw_value:
                normalized_product_keys.add(
                    "*" if raw_value == "*" else normalize_key(raw_value)
                )
        product_keys = frozenset(normalized_product_keys)
        key = (unordered_pair(left, right), product_keys)
        if not left or not right or left == right or not product_keys or key in existing_vendor_rules:
            continue
        registry.vendor_alias_rules.append(
            VendorAliasRule(
                left=left,
                right=right,
                product_keys=product_keys,
                basis=str(raw_rule.get("basis", "curated_vendor_alias")),
            )
        )
        existing_vendor_rules.add(key)

    for raw_rule in payload.get("repo_product_aliases", []):
        if not isinstance(raw_rule, dict):
            continue
        repo_key = str(raw_rule.get("repo_key", "")).strip()
        vendor = normalize_key(str(raw_rule.get("vendor", "")))
        product = normalize_key(str(raw_rule.get("product", "")))
        if repo_key.count("@") != 1 or not vendor or not product:
            continue
        owner, repo = repo_key.split("@", 1)
        canonical_repo_key = f"{normalize_key(owner)}@{normalize_key(repo)}"
        registry.repo_product_aliases[(canonical_repo_key, vendor, product)] = str(
            raw_rule.get("basis", "curated_repo_product_alias")
        )

    for raw_rule in payload.get("blocked_repo_products", []):
        if not isinstance(raw_rule, dict):
            continue
        repo_key = str(raw_rule.get("repo_key", "")).strip()
        vendor_raw = str(raw_rule.get("vendor", "")).strip()
        product_raw = str(raw_rule.get("product", "")).strip()
        if repo_key.count("@") != 1 or not vendor_raw or not product_raw:
            continue
        owner, repo = repo_key.split("@", 1)
        canonical_repo_key = f"{normalize_key(owner)}@{normalize_key(repo)}"
        vendor = "*" if vendor_raw == "*" else normalize_key(vendor_raw)
        product = "*" if product_raw == "*" else normalize_key(product_raw)
        registry.blocked_repo_products[(canonical_repo_key, vendor, product)] = str(
            raw_rule.get("basis", "curated_repo_product_block")
        )


def load_repo_identity_registry(path: Path | None) -> RepoIdentityRegistry:
    registry = RepoIdentityRegistry()
    _merge_repo_identity_payload(registry, BUILTIN_IDENTITY_REGISTRY, "built_in_seed")
    if path is None or not path.is_file():
        return registry
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BuildError(f"invalid repository identity registry {path}: {error}") from error
    if not isinstance(payload, dict):
        raise BuildError(f"identity registry must be a JSON object: {path}")
    _merge_repo_identity_payload(registry, payload, str(path.resolve()))
    return registry


def registry_product_block_reason(
    repo: Repository, product: Product, registry: RepoIdentityRegistry
) -> str | None:
    canonical_repo_key = f"{repo.owner_key}@{repo.name_key}"
    candidates = (
        (canonical_repo_key, product.vendor_key, product.product_key),
        (canonical_repo_key, "*", product.product_key),
        (canonical_repo_key, product.vendor_key, "*"),
        (canonical_repo_key, "*", "*"),
    )
    for key in candidates:
        basis = registry.blocked_repo_products.get(key)
        if basis:
            return f"curated_repo_product_block:{basis}"
    return None


def build_reference_product_evidence(
    connection: sqlite3.Connection,
    repos_by_cve: Mapping[str, set[str]],
    urls_by_cve_repo: Mapping[tuple[str, str], set[str]],
) -> tuple[
    dict[tuple[str, int], set[str]],
    dict[tuple[str, int], set[str]],
    dict[int, dict[str, int]],
]:
    evidence_cves: dict[tuple[str, int], set[str]] = defaultdict(set)
    evidence_urls: dict[tuple[str, int], set[str]] = defaultdict(set)
    product_repo_counts: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for cve_id, product_id in connection.execute(
        "SELECT cve_id,product_id FROM current_binding"
    ):
        cve = str(cve_id)
        repos = repos_by_cve.get(cve)
        if not repos:
            continue
        pid = int(product_id)
        for repo_key in repos:
            key = (repo_key, pid)
            if cve not in evidence_cves[key]:
                evidence_cves[key].add(cve)
                product_repo_counts[pid][repo_key] += 1
            if len(evidence_urls[key]) < 10:
                evidence_urls[key].update(urls_by_cve_repo.get((cve, repo_key), ()))
    return evidence_cves, evidence_urls, product_repo_counts


def separator_equal(left: str, right: str) -> bool:
    return compact_key(left) == compact_key(right) and normalize_key(left) != normalize_key(right)


def prefix_abbreviation(left: str, right: str) -> bool:
    a, b = compact_key(left), compact_key(right)
    if not a or not b or a == b:
        return False
    short, long = sorted((a, b), key=len)
    return len(short) >= 4 and len(short) / len(long) >= 0.60 and long.startswith(short)


def acronym_match(left: str, right: str) -> bool:
    a, b = compact_key(left), compact_key(right)
    if not a or not b or a == b:
        return False
    return (2 <= len(a) <= 8 and a == acronym(right)) or (
        2 <= len(b) <= 8 and b == acronym(left)
    )


def artifact_role_conflict(repo: Repository, product: Product) -> str | None:
    repo_tokens = set(name_tokens(repo.name))
    product_tokens = set(name_tokens(product.product_key))
    repo_roles = repo_tokens & ARTIFACT_ROLE_TOKENS
    product_roles = product_tokens & ARTIFACT_ROLE_TOKENS

    # If both explicitly name artifact roles, they must agree.
    if repo_roles and product_roles and repo_roles != product_roles:
        return f"artifact_role_mismatch:{sorted(repo_roles)}!={sorted(product_roles)}"

    # A role-bearing repository must not collapse onto the unqualified product.
    if repo_roles and not product_roles:
        return f"repo_is_distinct_artifact:{sorted(repo_roles)}"

    # Different language drivers/bindings are distinct products.
    if (repo_roles | product_roles) & {"driver", "drivers", "binding", "bindings", "sdk"}:
        repo_lang = repo_tokens & LANGUAGE_TOKENS
        product_lang = product_tokens & LANGUAGE_TOKENS
        if repo_lang and product_lang and repo_lang.isdisjoint(product_lang):
            return f"artifact_language_mismatch:{sorted(repo_lang)}!={sorted(product_lang)}"
    return None


def part_compatible(left: Product, right: Product) -> bool:
    if left.part == right.part:
        return True
    parts = {left.part, right.part}
    # Unknown application identity must not bridge into operating-system or
    # hardware CPEs.  This was the path behind nextcloud/android -> Android OS.
    if "unknown" in parts and parts & {"o", "h"}:
        return False
    # Hardware and OS identities only cross a wildcard when the other side is
    # the same concrete part; unknown is never sufficient evidence.
    if "h" in parts:
        return parts <= {"h", "*"}
    if "o" in parts:
        return parts <= {"o", "*"}
    if "unknown" in parts or "*" in parts:
        return parts <= {"a", "unknown", "*"}
    return False


def pair_blocked(identity: IdentityData, left: int, right: int) -> bool:
    pair = tuple(sorted((left, right)))
    return pair in identity.hard_distinct or pair in identity.relation_blockers


def vendor_identity_basis(
    left_vendor: str,
    right_vendor: str,
    product_key: str,
    identity: IdentityData,
    raw_vendor_aliases: set[tuple[str, tuple[str, str]]],
    registry: RepoIdentityRegistry,
) -> str | None:
    left = normalize_key(left_vendor)
    right = normalize_key(right_vendor)
    if not left or not right:
        return None
    if left == right:
        return "vendor_exact"
    if compact_key(left) == compact_key(right):
        return "vendor_separator_variant"

    pair = unordered_pair(left, right)
    if pair in identity.strict_vendor_pairs:
        return "strict_vendor_cluster"
    if (normalize_key(product_key), pair) in raw_vendor_aliases:
        return "product_alias_vendor"

    for rule in registry.vendor_alias_rules:
        if unordered_pair(rule.left, rule.right) != pair:
            continue
        normalized_product = normalize_key(product_key)
        if "*" in rule.product_keys or normalized_product in rule.product_keys:
            return f"curated_vendor_alias:{rule.basis}"

    left_core = strip_vendor_organisation_suffix(left)
    right_core = strip_vendor_organisation_suffix(right)
    if (
        left_core
        and right_core
        and len(compact_key(left_core)) >= 4
        and compact_key(left_core) == compact_key(right_core)
    ):
        return "vendor_organisation_suffix_variant"
    return None


def reference_name_method(
    repo: Repository,
    product: Product,
    identity: IdentityData,
    raw_vendor_aliases: set[tuple[str, tuple[str, str]]],
    registry: RepoIdentityRegistry,
) -> str | None:
    vendor_exact = repo.owner_key == product.vendor_key
    vendor_separator = compact_key(repo.owner_key) == compact_key(product.vendor_key)
    product_exact = repo.name_key == product.product_key
    product_separator = compact_key(repo.name_key) == compact_key(product.product_key)
    vendor_basis = vendor_identity_basis(
        repo.owner_key,
        product.vendor_key,
        product.product_key,
        identity,
        raw_vendor_aliases,
        registry,
    )
    normalized_repo_key = f"{repo.owner_key}@{repo.name_key}"
    if (
        normalized_repo_key,
        product.vendor_key,
        product.product_key,
    ) in registry.repo_product_aliases:
        return "reference_curated_product_alias"

    # The function is called only for a product bound to a CVE that directly
    # references this corpus repository.  With that evidence, an exact product
    # name is sufficient even when owner and NVD vendor namespaces differ.
    # This recovers axiosys/Bento4, gnu/LibreDWG, google/TensorFlow, etc., while
    # unrelated same-name bridges without a direct reference remain impossible.
    if product_exact:
        return "reference_exact_product"

    # Owner/vendor prefix abbreviation is deliberately not treated as identity.
    # It recovers some aliases but also revives angular/angular -> angularjs.
    reference_vendor_compatible = vendor_basis is not None

    if product_separator and (
        vendor_exact or vendor_separator or reference_vendor_compatible
    ):
        return "reference_separator_alias"

    # Common official-repository form: vendor/product is rendered as one repo
    # name, e.g. mongodb + go_driver -> mongo-go-driver.  This is accepted only
    # on a direct NVD reference and only when the non-product prefix identifies
    # the owner/vendor.
    repo_compact = compact_key(repo.name)
    product_compact = compact_key(product.product_key)
    if product_compact and repo_compact.endswith(product_compact):
        prefix = repo_compact[: -len(product_compact)]
        owner_compact = compact_key(repo.owner)
        vendor_compact = compact_key(product.vendor_key)
        if prefix and (
            prefix in {owner_compact, vendor_compact}
            or prefix_abbreviation(prefix, owner_compact)
            or prefix_abbreviation(prefix, vendor_compact)
        ):
            return "reference_owner_product_composition"

    if acronym_match(repo.name, product.product_key) and reference_vendor_compatible:
        return "reference_acronym"
    if (
        compact_key(strip_reference_variant_tokens(repo.name))
        == compact_key(product.product_key)
        and compact_key(repo.name) != compact_key(product.product_key)
        and reference_vendor_compatible
    ):
        return "reference_product_variant"
    if prefix_abbreviation(repo.name, product.product_key) and reference_vendor_compatible:
        return "reference_prefix_abbreviation"
    return None


def candidate_better(new: Candidate, old: Candidate) -> bool:
    return (new.priority, new.evidence_count, -new.product_id) > (
        old.priority,
        old.evidence_count,
        -old.product_id,
    )


def add_candidate(
    candidates: dict[tuple[str, int], Candidate], candidate: Candidate
) -> None:
    key = (candidate.repo_key, candidate.product_id)
    previous = candidates.get(key)
    if previous is None or candidate_better(candidate, previous):
        candidates[key] = candidate
    elif previous.method == candidate.method:
        previous.evidence_cves.update(candidate.evidence_cves)
        previous.reference_urls.update(candidate.reference_urls)


def build_candidates(
    repositories: Mapping[str, Repository],
    products: Mapping[int, Product],
    by_pair: Mapping[tuple[str, str], list[int]],
    by_product: Mapping[str, list[int]],
    raw_alias_pairs: Mapping[tuple[str, str], set[int]],
    raw_vendor_aliases: set[tuple[str, tuple[str, str]]],
    registry: RepoIdentityRegistry,
    identity: IdentityData,
    evidence_cves: Mapping[tuple[str, int], set[str]],
    evidence_urls: Mapping[tuple[str, int], set[str]],
    product_repo_counts: Mapping[int, Mapping[str, int]],
) -> tuple[dict[tuple[str, int], Candidate], list[dict[str, Any]]]:
    candidates: dict[tuple[str, int], Candidate] = {}
    rejected: list[dict[str, Any]] = []

    # 1. Exact owner@repo == vendor@product anchors.
    for repo_key, repo in repositories.items():
        for product_id in by_pair.get((repo.owner_key, repo.name_key), ()):
            add_candidate(
                candidates,
                Candidate(
                    repo_key=repo_key,
                    product_id=product_id,
                    method="exact_pair",
                    evidence_cves=set(evidence_cves.get((repo_key, product_id), ())),
                    reference_urls=set(evidence_urls.get((repo_key, product_id), ())),
                    reason="vendor_key/product_key exactly equal owner/repo",
                ),
            )

    # 2. Direct NVD-reference-backed name anchors.  Candidate generation is
    # limited to product/repo pairs that co-occurred in one current CVE.
    for (repo_key, product_id), cves in evidence_cves.items():
        repo = repositories[repo_key]
        product = products[product_id]
        block_reason = registry_product_block_reason(repo, product, registry)
        if block_reason:
            rejected.append(
                {
                    "repo_key": repo_key,
                    "product_id": product_id,
                    "reason": block_reason,
                    "stage": "reference_anchor",
                }
            )
            continue
        conflict = artifact_role_conflict(repo, product)
        if conflict:
            rejected.append(
                {
                    "repo_key": repo_key,
                    "product_id": product_id,
                    "reason": conflict,
                    "stage": "reference_anchor",
                }
            )
            continue
        method = reference_name_method(
            repo,
            product,
            identity,
            raw_vendor_aliases,
            registry,
        )
        if method is None and product_id in raw_alias_pairs.get(
            (repo.owner_key, repo.name_key), set()
        ):
            method = "reference_separator_alias"
        if method is None:
            continue

        reference_vendor_basis = vendor_identity_basis(
            repo.owner_key,
            product.vendor_key,
            product.product_key,
            identity,
            raw_vendor_aliases,
            registry,
        ) or ""
        if method == "reference_exact_product" and not reference_vendor_basis:
            reference_vendor_basis = "direct_reference_exact_product"
        if method == "reference_curated_product_alias":
            registry_key = (
                f"{repo.owner_key}@{repo.name_key}",
                product.vendor_key,
                product.product_key,
            )
            reference_vendor_basis = (
                "curated_repo_product_alias:"
                + registry.repo_product_aliases.get(
                    registry_key, "curated_repo_product_alias"
                )
            )

        # A product referenced by several name-compatible corpus repositories is
        # ambiguous.  Keep only a unique highest-evidence repository.
        compatible_counts: list[tuple[int, str]] = []
        for other_repo_key, count in product_repo_counts.get(product_id, {}).items():
            other_repo = repositories[other_repo_key]
            if (
                reference_name_method(
                    other_repo,
                    product,
                    identity,
                    raw_vendor_aliases,
                    registry,
                )
                is not None
            ):
                compatible_counts.append((int(count), other_repo_key))
        compatible_counts.sort(reverse=True)
        if compatible_counts:
            top_count = compatible_counts[0][0]
            top_repos = {key for count, key in compatible_counts if count == top_count}
            if repo_key not in top_repos or len(top_repos) != 1:
                rejected.append(
                    {
                        "repo_key": repo_key,
                        "product_id": product_id,
                        "reason": "ambiguous_reference_repo_claim",
                        "stage": "reference_anchor",
                    }
                )
                continue
        add_candidate(
            candidates,
            Candidate(
                repo_key=repo_key,
                product_id=product_id,
                method=method,
                evidence_cves=set(cves),
                reference_urls=set(evidence_urls.get((repo_key, product_id), ())),
                vendor_identity_basis=reference_vendor_basis,
                reason="current CVE binds product and references this corpus repository",
            ),
        )

    # 3. Expand only strict, review-clean NVD identity clusters.  Alias
    # expansion is allowed only when this repo has at least one direct reference
    # to any member of the cluster.
    cluster_repo_reference: dict[tuple[int, str], set[str]] = defaultdict(set)
    cluster_repo_urls: dict[tuple[int, str], set[str]] = defaultdict(set)
    for (repo_key, product_id), cves in evidence_cves.items():
        cluster_id = identity.product_to_cluster.get(product_id)
        if cluster_id is None:
            continue
        cluster_repo_reference[(cluster_id, repo_key)].update(cves)
        cluster_repo_urls[(cluster_id, repo_key)].update(
            evidence_urls.get((repo_key, product_id), ())
        )

    snapshot = list(candidates.values())
    for anchor in snapshot:
        cluster_id = identity.product_to_cluster.get(anchor.product_id)
        if cluster_id is None or cluster_id not in identity.strict_clusters:
            continue
        reference_key = (cluster_id, anchor.repo_key)
        if not cluster_repo_reference.get(reference_key):
            continue
        repo = repositories[anchor.repo_key]
        anchor_product = products[anchor.product_id]
        for product_id in identity.cluster_to_products.get(cluster_id, ()):
            if product_id == anchor.product_id:
                continue
            product = products[product_id]
            if pair_blocked(identity, anchor.product_id, product_id):
                continue
            if not part_compatible(anchor_product, product):
                continue
            conflict = artifact_role_conflict(repo, product)
            if conflict:
                rejected.append(
                    {
                        "repo_key": anchor.repo_key,
                        "product_id": product_id,
                        "reason": conflict,
                        "stage": "strict_cluster_expansion",
                    }
                )
                continue
            add_candidate(
                candidates,
                Candidate(
                    repo_key=anchor.repo_key,
                    product_id=product_id,
                    method="strict_cluster_expansion",
                    evidence_cves=set(cluster_repo_reference[reference_key]),
                    reference_urls=set(cluster_repo_urls[reference_key]),
                    anchor_product_id=anchor.product_id,
                    cluster_id=cluster_id,
                    reason="strict identity cluster, gated by repository reference evidence",
                ),
            )

    # 4. Product-key propagation across vendor variations.  A shared product
    # key is only candidate retrieval; the vendor axis must independently prove
    # identity.  This prevents corpus-coverage accidents such as jina-ai/reader
    # inheriting Adobe/Foxit Reader or nextcloud/android inheriting Android OS.
    product_key_repo_anchors: dict[str, set[str]] = defaultdict(set)
    product_key_anchor_ids: dict[tuple[str, str], list[int]] = defaultdict(list)
    for candidate in candidates.values():
        product = products[candidate.product_id]
        product_key_repo_anchors[product.product_key].add(candidate.repo_key)
        product_key_anchor_ids[(product.product_key, candidate.repo_key)].append(
            candidate.product_id
        )

    vendor_basis_rank = {
        "vendor_exact": 6,
        "vendor_separator_variant": 5,
        "strict_vendor_cluster": 5,
        "product_alias_vendor": 5,
        "vendor_organisation_suffix_variant": 4,
    }

    for product_key, product_ids in by_product.items():
        if len(product_key) < 4:
            continue
        repos = product_key_repo_anchors.get(product_key, set())
        if len(repos) != 1:
            continue
        repo_key = next(iter(repos))
        repo = repositories[repo_key]
        anchor_ids = product_key_anchor_ids[(product_key, repo_key)]
        for product_id in product_ids:
            if (repo_key, product_id) in candidates:
                continue
            product = products[product_id]
            block_reason = registry_product_block_reason(repo, product, registry)
            if block_reason:
                rejected.append(
                    {
                        "repo_key": repo_key,
                        "product_id": product_id,
                        "reason": block_reason,
                        "stage": "vendor_identity_product_key_bridge",
                    }
                )
                continue

            # A direct reference to a different corpus repository always wins
            # over fallback propagation.
            competing = {
                key for key in product_repo_counts.get(product_id, {}) if key != repo_key
            }
            if competing:
                rejected.append(
                    {
                        "repo_key": repo_key,
                        "product_id": product_id,
                        "reason": "competing_direct_repository_reference",
                        "stage": "vendor_identity_product_key_bridge",
                    }
                )
                continue

            viable: list[tuple[int, int, int, str, Candidate]] = []
            failure_reasons: set[str] = set()
            for anchor_id in anchor_ids:
                anchor_product = products[anchor_id]
                anchor_candidate = candidates[(repo_key, anchor_id)]
                # A direct reference with an exact product name proves only that
                # repo/product pair.  When owner and vendor are unrelated, it
                # must not become a transitive bridge seed for every other vendor
                # sharing the same product key (mysqljs/mysql was the key case).
                if (
                    anchor_candidate.method == "reference_exact_product"
                    and anchor_candidate.vendor_identity_basis
                    == "direct_reference_exact_product"
                ):
                    failure_reasons.add(
                        "anchor_lacks_independent_vendor_identity"
                    )
                    continue
                if pair_blocked(identity, anchor_id, product_id):
                    failure_reasons.add("hard_distinct_or_relation_blocker")
                    continue
                if not part_compatible(anchor_product, product):
                    failure_reasons.add(
                        f"part_incompatible:{anchor_product.part}!={product.part}"
                    )
                    continue
                conflict = artifact_role_conflict(repo, product)
                if conflict:
                    failure_reasons.add(conflict)
                    continue

                bases: list[str] = []
                for source_vendor in {anchor_product.vendor_key, repo.owner_key}:
                    basis = vendor_identity_basis(
                        source_vendor,
                        product.vendor_key,
                        product_key,
                        identity,
                        raw_vendor_aliases,
                        registry,
                    )
                    if basis is not None:
                        bases.append(basis)
                if not bases:
                    failure_reasons.add("no_vendor_identity_evidence")
                    continue

                def basis_score(value: str) -> int:
                    if value.startswith("curated_vendor_alias:"):
                        return 7
                    return vendor_basis_rank.get(value, 0)

                best_basis = max(bases, key=lambda value: (basis_score(value), value))
                if product_key in GENERIC_PRODUCT_KEYS and not (
                    best_basis.startswith("curated_vendor_alias:")
                    or best_basis in {"strict_vendor_cluster", "product_alias_vendor"}
                ):
                    failure_reasons.add(
                        "generic_product_key_requires_curated_or_db_vendor_identity"
                    )
                    continue
                viable.append(
                    (
                        basis_score(best_basis),
                        anchor_candidate.priority,
                        anchor_candidate.evidence_count,
                        best_basis,
                        anchor_candidate,
                    )
                )

            if not viable:
                rejected.append(
                    {
                        "repo_key": repo_key,
                        "product_id": product_id,
                        "reason": ";".join(sorted(failure_reasons))
                        or "no_compatible_vendor_identity_anchor",
                        "stage": "vendor_identity_product_key_bridge",
                    }
                )
                continue

            _, _, _, basis, anchor_candidate = max(viable)
            add_candidate(
                candidates,
                Candidate(
                    repo_key=repo_key,
                    product_id=product_id,
                    method="vendor_identity_product_key_bridge",
                    evidence_cves=set(anchor_candidate.evidence_cves),
                    reference_urls=set(anchor_candidate.reference_urls),
                    anchor_product_id=anchor_candidate.product_id,
                    cluster_id=identity.product_to_cluster.get(product_id),
                    vendor_identity_basis=basis,
                    reason=(
                        "same product_key plus independent vendor identity: " + basis
                    ),
                ),
            )

    return candidates, rejected


def resolve_product_claim_conflicts(
    candidates: Mapping[tuple[str, int], Candidate],
) -> tuple[list[Candidate], list[dict[str, Any]]]:
    """Conservatively enforce one repository per product_id."""

    by_product: dict[int, list[Candidate]] = defaultdict(list)
    for candidate in candidates.values():
        by_product[candidate.product_id].append(candidate)

    accepted: list[Candidate] = []
    rejected: list[dict[str, Any]] = []
    for product_id, claims in by_product.items():
        claims.sort(
            key=lambda item: (item.priority, item.evidence_count, item.repo_key),
            reverse=True,
        )
        best = claims[0]
        tied = [
            item
            for item in claims
            if (item.priority, item.evidence_count)
            == (best.priority, best.evidence_count)
        ]
        if len(tied) > 1:
            for item in claims:
                rejected.append(
                    {
                        "repo_key": item.repo_key,
                        "product_id": product_id,
                        "reason": "ambiguous_equal_rank_product_claim",
                        "stage": "cross_repo_conflict",
                    }
                )
            continue
        accepted.append(best)
        for item in claims[1:]:
            rejected.append(
                {
                    "repo_key": item.repo_key,
                    "product_id": product_id,
                    "reason": f"superseded_by:{best.repo_key}:{best.method}",
                    "stage": "cross_repo_conflict",
                }
            )
    accepted.sort(key=lambda item: (item.repo_key.casefold(), item.product_id))
    return accepted, rejected


def validate_accepted_mappings(mappings: Sequence[Candidate]) -> None:
    for mapping in mappings:
        if (
            mapping.method == "vendor_identity_product_key_bridge"
            and not mapping.vendor_identity_basis
        ):
            raise BuildError(
                "vendor bridge accepted without vendor identity basis: "
                f"{mapping.repo_key} -> {mapping.product_id}"
            )


def create_output_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        PRAGMA foreign_keys=ON;
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;

        CREATE TABLE build_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        ) WITHOUT ROWID;

        CREATE TABLE cve_info (
            cve_id TEXT PRIMARY KEY,
            source_identifier TEXT,
            vuln_status TEXT NOT NULL,
            published TEXT,
            last_modified TEXT,
            primary_description TEXT,
            enrichment_class TEXT NOT NULL,
            admission_status TEXT NOT NULL
        ) WITHOUT ROWID;

        CREATE TABLE repo_product_map (
            mapping_id INTEGER PRIMARY KEY,
            repo_key TEXT NOT NULL,
            owner TEXT NOT NULL,
            repo TEXT NOT NULL,
            owner_key TEXT NOT NULL,
            repo_name_key TEXT NOT NULL,
            languages TEXT NOT NULL,
            product_id INTEGER NOT NULL,
            vendor_key TEXT NOT NULL,
            product_key TEXT NOT NULL,
            part TEXT NOT NULL,
            canonical_vendor TEXT NOT NULL,
            canonical_product TEXT NOT NULL,
            match_method TEXT NOT NULL,
            match_priority INTEGER NOT NULL,
            anchor_product_id INTEGER,
            identity_cluster_id INTEGER,
            vendor_identity_basis TEXT NOT NULL,
            reference_cve_count INTEGER NOT NULL,
            reference_cves_json TEXT NOT NULL,
            reference_urls_json TEXT NOT NULL,
            reason TEXT NOT NULL,
            UNIQUE (repo_key,product_id)
        );

        CREATE TABLE repo2cve (
            repo_key TEXT NOT NULL,
            cve_id TEXT NOT NULL REFERENCES cve_info(cve_id),
            product_id INTEGER NOT NULL,
            mapping_id INTEGER NOT NULL REFERENCES repo_product_map(mapping_id),
            binding_id INTEGER NOT NULL,
            match_method TEXT NOT NULL,
            enrichment_class TEXT NOT NULL,
            provisional_llm_identity INTEGER NOT NULL,
            manual_review_required INTEGER NOT NULL,
            PRIMARY KEY (repo_key,cve_id,product_id)
        ) WITHOUT ROWID;

        -- Version applicability, carried over from the normalization DB.
        --
        -- Grain is (cve_id, product_id, assertion_id, ordinal), NOT repo_key:
        -- version semantics belong to the CVE/product pair, and several
        -- repositories may legitimately share one product.  Join through
        -- repo2cve (or the repo_cve_version view) to reach a repository.
        --
        -- ``polarity`` must be honoured: a CVE carries both affected and
        -- unaffected segments, and ignoring the unaffected ones inverts the
        -- meaning of a defaultStatus closure.
        CREATE TABLE cve_version_range (
            range_id INTEGER PRIMARY KEY,
            cve_id TEXT NOT NULL REFERENCES cve_info(cve_id),
            product_id INTEGER NOT NULL,
            assertion_id INTEGER NOT NULL,
            scope_id INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            polarity TEXT NOT NULL,
            segment_status TEXT,
            lower_bound TEXT,
            lower_inclusive INTEGER,
            upper_bound TEXT,
            upper_inclusive INTEGER,
            exact_value TEXT,
            version_resolution_class TEXT NOT NULL,
            breadth_class TEXT,
            is_default_closure INTEGER NOT NULL,
            use_for_version_index INTEGER NOT NULL,
            source_family TEXT NOT NULL,
            evidence_tier TEXT,
            cpe_match_role TEXT,
            UNIQUE (assertion_id,ordinal)
        );

        CREATE INDEX repo2cve_repo_idx ON repo2cve(repo_key,cve_id);
        CREATE INDEX repo2cve_cve_idx ON repo2cve(cve_id,repo_key);
        CREATE INDEX repo_product_product_idx ON repo_product_map(product_id);
        CREATE INDEX cve_version_range_cve_idx
            ON cve_version_range(cve_id,product_id);
        CREATE INDEX cve_version_range_product_idx
            ON cve_version_range(product_id);

        CREATE VIEW repo_cve AS
        SELECT repo_key,cve_id,
               MIN(manual_review_required) AS min_manual_review_required,
               MAX(manual_review_required) AS any_manual_review_required,
               MAX(provisional_llm_identity) AS any_provisional_llm_identity,
               COUNT(DISTINCT product_id) AS product_path_count
        FROM repo2cve
        GROUP BY repo_key,cve_id;

        -- Repository-oriented projection of the version ranges.
        CREATE VIEW repo_cve_version AS
        SELECT r.repo_key,r.cve_id,r.product_id,r.match_method,
               r.manual_review_required,r.provisional_llm_identity,
               v.polarity,v.lower_bound,v.lower_inclusive,
               v.upper_bound,v.upper_inclusive,v.exact_value,
               v.version_resolution_class,v.breadth_class,
               v.is_default_closure,v.source_family,v.evidence_tier
        FROM repo2cve r
        JOIN cve_version_range v
          ON v.cve_id=r.cve_id AND v.product_id=r.product_id;

        -- One row per (repo, CVE, product) summarising whether a concrete
        -- affected range exists at all.  ``has_bounded_affected_range=0`` means
        -- the CVE is product-level only and every version must be treated as a
        -- candidate until the normalization query engine is consulted.
        CREATE VIEW repo_cve_version_summary AS
        SELECT r.repo_key,r.cve_id,r.product_id,
               COUNT(v.range_id) AS version_range_count,
               SUM(CASE WHEN v.polarity='affected' THEN 1 ELSE 0 END)
                   AS affected_range_count,
               MAX(CASE WHEN v.polarity='affected'
                         AND (v.lower_bound IS NOT NULL
                              OR v.upper_bound IS NOT NULL
                              OR v.exact_value IS NOT NULL)
                        THEN 1 ELSE 0 END) AS has_bounded_affected_range
        FROM repo2cve r
        LEFT JOIN cve_version_range v
          ON v.cve_id=r.cve_id AND v.product_id=r.product_id
        GROUP BY r.repo_key,r.cve_id,r.product_id;
        """
    )



def populate_version_ranges(
    output: sqlite3.Connection,
    source_connection: sqlite3.Connection,
    product_ids: Sequence[int],
    admitted_cves: set[str],
) -> int:
    """Copy active version assertions for the accepted products.

    Only assertions whose CVE was actually admitted into ``cve_info`` are
    copied, so the foreign key holds and the output stays self-contained.
    ``active_assertion`` already restricts to reconciled rows; both affected
    and unaffected polarities are carried because a defaultStatus closure is
    only interpretable with its unaffected counterpart.
    """

    if not product_ids or not admitted_cves:
        return 0

    source_connection.execute(
        "CREATE TEMP TABLE IF NOT EXISTS selected_product("
        "product_id INTEGER PRIMARY KEY) WITHOUT ROWID"
    )
    source_connection.execute("DELETE FROM selected_product")
    source_connection.executemany(
        "INSERT OR IGNORE INTO selected_product(product_id) VALUES (?)",
        [(int(value),) for value in product_ids],
    )

    sql = """SELECT a.cve_id,sc.product_id,a.assertion_id,a.scope_id,vs.ordinal,
                    a.assertion_polarity,vs.status,
                    vs.lower_bound,vs.lower_inclusive,
                    vs.upper_bound,vs.upper_inclusive,vs.exact_value,
                    a.version_resolution_class,vs.breadth_class,
                    a.is_default_closure,a.use_for_version_index,
                    a.source_family,a.evidence_tier,a.cpe_match_role
             FROM selected_product s
             JOIN applicability_scope sc ON sc.product_id=s.product_id
             JOIN applicability_assertion a ON a.scope_id=sc.scope_id
              AND a.reconciliation_status IN ('active','conflict_review')
             JOIN version_segment vs ON vs.expression_id=a.expression_id"""

    insert = """INSERT OR IGNORE INTO cve_version_range(
                    cve_id,product_id,assertion_id,scope_id,ordinal,
                    polarity,segment_status,lower_bound,lower_inclusive,
                    upper_bound,upper_inclusive,exact_value,
                    version_resolution_class,breadth_class,is_default_closure,
                    use_for_version_index,source_family,evidence_tier,
                    cpe_match_role
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""

    batch: list[tuple[Any, ...]] = []
    written = 0
    for row in source_connection.execute(sql):
        cve_id = str(row[0])
        if cve_id not in admitted_cves:
            continue
        batch.append(
            (
                cve_id,
                int(row[1]),
                int(row[2]),
                int(row[3]),
                int(row[4]),
                str(row[5]),
                row[6],
                row[7],
                None if row[8] is None else int(row[8]),
                row[9],
                None if row[10] is None else int(row[10]),
                row[11],
                str(row[12]),
                row[13],
                int(row[14] or 0),
                int(row[15] or 0),
                str(row[16]),
                row[17],
                row[18],
            )
        )
        if len(batch) >= 10000:
            output.executemany(insert, batch)
            written += len(batch)
            batch.clear()
    if batch:
        output.executemany(insert, batch)
        written += len(batch)
    return written


def populate_output_db(
    output_path: Path,
    source_connection: sqlite3.Connection,
    repositories: Mapping[str, Repository],
    products: Mapping[int, Product],
    mappings: Sequence[Candidate],
    metadata: Mapping[str, Any],
) -> dict[str, int]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    temp_path.unlink(missing_ok=True)
    output = sqlite3.connect(temp_path)
    output.row_factory = sqlite3.Row
    try:
        create_output_schema(output)
        output.executemany(
            "INSERT INTO build_metadata(key,value) VALUES (?,?)",
            [(key, json.dumps(value, ensure_ascii=False, sort_keys=True)) for key, value in metadata.items()],
        )

        mapping_ids: dict[tuple[str, int], int] = {}
        for candidate in mappings:
            repo = repositories[candidate.repo_key]
            product = products[candidate.product_id]
            cursor = output.execute(
                """INSERT INTO repo_product_map(
                       repo_key,owner,repo,owner_key,repo_name_key,languages,
                       product_id,vendor_key,product_key,part,canonical_vendor,canonical_product,
                       match_method,match_priority,anchor_product_id,
                       identity_cluster_id,vendor_identity_basis,reference_cve_count,
                       reference_cves_json,reference_urls_json,reason
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    candidate.repo_key,
                    repo.owner,
                    repo.name,
                    repo.owner_key,
                    repo.name_key,
                    ",".join(sorted(repo.languages)),
                    product.product_id,
                    product.vendor_key,
                    product.product_key,
                    product.part,
                    product.canonical_vendor,
                    product.canonical_product,
                    candidate.method,
                    candidate.priority,
                    candidate.anchor_product_id,
                    candidate.cluster_id,
                    candidate.vendor_identity_basis,
                    candidate.evidence_count,
                    json.dumps(sorted(candidate.evidence_cves), ensure_ascii=False),
                    json.dumps(sorted(candidate.reference_urls), ensure_ascii=False),
                    candidate.reason,
                ),
            )
            mapping_ids[(candidate.repo_key, candidate.product_id)] = int(cursor.lastrowid)

        accepted_products = {candidate.product_id for candidate in mappings}
        candidate_by_key = {
            (candidate.repo_key, candidate.product_id): candidate
            for candidate in mappings
        }
        if not accepted_products:
            output.commit()
            os.replace(temp_path, output_path)
            return {"mappings": 0, "repo2cve": 0, "cves": 0}

        source_connection.execute(
            "CREATE TEMP TABLE IF NOT EXISTS selected_repo_product(repo_key TEXT,product_id INTEGER,PRIMARY KEY(repo_key,product_id)) WITHOUT ROWID"
        )
        source_connection.execute("DELETE FROM selected_repo_product")
        source_connection.executemany(
            "INSERT INTO selected_repo_product(repo_key,product_id) VALUES (?,?)",
            [(candidate.repo_key, candidate.product_id) for candidate in mappings],
        )

        sql = """SELECT s.repo_key,b.product_id,b.cve_id,b.binding_id,
                        b.enrichment_class,b.provisional_llm_identity,
                        b.manual_review_required,
                        r.source_identifier,r.vuln_status,r.published,
                        r.last_modified,r.primary_description,
                        r.enrichment_class,r.admission_status
                 FROM selected_repo_product s
                 JOIN current_binding b USING(product_id)
                 JOIN raw_cve r USING(cve_id)
                 ORDER BY s.repo_key,b.cve_id,b.product_id"""
        cve_seen: set[str] = set()
        repo2cve_count = 0
        cve_batch: list[tuple[Any, ...]] = []
        map_batch: list[tuple[Any, ...]] = []

        def flush_cves() -> None:
            if not cve_batch:
                return
            output.executemany(
                """INSERT OR IGNORE INTO cve_info(
                       cve_id,source_identifier,vuln_status,published,
                       last_modified,primary_description,enrichment_class,
                       admission_status) VALUES (?,?,?,?,?,?,?,?)""",
                cve_batch,
            )
            cve_batch.clear()

        def flush_mappings() -> None:
            if not map_batch:
                return
            flush_cves()
            output.executemany(
                """INSERT OR IGNORE INTO repo2cve(
                       repo_key,cve_id,product_id,mapping_id,binding_id,
                       match_method,enrichment_class,
                       provisional_llm_identity,manual_review_required
                   ) VALUES (?,?,?,?,?,?,?,?,?)""",
                map_batch,
            )
            map_batch.clear()

        for row in source_connection.execute(sql):
            repo_key = str(row[0])
            product_id = int(row[1])
            cve_id = str(row[2])
            if cve_id not in cve_seen:
                cve_seen.add(cve_id)
                cve_batch.append(
                    (
                        cve_id,
                        row[7],
                        str(row[8]),
                        row[9],
                        row[10],
                        row[11],
                        str(row[12]),
                        str(row[13]),
                    )
                )
            candidate = candidate_by_key[(repo_key, product_id)]
            map_batch.append(
                (
                    repo_key,
                    cve_id,
                    product_id,
                    mapping_ids[(repo_key, product_id)],
                    int(row[3]),
                    candidate.method,
                    str(row[4]),
                    int(row[5]),
                    int(row[6]),
                )
            )
            repo2cve_count += 1
            if len(cve_batch) >= 5000:
                flush_cves()
            if len(map_batch) >= 10000:
                flush_mappings()
        flush_mappings()
        flush_cves()

        version_rows = populate_version_ranges(
            output, source_connection, sorted(accepted_products), cve_seen
        )

        output.execute("ANALYZE")
        output.commit()
        counts = {
            "mappings": int(output.execute("SELECT COUNT(*) FROM repo_product_map").fetchone()[0]),
            "repo2cve": int(output.execute("SELECT COUNT(*) FROM repo2cve").fetchone()[0]),
            "repo_cve_distinct": int(output.execute("SELECT COUNT(*) FROM repo_cve").fetchone()[0]),
            "cves": int(output.execute("SELECT COUNT(*) FROM cve_info").fetchone()[0]),
            "repos": int(output.execute("SELECT COUNT(DISTINCT repo_key) FROM repo_product_map").fetchone()[0]),
            "strict_repo2cve": int(
                output.execute(
                    """SELECT COUNT(*) FROM repo2cve
                       WHERE manual_review_required=0
                         AND provisional_llm_identity=0"""
                ).fetchone()[0]
            ),
            "strict_repo_cve_distinct": int(
                output.execute(
                    """SELECT COUNT(*) FROM repo_cve
                       WHERE any_manual_review_required=0
                         AND any_provisional_llm_identity=0"""
                ).fetchone()[0]
            ),
            "manual_review_repo2cve": int(
                output.execute(
                    "SELECT COUNT(*) FROM repo2cve WHERE manual_review_required=1"
                ).fetchone()[0]
            ),
            "provisional_llm_repo2cve": int(
                output.execute(
                    "SELECT COUNT(*) FROM repo2cve WHERE provisional_llm_identity=1"
                ).fetchone()[0]
            ),
            "mappings_without_current_binding": int(
                output.execute(
                    """SELECT COUNT(*) FROM repo_product_map rpm
                       WHERE NOT EXISTS (
                           SELECT 1 FROM repo2cve r WHERE r.mapping_id=rpm.mapping_id
                       )"""
                ).fetchone()[0]
            ),
            "cve_version_ranges": version_rows,
            "cve_version_affected_ranges": int(
                output.execute(
                    "SELECT COUNT(*) FROM cve_version_range WHERE polarity='affected'"
                ).fetchone()[0]
            ),
            "repo2cve_with_version_range": int(
                output.execute(
                    """SELECT COUNT(*) FROM repo2cve r
                       WHERE EXISTS (
                           SELECT 1 FROM cve_version_range v
                           WHERE v.cve_id=r.cve_id AND v.product_id=r.product_id
                       )"""
                ).fetchone()[0]
            ),
            "repo2cve_with_bounded_affected_range": int(
                output.execute(
                    """SELECT COUNT(*) FROM repo_cve_version_summary
                       WHERE has_bounded_affected_range=1"""
                ).fetchone()[0]
            ),
        }
    finally:
        output.close()
    os.replace(temp_path, output_path)
    return counts


def _count_text_lines(path: Path) -> int:
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for _ in handle)


def write_audit_files(
    audit_dir: Path,
    mappings: Sequence[Candidate],
    rejected: Sequence[Mapping[str, Any]],
    repositories: Mapping[str, Repository],
    products: Mapping[int, Product],
    summary: Mapping[str, Any],
) -> dict[str, Any]:
    audit_dir.parent.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(
        tempfile.mkdtemp(prefix=f".{audit_dir.name}.tmp-", dir=audit_dir.parent)
    )
    try:
        accepted_path = temp_dir / "accepted_repo_product.jsonl"
        rejected_path = temp_dir / "rejected_repo_product.jsonl"
        with accepted_path.open("w", encoding="utf-8") as handle:
            for item in mappings:
                repo = repositories[item.repo_key]
                product = products[item.product_id]
                handle.write(
                    json.dumps(
                        {
                            "build_id": summary.get("build_id"),
                            "repo_key": item.repo_key,
                            "owner": repo.owner,
                            "repo": repo.name,
                            "product_id": product.product_id,
                            "vendor_key": product.vendor_key,
                            "product_key": product.product_key,
                            "part": product.part,
                            "method": item.method,
                            "priority": item.priority,
                            "anchor_product_id": item.anchor_product_id,
                            "cluster_id": item.cluster_id,
                            "vendor_identity_basis": item.vendor_identity_basis,
                            "reference_cve_count": item.evidence_count,
                            "reference_cves": sorted(item.evidence_cves),
                            "reference_urls": sorted(item.reference_urls),
                            "reason": item.reason,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
        with rejected_path.open("w", encoding="utf-8") as handle:
            for item in rejected:
                record = {"build_id": summary.get("build_id"), **dict(item)}
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")

        audit_info = {
            "directory": str(audit_dir.resolve()),
            "accepted_rows": len(mappings),
            "rejected_rows": len(rejected),
            "replacement_mode": "atomic_fresh_directory",
        }
        audit_summary = {**dict(summary), "audit": audit_info}
        (temp_dir / "summary.json").write_text(
            json.dumps(audit_summary, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (temp_dir / "audit_manifest.json").write_text(
            json.dumps(
                {
                    "build_id": summary.get("build_id"),
                    "built_at": summary.get("built_at"),
                    "script_version": summary.get("script_version"),
                    "output_db": summary.get("output_db"),
                    **audit_info,
                },
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        if _count_text_lines(accepted_path) != len(mappings):
            raise BuildError("accepted audit row count does not match current build")
        if _count_text_lines(rejected_path) != len(rejected):
            raise BuildError("rejected audit row count does not match current build")

        if audit_dir.exists():
            if audit_dir.is_dir():
                shutil.rmtree(audit_dir)
            else:
                audit_dir.unlink()
        os.replace(temp_dir, audit_dir)
        return audit_info
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def build_command(arguments: argparse.Namespace) -> int:
    source_db = Path(arguments.db)
    git_dir = Path(arguments.git_dir)
    output_db = Path(arguments.output_db)
    audit_dir = Path(arguments.audit_dir) if arguments.audit_dir else output_db.parent / (output_db.stem + "_audit")
    if not source_db.is_file():
        raise BuildError(f"source DB does not exist: {source_db}")

    source = sqlite3.connect(source_db.resolve().as_uri() + "?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    try:
        validate_source_db(source)
        repositories = load_repositories(git_dir)
        products, by_pair, by_product = load_products(source)
        identity = load_identity_data(source, products)
        raw_alias_pairs, raw_vendor_aliases = load_raw_alias_pairs(source, products)
        identity_registry_path = (
            Path(arguments.identity_registry)
            if arguments.identity_registry
            else DEFAULT_IDENTITY_REGISTRY
        )
        registry = load_repo_identity_registry(identity_registry_path)
        valid_cves = {str(row[0]) for row in source.execute("SELECT cve_id FROM raw_cve")}
        nvd_jsonl = discover_nvd_jsonl(
            source, Path(arguments.nvd_jsonl) if arguments.nvd_jsonl else None
        )

        repos_by_cve, urls_by_cve_repo, reference_stats = scan_github_references(
            nvd_jsonl, repositories, valid_cves
        )
        evidence_cves, evidence_urls, product_repo_counts = build_reference_product_evidence(
            source, repos_by_cve, urls_by_cve_repo
        )
        candidates, rejected = build_candidates(
            repositories,
            products,
            by_pair,
            by_product,
            raw_alias_pairs,
            raw_vendor_aliases,
            registry,
            identity,
            evidence_cves,
            evidence_urls,
            product_repo_counts,
        )
        mappings, conflict_rejected = resolve_product_claim_conflicts(candidates)
        rejected.extend(conflict_rejected)
        validate_accepted_mappings(mappings)

        method_counts = Counter(item.method for item in mappings)
        built_at = utc_now()
        build_id = f"{SCRIPT_VERSION}:{built_at}:{output_db.resolve()}"
        metadata = {
            "script_version": SCRIPT_VERSION,
            "build_id": build_id,
            "built_at": built_at,
            "source_db": str(source_db.resolve()),
            "output_db": str(output_db.resolve()),
            "audit_dir": str(audit_dir.resolve()),
            "source_db_user_version": int(source.execute("PRAGMA user_version").fetchone()[0]),
            "nvd_jsonl": str(nvd_jsonl.resolve()),
            "git_dir": str(git_dir.resolve()),
            "corpus_repo_count": len(repositories),
            "source_product_count": len(products),
            "source_cve_count": len(valid_cves),
            "identity_registry": (
                str(identity_registry_path.resolve())
                if identity_registry_path.is_file()
                else "built_in_seed"
            ),
            "identity_registry_external": (
                str(identity_registry_path.resolve())
                if identity_registry_path.is_file()
                else None
            ),
            "identity_registry_sources": list(registry.source_labels),
            "identity_registry_vendor_alias_rules": len(registry.vendor_alias_rules),
            "identity_registry_repo_product_aliases": len(registry.repo_product_aliases),
            "identity_registry_blocked_repo_products": len(registry.blocked_repo_products),
            "reference_scan": reference_stats,
            "accepted_method_counts": dict(sorted(method_counts.items())),
            "rejected_candidate_count": len(rejected),
        }
        counts = populate_output_db(
            output_db, source, repositories, products, mappings, metadata
        )
        summary = {**metadata, "output_counts": counts}
        audit_info = write_audit_files(
            audit_dir, mappings, rejected, repositories, products, summary
        )
        summary = {**summary, "audit": audit_info}
        print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))
        return 0
    finally:
        source.close()


def format_version_range(row: Mapping[str, Any]) -> str:
    """Render one version segment as a human-readable interval."""

    exact = row["exact_value"]
    if exact:
        return f"={exact}"
    lower, upper = row["lower_bound"], row["upper_bound"]
    if lower is None and upper is None:
        return "*"
    left = "" if lower is None else f"{lower} {'<=' if row['lower_inclusive'] else '<'} "
    right = "" if upper is None else f" {'<=' if row['upper_inclusive'] else '<'} {upper}"
    return f"{left}v{right}"


def attach_version_ranges(
    connection: sqlite3.Connection,
    repo_key: str,
    rows: Sequence[dict[str, Any]],
) -> None:
    """Attach affected/unaffected version intervals to each CVE row in place."""

    if not rows or not table_exists(connection, "cve_version_range"):
        return
    by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for chunk in chunked([str(row["cve_id"]) for row in rows], 400):
        placeholders = ",".join("?" for _ in chunk)
        for record in connection.execute(
            f"""SELECT cve_id,polarity,lower_bound,lower_inclusive,
                       upper_bound,upper_inclusive,exact_value,
                       version_resolution_class,source_family
                FROM repo_cve_version
                WHERE repo_key=? AND cve_id IN ({placeholders})
                ORDER BY cve_id,polarity,lower_bound""",
            (repo_key, *chunk),
        ):
            by_cve[str(record["cve_id"])].append(dict(record))
    for row in rows:
        records = by_cve.get(str(row["cve_id"]), [])
        affected = [item for item in records if item["polarity"] == "affected"]
        bounded = [
            item
            for item in affected
            if item["lower_bound"] is not None
            or item["upper_bound"] is not None
            or item["exact_value"] is not None
        ]
        row["version_range_count"] = len(records)
        row["has_bounded_affected_range"] = bool(bounded)
        row["affected_versions"] = [format_version_range(item) for item in bounded]
        row["version_source_families"] = sorted(
            {str(item["source_family"]) for item in records}
        )


def query_command(arguments: argparse.Namespace) -> int:
    path = Path(arguments.mapping_db)
    if not path.is_file():
        raise BuildError(f"mapping DB does not exist: {path}")
    repo_key = arguments.repo_key
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        owner_key = repo_name_key = ""
        if repo_key.count("@") == 1:
            raw_owner, raw_repo = repo_key.split("@", 1)
            owner_key, repo_name_key = normalize_key(raw_owner), normalize_key(raw_repo)
        resolved = connection.execute(
            """SELECT repo_key FROM repo_product_map
               WHERE repo_key=? OR (owner_key=? AND repo_name_key=?)
               ORDER BY CASE WHEN repo_key=? THEN 0 ELSE 1 END LIMIT 1""",
            (repo_key, owner_key, repo_name_key, repo_key),
        ).fetchone()
        resolved_repo_key = repo_key if resolved is None else str(resolved[0])
        mapping_rows = [
            dict(row)
            for row in connection.execute(
                """SELECT mapping_id,repo_key,product_id,vendor_key,product_key,
                          part,canonical_vendor,canonical_product,match_method,
                          vendor_identity_basis,reference_cve_count,reason
                   FROM repo_product_map WHERE repo_key=?
                   ORDER BY match_priority DESC,product_id""",
                (resolved_repo_key,),
            )
        ]
        where = "WHERE rc.repo_key=?"
        parameters: list[Any] = [resolved_repo_key]
        if arguments.strict_only:
            where += " AND rc.any_manual_review_required=0 AND rc.any_provisional_llm_identity=0"
        rows = [
            dict(row)
            for row in connection.execute(
                f"""SELECT rc.repo_key,rc.cve_id,rc.product_path_count,
                           rc.any_manual_review_required,
                           rc.any_provisional_llm_identity,
                           c.vuln_status,c.published,c.last_modified,
                           c.primary_description,c.enrichment_class
                    FROM repo_cve rc JOIN cve_info c USING(cve_id)
                    {where}
                    ORDER BY rc.cve_id LIMIT ?""",
                (*parameters, int(arguments.limit)),
            )
        ]
        total = int(
            connection.execute(
                f"SELECT COUNT(*) FROM repo_cve rc {where}", tuple(parameters)
            ).fetchone()[0]
        )
        attach_version_ranges(connection, resolved_repo_key, rows)
        result = {
            "repo_key": resolved_repo_key,
            "requested_repo_key": repo_key,
            "strict_only": bool(arguments.strict_only),
            "mapping_count": len(mapping_rows),
            "mappings": mapping_rows,
            "cve_count": total,
            "returned": len(rows),
            "cves": rows,
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if mapping_rows else 2
    finally:
        connection.close()


def stats_command(arguments: argparse.Namespace) -> int:
    path = Path(arguments.mapping_db)
    if not path.is_file():
        raise BuildError(f"mapping DB does not exist: {path}")
    connection = sqlite3.connect(path)
    try:
        result = {
            "repo_product_map": int(connection.execute("SELECT COUNT(*) FROM repo_product_map").fetchone()[0]),
            "mapped_repos": int(connection.execute("SELECT COUNT(DISTINCT repo_key) FROM repo_product_map").fetchone()[0]),
            "repo2cve_rows": int(connection.execute("SELECT COUNT(*) FROM repo2cve").fetchone()[0]),
            "distinct_repo_cve": int(connection.execute("SELECT COUNT(*) FROM repo_cve").fetchone()[0]),
            "distinct_cves": int(connection.execute("SELECT COUNT(*) FROM cve_info").fetchone()[0]),
            "strict_repo2cve": int(
                connection.execute(
                    """SELECT COUNT(*) FROM repo2cve
                       WHERE manual_review_required=0
                         AND provisional_llm_identity=0"""
                ).fetchone()[0]
            ),
            "strict_repo_cve": int(
                connection.execute(
                    """SELECT COUNT(*) FROM repo_cve
                       WHERE any_manual_review_required=0
                         AND any_provisional_llm_identity=0"""
                ).fetchone()[0]
            ),
            "cve_version_ranges": int(
                connection.execute("SELECT COUNT(*) FROM cve_version_range").fetchone()[0]
            ),
            "repo2cve_with_bounded_affected_range": int(
                connection.execute(
                    """SELECT COUNT(*) FROM repo_cve_version_summary
                       WHERE has_bounded_affected_range=1"""
                ).fetchone()[0]
            ),
            "manual_review_repo2cve": int(
                connection.execute(
                    "SELECT COUNT(*) FROM repo2cve WHERE manual_review_required=1"
                ).fetchone()[0]
            ),
            "provisional_llm_repo2cve": int(
                connection.execute(
                    "SELECT COUNT(*) FROM repo2cve WHERE provisional_llm_identity=1"
                ).fetchone()[0]
            ),
            "methods": {
                str(row[0]): int(row[1])
                for row in connection.execute(
                    "SELECT match_method,COUNT(*) FROM repo_product_map GROUP BY match_method ORDER BY match_method"
                )
            },
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    finally:
        connection.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="build repository-to-CVE SQLite DB")
    build.add_argument("--db", type=Path, default=DEFAULT_SOURCE_DB)
    build.add_argument("--git-dir", type=Path, default=DEFAULT_GIT_DIR)
    build.add_argument("--nvd-jsonl", type=Path)
    build.add_argument(
        "--identity-registry",
        type=Path,
        help=(
            "optional product-scoped vendor/repository identity registry "
            f"(default: {DEFAULT_IDENTITY_REGISTRY})"
        ),
    )
    build.add_argument("--output-db", type=Path, default=DEFAULT_OUTPUT_DB)
    build.add_argument("--audit-dir", type=Path)
    build.set_defaults(func=build_command)

    query = subparsers.add_parser("query", help="query CVEs by owner@repo")
    query.add_argument("repo_key")
    query.add_argument("--mapping-db", type=Path, default=DEFAULT_OUTPUT_DB)
    query.add_argument("--strict-only", action="store_true")
    query.add_argument("--limit", type=int, default=100)
    query.set_defaults(func=query_command)

    stats = subparsers.add_parser("stats", help="show output DB statistics")
    stats.add_argument("--mapping-db", type=Path, default=DEFAULT_OUTPUT_DB)
    stats.set_defaults(func=stats_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        return int(arguments.func(arguments))
    except (BuildError, sqlite3.Error, OSError) as error:
        parser.error(str(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
