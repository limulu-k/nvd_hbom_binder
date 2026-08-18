"""Pinned framework policy used by the staged schema-v5 builder."""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
import re
import unicodedata
from pathlib import Path
from typing import Any

FRAMEWORK_VERSION = "nvd-applicability-3.3.3-llm-safe-admission"
SCHEMA_VERSION = 5
RULE_VERSION = "3.3.3-llm-safe-admission.1"
PROFILE_VERSION = "1.0.0"
FAILURE_TAXONOMY_VERSION = "1.1"
DOTTED_BOUND_POLICY = "literal_endpoint"

IDENTITY_REGISTRY_PATH = Path(__file__).with_name("identity_alias_registry_v1.json")
IDENTITY_REGISTRY_JSON = IDENTITY_REGISTRY_PATH.read_text(encoding="utf-8")
IDENTITY_REGISTRY = json.loads(IDENTITY_REGISTRY_JSON)
IDENTITY_REGISTRY_VERSION = str(IDENTITY_REGISTRY["registry_version"])
IDENTITY_REGISTRY_SHA256 = hashlib.sha256(
    IDENTITY_REGISTRY_JSON.encode("utf-8")
).hexdigest()
IDENTITY_CLUSTER_SIZE_LIMIT = 8
IDENTITY_ALIAS_BUCKET_SIZE_LIMIT = 64
IDENTITY_TYPO_POLICY: dict[str, Any] = {
    # B3 is deliberately narrower than the review-only B2 candidate funnel.
    # Every condition is conjunctive; string similarity by itself never
    # creates an accepted identity edge.
    "vendor": {
        "min_compact_length": 6,
        "min_bigram_jaccard": 0.60,
        "min_lcs_ratio": 0.83,
        "min_shared_product_identities": 3,
    },
    "product": {
        "min_compact_length": 8,
        "min_bigram_jaccard": 0.75,
        "min_lcs_ratio": 0.90,
        "min_distinct_cves": 3,
        "allowed_parts": ["a", "unknown"],
    },
    "common_guards": {
        "exact_edit_distance": 1,
        "same_digit_signature": True,
        "mutual_unique_component_match": True,
        "semantic_chaining": False,
        "max_cluster_size": IDENTITY_CLUSTER_SIZE_LIMIT,
    },
}

LEGAL_SUFFIXES = frozenset(
    {"inc", "incorporated", "corp", "corporation", "ltd", "limited",
     "llc", "gmbh", "plc", "bv"}
)
ORG_SUFFIXES = frozenset(
    {"project", "software", "systems", "networks", "security", "labs",
     "foundation", "group", "org", "team"}
)
SOFT_GENERIC_ANCHORS = frozenset(
    {"core", "cms", "iot", "security", "nas", "agent", "server", "client"}
)
HARD_GENERIC_ANCHORS = frozenset(
    {"cve", "poc", "advisories", "advisory", "vulnerabilities",
     "vulnerability"}
)

PLACEHOLDERS = frozenset(
    {"", "*", "-", "n/a", "na", "none", "null", "unknown", "unspecified"}
)

# This is deliberately an explicit registry, not a name heuristic.  It is
# intentionally short and can be versioned with this module.
DISTRIBUTION_VENDORS = frozenset(
    {
        "almalinux",
        "alpinelinux",
        "amazon",
        "canonical",
        "centos",
        "debian",
        "fedora",
        "gentoo",
        "mageia",
        "opensuse",
        "oracle",
        "redhat",
        "rocky",
        "suse",
        "ubuntu",
    }
)

DISTRIBUTION_PRODUCTS = frozenset(
    {
        "almalinux",
        "alpine_linux",
        "amazon_linux",
        "centos",
        "debian_linux",
        "enterprise_linux",
        "enterprise_linux_desktop",
        "enterprise_linux_server",
        "enterprise_linux_workstation",
        "fedora",
        "linux",
        "linux_enterprise_server",
        "opensuse",
        "oracle_linux",
        "red_hat_enterprise_linux",
        "rocky_linux",
        "sles",
        "suse_linux_enterprise_server",
        "ubuntu_linux",
    }
)

# These vendors are unambiguous distribution/package namespaces. Vendors such
# as Oracle, Red Hat, SUSE, Amazon, and Canonical also publish first-party
# upstream software and therefore require product/context evidence.
DISTRIBUTION_PACKAGE_VENDORS = frozenset(
    {
        "almalinux",
        "alpinelinux",
        "centos",
        "debian",
        "fedora",
        "gentoo",
        "mageia",
        "opensuse",
        "rocky",
        "ubuntu",
    }
)

# Explicit P1 identity aliases only. These are authoritative product spelling
# equivalences, not fuzzy substring rules.
P1_PRODUCT_ALIAS_GROUPS = (
    (("linux", "linux"), ("linux", "linux_kernel")),
)

P1_PRODUCT_KEY_REWRITES = {
    "microsoft": {
        "prefixes": {
            "windows_10_version_": "windows_10_",
            "windows_11_version_": "windows_11_",
        },
        "suffixes": (
            "_edition_server_core_installation",
            "_server_core_installation",
        ),
    },
}

AXES = (
    "part",
    "distribution",
    "edition",
    "component",
    "update",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)

CONTEXT_AXES = frozenset(
    {
        "distribution",
        "edition",
        "component",
        "update",
        "sw_edition",
        "target_sw",
        "target_hw",
        "other",
    }
)

SOURCE_AXIS_PRIORITY = {
    "cna_structured": {
        "identity": 1,
        "relation": 1,
        "version": 1,
        "scope": 1,
    },
    "osv": {"identity": 2, "relation": 2, "version": 2, "scope": 2},
    "ghsa": {"identity": 2, "relation": 2, "version": 2, "scope": 2},
    "nvd_cpe": {"identity": 4, "relation": 5, "version": 3, "scope": 3},
    "advisory_text": {
        "identity": 5,
        "relation": 3,
        "version": 4,
        "scope": 4,
    },
    "llm_description": {
        "identity": 3,
        "relation": 3,
        "version": None,
        "scope": None,
    },
    "rule_ner": {
        "identity": 6,
        "relation": 6,
        "version": None,
        "scope": None,
    },
    "manual_review": {
        "identity": 1,
        "relation": 1,
        "version": 1,
        "scope": 1,
    },
}

_AUTHORITY = {
    "cna_structured": 3,
    "manual_review": 3,
    "osv": 2,
    "ghsa": 2,
    "nvd_cpe": 1,
    "advisory_text": 1,
    "llm_description": 0,
    "rule_ner": 0,
}

_STRUCTUREDNESS = {
    "cna_structured": 2,
    "manual_review": 2,
    "osv": 2,
    "ghsa": 2,
    "nvd_cpe": 2,
    "advisory_text": 0,
    "llm_description": 1,
    "rule_ner": 1,
}

VERSION_SPECIFICITY = {
    "EXACT": 4,
    "BOUNDED_RANGE": 3,
    "BRANCH_RANGE": 3,
    "UNBOUNDED_RANGE": 2,
    "EXPLICIT_ALL": 1,
    "CPE_ANY_UNCORROBORATED": 0,
    "UNSPECIFIED": 0,
    "NOT_APPLICABLE": 0,
    "UNPARSED": 0,
}

DIRECTNESS = {
    "DIRECT_UPSTREAM": 2,
    "DIRECT_ALTERNATIVE_PRODUCT": 1,
    "DOWNSTREAM_DISTRIBUTION": 0,
    "DOWNSTREAM_PACKAGE": 0,
    "REQUIRED_PLATFORM": 0,
    "REQUIRED_HARDWARE": 0,
    "BUNDLED_COMPONENT": 0,
    "UNRESOLVED": 0,
    None: 0,
}

RULE_CONFIGURATION: dict[str, Any] = {
    "framework_version": FRAMEWORK_VERSION,
    "schema_version": SCHEMA_VERSION,
    "identity_alias_registry": {
        "version": IDENTITY_REGISTRY_VERSION,
        "sha256": IDENTITY_REGISTRY_SHA256,
        "cluster_size_limit": IDENTITY_CLUSTER_SIZE_LIMIT,
        "alias_bucket_size_limit": IDENTITY_ALIAS_BUCKET_SIZE_LIMIT,
        "typo_policy": IDENTITY_TYPO_POLICY,
        "raw_entity_merge": False,
        "provisional_strict_positive": False,
    },
    "rule_version": RULE_VERSION,
    "failure_taxonomy_version": FAILURE_TAXONOMY_VERSION,
    "entity_policy": {
        "placeholder_values": sorted(PLACEHOLDERS),
        "automatic_merge": "exact_plus_evidence_backed_resolution",
        "relation_is_identity": False,
        "p1_product_alias_groups": [
            [list(identity) for identity in group]
            for group in P1_PRODUCT_ALIAS_GROUPS
        ],
        "p1_product_key_rewrites": P1_PRODUCT_KEY_REWRITES,
    },
    "cpe_role_policy": {
        "distribution_vendors": sorted(DISTRIBUTION_VENDORS),
        "distribution_products": sorted(DISTRIBUTION_PRODUCTS),
        "distribution_package_vendors": sorted(
            DISTRIBUTION_PACKAGE_VENDORS
        ),
        "unresolved_strict_positive": False,
    },
    "version_bound_policy": {
        "dotted_numeric": DOTTED_BOUND_POLICY,
        "short_bound_is_branch_prefix_only_when_explicit_wildcard": True,
    },
    "version_profiles": {
        "semver": PROFILE_VERSION,
        "dotted_numeric": PROFILE_VERSION,
        "openssl": PROFILE_VERSION,
        "imagemagick": PROFILE_VERSION,
        "deb": PROFILE_VERSION,
        "opaque": PROFILE_VERSION,
    },
    "source_reconciliation_policy": {
        "axis_priority_matrix": SOURCE_AXIS_PRIORITY,
        "specificity_override": True,
        "directness_override": True,
    },
    "llm_evidence_policy": {
        "identity_min_agreement_ratio": 0.8,
        "identity_min_k": 5,
        "version_and_scope_binding": True,
        "enabled_axes": ["identity", "version"],
        "preliminary_axes": ["version", "scope"],
        "legacy_single_pass_result_ceiling": "potentially_affected",
        "legacy_single_pass_version_index": False,
        "legacy_single_pass_requires_bounded_range": True,
        "legacy_single_pass_structured_decision_override": False,
        "structured_evidence_override": False,
    },
    "query_policies": {
        "default": "operational_strict",
        "language_omitted": "ANY",
        "context_omitted": "UNKNOWN",
    },
}

RULE_CONFIGURATION_JSON = json.dumps(
    RULE_CONFIGURATION, ensure_ascii=False, sort_keys=True, separators=(",", ":")
)
RULE_CONFIGURATION_SHA256 = hashlib.sha256(
    RULE_CONFIGURATION_JSON.encode("utf-8")
).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def stable_hash(value: Any) -> str:
    if not isinstance(value, str):
        value = canonical_json(value)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@lru_cache(maxsize=262_144)
def normalize_key(value: str | None) -> str:
    """Conservative identity key: NFKC/casefold and separator folding only."""

    if value is None:
        return ""
    normalized = unicodedata.normalize("NFKC", value).casefold().strip()
    normalized = re.sub(r"[^\w]+", "_", normalized, flags=re.UNICODE)
    return normalized.strip("_")


_PLACEHOLDER_KEYS = frozenset(normalize_key(item) for item in PLACEHOLDERS)


def is_placeholder(value: str | None) -> bool:
    return normalize_key(value) in _PLACEHOLDER_KEYS


def evidence_tuple(
    *,
    source_family: str,
    version_class: str,
    role: str | None,
    scope_specificity: int,
    freshness: int = 0,
    corroboration: int = 0,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        _AUTHORITY.get(source_family, 0),
        _STRUCTUREDNESS.get(source_family, 0),
        max(0, min(scope_specificity, 3)),
        VERSION_SPECIFICITY.get(version_class, 0),
        DIRECTNESS.get(role, 0),
        max(0, min(freshness, 2)),
        max(0, min(corroboration, 2)),
    )


def evidence_wins(
    left: tuple[int, int, int, int, int, int, int],
    right: tuple[int, int, int, int, int, int, int],
) -> bool:
    # v3.2 specificity override.
    if left[3] > 0 and right[3] == 0:
        return True
    if left[3] == 0 and right[3] > 0:
        return False
    # v3.2 directness override.
    if left[4] == 2 and right[4] == 0:
        return True
    if left[4] == 0 and right[4] == 2:
        return False
    return left > right
