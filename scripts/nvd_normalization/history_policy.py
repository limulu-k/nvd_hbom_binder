"""Read-only history conflict adjudication policy used by the query engine."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Iterable

from .rules import normalize_key


POLICY_SCHEMA_VERSION = 1
POLICY_ACTIONS = frozenset(
    {"prefer_latest_cpe", "accept_added_range", "conflict_review"}
)


class HistoryPolicyError(ValueError):
    """Raised when a history conflict policy sidecar is malformed."""


@dataclass(frozen=True, slots=True)
class HistoryPolicyDecision:
    cve_id: str
    action: str
    relation: str
    basis: str


class HistoryConflictPolicy:
    """CVE/product decisions derived from current ranges and NVD history.

    The sidecar is deliberately external to the applicability database.  This
    keeps the published schema stable and makes applying the policy an explicit
    query-time choice rather than silently changing the underlying evidence.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise HistoryPolicyError(
                f"history conflict policy does not exist: {self.path}"
            )
        self._by_identity: dict[
            tuple[str, str, str], list[HistoryPolicyDecision]
        ] = {}
        self._by_product: dict[
            tuple[str, str], list[HistoryPolicyDecision]
        ] = {}
        self._load()

    def _load(self) -> None:
        with self.path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    raise HistoryPolicyError(
                        f"invalid policy JSON at {self.path}:{line_number}: {error}"
                    ) from error
                if not isinstance(row, dict):
                    raise HistoryPolicyError(
                        f"policy row must be an object at {self.path}:{line_number}"
                    )
                schema_version = row.get("schema_version", POLICY_SCHEMA_VERSION)
                if schema_version != POLICY_SCHEMA_VERSION:
                    raise HistoryPolicyError(
                        f"unsupported history policy schema {schema_version!r} "
                        f"at {self.path}:{line_number}"
                    )
                cve_id = str(row.get("cve_id") or "").strip().upper()
                action = str(row.get("action") or "")
                relation = str(row.get("relation") or "")
                basis = str(row.get("basis") or "")
                if not cve_id.startswith("CVE-") or action not in POLICY_ACTIONS:
                    raise HistoryPolicyError(
                        f"invalid policy decision at {self.path}:{line_number}"
                    )
                decision = HistoryPolicyDecision(
                    cve_id=cve_id,
                    action=action,
                    relation=relation,
                    basis=basis,
                )
                identities = row.get("identities")
                if not isinstance(identities, list) or not identities:
                    raise HistoryPolicyError(
                        f"policy identities must be a non-empty list at "
                        f"{self.path}:{line_number}"
                    )
                for identity in identities:
                    if not isinstance(identity, dict):
                        raise HistoryPolicyError(
                            f"invalid policy identity at {self.path}:{line_number}"
                        )
                    vendor_raw = identity.get("vendor")
                    product_raw = identity.get("product")
                    vendor = normalize_key(
                        None if vendor_raw is None else str(vendor_raw)
                    )
                    product = normalize_key(
                        None if product_raw is None else str(product_raw)
                    )
                    if not product:
                        raise HistoryPolicyError(
                            f"empty policy product at {self.path}:{line_number}"
                        )
                    self._by_identity.setdefault(
                        (cve_id, vendor, product), []
                    ).append(decision)
                    self._by_product.setdefault((cve_id, product), []).append(
                        decision
                    )

    def resolve(
        self,
        cve_id: str,
        identities: Iterable[tuple[str, str]],
    ) -> HistoryPolicyDecision | None:
        """Return one unambiguous decision for the resolved query products."""

        normalized_cve = cve_id.strip().upper()
        matches: list[HistoryPolicyDecision] = []
        seen: set[HistoryPolicyDecision] = set()
        normalized_identities = [
            (normalize_key(vendor), normalize_key(product))
            for vendor, product in identities
            if normalize_key(product)
        ]
        for vendor, product in normalized_identities:
            candidates = self._by_identity.get(
                (normalized_cve, vendor, product), []
            )
            if not candidates:
                # Vendor spelling often differs between CNA and CPE.  A
                # product-only fallback is safe only when it yields one action.
                candidates = self._by_product.get(
                    (normalized_cve, product), []
                )
            for decision in candidates:
                if decision not in seen:
                    seen.add(decision)
                    matches.append(decision)
        actions = {decision.action for decision in matches}
        if len(actions) != 1:
            return None
        return matches[0]
