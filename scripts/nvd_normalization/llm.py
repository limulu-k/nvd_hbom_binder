"""Adapter for the precomputed description parsing JSONL files.

The supplied files predate the v3.2 LLM claim schema.  This adapter derives
code-point spans when possible, but it never invents self-consistency or gate
results: identity claims remain ``below_agreement`` (k=1), and version ranges
remain preliminary/non-binding.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, BinaryIO, Mapping

from .rules import canonical_json
from .storage import Store


LEGACY_GUIDED_SCHEMA = {
    "type": "object",
    "properties": {
        "bindings": {
            "type": ["array", "null"],
            "items": {
                "type": "object",
                "properties": {
                    "vendor": {"type": ["string", "null"]},
                    "product": {"type": "string"},
                    "version_ranges": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "start": {"type": ["string", "null"]},
                                "start_inclusive": {"type": ["boolean", "null"]},
                                "end": {"type": ["string", "null"]},
                                "end_inclusive": {"type": ["boolean", "null"]},
                            },
                        },
                    },
                },
            },
        }
    },
}
LEGACY_SCHEMA_HASH = hashlib.sha256(
    canonical_json(LEGACY_GUIDED_SCHEMA).encode("utf-8")
).hexdigest()


@dataclass(slots=True)
class _RecordReference:
    reader: "_IndexedFile"
    offset: int
    line_number: int
    original_source_index: int | None
    description_sha256: bytes | None
    consumed: bool = False


@dataclass(frozen=True, slots=True)
class GroundedLLMRange:
    """One description-grounded version range inside an LLM binding."""

    claim_id: int
    range_index: int
    start: str | None
    start_inclusive: bool | None
    end: str | None
    end_inclusive: bool | None


@dataclass(frozen=True, slots=True)
class GroundedLLMBinding:
    """A binding whose identity and ranges are grounded in the description.

    The legacy JSONL preserves vendor/product/range grouping, while the v5
    ``llm_claim`` table is intentionally flat.  Keeping this short-lived
    object during the build lets the compiler materialize a provisional
    applicability assertion without guessing the relationship later.
    """

    binding_index: int
    vendor: str
    product: str
    vendor_claim_id: int
    product_claim_id: int
    version_ranges: tuple[GroundedLLMRange, ...]


class _IndexedFile:
    """Byte-offset index for one LLM JSONL without retaining its payloads."""

    def __init__(self, path: Path, *, success: bool) -> None:
        self.path = path
        self.success = success
        self.file: BinaryIO = path.open("rb")
        self.hasher = hashlib.sha256()
        self.count = 0
        self.references: list[_RecordReference] = []

    def build_index(
        self,
        by_cve: dict[
            str,
            _RecordReference | list[_RecordReference],
        ],
        unkeyed: list[_RecordReference],
    ) -> None:
        while True:
            offset = self.file.tell()
            raw = self.file.readline()
            if not raw:
                break
            self.hasher.update(raw)
            self.count += 1
            value = json.loads(raw)
            if not isinstance(value, Mapping):
                raise ValueError(
                    f"LLM JSONL row is not an object: {self.path}:{self.count}"
                )
            metadata = value.get("_meta")
            metadata = metadata if isinstance(metadata, Mapping) else {}
            original_source_index = metadata.get("source_index")
            if not isinstance(original_source_index, int):
                original_source_index = None
            description = value.get("description")
            description_sha256 = (
                hashlib.sha256(description.encode("utf-8")).digest()
                if isinstance(description, str)
                else None
            )
            reference = _RecordReference(
                reader=self,
                offset=offset,
                line_number=self.count,
                original_source_index=original_source_index,
                description_sha256=description_sha256,
            )
            self.references.append(reference)
            cve_id = value.get("cve_id")
            if isinstance(cve_id, str) and cve_id:
                existing = by_cve.get(cve_id)
                if existing is None:
                    # Most CVEs occur once.  Avoid allocating hundreds of
                    # thousands of one-element lists for the common case.
                    by_cve[cve_id] = reference
                elif isinstance(existing, list):
                    existing.append(reference)
                else:
                    by_cve[cve_id] = [existing, reference]
            else:
                unkeyed.append(reference)

    def read(self, reference: _RecordReference) -> Mapping[str, Any]:
        self.file.seek(reference.offset)
        raw = self.file.readline()
        value = json.loads(raw)
        if not isinstance(value, Mapping):
            raise ValueError(
                "LLM JSONL indexed row is not an object: "
                f"{self.path}:{reference.line_number}"
            )
        return value

    def close(self) -> None:
        self.file.close()


class LLMResultStream:
    """Join precomputed LLM rows to NVD rows by CVE ID.

    ``source_index`` in the legacy files belongs to the NVD snapshot used when
    extraction ran.  History maintenance can reorder or remove NVD rows, so it
    is retained only as provenance/tie-break information and is never used as
    the join key.
    """

    def __init__(self, success_path: Path, fail_path: Path | None) -> None:
        self.success = _IndexedFile(success_path, success=True)
        self.failure = (
            _IndexedFile(fail_path, success=False)
            if fail_path is not None
            else None
        )
        self.by_cve: dict[
            str,
            _RecordReference | list[_RecordReference],
        ] = {}
        self.unkeyed: list[_RecordReference] = []
        self.success.build_index(self.by_cve, self.unkeyed)
        if self.failure is not None:
            self.failure.build_index(self.by_cve, self.unkeyed)
        self.lookup_count = 0
        self.description_matches = 0
        self.description_fallbacks = 0
        self.duplicate_candidate_lookups = 0

    @staticmethod
    def _rank(reference: _RecordReference) -> tuple[int, int, int]:
        # Prefer a successful extraction.  The legacy source index and line
        # number make selection deterministic when a CVE has repeated results.
        return (
            int(reference.reader.success),
            reference.original_source_index
            if reference.original_source_index is not None
            else -1,
            reference.line_number,
        )

    def for_cve(
        self,
        cve_id: str,
        description: str | None,
    ) -> Mapping[str, Any] | None:
        self.lookup_count += 1
        bucket = self.by_cve.get(cve_id)
        if bucket is None:
            return None
        bucket_items = bucket if isinstance(bucket, list) else (bucket,)
        candidates = [
            item for item in bucket_items if not item.consumed
        ]
        if not candidates:
            return None
        if len(candidates) > 1:
            self.duplicate_candidate_lookups += 1

        exact: list[_RecordReference] = []
        if description is not None:
            digest = hashlib.sha256(description.encode("utf-8")).digest()
            exact = [
                item for item in candidates if item.description_sha256 == digest
            ]
        if exact:
            selected = max(exact, key=self._rank)
            # Defend against the theoretical hash collision before admission.
            record = selected.reader.read(selected)
            if record.get("description") != description:
                exact = []
            else:
                self.description_matches += 1
                selected.consumed = True
                return record

        # A CVE-ID match is still returned so ingest_llm_result can preserve an
        # audit row and reject its claims as description_missing_or_stale.
        selected = max(candidates, key=self._rank)
        self.description_fallbacks += 1
        selected.consumed = True
        return selected.reader.read(selected)

    def join_summary(self) -> dict[str, Any]:
        references = list(self.success.references)
        if self.failure is not None:
            references.extend(self.failure.references)
        unmatched = [item for item in references if not item.consumed]
        examples = [
            {
                "path": str(item.reader.path),
                "line_number": item.line_number,
                "source_index": item.original_source_index,
            }
            for item in unmatched[:10]
        ]
        return {
            "lookup_count": self.lookup_count,
            "description_matches": self.description_matches,
            "description_fallbacks": self.description_fallbacks,
            "duplicate_candidate_lookups": self.duplicate_candidate_lookups,
            "unmatched_count": len(unmatched),
            "unkeyed_count": len(self.unkeyed),
            "unmatched_examples": examples,
        }

    def finish(self) -> tuple[str, int, dict[str, str]]:
        hashes = {"success": self.success.hasher.hexdigest()}
        count = self.success.count
        if self.failure is not None:
            hashes["failure"] = self.failure.hasher.hexdigest()
            count += self.failure.count
        combined = hashlib.sha256(canonical_json(hashes).encode("utf-8")).hexdigest()
        return combined, count, hashes

    def close(self) -> None:
        self.success.close()
        if self.failure is not None:
            self.failure.close()


def _span(text: str, value: str) -> tuple[int, int, str] | None:
    if not value:
        return None
    start = text.find(value)
    if start >= 0:
        return start, start + len(value), text[start : start + len(value)]
    match = re.search(re.escape(value), text, flags=re.IGNORECASE)
    if match is None:
        return None
    return match.start(), match.end(), text[match.start() : match.end()]


def _range_span(
    text: str, version_range: Mapping[str, Any]
) -> tuple[int, int, str] | None:
    spans = []
    for key in ("start", "end"):
        value = version_range.get(key)
        if isinstance(value, str) and value:
            found = _span(text, value)
            if found is not None:
                spans.append(found)
    if not spans:
        return None
    start = min(item[0] for item in spans)
    end = max(item[1] for item in spans)
    return start, end, text[start:end]


def ingest_llm_result(
    store: Store,
    *,
    run_id: int,
    record: Mapping[str, Any],
    expected_cve_id: str,
    source_index: int,
    description_id: str | None,
    description: str | None,
    grounded_bindings: list[GroundedLLMBinding] | None = None,
) -> dict[str, int]:
    counts = {
        "results": 0,
        "claims": 0,
        "identity_below_agreement": 0,
        "version_preliminary": 0,
        "bindings_preliminary": 0,
        "ungrounded": 0,
        "failures": 0,
    }
    cve_id = record.get("cve_id")
    metadata = record.get("_meta")
    metadata = dict(metadata) if isinstance(metadata, Mapping) else {}
    status = metadata.get("status")
    status = status if isinstance(status, str) else "unknown"
    if cve_id != expected_cve_id:
        store.add_issue(
            code="F-LLM-04",
            stage="llm_admission",
            severity="high",
            cve_id=expected_cve_id,
            details={
                "reason": "cve_id_mismatch",
                "expected": expected_cve_id,
                "actual": cve_id,
                "source_index": source_index,
            },
        )
        return counts
    text = description or ""
    supplied_description = record.get("description")
    same_description = isinstance(supplied_description, str) and supplied_description == text
    bindings = record.get("bindings")
    bindings = bindings if isinstance(bindings, list) else []
    rejected_payload: list[Mapping[str, Any]] = []
    if description_id is None or not same_description:
        rejected_payload = [
            item for item in bindings if isinstance(item, Mapping)
        ]
        counts["ungrounded"] += len(rejected_payload)
        store.add_issue(
            code="F-LLM-04",
            stage="llm_admission",
            severity="medium",
            cve_id=expected_cve_id,
            details={
                "reason": "description_missing_or_stale",
                "source_index": source_index,
            },
        )
    else:
        for binding_index, binding in enumerate(bindings):
            if not isinstance(binding, Mapping):
                continue
            product = binding.get("product")
            vendor = binding.get("vendor")
            product_claim_id: int | None = None
            vendor_claim_id: int | None = None
            grounded_ranges: list[GroundedLLMRange] = []
            product_span = _span(text, product) if isinstance(product, str) else None
            if isinstance(product, str) and product_span is not None:
                product_claim_id = store.add_llm_claim(
                    run_id=run_id,
                    cve_id=expected_cve_id,
                    description_id=description_id,
                    axis="product",
                    claimed_role="affected_product",
                    extracted_value=product,
                    span_start=product_span[0],
                    span_end=product_span[1],
                    evidence_text=product_span[2],
                    admission_status="below_agreement",
                )
                counts["claims"] += 1
                counts["identity_below_agreement"] += 1
            elif isinstance(product, str):
                counts["ungrounded"] += 1
                rejected_payload.append(binding)
            vendor_span = _span(text, vendor) if isinstance(vendor, str) else None
            if isinstance(vendor, str) and vendor_span is not None:
                vendor_claim_id = store.add_llm_claim(
                    run_id=run_id,
                    cve_id=expected_cve_id,
                    description_id=description_id,
                    axis="vendor",
                    claimed_role="vendor_of_record",
                    extracted_value=vendor,
                    span_start=vendor_span[0],
                    span_end=vendor_span[1],
                    evidence_text=vendor_span[2],
                    admission_status="below_agreement",
                )
                counts["claims"] += 1
                counts["identity_below_agreement"] += 1
            elif isinstance(vendor, str):
                counts["ungrounded"] += 1
                rejected_payload.append(binding)
            ranges = binding.get("version_ranges")
            if not isinstance(ranges, list):
                continue
            for range_index, version_range in enumerate(ranges):
                if not isinstance(version_range, Mapping):
                    continue
                if version_range.get("start") is None and version_range.get("end") is None:
                    continue
                found = _range_span(text, version_range)
                if found is None:
                    counts["ungrounded"] += 1
                    rejected_payload.append(binding)
                    continue
                version_claim_id = store.add_llm_claim(
                    run_id=run_id,
                    cve_id=expected_cve_id,
                    description_id=description_id,
                    axis="version",
                    claimed_role="affected_product",
                    extracted_value=canonical_json(version_range),
                    span_start=found[0],
                    span_end=found[1],
                    evidence_text=found[2],
                    admission_status="accepted_preliminary",
                )
                counts["claims"] += 1
                counts["version_preliminary"] += 1
                grounded_ranges.append(
                    GroundedLLMRange(
                        claim_id=version_claim_id,
                        range_index=range_index,
                        start=(
                            version_range.get("start")
                            if isinstance(version_range.get("start"), str)
                            else None
                        ),
                        start_inclusive=(
                            version_range.get("start_inclusive")
                            if isinstance(
                                version_range.get("start_inclusive"), bool
                            )
                            else None
                        ),
                        end=(
                            version_range.get("end")
                            if isinstance(version_range.get("end"), str)
                            else None
                        ),
                        end_inclusive=(
                            version_range.get("end_inclusive")
                            if isinstance(
                                version_range.get("end_inclusive"), bool
                            )
                            else None
                        ),
                    )
                )
            if (
                grounded_bindings is not None
                and status == "ok"
                and isinstance(vendor, str)
                and isinstance(product, str)
                and vendor_claim_id is not None
                and product_claim_id is not None
                and grounded_ranges
            ):
                grounded_bindings.append(
                    GroundedLLMBinding(
                        binding_index=binding_index,
                        vendor=vendor,
                        product=product,
                        vendor_claim_id=vendor_claim_id,
                        product_claim_id=product_claim_id,
                        version_ranges=tuple(grounded_ranges),
                    )
                )
                counts["bindings_preliminary"] += 1
    error = metadata.get("error")
    error = error if isinstance(error, str) else None
    raw_model_output = metadata.get("raw_model_output")
    raw_model_output = (
        raw_model_output if isinstance(raw_model_output, str) else None
    )
    if status != "ok":
        counts["failures"] += 1
        store.add_issue(
            code="F-LLM-04",
            stage="llm_extraction",
            severity="medium",
            cve_id=expected_cve_id,
            details={"status": status, "error": error, "source_index": source_index},
        )
    elif rejected_payload:
        # Preserve only claims that cannot be represented by the span-constrained
        # llm_claim table.  Grounded rows are already losslessly materialized.
        unique_rejected = {
            canonical_json(item): item for item in rejected_payload
        }
        raw_model_output = canonical_json(
            {"bindings": list(unique_rejected.values())}
        )
    description_sha256 = (
        hashlib.sha256(text.encode("utf-8")).hexdigest() if description is not None else None
    )
    store.add_llm_result(
        run_id=run_id,
        cve_id=expected_cve_id,
        source_index=source_index,
        status=status,
        description_sha256=description_sha256,
        error=error,
        raw_model_output=raw_model_output,
        metadata=metadata,
    )
    counts["results"] += 1
    return counts
