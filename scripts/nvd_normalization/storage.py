"""SQLite schema-v5 persistence.

All SQL writes are kept here so parsing and query semantics stay independent
from SQLite details.  A new database is built with secondary indexes deferred
until publication; this avoids paying index maintenance for every source row.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping, Sequence

from .rules import (
    FRAMEWORK_VERSION,
    PROFILE_VERSION,
    RULE_CONFIGURATION_JSON,
    RULE_CONFIGURATION_SHA256,
    RULE_VERSION,
    SCHEMA_VERSION,
    canonical_json,
    normalize_key,
    stable_hash,
)
from .versioning import CompiledExpression


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class StorageError(RuntimeError):
    pass


class Store:
    _SCOPE_CACHE_LIMIT = 250_000

    def __init__(self, path: Path) -> None:
        self.path = path
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        # Referential integrity is verified before publication.  Deferring
        # per-row FK probes avoids duplicating that work during bulk ingest.
        self.connection.execute("PRAGMA foreign_keys=OFF")
        self.connection.execute("PRAGMA journal_mode=OFF")
        self.connection.execute("PRAGMA synchronous=OFF")
        self.connection.execute("PRAGMA temp_store=MEMORY")
        self.connection.execute("PRAGMA cache_size=-262144")
        self._created_at = utc_now()
        self._product_cache: dict[tuple[str, str, str], int] = {}
        self._scope_cache: OrderedDict[str, int] = OrderedDict()
        self._scope_cache_saturated = False

    @property
    def migrations(self) -> Path:
        return Path(__file__).with_name("migrations")

    def initialize(self) -> None:
        schema = (self.migrations / "0005_schema_v5.sql").read_text(
            encoding="utf-8"
        )
        self.connection.executescript(schema)
        self.connection.execute("PRAGMA foreign_keys=OFF")
        self.connection.execute("BEGIN IMMEDIATE")
        self.connection.executemany(
            "INSERT INTO metadata(key,value) VALUES (?,?)",
            (
                ("framework_version", FRAMEWORK_VERSION),
                ("schema_version", str(SCHEMA_VERSION)),
                ("rule_version", RULE_VERSION),
                ("profile_version", PROFILE_VERSION),
                ("publish_health", "blocked_incomplete_materialization"),
            ),
        )
        self.connection.execute(
            """INSERT INTO rule_configuration(
                   framework_version,configuration_json,
                   configuration_sha256,created_at
               ) VALUES (?,?,?,?)""",
            (
                FRAMEWORK_VERSION,
                RULE_CONFIGURATION_JSON,
                RULE_CONFIGURATION_SHA256,
                self._created_at,
            ),
        )

    def close(self) -> None:
        self.connection.close()

    def create_snapshot(
        self, source_path: Path, *, is_complete: bool
    ) -> int:
        cursor = self.connection.execute(
            """INSERT INTO source_snapshot_manifest(
                   source_family,source_channel,source_path,downloaded_at,
                   is_complete,retrieval_mode,status
               ) VALUES ('NVD','merged_jsonl',?,?,?,'bulk_feed','building')""",
            (str(source_path.resolve()), self._created_at, int(is_complete)),
        )
        return int(cursor.lastrowid)

    def create_run(
        self, snapshot_id: int, run_uuid: str, reinterpretation_token: str
    ) -> tuple[int, int]:
        cursor = self.connection.execute(
            """INSERT INTO pipeline_run(
                   run_uuid,snapshot_id,rule_configuration_id,
                   framework_version,started_at,status
               ) VALUES (?,?,1,?,?,'running')""",
            (run_uuid, snapshot_id, FRAMEWORK_VERSION, self._created_at),
        )
        pipeline_run_id = int(cursor.lastrowid)
        cursor = self.connection.execute(
            """INSERT INTO binding_revision(
                   pipeline_run_id,reinterpretation_token,framework_version,
                   rule_configuration_id,state
               ) VALUES (?,?,?,1,'draft')""",
            (
                pipeline_run_id,
                reinterpretation_token,
                FRAMEWORK_VERSION,
            ),
        )
        return pipeline_run_id, int(cursor.lastrowid)

    def create_llm_run(
        self,
        *,
        snapshot_id: int,
        source_path: Path,
        model_id: str,
        model_revision: str,
        prompt_hash: str,
        schema_hash: str,
        self_consistency_k: int,
    ) -> int:
        run_uuid = stable_hash(
            {
                "source": str(source_path.resolve()),
                "model": model_id,
                "revision": model_revision,
                "prompt": prompt_hash,
                "schema": schema_hash,
            }
        )
        cursor = self.connection.execute(
            """INSERT INTO llm_extraction_run(
                   run_uuid,model_id,model_revision,serving_stack,
                   prompt_template_hash,guided_schema_hash,decoding_json,
                   self_consistency_k,input_snapshot_id,source_path,
                   started_at,status
               ) VALUES (?,?,?,'external_precomputed',?,?,'{}',?,?,?,
                         ?,'metadata_incomplete')""",
            (
                run_uuid,
                model_id,
                model_revision,
                prompt_hash,
                schema_hash,
                self_consistency_k,
                snapshot_id,
                str(source_path.resolve()),
                self._created_at,
            ),
        )
        return int(cursor.lastrowid)

    def add_raw_cve(
        self,
        *,
        cve_id: str,
        snapshot_id: int,
        line_number: int,
        byte_offset: int,
        byte_length: int,
        raw_sha256: str,
        source_identifier: str | None,
        vuln_status: str,
        published: str | None,
        last_modified: str | None,
        primary_description: str | None,
        has_cpe: bool,
        has_cna: bool,
        has_llm_identity: bool,
        enrichment_class: str,
        admission_status: str,
    ) -> None:
        self.connection.execute(
            """INSERT INTO raw_cve(
                   cve_id,snapshot_id,line_number,byte_offset,byte_length,
                   raw_sha256,source_identifier,vuln_status,published,last_modified,
                   primary_description,has_cpe_configuration,has_cna_affected,
                   has_llm_identity,enrichment_class,admission_status
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                cve_id,
                snapshot_id,
                line_number,
                byte_offset,
                byte_length,
                raw_sha256,
                source_identifier,
                vuln_status,
                published,
                last_modified,
                primary_description,
                int(has_cpe),
                int(has_cna),
                int(has_llm_identity),
                enrichment_class,
                admission_status,
            ),
        )

    def add_description(
        self,
        *,
        description_id: str,
        cve_id: str,
        language: str | None,
        raw_bytes: bytes,
        pointer: str,
    ) -> None:
        self.connection.execute(
            """INSERT OR IGNORE INTO description(
                   description_id,cve_id,language,description_bytes,source_pointer
               ) VALUES (?,?,?,?,?)""",
            (description_id, cve_id, language, raw_bytes, pointer),
        )

    def product_id(
        self,
        vendor: str,
        product: str,
        *,
        part: str,
        source_family: str,
        evidence_basis: str,
        label_priority: int,
    ) -> int:
        vendor_key, product_key = normalize_key(vendor), normalize_key(product)
        normalized_part = part if part in {"a", "o", "h"} else "unknown"
        cache_key = (vendor_key, product_key, normalized_part)
        cached = self._product_cache.get(cache_key)
        if cached is not None:
            product_id = cached
        else:
            rows = self.connection.execute(
                """SELECT product_id,part,label_priority
                   FROM product_entity
                   WHERE vendor_key=? AND product_key=?
                   ORDER BY product_id""",
                (vendor_key, product_key),
            ).fetchall()
            selected: sqlite3.Row | None = None
            update_unknown = False
            if normalized_part == "unknown":
                unknown = [item for item in rows if item["part"] == "unknown"]
                if unknown:
                    selected = unknown[0]
                elif len(rows) == 1:
                    selected = rows[0]
            else:
                exact = [
                    item for item in rows if item["part"] == normalized_part
                ]
                if exact:
                    selected = exact[0]
                elif len(rows) == 1 and rows[0]["part"] == "unknown":
                    selected = rows[0]
                    update_unknown = True
            if selected is not None:
                product_id = int(selected["product_id"])
                if update_unknown:
                    self.connection.execute(
                        "UPDATE product_entity SET part=? WHERE product_id=?",
                        (normalized_part, product_id),
                    )
            else:
                cursor = self.connection.execute(
                    """INSERT INTO product_entity(
                           vendor_key,product_key,part,canonical_vendor,
                           canonical_product,label_basis,label_priority
                       ) VALUES (?,?,?,?,?,?,?)""",
                    (
                        vendor_key,
                        product_key,
                        normalized_part,
                        vendor,
                        product,
                        evidence_basis,
                        label_priority,
                    ),
                )
                product_id = int(cursor.lastrowid)
            current = self.connection.execute(
                "SELECT label_priority FROM product_entity WHERE product_id=?",
                (product_id,),
            ).fetchone()
            if current is not None and label_priority < int(current[0]):
                self.connection.execute(
                    """UPDATE product_entity
                       SET canonical_vendor=?,canonical_product=?,
                           label_basis=?,label_priority=?
                       WHERE product_id=?""",
                    (
                        vendor,
                        product,
                        evidence_basis,
                        label_priority,
                        product_id,
                    ),
                )
            if normalized_part != "unknown":
                self._product_cache.pop(
                    (vendor_key, product_key, "unknown"), None
                )
            if len(self._product_cache) >= 100_000:
                self._product_cache.clear()
            self._product_cache[cache_key] = product_id
        self.connection.execute(
            """INSERT OR IGNORE INTO product_alias(
                   product_id,vendor_raw,product_raw,source_family,evidence_basis
               ) VALUES (?,?,?,?,?)""",
            (product_id, vendor, product, source_family, evidence_basis),
        )
        return product_id

    def add_product_alias(
        self,
        *,
        product_id: int,
        vendor: str,
        product: str,
        source_family: str,
        evidence_basis: str,
    ) -> None:
        self.connection.execute(
            """INSERT OR IGNORE INTO product_alias(
                   product_id,vendor_raw,product_raw,source_family,evidence_basis
               ) VALUES (?,?,?,?,?)""",
            (product_id, vendor, product, source_family, evidence_basis),
        )

    def add_configuration(
        self, *, cve_id: str, index: int, graph: Mapping[str, Any]
    ) -> int:
        graph_json = canonical_json(graph)
        cursor = self.connection.execute(
            """INSERT INTO configuration(
                   cve_id,configuration_index,graph_json,graph_sha256
               ) VALUES (?,?,?,?)""",
            (cve_id, index, graph_json, stable_hash(graph_json)),
        )
        return int(cursor.lastrowid)

    def add_source_claim(
        self,
        *,
        snapshot_id: int,
        cve_id: str,
        product_id: int | None,
        source_family: str,
        source_identifier: str | None,
        pointer: str,
        raw_fragment_sha256: str,
        vendor: str | None,
        product: str | None,
        version: str | None,
        status: str | None,
        default_status: str | None,
        version_kind: str,
        version_class: str,
        cpe_criteria: str | None,
        cpe_match_id: str | None,
        vulnerable: bool | None,
        node_path: str | None,
        start_including: str | None,
        start_excluding: str | None,
        end_including: str | None,
        end_excluding: str | None,
        admission_status: str,
    ) -> int:
        cursor = self.connection.execute(
            """INSERT INTO source_claim(
                   snapshot_id,cve_id,product_id,source_family,source_identifier,
                   json_pointer,raw_fragment_sha256,vendor_raw,product_raw,
                   version_raw,status_raw,default_status_raw,version_kind,
                   version_resolution_class,cpe_criteria,cpe_match_id,
                   vulnerable_flag,node_path,version_start_including,
                   version_start_excluding,version_end_including,
                   version_end_excluding,admission_status,created_at
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                snapshot_id,
                cve_id,
                product_id,
                source_family,
                source_identifier,
                pointer,
                raw_fragment_sha256,
                vendor,
                product,
                version,
                status,
                default_status,
                version_kind,
                version_class,
                cpe_criteria,
                cpe_match_id,
                None if vulnerable is None else int(vulnerable),
                node_path,
                start_including,
                start_excluding,
                end_including,
                end_excluding,
                admission_status,
                self._created_at,
            ),
        )
        return int(cursor.lastrowid)

    def add_expression(
        self, source_claim_id: int, expression: CompiledExpression
    ) -> tuple[int, tuple[int, ...]]:
        cursor = self.connection.execute(
            """INSERT INTO version_expression(
                   source_claim_id,version_kind,version_resolution_class,
                   nvd_range_fields_present,raw_expression,parse_status,
                   parse_error_code,profile_name,profile_version,
                   semantic_fingerprint,status,evidence_tier
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                source_claim_id,
                expression.version_kind,
                expression.version_class,
                expression.nvd_range_fields_present,
                expression.raw_expression,
                expression.parse_status,
                expression.parse_error,
                expression.profile,
                PROFILE_VERSION,
                expression.semantic_fingerprint,
                expression.status,
                expression.evidence_tier,
            ),
        )
        expression_id = int(cursor.lastrowid)
        segment_ids: list[int] = []
        for ordinal, segment in enumerate(expression.segments):
            cursor = self.connection.execute(
                """INSERT INTO version_segment(
                       expression_id,ordinal,status,branch_key,
                       lower_bound,lower_inclusive,lower_arity_semantics,
                       upper_bound,upper_inclusive,upper_arity_semantics,
                       exact_value,transition_source,closure_origin,
                       breadth_class,comparator_version
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    expression_id,
                    ordinal,
                    segment.status,
                    segment.branch_key,
                    segment.lower,
                    None
                    if segment.lower_inclusive is None
                    else int(segment.lower_inclusive),
                    segment.lower_arity,
                    segment.upper,
                    None
                    if segment.upper_inclusive is None
                    else int(segment.upper_inclusive),
                    segment.upper_arity,
                    segment.exact,
                    segment.transition_source,
                    segment.closure_origin,
                    segment.breadth_class,
                    PROFILE_VERSION,
                ),
            )
            segment_ids.append(int(cursor.lastrowid))
        return expression_id, tuple(segment_ids)

    def _remember_scope(self, fingerprint: str, scope_id: int) -> None:
        """Keep a bounded LRU while remembering when DB fallback is required."""

        if fingerprint in self._scope_cache:
            self._scope_cache.move_to_end(fingerprint)
            self._scope_cache[fingerprint] = scope_id
            return
        if len(self._scope_cache) >= self._SCOPE_CACHE_LIMIT:
            self._scope_cache.popitem(last=False)
            self._scope_cache_saturated = True
        self._scope_cache[fingerprint] = scope_id

    def scope_id(
        self,
        *,
        product_id: int,
        axes: Mapping[str, tuple[str, str | None]],
        configuration_id: int | None,
        configuration_match_id: str | None,
        cpe_role: str | None,
        exclusive_scope: str | None,
    ) -> int:
        payload = {
            "product_id": product_id,
            "axes": {key: list(value) for key, value in sorted(axes.items())},
            "configuration_id": configuration_id,
            "configuration_match_id": configuration_match_id,
            "cpe_role": cpe_role,
            "exclusive_scope": exclusive_scope,
            "rule_version": RULE_VERSION,
        }
        fingerprint = stable_hash(payload)
        cached = self._scope_cache.get(fingerprint)
        if cached is not None:
            self._scope_cache.move_to_end(fingerprint)
            return cached
        if self._scope_cache_saturated:
            existing = self.connection.execute(
                """SELECT scope_id FROM applicability_scope
                   WHERE scope_fingerprint=?""",
                (fingerprint,),
            ).fetchone()
            if existing is not None:
                scope_id = int(existing[0])
                self._remember_scope(fingerprint, scope_id)
                return scope_id

        def axis(name: str) -> tuple[str, str | None]:
            return axes.get(name, ("UNKNOWN", None))

        values: list[Any] = [product_id]
        for name in (
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
        ):
            values.extend(axis(name))
        values.extend(
            (
                configuration_id,
                configuration_match_id,
                cpe_role,
                exclusive_scope,
                fingerprint,
                1,
                0,
            )
        )
        cursor = self.connection.execute(
            """INSERT INTO applicability_scope(
                   product_id,
                   part_state,part_value,
                   distribution_state,distribution_value,
                   edition_state,edition_value,
                   component_state,component_value,
                   update_state,update_value,
                   language_state,language_value,
                   sw_edition_state,sw_edition_value,
                   target_sw_state,target_sw_value,
                   target_hw_state,target_hw_value,
                   other_state,other_value,
                   configuration_id,configuration_match_id,cpe_match_role,
                   exclusive_scope,scope_fingerprint,is_maximal,subsumption_depth
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            values,
        )
        scope_id = int(cursor.lastrowid)
        self._remember_scope(fingerprint, scope_id)
        return scope_id

    def add_assertion(
        self,
        *,
        cve_id: str,
        scope_id: int,
        expression_id: int | None,
        source_claim_id: int,
        source_family: str,
        claim_group: str,
        polarity: str,
        evidence_tier: str,
        entity_basis: str,
        llm_claim_id: int | None,
        default_inferred: bool,
        default_effective: str,
        is_default_closure: bool,
        branch_coverage: str,
        branch_coverage_basis: str,
        version_class: str,
        max_result_state: str | None,
        cpe_role: str | None,
        role_basis: str | None,
        use_for_version_index: bool,
        corroboration_independence: str,
        comparison_tuple: Sequence[int],
        breadth_class: str,
        scope_status: str,
        version_status: str,
        reconciliation_status: str = "active",
    ) -> int:
        cursor = self.connection.execute(
            """INSERT INTO applicability_assertion(
                   cve_id,scope_id,expression_id,source_claim_id,source_family,
                   claim_group,assertion_polarity,evidence_tier,
                   entity_resolution_basis,llm_claim_id,default_status_inferred,
                   default_status_effective,is_default_closure,
                   branch_coverage_completeness,branch_coverage_basis,
                   version_resolution_class,max_result_state,cpe_match_role,
                   role_basis,use_for_version_index,corroboration_independence,
                   comparison_tuple_json,breadth_class,scope_resolution_status,
                   version_resolution_status,reconciliation_status,created_at,
                   rule_version
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                cve_id,
                scope_id,
                expression_id,
                source_claim_id,
                source_family,
                claim_group,
                polarity,
                evidence_tier,
                entity_basis,
                llm_claim_id,
                int(default_inferred),
                default_effective,
                int(is_default_closure),
                branch_coverage,
                branch_coverage_basis,
                version_class,
                max_result_state,
                cpe_role,
                role_basis,
                int(use_for_version_index),
                corroboration_independence,
                canonical_json(list(comparison_tuple)),
                breadth_class,
                scope_status,
                version_status,
                reconciliation_status,
                self._created_at,
                RULE_VERSION,
            ),
        )
        return int(cursor.lastrowid)

    def reconcile(
        self,
        assertion_id: int,
        *,
        status: str,
        winner: int | None,
        reason: str,
        triggering_axis: str | None,
        triggering_tier: str | None,
        comparison_tuple: Sequence[int],
    ) -> None:
        self.connection.execute(
            """UPDATE applicability_assertion
               SET reconciliation_status=? WHERE assertion_id=?""",
            (status, assertion_id),
        )
        self.connection.execute(
            """INSERT INTO assertion_reconciliation(
                   assertion_id,status,winner_assertion_id,reason,
                   triggering_axis,triggering_tier,comparison_tuple_json,
                   rule_version,created_at
               ) VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                assertion_id,
                status,
                winner,
                reason,
                triggering_axis,
                triggering_tier,
                canonical_json(list(comparison_tuple)),
                RULE_VERSION,
                self._created_at,
            ),
        )

    def add_binding(
        self,
        *,
        revision_id: int,
        cve_id: str,
        product_id: int,
        entity_basis: str,
        corroboration_independence: str,
        enrichment_class: str,
        provisional: bool,
        manual_review: bool,
        llm_run_id: int | None,
        assertion_ids: Sequence[tuple[int, bool]],
    ) -> int:
        cursor = self.connection.execute(
            """INSERT INTO cve_applicability_binding(
                   binding_revision_id,cve_id,product_id,entity_resolution_basis,
                   corroboration_independence,enrichment_class,
                   provisional_llm_identity,manual_review_required,
                   framework_version,llm_extraction_run_id,created_at
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                revision_id,
                cve_id,
                product_id,
                entity_basis,
                corroboration_independence,
                enrichment_class,
                int(provisional),
                int(manual_review),
                FRAMEWORK_VERSION,
                llm_run_id,
                self._created_at,
            ),
        )
        binding_id = int(cursor.lastrowid)
        self.connection.executemany(
            """INSERT INTO binding_assertion_member(
                   binding_id,assertion_id,is_active
               ) VALUES (?,?,?)""",
            (
                (binding_id, assertion_id, int(active))
                for assertion_id, active in assertion_ids
            ),
        )
        return binding_id

    def add_issue(
        self,
        *,
        code: str,
        stage: str,
        severity: str,
        cve_id: str | None,
        details: Mapping[str, Any] | str,
        source_claim_id: int | None = None,
        llm_claim_id: int | None = None,
    ) -> int:
        cursor = self.connection.execute(
            """INSERT INTO normalization_issue(
                   failure_code,stage,severity,cve_id,source_claim_id,
                   llm_claim_id,details_json,status,created_at
               ) VALUES (?,?,?,?,?,?,?,'open',?)""",
            (
                code,
                stage,
                severity,
                cve_id,
                source_claim_id,
                llm_claim_id,
                details
                if isinstance(details, str)
                else canonical_json(details),
                self._created_at,
            ),
        )
        return int(cursor.lastrowid)

    def add_llm_result(
        self,
        *,
        run_id: int,
        cve_id: str,
        source_index: int,
        status: str,
        description_sha256: str | None,
        error: str | None,
        raw_model_output: str | None,
        metadata: Mapping[str, Any],
    ) -> int:
        cursor = self.connection.execute(
            """INSERT INTO llm_result(
                   extraction_run_id,cve_id,source_index,status,
                   description_sha256,error,raw_model_output,metadata_json
               ) VALUES (?,?,?,?,?,?,?,?)""",
            (
                run_id,
                cve_id,
                source_index,
                status,
                description_sha256,
                error,
                raw_model_output,
                canonical_json(metadata),
            ),
        )
        return int(cursor.lastrowid)

    def add_llm_claim(
        self,
        *,
        run_id: int,
        cve_id: str,
        description_id: str,
        axis: str,
        claimed_role: str,
        extracted_value: str,
        span_start: int,
        span_end: int,
        evidence_text: str,
        admission_status: str,
        agreement_count: int = 1,
        agreement_k: int = 1,
    ) -> int:
        cursor = self.connection.execute(
            """INSERT INTO llm_claim(
                   extraction_run_id,cve_id,description_id,axis,claimed_role,
                   extracted_value,span_unit,evidence_span_start,
                   evidence_span_end,evidence_text,agreement_count,agreement_k,
                   admission_status,schema_version,created_at
               ) VALUES (?,?,?,?,?,?,'utf8_codepoint',?,?,?,?,?,?,'legacy-bindings-v1',?)""",
            (
                run_id,
                cve_id,
                description_id,
                axis,
                claimed_role,
                extracted_value,
                span_start,
                span_end,
                evidence_text,
                agreement_count,
                agreement_k,
                admission_status,
                self._created_at,
            ),
        )
        return int(cursor.lastrowid)

    def set_identity_cluster_digest(
        self, *, revision_id: int, cluster_digest: str
    ) -> None:
        self.connection.execute(
            """UPDATE binding_revision
               SET identity_cluster_digest=?
               WHERE binding_revision_id=?""",
            (cluster_digest, revision_id),
        )

    def finalize_snapshot(
        self,
        *,
        snapshot_id: int,
        payload_sha256: str,
        byte_size: int,
        record_count: int,
        coverage_start: str | None,
        coverage_end: str | None,
    ) -> None:
        self.connection.execute(
            """UPDATE source_snapshot_manifest
               SET payload_sha256=?,byte_size=?,record_count=?,
                   coverage_start=?,coverage_end=?,status='complete'
               WHERE snapshot_id=?""",
            (
                payload_sha256,
                byte_size,
                record_count,
                coverage_start,
                coverage_end,
                snapshot_id,
            ),
        )

    def finalize_llm_run(
        self,
        *,
        run_id: int,
        source_sha256: str,
        record_count: int,
        status: str,
    ) -> None:
        self.connection.execute(
            """UPDATE llm_extraction_run
               SET source_sha256=?,record_count=?,ended_at=?,status=?
               WHERE extraction_run_id=?""",
            (source_sha256, record_count, utc_now(), status, run_id),
        )

    def publish(
        self,
        *,
        pipeline_run_id: int,
        revision_id: int,
        record_count: int,
        summary: Mapping[str, Any],
        health: str,
    ) -> None:
        issue_count = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM normalization_issue"
            ).fetchone()[0]
        )
        now = utc_now()
        self.connection.execute(
            """UPDATE binding_revision
               SET state='published',published_at=?
               WHERE binding_revision_id=?""",
            (now, revision_id),
        )
        self.connection.execute(
            """UPDATE pipeline_run
               SET ended_at=?,status='complete',record_count=?,
                   issue_count=?,summary_json=?
               WHERE pipeline_run_id=?""",
            (
                now,
                record_count,
                issue_count,
                canonical_json(summary),
                pipeline_run_id,
            ),
        )
        self.connection.execute(
            "UPDATE metadata SET value=? WHERE key='publish_health'",
            (health,),
        )

    def commit_base(self) -> None:
        self.connection.commit()

    def create_post_ingest_indexes(self) -> None:
        """Create narrow work indexes only after bulk source ingestion.

        Identity materialization and alias-role publication run before the
        permanent publish indexes are created.  These two indexes avoid full
        scans and automatic temporary indexes during that interval without
        imposing per-row maintenance cost on the ingest loop.
        """

        self.connection.execute(
            """CREATE INDEX build_source_claim_cve_family_product_idx
               ON source_claim(
                   cve_id,source_family,product_id,vulnerable_flag
               )"""
        )
        self.connection.execute(
            """CREATE INDEX build_assertion_role_claim_idx
               ON applicability_assertion(
                   source_family,cpe_match_role,source_claim_id,assertion_id
               )"""
        )
        self.connection.execute(
            """CREATE INDEX build_binding_member_assertion_idx
               ON binding_assertion_member(
                   assertion_id,binding_id,is_active
               )"""
        )
        self.connection.execute("ANALYZE source_claim")
        self.connection.execute("ANALYZE applicability_assertion")

    def drop_post_ingest_indexes(self) -> None:
        """Remove transient work indexes before permanent publication."""

        self.connection.execute(
            "DROP INDEX IF EXISTS build_source_claim_cve_family_product_idx"
        )
        self.connection.execute(
            "DROP INDEX IF EXISTS build_assertion_role_claim_idx"
        )
        self.connection.execute(
            "DROP INDEX IF EXISTS build_binding_member_assertion_idx"
        )

    def create_indexes(self) -> None:
        indexes = (self.migrations / "0005_schema_v5_indexes.sql").read_text(
            encoding="utf-8"
        )
        self.connection.executescript(indexes)
        self.connection.execute("ANALYZE")
        self.connection.execute("PRAGMA optimize")
        self.connection.commit()

    def verify_integrity(self) -> None:
        self.connection.execute("PRAGMA foreign_keys=ON")
        foreign = self.connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign:
            raise StorageError(f"foreign key violations: {len(foreign)}")
        result = str(
            self.connection.execute("PRAGMA quick_check").fetchone()[0]
        )
        if result != "ok":
            raise StorageError(f"SQLite quick_check failed: {result}")
