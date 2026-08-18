"""Semantic publish audit and compact database inventory."""

from __future__ import annotations

from pathlib import Path
import sqlite3
from typing import Any, Mapping


class AuditError(RuntimeError):
    pass


AUDITS = {
    "A-BINDING-ASSERTION": """
        SELECT COUNT(*) FROM cve_applicability_binding b
        LEFT JOIN binding_assertion_member m USING(binding_id)
        WHERE m.binding_id IS NULL
    """,
    "A-BINDING-MANUAL-REVIEW-DRIFT": """
        WITH expected(binding_id) AS MATERIALIZED (
          SELECT DISTINCT m.binding_id
          FROM binding_assertion_member m
          JOIN applicability_assertion a USING(assertion_id)
          WHERE m.is_active=1
            AND (
              a.cpe_match_role='UNRESOLVED'
              OR a.reconciliation_status IN (
                'conflict_review','unparsed_review'
              )
            )
        )
        SELECT COUNT(*)
        FROM cve_applicability_binding b
        LEFT JOIN expected e USING(binding_id)
        WHERE b.manual_review_required<>(e.binding_id IS NOT NULL)
    """,
    "A-LLM-VERSION-BINDING": """
        SELECT COUNT(*) FROM applicability_assertion a
        JOIN source_claim c USING(source_claim_id)
        WHERE c.source_family='llm_description'
          AND a.reconciliation_status IN ('active','conflict_review')
          AND (
            a.max_result_state IS NOT 'potentially_affected'
            OR a.use_for_version_index<>0
            OR a.llm_claim_id IS NULL
          )
    """,
    "A-CPE-ANY-CEILING": """
        SELECT COUNT(*) FROM applicability_assertion
        WHERE version_resolution_class='CPE_ANY_UNCORROBORATED'
          AND max_result_state IS NOT 'potentially_affected'
    """,
    "A-CPE-ANY-INDEX": """
        SELECT COUNT(*) FROM applicability_assertion
        WHERE version_resolution_class='CPE_ANY_UNCORROBORATED'
          AND use_for_version_index=1
    """,
    "A-CPE-ROLE-UPSTREAM": """
        SELECT COUNT(*) FROM applicability_assertion
        WHERE cpe_match_role LIKE 'DOWNSTREAM_%'
          AND use_for_version_index=1
    """,
    "A-CPE-ROLE-UNRESOLVED": """
        SELECT COUNT(*) FROM applicability_assertion
        WHERE cpe_match_role='UNRESOLVED' AND use_for_version_index=1
    """,
    "A-CPE-ROLE-COVERAGE": """
        SELECT COUNT(*) FROM applicability_assertion
        WHERE source_family='nvd_cpe'
          AND reconciliation_status IN ('active','conflict_review')
          AND (cpe_match_role IS NULL OR role_basis IS NULL)
    """,
    "A-UNSPECIFIED-INDEX": """
        SELECT COUNT(*) FROM applicability_assertion
        WHERE version_resolution_class='UNSPECIFIED'
          AND use_for_version_index=1
    """,
    "A-DEFAULTSTATUS-UNKNOWN-ASSERTION": """
        SELECT COUNT(*) FROM applicability_assertion
        WHERE source_family='cna_structured'
          AND is_default_closure=1
          AND default_status_effective='unknown'
    """,
    "A-CONFIG-VULNERABLE-FALSE": """
        SELECT COUNT(*) FROM applicability_assertion a
        JOIN source_claim c USING(source_claim_id)
        WHERE c.vulnerable_flag=0 AND a.assertion_polarity='affected'
    """,
    "A-DEFAULTSTATUS-OMITTED": """
        SELECT COUNT(*) FROM applicability_assertion a
        JOIN source_claim c USING(source_claim_id)
        WHERE c.source_family='cna_structured'
          AND c.default_status_raw IS NULL
          AND a.default_status_inferred=1
          AND a.default_status_effective='unaffected'
    """,
    "A-VERSION-EXACT-COMPARATOR": """
        SELECT COUNT(*) FROM version_segment
        WHERE exact_value GLOB '<*' OR exact_value GLOB '>*'
           OR exact_value GLOB '=*' OR exact_value GLOB '!*'
    """,
    "A-WILDCARD-KIND": """
        SELECT COUNT(*) FROM version_expression WHERE version_kind='wildcard'
    """,
    "A-CPE-RANGE-FIELDS": """
        SELECT COUNT(*) FROM source_claim c
        WHERE c.source_family='nvd_cpe' AND c.version_raw='*'
          AND CASE
            WHEN (
              (c.version_start_including IS NOT NULL) +
              (c.version_start_excluding IS NOT NULL) +
              (c.version_end_including IS NOT NULL) +
              (c.version_end_excluding IS NOT NULL)
            ) = 0
            THEN c.version_resolution_class
                 <> 'CPE_ANY_UNCORROBORATED'
            ELSE c.version_resolution_class
                 NOT IN ('BOUNDED_RANGE','UNBOUNDED_RANGE','UNPARSED')
          END
    """,
    "A-CPE-RANGE-SEGMENTS": """
        SELECT COUNT(*)
        FROM source_claim c
        JOIN version_expression e USING(source_claim_id)
        JOIN version_segment v USING(expression_id)
        WHERE c.source_family='nvd_cpe'
          AND c.version_resolution_class
              IN ('BOUNDED_RANGE','UNBOUNDED_RANGE')
          AND (
            ((c.version_start_including IS NOT NULL
              OR c.version_start_excluding IS NOT NULL)
             AND v.lower_bound IS NULL)
            OR
            ((c.version_end_including IS NOT NULL
              OR c.version_end_excluding IS NOT NULL)
             AND v.upper_bound IS NULL)
          )
    """,
    "A-CNA-SCOPE-COVERAGE": """
        SELECT CASE
          WHEN NOT EXISTS (
            SELECT 1 FROM source_snapshot_manifest WHERE is_complete=1
          ) THEN 0
          WHEN COUNT(*)=0 THEN 0
          WHEN 100 * SUM(scope_resolution_status='resolved')
               < 95 * COUNT(*) THEN 1
          ELSE 0
        END
        FROM applicability_assertion
        WHERE source_family='cna_structured'
          AND reconciliation_status <> 'unparsed_review'
    """,
    "A-CPE-ROLE-RESOLUTION": """
        SELECT CASE
          WHEN NOT EXISTS (
            SELECT 1 FROM source_snapshot_manifest WHERE is_complete=1
          ) THEN 0
          WHEN COUNT(*)=0 THEN 0
          WHEN 100 * SUM(cpe_match_role='UNRESOLVED')
               > 90 * COUNT(*) THEN 1
          ELSE 0
        END
        FROM applicability_assertion
        WHERE source_family='nvd_cpe'
          AND reconciliation_status IN ('active','conflict_review')
    """,
    "A-VERSION-INDEX-COVERAGE": """
        SELECT CASE
          WHEN NOT EXISTS (
            SELECT 1 FROM source_snapshot_manifest WHERE is_complete=1
          ) THEN 0
          WHEN COUNT(*)=0 THEN 0
          WHEN SUM(use_for_version_index)=0 THEN 1
          ELSE 0
        END
        FROM applicability_assertion
        WHERE cpe_match_role IN (
                'DIRECT_UPSTREAM','DIRECT_ALTERNATIVE_PRODUCT'
              )
          AND source_family<>'llm_description'
          AND scope_resolution_status='resolved'
          AND version_resolution_status='resolved'
          AND reconciliation_status IN ('active','conflict_review')
    """,
    "A-CHANGES-UPPER-DISCARD": """
        SELECT COUNT(*) FROM normalization_issue
        WHERE details_json LIKE '%changes_outside_upper_bound%'
    """,
    "A-COMPARATOR-BOUND": """
        SELECT COUNT(*) FROM version_segment
        WHERE lower_bound GLOB '*[<>=!]*'
           OR upper_bound GLOB '*[<>=!]*'
    """,
    "A-ALIAS-HARD-DISTINCT-CLUSTER": """
        SELECT COUNT(*)
        FROM identity_hard_distinct d
        JOIN identity_cluster_member l ON l.node_id=d.left_node_id
        JOIN identity_cluster_member r ON r.node_id=d.right_node_id
        WHERE l.cluster_id=r.cluster_id
    """,
    "A-ALIAS-MISSING-EVIDENCE": """
        SELECT COUNT(*) FROM identity_alias_edge
        WHERE evidence_tier IS NULL OR evidence_tier=''
           OR basis_json IS NULL OR basis_json=''
    """,
    "A-ALIAS-BASIS-ENVELOPE": """
        SELECT COALESCE(SUM(
          CASE
            WHEN json_valid(basis_json)=0 THEN 1
            WHEN json_extract(basis_json,'$.format')
                 IS NOT 'bounded_evidence_v1' THEN 1
            WHEN json_type(basis_json,'$.evidence') IS NOT 'array' THEN 1
            WHEN json_type(basis_json,'$.evidence_count')
                 IS NOT 'integer' THEN 1
            WHEN json_type(basis_json,'$.evidence_examples_limit')
                 IS NOT 'integer' THEN 1
            WHEN json_extract(basis_json,'$.evidence_examples_limit')
                 <>32 THEN 1
            WHEN json_type(basis_json,'$.evidence_truncated')
                 NOT IN ('true','false') THEN 1
            WHEN json_array_length(basis_json,'$.evidence')>32 THEN 1
            WHEN json_extract(basis_json,'$.evidence_count')
                 <json_array_length(basis_json,'$.evidence') THEN 1
            ELSE 0
          END
        ),0)
        FROM identity_alias_edge
    """,
    "A-ALIAS-E4-ACCEPTED": """
        SELECT COUNT(*) FROM identity_alias_edge
        WHERE evidence_tier='E4' AND status='accepted'
    """,
    "A-ALIAS-NONACCEPTED-IN-CLUSTER": """
        SELECT COUNT(*) FROM identity_cluster_edge ce
        JOIN identity_alias_edge e USING(edge_id)
        WHERE e.status<>'accepted'
    """,
    "A-ALIAS-OVERSIZE-NOT-REVIEW": """
        SELECT COUNT(*) FROM identity_cluster
        WHERE member_count>8 AND review_state='ok'
    """,
    "A-ALIAS-STRICT-CONTAMINATION": """
        SELECT COUNT(*) FROM identity_cluster c
        WHERE c.strict_eligible=1 AND EXISTS (
            SELECT 1 FROM identity_cluster_edge ce
            JOIN identity_alias_edge e USING(edge_id)
            WHERE ce.cluster_id=c.cluster_id AND e.strict_eligible=0
        )
    """,
    "A-IDENTITY-DIGEST-MISSING": """
        SELECT COUNT(*) FROM binding_revision
        WHERE state='published' AND identity_cluster_digest IS NULL
    """,
    "A-IDENTITY-ROLE-RECONCILIATION-DRIFT": """
        SELECT COUNT(*)
        FROM applicability_assertion a
        JOIN assertion_reconciliation r USING(assertion_id)
        WHERE a.comparison_tuple_json<>r.comparison_tuple_json
    """,
    "A-IDENTITY-RAW-KEY-PROVENANCE": """
        SELECT COUNT(*)
        FROM identity_key k
        LEFT JOIN product_alias a
          ON a.product_alias_id=k.source_alias_id
        WHERE k.origin='raw_alias_observation'
          AND a.product_alias_id IS NULL
    """,
}

BLOCKING = frozenset(AUDITS)


def audit_database(path: Path, *, full_integrity: bool = False) -> Mapping[str, Any]:
    if not path.is_file():
        raise AuditError(f"database does not exist: {path}")
    connection = sqlite3.connect(
        path.resolve().as_uri() + "?mode=ro", uri=True
    )
    try:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != 5:
            raise AuditError(f"schema v5 required, found v{version}")
        integrity_pragma = "integrity_check" if full_integrity else "quick_check"
        integrity = str(
            connection.execute(f"PRAGMA {integrity_pragma}").fetchone()[0]
        )
        foreign_key_violations = len(
            connection.execute("PRAGMA foreign_key_check").fetchall()
        )
        results = {
            name: int(connection.execute(sql).fetchone()[0])
            for name, sql in AUDITS.items()
        }
        blocking = {
            name: count
            for name, count in results.items()
            if name in BLOCKING and count
        }
        tables = {
            str(row[0]): int(
                connection.execute(f'SELECT COUNT(*) FROM "{row[0]}"').fetchone()[0]
            )
            for row in connection.execute(
                """SELECT name FROM sqlite_master
                   WHERE type='table' AND name NOT LIKE 'sqlite_%'
                   ORDER BY name"""
            )
        }
        metadata = dict(connection.execute("SELECT key,value FROM metadata"))
        return {
            "database": str(path),
            "database_bytes": path.stat().st_size,
            "schema_version": version,
            "integrity": integrity,
            "foreign_key_violations": foreign_key_violations,
            "audits": results,
            "blocking_violations": blocking,
            "passed": (
                integrity == "ok"
                and foreign_key_violations == 0
                and not blocking
            ),
            "metadata": metadata,
            "row_counts": tables,
        }
    finally:
        connection.close()
