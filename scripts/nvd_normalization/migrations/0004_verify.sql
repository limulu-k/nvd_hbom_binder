PRAGMA foreign_key_check;
PRAGMA integrity_check;

SELECT 'binding_without_assertion', COUNT(*)
FROM cve_applicability_binding AS b
LEFT JOIN binding_assertion_member AS m USING (binding_id)
WHERE m.binding_id IS NULL;

SELECT 'llm_version_active', COUNT(*)
FROM applicability_assertion AS a
JOIN source_claim AS c USING (source_claim_id)
WHERE c.source_family = 'llm_description'
  AND a.reconciliation_status IN ('active', 'conflict_review')
  AND (
    a.max_result_state IS NOT 'potentially_affected'
    OR a.use_for_version_index <> 0
    OR a.llm_claim_id IS NULL
  );

SELECT 'cpe_any_strict_index', COUNT(*)
FROM applicability_assertion
WHERE version_resolution_class = 'CPE_ANY_UNCORROBORATED'
  AND use_for_version_index = 1;

SELECT 'downstream_upstream_index', COUNT(*)
FROM applicability_assertion
WHERE cpe_match_role LIKE 'DOWNSTREAM_%'
  AND use_for_version_index = 1;

SELECT 'omitted_default_became_unaffected', COUNT(*)
FROM applicability_assertion AS a
JOIN source_claim AS c USING (source_claim_id)
WHERE c.source_family = 'cna_structured'
  AND c.default_status_raw IS NULL
  AND a.default_status_inferred = 1
  AND a.default_status_effective = 'unaffected';

SELECT 'cna_scope_resolution_collapse',
       CASE
         WHEN NOT EXISTS (
           SELECT 1 FROM source_snapshot_manifest WHERE is_complete = 1
         ) THEN 0
         WHEN COUNT(*) = 0 THEN 0
         WHEN 100 * SUM(scope_resolution_status = 'resolved')
              < 95 * COUNT(*) THEN 1
         ELSE 0
       END
FROM applicability_assertion
WHERE source_family = 'cna_structured'
  AND reconciliation_status <> 'unparsed_review';

SELECT 'cpe_role_resolution_collapse',
       CASE
         WHEN NOT EXISTS (
           SELECT 1 FROM source_snapshot_manifest WHERE is_complete = 1
         ) THEN 0
         WHEN COUNT(*) = 0 THEN 0
         WHEN 100 * SUM(cpe_match_role = 'UNRESOLVED')
              > 90 * COUNT(*) THEN 1
         ELSE 0
       END
FROM applicability_assertion
WHERE source_family = 'nvd_cpe'
  AND reconciliation_status IN ('active', 'conflict_review');

SELECT 'changes_outside_upper_discarded', COUNT(*)
FROM normalization_issue
WHERE details_json LIKE '%changes_outside_upper_bound%';
