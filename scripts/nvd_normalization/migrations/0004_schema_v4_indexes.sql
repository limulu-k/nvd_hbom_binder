CREATE INDEX raw_cve_enrichment_idx
    ON raw_cve(enrichment_class, cve_id);
CREATE INDEX description_cve_idx
    ON description(cve_id, language);
CREATE INDEX product_lookup_idx
    ON product_entity(product_key, vendor_key);
CREATE INDEX product_alias_lookup_idx
    ON product_alias(product_raw, vendor_raw);
CREATE INDEX configuration_cve_idx
    ON configuration(cve_id);
CREATE INDEX source_claim_cve_idx
    ON source_claim(cve_id, source_family);
CREATE INDEX source_claim_product_idx
    ON source_claim(product_id, cve_id, vulnerable_flag);
CREATE INDEX version_segment_expression_idx
    ON version_segment(expression_id, ordinal);
CREATE INDEX version_segment_branch_idx
    ON version_segment(branch_key);
CREATE INDEX scope_product_idx
    ON applicability_scope(product_id, cpe_match_role);
CREATE INDEX assertion_product_path_idx
    ON applicability_assertion(scope_id, reconciliation_status, cve_id);
CREATE INDEX binding_product_idx
    ON cve_applicability_binding(product_id, cve_id, binding_revision_id);
CREATE INDEX binding_member_assertion_idx
    ON binding_assertion_member(assertion_id, is_active);
CREATE INDEX llm_result_status_idx
    ON llm_result(status, cve_id);
CREATE INDEX llm_claim_cve_axis_idx
    ON llm_claim(cve_id, axis);
CREATE INDEX llm_claim_admission_idx
    ON llm_claim(admission_status, axis);
CREATE INDEX issue_code_status_idx
    ON normalization_issue(failure_code, status);
CREATE INDEX issue_cve_idx
    ON normalization_issue(cve_id);
CREATE INDEX source_defect_code_idx
    ON source_defect(defect_code, severity);
