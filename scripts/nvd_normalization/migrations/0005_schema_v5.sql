PRAGMA foreign_keys = ON;

CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE rule_configuration (
    rule_configuration_id INTEGER PRIMARY KEY,
    framework_version TEXT NOT NULL,
    configuration_json TEXT NOT NULL,
    configuration_sha256 TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE source_snapshot_manifest (
    snapshot_id INTEGER PRIMARY KEY,
    source_family TEXT NOT NULL,
    source_channel TEXT NOT NULL,
    source_path TEXT NOT NULL,
    upstream_last_modified TEXT,
    downloaded_at TEXT NOT NULL,
    payload_sha256 TEXT,
    byte_size INTEGER,
    record_count INTEGER,
    coverage_start TEXT,
    coverage_end TEXT,
    is_complete INTEGER NOT NULL,
    retrieval_mode TEXT NOT NULL,
    api_result_total INTEGER,
    status TEXT NOT NULL
);

CREATE TABLE pipeline_run (
    pipeline_run_id INTEGER PRIMARY KEY,
    run_uuid TEXT NOT NULL UNIQUE,
    snapshot_id INTEGER NOT NULL REFERENCES source_snapshot_manifest,
    rule_configuration_id INTEGER NOT NULL REFERENCES rule_configuration,
    framework_version TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    status TEXT NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0,
    issue_count INTEGER NOT NULL DEFAULT 0,
    summary_json TEXT
);

CREATE TABLE binding_revision (
    binding_revision_id INTEGER PRIMARY KEY,
    pipeline_run_id INTEGER NOT NULL REFERENCES pipeline_run,
    reinterpretation_token TEXT NOT NULL,
    framework_version TEXT NOT NULL,
    rule_configuration_id INTEGER NOT NULL REFERENCES rule_configuration,
    llm_extraction_run_id INTEGER,
    state TEXT NOT NULL,
    published_at TEXT,
    superseded_by INTEGER REFERENCES binding_revision,
    identity_cluster_digest TEXT
);

CREATE TABLE raw_cve (
    cve_id TEXT PRIMARY KEY,
    snapshot_id INTEGER NOT NULL REFERENCES source_snapshot_manifest,
    line_number INTEGER NOT NULL,
    byte_offset INTEGER NOT NULL,
    byte_length INTEGER NOT NULL,
    raw_sha256 TEXT NOT NULL,
    source_identifier TEXT,
    vuln_status TEXT NOT NULL,
    published TEXT,
    last_modified TEXT,
    primary_description TEXT,
    has_cpe_configuration INTEGER NOT NULL,
    has_cna_affected INTEGER NOT NULL,
    has_llm_identity INTEGER NOT NULL DEFAULT 0,
    enrichment_class TEXT NOT NULL,
    admission_status TEXT NOT NULL
);

CREATE TABLE description (
    description_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES raw_cve,
    language TEXT,
    description_bytes BLOB NOT NULL,
    source_pointer TEXT NOT NULL,
    UNIQUE (cve_id, source_pointer)
);

CREATE TABLE product_entity (
    product_id INTEGER PRIMARY KEY,
    vendor_key TEXT NOT NULL,
    product_key TEXT NOT NULL,
    part TEXT NOT NULL,
    canonical_vendor TEXT NOT NULL,
    canonical_product TEXT NOT NULL,
    label_basis TEXT NOT NULL,
    label_priority INTEGER NOT NULL,
    version_profile TEXT,
    UNIQUE (vendor_key, product_key, part)
);

CREATE TABLE product_alias (
    product_alias_id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES product_entity,
    vendor_raw TEXT NOT NULL,
    product_raw TEXT NOT NULL,
    source_family TEXT NOT NULL,
    evidence_basis TEXT NOT NULL,
    UNIQUE (product_id, vendor_raw, product_raw, source_family)
);

CREATE TABLE identity_node (
    node_id INTEGER PRIMARY KEY,
    node_key TEXT NOT NULL UNIQUE,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('vendor','product')),
    vendor_key TEXT NOT NULL,
    product_key TEXT,
    part TEXT,
    product_id INTEGER UNIQUE REFERENCES product_entity,
    CHECK (
        (scope_kind='vendor' AND product_key IS NULL AND part IS NULL AND product_id IS NULL)
        OR
        (scope_kind='product' AND product_key IS NOT NULL AND part IS NOT NULL AND product_id IS NOT NULL)
    )
);

CREATE TABLE identity_key (
    node_id INTEGER NOT NULL REFERENCES identity_node,
    key_kind TEXT NOT NULL CHECK (key_kind IN (
        'safe','separator','legal_root','org_root','acronym',
        'digit_signature','token_multiset'
    )),
    key_value TEXT NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN (
        'canonical_entity','raw_alias_observation','registry_strict','registry_non_strict'
    )),
    source_alias_id INTEGER NOT NULL DEFAULT 0,
    derivation_rule TEXT NOT NULL,
    CHECK (
        (origin='raw_alias_observation' AND source_alias_id>0)
        OR
        (origin<>'raw_alias_observation' AND source_alias_id=0)
    ),
    PRIMARY KEY (node_id,key_kind,key_value,origin,source_alias_id)
) WITHOUT ROWID;

CREATE TABLE identity_alias_edge (
    edge_id INTEGER PRIMARY KEY,
    left_node_id INTEGER NOT NULL REFERENCES identity_node,
    right_node_id INTEGER NOT NULL REFERENCES identity_node,
    alias_class TEXT NOT NULL CHECK (alias_class IN (
        'A1_SEPARATOR','A2_LEGAL_SUFFIX','A3_ORG_SUFFIX',
        'B1_ACRONYM','B2_BRAND_ALIAS','B3_TYPO'
    )),
    evidence_tier TEXT NOT NULL CHECK (evidence_tier IN ('E0','E1','E2','E3','E4')),
    corroboration_independence TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'accepted','provisional','candidate','rejected','superseded'
    )),
    strict_eligible INTEGER NOT NULL,
    basis_json TEXT NOT NULL,
    registry_version TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    CHECK (left_node_id < right_node_id),
    UNIQUE (left_node_id,right_node_id,alias_class,registry_version)
);

CREATE TABLE identity_hard_distinct (
    left_node_id INTEGER NOT NULL REFERENCES identity_node,
    right_node_id INTEGER NOT NULL REFERENCES identity_node,
    basis TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    CHECK (left_node_id < right_node_id),
    PRIMARY KEY (left_node_id,right_node_id)
) WITHOUT ROWID;

CREATE TABLE identity_cluster (
    cluster_id INTEGER PRIMARY KEY,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('vendor','product')),
    canonical_node_id INTEGER NOT NULL REFERENCES identity_node,
    member_count INTEGER NOT NULL,
    max_tier TEXT NOT NULL CHECK (max_tier IN (
        'T0_EXACT','T1_FORMAT','T2_REGISTRY','T3_PROVISIONAL'
    )),
    strict_eligible INTEGER NOT NULL,
    review_state TEXT NOT NULL CHECK (review_state IN ('ok','cluster_review')),
    cluster_digest TEXT NOT NULL UNIQUE
);

CREATE TABLE identity_cluster_member (
    cluster_id INTEGER NOT NULL REFERENCES identity_cluster,
    node_id INTEGER NOT NULL REFERENCES identity_node,
    product_id INTEGER REFERENCES product_entity,
    join_tier TEXT NOT NULL,
    strict_eligible INTEGER NOT NULL,
    PRIMARY KEY (cluster_id,node_id),
    UNIQUE (node_id)
) WITHOUT ROWID;

CREATE TABLE identity_cluster_edge (
    cluster_id INTEGER NOT NULL REFERENCES identity_cluster,
    edge_id INTEGER NOT NULL REFERENCES identity_alias_edge,
    PRIMARY KEY (cluster_id,edge_id)
) WITHOUT ROWID;

CREATE TABLE product_relation (
    relation_id INTEGER PRIMARY KEY,
    from_product_id INTEGER NOT NULL REFERENCES product_entity,
    to_product_id INTEGER NOT NULL REFERENCES product_entity,
    relation_type TEXT NOT NULL,
    propagation_policy TEXT NOT NULL,
    evidence_basis TEXT NOT NULL,
    source_claim_id INTEGER,
    llm_claim_id INTEGER,
    corroboration_independence TEXT NOT NULL,
    UNIQUE (
        from_product_id, to_product_id, relation_type,
        evidence_basis, corroboration_independence
    )
);

CREATE TABLE configuration (
    configuration_id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES raw_cve,
    configuration_index INTEGER NOT NULL,
    graph_json TEXT NOT NULL,
    graph_sha256 TEXT NOT NULL,
    UNIQUE (cve_id, configuration_index)
);

CREATE TABLE source_claim (
    source_claim_id INTEGER PRIMARY KEY,
    snapshot_id INTEGER NOT NULL REFERENCES source_snapshot_manifest,
    cve_id TEXT NOT NULL REFERENCES raw_cve,
    product_id INTEGER REFERENCES product_entity,
    source_family TEXT NOT NULL,
    source_identifier TEXT,
    json_pointer TEXT NOT NULL,
    raw_fragment_sha256 TEXT NOT NULL,
    vendor_raw TEXT,
    product_raw TEXT,
    version_raw TEXT,
    status_raw TEXT,
    default_status_raw TEXT,
    version_kind TEXT NOT NULL,
    version_resolution_class TEXT NOT NULL,
    cpe_criteria TEXT,
    cpe_match_id TEXT,
    vulnerable_flag INTEGER,
    node_path TEXT,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT,
    admission_status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (snapshot_id, cve_id, json_pointer)
);

CREATE TABLE version_expression (
    expression_id INTEGER PRIMARY KEY,
    source_claim_id INTEGER NOT NULL REFERENCES source_claim,
    version_kind TEXT NOT NULL,
    version_resolution_class TEXT NOT NULL,
    nvd_range_fields_present INTEGER NOT NULL DEFAULT 0,
    raw_expression TEXT NOT NULL,
    parse_status TEXT NOT NULL,
    parse_error_code TEXT,
    profile_name TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    semantic_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence_tier TEXT NOT NULL,
    UNIQUE (source_claim_id, semantic_fingerprint, profile_name)
);

CREATE TABLE version_segment (
    segment_id INTEGER PRIMARY KEY,
    expression_id INTEGER NOT NULL REFERENCES version_expression,
    ordinal INTEGER NOT NULL,
    status TEXT NOT NULL,
    branch_key TEXT,
    lower_bound TEXT,
    lower_inclusive INTEGER,
    lower_arity_semantics TEXT NOT NULL,
    upper_bound TEXT,
    upper_inclusive INTEGER,
    upper_arity_semantics TEXT NOT NULL,
    exact_value TEXT,
    transition_source TEXT NOT NULL,
    closure_origin TEXT,
    breadth_class TEXT NOT NULL,
    comparator_version TEXT NOT NULL,
    UNIQUE (expression_id, ordinal),
    CHECK (
        (lower_bound IS NULL AND lower_arity_semantics = 'not_applicable')
        OR
        (lower_bound IS NOT NULL AND lower_arity_semantics <> 'not_applicable')
    ),
    CHECK (
        (upper_bound IS NULL AND upper_arity_semantics = 'not_applicable')
        OR
        (upper_bound IS NOT NULL AND upper_arity_semantics <> 'not_applicable')
    )
);

CREATE TABLE applicability_scope (
    scope_id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES product_entity,
    part_state TEXT NOT NULL,
    part_value TEXT,
    distribution_state TEXT NOT NULL,
    distribution_value TEXT,
    edition_state TEXT NOT NULL,
    edition_value TEXT,
    component_state TEXT NOT NULL,
    component_value TEXT,
    update_state TEXT NOT NULL,
    update_value TEXT,
    language_state TEXT NOT NULL,
    language_value TEXT,
    sw_edition_state TEXT NOT NULL,
    sw_edition_value TEXT,
    target_sw_state TEXT NOT NULL,
    target_sw_value TEXT,
    target_hw_state TEXT NOT NULL,
    target_hw_value TEXT,
    other_state TEXT NOT NULL,
    other_value TEXT,
    configuration_id INTEGER REFERENCES configuration,
    configuration_match_id TEXT,
    cpe_match_role TEXT,
    exclusive_scope TEXT,
    scope_fingerprint TEXT NOT NULL UNIQUE,
    is_maximal INTEGER NOT NULL,
    subsumption_depth INTEGER NOT NULL
);

CREATE TABLE scope_subsumption_edge (
    subsumed_scope_id INTEGER NOT NULL REFERENCES applicability_scope,
    subsuming_scope_id INTEGER NOT NULL REFERENCES applicability_scope,
    basis TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    PRIMARY KEY (subsumed_scope_id, subsuming_scope_id)
) WITHOUT ROWID;

CREATE TABLE applicability_assertion (
    assertion_id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES raw_cve,
    scope_id INTEGER NOT NULL REFERENCES applicability_scope,
    expression_id INTEGER REFERENCES version_expression,
    source_claim_id INTEGER NOT NULL REFERENCES source_claim,
    source_family TEXT NOT NULL,
    claim_group TEXT NOT NULL,
    assertion_polarity TEXT NOT NULL,
    evidence_tier TEXT NOT NULL,
    entity_resolution_basis TEXT NOT NULL,
    llm_claim_id INTEGER,
    default_status_inferred INTEGER NOT NULL,
    default_status_effective TEXT NOT NULL,
    is_default_closure INTEGER NOT NULL,
    branch_coverage_completeness TEXT NOT NULL,
    branch_coverage_basis TEXT NOT NULL,
    version_resolution_class TEXT NOT NULL,
    max_result_state TEXT,
    cpe_match_role TEXT,
    role_basis TEXT,
    use_for_version_index INTEGER NOT NULL,
    corroboration_independence TEXT NOT NULL,
    comparison_tuple_json TEXT NOT NULL,
    breadth_class TEXT NOT NULL,
    scope_resolution_status TEXT NOT NULL,
    version_resolution_status TEXT NOT NULL,
    reconciliation_status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    rule_version TEXT NOT NULL
);

CREATE TABLE assertion_reconciliation (
    reconciliation_id INTEGER PRIMARY KEY,
    assertion_id INTEGER NOT NULL UNIQUE REFERENCES applicability_assertion,
    status TEXT NOT NULL,
    winner_assertion_id INTEGER REFERENCES applicability_assertion,
    reason TEXT NOT NULL,
    triggering_axis TEXT,
    triggering_tier TEXT,
    comparison_tuple_json TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE cve_applicability_binding (
    binding_id INTEGER PRIMARY KEY,
    binding_revision_id INTEGER NOT NULL REFERENCES binding_revision,
    cve_id TEXT NOT NULL REFERENCES raw_cve,
    product_id INTEGER NOT NULL REFERENCES product_entity,
    entity_resolution_basis TEXT NOT NULL,
    corroboration_independence TEXT NOT NULL,
    enrichment_class TEXT NOT NULL,
    provisional_llm_identity INTEGER NOT NULL,
    manual_review_required INTEGER NOT NULL,
    framework_version TEXT NOT NULL,
    llm_extraction_run_id INTEGER,
    created_at TEXT NOT NULL,
    UNIQUE (binding_revision_id, cve_id, product_id)
);

CREATE TABLE binding_assertion_member (
    binding_id INTEGER NOT NULL REFERENCES cve_applicability_binding,
    assertion_id INTEGER NOT NULL REFERENCES applicability_assertion,
    is_active INTEGER NOT NULL,
    PRIMARY KEY (binding_id, assertion_id)
) WITHOUT ROWID;

CREATE TABLE llm_extraction_run (
    extraction_run_id INTEGER PRIMARY KEY,
    run_uuid TEXT NOT NULL UNIQUE,
    model_id TEXT NOT NULL,
    model_revision TEXT NOT NULL,
    quantization TEXT,
    serving_stack TEXT NOT NULL,
    prompt_template_hash TEXT NOT NULL,
    guided_schema_hash TEXT NOT NULL,
    decoding_json TEXT NOT NULL,
    self_consistency_k INTEGER NOT NULL,
    hardware_profile TEXT,
    input_snapshot_id INTEGER NOT NULL REFERENCES source_snapshot_manifest,
    source_path TEXT NOT NULL,
    source_sha256 TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    record_count INTEGER,
    status TEXT NOT NULL
);

CREATE TABLE llm_result (
    result_id INTEGER PRIMARY KEY,
    extraction_run_id INTEGER NOT NULL REFERENCES llm_extraction_run,
    cve_id TEXT NOT NULL REFERENCES raw_cve,
    source_index INTEGER NOT NULL,
    status TEXT NOT NULL,
    description_sha256 TEXT,
    error TEXT,
    raw_model_output TEXT,
    metadata_json TEXT NOT NULL,
    UNIQUE (extraction_run_id, cve_id)
);

CREATE TABLE llm_claim (
    llm_claim_id INTEGER PRIMARY KEY,
    extraction_run_id INTEGER NOT NULL REFERENCES llm_extraction_run,
    cve_id TEXT NOT NULL REFERENCES raw_cve,
    description_id TEXT NOT NULL REFERENCES description,
    axis TEXT NOT NULL,
    claimed_role TEXT NOT NULL,
    extracted_value TEXT NOT NULL,
    relation_type TEXT,
    relation_target TEXT,
    span_unit TEXT NOT NULL,
    evidence_span_start INTEGER NOT NULL,
    evidence_span_end INTEGER NOT NULL,
    evidence_text TEXT NOT NULL,
    model_confidence REAL,
    agreement_count INTEGER NOT NULL,
    agreement_k INTEGER NOT NULL,
    admission_status TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (evidence_span_end > evidence_span_start)
);

CREATE TABLE normalization_issue (
    issue_id INTEGER PRIMARY KEY,
    failure_code TEXT NOT NULL,
    stage TEXT NOT NULL,
    severity TEXT NOT NULL,
    cve_id TEXT,
    source_claim_id INTEGER REFERENCES source_claim,
    binding_id INTEGER REFERENCES cve_applicability_binding,
    llm_claim_id INTEGER REFERENCES llm_claim,
    details_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE source_defect (
    defect_id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES raw_cve,
    defect_code TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_family TEXT NOT NULL,
    offending_claim_id INTEGER REFERENCES source_claim,
    contradicting_json TEXT NOT NULL,
    requires_human_confirmation INTEGER NOT NULL,
    confirmation_status TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TRIGGER raw_cve_no_update
BEFORE UPDATE ON raw_cve BEGIN
    SELECT RAISE(ABORT, 'raw_cve is append-only');
END;
CREATE TRIGGER raw_cve_no_delete
BEFORE DELETE ON raw_cve BEGIN
    SELECT RAISE(ABORT, 'raw_cve is append-only');
END;
CREATE TRIGGER source_claim_no_update
BEFORE UPDATE ON source_claim BEGIN
    SELECT RAISE(ABORT, 'source_claim is append-only');
END;
CREATE TRIGGER source_claim_no_delete
BEFORE DELETE ON source_claim BEGIN
    SELECT RAISE(ABORT, 'source_claim is append-only');
END;
CREATE TRIGGER llm_claim_no_update
BEFORE UPDATE ON llm_claim BEGIN
    SELECT RAISE(ABORT, 'llm_claim is append-only');
END;
CREATE TRIGGER llm_claim_no_delete
BEFORE DELETE ON llm_claim BEGIN
    SELECT RAISE(ABORT, 'llm_claim is append-only');
END;

CREATE VIEW current_binding AS
SELECT b.*
FROM cve_applicability_binding AS b
JOIN binding_revision AS r USING (binding_revision_id)
WHERE r.state = 'published' AND r.superseded_by IS NULL;

CREATE VIEW active_assertion AS
SELECT a.*
FROM applicability_assertion AS a
WHERE a.reconciliation_status IN ('active', 'conflict_review');

PRAGMA user_version = 5;
