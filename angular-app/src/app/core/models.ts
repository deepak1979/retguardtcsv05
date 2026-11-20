export type Role = 'admin' | 'steward' | 'viewer';

export interface User { user_id: number; username: string; full_name: string; role: Role; }

// ---------------------------------------------------------------- policies & rules
export interface Rule {
  rule_id: number; policy_id: number; rule_order: number; name: string; description: string;
  trigger_event: string; action: string; masking_method: string | null; enforcement_mode: string | null;
  min_confidence: number | null; element_filter: string | null; table_filter: string | null;
  source_id: number | null; target_table: string | null; anchor_column: string | null; retention_days: number | null;
  cascade_scope: string | null; anonymization_level: string | null; is_active: boolean;
}

export interface MatchedFinding {
  finding_id: number; table_name: string; column_name: string; data_element: string;
  confidence: number; status: string; protection: string; rule: string;
}

export interface Policy {
  policy_id: number; policy_code: string; name: string; description: string; data_category: string;
  regulation: string; status: 'DRAFT' | 'ACTIVE' | 'RETIRED'; version: number; owner: string | null;
  effective_from: string | null; created_at: string; updated_at: string; rule_count: number;
  rules?: Rule[]; matched_findings?: MatchedFinding[];
  scope_level: string; region_id: number | null; country_id: number | null; override_parent: number;
  scope_label: string; scope_valid: boolean; covered_countries?: string[];
}

export interface PolicyInput {
  name: string; description: string; data_category: string; regulation: string; status: string;
  policy_code?: string | null; effective_from?: string | null;
  scope_level?: string; region_id?: number | null; country_id?: number | null; override_parent?: boolean;
}

export type RuleInput = Omit<Rule, 'rule_id' | 'policy_id' | 'rule_order'>;

export interface Lookups {
  data_categories: string[]; trigger_events: string[]; rule_actions: string[]; masking_methods: string[];
  enforcement_modes: string[]; cascade_scopes: string[]; policy_statuses: string[]; regulations: string[];
  roles: string[]; anonymization_levels: { code: string; help: string }[];
  scope_levels: string[]; regions: { region_id: number; code: string; name: string; is_active: boolean }[];
  countries: { country_id: number; iso2: string; name: string; region_id: number; is_active: boolean }[];
  data_elements: { code: string; name: string; category: string; pii_class: string }[];
}

// ---------------------------------------------------------------- sources, catalog, scans
export interface Source {
  source_id: number; name: string; source_type: string; host: string; port: number; service_name: string;
  schema_name: string; status: string; last_discovered_at: string | null; last_scan_at: string | null;
  tables: number; columns: number; sourcesys: string | null; domain: string | null;
  is_pushdown_enabled: boolean;
}

export interface ConnectorType {
  code: string; label: string; default_port: number; service_label: string; live: boolean;
  host_label?: string; username_label?: string; password_label?: string;
}

export interface SourceConnectionInput {
  source_type: string; host: string | null; port: number | null; service_name: string | null;
  username: string | null; password: string | null; domain?: string | null;
}

export interface ConnectionTestResult { ok: boolean; message: string; detail: string | null; }

export interface Scan {
  scan_id: number; source_id: number; scan_mode: string; sample_size: number | null; status: string;
  tables_total: number; tables_done: number; columns_scanned: number; findings_total: number;
  findings_new: number; findings_resolved: number; message: string | null; requested_by: string;
  started_at: string | null; finished_at: string | null; created_at: string;
}

export interface CatalogFinding {
  finding_id: number; column_name: string; data_element: string; category: string; confidence: number;
  status: string; protection: string;
}
export interface CatalogColumn {
  table_name: string; column_name: string; data_type: string; data_length: number; is_nullable: boolean;
  is_pk: boolean; ordinal: number; null_ratio: number | null; distinct_ratio: number | null;
  findings: CatalogFinding[];
}
export interface CatalogTable {
  table_name: string; row_count: number; column_count: number; pii_columns: number; columns: CatalogColumn[];
}
export interface LineageEdge {
  child_table: string; child_column: string; parent_table: string; parent_column: string;
  kind: 'FK' | 'INFERRED'; confidence: number;
}
export interface Catalog { tables: CatalogTable[]; lineage: LineageEdge[]; }

export interface Finding {
  finding_id: number; table_name: string; column_name: string; data_element: string; category: string;
  pii_class: string | null; confidence: number; name_hit: number; match_ratio: number | null;
  rows_sampled: number | null; status: string; protection: string; decided_by: string | null;
  samples: string | null;
}

// Document (PDF folder) governance - parallel to Source/Scan/Finding above, not the same shape (a
// document has no rows/columns to scan a sample of - see rg/docscan.py).
export interface DocSource {
  doc_source_id: number; name: string; folder_path: string; status: string;
  last_discovered_at: string | null; last_scan_at: string | null; created_at: string; domain: string | null;
  documents: number; findings: number;
}
export interface DocScan {
  doc_scan_id: number; doc_source_id: number; status: string; documents_total: number; documents_done: number;
  findings_total: number; findings_new: number; findings_resolved: number; message: string | null;
  requested_by: string; started_at: string | null; finished_at: string | null; created_at: string;
}
export interface DocFinding {
  doc_finding_id: number; document_id: number; file_name: string; file_path: string; doc_source_id: number;
  source: string; field_name: string; data_element: string; category: string; pii_class: string | null;
  confidence: number; match_count: number; status: string; decided_by: string | null; samples: string | null;
}

/** LLM-assisted name detection for the document body-text sweep - local only, see rg/name_llm.py. */
export interface DocNameLlmSettings {
  enabled: boolean; master_llm_enabled: boolean; active: boolean; model: string; base_url: string; timeout: number;
}

// Document redaction - its own lifecycle (PROPOSED/APPROVED/REJECTED/EXECUTED/FAILED), parallel to
// Task (table remediation) above, not the same shape. The source PDF is never modified - see rg/redact.py.
export interface EligibleDocument {
  document_id: number; file_name: string; doc_source_id: number; pending_findings: number;
}
export interface DocRedactionTask {
  redaction_task_id: number; document_id: number; file_name: string; file_path: string; doc_source_id: number;
  status: string; element_summary: string | null; output_path: string | null; redaction_count: number | null;
  requested_by: string; approved_by: string | null; approved_at: string | null; executed_at: string | null;
  note: string | null; created_at: string;
}
/** "Redact all" background job - propose + approve + execute every eligible document in one go. */
export interface DocRedactionBatch {
  redaction_batch_id: number; doc_source_id: number; status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  documents_total: number; documents_done: number; documents_failed: number; redactions_total: number;
  message: string | null; requested_by: string; started_at: string | null; finished_at: string | null; created_at: string;
}

// Semantic search - two local Chroma collections (redacted "safe", unredacted "pii"), gated by role at
// query time, built on top of redaction's output. See rg/vectorsearch.py.
export interface VectorSearchSettings {
  enabled: boolean; chroma_url: string; ollama_base_url: string; embed_model: string; timeout: number;
}
export interface DocIndexStatus {
  document_id: number; file_name: string; doc_source_id: number;
  state: 'NOT_REDACTED' | 'NOT_INDEXED' | 'STALE' | 'INDEXED' | 'FAILED';
  safe_chunk_count: number | null; pii_chunk_count: number | null; indexed_at: string | null; message: string | null;
}
export interface SearchResult {
  document_id: number; file_name: string; doc_source_id: number; chunk_index: number;
  snippet: string; score: number; source: 'safe' | 'pii';
}

export interface Classifier {
  classifier_id: number; code: string; name: string; category: string; pii_class: string; applies_to: string;
  name_pattern: string | null; content_method: string; content_pattern: string | null; min_match_ratio: number | null;
  name_weight: number; content_weight: number; description: string; is_active: boolean; is_builtin: boolean;
  scope_level: string; region_id: number | null; country_id: number | null; scope_label: string; scope_valid: boolean;
}

export interface Snapshot {
  snapshots: { table_name: string; backup_table: string; row_count: number; current_rows: number; differs: boolean }[];
  modified_tables: string[]; masked_views: string[];
}

// ---------------------------------------------------------------- remediation
export interface Violation {
  violation_id: number; policy_id: number; rule_id: number; source_id: number; source_name: string;
  violation_type: string; table_name: string;
  detail: string; columns: string[]; rows_affected: number; status: string; detected_at: string;
  policy_code: string; policy_name: string; rule_name: string; task_id: number | null;
}

export interface PlanStep {
  table: string; operation: string; est_rows?: number; rows?: number; sql: string | null; reason?: string;
  columns?: string[]; archive_id?: number; archive_file?: string; note?: string;
}
export interface ArchiveEntry {
  archive_id: number; task_id: number | null; rule_id: number | null; policy_code: string | null; table_name: string;
  anchor_column: string | null; retention_days: number | null; file_path: string; row_count: number;
  primary_key_column: string | null; created_by: string; created_at: string;
}
export interface ArchiveFile {
  table: string; row_count: number; primary_key_column: string | null;
  rule: { rule_id: number | null; name: string | null; policy_code: string | null };
  anchor_column: string | null; retention_days: number | null; archived_at: string; archived_by: string;
  columns: string[]; rows: Record<string, unknown>[];
}
export interface RowPreview {
  table: string; columns: string[]; masked_columns: string[]; rows: unknown[][]; total: number; shown: number;
}
export interface Plan {
  kind: string; rule: string; policy: string; action: string; table: string; mode: string;
  method?: string; view?: string; blocked: string | null; notes: string[]; steps: PlanStep[];
  columns: { column: string; element: string; confidence: number; treatment?: string; note?: string }[];
  level?: string; scope?: string; scope_level?: string;
}
export interface Task {
  task_id: number; violation_id: number | null; rule_id: number; source_id: number; source_name: string;
  action: string; table_name: string;
  title: string; status: string; verified: boolean | null; requested_by: string; approved_by: string | null;
  executed_at: string | null; created_at: string; note: string | null;
  plan?: Plan; result?: { steps: PlanStep[]; verified: boolean; verification: string };
  evidence?: Evidence[];
}
export interface Evidence { evidence_id: number; summary: string; verification: string; created_by: string; created_at: string; }

// ---------------------------------------------------------------- erasure
export interface Candidate {
  root_table: string; key: string; found_in: { table: string; column: string; element: string }[];
  preview: Record<string, string>; country?: string | null; customer_no?: string | null;
  source_id: number; source_name?: string | null;
}
export interface ErasureStep {
  table: string; operation: string; rows: number; sql: string | null; reason: string; held_rows?: number;
  treatments?: { column: string; element: string; treatment: string; note: string }[];
}
export interface ErasurePlan {
  root_table: string; root_key: string; blocked: string | null; notes: string[]; steps: ErasureStep[]; level?: string | null;
  jurisdiction?: { iso2: string | null; name: string | null };
  root_held?: boolean; hold_ids?: number[]; held?: { table: string; rows: number; holds: number[] }[];
  rule: { name: string; policy: string; action: string; cascade_scope: string; anonymization_level?: string; scope?: string } | null;
}
export interface ErasureRequest {
  request_id: number; search_value: string; reason: string; status: string; root_table: string | null;
  root_key: string | null; verified: boolean | null; requested_by: string; approved_by: string | null;
  executed_at: string | null; created_at: string; source_id: number; source_name: string;
  candidates?: Candidate[] | null; plan?: ErasurePlan | null;
  result?: { steps: ErasureStep[]; verified: boolean; verification: string; held?: { table: string; rows: number; holds: number[] }[];
             documents?: { documents_removed: number; chunks_removed?: number; files_removed?: number; chroma_note?: string | null;
                           skipped?: boolean; reason?: string; error?: string } | null } | null;
  evidence?: Evidence[];
}
export interface LegalHold {
  hold_id: number; source_id: number; root_table: string; key_value: string; reason: string; status: string;
  created_by: string; created_at: string; released_at: string | null;
  matter_ref: string | null; entity_label: string | null; customer_ref: string | null; released_by: string | null; release_reason: string | null;
}
export interface EvaluableRule {
  rule_id: number; name: string; trigger_event: string; action: string;
  source_name: string | null; target_table: string | null;
}
export interface EvaluableGroup {
  policy_id: number; policy_code: string; policy_name: string; data_category: string;
  scope_level: string; scope: string; rules: EvaluableRule[];
}
export interface EvaluateResult { open_violations: number; tasks_proposed: number; resolved: number; rules_evaluated: number; rules_total: number }
export interface LlmProvider { code: string; label: string; default_model: string; default_url: string; needs_key: boolean; local: boolean }
export type LlmSampleLevel = 'NONE' | 'MASKED' | 'REAL';
export interface LlmSettings {
  enabled: boolean; provider: string; model: string; base_url: string; sample_level: LlmSampleLevel; send_samples: boolean;
  timeout: number; local: boolean; key_present: boolean; prompt_version: string; sample_levels: LlmSampleLevel[]; providers: LlmProvider[];
}
export interface LlmOpinion {
  opinion_id: number; finding_id: number; verdict: 'AGREE' | 'DISAGREE' | 'UNSURE'; suggested: string | null; confidence: number | null;
  reason: string | null; provider: string; model: string; samples_sent: number; sample_level: LlmSampleLevel;
  created_by: string; created_at: string; cached?: boolean;
}
/** Off by default - writes a real Unity Catalog `pii_classification` column tag the moment a steward
 * CONFIRMS a classifier-sourced finding, but only when the column has no native tag already. */
export interface UcTaggingSettings { enabled: boolean; }
export interface UcTaggingStats { tagged: number; eligible_untagged: number; }
/** Y = this record is on hold, COVERED = held because of a related record, N = free. */
export type HoldFlag = 'Y' | 'N' | 'COVERED';
export interface HoldCustomerHit {
  customer_id: number; customer_no: string; name: string; email: string | null; country: string | null; city: string | null;
  policies: number; claims: number; hold: HoldFlag; source_id: number; source_name: string;
}
export interface HoldRecord {
  table: string; kind_label: string; key: string; label: string; hold: HoldFlag; hold_id: number | null;
  reason: string | null; matter_ref: string | null; held_by: string | null; held_at: string | null;
  covered_by: { hold_id: number; relation: 'SELF' | 'BELOW' | 'ABOVE'; entity: string }[];
  name?: string; email?: string | null; country?: string | null; city?: string | null; status?: string | null; date?: string | null;
  kind?: string | null; policy_id?: string | null;
}
export interface HoldTree { customer: HoldRecord; policies: HoldRecord[]; claims: HoldRecord[]; history: LegalHold[] }

// ---------------------------------------------------------------- dashboard & audit
export interface Dashboard {
  tables_cataloged: number; columns_cataloged: number; sensitive_findings: number; needs_review: number;
  sensitive_protected: number; active_policies: number; active_rules: number; open_violations: number;
  tasks_awaiting_approval: number; tasks_verified: number; erasure_requests: number; erasure_verified: number;
  active_holds: number; by_table: { table_name: string; findings: number; unprotected: number; health: number }[];
  tasks_by_status: Record<string, number>; last_scan: Scan | null;
  recent_activity: { ts: string; username: string; entity_type: string; action: string; details: string }[];
}

export interface AuditEntry {
  audit_id: number; ts: string; username: string; entity_type: string; entity_id: number; action: string; details: string;
}

// ---------------------------------------------------------------- organisation, branding, hierarchy
export interface BrandingInfo {
  org_id: number | null; code?: string; name: string; tagline: string; logo: string | null;
  banner_color: string; primary_color: string;
}
export interface Organization {
  org_id: number; code: string; name: string; tagline: string | null; logo_url: string | null; logo: string | null;
  banner_color: string; primary_color: string; is_active: boolean; regions: number;
}
export interface OrgInput {
  name: string; code?: string | null; tagline?: string | null; logo_url?: string | null; logo_data?: string | null;
  clear_logo?: boolean; banner_color: string; primary_color: string; seed_hierarchy?: boolean;
}
export interface Country {
  country_id: number; region_id: number; iso2: string; name: string; regulation: string | null;
  regulator: string | null; notes: string | null; is_active: boolean; policies: number; classifiers: number;
}
export interface Region {
  region_id: number; org_id: number; code: string; name: string; description: string | null; sort_order: number;
  is_active: boolean; policies: number; classifiers: number; countries: Country[];
}
export interface Hierarchy {
  org: BrandingInfo; global: { policies: number; classifiers: number }; regions: Region[];
}
export interface CoverageRule {
  rule_id: number; rule: string; policy_code: string; scope: string; scope_level: string; action: string; trigger: string;
  detail: string; effective: boolean; overridden_by: string | null;
}
export interface Coverage {
  country: { iso2: string; name: string; regulation: string | null; regulator: string | null } | null;
  region: { code: string; name: string } | null;
  groups: { level: string; title: string; policies: { policy_id: number; policy_code: string; name: string; status: string; data_category: string; rule_count: number; override_parent: boolean }[] }[];
  rules: CoverageRule[];
  classifiers: { classifier_id: number; code: string; name: string; category: string; pii_class: string; scope_level: string; scope: string }[];
}
export interface JurisdictionReport {
  tables: { table: string; source: string; via: string[]; country_table: string | null; country_column: string | null;
            distribution: { country: string | null; rows: number }[] }[];
  unmapped_countries: string[];
}
