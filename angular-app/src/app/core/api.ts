import { HttpClient, HttpErrorResponse, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import {
  ArchiveEntry, ArchiveFile, AuditEntry, BrandingInfo, Catalog, Classifier, ConnectionTestResult, ConnectorType, Country, Coverage, Dashboard, DocFinding, DocIndexStatus, DocNameLlmSettings, DocRedactionBatch, DocRedactionTask, DocScan, DocSource, EligibleDocument, ErasureRequest, EvaluableGroup, EvaluateResult, Finding, Hierarchy,
  HoldCustomerHit, HoldTree, JurisdictionReport, LegalHold, LlmOpinion, LlmSettings, Lookups, OrgInput, Organization, Policy, PolicyInput, Region, RowPreview, RuleInput, Scan,
  SearchResult, Snapshot, Source, SourceConnectionInput, Task, UcTaggingSettings, UcTaggingStats, VectorSearchSettings, Violation,
} from './models';

/** Turns a FastAPI error body (string or pydantic list) into a readable message. */
export function errorMessage(e: unknown): string {
  if (e instanceof HttpErrorResponse) {
    const d = e.error?.detail;
    if (typeof d === 'string') return d;
    if (Array.isArray(d)) return d.map((x) => `${x.loc?.slice(1).join('.')}: ${x.msg}`).join('; ');
    if (e.status === 0) return 'Cannot reach the API. Is the backend running on port 8001?';
  }
  return 'Something went wrong';
}

@Injectable({ providedIn: 'root' })
export class Api {
  private http = inject(HttpClient);

  lookups() { return this.http.get<Lookups>('/api/lookups'); }
  dashboard() { return this.http.get<Dashboard>('/api/dashboard'); }

  // sources / catalog / scans
  sources() { return this.http.get<Source[]>('/api/sources'); }
  connectorTypes() { return this.http.get<ConnectorType[]>('/api/sources/connector-types'); }
  testSourceConnection(body: SourceConnectionInput) { return this.http.post<ConnectionTestResult>('/api/sources/test', body); }
  createSource(body: SourceConnectionInput & { name: string }) { return this.http.post<Source & { tested: ConnectionTestResult }>('/api/sources', body); }
  deleteSource(id: number) { return this.http.delete<{ deleted_source: string; rules_removed: string[] }>(`/api/sources/${id}`); }
  setPushdownEnabled(id: number, enabled: boolean) { return this.http.put<Source>(`/api/sources/${id}/pushdown`, { enabled }); }
  discover(id: number) { return this.http.post<{ tables: number; columns: number; fk_links: number; inferred_links: number }>(`/api/sources/${id}/discover`, {}); }
  catalog(id: number) { return this.http.get<Catalog>(`/api/sources/${id}/catalog`); }
  scans() { return this.http.get<Scan[]>('/api/scans'); }
  startScan(body: { source_id: number; mode: string; sample_size: number | null; tables: string[] | null }) {
    return this.http.post<Scan>('/api/scans', body);
  }

  // document (PDF folder) sources - parallel to sources/catalog/scans/findings above, not the same shape
  docSources() { return this.http.get<DocSource[]>('/api/doc-sources'); }
  createDocSource(name: string, folder_path: string, domain?: string | null) { return this.http.post<DocSource>('/api/doc-sources', { name, folder_path, domain }); }
  deleteDocSource(id: number) { return this.http.delete<void>(`/api/doc-sources/${id}`); }
  discoverDocSource(id: number) { return this.http.post<{ documents: number }>(`/api/doc-sources/${id}/discover`, {}); }
  scanDocSource(id: number) { return this.http.post<{ doc_scan_id: number }>(`/api/doc-sources/${id}/scan`, {}); }
  docScans(doc_source_id?: number) { return this.http.get<DocScan[]>('/api/doc-scans', { params: doc_source_id ? { doc_source_id } : {} }); }
  docFindings(f: { doc_source_id?: number; status?: string; category?: string; include_low?: boolean }) {
    let p = new HttpParams();
    for (const [k, v] of Object.entries(f)) if (v !== undefined && v !== '' && v !== null) p = p.set(k, String(v));
    return this.http.get<DocFinding[]>('/api/doc-findings', { params: p });
  }
  decideDocFinding(id: number, status: string) { return this.http.put<DocFinding>(`/api/doc-findings/${id}`, { status }); }

  // LLM-assisted name detection for documents - a second source of FULL_NAME candidates alongside the
  // dictionary pairing, off by default (rg/name_llm.py)
  docNameLlmSettings() { return this.http.get<DocNameLlmSettings>('/api/doc-name-llm/settings'); }
  saveDocNameLlmSettings(body: Partial<Pick<DocNameLlmSettings, 'enabled' | 'model' | 'base_url' | 'timeout'>>) {
    return this.http.put<DocNameLlmSettings>('/api/doc-name-llm/settings', body);
  }
  docNameLlmTest() { return this.http.post<{ ok: boolean; reply: string; model: string }>('/api/doc-name-llm/test', {}); }

  // document redaction - its own lifecycle, parallel to tasks()/taskAction() above, not the same shape
  docRedactionEligible(doc_source_id: number) { return this.http.get<EligibleDocument[]>('/api/doc-redaction/eligible', { params: { doc_source_id } }); }
  docRedactionEvaluate(doc_source_id: number) { return this.http.post<{ proposed: number }>('/api/doc-redaction/evaluate', {}, { params: { doc_source_id } }); }
  docRedactionTasks(doc_source_id?: number) { return this.http.get<DocRedactionTask[]>('/api/doc-redaction/tasks', { params: doc_source_id ? { doc_source_id } : {} }); }
  docRedactionAction(id: number, action: 'approve' | 'reject' | 'execute') {
    return this.http.post<DocRedactionTask>(`/api/doc-redaction/tasks/${id}/${action}`, action === 'reject' ? { note: '' } : {});
  }
  docRedactionBatchStart(doc_source_id: number) {
    return this.http.post<{ redaction_batch_id: number }>('/api/doc-redaction/batch', {}, { params: { doc_source_id } });
  }
  docRedactionBatches(doc_source_id?: number) {
    return this.http.get<DocRedactionBatch[]>('/api/doc-redaction/batches', { params: doc_source_id ? { doc_source_id } : {} });
  }

  // semantic search - two local Chroma collections gated by role at query time, built on redaction's
  // output (rg/vectorsearch.py)
  vsSettings() { return this.http.get<VectorSearchSettings>('/api/vector-search/settings'); }
  saveVsSettings(body: Partial<VectorSearchSettings>) { return this.http.put<VectorSearchSettings>('/api/vector-search/settings', body); }
  vsTest() { return this.http.post<{ ok: boolean; embed_model: string; dimensions: number; chroma_url: string }>('/api/vector-search/test', {}); }
  vsIndexStatus(doc_source_id?: number) {
    return this.http.get<DocIndexStatus[]>('/api/vector-search/index-status', { params: doc_source_id ? { doc_source_id } : {} });
  }
  vsIndexDocument(documentId: number) {
    return this.http.post<{ document_id: number; safe_chunks: number; pii_chunks: number }>(`/api/vector-search/index/${documentId}`, {});
  }
  vsSearch(query: string, doc_source_id?: number) {
    return this.http.post<SearchResult[]>('/api/vector-search/search', { query, doc_source_id });
  }

  // findings / classifiers
  findings(f: { status?: string; category?: string; table?: string; min_conf?: number; include_low?: boolean }) {
    let p = new HttpParams();
    for (const [k, v] of Object.entries(f)) if (v !== undefined && v !== '' && v !== null) p = p.set(k, String(v));
    return this.http.get<Finding[]>('/api/findings', { params: p });
  }
  decide(id: number, status: string) { return this.http.put<Finding>(`/api/findings/${id}`, { status }); }
  classifiers() { return this.http.get<Classifier[]>('/api/classifiers'); }
  createClassifier(c: object) { return this.http.post<Classifier>('/api/classifiers', c); }
  toggleClassifier(id: number, is_active: boolean) { return this.http.put<Classifier>(`/api/classifiers/${id}`, { is_active }); }
  deleteClassifier(id: number) { return this.http.delete<void>(`/api/classifiers/${id}`); }

  // policies / rules
  policies() { return this.http.get<Policy[]>('/api/policies'); }
  policy(id: number) { return this.http.get<Policy>(`/api/policies/${id}`); }
  createPolicy(p: PolicyInput) { return this.http.post<Policy>('/api/policies', p); }
  updatePolicy(id: number, p: PolicyInput) { return this.http.put<Policy>(`/api/policies/${id}`, p); }
  deletePolicy(id: number) { return this.http.delete<void>(`/api/policies/${id}`); }
  createRule(policyId: number, r: Partial<RuleInput>) { return this.http.post<Policy>(`/api/policies/${policyId}/rules`, r); }
  updateRule(id: number, r: Partial<RuleInput>) { return this.http.put<Policy>(`/api/rules/${id}`, r); }
  deleteRule(id: number) { return this.http.delete<Policy>(`/api/rules/${id}`); }

  // remediation
  evaluateScope() { return this.http.get<EvaluableGroup[]>('/api/evaluate/scope'); }
  evaluate(ruleIds?: number[], sourceId?: number | null) {
    return this.http.post<EvaluateResult>('/api/evaluate', { rule_ids: ruleIds ?? null, source_id: sourceId ?? null });
  }
  violations() { return this.http.get<Violation[]>('/api/violations'); }
  tasks() { return this.http.get<Task[]>('/api/tasks'); }
  task(id: number) { return this.http.get<Task>(`/api/tasks/${id}`); }
  taskPreview(id: number, limit = 20) { return this.http.get<RowPreview>(`/api/tasks/${id}/preview`, { params: { limit } }); }
  taskAction(id: number, action: 'plan' | 'approve' | 'reject' | 'repropose' | 'execute') {
    return this.http.post<Task>(`/api/tasks/${id}/${action}`, action === 'reject' ? { note: '' } : {});
  }

  // erasure
  erasures() { return this.http.get<ErasureRequest[]>('/api/erasure'); }
  erasure(id: number) { return this.http.get<ErasureRequest>(`/api/erasure/${id}`); }
  erasureSamples() { return this.http.get<{ label: string; search_value: string }[]>('/api/erasure-samples'); }
  createErasure(search_value: string, reason: string) { return this.http.post<ErasureRequest>('/api/erasure', { search_value, reason }); }
  selectSubject(id: number, root_table: string, key: string) { return this.http.post<ErasureRequest>(`/api/erasure/${id}/subject`, { root_table, key }); }
  erasureAction(id: number, action: 'approve' | 'reject' | 'execute') { return this.http.post<ErasureRequest>(`/api/erasure/${id}/${action}`, {}); }
  holds(status?: string) { return this.http.get<LegalHold[]>('/api/legal-holds', { params: status ? { status } : {} }); }
  holdCustomers(q: string) { return this.http.get<HoldCustomerHit[]>('/api/legal-holds/customers', { params: { q } }); }
  holdCustomer(sourceId: number, id: number) { return this.http.get<HoldTree>(`/api/legal-holds/customer/${id}`, { params: { source_id: sourceId } }); }
  setHoldFlag(source_id: number, root_table: string, key_value: string, flag: 'Y' | 'N', reason: string, matter_ref = '') {
    return this.http.post<LegalHold>('/api/legal-holds/flag', { source_id, root_table, key_value, flag, reason, matter_ref });
  }
  releaseHold(id: number, reason: string) { return this.http.post<LegalHold>(`/api/legal-holds/${id}/release`, { reason }); }

  // optional LLM second opinion (off by default)
  llmSettings() { return this.http.get<LlmSettings>('/api/llm/settings'); }
  saveLlmSettings(body: Partial<Pick<LlmSettings, 'enabled' | 'provider' | 'model' | 'base_url' | 'sample_level' | 'timeout'>>) {
    return this.http.put<LlmSettings>('/api/llm/settings', body);
  }
  llmTest() { return this.http.post<{ ok: boolean; reply: string; provider: string; model: string }>('/api/llm/test', {}); }
  llmOpinions() { return this.http.get<LlmOpinion[]>('/api/llm/opinions'); }

  // Unity Catalog governed-tag write-back on finding confirmation (off by default)
  ucTaggingSettings() { return this.http.get<UcTaggingSettings>('/api/uc-tagging/settings'); }
  saveUcTaggingSettings(body: UcTaggingSettings) { return this.http.put<UcTaggingSettings>('/api/uc-tagging/settings', body); }
  ucTaggingStats() { return this.http.get<UcTaggingStats>('/api/uc-tagging/stats'); }
  ucTaggingCommit() { return this.http.post<{ tagged: number; untagged: number }>('/api/uc-tagging/commit', {}); }
  llmOpinion(findingId: number, refresh = false) {
    return this.http.post<LlmOpinion>(`/api/llm/opinion/${findingId}`, {}, { params: refresh ? { refresh: 'true' } : {} });
  }

  // organisation, branding, hierarchy
  branding() { return this.http.get<BrandingInfo>('/api/branding'); }
  orgs() { return this.http.get<Organization[]>('/api/organizations'); }
  createOrg(o: OrgInput) { return this.http.post<Organization>('/api/organizations', o); }
  updateOrg(id: number, o: OrgInput) { return this.http.put<Organization>(`/api/organizations/${id}`, o); }
  activateOrg(id: number) { return this.http.post<Organization>(`/api/organizations/${id}/activate`, {}); }
  deleteOrg(id: number) { return this.http.delete<void>(`/api/organizations/${id}`); }
  hierarchy() { return this.http.get<Hierarchy>('/api/hierarchy'); }
  createRegion(r: object) { return this.http.post<Region>('/api/regions', r); }
  updateRegion(id: number, r: object) { return this.http.put<Region>(`/api/regions/${id}`, r); }
  deleteRegion(id: number) { return this.http.delete<void>(`/api/regions/${id}`); }
  createCountry(c: object) { return this.http.post<Country>('/api/countries', c); }
  updateCountry(id: number, c: object) { return this.http.put<Country>(`/api/countries/${id}`, c); }
  deleteCountry(id: number) { return this.http.delete<void>(`/api/countries/${id}`); }
  coverage(country?: string) { return this.http.get<Coverage>('/api/coverage', { params: country ? { country } : {} }); }
  jurisdiction() { return this.http.get<JurisdictionReport>('/api/jurisdiction'); }
  classifierScope(id: number, s: object) { return this.http.put<Classifier>(`/api/classifiers/${id}/scope`, s); }

  // demo data + audit
  snapshot(source_id = 1) { return this.http.get<Snapshot>('/api/snapshot', { params: { source_id } }); }
  restore(source_id = 1) { return this.http.post<{ tables_restored: number }>('/api/snapshot/restore', {}, { params: { source_id } }); }
  restoreTables(tables: string[], source_id = 1) { return this.http.post<{ tables_restored: string[] }>('/api/snapshot/restore-tables', { tables, source_id }); }
  retake(source_id = 1) { return this.http.post<{ tables: number }>('/api/snapshot/retake', {}, { params: { source_id } }); }
  clearAll() { return this.http.post<{ tables_restored: number; chunks_cleared: number }>('/api/snapshot/clear-all', {}); }
  audit() { return this.http.get<AuditEntry[]>('/api/audit'); }

  // archived records (the ARCHIVE remediation action)
  archives(table?: string) { return this.http.get<ArchiveEntry[]>('/api/archive', { params: table ? { table } : {} }); }
  archiveFile(id: number) { return this.http.get<ArchiveFile>(`/api/archive/${id}/file`); }
}
