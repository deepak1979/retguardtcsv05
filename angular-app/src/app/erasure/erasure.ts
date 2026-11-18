import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Api, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { Confirms } from '../core/confirm';
import { pretty, tone } from '../core/format';
import { Candidate, ErasureRequest, LegalHold } from '../core/models';
import { Toasts } from '../core/toast';

const STEPS = ['Request', 'Find the person', 'Plan', 'Approval', 'Erased'];

@Component({
  selector: 'app-erasure',
  imports: [FormsModule, RouterLink],
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1>Erasure requests</h1>
          <p>GDPR Art. 17. Find the person across every classified PII column, plan the removal in dependency order, respect retention and legal holds, then verify.</p>
        </div>
      </div>

      <div class="layout-split">
        <div>
          @if (auth.canEdit()) {
            <section class="card card-pad" style="margin-bottom:14px">
              <h2>New request</h2>
              <div class="field" style="margin-top:12px">
                <label for="sv">Identifier to search for</label>
                <input id="sv" type="text" placeholder="email, phone, licence ID or full name" [ngModel]="search()" (ngModelChange)="search.set($event)" />
              </div>
              <div class="field">
                <label for="rs">Reason</label>
                <input id="rs" type="text" placeholder="e.g. Art. 17 request received by email" [ngModel]="reason()" (ngModelChange)="reason.set($event)" />
              </div>
              <button class="btn btn-primary" (click)="create()" [disabled]="busy() || search().trim().length < 3">{{ busy() ? 'Searching…' : 'Search & create request' }}</button>
              @if (samples().length) {
                <div class="hint-box">
                  <span class="muted small">Try a demo subject:</span>
                  @for (s of samples(); track s.label) { <button class="sample" (click)="search.set(s.search_value); reason.set('Demo: ' + s.label)">{{ s.label }}</button> }
                </div>
              }
            </section>
          }
          <section class="card">
            @for (r of requests(); track r.request_id) {
              <div class="list-item" [class.sel]="r.request_id === selectedId()" (click)="select(r.request_id)">
                <div class="row" style="justify-content:space-between;flex-wrap:nowrap">
                  <b class="small">#{{ r.request_id }} · <span class="mono">{{ r.search_value }}</span></b>
                  <span class="badge" [class]="'badge s-' + tone(r.status)">{{ pretty(r.status) }}</span>
                </div>
                <span class="muted small">{{ r.root_table ? r.root_table + ' ' + r.root_key + ' · ' : '' }}{{ r.created_at.slice(0, 16).replace('T', ' ') }} · {{ r.requested_by }}</span>
              </div>
            } @empty { <div class="empty">No requests yet.</div> }
          </section>
        </div>

        @if (detail(); as r) {
          <section class="card card-pad">
            <div class="row" style="justify-content:space-between;align-items:flex-start">
              <div><h2>Request #{{ r.request_id }}</h2><span class="muted small">{{ r.reason }}</span></div>
              <span class="badge" [class]="'badge s-' + tone(r.status)">{{ pretty(r.status) }}</span>
            </div>

            <ol class="stepper">
              @for (s of steps; track s; let i = $index) { <li [class.done]="i < stage()" [class.now]="i === stage()"><span>{{ i < stage() ? '✓' : i + 1 }}</span>{{ s }}</li> }
            </ol>

            @if (r.status === 'NO_MATCH') { <div class="note warn">No classified PII column contains that value. Check the spelling, or run a scan so the columns are classified first.</div> }

            @if (r.candidates?.length) {
              <h3 style="margin:14px 0 8px">People found ({{ r.candidates!.length }})</h3>
              <p class="muted small" style="margin:0 0 8px">Hits in different tables are correlated into one person through the lineage graph, including derived copies with no foreign key.</p>
              @for (c of r.candidates; track c.root_table + c.key) {
                <div class="cand" [class.on]="isSelected(r, c)">
                  <div class="row" style="justify-content:space-between">
                    <span><b class="mono">{{ c.root_table }} #{{ c.key }}</b>@if (c.customer_no) { <span class="mono muted"> · {{ c.customer_no }}</span> } @if (c.source_name) { <span class="badge s-gray">{{ c.source_name }}</span> } @if (c.country) { <span class="badge s-blue">{{ c.country }}</span> }</span>
                    @if (auth.canEdit() && canPick(r)) { <button class="btn btn-sm" [class.btn-primary]="!isSelected(r, c)" (click)="pick(r, c)" [disabled]="isSelected(r, c) || busy()">{{ isSelected(r, c) ? 'Selected' : 'Use this person' }}</button> }
                  </div>
                  <div class="row" style="margin:6px 0">
                    @for (f of c.found_in; track f.table + f.column) { <span class="chip soft small">found in <b class="mono">{{ f.table }}.{{ f.column }}</b></span> }
                  </div>
                  <div class="mono muted small">{{ preview(c) }}</div>
                </div>
              }
            }

            @if (r.plan; as p) {
              <h3 style="margin:16px 0 8px">Erasure plan</h3>
              @if (p.rule) { <div class="muted small" style="margin-bottom:6px">Authorised by rule “{{ p.rule.name }}” ({{ p.rule.policy }}, scope: {{ p.rule.scope }}){{ p.level ? ' · anonymisation level: ' + p.level.toLowerCase() : '' }}
                  @if (p.jurisdiction?.iso2) { · jurisdiction: <b>{{ p.jurisdiction!.name ?? p.jurisdiction!.iso2 }}</b> }</div> }
              @if (p.blocked) { <div class="note bad">Blocked: {{ p.blocked }}</div> }
              @if (p.steps.length) {
                <div class="tbl-wrap">
                  <table class="tbl">
                    <thead><tr><th>Table</th><th>Outcome</th><th>Rows</th><th>Why</th></tr></thead>
                    <tbody>
                      @for (s of p.steps; track s.table) {
                        <tr>
                          <td class="mono">{{ s.table }}</td>
                          <td><span class="badge" [class]="'badge s-' + tone(s.operation)">{{ s.operation === 'ANONYMIZE' ? 'Anonymise' : pretty(s.operation) }}</span></td>
                          <td>{{ s.rows }}</td>
                          <td class="small">{{ s.reason }}@if (s.held_rows) { <span class="muted"> ({{ s.held_rows }} row(s) under legal hold are skipped)</span> }
                            @if (s.treatments?.length) {
                              <div class="treat">
                                @for (t of s.treatments; track t.column) { <span class="chip soft mono" [class.kept]="t.treatment === 'KEEP'">{{ t.column }} → {{ t.note }}</span> }
                              </div>
                            }
                            @if (s.sql) { <details><summary class="muted">SQL</summary><pre class="code">{{ s.sql }}</pre></details> }</td>
                        </tr>
                      }
                    </tbody>
                  </table>
                </div>
              }
              @for (n of p.notes; track n) { <div class="note good">{{ n }}</div> }
            }

            @if (r.result; as res) {
              <h3 style="margin:16px 0 8px">Result</h3>
              <div class="note" [class.good]="res.verified" [class.bad]="!res.verified"><b>{{ res.verified ? '✓ Verified' : '✗ Not verified' }}</b> — {{ res.verification }}</div>
              @for (h of res.held ?? []; track h.table) { <div class="muted small">🔒 {{ h.rows }} row(s) of {{ h.table }} were left untouched under legal hold {{ h.holds.join(', #') ? '#' + h.holds.join(', #') : '' }}. The skip is in the audit log.</div> }
              @if (res.documents; as doc) {
                @if (doc.documents_removed) {
                  <div class="muted small">📄 {{ doc.documents_removed }} document(s), {{ doc.chunks_removed ?? 0 }} vector chunk(s) and {{ doc.files_removed ?? 0 }} file(s) removed (matched by customer number in the filename).
                    @if (doc.chroma_note) { <span> Note: {{ doc.chroma_note }}</span> }</div>
                } @else if (doc.skipped || doc.error) {
                  <div class="muted small">📄 Document/vector cleanup: {{ doc.error ? 'failed - ' + doc.error : doc.reason }}</div>
                }
              }
              @for (e of r.evidence ?? []; track e.evidence_id) { <div class="muted small">🗂 Evidence #{{ e.evidence_id }}: {{ e.summary }}</div> }
              <div class="muted small" style="margin-top:6px">The identifier you searched for was masked in this record once the erasure completed.</div>
            }

            <div class="row" style="margin-top:18px">
              @if (auth.isAdmin() && r.status === 'PLAN_READY') { <button class="btn btn-primary" (click)="act(r, 'approve')" [disabled]="busy()">✓ Approve plan</button> }
              @if (auth.isAdmin() && r.status === 'APPROVED') { <button class="btn btn-primary" (click)="execute(r)" [disabled]="busy()">▶ Execute erasure</button> }
              @if (auth.isAdmin() && !['EXECUTED', 'REJECTED', 'NO_MATCH'].includes(r.status)) { <button class="btn btn-danger" (click)="act(r, 'reject')" [disabled]="busy()">Reject</button> }
              @if (!auth.isAdmin() && r.status === 'PLAN_READY') { <span class="muted small">Waiting for an admin to approve.</span> }
            </div>
          </section>
        } @else {
          <section class="card empty">Create a request, or select one, to see how the person is found, how the plan is built and what happens.</section>
        }
      </div>

      <div class="section-title"><h2>Legal holds</h2><a class="btn btn-sm" routerLink="/legal-holds">Manage legal holds</a></div>
      <section class="card card-pad">
        <div>
          <b>{{ holds().length }}</b> active legal hold{{ holds().length === 1 ? '' : 's' }}.
          <span class="muted">Records on hold are skipped by an erasure request: the rest of the request carries on, and the person's identity record is kept until the hold is released. Stewards and admins set the flag under Legal holds.</span>
        </div>
      </section>
    </main>
  `,
  styles: `
    .small { font-size: 12.5px; }
    .hint-box { margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--border); display: flex; flex-direction: column; gap: 6px; align-items: flex-start; }
    .sample { background: #f0fdfa; border: 1px solid #99f6e4; color: var(--primary-dark); border-radius: 8px; padding: 6px 10px; font: inherit; font-size: 12.5px; text-align: left; cursor: pointer; }
    .sample:hover { background: var(--primary-soft); }
    .stepper { list-style: none; display: flex; gap: 6px; padding: 0; margin: 16px 0 6px; flex-wrap: wrap; }
    .stepper li { display: flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--muted); padding-right: 12px; }
    .stepper li span { width: 22px; height: 22px; border-radius: 50%; border: 2px solid #cbd5e1; display: grid; place-items: center; font-weight: 700; font-size: 11px; }
    .stepper li.done { color: var(--text); } .stepper li.done span { background: var(--primary); border-color: var(--primary); color: #fff; }
    .stepper li.now { color: var(--primary-dark); font-weight: 600; } .stepper li.now span { border-color: var(--primary); color: var(--primary-dark); }
    .cand { border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; margin-bottom: 8px; }
    .cand.on { border-color: var(--primary); background: #f0fdfa; }
    .treat { display: flex; flex-wrap: wrap; gap: 4px; margin: 6px 0 2px; }
    .chip.kept { opacity: 0.6; }
  `,
})
export class Erasure {
  private api = inject(Api);
  private toasts = inject(Toasts);
  private confirm = inject(Confirms);
  auth = inject(Auth);
  pretty = pretty; tone = tone; steps = STEPS;

  requests = signal<ErasureRequest[]>([]);
  detail = signal<ErasureRequest | null>(null);
  selectedId = signal<number | null>(null);
  holds = signal<LegalHold[]>([]);
  samples = signal<{ label: string; search_value: string }[]>([]);
  search = signal('');
  reason = signal('');
  busy = signal(false);

  stage = computed(() => {
    switch (this.detail()?.status) {
      case 'CANDIDATES_FOUND': return 1;
      case 'PLAN_READY': case 'BLOCKED': return 2;
      case 'APPROVED': return 3;
      case 'EXECUTED': return 5;
      default: return 0;
    }
  });

  constructor() {
    this.loadList();
    this.loadHolds();
    if (this.auth.canEdit()) this.api.erasureSamples().subscribe({ next: (s) => this.samples.set(s), error: () => {} });
  }

  loadList() { this.api.erasures().subscribe((r) => this.requests.set(r)); }
  loadHolds() { this.api.holds('ACTIVE').subscribe((h) => this.holds.set(h)); }

  select(id: number) {
    this.selectedId.set(id);
    this.api.erasure(id).subscribe({ next: (r) => this.detail.set(r), error: (e) => this.toasts.error(errorMessage(e)) });
  }

  private applied(r: ErasureRequest, msg?: string) {
    this.detail.set(r); this.selectedId.set(r.request_id); this.loadList(); if (msg) this.toasts.ok(msg);
  }

  create() {
    this.busy.set(true);
    this.api.createErasure(this.search().trim(), this.reason()).subscribe({
      next: (r) => { this.busy.set(false); this.applied(r, r.status === 'NO_MATCH' ? 'No matching person found' : `Request #${r.request_id} created`); },
      error: (e) => { this.busy.set(false); this.toasts.error(errorMessage(e)); },
    });
  }

  isSelected(r: ErasureRequest, c: Candidate) { return r.root_table === c.root_table && r.root_key === c.key; }
  canPick(r: ErasureRequest) { return ['CANDIDATES_FOUND', 'PLAN_READY', 'BLOCKED'].includes(r.status); }
  preview(c: Candidate) { return Object.entries(c.preview).map(([k, v]) => `${k.toLowerCase()}: ${v}`).join('  ·  '); }

  pick(r: ErasureRequest, c: Candidate) {
    this.busy.set(true);
    this.api.selectSubject(r.request_id, c.root_table, c.key).subscribe({
      next: (x) => { this.busy.set(false); this.applied(x, 'Plan built'); },
      error: (e) => { this.busy.set(false); this.toasts.error(errorMessage(e)); },
    });
  }

  act(r: ErasureRequest, action: 'approve' | 'reject') {
    this.busy.set(true);
    this.api.erasureAction(r.request_id, action).subscribe({
      next: (x) => { this.busy.set(false); this.applied(x, action === 'approve' ? 'Request approved' : 'Request rejected'); },
      error: (e) => { this.busy.set(false); this.toasts.error(errorMessage(e)); this.select(r.request_id); },
    });
  }

  async execute(r: ErasureRequest) {
    if (!await this.confirm.ask(`Execute the erasure plan for ${r.root_table} #${r.root_key}? This changes real rows in ${r.source_name} (a snapshot exists to restore from).`)) return;
    this.busy.set(true);
    this.api.erasureAction(r.request_id, 'execute').subscribe({
      next: (x) => { this.busy.set(false); this.applied(x, x.verified ? 'Erasure executed and verified' : 'Executed, but verification failed'); },
      error: (e) => { this.busy.set(false); this.toasts.error(errorMessage(e)); this.select(r.request_id); },
    });
  }
}
