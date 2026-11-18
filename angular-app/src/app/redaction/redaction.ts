import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { Confirms } from '../core/confirm';
import { pretty, tone } from '../core/format';
import { DocRedactionBatch, DocRedactionTask, DocSource } from '../core/models';
import { Toasts } from '../core/toast';

@Component({
  selector: 'app-redaction',
  imports: [FormsModule],
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1>Redaction</h1>
          <p>Evaluate a document source for AUTO/CONFIRMED PII, review what would be removed, then approve
             and execute. The source PDF is never changed - each execution writes a new file into a
             <span class="mono">PDFREDACTED</span> folder beside it.</p>
        </div>
        <div class="row" style="gap:10px;flex:none">
          @if (sources().length > 1) {
            <select [ngModel]="sourceId()" (ngModelChange)="pickSource($event)">
              @for (s of sources(); track s.doc_source_id) { <option [ngValue]="s.doc_source_id">{{ s.name }}</option> }
            </select>
          }
          @if (auth.canEdit()) {
            <button class="btn btn-primary" (click)="evaluate()" [disabled]="busy() || !sourceId()">
              {{ busy() === 'evaluate' ? 'Evaluating…' : '⟳ Evaluate for redaction' }}
            </button>
          }
          @if (auth.isAdmin()) {
            <button class="btn btn-primary" (click)="startBatch()" [disabled]="!sourceId() || batchRunning()"
                    title="Propose, approve and redact every eligible document in the background - keep working while it runs">
              {{ batchRunning() ? '⏳ Redacting…' : '▶▶ Redact all' }}
            </button>
          }
        </div>
      </div>

      @if (!sources().length) {
        <section class="card card-pad"><div class="empty">No document sources registered yet - add one on the Documents page first.</div></section>
      } @else {

      <div class="kpis">
        @for (k of kpis(); track k.label) { <div class="card kpi"><span class="muted">{{ k.label }}</span><strong>{{ k.value }}</strong></div> }
      </div>

      @if (batches().length) {
        <div class="section-title"><h2>Batch runs</h2><span class="muted small">"Redact all" runs in the background - you can keep working while it finishes</span></div>
        <section class="card">
          <div class="tbl-wrap">
            <table class="tbl">
              <thead><tr><th>#</th><th>Status</th><th>Progress</th><th>Redacted</th><th>By</th><th>Started</th></tr></thead>
              <tbody>
                @for (b of batches(); track b.redaction_batch_id) {
                  <tr>
                    <td>{{ b.redaction_batch_id }}</td>
                    <td><span class="badge" [class]="'badge s-' + tone(b.status)">{{ pretty(b.status) }}</span></td>
                    <td style="min-width:150px">
                      <div class="row" style="flex-wrap:nowrap"><div class="meter" style="flex:1"><i [style.width.%]="b.documents_total ? b.documents_done / b.documents_total * 100 : 0"></i></div>
                      <span class="muted small">{{ b.documents_done }}/{{ b.documents_total }}</span></div>
                    </td>
                    <td>{{ b.redactions_total }} <span class="muted small">{{ b.message ? '(' + b.message + ')' : '' }}</span></td>
                    <td>{{ b.requested_by }}</td>
                    <td class="muted mono">{{ ts(b.started_at ?? b.created_at) }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </section>
      }

      <div class="section-title"><h2>Redaction tasks</h2><span class="muted small">Nothing writes a file without an approved task</span></div>
      <div class="layout-split">
        <section class="card">
          @for (t of tasks(); track t.redaction_task_id) {
            <div class="list-item" [class.sel]="t.redaction_task_id === selectedId()" (click)="select(t)">
              <div class="row" style="justify-content:space-between;flex-wrap:nowrap">
                <b class="small">#{{ t.redaction_task_id }}</b>
                <span class="badge" [class]="'badge s-' + tone(t.status)">{{ pretty(t.status) }}</span>
              </div>
              <div class="small mono">{{ t.file_name }}</div>
              <span class="muted small">{{ t.element_summary }}</span>
            </div>
          } @empty { <div class="empty">No redaction tasks yet. Click Evaluate for redaction.</div> }
        </section>

        @if (detail(); as t) {
          <section class="card card-pad">
            <div class="row" style="justify-content:space-between;align-items:flex-start">
              <div>
                <h2 class="mono">{{ t.file_name }}</h2>
                <span class="muted small">Task #{{ t.redaction_task_id }} · proposed by {{ t.requested_by }}@if (t.approved_by) { · {{ t.status === 'REJECTED' ? 'rejected' : 'approved' }} by {{ t.approved_by }} }</span>
              </div>
              <span class="badge" [class]="'badge s-' + tone(t.status)">{{ pretty(t.status) }}</span>
            </div>

            <div class="section-title" style="margin:16px 0 6px"><h3>What will be redacted</h3></div>
            <div class="row" style="margin:4px 0 8px">
              @for (el of (t.element_summary ?? '').split(', '); track el) { <span class="chip soft mono">{{ pretty(el) }}</span> }
            </div>
            <p class="muted small">Every occurrence of these element types, found the same way the Documents findings page
              reports them, is located on the page and the underlying text is removed (not just painted over) - verified by
              re-extracting text from a redacted output. Only AUTO or steward-CONFIRMED findings are ever included; a
              NEEDS_REVIEW or LOW finding is left untouched until confirmed on the Findings page.</p>

            @if (t.note) { <div class="note warn">{{ t.note }}</div> }

            @if (t.status === 'EXECUTED') {
              <div class="section-title" style="margin:16px 0 6px"><h3>Result</h3></div>
              <div class="note good">
                <b>✓ {{ t.redaction_count }} occurrence(s) redacted</b><br />
                <span class="small mono">{{ t.output_path }}</span>
              </div>
            }

            <div class="row" style="margin-top:18px">
              @if (auth.isAdmin() && t.status === 'PROPOSED') { <button class="btn btn-primary" (click)="act(t, 'approve')" [disabled]="busy()">✓ Approve</button> }
              @if (auth.isAdmin() && (t.status === 'PROPOSED' || t.status === 'APPROVED')) { <button class="btn btn-danger" (click)="act(t, 'reject')" [disabled]="busy()">Reject</button> }
              @if (auth.isAdmin() && t.status === 'APPROVED') { <button class="btn btn-primary" (click)="execute(t)" [disabled]="busy()">{{ busy() === 'execute' ? 'Redacting…' : '▶ Execute redaction' }}</button> }
              @if (!auth.isAdmin() && t.status === 'PROPOSED') { <span class="muted small">Waiting for an admin to approve.</span> }
            </div>
          </section>
        } @else {
          <section class="card empty">Select a task to see what it will redact.</section>
        }
      </div>
      }
    </main>
  `,
  styles: `
    .kpis { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 20px; }
    .kpi { padding: 12px 18px; display: flex; flex-direction: column; } .kpi strong { font-size: 24px; }
    .small { font-size: 12.5px; }
    @media (max-width: 800px) { .kpis { grid-template-columns: repeat(2, 1fr); } }
  `,
})
export class Redaction {
  private api = inject(Api);
  private toasts = inject(Toasts);
  private confirm = inject(Confirms);
  auth = inject(Auth);
  pretty = pretty; tone = tone;

  sources = signal<DocSource[]>([]);
  sourceId = signal<number | null>(null);
  tasks = signal<DocRedactionTask[]>([]);
  detail = signal<DocRedactionTask | null>(null);
  selectedId = signal<number | null>(null);
  busy = signal<'' | 'evaluate' | 'execute' | 'act'>('');

  // "Redact all" - runs in the background (rg/redact.py start_batch()); poll and toast on completion,
  // same pattern as the Documents page's scan job.
  batches = signal<DocRedactionBatch[]>([]);
  batchRunning = computed(() => this.batches().some((b) => b.status === 'RUNNING' || b.status === 'QUEUED'));
  private wasBatchRunning = false;

  kpis = computed(() => {
    const t = this.tasks();
    return [
      { label: 'Awaiting approval', value: t.filter((x) => x.status === 'PROPOSED').length },
      { label: 'Approved', value: t.filter((x) => x.status === 'APPROVED').length },
      { label: 'Redacted', value: t.filter((x) => x.status === 'EXECUTED').length },
    ];
  });

  constructor() {
    this.loadSources();
    const timer = setInterval(() => {
      if (this.batchRunning() || this.wasBatchRunning) this.loadBatches();
    }, 1500);
    inject(DestroyRef).onDestroy(() => clearInterval(timer));
  }

  ts(v: string | null) { return v ? v.slice(0, 19).replace('T', ' ') : '—'; }

  loadSources() {
    this.api.docSources().subscribe((s) => {
      this.sources.set(s);
      if (s.length && !this.sourceId()) this.pickSource(s[0].doc_source_id);
    });
  }

  pickSource(id: number) {
    this.sourceId.set(id);
    this.detail.set(null);
    this.selectedId.set(null);
    this.loadTasks();
    this.loadBatches();
  }

  loadBatches() {
    const sid = this.sourceId();
    if (!sid) return;
    this.api.docRedactionBatches(sid).subscribe((b) => {
      const nowRunning = b.some((x) => x.status === 'RUNNING' || x.status === 'QUEUED');
      if (this.wasBatchRunning && !nowRunning) {
        this.loadTasks();
        const last = b[0];
        this.toasts.ok(last?.status === 'FAILED' ? `Redact all failed: ${last.message ?? 'see details'}` : `Redact all finished: ${last?.message ?? 'done'}`);
      }
      this.wasBatchRunning = nowRunning;
      this.batches.set(b);
    });
  }

  async startBatch() {
    const sid = this.sourceId();
    if (!sid) return;
    if (!await this.confirm.ask('Redact every eligible document in this source? This proposes, approves and executes each one in the ' +
                 'background - you can keep working while it runs. Each writes a new file into PDFREDACTED; the originals are never changed.')) return;
    this.api.docRedactionBatchStart(sid).subscribe({
      next: () => { this.wasBatchRunning = true; this.loadBatches(); this.toasts.ok('Redact all started - running in the background'); },
      error: (e) => this.toasts.error(errorMessage(e)),
    });
  }

  loadTasks() {
    const sid = this.sourceId();
    if (!sid) return;
    this.api.docRedactionTasks(sid).subscribe((t) => {
      this.tasks.set(t);
      if (!this.selectedId() && t.length) this.select((t.find((x) => x.status === 'PROPOSED') ?? t[0]));
    });
  }

  select(t: DocRedactionTask) {
    this.selectedId.set(t.redaction_task_id);
    this.detail.set(t);
  }

  evaluate() {
    const sid = this.sourceId();
    if (!sid) return;
    this.busy.set('evaluate');
    this.api.docRedactionEvaluate(sid).subscribe({
      next: (r) => { this.busy.set(''); this.toasts.ok(`${r.proposed} document(s) proposed for redaction`); this.loadTasks(); },
      error: (e) => { this.busy.set(''); this.toasts.error(errorMessage(e)); },
    });
  }

  act(t: DocRedactionTask, action: 'approve' | 'reject') {
    this.busy.set('act');
    this.api.docRedactionAction(t.redaction_task_id, action).subscribe({
      next: (res) => { this.busy.set(''); this.detail.set(res); this.loadTasks(); this.toasts.ok(action === 'approve' ? 'Task approved' : 'Task rejected'); },
      error: (e) => { this.busy.set(''); this.toasts.error(errorMessage(e)); },
    });
  }

  async execute(t: DocRedactionTask) {
    if (!await this.confirm.ask(`Redact "${t.file_name}"? This writes a new redacted copy into PDFREDACTED - the original file is never changed.`)) return;
    this.busy.set('execute');
    this.api.docRedactionAction(t.redaction_task_id, 'execute').subscribe({
      next: (res) => { this.busy.set(''); this.detail.set(res); this.loadTasks(); this.toasts.ok(`Redacted: ${res.redaction_count} occurrence(s)`); },
      error: (e) => { this.busy.set(''); this.toasts.error(errorMessage(e)); this.loadTasks(); },
    });
  }
}
