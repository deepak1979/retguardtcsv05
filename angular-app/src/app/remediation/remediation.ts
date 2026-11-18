import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { Confirms } from '../core/confirm';
import { DomainScope } from '../core/domain';
import { pretty, tone, triggerLabel } from '../core/format';
import { EvaluableGroup, RowPreview, Source, Task, Violation } from '../core/models';
import { Toasts } from '../core/toast';

@Component({
  selector: 'app-remediation',
  imports: [FormsModule],
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1>Remediation</h1>
          <p>Evaluate policies against the findings, review each dry-run plan, then approve, execute and verify.</p>
        </div>
        <div class="row" style="gap:10px;flex:none">
          <div class="domain-toggle" role="group" aria-label="Domain">
            <button type="button" class="domain-opt" [class.on]="domain() === 'INSURANCE'" (click)="ds.set('INSURANCE')">Insurance</button>
            <button type="button" class="domain-opt" [class.on]="domain() === 'BANKING'" (click)="ds.set('BANKING')">Banking</button>
          </div>
          @if (auth.canEdit()) {
            <div class="row" style="flex-wrap:nowrap">
              <button class="btn btn-primary" (click)="evaluate()" [disabled]="busy()">{{ busy() === 'evaluate' ? 'Evaluating…' : '⟳ Evaluate policies' }}</button>
              <button class="btn" (click)="openEvalDialog()" [disabled]="busy()" title="Choose which policies and rules this run should evaluate">🎯 Evaluate selected…</button>
            </div>
          }
        </div>
      </div>

      <div class="kpis">
        @for (k of kpis(); track k.label) { <div class="card kpi"><span class="muted">{{ k.label }}</span><strong>{{ k.value }}</strong></div> }
      </div>

      <div class="section-title" style="margin-top:0"><h2>Violations</h2><span class="muted small">Where the data breaks a rule right now</span></div>
      <section class="card">
        @if (violations().length === 0) {
          <div class="empty">No violations recorded. Run <b>Evaluate policies</b> after a scan.</div>
        } @else {
          <div class="tbl-wrap">
            <table class="tbl">
              <thead><tr><th>Policy · rule</th><th>Type</th><th>Source</th><th>Table</th><th>Detail</th><th>Rows</th><th>Status</th></tr></thead>
              <tbody>
                @for (v of violations(); track v.violation_id) {
                  <tr class="clickable" (click)="v.task_id && select(v.task_id)">
                    <td>{{ v.rule_name }}<div class="muted mono small">{{ v.policy_code }}</div></td>
                    <td><span class="badge s-gray">{{ pretty(v.violation_type) }}</span></td>
                    <td><span class="badge s-blue">{{ v.source_name }}</span></td>
                    <td class="mono">{{ v.table_name }}</td>
                    <td class="small">{{ v.detail }}@if (v.columns.length && v.violation_type === 'UNPROTECTED_DATA') { <div class="mono muted">{{ v.columns.join(', ') }}</div> }</td>
                    <td>{{ v.rows_affected }}</td>
                    <td><span class="badge" [class]="'badge s-' + tone(v.status)">{{ pretty(v.status) }}</span></td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </section>

      <div class="section-title"><h2>Remediation tasks</h2><span class="muted small">Nothing runs without an approved task</span></div>
      <div class="layout-split">
        <section class="card">
          @for (t of tasks(); track t.task_id) {
            <div class="list-item" [class.sel]="t.task_id === selectedId()" (click)="select(t.task_id)">
              <div class="row" style="justify-content:space-between;flex-wrap:nowrap">
                <b class="small">#{{ t.task_id }} · {{ pretty(t.action) }}</b>
                <span class="badge" [class]="'badge s-' + tone(t.status)">{{ pretty(t.status) }}</span>
              </div>
              <div class="small">{{ t.title }}</div>
              <span class="badge s-blue small">{{ t.source_name }}</span>
              @if (t.status === 'EXECUTED') { <span class="small" [style.color]="t.verified ? 'var(--ok)' : 'var(--danger)'">{{ t.verified ? '✓ verified' : '✗ not verified' }}</span> }
            </div>
          } @empty { <div class="empty">No tasks yet.</div> }
        </section>

        @if (detail(); as t) {
          <section class="card card-pad">
            <div class="row" style="justify-content:space-between;align-items:flex-start">
              <div>
                <h2>{{ t.title }}</h2>
                <span class="muted small">Task #{{ t.task_id }} · {{ t.source_name }} · rule “{{ t.plan?.rule }}” · {{ t.plan?.policy }}@if (t.plan?.scope_level && t.plan?.scope_level !== 'GLOBAL') { · <span class="badge s-teal">{{ t.plan?.scope }}</span> } · proposed by {{ t.requested_by }}@if (t.approved_by) { · {{ t.status === 'REJECTED' ? 'rejected' : 'approved' }} by {{ t.approved_by }} }</span>
              </div>
              <span class="badge" [class]="'badge s-' + tone(t.status)">{{ pretty(t.status) }}</span>
            </div>

            @if (t.plan; as p) {
              <div class="section-title" style="margin:16px 0 6px"><h3>Dry-run plan</h3><span class="muted small">What would run, and how many rows it touches</span></div>
              @if (p.blocked) { <div class="note bad">Blocked: {{ p.blocked }}</div> }
              @for (n of p.notes; track n) { <div class="note">{{ n }}</div> }
              @if (p.columns.length) {
                <div class="row" style="margin:4px 0 8px">
                  @for (c of p.columns; track c.column) { <span class="chip soft mono" [class.kept]="c.treatment === 'KEEP'">{{ c.column }} <span class="muted">{{ pretty(c.element) }}@if (c.note) { → {{ c.note }} }</span></span> }
                </div>
              }
              @for (s of p.steps; track $index) {
                <div class="step">
                  <div class="row"><span class="badge" [class]="s.operation === 'ARCHIVE' ? 'badge s-teal' : 'badge s-blue'">{{ s.operation }}</span><b class="mono">{{ s.table }}</b><span class="muted">≈ {{ s.est_rows }} row(s)</span></div>
                  @if (s.operation === 'ARCHIVE') { <div class="muted small" style="margin-top:4px">Exported to a JSON file under <span class="mono">archive/{{ s.table }}/&lt;year&gt;/&lt;month&gt;/</span> before deletion, then indexed under Audit &gt; Archived records.</div> }
                  <details><summary class="muted small">Show SQL</summary><pre class="code">{{ s.operation === 'ARCHIVE' ? 'Rows are read first, then:\n' + s.sql : s.sql }}</pre></details>
                  @if (s.operation === 'DELETE' || s.operation === 'ARCHIVE') {
                    <button type="button" class="btn btn-sm" style="margin-top:6px" (click)="togglePreview($index)">
                      {{ previewFor() === $index ? 'Hide rows' : '👁 Preview rows that will be ' + (s.operation === 'ARCHIVE' ? 'archived' : 'deleted') }}
                    </button>
                    @if (previewFor() === $index) {
                      @if (previewLoading()) {
                        <div class="muted small" style="margin-top:6px">Loading…</div>
                      } @else if (previewData(); as pv) {
                        <div class="tbl-wrap" style="margin-top:8px">
                          <table class="tbl small">
                            <thead><tr>@for (c of pv.columns; track c) { <th>{{ c }}</th> }</tr></thead>
                            <tbody>
                              @for (r of pv.rows; track $index) {
                                <tr>@for (v of r; track $index) { <td class="mono">{{ v ?? '—' }}</td> }</tr>
                              } @empty { <tr><td [attr.colspan]="pv.columns.length" class="muted">No rows matched.</td></tr> }
                            </tbody>
                          </table>
                        </div>
                        <div class="muted small" style="margin-top:4px">
                          Showing {{ pv.shown }} of {{ pv.total }} row(s)@if (pv.masked_columns.length) { · {{ pv.masked_columns.length }} personal column(s) not shown here }
                        </div>
                      }
                    }
                  }
                </div>
              }
            }

            @if (t.note) { <div class="note warn">{{ t.note }}</div> }

            @if (t.result; as r) {
              <div class="section-title" style="margin:16px 0 6px"><h3>Result</h3></div>
              <div class="note" [class.good]="r.verified" [class.bad]="!r.verified"><b>{{ r.verified ? '✓ Verified' : '✗ Not verified' }}</b> — {{ r.verification }}</div>
              @for (s of r.steps; track $index) {
                <div class="row small" style="margin-bottom:4px"><span class="badge s-green">{{ s.operation }}</span><b class="mono">{{ s.table }}</b><span>{{ s.rows }} row(s)</span>
                  @if (s.archive_file) { <span class="mono muted">→ {{ s.archive_file }}</span> }
                  @if (s.note) { <span class="muted">({{ s.note }})</span> }
                </div>
              }
              @for (e of t.evidence ?? []; track e.evidence_id) {
                <div class="muted small" style="margin-top:8px">🗂 Evidence #{{ e.evidence_id }} recorded by {{ e.created_by }} at {{ e.created_at.slice(0, 19).replace('T', ' ') }}</div>
              }
            }

            <div class="row" style="margin-top:18px">
              @if (auth.canEdit() && (t.status === 'PROPOSED' || t.status === 'APPROVED')) { <button class="btn" (click)="act(t, 'plan')" [disabled]="busy()">↻ Refresh dry run</button> }
              @if (auth.canEdit() && (t.status === 'REJECTED' || t.status === 'FAILED')) { <button class="btn" (click)="act(t, 'repropose')" [disabled]="busy()">Re-propose</button> }
              @if (auth.isAdmin() && t.status === 'PROPOSED') { <button class="btn btn-primary" (click)="act(t, 'approve')" [disabled]="busy() || !!t.plan?.blocked">✓ Approve</button> }
              @if (auth.isAdmin() && (t.status === 'PROPOSED' || t.status === 'APPROVED')) { <button class="btn btn-danger" (click)="act(t, 'reject')" [disabled]="busy()">Reject</button> }
              @if (auth.isAdmin() && t.status === 'APPROVED') { <button class="btn btn-primary" (click)="execute(t)" [disabled]="busy()">{{ busy() === 'execute' ? 'Executing…' : '▶ Execute' }}</button> }
              @if (!auth.isAdmin() && t.status === 'PROPOSED') { <span class="muted small">Waiting for an admin to approve.</span> }
            </div>
          </section>
        } @else {
          <section class="card empty">Select a task to see its dry-run plan.</section>
        }
      </div>
    </main>

    @if (evalDialog()) {
      <div class="backdrop" (click)="evalDialog.set(false)">
        <div class="modal wide" role="dialog" aria-modal="true" (click)="$event.stopPropagation()">
          <div class="modal-head"><h2>Evaluate selected policies and rules</h2><button class="btn btn-sm" (click)="evalDialog.set(false)" aria-label="Close">✕</button></div>
          <div class="modal-body">
            <p class="muted small" style="margin-top:0">Only the checked rules run. Violations and tasks of any rule left unchecked are not touched.</p>
            <div class="field" style="margin-bottom:14px">
              <label for="evsrc">Data source</label>
              <select id="evsrc" [ngModel]="evalSourceId()" (ngModelChange)="evalSourceId.set($event === '' ? null : +$event)">
                <option [ngValue]="null">All data sources</option>
                @for (s of allSources(); track s.source_id) { <option [ngValue]="s.source_id">{{ s.name }}</option> }
              </select>
              @if (evalSourceId() !== null) {
                <span class="hint">A rule with no fixed source (MASK) still runs, but only for this source's own findings - other sources' violations under that rule are left untouched.</span>
              }
            </div>
            @if (evalLoading()) {
              <div class="empty">Loading policies…</div>
            } @else if (!evalGroups().length) {
              <div class="empty">No active policy has an active rule to evaluate.</div>
            } @else {
              <label class="check all-check"><input type="checkbox" [checked]="allSelected()" [indeterminate]="someSelected()" (change)="toggleAll($any($event.target).checked)" /> <b>Select all</b>
                <span class="muted small">{{ evalSelected().size }} of {{ totalRules() }} rule(s) selected</span></label>
              <div class="tree">
                @for (g of evalGroups(); track g.policy_id) {
                  <div class="grp-block">
                    <label class="check grp-check">
                      <input type="checkbox" [checked]="policyState(g) === 'all'" [indeterminate]="policyState(g) === 'some'" (change)="togglePolicy(g, $any($event.target).checked)" />
                      <b>{{ g.policy_name }}</b> <span class="mono muted small">{{ g.policy_code }}</span>
                      @if (g.scope_level !== 'GLOBAL') { <span class="badge s-teal">{{ g.scope }}</span> }
                    </label>
                    <div class="rule-list">
                      @for (r of g.rules; track r.rule_id) {
                        <label class="check rule-check">
                          <input type="checkbox" [checked]="evalSelected().has(r.rule_id)" (change)="toggleRule(r.rule_id, $any($event.target).checked)" />
                          {{ r.name }} <span class="muted small">{{ triggerLabel(r.trigger_event) }} → {{ pretty(r.action) }}</span>
                          @if (r.source_name) { <span class="badge s-blue small">{{ r.source_name }}</span> }
                          @if (r.target_table) { <span class="mono muted small">{{ r.target_table }}</span> }
                          @if (!r.source_name && !r.target_table) { <span class="muted small">(wherever found)</span> }
                        </label>
                      }
                    </div>
                  </div>
                }
              </div>
            }
          </div>
          <div class="modal-foot">
            <button class="btn" (click)="evalDialog.set(false)">Cancel</button>
            <button class="btn btn-primary" (click)="runSelected()" [disabled]="busy() || !evalSelected().size">
              {{ busy() === 'evaluate' ? 'Evaluating…' : 'Evaluate ' + evalSelected().size + ' selected rule(s)' }}
            </button>
          </div>
        </div>
      </div>
    }
  `,
  styles: `
    .domain-toggle { display: flex; flex: none; border: 1px solid var(--border); border-radius: 999px; padding: 3px; background: #fff; }
    .domain-opt { border: none; background: none; font: inherit; font-weight: 600; font-size: 13px; padding: 7px 16px; border-radius: 999px; cursor: pointer; color: var(--muted); }
    .domain-opt.on { background: var(--primary); color: #fff; }
    .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 20px; }
    .kpi { padding: 12px 18px; display: flex; flex-direction: column; } .kpi strong { font-size: 24px; }
    .small { font-size: 12.5px; }
    .step { padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 8px; }
    .step details { margin-top: 6px; }
    .chip.kept { opacity: 0.6; }
    .modal.wide { width: min(680px, 100%); }
    .check { display: flex; align-items: center; gap: 8px; font-weight: 500; }
    .all-check { padding-bottom: 10px; margin-bottom: 10px; border-bottom: 1px solid var(--border); }
    .tree { max-height: 50vh; overflow: auto; display: flex; flex-direction: column; gap: 4px; }
    .grp-block { border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }
    .grp-check { margin-bottom: 4px; }
    .rule-list { display: flex; flex-direction: column; gap: 4px; margin-left: 26px; }
    .rule-check { font-weight: 400; font-size: 13.5px; }
    @media (max-width: 800px) { .kpis { grid-template-columns: repeat(2, 1fr); } }
  `,
})
export class Remediation {
  private api = inject(Api);
  private toasts = inject(Toasts);
  private confirm = inject(Confirms);
  auth = inject(Auth);
  ds = inject(DomainScope);
  domain = this.ds.domain;
  pretty = pretty; tone = tone; triggerLabel = triggerLabel;

  // source_id -> domain ('Insurance'/'Banking'/null), so violations/tasks (which only carry source_id) can
  // be filtered the same way Data sources filters its own list (core/domain.ts).
  private sourceDomains = signal<Map<number, string | null>>(new Map());
  allSources = signal<Source[]>([]);

  allViolations = signal<Violation[]>([]);
  allTasks = signal<Task[]>([]);
  violations = computed(() => this.allViolations().filter((v) => this.ds.matches(this.sourceDomains().get(v.source_id))));
  tasks = computed(() => this.allTasks().filter((t) => this.ds.matches(this.sourceDomains().get(t.source_id))));
  detail = signal<Task | null>(null);
  selectedId = signal<number | null>(null);
  previewFor = signal<number | null>(null);
  previewLoading = signal(false);
  previewData = signal<RowPreview | null>(null);
  busy = signal<'' | 'evaluate' | 'execute' | 'act'>('');

  evalDialog = signal(false);
  evalLoading = signal(false);
  evalGroups = signal<EvaluableGroup[]>([]);
  evalSelected = signal<Set<number>>(new Set());
  evalSourceId = signal<number | null>(null);   // null = every data source (the previous, only behaviour)
  totalRules = computed(() => this.evalGroups().reduce((n, g) => n + g.rules.length, 0));
  allSelected = computed(() => this.totalRules() > 0 && this.evalSelected().size === this.totalRules());
  someSelected = computed(() => this.evalSelected().size > 0 && !this.allSelected());

  kpis = computed(() => {
    const t = this.tasks();
    return [
      { label: 'Open violations', value: this.violations().filter((v) => v.status === 'OPEN').length },
      { label: 'Awaiting approval', value: t.filter((x) => x.status === 'PROPOSED').length },
      { label: 'Approved', value: t.filter((x) => x.status === 'APPROVED').length },
      { label: 'Executed & verified', value: t.filter((x) => x.status === 'EXECUTED' && x.verified).length },
    ];
  });

  constructor() { this.load(true); }

  load(pick = false) {
    this.api.sources().subscribe((s) => {
      this.sourceDomains.set(new Map(s.map((x) => [x.source_id, x.domain])));
      this.allSources.set(s);
    });
    this.api.violations().subscribe((v) => this.allViolations.set(v));
    this.api.tasks().subscribe((t) => {
      this.allTasks.set(t);
      const visible = this.tasks();
      if (pick && !this.selectedId() && visible.length) this.select((visible.find((x) => x.status === 'PROPOSED') ?? visible[0]).task_id);
    });
  }

  select(id: number) {
    this.selectedId.set(id);
    this.previewFor.set(null);
    this.previewData.set(null);
    this.api.task(id).subscribe({ next: (t) => this.detail.set(t), error: (e) => this.toasts.error(errorMessage(e)) });
  }

  togglePreview(stepIndex: number) {
    if (this.previewFor() === stepIndex) { this.previewFor.set(null); return; }
    const id = this.selectedId();
    if (!id) return;
    this.previewFor.set(stepIndex);
    this.previewData.set(null);
    this.previewLoading.set(true);
    this.api.taskPreview(id).subscribe({
      next: (pv) => { this.previewLoading.set(false); this.previewData.set(pv); },
      error: (e) => { this.previewLoading.set(false); this.previewFor.set(null); this.toasts.error(errorMessage(e)); },
    });
  }

  evaluate() {
    this.busy.set('evaluate');
    this.api.evaluate().subscribe({
      next: (r) => {
        this.busy.set('');
        this.toasts.ok(`${r.open_violations} open violation(s), ${r.tasks_proposed} task(s) proposed, ${r.resolved} resolved`);
        this.load(true);
      },
      error: (e) => { this.busy.set(''); this.toasts.error(errorMessage(e)); },
    });
  }

  openEvalDialog() {
    this.evalDialog.set(true);
    this.evalLoading.set(true);
    this.evalSourceId.set(null);
    this.api.evaluateScope().subscribe({
      next: (groups) => {
        this.evalLoading.set(false);
        this.evalGroups.set(groups);
        this.evalSelected.set(new Set(groups.flatMap((g) => g.rules.map((r) => r.rule_id))));   // select all by default
      },
      error: (e) => { this.evalLoading.set(false); this.evalDialog.set(false); this.toasts.error(errorMessage(e)); },
    });
  }

  policyState(g: EvaluableGroup): 'all' | 'some' | 'none' {
    const sel = this.evalSelected();
    const n = g.rules.filter((r) => sel.has(r.rule_id)).length;
    return n === 0 ? 'none' : n === g.rules.length ? 'all' : 'some';
  }

  toggleAll(checked: boolean) {
    this.evalSelected.set(checked ? new Set(this.evalGroups().flatMap((g) => g.rules.map((r) => r.rule_id))) : new Set());
  }
  togglePolicy(g: EvaluableGroup, checked: boolean) {
    this.evalSelected.update((s) => {
      const n = new Set(s);
      for (const r of g.rules) checked ? n.add(r.rule_id) : n.delete(r.rule_id);
      return n;
    });
  }
  toggleRule(ruleId: number, checked: boolean) {
    this.evalSelected.update((s) => { const n = new Set(s); checked ? n.add(ruleId) : n.delete(ruleId); return n; });
  }

  runSelected() {
    const ids = [...this.evalSelected()];
    if (!ids.length) return;
    this.busy.set('evaluate');
    this.api.evaluate(ids, this.evalSourceId()).subscribe({
      next: (r) => {
        this.busy.set('');
        this.evalDialog.set(false);
        const scope = r.rules_evaluated === r.rules_total ? 'every active rule' : `${r.rules_evaluated} of ${r.rules_total} active rule(s)`;
        const src = this.evalSourceId() !== null ? `, ${this.allSources().find((s) => s.source_id === this.evalSourceId())?.name ?? 'selected source'} only` : '';
        this.toasts.ok(`Evaluated ${scope}${src}: ${r.open_violations} open violation(s), ${r.tasks_proposed} task(s) proposed, ${r.resolved} resolved`);
        this.load(true);
      },
      error: (e) => { this.busy.set(''); this.toasts.error(errorMessage(e)); },
    });
  }

  act(t: Task, action: 'plan' | 'approve' | 'reject' | 'repropose') {
    this.busy.set('act');
    this.api.taskAction(t.task_id, action).subscribe({
      next: (res) => { this.busy.set(''); this.detail.set(res); this.load(); this.toasts.ok(({ plan: 'Dry run refreshed', approve: 'Task approved', reject: 'Task rejected', repropose: 'Task re-proposed' })[action]); },
      error: (e) => { this.busy.set(''); this.toasts.error(errorMessage(e)); },
    });
  }

  async execute(t: Task) {
    const destructive = t.plan?.mode !== 'VIEW';
    if (!await this.confirm.ask(destructive ? `Execute "${t.title}"? This changes real rows in Databricks (a snapshot exists to restore from).` : `Execute "${t.title}"?`)) return;
    this.busy.set('execute');
    this.api.taskAction(t.task_id, 'execute').subscribe({
      next: (res) => { this.busy.set(''); this.detail.set(res); this.load(); this.toasts.ok(res.verified ? 'Executed and verified' : 'Executed, but verification failed'); },
      error: (e) => { this.busy.set(''); this.toasts.error(errorMessage(e)); this.select(t.task_id); this.load(); },
    });
  }
}
