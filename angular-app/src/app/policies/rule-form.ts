import { Component, computed, inject, input, output, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Api, errorMessage } from '../core/api';
import { pretty, triggerLabel } from '../core/format';
import { Catalog, Lookups, Policy, Rule, Source } from '../core/models';

const ACTIONS_BY_TRIGGER: Record<string, string[]> = {
  ALWAYS: ['MASK', 'RETAIN'],
  GDPR_ERASURE_REQUEST: ['DELETE', 'ANONYMIZE'],
  RETENTION_EXPIRY: ['DELETE', 'ARCHIVE', 'ANONYMIZE'],
};

const HELP: Record<string, string> = {
  MASK: 'Applies to classifier output: every column found as this policy\'s category is masked.',
  RETAIN: 'Protects the rows of one table until the anchor date plus the retention period. Outranks erasure and expiry.',
  'GDPR_ERASURE_REQUEST:DELETE': 'When a person asks to be erased: delete their data, and everything that depends on it.',
  'GDPR_ERASURE_REQUEST:ANONYMIZE': 'When a person asks to be erased: keep the row, irreversibly replace the identifying values.',
  'RETENTION_EXPIRY:DELETE': 'Delete rows once the anchor date plus the retention period has passed (leaf tables only).',
  'RETENTION_EXPIRY:ARCHIVE': 'Export matching rows to a JSON file, then delete them from the table (leaf tables only). '
    + 'The file path is recorded on the task\'s evidence and listed under Audit > Archived records.',
  'RETENTION_EXPIRY:ANONYMIZE': 'Irreversibly anonymise classified PII in rows once the retention period has passed.',
};

/** Create / edit dialog for a rule. The sections shown depend on the trigger and action. */
@Component({
  selector: 'app-rule-form',
  imports: [ReactiveFormsModule],
  template: `
    <div class="backdrop" (click)="cancelled.emit()">
      <form class="modal" style="width:min(640px,100%)" role="dialog" aria-modal="true" [formGroup]="form" (ngSubmit)="save()" (click)="$event.stopPropagation()">
        <div class="modal-head">
          <h2>{{ rule() ? 'Edit rule' : 'New rule' }} <span class="muted" style="font-weight:400">· {{ pretty(category()) }} policy</span></h2>
          <button type="button" class="btn btn-sm" (click)="cancelled.emit()" aria-label="Close">✕</button>
        </div>
        <div class="modal-body">
          @if (error()) { <div class="alert alert-error">{{ error() }}</div> }

          <div class="field">
            <label for="rn">Rule name</label>
            <input id="rn" type="text" formControlName="name" [class.invalid]="nameBad()" />
            @if (nameBad()) { <span class="err">Enter a name of at least 3 characters.</span> }
          </div>

          <div class="grid-2">
            <div class="field">
              <label for="rt">When (trigger)</label>
              <select id="rt" formControlName="trigger_event" (change)="triggerChanged()">
                @for (t of lookups().trigger_events; track t) { <option [value]="t">{{ triggerLabel(t) }}</option> }
              </select>
            </div>
            <div class="field">
              <label for="ra">Then (action)</label>
              <select id="ra" formControlName="action">
                @for (a of actions(); track a) { <option [value]="a">{{ pretty(a) }}</option> }
              </select>
            </div>
          </div>
          <div class="note">{{ help() }}</div>

          @if (usesClassification()) {
            <fieldset class="scope">
              <legend>Applies to classifier output</legend>
              <div class="field">
                <label for="rc">Minimum confidence: <b>{{ confidencePct() }}%</b></label>
                <input id="rc" type="range" min="0.5" max="1" step="0.05" formControlName="min_confidence" />
                <span class="hint">Only findings at least this sure (and Auto or Confirmed) are governed.</span>
              </div>
              <div class="field">
                <span class="label">Data elements <span class="muted">(none ticked = all {{ pretty(category()) }} elements)</span></span>
                <div class="chips">
                  @for (e of elements(); track e.code) {
                    <label class="chip-check" [class.on]="picked().has(e.code)"><input type="checkbox" [checked]="picked().has(e.code)" (change)="toggleElement(e.code)" />{{ e.name }}</label>
                  } @empty { <span class="muted">No classifier produces {{ pretty(category()) }} findings.</span> }
                </div>
              </div>
              <div class="field">
                <label for="rtf">Only these tables <span class="muted">(optional, comma separated, % wildcard)</span></label>
                <input id="rtf" type="text" class="mono" placeholder="CUSTOMER, AGENT, MKT_%" formControlName="table_filter" />
              </div>
            </fieldset>
          }

          @if (action() === 'MASK') {
            <div class="grid-2">
              <div class="field">
                <label for="rm">Masking method</label>
                <select id="rm" formControlName="masking_method">
                  @for (m of lookups().masking_methods; track m) { <option [value]="m">{{ pretty(m) }}</option> }
                </select>
                <span class="hint">{{ maskHelp() }}</span>
              </div>
              <div class="field">
                <label for="re">Enforcement</label>
                <select id="re" formControlName="enforcement_mode">
                  <option value="VIEW">Masked view (non-destructive)</option>
                  <option value="IN_PLACE">In place (overwrites data)</option>
                </select>
                <span class="hint">A view leaves the source rows untouched.</span>
              </div>
            </div>
          }

          @if (trigger() === 'GDPR_ERASURE_REQUEST') {
            <div class="field">
              <label for="rcs">Dependent data</label>
              <select id="rcs" formControlName="cascade_scope">
                <option value="SUBJECT_TREE">Include everything linked to the person (dependents first)</option>
                <option value="NONE">Only the person's own rows and derived copies</option>
              </select>
            </div>
          }

          @if (anonymises()) {
            <div class="field">
              <label for="ral">Anonymisation level</label>
              <select id="ral" formControlName="anonymization_level">
                @for (l of lookups().anonymization_levels; track l.code) { <option [value]="l.code">{{ levelLabel(l.code) }}</option> }
              </select>
              <span class="hint">{{ levelHelp() }}</span>
            </div>
          }

          @if (usesRetention()) {
            <fieldset class="scope">
              <legend>Retention scope</legend>
              <div class="field">
                <label for="rsrc">Data source</label>
                <select id="rsrc" formControlName="source_id" (change)="sourceChanged()">
                  @for (s of sources(); track s.source_id) { <option [value]="s.source_id">{{ s.name }}</option> }
                </select>
                <span class="hint">Which source's catalog the table and column below are picked from.</span>
              </div>
              <div class="grid-2">
                <div class="field">
                  <label for="rtt">Table</label>
                  <select id="rtt" formControlName="target_table" (change)="form.controls.anchor_column.setValue('')">
                    <option value="">Choose a table…</option>
                    @for (t of tables(); track t) { <option [value]="t">{{ t }}</option> }
                  </select>
                  @if (!tables().length) { <span class="hint">No catalog for this source yet - run Discover from Data sources first.</span> }
                </div>
                <div class="field">
                  <label for="rac">Anchor date column</label>
                  <select id="rac" formControlName="anchor_column">
                    <option value="">Choose a date column…</option>
                    @for (c of dateColumns(); track c) { <option [value]="c">{{ c }}</option> }
                  </select>
                  <span class="hint">Retention counts from this date. An empty date means still open.</span>
                </div>
              </div>
              <div class="field">
                <label for="rd">Retention period (days)</label>
                <input id="rd" type="number" min="1" formControlName="retention_days" />
                <div class="row" style="margin-top:6px">
                  @for (p of presets; track p.days) { <button type="button" class="btn btn-sm" (click)="form.controls.retention_days.setValue(p.days)">{{ p.label }}</button> }
                </div>
              </div>
            </fieldset>
          }

          <div class="field">
            <label for="rdesc">Description</label>
            <textarea id="rdesc" formControlName="description"></textarea>
          </div>
          <label class="check"><input type="checkbox" formControlName="is_active" /> Rule is active</label>
        </div>
        <div class="modal-foot">
          <button type="button" class="btn" (click)="cancelled.emit()">Cancel</button>
          <button type="submit" class="btn btn-primary" [disabled]="saving()">{{ saving() ? 'Saving…' : 'Save rule' }}</button>
        </div>
      </form>
    </div>
  `,
  styles: `
    .scope { border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px 2px; margin: 0 0 14px; }
    .scope legend { padding: 0 6px; font-weight: 600; font-size: 13px; color: var(--primary-dark); }
    input[type='range'] { padding: 0; accent-color: var(--primary); }
    .chips { display: flex; flex-wrap: wrap; gap: 6px; }
    .chip-check { display: inline-flex; align-items: center; gap: 6px; padding: 3px 10px; border: 1px solid var(--border); border-radius: 999px; font-size: 12.5px; cursor: pointer; }
    .chip-check.on { background: var(--primary-soft); border-color: var(--primary); color: var(--primary-dark); }
    .chip-check input { display: none; }
  `,
})
export class RuleForm {
  private api = inject(Api);
  private fb = inject(FormBuilder).nonNullable;
  pretty = pretty; triggerLabel = triggerLabel;

  lookups = input.required<Lookups>();
  policyId = input.required<number>();
  category = input.required<string>();
  rule = input<Rule | null>(null);
  saved = output<Policy>();
  cancelled = output<void>();

  presets = [{ label: '1 year', days: 365 }, { label: '3 years', days: 1095 }, { label: '5 years', days: 1825 }, { label: '7 years', days: 2555 }, { label: '10 years', days: 3650 }];

  form = this.fb.group({
    name: ['', [Validators.required, Validators.minLength(3)]],
    description: [''],
    trigger_event: ['ALWAYS'],
    action: ['MASK'],
    masking_method: ['PARTIAL'],
    enforcement_mode: ['VIEW'],
    min_confidence: [0.8],
    table_filter: [''],
    cascade_scope: ['SUBJECT_TREE'],
    anonymization_level: ['FULL'],
    source_id: [1],
    target_table: [''],
    anchor_column: [''],
    retention_days: [null as number | null],
    is_active: [true],
  });
  private trig = toSignal(this.form.controls.trigger_event.valueChanges, { initialValue: 'ALWAYS' });
  private act = toSignal(this.form.controls.action.valueChanges, { initialValue: 'MASK' });
  private target = toSignal(this.form.controls.target_table.valueChanges, { initialValue: '' });
  private conf = toSignal(this.form.controls.min_confidence.valueChanges, { initialValue: 0.8 });
  private method = toSignal(this.form.controls.masking_method.valueChanges, { initialValue: 'PARTIAL' });
  private level = toSignal(this.form.controls.anonymization_level.valueChanges, { initialValue: 'FULL' });

  trigger = this.trig;
  action = this.act;
  picked = signal<Set<string>>(new Set());
  catalog = signal<Catalog | null>(null);
  sources = signal<Source[]>([]);
  saving = signal(false);
  error = signal('');

  actions = computed(() => ACTIONS_BY_TRIGGER[this.trig()] ?? []);
  help = computed(() => HELP[this.act() === 'MASK' || this.act() === 'RETAIN' ? this.act() : `${this.trig()}:${this.act()}`] ?? '');
  usesClassification = computed(() => this.act() === 'MASK' || this.trig() === 'GDPR_ERASURE_REQUEST');
  usesRetention = computed(() => this.act() === 'RETAIN' || this.trig() === 'RETENTION_EXPIRY');
  /** erasure requests and retention rules that ANONYMIZE decide how much is removed */
  anonymises = computed(() => this.trig() === 'GDPR_ERASURE_REQUEST' || (this.trig() === 'RETENTION_EXPIRY' && this.act() === 'ANONYMIZE'));
  levelHelp = computed(() => this.lookups().anonymization_levels.find((l) => l.code === this.level())?.help ?? '');
  levelLabel(code: string) { return ({ BASIC: 'Basic: direct identifiers only', GENERALISE: 'Generalise: coarsen quasi-identifiers', FULL: 'Full: remove all identifying data' } as Record<string, string>)[code] ?? code; }
  confidencePct = computed(() => Math.round((this.conf() ?? 0.8) * 100));
  elements = computed(() => this.lookups().data_elements.filter((e) => e.category === this.category()));
  tables = computed(() => this.catalog()?.tables.map((t) => t.table_name) ?? []);
  dateColumns = computed(() => this.catalog()?.tables.find((t) => t.table_name === this.target())?.columns
    .filter((c) => c.data_type === 'DATE' || c.data_type === 'TIMESTAMP').map((c) => c.column_name) ?? []);
  maskHelp = computed(() => ({ FULL: 'All characters replaced by *', PARTIAL: 'Keeps a recognisable part: an***@mail.example, ***0464', HASH: 'SHA-256 hash, consistent across tables', TOKENIZE: 'TOK- plus a short hash' } as Record<string, string>)[this.method()] ?? '');

  ngOnInit() {
    this.api.sources().subscribe((s) => this.sources.set(s));
    const r = this.rule();
    if (r) {
      this.form.patchValue({
        ...r, description: r.description ?? '', masking_method: r.masking_method ?? 'PARTIAL', enforcement_mode: r.enforcement_mode ?? 'VIEW',
        min_confidence: r.min_confidence ?? 0.8, table_filter: r.table_filter ?? '', cascade_scope: r.cascade_scope ?? 'SUBJECT_TREE',
        source_id: r.source_id ?? 1, target_table: r.target_table ?? '', anchor_column: r.anchor_column ?? '', anonymization_level: r.anonymization_level ?? 'FULL',
      });
      this.picked.set(new Set((r.element_filter ?? '').split(',').filter(Boolean)));
    }
    this.loadCatalog(this.form.controls.source_id.value);
  }

  private loadCatalog(sourceId: number) {
    this.api.catalog(sourceId).subscribe((c) => this.catalog.set(c));
  }

  sourceChanged() {
    this.form.patchValue({ target_table: '', anchor_column: '' });
    this.loadCatalog(+this.form.controls.source_id.value);
  }

  triggerChanged() {
    const first = ACTIONS_BY_TRIGGER[this.form.controls.trigger_event.value][0];
    if (!this.actions().includes(this.form.controls.action.value)) this.form.controls.action.setValue(first);
  }

  toggleElement(code: string) {
    const s = new Set(this.picked());
    s.has(code) ? s.delete(code) : s.add(code);
    this.picked.set(s);
  }

  nameBad() { const c = this.form.controls.name; return c.invalid && (c.dirty || c.touched); }

  save() {
    if (this.form.invalid) { this.form.markAllAsTouched(); return; }
    this.saving.set(true);
    this.error.set('');
    const v = this.form.getRawValue();
    const body = {
      ...v,
      min_confidence: this.usesClassification() ? +(v.min_confidence ?? 0.8) : null,
      element_filter: this.usesClassification() ? [...this.picked()].join(',') || null : null,
      table_filter: this.usesClassification() ? v.table_filter || null : null,
      source_id: this.usesRetention() ? +v.source_id : null,
      target_table: this.usesRetention() ? v.target_table || null : null,
      anchor_column: this.usesRetention() ? v.anchor_column || null : null,
      retention_days: this.usesRetention() ? v.retention_days : null,
      anonymization_level: this.anonymises() ? v.anonymization_level : null,
    };
    const r = this.rule();
    (r ? this.api.updateRule(r.rule_id, body as any) : this.api.createRule(this.policyId(), body as any)).subscribe({
      next: (res) => this.saved.emit(res),
      error: (e) => { this.error.set(errorMessage(e)); this.saving.set(false); },
    });
  }
}
