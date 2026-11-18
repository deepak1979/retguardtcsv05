import { Component, effect, inject, input, signal } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { Api, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { Confirms } from '../core/confirm';
import { pct, pretty, retention, tone, triggerLabel } from '../core/format';
import { Lookups, Policy, Rule } from '../core/models';
import { Toasts } from '../core/toast';
import { PolicyForm } from './policy-form';
import { RuleForm } from './rule-form';

@Component({
  selector: 'app-policy-detail',
  imports: [RouterLink, PolicyForm, RuleForm],
  template: `
    <main class="page">
      <a routerLink="/policies" class="back">← All policies</a>

      @if (error()) {
        <div class="alert alert-error">{{ error() }}</div>
      } @else if (policy(); as p) {
        <div class="page-head">
          <div>
            <div class="row">
              <h1>{{ p.name }}</h1>
              <span class="badge" [class]="'badge b-' + p.status.toLowerCase()">{{ pretty(p.status) }}</span>
            </div>
            <p class="mono">{{ p.policy_code }} · v{{ p.version }}</p>
          </div>
          @if (auth.canEdit()) {
            <div class="row">
              <button class="btn" (click)="editingPolicy.set(true)">Edit policy</button>
              <button class="btn btn-danger" (click)="deletePolicy(p)">Delete</button>
            </div>
          }
        </div>

        @if (p.status !== 'ACTIVE') {
          <div class="note warn">This policy is {{ pretty(p.status).toLowerCase() }}, so its rules are not evaluated. Set it to Active to put it to work.</div>
        }

        <section class="card card-pad kv">
          <div><span class="muted">Data category</span><span class="badge b-cat">{{ pretty(p.data_category) }}</span></div>
          <div><span class="muted">Regulation</span><span class="badge b-reg">{{ pretty(p.regulation) }}</span></div>
          <div><span class="muted">Scope</span><span class="badge" [class]="'badge s-' + (!p.scope_valid ? 'orange' : p.scope_level === 'GLOBAL' ? 'gray' : p.scope_level === 'REGION' ? 'blue' : 'teal')">{{ p.scope_valid ? p.scope_label : 'Not in use' }}</span></div>
          <div><span class="muted">Owner</span><b>{{ p.owner }}</b></div>
          <div><span class="muted">Effective from</span><b>{{ p.effective_from ? p.effective_from.slice(0, 10) : '—' }}</b></div>
          <div><span class="muted">Last updated</span><b>{{ p.updated_at.slice(0, 19).replace('T', ' ') }}</b></div>
        </section>
        @if (!p.scope_valid) { <div class="note warn">This policy is scoped to another company, or to a region or country that is inactive, so none of its rules are evaluated.</div> }
        @if (p.override_parent) { <div class="note">This policy <b>overrides</b> broader policies of the same kind for {{ p.scope_label }}: where it has a rule of the same kind, the broader rule no longer applies here.</div> }
        @if (p.scope_level !== 'GLOBAL' && p.covered_countries?.length) {
          <p class="desc muted small">Applies to rows belonging to:
            @for (c of p.covered_countries; track c) { <span class="chip soft mono" style="margin-right:4px">{{ c }}</span> }</p>
        }
        @if (p.description) { <p class="desc muted">{{ p.description }}</p> }

        <div class="section-title">
          <h2>Rules <span class="muted">({{ p.rules?.length ?? 0 }})</span></h2>
          @if (auth.canEdit()) { <button class="btn btn-primary btn-sm" (click)="openRule(null)">＋ Add rule</button> }
        </div>

        @if (!p.rules?.length) {
          <div class="card empty">No rules yet.</div>
        }
        @for (r of p.rules; track r.rule_id) {
          <article class="card rule" [class.off]="!r.is_active">
            <div class="order">{{ r.rule_order }}</div>
            <div class="body">
              <div class="row">
                <h3>{{ r.name }}</h3>
                @if (!r.is_active) { <span class="badge s-gray">Inactive</span> }
              </div>
              <div class="flow">
                <span class="kw">WHEN</span><span class="chip when">{{ triggerLabel(r.trigger_event) }}</span>
                <span class="kw">THEN</span><span class="chip" [class]="'chip act-' + r.action.toLowerCase()">{{ pretty(r.action) }}</span>
                @if (r.masking_method) { <span class="chip soft">{{ pretty(r.masking_method) }} masking</span> }
                @if (r.enforcement_mode) { <span class="chip soft">{{ r.enforcement_mode === 'VIEW' ? 'via masked view' : 'in place' }}</span> }
                @if (r.cascade_scope === 'SUBJECT_TREE') { <span class="chip soft warn">Includes linked tables</span> }
                @if (r.anonymization_level) { <span class="chip soft" [title]="levelText(r.anonymization_level)">Anonymise: {{ r.anonymization_level.toLowerCase() }}</span> }
              </div>
              <div class="flow scope">
                @if (r.target_table) {
                  <span class="kw">SCOPE</span>
                  <span class="chip soft mono">{{ r.target_table }}.{{ r.anchor_column }} + {{ retention(r.retention_days) }}</span>
                } @else if (r.min_confidence) {
                  <span class="kw">SCOPE</span>
                  <span class="chip soft">{{ pretty(p.data_category) }} findings ≥ {{ pct(r.min_confidence) }}</span>
                  @if (r.element_filter) { <span class="chip soft">{{ r.element_filter }}</span> }
                  @if (r.table_filter) { <span class="chip soft mono">tables: {{ r.table_filter }}</span> }
                }
              </div>
              @if (r.description) { <p class="muted rdesc">{{ r.description }}</p> }
            </div>
            @if (auth.canEdit()) {
              <div class="row actions">
                <button class="btn btn-sm" (click)="openRule(r)">Edit</button>
                <button class="btn btn-sm btn-danger" (click)="deleteRule(r)">Delete</button>
              </div>
            }
          </article>
        }

        <div class="section-title"><h2>Classification output this policy governs</h2></div>
        <section class="card">
          @if (p.matched_findings?.length) {
            <div class="tbl-wrap">
              <table class="tbl">
                <thead><tr><th>Column</th><th>Detected as</th><th>Confidence</th><th>Status</th><th>Protection</th><th>Via rule</th></tr></thead>
                <tbody>
                  @for (f of p.matched_findings; track f.finding_id) {
                    <tr>
                      <td class="mono"><b>{{ f.table_name }}</b>.{{ f.column_name }}</td>
                      <td>{{ pretty(f.data_element) }}</td>
                      <td>{{ pct(f.confidence) }}</td>
                      <td><span class="badge" [class]="'badge s-' + tone(f.status)">{{ pretty(f.status) }}</span></td>
                      <td><span class="badge" [class]="'badge s-' + (f.protection === 'NONE' ? 'orange' : 'teal')">{{ f.protection === 'NONE' ? 'Unprotected' : pretty(f.protection) }}</span></td>
                      <td class="muted">{{ f.rule }}</td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          } @else {
            <div class="empty">The scanner has no {{ pretty(p.data_category) }} findings for this policy's rules yet. Run a scan from <a routerLink="/sources">Data sources</a>.
              Rules that name a table (retention) act on that table directly.</div>
          }
        </section>
      } @else {
        <div class="empty">Loading…</div>
      }
    </main>

    @if (editingPolicy() && policy() && lookups(); as l) {
      <app-policy-form [lookups]="l" [policy]="policy()" (saved)="policySaved($event)" (cancelled)="editingPolicy.set(false)" />
    }
    @if (ruleDialog() && policy() && lookups(); as l) {
      <app-rule-form [lookups]="l" [policyId]="policy()!.policy_id" [category]="policy()!.data_category" [rule]="ruleDialog()!.rule" (saved)="ruleSaved($event)" (cancelled)="ruleDialog.set(null)" />
    }
  `,
  styles: `
    .back { display: inline-block; margin-bottom: 12px; font-weight: 500; }
    .desc { margin: 12px 2px 0; }
    .rule { display: flex; gap: 16px; padding: 16px 18px; margin-bottom: 10px; align-items: flex-start; }
    .rule.off { opacity: 0.6; }
    .order { flex: none; width: 28px; height: 28px; border-radius: 50%; background: var(--primary-soft); color: var(--primary-dark); font-weight: 700; display: grid; place-items: center; }
    .body { flex: 1; min-width: 0; }
    .flow { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
    .flow.scope { margin-top: 6px; }
    .kw { font-size: 11px; font-weight: 700; letter-spacing: 0.06em; color: var(--muted); min-width: 40px; }
    .chip.when { background: var(--info-soft); color: var(--info); }
    .chip.act-mask { background: #fef3c7; color: #92400e; }
    .chip.act-delete { background: var(--danger-soft); color: var(--danger); }
    .chip.act-retain { background: #f3e8ff; color: #6b21a8; }
    .chip.act-anonymize { background: #fae8ff; color: #86198f; }
    .chip.warn { background: var(--warn-soft); color: var(--warn); border-color: transparent; }
    .rdesc { margin: 8px 0 0; }
    .actions { flex: none; }
    @media (max-width: 720px) { .rule { flex-wrap: wrap; } }
  `,
})
export class PolicyDetail {
  private api = inject(Api);
  private router = inject(Router);
  private toasts = inject(Toasts);
  private confirm = inject(Confirms);
  auth = inject(Auth);
  pretty = pretty; retention = retention; pct = pct; tone = tone; triggerLabel = triggerLabel;

  /** bound from the :id route param via withComponentInputBinding() */
  id = input.required<string>();

  policy = signal<Policy | null>(null);
  lookups = signal<Lookups | null>(null);
  error = signal('');
  editingPolicy = signal(false);
  ruleDialog = signal<{ rule: Rule | null } | null>(null);

  constructor() {
    this.api.lookups().subscribe((l) => this.lookups.set(l));
    effect(() => {
      this.error.set('');
      this.api.policy(+this.id()).subscribe({
        next: (p) => this.policy.set(p),
        error: (e) => this.error.set(errorMessage(e)),
      });
    });
  }

  levelText(l: string) { return ({ BASIC: 'Direct identifiers only', GENERALISE: 'Quasi-identifiers coarsened or removed', FULL: 'Direct and quasi-identifiers removed' } as Record<string, string>)[l] ?? l; }

  openRule(rule: Rule | null) { this.ruleDialog.set({ rule }); }

  policySaved(p: Policy) { this.policy.set(p); this.editingPolicy.set(false); this.toasts.ok('Policy saved'); }
  ruleSaved(p: Policy) { this.policy.set(p); this.ruleDialog.set(null); this.toasts.ok('Rule saved'); }

  async deleteRule(r: Rule) {
    if (!await this.confirm.ask(`Delete rule "${r.name}"?`)) return;
    this.api.deleteRule(r.rule_id).subscribe({
      next: (p) => { this.policy.set(p); this.toasts.ok('Rule deleted'); },
      error: (e) => this.toasts.error(errorMessage(e)),
    });
  }

  async deletePolicy(p: Policy) {
    if (!await this.confirm.ask(`Delete policy "${p.name}" and its ${p.rules?.length ?? 0} rules? This cannot be undone.`)) return;
    this.api.deletePolicy(p.policy_id).subscribe({
      next: () => { this.toasts.ok('Policy deleted'); this.router.navigate(['/policies']); },
      error: (e) => this.toasts.error(errorMessage(e)),
    });
  }
}
