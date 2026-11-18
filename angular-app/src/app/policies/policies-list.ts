import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { Api, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { pretty } from '../core/format';
import { Lookups, Policy } from '../core/models';
import { Toasts } from '../core/toast';
import { PolicyForm } from './policy-form';

@Component({
  selector: 'app-policies-list',
  imports: [FormsModule, PolicyForm],
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1>Data retention policies</h1>
          <p>A policy governs one category of data. Its rules say what happens, when, and to which classified data.</p>
        </div>
        @if (auth.canEdit()) {
          <button class="btn btn-primary" (click)="creating.set(true)">＋ New policy</button>
        }
      </div>

      <div class="kpis">
        @for (k of kpis(); track k.label) {
          <div class="card kpi">
            <span class="muted">{{ k.label }}</span>
            <strong>{{ k.value }}</strong>
          </div>
        }
      </div>

      <div class="card">
        <div class="filters">
          <input type="text" placeholder="Search name, code or description…" aria-label="Search policies"
                 [ngModel]="q()" (ngModelChange)="q.set($event)" />
          <select aria-label="Filter by status" [ngModel]="status()" (ngModelChange)="status.set($event)">
            <option value="">All statuses</option>
            @for (s of lookups()?.policy_statuses ?? []; track s) { <option [value]="s">{{ pretty(s) }}</option> }
          </select>
          <select aria-label="Filter by scope" [ngModel]="scopeFilter()" (ngModelChange)="scopeFilter.set($event)">
            <option value="">All scopes</option>
            <option value="GLOBAL">Global</option>
            @for (r of lookups()?.regions ?? []; track r.region_id) {
              <optgroup [label]="r.name">
                <option [value]="'R' + r.region_id">{{ r.name }} (whole region)</option>
                @for (c of countriesOf(r.region_id); track c.country_id) { <option [value]="'C' + c.country_id">{{ c.name }}</option> }
              </optgroup>
            }
          </select>
          <select aria-label="Filter by data category" [ngModel]="category()" (ngModelChange)="category.set($event)">
            <option value="">All data categories</option>
            @for (c of lookups()?.data_categories ?? []; track c) {
              <option [value]="c">{{ pretty(c) }}</option>
            }
          </select>
        </div>

        @if (error()) {
          <div class="alert alert-error" style="margin: 14px">{{ error() }}</div>
        } @else if (loading()) {
          <div class="empty">Loading…</div>
        } @else if (filtered().length === 0) {
          <div class="empty">No policies match your filters.</div>
        } @else {
          <div class="tbl-wrap">
            <table class="tbl">
              <thead>
                <tr><th>Policy</th><th>Scope</th><th>Data category</th><th>Regulation</th><th>Status</th><th>Rules</th><th>Owner</th><th>Updated</th></tr>
              </thead>
              <tbody>
                @for (p of filtered(); track p.policy_id) {
                  <tr class="clickable" tabindex="0" (click)="open(p)" (keydown.enter)="open(p)">
                    <td>
                      <div class="pname">{{ p.name }}</div>
                      <div class="muted mono">{{ p.policy_code }}</div>
                    </td>
                    <td>
                      <span class="badge" [class]="'badge s-' + (!p.scope_valid ? 'orange' : p.scope_level === 'GLOBAL' ? 'gray' : p.scope_level === 'REGION' ? 'blue' : 'teal')"
                            [title]="p.scope_valid ? '' : 'Scoped to another company or an inactive region or country, so it is not evaluated'">{{ p.scope_valid ? p.scope_label : 'Not in use' }}</span>
                      @if (p.override_parent) { <div class="muted small">overrides parent</div> }
                    </td>
                    <td><span class="badge b-cat">{{ pretty(p.data_category) }}</span></td>
                    <td><span class="badge b-reg">{{ pretty(p.regulation) }}</span></td>
                    <td><span class="badge" [class]="'badge b-' + p.status.toLowerCase()">{{ pretty(p.status) }}</span></td>
                    <td>{{ p.rule_count }}</td>
                    <td>{{ p.owner }}</td>
                    <td class="muted">{{ p.updated_at.slice(0, 10) }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </div>
    </main>

    @if (creating() && lookups(); as l) {
      <app-policy-form [lookups]="l" (saved)="created($event)" (cancelled)="creating.set(false)" />
    }
  `,
  styles: `
    .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 16px; }
    .kpi { padding: 14px 18px; display: flex; flex-direction: column; }
    .kpi strong { font-size: 26px; }
    .filters { display: grid; grid-template-columns: 1fr 170px 230px 200px; gap: 10px; padding: 14px; border-bottom: 1px solid var(--border); }
    .pname { font-weight: 600; }
    @media (max-width: 720px) { .kpis { grid-template-columns: repeat(2, 1fr); } .filters { grid-template-columns: 1fr; } }
  `,
})
export class PoliciesList {
  private api = inject(Api);
  private router = inject(Router);
  private toasts = inject(Toasts);
  auth = inject(Auth);
  pretty = pretty;

  policies = signal<Policy[]>([]);
  lookups = signal<Lookups | null>(null);
  loading = signal(true);
  error = signal('');
  creating = signal(false);

  q = signal('');
  status = signal('');
  category = signal('');
  scopeFilter = signal('');

  filtered = computed(() => {
    const q = this.q().toLowerCase();
    return this.policies().filter(
      (p) =>
        (!this.status() || p.status === this.status()) &&
        (!this.category() || p.data_category === this.category()) &&
        this.inScope(p) &&
        (!q || [p.name, p.policy_code, p.description].some((s) => (s ?? '').toLowerCase().includes(q))),
    );
  });

  kpis = computed(() => {
    const p = this.policies();
    return [
      { label: 'Policies', value: p.length },
      { label: 'Active', value: p.filter((x) => x.status === 'ACTIVE').length },
      { label: 'Draft', value: p.filter((x) => x.status === 'DRAFT').length },
      { label: 'Rules defined', value: p.reduce((n, x) => n + x.rule_count, 0) },
    ];
  });

  constructor() {
    this.api.lookups().subscribe((l) => this.lookups.set(l));
    this.api.policies().subscribe({
      next: (p) => { this.policies.set(p); this.loading.set(false); },
      error: (e) => { this.error.set(errorMessage(e)); this.loading.set(false); },
    });
  }

  countriesOf(regionId: number) { return (this.lookups()?.countries ?? []).filter((c) => c.region_id === regionId); }

  private inScope(p: Policy) {
    const f = this.scopeFilter();
    if (!f) return true;
    if (f === 'GLOBAL') return p.scope_level === 'GLOBAL';
    return f.startsWith('R') ? p.scope_level === 'REGION' && p.region_id === +f.slice(1) : p.scope_level === 'COUNTRY' && p.country_id === +f.slice(1);
  }

  open(p: Policy) { this.router.navigate(['/policies', p.policy_id]); }

  created(p: Policy) {
    this.toasts.ok(`Policy "${p.name}" created`);
    this.router.navigate(['/policies', p.policy_id]);
  }
}
