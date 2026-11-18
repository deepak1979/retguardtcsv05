import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { pretty, tone } from '../core/format';
import { HoldCustomerHit, HoldRecord, HoldTree, LegalHold } from '../core/models';
import { Toasts } from '../core/toast';

interface Row { rec: HoldRecord; indent: 0 | 1 | 2 }
/** What the flag dialog is about. hold_id is set when a specific hold from the register is being released. */
interface Ask { source_id: number; table: string; key: string; label: string; flag: 'Y' | 'N'; hold_id?: number }

const IMPACT: Record<string, string> = {
  CUSTOMER: 'Covers this customer and everything that belongs to them: policies, claims, payments, operations and derived copies.',
  POLICY: "Covers this policy and its claims, payments and operations. The customer's identity record is kept too, because the policy hangs off it.",
  CLAIM: "Covers this claim and its payments. The policy and the customer's identity record are kept too. Other claims of the customer are not held.",
};

@Component({
  selector: 'app-legal-holds',
  imports: [FormsModule],
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1>Legal holds</h1>
          <p>Flag a customer, a policy or a claim as on hold (Y) or release it (N). Every remediation task and erasure request checks this register first.</p>
        </div>
      </div>

      <div class="note">
        <b>What a hold does.</b> Held records are not deleted, anonymised or overwritten in place, and neither is the identity record they hang off.
        Everything else in the same task or request carries on, and each skip is written to the audit log. Masked views are not affected: they hide data, they do not change it.
      </div>

      <div class="layout-split" style="margin-top:14px">
        <section class="card">
          <div class="card-pad" style="padding-bottom:12px">
            <h2>Find a customer</h2>
            <div class="row" style="margin-top:12px; flex-wrap:nowrap">
              <input type="text" style="flex:1" placeholder="Customer, policy or claim number, or name" aria-label="Search customers"
                     [ngModel]="q()" (ngModelChange)="q.set($event)" (keydown.enter)="search()" />
              <button class="btn btn-primary" (click)="search()" [disabled]="q().trim().length < 2 || searching()">Search</button>
            </div>
            <div class="muted small" style="margin-top:6px">Names are shown masked.</div>
          </div>
          @if (hits().length) {
            <div class="hits">
              @for (h of hits(); track h.source_id + '-' + h.customer_id) {
                <button type="button" class="hit" [class.on]="tree()?.customer?.key === '' + h.customer_id && treeSourceId() === h.source_id" (click)="open(h.customer_id, h.source_id)">
                  <span class="mono"><b>{{ h.customer_no }}</b></span>
                  <span>{{ h.name }}</span>
                  <span class="mono small">{{ h.email }}</span>
                  <span class="muted small">{{ h.country }} {{ h.city ? '· ' + h.city : '' }} · {{ h.policies }} polic{{ h.policies === 1 ? 'y' : 'ies' }}, {{ h.claims }} claim{{ h.claims === 1 ? '' : 's' }} · {{ h.source_name }}</span>
                  @if (h.hold !== 'N') { <span class="badge" [class]="'badge s-' + (h.hold === 'Y' ? 'red' : 'purple')">{{ h.hold === 'Y' ? 'On hold' : 'Has held records' }}</span> }
                </button>
              }
            </div>
          } @else if (searched()) {
            <div class="empty">No customer matches “{{ lastQ() }}”.</div>
          }
        </section>

        <div>
          @if (tree(); as t) {
            <section class="card">
              <div class="card-pad" style="padding-bottom:10px">
                <h2>{{ t.customer.label }} <span class="muted" style="font-weight:400">{{ t.customer.name }}</span></h2>
                <div class="mono small">{{ t.customer.email }}</div>
                <div class="muted small">{{ t.customer.country ?? 'no country' }}{{ t.customer.city ? ' · ' + t.customer.city : '' }} · {{ t.policies.length }} polic{{ t.policies.length === 1 ? 'y' : 'ies' }} · {{ t.claims.length }} claim{{ t.claims.length === 1 ? '' : 's' }}</div>
              </div>
              <div class="tbl-wrap">
                <table class="tbl">
                  <thead><tr><th>Record</th><th>Status</th><th>Legal hold</th><th>Details</th></tr></thead>
                  <tbody>
                    @for (row of rows(); track row.rec.table + row.rec.key) {
                      <tr [class.held]="row.rec.hold === 'Y'">
                        <td [style.padding-left.px]="14 + row.indent * 22">
                          <span class="badge s-gray">{{ row.rec.kind_label }}</span> <b class="mono">{{ row.rec.label }}</b>
                        </td>
                        <td class="small">{{ pretty(row.rec.status) }}@if (row.rec.kind) { <span class="muted"> · {{ pretty(row.rec.kind) }}</span> }</td>
                        <td>
                          <div class="seg" role="group" [attr.aria-label]="'Legal hold flag for ' + row.rec.label">
                            <button type="button" class="seg-y" [class.on]="row.rec.hold === 'Y'" [disabled]="!auth.canEdit() || row.rec.hold === 'Y'"
                                    (click)="ask(row.rec, 'Y')" title="Place a legal hold">Y</button>
                            <button type="button" class="seg-n" [class.on]="row.rec.hold !== 'Y'" [disabled]="!auth.canEdit() || row.rec.hold !== 'Y'"
                                    (click)="ask(row.rec, 'N')" title="Release the legal hold">N</button>
                          </div>
                        </td>
                        <td class="small">
                          @if (row.rec.hold === 'Y') {
                            <div><b>{{ row.rec.reason }}</b>@if (row.rec.matter_ref) { <span class="muted"> · {{ row.rec.matter_ref }}</span> }</div>
                            <div class="muted">by {{ row.rec.held_by }}, {{ when(row.rec.held_at) }}</div>
                          }
                          @for (c of row.rec.covered_by; track c.hold_id) {
                            <div class="muted">{{ c.relation === 'BELOW' ? 'Held because it belongs to ' : 'Kept because ' }}{{ c.entity }}{{ c.relation === 'BELOW' ? '' : ' is on hold' }}</div>
                          }
                        </td>
                      </tr>
                    }
                  </tbody>
                </table>
              </div>
              @if (!auth.canEdit()) { <div class="muted small" style="padding:10px 14px">Your role can read the register but not change flags.</div> }
            </section>
          } @else {
            <section class="card empty">Search for a customer, then flag the customer, one of their policies or one of their claims.</section>
          }
        </div>
      </div>

      <div class="section-title">
        <h2>Register</h2>
        <div class="row">
          <label class="muted small" for="rf">Show</label>
          <select id="rf" [ngModel]="filter()" (ngModelChange)="setFilter($event)">
            <option value="ACTIVE">Active holds</option><option value="">All, including released</option>
          </select>
        </div>
      </div>
      <section class="card">
        @if (holds().length) {
          <div class="tbl-wrap">
            <table class="tbl">
              <thead><tr><th>Record</th><th>Customer</th><th>Reason</th><th>Placed</th><th>Status</th><th></th></tr></thead>
              <tbody>
                @for (h of holds(); track h.hold_id) {
                  <tr>
                    <td><b class="mono">{{ h.entity_label ?? h.root_table + ' ' + h.key_value }}</b></td>
                    <td class="mono">{{ h.customer_ref ?? '' }}</td>
                    <td class="small">{{ h.reason }}@if (h.matter_ref) { <span class="muted"> · {{ h.matter_ref }}</span> }</td>
                    <td class="small muted">{{ h.created_by }}<br />{{ when(h.created_at) }}</td>
                    <td class="small">
                      <span class="badge" [class]="'badge s-' + (h.status === 'ACTIVE' ? 'red' : 'gray')">{{ pretty(h.status) }}</span>
                      @if (h.status !== 'ACTIVE') { <div class="muted">by {{ h.released_by }}, {{ when(h.released_at) }}<br />{{ h.release_reason }}</div> }
                    </td>
                    <td>
                      @if (auth.canEdit() && h.status === 'ACTIVE') {
                        <button class="btn btn-sm" (click)="askRelease(h)">Release (N)</button>
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else { <div class="empty">No legal holds{{ filter() ? ' are active' : '' }}.</div> }
      </section>
    </main>

    @if (dialog(); as d) {
      <div class="backdrop" (click)="dialog.set(null)"><div class="modal" role="dialog" aria-modal="true" (click)="$event.stopPropagation()">
        <div class="modal-head"><h2>{{ d.flag === 'Y' ? 'Place legal hold' : 'Release legal hold' }}</h2><button class="btn btn-sm" (click)="dialog.set(null)" aria-label="Close">✕</button></div>
        <div class="modal-body">
          @if (dialogError()) { <div class="alert alert-error">{{ dialogError() }}</div> }
          <p style="margin-top:0">{{ d.flag === 'Y' ? 'Set the flag to Y on' : 'Set the flag to N on' }} <b class="mono">{{ d.label }}</b>.</p>
          @if (d.flag === 'Y') { <div class="note">{{ impact(d.table) }} Erasure requests and retention clean-ups skip it from now on.</div> }
          @else { <div class="note">Once released, the record is treated like any other again. The hold stays in the register as history.</div> }
          <div class="field">
            <label for="hr">{{ d.flag === 'Y' ? 'Reason' : 'Reason for release' }}</label>
            <input id="hr" type="text" [placeholder]="d.flag === 'Y' ? 'e.g. litigation opened, court order' : 'e.g. matter settled'" [(ngModel)]="form.reason" />
          </div>
          @if (d.flag === 'Y') {
            <div class="field"><label for="hm">Matter reference <span class="muted">(optional)</span></label><input id="hm" type="text" class="mono" placeholder="e.g. case or court number" [(ngModel)]="form.matter" /></div>
          }
        </div>
        <div class="modal-foot">
          <button class="btn" (click)="dialog.set(null)">Cancel</button>
          <button class="btn btn-primary" (click)="submit()" [disabled]="busy() || form.reason.trim().length < 3">{{ d.flag === 'Y' ? 'Place hold (Y)' : 'Release hold (N)' }}</button>
        </div>
      </div></div>
    }
  `,
  styles: `
    .small { font-size: 12.5px; }
    .hits { border-top: 1px solid var(--border); max-height: 420px; overflow: auto; }
    .hit { display: grid; gap: 2px; width: 100%; text-align: left; background: transparent; border: 0; border-bottom: 1px solid var(--border); padding: 10px 20px; font: inherit; cursor: pointer; color: inherit; }
    .hit:hover { background: #f8fafc; }
    .hit.on { background: var(--primary-soft); }
    .hit .badge { justify-self: start; margin-top: 2px; }
    .seg { display: inline-flex; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
    .seg button { border: 0; background: #fff; padding: 4px 16px; font: inherit; font-weight: 700; font-size: 13px; cursor: pointer; color: var(--muted); }
    .seg button + button { border-left: 1px solid var(--border); }
    .seg button:not(:disabled):hover { background: #f1f5f9; }
    .seg button:disabled { cursor: default; }
    .seg .seg-y.on { background: var(--danger); color: #fff; }
    .seg .seg-n.on { background: #e2e8f0; color: #334155; }
    tr.held td { background: #fef2f2; }
  `,
})
export class LegalHolds {
  private api = inject(Api);
  private toasts = inject(Toasts);
  auth = inject(Auth);
  pretty = pretty; tone = tone;

  q = signal('');
  lastQ = signal('');
  searching = signal(false);
  searched = signal(false);
  hits = signal<HoldCustomerHit[]>([]);
  tree = signal<HoldTree | null>(null);
  treeSourceId = signal(1);
  holds = signal<LegalHold[]>([]);
  filter = signal('ACTIVE');
  dialog = signal<Ask | null>(null);
  dialogError = signal('');
  busy = signal(false);
  form = { reason: '', matter: '' };

  /** The customer, then each policy with its claims underneath, then claims that have no policy. */
  rows = computed<Row[]>(() => {
    const t = this.tree();
    if (!t) return [];
    const out: Row[] = [{ rec: t.customer, indent: 0 }];
    const claimsOf = new Map<string, HoldRecord[]>();
    for (const c of t.claims) claimsOf.set(c.policy_id ?? '', [...(claimsOf.get(c.policy_id ?? '') ?? []), c]);
    for (const p of t.policies) {
      out.push({ rec: p, indent: 1 });
      for (const c of claimsOf.get(p.key) ?? []) out.push({ rec: c, indent: 2 });
      claimsOf.delete(p.key);
    }
    for (const rest of claimsOf.values()) for (const c of rest) out.push({ rec: c, indent: 1 });
    return out;
  });

  constructor() { this.loadRegister(); }

  impact(table: string) { return IMPACT[table] ?? ''; }
  when(v: string | null | undefined) { return v ? v.slice(0, 16).replace('T', ' ') : ''; }

  loadRegister() { this.api.holds(this.filter() || undefined).subscribe((h) => this.holds.set(h)); }
  setFilter(v: string) { this.filter.set(v); this.loadRegister(); }

  search() {
    const q = this.q().trim();
    if (q.length < 2) return;
    this.searching.set(true);
    this.api.holdCustomers(q).subscribe({
      next: (h) => { this.searching.set(false); this.searched.set(true); this.lastQ.set(q); this.hits.set(h); if (h.length === 1) this.open(h[0].customer_id, h[0].source_id); },
      error: (e) => { this.searching.set(false); this.toasts.error(errorMessage(e)); },
    });
  }

  open(customerId: number, sourceId: number) {
    this.treeSourceId.set(sourceId);
    this.api.holdCustomer(sourceId, customerId).subscribe({ next: (t) => this.tree.set(t), error: (e) => this.toasts.error(errorMessage(e)) });
  }

  ask(rec: HoldRecord, flag: 'Y' | 'N') {
    this.form = { reason: '', matter: '' };
    this.dialogError.set('');
    this.dialog.set({ source_id: this.treeSourceId(), table: rec.table, key: rec.key, label: `${rec.kind_label} ${rec.label}`, flag, hold_id: flag === 'N' ? rec.hold_id ?? undefined : undefined });
  }

  askRelease(h: LegalHold) {
    this.form = { reason: '', matter: '' };
    this.dialogError.set('');
    this.dialog.set({ source_id: h.source_id, table: h.root_table, key: h.key_value, label: h.entity_label ?? `${h.root_table} ${h.key_value}`, flag: 'N', hold_id: h.hold_id });
  }

  submit() {
    const d = this.dialog();
    if (!d) return;
    this.busy.set(true);
    const call = d.flag === 'N' && d.hold_id
      ? this.api.releaseHold(d.hold_id, this.form.reason)
      : this.api.setHoldFlag(d.source_id, d.table, d.key, d.flag, this.form.reason, this.form.matter);
    call.subscribe({
      next: () => {
        this.busy.set(false);
        this.dialog.set(null);
        this.toasts.ok(d.flag === 'Y' ? `Legal hold placed on ${d.label}` : `Legal hold released on ${d.label}`);
        const cur = this.tree();
        if (cur) this.open(+cur.customer.key, this.treeSourceId());
        if (this.searched()) this.api.holdCustomers(this.lastQ()).subscribe((h) => this.hits.set(h));
        this.loadRegister();
      },
      error: (e) => { this.busy.set(false); this.dialogError.set(errorMessage(e)); },
    });
  }
}
