import { Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, errorMessage } from '../core/api';
import { pretty } from '../core/format';
import { Branding } from '../core/branding';
import { Dashboard as Dash } from '../core/models';

@Component({
  selector: 'app-dashboard',
  imports: [RouterLink],
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1>Data lifecycle overview</h1>
          <p>From discovery to verified remediation, for {{ brand.name() }}'s insurance data.</p>
        </div>
      </div>

      @if (error()) {
        <div class="alert alert-error">{{ error() }}</div>
      } @else if (d(); as d) {
        <div class="pipeline">
          @for (s of stages(); track s.n) {
            <a class="card stage" [routerLink]="s.link">
              <span class="n">{{ s.n }}</span>
              <span class="ttl">{{ s.title }}</span>
              <strong>{{ s.big }}</strong>
              <span class="muted small">{{ s.sub }}</span>
            </a>
          }
        </div>

        <div class="cols">
          <section class="card card-pad">
            <h2>Sensitive data protection by table</h2>
            <p class="muted small top">Classified personal and health columns, and how many are covered by a masking control.</p>
            @for (t of d.by_table; track t.table_name) {
              <div class="bar-row">
                <span class="mono lbl">{{ t.table_name }} @if (t.health) { <span class="badge s-purple" title="Includes health data">health</span> }</span>
                <div class="meter" [class.warn]="t.unprotected > 0"><i [style.width.%]="(t.findings - t.unprotected) / t.findings * 100"></i></div>
                <span class="small">{{ t.findings - t.unprotected }}/{{ t.findings }} protected</span>
              </div>
            } @empty {
              <div class="empty">No sensitive data found yet. Run a scan from <a routerLink="/sources">Data sources</a>.</div>
            }
            @if (d.sensitive_findings) {
              <div class="note" [class.good]="d.sensitive_protected === d.sensitive_findings">
                {{ d.sensitive_protected }} of {{ d.sensitive_findings }} sensitive columns are covered by a masking control.
              </div>
            }
          </section>

          <section class="card card-pad">
            <h2>Guided walkthrough</h2>
            <p class="muted small top">Follow the lifecycle end to end. Steps tick off as the data changes.</p>
            <ol class="steps">
              @for (s of steps(); track s.text) {
                <li [class.done]="s.done">
                  <span class="tick">{{ s.done ? '✓' : '' }}</span>
                  <a [routerLink]="s.link">{{ s.text }}</a>
                </li>
              }
            </ol>
          </section>
        </div>

        <section class="card" style="margin-top:16px">
          <div class="card-pad" style="padding-bottom:0"><h2>Recent activity</h2></div>
          <div class="tbl-wrap">
            <table class="tbl">
              <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Details</th></tr></thead>
              <tbody>
                @for (a of d.recent_activity; track $index) {
                  <tr>
                    <td class="mono muted">{{ a.ts.slice(0, 19).replace('T', ' ') }}</td>
                    <td>{{ a.username }}</td>
                    <td><span class="badge s-gray">{{ pretty(a.entity_type) }} · {{ a.action }}</span></td>
                    <td class="muted">{{ a.details }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </section>
      } @else {
        <div class="empty">Loading…</div>
      }
    </main>
  `,
  styles: `
    .pipeline { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 16px; }
    .stage { padding: 14px 16px; display: flex; flex-direction: column; gap: 2px; color: var(--text); position: relative; }
    .stage:hover { text-decoration: none; border-color: var(--primary); }
    .stage .n { position: absolute; top: 12px; right: 14px; width: 22px; height: 22px; border-radius: 50%; background: var(--primary-soft); color: var(--primary-dark); font-size: 12px; font-weight: 700; display: grid; place-items: center; }
    .stage .ttl { font-weight: 600; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
    .stage strong { font-size: 24px; margin-top: 2px; }
    .small { font-size: 12.5px; }
    .top { margin: 2px 0 14px; }
    .cols { display: grid; grid-template-columns: 1.3fr 1fr; gap: 16px; }
    .bar-row { display: grid; grid-template-columns: 170px 1fr 110px; gap: 12px; align-items: center; padding: 7px 0; }
    .lbl { overflow: hidden; text-overflow: ellipsis; }
    .steps { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
    .steps li { display: flex; align-items: center; gap: 10px; }
    .tick { width: 22px; height: 22px; border-radius: 50%; border: 2px solid #cbd5e1; display: grid; place-items: center; font-size: 12px; font-weight: 700; color: #fff; flex: none; }
    .steps li.done .tick { background: var(--primary); border-color: var(--primary); }
    .steps li.done a { color: var(--muted); }
    @media (max-width: 1000px) { .pipeline { grid-template-columns: repeat(3, 1fr); } .cols { grid-template-columns: 1fr; } }
    @media (max-width: 600px) { .pipeline { grid-template-columns: repeat(2, 1fr); } .bar-row { grid-template-columns: 110px 1fr; } .bar-row span:last-child { display: none; } }
  `,
})
export class Dashboard {
  private api = inject(Api);
  brand = inject(Branding);
  pretty = pretty;
  d = signal<Dash | null>(null);
  error = signal('');

  stages = computed(() => {
    const d = this.d();
    if (!d) return [];
    return [
      { n: 1, title: 'Discover', big: d.tables_cataloged, sub: `tables · ${d.columns_cataloged} columns`, link: '/sources' },
      { n: 2, title: 'Classify', big: d.sensitive_findings, sub: `sensitive columns · ${d.needs_review} to review`, link: '/findings' },
      { n: 3, title: 'Govern', big: d.active_rules, sub: `active rules · ${d.active_policies} policies`, link: '/policies' },
      { n: 4, title: 'Evaluate', big: d.open_violations, sub: 'open violations', link: '/remediation' },
      { n: 5, title: 'Remediate', big: d.tasks_verified, sub: `verified · ${d.tasks_awaiting_approval} awaiting approval`, link: '/remediation' },
      { n: 6, title: 'Erase', big: d.erasure_verified, sub: `verified · ${d.erasure_requests} requests`, link: '/erasure' },
    ];
  });

  steps = computed(() => {
    const d = this.d();
    if (!d) return [];
    return [
      { text: 'Discover the Databricks catalog', done: d.tables_cataloged > 0, link: '/sources' },
      { text: 'Run a scan (try FULL)', done: d.last_scan?.status === 'COMPLETED', link: '/sources' },
      { text: 'Review what the classifiers found', done: d.sensitive_findings > 0 && d.needs_review === 0, link: '/findings' },
      { text: 'Look at the policies and rules', done: d.active_rules > 0, link: '/policies' },
      { text: 'Evaluate policies against the findings', done: d.open_violations > 0 || d.tasks_verified > 0, link: '/remediation' },
      { text: 'Approve, execute and verify a task', done: d.tasks_verified > 0, link: '/remediation' },
      { text: 'Submit a GDPR erasure request', done: d.erasure_requests > 0, link: '/erasure' },
    ];
  });

  constructor() {
    this.api.dashboard().subscribe({ next: (d) => this.d.set(d), error: (e) => this.error.set(errorMessage(e)) });
  }
}
