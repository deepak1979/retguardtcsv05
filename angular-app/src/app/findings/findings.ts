import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { Confirms } from '../core/confirm';
import { pct, pretty, tone } from '../core/format';
import { Classifier, Finding, LlmOpinion, LlmSampleLevel, LlmSettings, Lookups, UcTaggingSettings, UcTaggingStats } from '../core/models';
import { Toasts } from '../core/toast';

interface ClassifierDraft {
  code: string; name: string; category: string; pii_class: string; applies_to: string; method: 'REGEX' | 'KEYWORD';
  name_pattern: string; content_pattern: string; min_match_ratio: number; name_weight: number; content_weight: number;
  description: string; scope_level: string; region_id: number | null; country_id: number | null;
}

@Component({
  selector: 'app-findings',
  imports: [FormsModule],
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1>Classification findings</h1>
          <p>What the scanner believes each column contains, and how sure it is. Steward decisions survive re-scans.</p>
        </div>
        @if (llm(); as l) {
          <div class="llm-box">
            <label class="switch" [title]="auth.isAdmin() ? 'Switch the LLM second opinion on or off' : 'Only an admin can change this'">
              <input type="checkbox" role="switch" aria-label="LLM second opinion" [checked]="l.enabled" [disabled]="!auth.isAdmin() || llmBusy()"
                     (change)="toggleLlm($any($event.target).checked)" />
              <span class="track"><i></i></span>
            </label>
            <div class="llm-text">
              <b>LLM second opinion</b>
              <span class="muted small">{{ llmLine() }}</span>
            </div>
            @if (auth.isAdmin()) { <button class="btn btn-sm" (click)="openLlm()">Configure</button> }
          </div>
        }
        @if (ucTagging(); as u) {
          <div class="llm-box" title="Writes this finding's classification to Unity Catalog as a pii_classification column tag the moment it's confirmed - only when the column has no native tag already">
            <label class="switch" [title]="auth.isAdmin() ? 'Switch Unity Catalog auto-tagging on or off' : 'Only an admin can change this'">
              <input type="checkbox" role="switch" aria-label="Unity Catalog auto-tagging" [checked]="u.enabled" [disabled]="!auth.isAdmin() || ucTaggingBusy()"
                     (change)="toggleUcTagging($any($event.target).checked)" />
              <span class="track"><i></i></span>
            </label>
            <div class="llm-text">
              <b>UC auto-tagging</b>
              <span class="muted small">{{ u.enabled ? 'On - confirming a finding tags its column in Unity Catalog' : 'Off - confirming only updates this app' }}</span>
            </div>
            @if (auth.isAdmin()) {
              <button class="btn btn-sm" [disabled]="ucCommitBusy()" (click)="commitUcTags()"
                      title="Reconcile Unity Catalog tags against every finding's status right now - tags anything CONFIRMED that's missing a tag, untags anything that's no longer CONFIRMED. Works even while auto-tagging is off.">
                {{ ucCommitBusy() ? 'Committing…' : 'UC Commit' }}
              </button>
            }
          </div>
        }
      </div>

      <div class="tabs">
        <button class="tab" [class.active]="tab() === 'findings'" (click)="tab.set('findings')">Findings ({{ rows().length }})</button>
        <button class="tab" [class.active]="tab() === 'classifiers'" (click)="tab.set('classifiers')">Classifier library ({{ classifiers().length }})</button>
      </div>

      @if (tab() === 'findings') {
        <div class="kpis">
          @for (k of kpis(); track k.label) { <div class="card kpi"><span class="muted">{{ k.label }}</span><strong>{{ k.value }}</strong></div> }
          @if (ucStats(); as s) {
            <div class="card kpi" title="Confirmed findings whose classification has been written to Unity Catalog as a pii_classification column tag">
              <span class="muted">Tagged in UC</span><strong>{{ s.tagged }}</strong>
            </div>
          }
        </div>
        <div class="card">
          <div class="filters">
            <select aria-label="Status" [ngModel]="status()" (ngModelChange)="status.set($event); load()">
              <option value="">Active (auto + review + confirmed)</option>
              @for (s of statuses; track s) { <option [value]="s">{{ pretty(s) }}</option> }
            </select>
            <select aria-label="Category" [ngModel]="category()" (ngModelChange)="category.set($event); load()">
              <option value="">All categories</option>
              @for (c of lookups()?.data_categories ?? []; track c) { <option [value]="c">{{ pretty(c) }}</option> }
            </select>
            <input type="text" placeholder="Filter by table or column…" aria-label="Search" [ngModel]="q()" (ngModelChange)="q.set($event)" />
          </div>
          @if (llm()?.enabled && auth.canEdit() && (reviewable().length || bulk())) {
            <div class="bulk">
              @if (!bulk()) {
                <span>{{ reviewable().length }} finding(s) still need a decision.</span>
                <button class="btn btn-sm" (click)="askAll()">Ask the LLM about them</button>
              } @else {
                <span>Asking the model: {{ bulk()!.done }} of {{ bulk()!.total }}…</span>
                <button class="btn btn-sm btn-danger" (click)="cancelBulk()" [disabled]="bulk()!.stop">{{ bulk()!.stop ? 'Stopping…' : 'Stop' }}</button>
              }
              <span class="muted small">A laptop model needs several seconds per finding. Nothing is changed: you still confirm or reject.</span>
            </div>
          }
          @if (error()) { <div class="alert alert-error" style="margin:14px">{{ error() }}</div> }
          @else if (shown().length === 0) { <div class="empty">No findings match. Run a scan from Data sources.</div> }
          @else {
            <div class="tbl-wrap">
              <table class="tbl">
                <thead><tr><th>Column</th><th>Detected as</th><th>Confidence</th><th>Evidence</th><th>Sample (masked)</th><th>Status</th><th></th></tr></thead>
                <tbody>
                  @for (f of shown(); track f.finding_id) {
                    <tr>
                      <td><span class="mono"><b>{{ f.table_name }}</b>.{{ f.column_name }}</span></td>
                      <td>
                        {{ pretty(f.data_element) }}
                        <div class="row" style="gap:4px;margin-top:2px">
                          <span class="badge s-blue">{{ pretty(f.category) }}</span>
                          @if (f.pii_class && f.pii_class !== 'DIRECT') { <span class="badge" [class]="'badge s-' + classTone(f.pii_class)" [title]="classHelp(f.pii_class)">{{ f.pii_class.toLowerCase() }}</span> }
                        </div>
                      </td>
                      <td style="min-width:110px">
                        <div class="row" style="flex-wrap:nowrap"><div class="meter" style="flex:1" [class.warn]="f.confidence < 0.8"><i [style.width.%]="f.confidence * 100"></i></div><b>{{ pct(f.confidence) }}</b></div>
                      </td>
                      <td class="small evidence">
                        <div>{{ f.name_hit ? '✓' : '✗' }} column name</div>
                        <div>{{ f.match_ratio === null ? 'content not read' : pct(f.match_ratio) + ' of ' + f.rows_sampled + ' values match' }}</div>
                      </td>
                      <td class="mono small samples">{{ f.samples ?? '—' }}</td>
                      <td>
                        <span class="badge" [class]="'badge s-' + tone(f.status)">{{ pretty(f.status) }}</span>
                        @if (f.protection !== 'NONE') { <div><span class="badge s-teal" style="margin-top:4px">🛡 {{ pretty(f.protection) }}</span></div> }
                        @if (f.decided_by) { <div class="muted small">by {{ f.decided_by }}</div> }
                      </td>
                      <td style="white-space:nowrap">
                        @if (auth.canEdit() && f.status !== 'RESOLVED') {
                          @if (f.status !== 'CONFIRMED') { <button class="btn btn-sm" (click)="decide(f, 'CONFIRMED')">Confirm</button> }
                          @if (f.status !== 'REJECTED') { <button class="btn btn-sm btn-danger" (click)="decide(f, 'REJECTED')">Reject</button> }
                        }
                        @if (llm()?.enabled && auth.canEdit() && f.status !== 'RESOLVED') {
                          <button class="btn btn-sm" (click)="ask(f)" [disabled]="asking().has(f.finding_id)" title="Ask the language model for a second opinion">
                            {{ asking().has(f.finding_id) ? 'Asking…' : (opinion(f) ? 'Ask again' : 'Ask LLM') }}
                          </button>
                        }
                      </td>
                    </tr>
                    @if (opinion(f); as o) {
                      <tr class="op-row"><td colspan="7">
                        <div class="opinion" [class]="'opinion v-' + o.verdict.toLowerCase()">
                          <b>🤖 {{ verdictText(o) }}</b>
                          <span class="muted small"> · {{ o.confidence === null ? '' : pct(o.confidence) + ' sure · ' }}{{ o.model }}{{ sampleNote(o.sample_level) }}</span>
                          @if (o.reason) { <div>{{ o.reason }}</div> }
                        </div>
                      </td></tr>
                    }
                  }
                </tbody>
              </table>
            </div>
          }
        </div>
        <p class="muted small" style="margin-top:10px">
          Auto ≥ 80% is trusted. 50–80% needs a steward decision before policies act on it. 30–50% is kept as a low-confidence
          look-alike (for example <span class="mono">BRANCH_NAME</span>) and ignored by policies.
        </p>
      } @else {
        <div class="section-title" style="margin-top:0">
          <span class="muted">confidence = name weight × name match + content weight × content match</span>
          @if (auth.canEdit()) { <button class="btn btn-primary" (click)="openClf()">＋ Custom classifier</button> }
        </div>
        <div class="card">
          <div class="tbl-wrap">
            <table class="tbl">
              <thead><tr><th>Element</th><th>Category</th><th>Detects</th><th>Weights (name / content)</th><th>Origin</th><th>Enabled</th></tr></thead>
              <tbody>
                @for (g of groups(); track g.key) {
                  <tr class="grp"><td colspan="6"><b>{{ g.title }}</b><span class="muted small" style="margin-left:10px">{{ g.items.length }} classifier(s) · {{ g.hint }}</span></td></tr>
                  @for (c of g.items; track c.classifier_id) {
                  <tr>
                    <td><b>{{ c.name }}</b><div class="mono muted small">{{ c.code }}</div></td>
                    <td><span class="badge s-blue">{{ pretty(c.category) }}</span></td>
                    <td class="small">{{ c.description }}<div class="mono muted">{{ pretty(c.content_method) }}{{ c.min_match_ratio ? ' · full evidence at ' + pct(c.min_match_ratio) + ' of rows' : '' }}{{ c.name_pattern ? ' · name ~ ' + c.name_pattern : '' }}</div></td>
                    <td>{{ c.name_weight }} / {{ c.content_weight }}</td>
                    <td>{{ c.is_builtin ? 'Built-in' : 'Custom' }}</td>
                    <td style="white-space:nowrap">
                      <label class="check" style="margin:0"><input type="checkbox" [checked]="c.is_active" [disabled]="!auth.canEdit()" (change)="toggle(c, $any($event.target).checked)" /> {{ c.is_active ? 'On' : 'Off' }}</label>
                      @if (!c.is_builtin && auth.canEdit()) { <button class="btn btn-sm btn-danger" (click)="remove(c)">Delete</button> }
                    </td>
                  </tr>
                  }
                }
              </tbody>
            </table>
          </div>
        </div>
        <p class="muted small" style="margin-top:10px">Changes to the library take effect on the next scan.</p>
      }
    </main>

    @if (llmDialog()) {
      <div class="backdrop" (click)="llmDialog.set(false)">
        <div class="modal" role="dialog" aria-modal="true" (click)="$event.stopPropagation()">
          <div class="modal-head"><h2>LLM second opinion</h2><button class="btn btn-sm" (click)="llmDialog.set(false)" aria-label="Close">✕</button></div>
          <div class="modal-body">
            @if (llmError()) { <div class="alert alert-error">{{ llmError() }}</div> }
            @if (llmReply()) { <div class="note good">✓ {{ llmReply() }}</div> }
            <div class="note">The rule-based scanner always runs on this machine. The model only comments on a finding when someone asks, and it never changes one.
              With the switch off, nothing is sent anywhere.</div>
            <div class="field"><label for="lp">Where the model runs</label>
              <select id="lp" [(ngModel)]="lf.provider" (ngModelChange)="providerChanged()">
                @for (p of llm()?.providers ?? []; track p.code) { <option [value]="p.code">{{ p.label }}</option> }
              </select></div>
            <div class="grid-2">
              <div class="field"><label for="lm">Model</label><input id="lm" type="text" class="mono" [(ngModel)]="lf.model" /></div>
              <div class="field"><label for="lt">Timeout (seconds)</label><input id="lt" type="number" min="5" max="900" [(ngModel)]="lf.timeout" /></div>
            </div>
            <div class="field"><label for="lu">Address</label><input id="lu" type="text" class="mono" [(ngModel)]="lf.base_url" />
              @if (providerIsLocal()) { <span class="hint">Must be on this machine. Install Ollama, then run <span class="mono">ollama pull {{ lf.model }}</span>.</span> }
              @else { <span class="hint">Cloud service: column names and statistics leave this machine when an opinion is requested.</span> }
            </div>
            @if (!providerIsLocal()) {
              <div class="note" [class.good]="llm()?.key_present" [class.bad]="!llm()?.key_present">{{ llm()?.key_present ? '✓ Ready to use' : '✗ No API key configured for this provider. Add it to backend-databricks/.env and restart the app. It is never stored in the database.' }}</div>
            }
            <div class="field">
              <span class="label">How much detail to send</span>
              <label class="level"><input type="radio" name="lvl" value="NONE" [(ngModel)]="lf.sample_level" />
                <span><b>Metadata only</b><br /><span class="muted small">Column name, type and statistics. No value from your data ever leaves the database.</span></span></label>
              <label class="level"><input type="radio" name="lvl" value="MASKED" [(ngModel)]="lf.sample_level" />
                <span><b>+ masked samples</b><br /><span class="muted small">Up to 3 already-masked example values, e.g. <span class="mono">j***&#64;x.com</span>.</span></span></label>
              <label class="level" [class.off]="!providerIsLocal()"><input type="radio" name="lvl" value="REAL" [(ngModel)]="lf.sample_level" [disabled]="!providerIsLocal()" />
                <span><b>+ real sample values</b><br /><span class="muted small">Up to 3 REAL, unmasked values read live from the column. Usually the most accurate.
                @if (providerIsLocal()) { Never stored - only sent for that one request, to the model running on this machine. }
                @else { Local model only. }</span></span></label>
            </div>
          </div>
          <div class="modal-foot">
            <button class="btn" (click)="llmDialog.set(false)">Close</button>
            <button class="btn" (click)="saveLlm(true)" [disabled]="llmBusy() || !llm()?.enabled" [title]="llm()?.enabled ? 'Save, then send a test message that contains no data' : 'Switch the LLM on first'">Save and test</button>
            <button class="btn btn-primary" (click)="saveLlm(false)" [disabled]="llmBusy()">Save</button>
          </div>
        </div>
      </div>
    }

    @if (clfOpen()) {
      <div class="backdrop" (click)="clfOpen.set(false)">
        <div class="modal" role="dialog" aria-modal="true" (click)="$event.stopPropagation()">
          <div class="modal-head"><h2>Custom classifier</h2><button class="btn btn-sm" (click)="clfOpen.set(false)" aria-label="Close">✕</button></div>
          <div class="modal-body">
            @if (clfError()) { <div class="alert alert-error">{{ clfError() }}</div> }
            <div class="grid-2">
              <div class="field"><label for="cc">Code</label><input id="cc" type="text" placeholder="POLICY_HOLDER_ID" [(ngModel)]="clf.code" /></div>
              <div class="field"><label for="cn">Name</label><input id="cn" type="text" [(ngModel)]="clf.name" /></div>
              <div class="field"><label for="ck">Category</label>
                <select id="ck" [(ngModel)]="clf.category">@for (c of lookups()?.data_categories ?? []; track c) { <option [value]="c">{{ pretty(c) }}</option> }</select></div>
              <div class="field"><label for="cs">Scope</label>
                <select id="cs" [(ngModel)]="clf.scope_level" (ngModelChange)="scopeChanged()"><option value="GLOBAL">Global</option><option value="REGION">A region</option><option value="COUNTRY">One country</option></select>
                <span class="hint">A regional or country classifier only runs when that region or country is active.</span></div>
              @if (clf.scope_level === 'REGION') {
                <div class="field"><label for="csr">Region</label><select id="csr" [(ngModel)]="clf.region_id">@for (r of lookups()?.regions ?? []; track r.region_id) { <option [ngValue]="r.region_id">{{ r.name }}</option> }</select></div>
              }
              @if (clf.scope_level === 'COUNTRY') {
                <div class="field"><label for="csc">Country</label><select id="csc" [(ngModel)]="clf.country_id">@for (c of lookups()?.countries ?? []; track c.country_id) { <option [ngValue]="c.country_id">{{ c.name }} ({{ c.iso2 }})</option> }</select></div>
              }
              <div class="field"><label for="ct">Column data type</label>
                <select id="ct" [(ngModel)]="clf.applies_to"><option value="STRING">Text</option><option value="NUMBER">Number</option><option value="DATE">Date</option></select></div>
              <div class="field"><label for="cl">Kind of data</label>
                <select id="cl" [(ngModel)]="clf.pii_class">
                  <option value="DIRECT">Direct identifier</option><option value="IDENTIFIER">Business identifier</option>
                  <option value="QUASI">Quasi-identifier</option><option value="SENSITIVE">Sensitive / special category</option>
                </select><span class="hint">{{ classHelp(clf.pii_class) }}</span></div>
            </div>
            <div class="field"><label for="cm">Detect by</label>
              <select id="cm" [(ngModel)]="clf.method"><option value="REGEX">Value pattern (regular expression)</option><option value="KEYWORD">Keyword list (words inside the value)</option></select></div>
            @if (clf.method === 'REGEX') {
              <div class="field"><label for="cp">Value pattern (regular expression)</label><input id="cp" type="text" class="mono" placeholder="^HD-\\d{6}$" [(ngModel)]="clf.content_pattern" /><span class="hint">Matched against the whole value.</span></div>
            } @else {
              <div class="field"><label for="ck2">Keywords <span class="muted">(comma separated)</span></label><textarea id="ck2" class="mono" placeholder="dental, hospital, surgery, outpatient" [(ngModel)]="clf.content_pattern"></textarea><span class="hint">A value matches when a word in it starts with any keyword, so "hospital" also finds "hospitalization".</span></div>
              <div class="field"><label for="cr">Share of rows that counts as full evidence</label><input id="cr" type="number" step="0.01" min="0.01" max="1" [(ngModel)]="clf.min_match_ratio" /><span class="hint">For sparse data. 0.15 means a column where a sixth of the values match is treated as a full match.</span></div>
            }
            <div class="field"><label for="cnp">Column name pattern <span class="muted">(optional)</span></label><input id="cnp" type="text" class="mono" placeholder="HOLDER|POLICYHOLDER" [(ngModel)]="clf.name_pattern" /></div>
            <div class="grid-2">
              <div class="field"><label for="cw1">Name weight</label><input id="cw1" type="number" step="0.05" min="0" max="1" [(ngModel)]="clf.name_weight" /></div>
              <div class="field"><label for="cw2">Content weight</label><input id="cw2" type="number" step="0.05" min="0" max="1" [(ngModel)]="clf.content_weight" /></div>
            </div>
            <div class="field"><label for="cd">Description</label><input id="cd" type="text" [(ngModel)]="clf.description" /></div>
          </div>
          <div class="modal-foot"><button class="btn" (click)="clfOpen.set(false)">Cancel</button><button class="btn btn-primary" (click)="saveClf()">Save classifier</button></div>
        </div>
      </div>
    }
  `,
  styles: `
    .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 16px; }
    .kpi { padding: 12px 18px; display: flex; flex-direction: column; } .kpi strong { font-size: 24px; }
    .filters { display: grid; grid-template-columns: 260px 200px 1fr; gap: 10px; padding: 14px; border-bottom: 1px solid var(--border); }
    .small { font-size: 12.5px; }
    .samples { max-width: 200px; word-break: break-all; }
    .evidence { white-space: nowrap; }
    tr.grp td { background: #f8fafc; padding: 8px 14px; border-top: 1px solid var(--border); }
    .llm-box { display: flex; align-items: center; gap: 12px; padding: 8px 12px; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); }
    .llm-text { display: flex; flex-direction: column; line-height: 1.3; max-width: 300px; }
    .switch { position: relative; display: inline-block; width: 42px; height: 24px; flex: none; }
    .switch input { position: absolute; inset: 0; width: 100%; height: 100%; margin: 0; opacity: 0; cursor: pointer; z-index: 1; }
    .switch input:disabled { cursor: not-allowed; }
    .switch .track { position: absolute; inset: 0; background: #cbd5e1; border-radius: 999px; transition: background 0.15s; }
    .switch .track i { position: absolute; top: 3px; left: 3px; width: 18px; height: 18px; background: #fff; border-radius: 50%; box-shadow: 0 1px 2px rgba(0, 0, 0, 0.3); transition: transform 0.15s; }
    .switch input:checked + .track { background: var(--primary); }
    .switch input:checked + .track i { transform: translateX(18px); }
    .switch input:focus-visible + .track { outline: 2px solid var(--primary); outline-offset: 2px; }
    .bulk { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding: 10px 14px; border-bottom: 1px solid var(--border); background: #f8fafc; }
    tr.op-row td { padding-top: 0; }
    .opinion { border-left: 3px solid #94a3b8; background: #f8fafc; padding: 8px 12px; border-radius: 6px; font-size: 13px; }
    .opinion.v-agree { border-color: var(--ok); }
    .opinion.v-disagree { border-color: var(--warn); }
    .level { display: flex; align-items: flex-start; gap: 10px; padding: 8px 4px; cursor: pointer; }
    .level.off { opacity: 0.55; cursor: not-allowed; }
    .level input { margin-top: 3px; }
    @media (max-width: 800px) { .kpis { grid-template-columns: repeat(2, 1fr); } .filters { grid-template-columns: 1fr; } }
  `,
})
export class Findings {
  private api = inject(Api);
  private toasts = inject(Toasts);
  private confirm = inject(Confirms);
  auth = inject(Auth);
  pretty = pretty; tone = tone; pct = pct;
  statuses = ['AUTO', 'NEEDS_REVIEW', 'CONFIRMED', 'REJECTED', 'LOW', 'RESOLVED'];

  tab = signal<'findings' | 'classifiers'>('findings');
  rows = signal<Finding[]>([]);
  classifiers = signal<Classifier[]>([]);
  lookups = signal<Lookups | null>(null);
  status = signal('');
  category = signal('');
  q = signal('');
  error = signal('');

  shown = computed(() => {
    const q = this.q().toLowerCase();
    return this.rows().filter((f) => !q || `${f.table_name}.${f.column_name}`.toLowerCase().includes(q));
  });
  /** The library grouped by pack: global first, then each region, then each country. */
  groups = computed(() => {
    const out = new Map<string, { key: string; title: string; hint: string; order: number; items: Classifier[] }>();
    for (const c of this.classifiers()) {
      const lvl = c.scope_level;
      const key = lvl === 'GLOBAL' ? 'G' : `${lvl[0]}${c.scope_label}`;
      if (!out.has(key)) out.set(key, {
        key, order: lvl === 'GLOBAL' ? 0 : lvl === 'REGION' ? 1 : 2,
        title: lvl === 'GLOBAL' ? 'Global library' : lvl === 'REGION' ? `${c.scope_label} pack` : `${c.scope_label} pack`,
        hint: lvl === 'GLOBAL' ? 'runs everywhere' : lvl === 'REGION' ? 'runs when the region is active' : c.scope_valid ? 'runs when the country is active' : 'country not in the active company', items: [] });
      out.get(key)!.items.push(c);
    }
    return [...out.values()].sort((a, b) => a.order - b.order || a.title.localeCompare(b.title));
  });

  kpis = computed(() => {
    const r = this.rows();
    return [
      { label: 'Shown', value: r.length },
      { label: 'Auto-classified', value: r.filter((f) => f.status === 'AUTO').length },
      { label: 'Needs review', value: r.filter((f) => f.status === 'NEEDS_REVIEW').length },
      { label: 'Confirmed', value: r.filter((f) => f.status === 'CONFIRMED').length },
    ];
  });

  clfOpen = signal(false);
  clfError = signal('');
  clf: ClassifierDraft = this.blankClf();

  // ---- optional LLM second opinion. Off means the UI shows no trace of it and the server refuses every call.
  llm = signal<LlmSettings | null>(null);
  opinions = signal<Record<number, LlmOpinion>>({});
  asking = signal<Set<number>>(new Set());
  bulk = signal<{ done: number; total: number; stop: boolean } | null>(null);
  llmBusy = signal(false);
  llmDialog = signal(false);
  llmError = signal('');
  llmReply = signal('');
  lf: { provider: string; model: string; base_url: string; timeout: number; sample_level: LlmSampleLevel } =
    { provider: 'OLLAMA', model: '', base_url: '', timeout: 180, sample_level: 'NONE' };

  reviewable = computed(() => this.shown().filter((f) => (f.status === 'NEEDS_REVIEW' || f.status === 'LOW') && !this.opinions()[f.finding_id]));

  constructor() {
    this.api.lookups().subscribe((l) => this.lookups.set(l));
    this.load();
    this.loadClassifiers();
    this.loadLlm();
    this.loadUcTagging();
  }

  // ---- Unity Catalog governed-tag write-back on confirmation (off by default)
  ucTagging = signal<UcTaggingSettings | null>(null);
  ucStats = signal<UcTaggingStats | null>(null);
  ucTaggingBusy = signal(false);

  loadUcTagging() {
    this.api.ucTaggingSettings().subscribe({ next: (s) => this.ucTagging.set(s), error: () => this.ucTagging.set(null) });
    this.loadUcStats();
  }
  loadUcStats() {
    this.api.ucTaggingStats().subscribe({ next: (s) => this.ucStats.set(s), error: () => this.ucStats.set(null) });
  }
  toggleUcTagging(on: boolean) {
    this.ucTaggingBusy.set(true);
    this.api.saveUcTaggingSettings({ enabled: on }).subscribe({
      next: (s) => {
        this.ucTaggingBusy.set(false); this.ucTagging.set(s);
        this.toasts.ok(s.enabled ? 'UC auto-tagging is on' : 'UC auto-tagging is off');
      },
      error: (e) => { this.ucTaggingBusy.set(false); this.toasts.error(errorMessage(e)); this.loadUcTagging(); },
    });
  }

  ucCommitBusy = signal(false);
  commitUcTags() {
    this.ucCommitBusy.set(true);
    this.api.ucTaggingCommit().subscribe({
      next: (r) => {
        this.ucCommitBusy.set(false); this.loadUcStats();
        this.toasts.ok(`UC Commit: ${r.tagged} tagged, ${r.untagged} untagged`);
      },
      error: (e) => { this.ucCommitBusy.set(false); this.toasts.error(errorMessage(e)); },
    });
  }

  loadLlm() {
    this.api.llmSettings().subscribe({
      next: (s) => { this.llm.set(s); if (s.enabled) this.loadOpinions(); else this.opinions.set({}); },
      error: () => this.llm.set(null),
    });
  }
  loadOpinions() {
    this.api.llmOpinions().subscribe((list) => this.opinions.set(Object.fromEntries(list.map((o) => [o.finding_id, o]))));
  }
  opinion(f: Finding): LlmOpinion | undefined { return this.llm()?.enabled ? this.opinions()[f.finding_id] : undefined; }
  llmLine(): string {
    const l = this.llm();
    if (!l) return '';
    if (!l.enabled) return 'Off. Scanning uses only local rules and dictionaries.';
    const where = l.provider === 'OLLAMA' ? 'on this machine' : 'cloud, data leaves this machine';
    const detail = { NONE: 'metadata only', MASKED: 'with masked samples', REAL: 'with REAL sample values' }[l.sample_level];
    return `On · ${l.model} (${where}) · ${detail}`;
  }
  sampleNote(level: LlmSampleLevel): string {
    return level === 'REAL' ? ' · REAL sample values were sent' : level === 'MASKED' ? ' · masked samples were sent' : '';
  }
  verdictText(o: LlmOpinion): string {
    if (o.verdict === 'AGREE') return 'Agrees with the scanner';
    if (o.verdict === 'UNSURE') return 'Cannot tell from the metadata';
    return !o.suggested || o.suggested === 'NONE' ? 'Thinks this is not sensitive data' : `Suggests: ${pretty(o.suggested)}`;
  }
  providerIsLocal() { return (this.llm()?.providers ?? []).find((p) => p.code === this.lf.provider)?.local ?? true; }

  async toggleLlm(on: boolean) {
    const l = this.llm();
    if (!l) return;
    if (on && !l.local && !await this.confirm.ask('This provider is a cloud service. Column names, types and statistics will leave this machine whenever someone asks for an opinion. Switch it on?')) {
      this.loadLlm();
      return;
    }
    this.llmBusy.set(true);
    this.api.saveLlmSettings({ enabled: on }).subscribe({
      next: (s) => {
        this.llmBusy.set(false); this.llm.set(s);
        if (s.enabled) { this.loadOpinions(); this.toasts.ok('LLM second opinion is on'); }
        else { this.opinions.set({}); this.bulk.set(null); this.toasts.ok('LLM second opinion is off. Nothing will be sent anywhere.'); }
      },
      error: (e) => { this.llmBusy.set(false); this.toasts.error(errorMessage(e)); this.loadLlm(); },
    });
  }

  openLlm() {
    const l = this.llm();
    if (!l) return;
    this.lf = { provider: l.provider, model: l.model, base_url: l.base_url, timeout: l.timeout, sample_level: l.sample_level };
    this.llmError.set(''); this.llmReply.set('');
    this.llmDialog.set(true);
  }
  providerChanged() {
    const p = (this.llm()?.providers ?? []).find((x) => x.code === this.lf.provider);
    if (p) { this.lf.model = p.default_model; this.lf.base_url = p.default_url; }
    if (!p?.local && this.lf.sample_level === 'REAL') this.lf.sample_level = 'MASKED';  // REAL is local-only
  }
  async saveLlm(thenTest: boolean) {
    const cloud = !this.providerIsLocal();
    if (cloud && this.lf.sample_level === 'MASKED' && !await this.confirm.ask('Masked sample values will be sent to a cloud provider. Continue?')) return;
    if (this.lf.sample_level === 'REAL' && !await this.confirm.ask(`Real, unmasked values from your database will be sent to ${this.lf.model} running on this machine via Ollama. Continue?`)) return;
    this.llmBusy.set(true); this.llmError.set(''); this.llmReply.set('');
    this.api.saveLlmSettings({ provider: this.lf.provider, model: this.lf.model, base_url: this.lf.base_url, timeout: +this.lf.timeout, sample_level: this.lf.sample_level }).subscribe({
      next: (s) => {
        this.llm.set(s);
        if (!thenTest) { this.llmBusy.set(false); this.toasts.ok('LLM settings saved'); return; }
        this.api.llmTest().subscribe({
          next: (t) => { this.llmBusy.set(false); this.llmReply.set(`The model answered: “${t.reply}” (${t.model})`); },
          error: (e) => { this.llmBusy.set(false); this.llmError.set(errorMessage(e)); },
        });
      },
      error: (e) => { this.llmBusy.set(false); this.llmError.set(errorMessage(e)); },
    });
  }

  private putOpinion(o: LlmOpinion) { this.opinions.update((m) => ({ ...m, [o.finding_id]: o })); }
  ask(f: Finding) {
    this.asking.update((s) => new Set(s).add(f.finding_id));
    this.api.llmOpinion(f.finding_id, !!this.opinions()[f.finding_id]).subscribe({
      next: (o) => { this.putOpinion(o); this.doneAsking(f.finding_id); },
      error: (e) => { this.doneAsking(f.finding_id); this.toasts.error(errorMessage(e)); this.loadLlm(); },
    });
  }
  private doneAsking(id: number) { this.asking.update((s) => { const n = new Set(s); n.delete(id); return n; }); }

  /** One finding at a time: a laptop model is slow, and the person can stop at any moment. */
  askAll() {
    const queue = this.reviewable().map((f) => f.finding_id);
    if (!queue.length) return;
    this.bulk.set({ done: 0, total: queue.length, stop: false });
    const next = () => {
      const cur = this.bulk();
      if (!cur || cur.stop || !queue.length) {
        this.bulk.set(null);
        if (cur) this.toasts.ok(cur.stop ? 'Stopped' : 'Second opinions are ready');
        return;
      }
      this.api.llmOpinion(queue.shift()!).subscribe({
        next: (o) => { this.putOpinion(o); const b = this.bulk(); if (b) this.bulk.set({ ...b, done: b.done + 1 }); next(); },
        error: (e) => { this.bulk.set(null); this.toasts.error(errorMessage(e)); this.loadLlm(); },
      });
    };
    next();
  }
  cancelBulk() { this.bulk.update((b) => (b ? { ...b, stop: true } : b)); }

  load() {
    this.api.findings({ status: this.status(), category: this.category() }).subscribe({
      next: (r) => { this.rows.set(r); this.error.set(''); },
      error: (e) => this.error.set(errorMessage(e)),
    });
  }
  loadClassifiers() { this.api.classifiers().subscribe((c) => this.classifiers.set(c)); }

  decide(f: Finding, status: string) {
    this.api.decide(f.finding_id, status).subscribe({
      next: () => {
        this.toasts.ok(`${f.table_name}.${f.column_name} ${status.toLowerCase()}`);
        this.load();
        if (status === 'CONFIRMED' && this.ucTagging()?.enabled) this.loadUcStats();
      },
      error: (e) => this.toasts.error(errorMessage(e)),
    });
  }

  toggle(c: Classifier, on: boolean) {
    this.api.toggleClassifier(c.classifier_id, on).subscribe({ next: () => this.loadClassifiers(), error: (e) => this.toasts.error(errorMessage(e)) });
  }
  async remove(c: Classifier) {
    if (!await this.confirm.ask(`Delete classifier ${c.code}?`)) return;
    this.api.deleteClassifier(c.classifier_id).subscribe({ next: () => { this.toasts.ok('Classifier deleted'); this.loadClassifiers(); }, error: (e) => this.toasts.error(errorMessage(e)) });
  }

  private blankClf(): ClassifierDraft { return { code: '', name: '', category: 'PII', pii_class: 'DIRECT', applies_to: 'STRING', method: 'REGEX', name_pattern: '', content_pattern: '', min_match_ratio: 0.15, name_weight: 0.3, content_weight: 0.7, description: '', scope_level: 'GLOBAL', region_id: null, country_id: null }; }
  scopeChanged() {
    this.clf.region_id = this.clf.scope_level === 'REGION' ? this.lookups()?.regions[0]?.region_id ?? null : null;
    this.clf.country_id = this.clf.scope_level === 'COUNTRY' ? this.lookups()?.countries[0]?.country_id ?? null : null;
  }
  classTone(c: string) { return ({ IDENTIFIER: 'teal', QUASI: 'gray', SENSITIVE: 'purple' } as Record<string, string>)[c] ?? 'gray'; }
  classHelp(c: string) { return ({ DIRECT: 'Identifies a person on its own', IDENTIFIER: 'A business id that points at one person; pseudonymised, not simply removed', QUASI: 'Identifies a person only in combination with other fields', SENSITIVE: 'Special-category data (for example health)' } as Record<string, string>)[c] ?? ''; }
  openClf() { this.clf = this.blankClf(); this.clfError.set(''); this.clfOpen.set(true); }
  saveClf() {
    this.api.createClassifier({ ...this.clf, name_pattern: this.clf.name_pattern || null, min_match_ratio: this.clf.method === 'KEYWORD' ? +this.clf.min_match_ratio : null }).subscribe({
      next: () => { this.clfOpen.set(false); this.toasts.ok('Classifier added. Run a scan to apply it.'); this.loadClassifiers(); },
      error: (e) => this.clfError.set(errorMessage(e)),
    });
  }
}
