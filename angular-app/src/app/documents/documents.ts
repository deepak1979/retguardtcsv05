import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { Confirms } from '../core/confirm';
import { DomainScope } from '../core/domain';
import { pretty, tone, pct } from '../core/format';
import { DocFinding, DocNameLlmSettings, DocScan, DocSource } from '../core/models';
import { Toasts } from '../core/toast';

@Component({
  selector: 'app-documents',
  imports: [FormsModule],
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1>Document sources</h1>
          <p>Point RetentionGuard at a folder of PDFs - discover what's there, scan it for PII in the
             metadata and the body text, and review findings, same lifecycle as a database source.</p>
        </div>
        <div class="row" style="gap:10px;flex:none">
          <div class="domain-toggle" role="group" aria-label="Domain">
            <button type="button" class="domain-opt" [class.on]="domain() === 'INSURANCE'" (click)="setDomain('INSURANCE')">Insurance</button>
            <button type="button" class="domain-opt" [class.on]="domain() === 'BANKING'" (click)="setDomain('BANKING')">Banking</button>
          </div>
          @if (auth.isAdmin()) {
            <button class="btn btn-primary" (click)="openAddSource()">+ Add a folder</button>
          }
        </div>
      </div>

      @if (nameLlm(); as nl) {
        <section class="card card-pad llm-box-wrap">
          <div class="llm-box">
            <label class="switch" [title]="nameLlmTitle(nl)">
              <input type="checkbox" role="switch" aria-label="LLM-assisted name detection" [checked]="nl.enabled"
                     [disabled]="!auth.isAdmin() || nameLlmBusy() || !nl.master_llm_enabled"
                     (change)="toggleNameLlm($any($event.target).checked)" />
              <span class="track"><i></i></span>
            </label>
            <div class="llm-text">
              <b>LLM-assisted name detection</b>
              <span class="muted small">{{ nameLlmLine(nl) }}</span>
            </div>
            @if (auth.isAdmin()) { <button class="btn btn-sm" (click)="openNameLlm(nl)">Configure</button> }
          </div>
        </section>
      }

      @if (sources().length === 0) {
        <section class="card card-pad">
          <div class="empty">No document sources yet. Add a folder to get started.</div>
        </section>
      }

      @for (s of sources(); track s.doc_source_id) {
        <section class="card card-pad">
          <div class="row" style="gap:14px">
            <span class="db">📄</span>
            <div>
              <h2>{{ s.name }}</h2>
              <span class="muted mono">{{ s.folder_path }}</span>
            </div>
            <span class="badge" [class]="'badge s-' + tone(s.status)">{{ pretty(s.status) }}</span>
            @if (s.domain) { <span class="badge s-teal">{{ s.domain }}</span> }
            <div class="row right">
              @if (auth.canEdit()) {
                <button class="btn" (click)="discover(s)" [disabled]="busy()">{{ busy() === 'discover-' + s.doc_source_id ? 'Discovering…' : 'Discover folder' }}</button>
                <button class="btn btn-primary" (click)="scan(s)" [disabled]="!s.documents || scanning()">▶ Run scan</button>
              }
              @if (auth.isAdmin()) {
                <button class="btn btn-danger" (click)="deleteSource(s)" [disabled]="busy()">{{ busy() === 'delete-' + s.doc_source_id ? 'Deleting…' : 'Delete' }}</button>
              }
            </div>
          </div>
          <div class="kv" style="margin-top:16px">
            <div><span class="muted">PDFs found</span><b>{{ s.documents }}</b></div>
            <div><span class="muted">Open findings</span><b>{{ s.findings }}</b></div>
            <div><span class="muted">Last discovered</span><b>{{ ts(s.last_discovered_at) }}</b></div>
            <div><span class="muted">Last scan</span><b>{{ ts(s.last_scan_at) }}</b></div>
          </div>
        </section>
      }

      <div class="section-title"><h2>Scan history</h2></div>
      <section class="card">
        @if (scans().length === 0) {
          <div class="empty">No document scans yet. Discover a folder, then run a scan.</div>
        } @else {
          <div class="tbl-wrap">
            <table class="tbl">
              <thead><tr><th>#</th><th>Status</th><th>Progress</th><th>Findings</th><th>By</th><th>Started</th></tr></thead>
              <tbody>
                @for (j of scans(); track j.doc_scan_id) {
                  <tr>
                    <td>{{ j.doc_scan_id }}</td>
                    <td><span class="badge" [class]="'badge s-' + tone(j.status)">{{ pretty(j.status) }}</span></td>
                    <td style="min-width:150px">
                      <div class="row" style="flex-wrap:nowrap"><div class="meter" style="flex:1"><i [style.width.%]="j.documents_total ? j.documents_done / j.documents_total * 100 : 0"></i></div>
                      <span class="muted small">{{ j.documents_done }}/{{ j.documents_total }}</span></div>
                    </td>
                    <td>{{ j.findings_total }} <span class="muted small">(+{{ j.findings_new }} new{{ j.findings_resolved ? ', ' + j.findings_resolved + ' resolved' : '' }})</span></td>
                    <td>{{ j.requested_by }}</td>
                    <td class="muted mono">{{ ts(j.started_at ?? j.created_at) }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </section>

      <div class="section-title">
        <div><h2>Findings</h2><span class="muted small">PII found in a document's metadata (author, title, …) or swept from its body text.</span></div>
        <select [ngModel]="statusFilter()" (ngModelChange)="statusFilter.set($event); loadFindings()">
          <option value="">Needs attention</option>
          <option value="AUTO">Auto-classified</option>
          <option value="NEEDS_REVIEW">Needs review</option>
          <option value="CONFIRMED">Confirmed</option>
          <option value="REJECTED">Rejected</option>
        </select>
      </div>
      <section class="card">
        @if (findings().length === 0) {
          <div class="empty">No findings match this filter.</div>
        } @else {
          <div class="tbl-wrap">
            <table class="tbl">
              <thead><tr><th>Document</th><th>Where</th><th>Element</th><th>Category</th><th>Matches</th><th>Sample(s)</th><th>Status</th><th></th></tr></thead>
              <tbody>
                @for (f of findings(); track f.doc_finding_id) {
                  <tr>
                    <td class="mono" [title]="f.file_path">{{ f.file_name }}</td>
                    <td>{{ f.source === 'CONTENT' ? 'Body text' : f.field_name }}</td>
                    <td>
                      {{ pretty(f.data_element) }}
                      <div><span class="badge s-blue">{{ pretty(f.category) }}</span>
                      @if (f.pii_class && f.pii_class !== 'DIRECT') { <span class="badge s-gray">{{ f.pii_class.toLowerCase() }}</span> }</div>
                    </td>
                    <td>{{ pct(f.confidence) }}</td>
                    <td>{{ f.match_count || '—' }}</td>
                    <td class="mono small samples">{{ f.samples ?? '—' }}</td>
                    <td>
                      <span class="badge" [class]="'badge s-' + tone(f.status)">{{ pretty(f.status) }}</span>
                      @if (f.decided_by) { <div class="muted small">by {{ f.decided_by }}</div> }
                    </td>
                    <td>
                      @if (auth.canEdit()) {
                        <div class="row" style="flex-wrap:nowrap;gap:6px">
                          @if (f.status !== 'CONFIRMED') { <button class="btn btn-sm" (click)="decide(f, 'CONFIRMED')">Confirm</button> }
                          @if (f.status !== 'REJECTED') { <button class="btn btn-sm btn-danger" (click)="decide(f, 'REJECTED')">Reject</button> }
                        </div>
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </section>
    </main>

    @if (addSourceOpen()) {
      <div class="backdrop" (click)="closeAddSource()">
        <div class="modal" role="dialog" aria-modal="true" (click)="$event.stopPropagation()">
          <div class="modal-head"><h2>Add a document folder</h2><button class="btn btn-sm" (click)="closeAddSource()" aria-label="Close">✕</button></div>
          <div class="modal-body">
            <div class="note">Tagged as <b>{{ domain() === 'BANKING' ? 'Banking' : 'Insurance' }}</b> - whichever domain is selected above. Switch it before adding if that's not right.</div>
            <div class="field">
              <label for="dn">Display name</label>
              <input id="dn" type="text" [ngModel]="newName()" (ngModelChange)="newName.set($event)" placeholder="e.g. Claims correspondence archive" />
            </div>
            <div class="field">
              <label for="dp">Folder path</label>
              <input id="dp" type="text" [ngModel]="newPath()" (ngModelChange)="newPath.set($event)" placeholder="C:\\path\\to\\folder" />
              <span class="hint">A path reachable from the machine running this backend. Every .pdf found under it (including subfolders) becomes a document.</span>
            </div>
            @if (addError(); as e) { <div class="note bad"><span class="small">{{ e }}</span></div> }
          </div>
          <div class="modal-foot">
            <button class="btn" (click)="closeAddSource()">Cancel</button>
            <button class="btn btn-primary" (click)="saveSource()" [disabled]="!newName().trim() || !newPath().trim() || saving()">{{ saving() ? 'Saving…' : 'Save' }}</button>
          </div>
        </div>
      </div>
    }

    @if (nameLlmDialog()) {
      <div class="backdrop" (click)="nameLlmDialog.set(false)">
        <div class="modal" role="dialog" aria-modal="true" (click)="$event.stopPropagation()">
          <div class="modal-head"><h2>LLM-assisted name detection</h2><button class="btn btn-sm" (click)="nameLlmDialog.set(false)" aria-label="Close">✕</button></div>
          <div class="modal-body">
            @if (nameLlmError()) { <div class="alert alert-error">{{ nameLlmError() }}</div> }
            @if (nameLlmReply()) { <div class="note good">✓ {{ nameLlmReply() }}</div> }
            <div class="note">The FULL_NAME dictionary pairing (a known first name next to a known surname) still runs either way.
              When this is on, a local model also reads each document's text for names it recognises from context -
              so e.g. "Anna Kowalski" is found even though "Kowalski" isn't in the surname dictionary. Always local:
              document text is never sent anywhere else for this feature. Needs "LLM second opinion" (Findings page) switched on too.</div>
            @if (!nameLlm()?.master_llm_enabled) {
              <div class="note bad">Switch on "LLM second opinion" in Findings first - that's the app-wide guarantee that nothing is sent anywhere.</div>
            }
            <div class="grid-2">
              <div class="field"><label for="nlm">Model</label><input id="nlm" type="text" class="mono" [(ngModel)]="nlf.model" /></div>
              <div class="field"><label for="nlt">Timeout (seconds)</label><input id="nlt" type="number" min="5" max="600" [(ngModel)]="nlf.timeout" /></div>
            </div>
            <div class="field"><label for="nlu">Address</label><input id="nlu" type="text" class="mono" [(ngModel)]="nlf.base_url" />
              <span class="hint">Must be on this machine. Install Ollama, then run <span class="mono">ollama pull {{ nlf.model }}</span>.</span>
            </div>
          </div>
          <div class="modal-foot">
            <button class="btn" (click)="nameLlmDialog.set(false)">Close</button>
            <button class="btn" (click)="saveNameLlm(true)" [disabled]="nameLlmBusy() || !nameLlm()?.master_llm_enabled" title="Save, then send a test message that contains no data">Save and test</button>
            <button class="btn btn-primary" (click)="saveNameLlm(false)" [disabled]="nameLlmBusy()">Save</button>
          </div>
        </div>
      </div>
    }
  `,
  styles: `
    .db { font-size: 26px; }
    .small { font-size: 12.5px; }
    .domain-toggle { display: flex; flex: none; border: 1px solid var(--border); border-radius: 999px; padding: 3px; background: #fff; }
    .domain-opt { border: none; background: none; font: inherit; font-weight: 600; font-size: 13px; padding: 7px 16px; border-radius: 999px; cursor: pointer; color: var(--muted); }
    .domain-opt.on { background: var(--primary); color: #fff; }
    .samples { max-width: 200px; word-break: break-all; }
    .llm-box-wrap { padding: 10px 14px; margin-bottom: 14px; }
    .llm-box { display: flex; align-items: center; gap: 12px; }
    .llm-text { display: flex; flex-direction: column; line-height: 1.3; max-width: 420px; }
    .switch { position: relative; display: inline-block; width: 42px; height: 24px; flex: none; }
    .switch input { position: absolute; inset: 0; width: 100%; height: 100%; margin: 0; opacity: 0; cursor: pointer; z-index: 1; }
    .switch input:disabled { cursor: not-allowed; }
    .switch .track { position: absolute; inset: 0; background: #cbd5e1; border-radius: 999px; transition: background 0.15s; }
    .switch .track i { position: absolute; top: 3px; left: 3px; width: 18px; height: 18px; background: #fff; border-radius: 50%; box-shadow: 0 1px 2px rgba(0, 0, 0, 0.3); transition: transform 0.15s; }
    .switch input:checked + .track { background: var(--primary); }
    .switch input:checked + .track i { transform: translateX(18px); }
    .switch input:focus-visible + .track { outline: 2px solid var(--primary); outline-offset: 2px; }
  `,
})
export class Documents {
  private api = inject(Api);
  private toasts = inject(Toasts);
  private confirm = inject(Confirms);
  private ds = inject(DomainScope);
  auth = inject(Auth);
  pretty = pretty; tone = tone; pct = pct;

  // Which business domain this demo is set up for - shared app-wide (core/domain.ts), same toggle the
  // Data sources page uses. Only document sources tagged for the selected domain are shown; one with no
  // domain set (pre-toggle legacy, or a one-off folder) stays visible under either domain.
  domain = this.ds.domain;
  allSources = signal<DocSource[]>([]);
  sources = computed(() => this.allSources().filter((s) => this.ds.matches(s.domain)));
  scans = signal<DocScan[]>([]);
  findings = signal<DocFinding[]>([]);
  statusFilter = signal('');
  busy = signal('');
  scanning = computed(() => this.scans().some((s) => s.status === 'RUNNING' || s.status === 'QUEUED'));

  addSourceOpen = signal(false);
  newName = signal('');
  newPath = signal('');
  addError = signal<string | null>(null);
  saving = signal(false);

  // LLM-assisted name detection (rg/name_llm.py) - off by default, local model only
  nameLlm = signal<DocNameLlmSettings | null>(null);
  nameLlmBusy = signal(false);
  nameLlmDialog = signal(false);
  nameLlmError = signal('');
  nameLlmReply = signal('');
  nlf: { model: string; base_url: string; timeout: number } = { model: '', base_url: '', timeout: 120 };

  private wasScanning = false;

  constructor() {
    this.loadAll();
    this.loadNameLlm();
    const timer = setInterval(() => {
      if (this.scanning() || this.wasScanning) this.loadScans();
    }, 1500);
    inject(DestroyRef).onDestroy(() => clearInterval(timer));
  }

  loadNameLlm() {
    this.api.docNameLlmSettings().subscribe({ next: (s) => this.nameLlm.set(s), error: () => this.nameLlm.set(null) });
  }

  nameLlmLine(nl: DocNameLlmSettings): string {
    if (!nl.master_llm_enabled) return 'Needs "LLM second opinion" (Findings page) switched on first.';
    return nl.enabled ? `On - ${nl.model}, catches names the dictionary misses` : 'Off - the name dictionary pairing alone finds names.';
  }

  nameLlmTitle(nl: DocNameLlmSettings): string {
    if (!this.auth.isAdmin()) return 'Only an admin can change this';
    if (!nl.master_llm_enabled) return 'Switch on "LLM second opinion" in Findings first';
    return 'Switch LLM-assisted name detection on or off';
  }

  toggleNameLlm(on: boolean) {
    const nl = this.nameLlm();
    if (!nl || !nl.master_llm_enabled) { this.loadNameLlm(); return; }
    this.nameLlmBusy.set(true);
    this.api.saveDocNameLlmSettings({ enabled: on }).subscribe({
      next: (s) => {
        this.nameLlmBusy.set(false); this.nameLlm.set(s);
        this.toasts.ok(s.enabled ? 'LLM-assisted name detection is on' : 'LLM-assisted name detection is off');
      },
      error: (e) => { this.nameLlmBusy.set(false); this.toasts.error(errorMessage(e)); this.loadNameLlm(); },
    });
  }

  openNameLlm(nl: DocNameLlmSettings) {
    this.nlf = { model: nl.model, base_url: nl.base_url, timeout: nl.timeout };
    this.nameLlmError.set(''); this.nameLlmReply.set('');
    this.nameLlmDialog.set(true);
  }

  saveNameLlm(thenTest: boolean) {
    this.nameLlmBusy.set(true); this.nameLlmError.set(''); this.nameLlmReply.set('');
    this.api.saveDocNameLlmSettings({ model: this.nlf.model, base_url: this.nlf.base_url, timeout: +this.nlf.timeout }).subscribe({
      next: (s) => {
        this.nameLlm.set(s);
        if (!thenTest) { this.nameLlmBusy.set(false); this.toasts.ok('Settings saved'); return; }
        this.api.docNameLlmTest().subscribe({
          next: (t) => { this.nameLlmBusy.set(false); this.nameLlmReply.set(`The model answered: "${t.reply}" (${t.model})`); },
          error: (e) => { this.nameLlmBusy.set(false); this.nameLlmError.set(errorMessage(e)); },
        });
      },
      error: (e) => { this.nameLlmBusy.set(false); this.nameLlmError.set(errorMessage(e)); },
    });
  }

  ts(v: string | null) { return v ? v.slice(0, 19).replace('T', ' ') : '—'; }

  loadAll() {
    this.api.docSources().subscribe((s) => this.allSources.set(s));
    this.loadScans();
    this.loadFindings();
  }

  setDomain(d: 'INSURANCE' | 'BANKING') {
    if (this.domain() === d) return;
    this.ds.set(d);
    this.toasts.ok(`Switched to ${d === 'BANKING' ? 'Banking' : 'Insurance'}. Document sources now show only this domain's folders; Findings below stays unfiltered.`);
  }

  loadScans() {
    this.api.docScans().subscribe((s) => {
      const nowScanning = s.some((x) => x.status === 'RUNNING' || x.status === 'QUEUED');
      if (this.wasScanning && !nowScanning) {
        this.api.docSources().subscribe((x) => this.allSources.set(x));
        this.loadFindings();
        this.toasts.ok('Document scan finished');
      }
      this.wasScanning = nowScanning;
      this.scans.set(s);
    });
  }

  loadFindings() {
    const status = this.statusFilter();
    this.api.docFindings(status ? { status } : {}).subscribe((f) => this.findings.set(f));
  }

  discover(s: DocSource) {
    this.busy.set('discover-' + s.doc_source_id);
    this.api.discoverDocSource(s.doc_source_id).subscribe({
      next: (r) => { this.busy.set(''); this.toasts.ok(`Found ${r.documents} PDF(s)`); this.loadAll(); },
      error: (e) => { this.busy.set(''); this.toasts.error(errorMessage(e)); },
    });
  }

  scan(s: DocSource) {
    this.api.scanDocSource(s.doc_source_id).subscribe({
      next: () => { this.wasScanning = true; this.loadScans(); this.toasts.ok('Scan started'); },
      error: (e) => this.toasts.error(errorMessage(e)),
    });
  }

  async deleteSource(s: DocSource) {
    if (!await this.confirm.ask(`Permanently delete "${s.name}"? This removes its documents and findings too. This cannot be undone.`)) return;
    this.busy.set('delete-' + s.doc_source_id);
    this.api.deleteDocSource(s.doc_source_id).subscribe({
      next: () => { this.busy.set(''); this.toasts.ok(`${s.name} deleted.`); this.loadAll(); },
      error: (e) => { this.busy.set(''); this.toasts.error(errorMessage(e)); },
    });
  }

  decide(f: DocFinding, status: string) {
    this.api.decideDocFinding(f.doc_finding_id, status).subscribe({
      next: () => { this.toasts.ok(`Marked ${status.toLowerCase()}`); this.loadFindings(); },
      error: (e) => this.toasts.error(errorMessage(e)),
    });
  }

  openAddSource() {
    this.newName.set(''); this.newPath.set(''); this.addError.set(null);
    this.addSourceOpen.set(true);
  }
  closeAddSource() { this.addSourceOpen.set(false); }

  saveSource() {
    this.saving.set(true);
    this.addError.set(null);
    this.api.createDocSource(this.newName().trim(), this.newPath().trim(), this.ds.label()).subscribe({
      next: () => { this.saving.set(false); this.addSourceOpen.set(false); this.toasts.ok('Folder added.'); this.loadAll(); },
      error: (e) => { this.saving.set(false); this.addError.set(errorMessage(e)); },
    });
  }
}
