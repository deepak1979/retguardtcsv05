import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { pretty, tone } from '../core/format';
import { DocIndexStatus, DocSource, SearchResult, VectorSearchSettings } from '../core/models';
import { Toasts } from '../core/toast';

@Component({
  selector: 'app-search',
  imports: [FormsModule],
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1>Semantic search</h1>
          <p>Search document text by meaning, not just keywords - built on redaction&rsquo;s output. Everyone searches the
             redacted text; only an admin&rsquo;s search also reaches the original, unredacted text.</p>
        </div>
        <div class="row" style="gap:10px;flex:none">
          @if (sources().length > 1) {
            <select [ngModel]="sourceId()" (ngModelChange)="pickSource($event)">
              @for (s of sources(); track s.doc_source_id) { <option [ngValue]="s.doc_source_id">{{ s.name }}</option> }
            </select>
          }
        </div>
      </div>

      @if (vs(); as v) {
        <section class="card card-pad llm-box-wrap">
          <div class="llm-box">
            <label class="switch" [title]="vsTitle(v)">
              <input type="checkbox" role="switch" aria-label="Semantic search" [checked]="v.enabled"
                     [disabled]="!auth.isAdmin() || vsBusy()" (change)="toggleVs($any($event.target).checked)" />
              <span class="track"><i></i></span>
            </label>
            <div class="llm-text">
              <b>Semantic search</b>
              <span class="muted small">{{ vsLine(v) }}</span>
            </div>
            @if (auth.isAdmin()) { <button class="btn btn-sm" (click)="openVs(v)">Configure</button> }
          </div>
        </section>
      }

      @if (!sources().length) {
        <section class="card card-pad"><div class="empty">No document sources registered yet - add one on the Documents page first.</div></section>
      } @else {

      <div class="section-title" style="margin-top:0"><h2>Search</h2></div>
      <section class="card card-pad">
        <div class="row" style="gap:10px;flex-wrap:nowrap">
          <input type="text" style="flex:1" placeholder="e.g. water damage claim, policy cancellation, customer complaint about delay"
                 [ngModel]="queryText()" (ngModelChange)="queryText.set($event)" (keydown.enter)="runSearch()" />
          <button class="btn btn-primary" (click)="runSearch()" [disabled]="!vs()?.enabled || searching() || !queryText().trim()">
            {{ searching() ? 'Searching…' : '🔍 Search' }}
          </button>
        </div>
        @if (!auth.isAdmin()) {
          <p class="muted small" style="margin-top:8px">Results come from the redacted text only. Sign in as an admin to also search the original, unredacted text.</p>
        }
        @if (searchError(); as e) { <div class="note bad" style="margin-top:10px"><span class="small">{{ e }}</span></div> }

        @if (results().length) {
          <div class="tbl-wrap" style="margin-top:14px">
            <table class="tbl">
              <thead><tr><th>Document</th><th>Match</th><th>Relevance</th><th>Index</th></tr></thead>
              <tbody>
                @for (r of results(); track r.document_id + '-' + r.chunk_index + '-' + r.source) {
                  <tr>
                    <td class="mono">{{ r.file_name }}</td>
                    <td class="small">{{ r.snippet }}</td>
                    <td>{{ pct(r.score) }}</td>
                    <td><span class="badge" [class]="r.source === 'pii' ? 'badge s-red' : 'badge s-green'">{{ r.source === 'pii' ? 'Unredacted (admin)' : 'Redacted' }}</span></td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else if (searched()) {
          <div class="empty" style="margin-top:14px">No matches.</div>
        }
      </section>

      <div class="section-title">
        <div><h2>Index status</h2><span class="muted small">Semantic search is built from each document&rsquo;s latest redaction &mdash; run redaction first, then index it here.</span></div>
      </div>
      <section class="card">
        @if (indexRows().length === 0) {
          <div class="empty">No documents with findings yet. Scan this source on the Documents page first.</div>
        } @else {
          <div class="tbl-wrap">
            <table class="tbl">
              <thead><tr><th>Document</th><th>Status</th><th>Chunks (safe / PII)</th><th>Indexed</th><th></th></tr></thead>
              <tbody>
                @for (d of indexRows(); track d.document_id) {
                  <tr>
                    <td class="mono">{{ d.file_name }}</td>
                    <td><span class="badge" [class]="'badge s-' + stateTone(d.state)">{{ pretty(d.state) }}</span></td>
                    <td>{{ d.safe_chunk_count ?? '—' }} / {{ d.pii_chunk_count ?? '—' }}</td>
                    <td class="muted mono">{{ ts(d.indexed_at) }}</td>
                    <td>
                      @if (auth.canEdit() && d.state !== 'NOT_REDACTED') {
                        <button class="btn btn-sm" (click)="indexOne(d)" [disabled]="indexingId() === d.document_id">
                          {{ indexingId() === d.document_id ? 'Indexing…' : (d.state === 'STALE' ? 'Re-index' : (d.state === 'INDEXED' ? 'Re-index' : 'Index')) }}
                        </button>
                      }
                      @if (d.state === 'NOT_REDACTED') { <span class="muted small">Run redaction first</span> }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </section>
      }
    </main>

    @if (vsDialog()) {
      <div class="backdrop" (click)="vsDialog.set(false)">
        <div class="modal" role="dialog" aria-modal="true" (click)="$event.stopPropagation()">
          <div class="modal-head"><h2>Semantic search</h2><button class="btn btn-sm" (click)="vsDialog.set(false)" aria-label="Close">✕</button></div>
          <div class="modal-body">
            @if (vsError(); as e) { <div class="alert alert-error">{{ e }}</div> }
            @if (vsReply(); as r) { <div class="note good">✓ {{ r }}</div> }
            <div class="note">Embeddings are computed locally via Ollama and stored in a local Chroma server - nothing here is sent
              to a cloud service. The redacted index is searchable by everyone; the unredacted index only ever answers an admin&rsquo;s query.</div>
            <div class="grid-2">
              <div class="field"><label for="vem">Embedding model (Ollama)</label><input id="vem" type="text" class="mono" [(ngModel)]="vf.embed_model" /></div>
              <div class="field"><label for="vto">Timeout (seconds)</label><input id="vto" type="number" min="5" max="300" [(ngModel)]="vf.timeout" /></div>
            </div>
            <div class="field"><label for="vou">Ollama address</label><input id="vou" type="text" class="mono" [(ngModel)]="vf.ollama_base_url" />
              <span class="hint">Must be on this machine. Run <span class="mono">ollama pull {{ vf.embed_model }}</span> if it is not installed.</span>
            </div>
            <div class="field"><label for="vcu">Chroma address</label><input id="vcu" type="text" class="mono" [(ngModel)]="vf.chroma_url" />
              <span class="hint">Must be on this machine. Start it with <span class="mono">chroma run --path ./chroma_data --port 8020</span>.</span>
            </div>
          </div>
          <div class="modal-foot">
            <button class="btn" (click)="vsDialog.set(false)">Close</button>
            <button class="btn" (click)="saveVs(true)" [disabled]="vsBusy() || !vs()?.enabled" title="Save, then embed a test phrase">Save and test</button>
            <button class="btn btn-primary" (click)="saveVs(false)" [disabled]="vsBusy()">Save</button>
          </div>
        </div>
      </div>
    }
  `,
  styles: `
    .small { font-size: 12.5px; }
    .llm-box-wrap { padding: 10px 14px; margin-bottom: 14px; }
    .llm-box { display: flex; align-items: center; gap: 12px; }
    .llm-text { display: flex; flex-direction: column; line-height: 1.3; max-width: 520px; }
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
export class Search {
  private api = inject(Api);
  private toasts = inject(Toasts);
  auth = inject(Auth);
  pretty = pretty; tone = tone;
  pct(v: number) { return Math.round(v * 100) + '%'; }
  ts(v: string | null) { return v ? v.slice(0, 19).replace('T', ' ') : '—'; }

  sources = signal<DocSource[]>([]);
  sourceId = signal<number | null>(null);
  indexRows = signal<DocIndexStatus[]>([]);
  indexingId = signal<number | null>(null);

  queryText = signal('');
  results = signal<SearchResult[]>([]);
  searching = signal(false);
  searched = signal(false);
  searchError = signal('');

  vs = signal<VectorSearchSettings | null>(null);
  vsBusy = signal(false);
  vsDialog = signal(false);
  vsError = signal('');
  vsReply = signal('');
  vf: { embed_model: string; chroma_url: string; ollama_base_url: string; timeout: number } =
    { embed_model: '', chroma_url: '', ollama_base_url: '', timeout: 60 };

  stateTone(state: string): string {
    return state === 'INDEXED' ? 'green' : state === 'STALE' ? 'orange' : state === 'FAILED' ? 'red' : 'gray';
  }

  constructor() {
    this.loadSources();
    this.loadVs();
  }

  loadSources() {
    this.api.docSources().subscribe((s) => {
      this.sources.set(s);
      if (s.length && !this.sourceId()) this.pickSource(s[0].doc_source_id);
    });
  }

  pickSource(id: number) {
    this.sourceId.set(id);
    this.results.set([]);
    this.searched.set(false);
    this.loadIndexStatus();
  }

  loadIndexStatus() {
    const sid = this.sourceId();
    if (!sid) return;
    this.api.vsIndexStatus(sid).subscribe((d) => this.indexRows.set(d));
  }

  loadVs() {
    this.api.vsSettings().subscribe({ next: (s) => this.vs.set(s), error: () => this.vs.set(null) });
  }

  vsLine(v: VectorSearchSettings): string {
    return v.enabled ? `On — ${v.embed_model} via Ollama, local Chroma at ${v.chroma_url}` : 'Off — no document text is embedded or searched.';
  }
  vsTitle(v: VectorSearchSettings): string {
    if (!this.auth.isAdmin()) return 'Only an admin can change this';
    return 'Switch semantic search on or off';
  }

  toggleVs(on: boolean) {
    this.vsBusy.set(true);
    this.api.saveVsSettings({ enabled: on }).subscribe({
      next: (s) => { this.vsBusy.set(false); this.vs.set(s); this.toasts.ok(s.enabled ? 'Semantic search is on' : 'Semantic search is off. Nothing is embedded or searched.'); },
      error: (e) => { this.vsBusy.set(false); this.toasts.error(errorMessage(e)); this.loadVs(); },
    });
  }

  openVs(v: VectorSearchSettings) {
    this.vf = { embed_model: v.embed_model, chroma_url: v.chroma_url, ollama_base_url: v.ollama_base_url, timeout: v.timeout };
    this.vsError.set(''); this.vsReply.set('');
    this.vsDialog.set(true);
  }

  saveVs(thenTest: boolean) {
    this.vsBusy.set(true); this.vsError.set(''); this.vsReply.set('');
    this.api.saveVsSettings(this.vf).subscribe({
      next: (s) => {
        this.vs.set(s);
        if (!thenTest) { this.vsBusy.set(false); this.toasts.ok('Settings saved'); return; }
        this.api.vsTest().subscribe({
          next: (t) => { this.vsBusy.set(false); this.vsReply.set(`${t.embed_model} answered with a ${t.dimensions}-dimension vector; Chroma reachable at ${t.chroma_url}`); },
          error: (e) => { this.vsBusy.set(false); this.vsError.set(errorMessage(e)); },
        });
      },
      error: (e) => { this.vsBusy.set(false); this.vsError.set(errorMessage(e)); },
    });
  }

  indexOne(d: DocIndexStatus) {
    this.indexingId.set(d.document_id);
    this.api.vsIndexDocument(d.document_id).subscribe({
      next: (r) => { this.indexingId.set(null); this.toasts.ok(`Indexed: ${r.safe_chunks} safe chunk(s), ${r.pii_chunks} PII chunk(s)`); this.loadIndexStatus(); },
      error: (e) => { this.indexingId.set(null); this.toasts.error(errorMessage(e)); this.loadIndexStatus(); },
    });
  }

  runSearch() {
    const q = this.queryText().trim();
    if (!q) return;
    this.searching.set(true);
    this.searchError.set('');
    this.api.vsSearch(q, this.sourceId() ?? undefined).subscribe({
      next: (r) => { this.searching.set(false); this.searched.set(true); this.results.set(r); },
      error: (e) => { this.searching.set(false); this.searched.set(true); this.results.set([]); this.searchError.set(errorMessage(e)); },
    });
  }
}
