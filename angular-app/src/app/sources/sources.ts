import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { Confirms } from '../core/confirm';
import { DomainScope } from '../core/domain';
import { pct, pretty, tone } from '../core/format';
import { Catalog, CatalogTable, ConnectionTestResult, ConnectorType, Scan, Snapshot, Source } from '../core/models';
import { Toasts } from '../core/toast';

const MODES = [
  { code: 'METADATA', label: 'Metadata', help: 'Column names only. No data is read. Fast, but every result needs review.' },
  { code: 'SAMPLE', label: 'Sample', help: 'A random sample of rows per table. Good balance of speed and evidence.' },
  { code: 'FULL', label: 'Full', help: 'Every row. Most accurate; slower on large tables.' },
];

@Component({
  selector: 'app-sources',
  imports: [FormsModule],
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1>Data sources</h1>
          <p>Connect, discover what exists, and scan it. Databricks is the only connector available in this build.</p>
        </div>
        <div class="row" style="gap:10px;flex:none">
          <div class="domain-toggle" role="group" aria-label="Domain">
            <button type="button" class="domain-opt" [class.on]="domain() === 'INSURANCE'" (click)="setDomain('INSURANCE')">Insurance</button>
            <button type="button" class="domain-opt" [class.on]="domain() === 'BANKING'" (click)="setDomain('BANKING')">Banking</button>
          </div>
          @if (auth.isAdmin()) {
            <button class="btn btn-primary" (click)="openAddSource()">+ Add a data source</button>
          }
        </div>
      </div>

      @for (s of sources(); track s.source_id) {
        <section class="card card-pad">
          <div class="row" style="gap:14px">
            <span class="db">🛢</span>
            <div>
              <h2>{{ s.name }}</h2>
              <span class="muted mono">{{ s.host }}:{{ s.port }}/{{ s.service_name }} · schema {{ s.schema_name }}</span>
            </div>
            <span class="badge" [class]="'badge s-' + tone(s.status)">{{ pretty(s.status) }}</span>
            @if (s.domain) { <span class="badge s-teal">{{ s.domain }}</span> }
            <div class="row right">
              @if (auth.canEdit()) {
                <button class="btn" (click)="discover(s)" [disabled]="busy()">{{ busy() === 'discover' ? 'Discovering…' : 'Discover catalog' }}</button>
                <button class="btn btn-primary" (click)="openScan(s)" [disabled]="!s.tables || scanning()">▶ Run scan…</button>
              }
              @if (auth.isAdmin() && s.source_id !== 1) {
                <button class="btn btn-danger" (click)="deleteSource(s)" [disabled]="busy()">{{ busy() === 'delete' ? 'Deleting…' : 'Delete' }}</button>
              }
            </div>
          </div>
          <div class="kv" style="margin-top:16px">
            <div><span class="muted">Tables</span><b>{{ s.tables }}</b></div>
            <div><span class="muted">Columns</span><b>{{ s.columns }}</b></div>
            <div><span class="muted">Last discovered</span><b>{{ ts(s.last_discovered_at) }}</b></div>
            <div><span class="muted">Last scan</span><b>{{ ts(s.last_scan_at) }}</b></div>
          </div>
          @if (s.source_type === 'DATABRICKS') {
            <label class="check" style="margin:14px 0 0" title="When on, classifiers with a SQL/UDF equivalent (country ID formats, postal codes, GENDER-style enums...) run as a query on this source's own compute instead of pulling rows back - faster and more accurate under Sample mode, but costs warehouse credits. Switch off to use the plain local/Python classifiers only.">
              <input type="checkbox" [checked]="s.is_pushdown_enabled" [disabled]="!auth.isAdmin() || pushdownBusy() === s.source_id"
                     (change)="togglePushdown(s, $any($event.target).checked)" />
              Use classifier pushdown on this source
            </label>
          }
        </section>
      }

      <div class="section-title"><h2>Scan history</h2></div>
      <section class="card">
        @if (scans().length === 0) {
          <div class="empty">No scans yet. Discover the catalog, then run a scan.</div>
        } @else {
          <div class="tbl-wrap">
            <table class="tbl">
              <thead><tr><th>#</th><th>Mode</th><th>Status</th><th>Progress</th><th>Columns</th><th>Findings</th><th>By</th><th>Started</th></tr></thead>
              <tbody>
                @for (j of scans(); track j.scan_id) {
                  <tr>
                    <td>{{ j.scan_id }}</td>
                    <td>{{ pretty(j.scan_mode) }}{{ j.sample_size ? ' (' + j.sample_size + ' rows)' : '' }}</td>
                    <td><span class="badge" [class]="'badge s-' + tone(j.status)">{{ pretty(j.status) }}</span></td>
                    <td style="min-width:150px">
                      <div class="row" style="flex-wrap:nowrap"><div class="meter" style="flex:1"><i [style.width.%]="j.tables_total ? j.tables_done / j.tables_total * 100 : 0"></i></div>
                      <span class="muted small">{{ j.tables_done }}/{{ j.tables_total }}</span></div>
                    </td>
                    <td>{{ j.columns_scanned }}</td>
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
        <div><h2>Catalog</h2><span class="muted small">Click a table to see its columns, what the scanner classified, and how it links to other tables.</span></div>
        @if (sources().length > 1) {
          <select [ngModel]="catalogSourceId()" (ngModelChange)="pickCatalogSource($event)">
            @for (s of sources(); track s.source_id) { <option [ngValue]="s.source_id">{{ s.name }}</option> }
          </select>
        }
      </div>
      @if (catalog(); as c) {
        <div class="layout-split">
          <section class="card">
            @for (t of c.tables; track t.table_name) {
              <div class="list-item" [class.sel]="t.table_name === selected()" (click)="selected.set(t.table_name)">
                <div class="row" style="justify-content:space-between">
                  <b class="mono">{{ t.table_name }}</b>
                  @if (t.pii_columns) { <span class="badge s-orange">{{ t.pii_columns }} PII</span> }
                </div>
                <span class="muted small">{{ t.row_count }} rows · {{ t.column_count }} columns</span>
              </div>
            }
          </section>

          @if (table(); as t) {
            <section class="card">
              <div class="card-pad" style="padding-bottom:8px">
                <h2 class="mono">{{ t.table_name }}</h2>
                <div class="row" style="margin-top:8px">
                  @for (e of parents(); track e.parent_table + e.child_column) {
                    <span class="chip soft">↑ {{ e.parent_table }}.{{ e.parent_column }} <span class="badge" [class]="'badge s-' + (e.kind === 'FK' ? 'gray' : 'purple')">{{ e.kind === 'FK' ? 'FK' : 'inferred' }}</span></span>
                  }
                  @for (e of children(); track e.child_table + e.child_column) {
                    <span class="chip soft">↓ {{ e.child_table }}.{{ e.child_column }} <span class="badge" [class]="'badge s-' + (e.kind === 'FK' ? 'gray' : 'purple')">{{ e.kind === 'FK' ? 'FK' : 'inferred' }}</span></span>
                  }
                </div>
              </div>
              <div class="tbl-wrap">
                <table class="tbl">
                  <thead><tr><th>Column</th><th>Type</th><th>Null</th><th>Classification</th></tr></thead>
                  <tbody>
                    @for (col of t.columns; track col.column_name) {
                      <tr>
                        <td class="mono">{{ col.column_name }} @if (col.is_pk) { <span class="badge s-gray">PK</span> }</td>
                        <td class="muted mono">{{ col.data_type }}{{ col.data_type === 'VARCHAR2' || col.data_type === 'CHAR' ? '(' + col.data_length + ')' : '' }}</td>
                        <td class="muted">{{ col.null_ratio === null ? '—' : pct(col.null_ratio) }}</td>
                        <td>
                          @for (f of col.findings; track f.finding_id) {
                            <span class="badge" [class]="'badge s-' + tone(f.status)" [title]="f.status">{{ pretty(f.data_element) }} {{ pct(f.confidence) }}</span>
                            @if (f.protection !== 'NONE') { <span class="badge s-teal" title="A masking control covers this column">🛡 {{ pretty(f.protection) }}</span> }
                          } @empty { <span class="muted">—</span> }
                        </td>
                      </tr>
                    }
                  </tbody>
                </table>
              </div>
            </section>
          }
        </div>
      }

      @if (auth.isAdmin() && isDatabricksCatalogSource() && snap(); as sn) {
        <div class="section-title"><h2>Demo data safety</h2></div>
        <section class="card card-pad">
          <p class="top muted">
            Remediation changes real rows in <b>{{ catalogSchema() }}</b>. Before anything runs, every source table is copied to
            <span class="mono">RG_BKP_*</span>. Restore puts the data back exactly as it was and resets the lifecycle
            (tasks, violations, protections, erasure requests) so you can run the whole demo again.
          </p>
          <div class="row">
            <span class="badge" [class]="'badge s-' + (sn.modified_tables.length ? 'orange' : 'green')">
              {{ sn.modified_tables.length ? sn.modified_tables.length + ' table(s) differ from the snapshot' : 'Source data matches the snapshot' }}
            </span>
            @if (sn.masked_views.length) { <span class="muted small">Masked views: {{ sn.masked_views.join(', ') }}</span> }
            <div class="row right">
              <button class="btn" (click)="retake()" [disabled]="busy()">Re-take snapshot</button>
              <button class="btn btn-danger" (click)="restore()" [disabled]="busy()">{{ busy() === 'restore' ? 'Restoring…' : 'Restore demo data' }}</button>
            </div>
          </div>
          @if (sn.modified_tables.length) {
            <div class="tbl-wrap" style="margin-top:14px">
              <table class="tbl">
                <thead><tr><th>Table</th><th>Rows now</th><th>Snapshot rows</th><th></th></tr></thead>
                <tbody>
                  @for (t of sn.snapshots; track t.table_name) {
                    @if (t.differs) {
                      <tr>
                        <td class="mono">{{ t.table_name }}</td>
                        <td>{{ t.current_rows }}</td>
                        <td>{{ t.row_count }}</td>
                        <td>
                          <button class="btn btn-sm" (click)="restoreOne(t.table_name)" [disabled]="busy() !== '' || !!restoringTable()"
                                  title="Restore just this table from its snapshot. Its own violations and tasks reset too; everything else - other tables, legal holds, other tasks - is left alone.">
                            {{ restoringTable() === t.table_name ? 'Restoring…' : 'Restore just this table' }}
                          </button>
                        </td>
                      </tr>
                    }
                  }
                </tbody>
              </table>
            </div>
          }
        </section>
      }
    </main>

    @if (scanOpen()) {
      <div class="backdrop" (click)="scanOpen.set(false)">
        <div class="modal" role="dialog" aria-modal="true" (click)="$event.stopPropagation()">
          <div class="modal-head"><h2>Run a scan</h2><button class="btn btn-sm" (click)="scanOpen.set(false)" aria-label="Close">✕</button></div>
          <div class="modal-body">
            <div class="field">
              <span class="label">Scan type</span>
              @for (m of modes; track m.code) {
                <label class="mode" [class.on]="mode() === m.code">
                  <input type="radio" name="mode" [checked]="mode() === m.code" (change)="mode.set(m.code)" />
                  <span><b>{{ m.label }}</b><br /><span class="muted small">{{ m.help }}</span></span>
                </label>
              }
            </div>
            @if (mode() === 'SAMPLE') {
              <div class="field">
                <label for="ss">Rows sampled per table</label>
                <input id="ss" type="number" min="10" max="5000" [ngModel]="sampleSize()" (ngModelChange)="sampleSize.set($event)" />
              </div>
            }
            <div class="field">
              <span class="label">Tables <button class="btn btn-sm" style="margin-left:8px" (click)="toggleAll()">{{ picked().size === allTables().length ? 'Clear' : 'Select all' }}</button></span>
              <div class="tables">
                @for (t of allTables(); track t) {
                  <label class="check" style="margin:0"><input type="checkbox" [checked]="picked().has(t)" (change)="toggleTable(t)" /> <span class="mono small">{{ t }}</span></label>
                }
              </div>
            </div>
          </div>
          <div class="modal-foot">
            <button class="btn" (click)="scanOpen.set(false)">Cancel</button>
            <button class="btn btn-primary" (click)="startScan()" [disabled]="picked().size === 0">Start scan</button>
          </div>
        </div>
      </div>
    }

    @if (addSourceOpen()) {
      <div class="backdrop" (click)="closeAddSource()">
        <div class="modal" role="dialog" aria-modal="true" (click)="$event.stopPropagation()">
          <div class="modal-head"><h2>Add a data source</h2><button class="btn btn-sm" (click)="closeAddSource()" aria-label="Close">✕</button></div>
          <div class="modal-body">
            <div class="field">
              <label for="ct">Database type</label>
              <select id="ct" [ngModel]="newSourceType()" (ngModelChange)="pickConnectorType($event)">
                @for (t of connectorTypes(); track t.code) { <option [ngValue]="t.code">{{ t.label }}{{ t.live ? '' : ' (coming soon)' }}</option> }
              </select>
              @if (!selectedConnectorLive()) {
                <span class="hint">This connector isn't implemented yet - you can still save it to register the source, but testing, discovering and scanning won't work until it's built.</span>
              }
            </div>
            <div class="field">
              <label for="sn">Display name</label>
              <input id="sn" type="text" [ngModel]="newSourceName()" (ngModelChange)="newSourceName.set($event); testResult.set(null)" placeholder="e.g. Claims warehouse" />
            </div>
            <div class="grid-2">
              <div class="field"><label for="sh">{{ selectedConnectorHostLabel() }}</label><input id="sh" type="text" [ngModel]="newHost()" (ngModelChange)="newHost.set($event); testResult.set(null)" placeholder="localhost" /></div>
              <div class="field"><label for="sp">Port</label><input id="sp" type="number" [ngModel]="newPort()" (ngModelChange)="newPort.set($event); testResult.set(null)" /></div>
            </div>
            <div class="field">
              <label for="ssv">{{ selectedConnectorServiceLabel() }}</label>
              <input id="ssv" type="text" [ngModel]="newServiceName()" (ngModelChange)="newServiceName.set($event); testResult.set(null)" />
            </div>
            <div class="grid-2">
              <div class="field"><label for="su">{{ selectedConnectorUsernameLabel() }}</label><input id="su" type="text" [ngModel]="newUsername()" (ngModelChange)="newUsername.set($event); testResult.set(null)" /></div>
              <div class="field"><label for="sw">{{ selectedConnectorPasswordLabel() }}</label><input id="sw" type="password" [ngModel]="newPassword()" (ngModelChange)="newPassword.set($event); testResult.set(null)" /></div>
            </div>
            @if (testResult(); as r) {
              <div class="note" [class.good]="r.ok" [class.bad]="!r.ok">
                <b>{{ r.ok ? '✓ Connected' : '✕ Connection failed' }}</b><br />
                <span class="small">{{ r.message }}</span>
                @if (r.detail) { <div class="muted small mono" style="margin-top:4px">{{ r.detail }}</div> }
              </div>
            }
          </div>
          <div class="modal-foot">
            <button class="btn" (click)="closeAddSource()">Cancel</button>
            <button class="btn" (click)="testConnection()" [disabled]="!canTestSource() || testing()">{{ testing() ? 'Testing…' : 'Test connection' }}</button>
            <button class="btn btn-primary" (click)="saveSource()" [disabled]="!canTestSource() || saving()">{{ saving() ? 'Saving…' : 'Save' }}</button>
          </div>
        </div>
      </div>
    }
  `,
  styles: `
    .db { font-size: 26px; }
    .small { font-size: 12.5px; }
    .top { margin-top: 0; }
    .domain-toggle { display: flex; flex: none; border: 1px solid var(--border); border-radius: 999px; padding: 3px; background: #fff; }
    .domain-opt { border: none; background: none; font: inherit; font-weight: 600; font-size: 13px; padding: 7px 16px; border-radius: 999px; cursor: pointer; color: var(--muted); }
    .domain-opt.on { background: var(--primary); color: #fff; }
    .mode { display: flex; gap: 10px; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 8px; cursor: pointer; align-items: flex-start; }
    .mode.on { border-color: var(--primary); background: #f0fdfa; }
    .mode input { margin-top: 4px; accent-color: var(--primary); }
    .tables { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 12px; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; max-height: 190px; overflow: auto; }
  `,
})
export class Sources {
  private api = inject(Api);
  private toasts = inject(Toasts);
  private confirm = inject(Confirms);
  auth = inject(Auth);
  private ds = inject(DomainScope);
  pretty = pretty; tone = tone; pct = pct; modes = MODES;

  allSources = signal<Source[]>([]);
  scans = signal<Scan[]>([]);
  catalog = signal<Catalog | null>(null);
  snap = signal<Snapshot | null>(null);
  selected = signal<string>('');
  busy = signal<'' | 'discover' | 'restore' | 'retake' | 'delete'>('');
  pushdownBusy = signal<number | null>(null);   // source_id currently being toggled, or null
  restoringTable = signal<string | null>(null);
  catalogSourceId = signal(1);

  // Which business domain this demo is set up for - shared app-wide (core/domain.ts), not local to this
  // page, so Remediation/Findings/etc. can filter by the same selection.
  domain = this.ds.domain;

  // Only sources tagged for the selected domain are shown; a source with no domain set (pre-toggle legacy
  // rows, in practice none once ddl.py's migration backfill has run) stays visible either way rather than
  // silently vanishing.
  sources = computed(() => this.allSources().filter((s) => this.ds.matches(s.domain)));

  scanOpen = signal(false);
  scanSourceId = signal(1);
  scanDialogTables = signal<string[] | null>(null);  // set only when the scan dialog targets a source other than the browsed catalog

  // The "Demo data safety" panel (snapshot/restore/retake) operates on whichever source is currently
  // browsed in Catalog below, not a hardcoded default - every Databricks source now has its own real
  // connection and its own RG_BKP_* backups (rg/engines/registry.py), so "restore" has to say which one.
  catalogSource = computed(() => this.allSources().find((s) => s.source_id === this.catalogSourceId()));
  isDatabricksCatalogSource = computed(() => this.catalogSource()?.source_type === 'DATABRICKS');

  catalogSchema(): string {
    return this.catalogSource()?.schema_name ?? 'the Databricks schema';
  }
  mode = signal('FULL');
  sampleSize = signal(200);
  picked = signal<Set<string>>(new Set());

  // Add a data source: type picker + its fields, live test, then save. Databricks is the only connector
  // this app ships with (see backend rg/connectors.py).
  addSourceOpen = signal(false);
  connectorTypes = signal<ConnectorType[]>([]);
  newSourceType = signal('DATABRICKS');
  newSourceName = signal('');
  newHost = signal('localhost');
  newPort = signal<number | null>(443);
  newServiceName = signal('');
  newUsername = signal('');
  newPassword = signal('');
  testResult = signal<ConnectionTestResult | null>(null);
  testing = signal(false);
  saving = signal(false);

  selectedConnector = computed(() => this.connectorTypes().find((t) => t.code === this.newSourceType()));
  selectedConnectorLive = computed(() => this.selectedConnector()?.live ?? false);
  selectedConnectorServiceLabel = computed(() => this.selectedConnector()?.service_label ?? 'Database');
  selectedConnectorHostLabel = computed(() => this.selectedConnector()?.host_label ?? 'Host');
  selectedConnectorUsernameLabel = computed(() => this.selectedConnector()?.username_label ?? 'Username');
  selectedConnectorPasswordLabel = computed(() => this.selectedConnector()?.password_label ?? 'Password');
  canTestSource = computed(() =>
    !!this.newSourceName().trim() && !!this.newHost().trim() && !!this.newPort() && !!this.newServiceName().trim() &&
    !!this.newUsername().trim() && !!this.newPassword().trim());

  table = computed<CatalogTable | undefined>(() => this.catalog()?.tables.find((t) => t.table_name === this.selected()));
  allTables = computed(() => this.scanDialogTables() ?? this.catalog()?.tables.map((t) => t.table_name) ?? []);
  parents = computed(() => this.catalog()?.lineage.filter((e) => e.child_table === this.selected() && e.parent_table !== e.child_table) ?? []);
  children = computed(() => this.catalog()?.lineage.filter((e) => e.parent_table === this.selected() && e.parent_table !== e.child_table) ?? []);
  scanning = computed(() => this.scans().some((s) => s.status === 'RUNNING' || s.status === 'QUEUED'));

  private wasScanning = false;

  constructor() {
    this.loadAll();
    const timer = setInterval(() => {
      if (this.scanning() || this.wasScanning) this.loadScans();
    }, 1500);
    inject(DestroyRef).onDestroy(() => clearInterval(timer));
  }

  ts(v: string | null) { return v ? v.slice(0, 19).replace('T', ' ') : '—'; }

  setDomain(d: 'INSURANCE' | 'BANKING') {
    if (this.domain() === d) return;
    this.ds.set(d);
    const visible = this.sources();
    if (visible.length && !visible.some((x) => x.source_id === this.catalogSourceId())) this.pickCatalogSource(visible[0].source_id);
    this.toasts.ok(`Switched to ${d === 'BANKING' ? 'Banking' : 'Insurance'}. Data sources and Remediation now show only this ` +
      `domain's rows; Findings, Policies and Erasure aren't domain-filtered yet.`);
  }

  loadAll() {
    this.api.sources().subscribe((s) => {
      this.allSources.set(s);
      const visible = this.sources();
      if (!visible.some((x) => x.source_id === this.catalogSourceId()) && visible.length) this.catalogSourceId.set(visible[0].source_id);
      // loadCatalog() has to come after the correction above, not run in parallel with it - otherwise it
      // fires with whatever stale catalogSourceId was there before this source list arrived (harmless
      // before the domain toggle existed, since source 1 was always visible; not harmless now).
      this.loadCatalog();
      this.loadSnapshot();
    });
    this.loadScans();
  }

  loadSnapshot() {
    if (!this.auth.isAdmin() || !this.isDatabricksCatalogSource()) { this.snap.set(null); return; }
    this.api.snapshot(this.catalogSourceId()).subscribe((s) => this.snap.set(s));
  }

  pickCatalogSource(id: number) {
    this.catalogSourceId.set(id);
    this.selected.set('');
    this.loadCatalog();
    this.loadSnapshot();
  }

  loadCatalog() {
    this.api.catalog(this.catalogSourceId()).subscribe((c) => {
      this.catalog.set(c);
      if (!this.selected() && c.tables.length) this.selected.set(c.tables.find((t) => t.pii_columns)?.table_name ?? c.tables[0].table_name);
    });
  }

  loadScans() {
    this.api.scans().subscribe((s) => {
      const nowScanning = s.some((x) => x.status === 'RUNNING' || x.status === 'QUEUED');
      if (this.wasScanning && !nowScanning) {           // a scan just finished: refresh everything it changed
        this.loadCatalog();
        this.api.sources().subscribe((x) => this.allSources.set(x));
        this.toasts.ok('Scan finished');
      }
      this.wasScanning = nowScanning;
      this.scans.set(s);
    });
  }

  discover(s: Source) {
    this.busy.set('discover');
    this.api.discover(s.source_id).subscribe({
      next: (r) => {
        this.busy.set('');
        this.toasts.ok(`Discovered ${r.tables} tables, ${r.columns} columns, ${r.fk_links} foreign keys and ${r.inferred_links} inferred links`);
        this.catalogSourceId.set(s.source_id);
        this.selected.set('');
        this.loadAll();
      },
      error: (e) => { this.busy.set(''); this.toasts.error(errorMessage(e)); },
    });
  }

  togglePushdown(s: Source, enabled: boolean) {
    this.pushdownBusy.set(s.source_id);
    this.api.setPushdownEnabled(s.source_id, enabled).subscribe({
      next: () => {
        this.pushdownBusy.set(null);
        this.toasts.ok(`Classifier pushdown ${enabled ? 'enabled' : 'disabled'} for ${s.name}`);
        this.loadAll();
      },
      error: (e) => { this.pushdownBusy.set(null); this.toasts.error(errorMessage(e)); },
    });
  }

  openScan(s: Source) {
    this.scanSourceId.set(s.source_id);
    if (this.catalogSourceId() === s.source_id) {
      this.scanDialogTables.set(null);
      this.picked.set(new Set(this.allTables()));
      this.scanOpen.set(true);
      return;
    }
    this.api.catalog(s.source_id).subscribe((c) => {    // scanning a source other than the one currently browsed - load its tables first
      const tables = c.tables.map((t) => t.table_name);
      this.scanDialogTables.set(tables);
      this.picked.set(new Set(tables));
      this.scanOpen.set(true);
    });
  }
  toggleTable(t: string) {
    const s = new Set(this.picked());
    s.has(t) ? s.delete(t) : s.add(t);
    this.picked.set(s);
  }
  toggleAll() {
    this.picked.set(this.picked().size === this.allTables().length ? new Set() : new Set(this.allTables()));
  }

  startScan() {
    const all = this.picked().size === this.allTables().length;
    this.api.startScan({ source_id: this.scanSourceId(), mode: this.mode(), sample_size: this.mode() === 'SAMPLE' ? +this.sampleSize() : null, tables: all ? null : [...this.picked()] }).subscribe({
      next: () => { this.scanOpen.set(false); this.wasScanning = true; this.loadScans(); this.toasts.ok('Scan started'); },
      error: (e) => this.toasts.error(errorMessage(e)),
    });
  }

  async restore() {
    const name = this.catalogSource()?.name ?? 'this source';
    if (!await this.confirm.ask(`Restore every ${name} table from its snapshot and reset tasks, violations and erasure requests?`)) return;
    this.busy.set('restore');
    this.api.restore(this.catalogSourceId()).subscribe({
      next: (r) => { this.busy.set(''); this.toasts.ok(`${r.tables_restored} tables restored. A fresh scan is running.`); this.wasScanning = true; this.loadAll(); },
      error: (e) => { this.busy.set(''); this.toasts.error(errorMessage(e)); },
    });
  }

  async restoreOne(table: string) {
    if (!await this.confirm.ask(`Restore just ${table} from its snapshot? Its own violations and tasks reset too. Every other table, legal hold and unrelated task is left exactly as it is.`)) return;
    this.restoringTable.set(table);
    this.api.restoreTables([table], this.catalogSourceId()).subscribe({
      next: () => { this.restoringTable.set(null); this.toasts.ok(`${table} restored. A fresh scan of it is running.`); this.wasScanning = true; this.loadAll(); },
      error: (e) => { this.restoringTable.set(null); this.toasts.error(errorMessage(e)); },
    });
  }

  async retake() {
    const name = this.catalogSource()?.name ?? 'this source';
    if (!await this.confirm.ask(`Replace ${name}'s snapshot with the CURRENT state of its tables?`)) return;
    this.busy.set('retake');
    this.api.retake(this.catalogSourceId()).subscribe({
      next: () => { this.busy.set(''); this.toasts.ok('Snapshot re-taken'); this.loadAll(); },
      error: (e) => { this.busy.set(''); this.toasts.error(errorMessage(e)); },
    });
  }

  async deleteSource(s: Source) {
    if (!await this.confirm.ask(`Permanently delete "${s.name}"? This removes its catalog, findings, scans, violations, `
      + `remediation tasks, snapshots and any retention/retain rule that targets it. This cannot be undone - `
      + `you can always add it back as a new source later.`)) return;
    this.busy.set('delete');
    this.api.deleteSource(s.source_id).subscribe({
      next: (r) => {
        this.busy.set('');
        const extra = r.rules_removed.length ? ` Also removed rule(s): ${r.rules_removed.join(', ')}.` : '';
        this.toasts.ok(`${r.deleted_source} deleted.${extra}`);
        this.loadAll();
      },
      error: (e) => { this.busy.set(''); this.toasts.error(errorMessage(e)); },
    });
  }

  // ---- add a data source
  openAddSource() {
    this.newSourceType.set('DATABRICKS'); this.newSourceName.set(''); this.newHost.set('localhost');
    this.newPort.set(443); this.newServiceName.set(''); this.newUsername.set(''); this.newPassword.set('');
    this.testResult.set(null);
    this.addSourceOpen.set(true);
    if (!this.connectorTypes().length) {
      this.api.connectorTypes().subscribe({
        next: (t) => this.connectorTypes.set(t),
        error: (e) => this.toasts.error(errorMessage(e)),
      });
    }
  }
  closeAddSource() { this.addSourceOpen.set(false); }

  pickConnectorType(code: string) {
    this.newSourceType.set(code);
    this.newPort.set(this.connectorTypes().find((t) => t.code === code)?.default_port ?? null);
    this.testResult.set(null);
  }

  private connectionBody() {
    return {
      source_type: this.newSourceType(), host: this.newHost().trim(), port: this.newPort(),
      service_name: this.newServiceName().trim(), username: this.newUsername().trim(), password: this.newPassword(),
    };
  }

  testConnection() {
    this.testing.set(true);
    this.testResult.set(null);
    this.api.testSourceConnection(this.connectionBody()).subscribe({
      next: (r) => { this.testing.set(false); this.testResult.set(r); },
      error: (e) => { this.testing.set(false); this.toasts.error(errorMessage(e)); },
    });
  }

  saveSource() {
    this.saving.set(true);
    const domain = this.domain() === 'BANKING' ? 'Banking' : 'Insurance';
    this.api.createSource({ ...this.connectionBody(), name: this.newSourceName().trim(), domain }).subscribe({
      next: (r) => {
        this.saving.set(false);
        this.addSourceOpen.set(false);
        this.toasts.ok(r.tested.ok ? `${r.name} added and verified.` : `${r.name} saved, but the connection test failed: ${r.tested.message}`);
        this.loadAll();
      },
      error: (e) => { this.saving.set(false); this.toasts.error(errorMessage(e)); },
    });
  }
}
