import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api, errorMessage } from '../core/api';
import { DomainScope } from '../core/domain';
import { pretty } from '../core/format';
import { Catalog, CatalogTable, LineageEdge, Source } from '../core/models';
import { Toasts } from '../core/toast';

interface GNode {
  table: string; x: number; y: number; w: number; h: number; pii: number; rows: number; isolated: boolean;
}
interface GEdge {
  from: string; to: string; kinds: Set<'FK' | 'INFERRED'>;
  pairs: { child_column: string; parent_column: string; kind: string; confidence: number }[];
  x1: number; y1: number; x2: number; y2: number; midX: number; midY: number;
}
interface Graph { nodes: GNode[]; edges: GEdge[]; width: number; height: number }

const NODE_W = 192, NODE_H = 54, GAP_X = 36, GAP_Y = 86, PAD = 36;

/** Layered top-down DAG: level 0 = tables nothing else is "above" (no outgoing FK/inferred edge of their
 * own - roots like CUSTOMER, BRANCH), deeper levels = tables that hang off something else. This is exactly
 * the direction erasure/retention cascade walks (Graph.paths_from in catalog.py): a person's identity row
 * at the top, everything that depends on it fanning out below. */
function layout(tables: CatalogTable[], lineage: LineageEdge[]): Graph {
  const pairMap = new Map<string, { from: string; to: string; kinds: Set<'FK' | 'INFERRED'>; pairs: LineageEdge[] }>();
  for (const l of lineage) {
    const key = `${l.child_table}\u0000${l.parent_table}`;
    let p = pairMap.get(key);
    if (!p) { p = { from: l.child_table, to: l.parent_table, kinds: new Set(), pairs: [] }; pairMap.set(key, p); }
    p.kinds.add(l.kind);
    p.pairs.push(l);
  }
  const names = tables.map((t) => t.table_name);
  const parentsOf = new Map<string, Set<string>>();
  const childrenOf = new Map<string, Set<string>>();
  for (const n of names) { parentsOf.set(n, new Set()); childrenOf.set(n, new Set()); }
  for (const p of pairMap.values()) {
    if (!parentsOf.has(p.from)) parentsOf.set(p.from, new Set());
    if (!childrenOf.has(p.to)) childrenOf.set(p.to, new Set());
    parentsOf.get(p.from)!.add(p.to);
    childrenOf.get(p.to)!.add(p.from);
  }

  const level = new Map<string, number>();
  const computeLevel = (t: string, seen: Set<string>): number => {
    const have = level.get(t);
    if (have !== undefined) return have;
    if (seen.has(t)) return 0; // a cycle (shouldn't happen) - stop recursing rather than hang
    seen.add(t);
    const parents = [...(parentsOf.get(t) ?? [])];
    const lv = parents.length ? Math.max(...parents.map((p) => computeLevel(p, seen))) + 1 : 0;
    level.set(t, lv);
    return lv;
  };
  for (const n of names) computeLevel(n, new Set());

  const byLevel = new Map<number, string[]>();
  for (const n of names) {
    const lv = level.get(n) ?? 0;
    if (!byLevel.has(lv)) byLevel.set(lv, []);
    byLevel.get(lv)!.push(n);
  }
  const levels = [...byLevel.keys()].sort((a, b) => a - b);
  const pos = new Map<string, { x: number; y: number }>();
  const nodes: GNode[] = [];
  let maxRowWidth = 0;
  for (const lv of levels) {
    const row = byLevel.get(lv)!.sort();
    maxRowWidth = Math.max(maxRowWidth, row.length * NODE_W + (row.length - 1) * GAP_X);
    row.forEach((t, i) => {
      const x = PAD + i * (NODE_W + GAP_X);
      const y = PAD + lv * (NODE_H + GAP_Y);
      pos.set(t, { x: x + NODE_W / 2, y: y + NODE_H / 2 });
      const tc = tables.find((tt) => tt.table_name === t);
      nodes.push({ table: t, x, y, w: NODE_W, h: NODE_H, pii: tc?.pii_columns ?? 0, rows: tc?.row_count ?? 0,
                   isolated: !parentsOf.get(t)?.size && !childrenOf.get(t)?.size });
    });
  }
  const edges: GEdge[] = [...pairMap.values()].map((p) => {
    const a = pos.get(p.from)!, b = pos.get(p.to)!;
    return { from: p.from, to: p.to, kinds: p.kinds, pairs: p.pairs.map((e) => (
             { child_column: e.child_column, parent_column: e.parent_column, kind: e.kind, confidence: e.confidence })),
             x1: a.x, y1: a.y, x2: b.x, y2: b.y, midX: (a.x + b.x) / 2, midY: (a.y + b.y) / 2 };
  });
  return { nodes, edges, width: Math.max(maxRowWidth + PAD * 2, 400), height: PAD * 2 + levels.length * (NODE_H + GAP_Y) };
}

@Component({
  selector: 'app-lineage',
  imports: [FormsModule],
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1>Lineage</h1>
          <p>How this source's tables connect - declared foreign keys and inferred derived copies - the same graph
             erasure and retention cascades walk to find everything linked to a person.</p>
        </div>
        <div class="row" style="gap:10px;flex:none">
          <div class="domain-toggle" role="group" aria-label="Domain">
            <button type="button" class="domain-opt" [class.on]="domain() === 'INSURANCE'" (click)="setDomain('INSURANCE')">Insurance</button>
            <button type="button" class="domain-opt" [class.on]="domain() === 'BANKING'" (click)="setDomain('BANKING')">Banking</button>
          </div>
          @if (sources().length > 1) {
            <select [ngModel]="sourceId()" (ngModelChange)="pick($event)">
              @for (s of sources(); track s.source_id) { <option [ngValue]="s.source_id">{{ s.name }}</option> }
            </select>
          }
        </div>
      </div>

      @if (!sources().length) {
        <section class="card card-pad"><div class="empty">No data source is tagged for this domain yet.</div></section>
      } @else if (loading()) {
        <section class="card card-pad"><div class="empty">Loading…</div></section>
      } @else if (!catalog()?.tables?.length) {
        <section class="card card-pad"><div class="empty">No catalog yet for this source. Run <b>Discover catalog</b> from Data sources first.</div></section>
      } @else {
        <div class="legend">
          <span class="leg"><i class="ln fk"></i> Foreign key (declared)</span>
          <span class="leg"><i class="ln inf"></i> Inferred (no declared FK, values line up ≥95%)</span>
          <span class="leg"><i class="dot pii"></i> Table has classified PII/PHI columns</span>
          <span class="muted small">Click a table for details · click empty space to clear</span>
        </div>

        <div class="layout-split">
          <section class="card graph-card" (click)="selected.set(null)">
            @if (g(); as graph) {
            <svg [attr.viewBox]="'0 0 ' + graph.width + ' ' + graph.height" [attr.width]="graph.width" [attr.height]="graph.height">
              <defs>
                <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                  <path d="M0,0 L10,5 L0,10 z" fill="var(--muted)" />
                </marker>
              </defs>
              @for (e of graph.edges; track e.from + e.to) {
                <path class="edge" [class.fk]="!e.kinds.has('INFERRED')" [class.inf]="e.kinds.has('INFERRED') && !e.kinds.has('FK')"
                      [class.dim]="selected() && !touches(e)"
                      [attr.d]="'M' + e.x1 + ',' + (e.y1 - h2) + ' C ' + e.x1 + ',' + (e.midY) + ' ' + e.x2 + ',' + (e.midY) + ' ' + e.x2 + ',' + (e.y2 + h2)"
                      marker-end="url(#arrow)" (click)="$event.stopPropagation(); selectEdge(e)" />
              }
              @for (n of graph.nodes; track n.table) {
                <g class="node" [class.dim]="selected() && selected() !== n.table && !neighborOf(n.table)"
                   [class.sel]="selected() === n.table" (click)="$event.stopPropagation(); selected.set(n.table)">
                  <rect [attr.x]="n.x" [attr.y]="n.y" [attr.width]="n.w" [attr.height]="n.h" rx="8"
                        [class.isolated]="n.isolated" />
                  <text [attr.x]="n.x + 10" [attr.y]="n.y + 22" class="name">{{ short(n.table) }}</text>
                  <text [attr.x]="n.x + 10" [attr.y]="n.y + 40" class="meta">{{ n.rows }} row(s)</text>
                  @if (n.pii) { <circle [attr.cx]="n.x + n.w - 14" [attr.cy]="n.y + 14" r="5" class="dot pii" /> }
                </g>
              }
            </svg>
            }
          </section>

          <section class="card card-pad detail">
            @if (!selected()) {
              <div class="empty">Select a table (or a connecting line) to see its relationships.</div>
            } @else if (detail(); as d) {
              <h2 class="mono">{{ d.table?.table_name }}</h2>
              <div class="kv" style="margin:10px 0 16px">
                <div><span class="muted">Rows</span><b>{{ d.table?.row_count }}</b></div>
                <div><span class="muted">Columns</span><b>{{ d.table?.column_count }}</b></div>
                <div><span class="muted">PII/PHI columns</span><b>{{ d.table?.pii_columns }}</b></div>
                <div><span class="muted">Relationships</span><b>{{ d.related.length }}</b></div>
              </div>
              @if (!d.related.length) {
                <div class="note">No declared or inferred relationship touches this table.</div>
              }
              @for (r of d.related; track r.child_table + r.parent_table + r.child_column) {
                <div class="rel">
                  <div class="row" style="justify-content:space-between">
                    <span class="mono small">
                      @if (r.parent_table === d.table?.table_name) {
                        <b>{{ short(r.child_table) }}</b>.{{ r.child_column }} → this.{{ r.parent_column }}
                      } @else {
                        this.{{ r.child_column }} → <b>{{ short(r.parent_table) }}</b>.{{ r.parent_column }}
                      }
                    </span>
                    <span class="badge" [class]="'badge s-' + (r.kind === 'FK' ? 'blue' : 'orange')">{{ pretty(r.kind) }}</span>
                  </div>
                  @if (r.kind === 'INFERRED') { <div class="muted small">{{ pct(r.confidence) }} of values match - no declared constraint</div> }
                </div>
              }
            }
          </section>
        </div>
      }
    </main>
  `,
  styles: `
    .domain-toggle { display: flex; flex: none; border: 1px solid var(--border); border-radius: 999px; padding: 3px; background: #fff; }
    .domain-opt { border: none; background: none; font: inherit; font-weight: 600; font-size: 13px; padding: 7px 16px; border-radius: 999px; cursor: pointer; color: var(--muted); }
    .domain-opt.on { background: var(--primary); color: #fff; }
    .legend { display: flex; align-items: center; gap: 20px; margin: 4px 0 14px; flex-wrap: wrap; }
    .leg { display: inline-flex; align-items: center; gap: 7px; font-size: 13px; color: var(--muted); }
    .ln { width: 22px; height: 0; border-top: 2px solid var(--primary); display: inline-block; }
    .ln.inf { border-top: 2px dashed #d97706; }
    .dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
    .dot.pii { background: #d97706; }
    .layout-split { display: grid; grid-template-columns: 1fr 320px; gap: 16px; align-items: start; }
    .graph-card { padding: 10px; overflow: auto; max-height: 72vh; }
    svg { display: block; }
    .edge { fill: none; stroke: var(--primary); stroke-width: 1.6; cursor: pointer; }
    .edge.inf { stroke: #d97706; stroke-dasharray: 5 4; }
    .edge.dim { opacity: 0.15; }
    .node rect { fill: #fff; stroke: var(--border); stroke-width: 1.3; cursor: pointer; }
    .node rect.isolated { stroke-dasharray: 3 3; }
    .node.sel rect { stroke: var(--primary); stroke-width: 2.4; }
    .node.dim { opacity: 0.25; }
    .node .name { font-size: 12.5px; font-weight: 700; font-family: var(--mono, monospace); }
    .node .meta { font-size: 10.5px; fill: var(--muted); }
    .detail { max-height: 72vh; overflow: auto; }
    .rel { padding: 9px 0; border-top: 1px solid var(--border); }
    .rel:first-of-type { border-top: none; }
  `,
})
export class Lineage {
  private api = inject(Api);
  private toasts = inject(Toasts);
  ds = inject(DomainScope);
  domain = this.ds.domain;
  pretty = pretty;

  allSources = signal<Source[]>([]);
  sources = computed(() => this.allSources().filter((s) => this.ds.matches(s.domain)));
  sourceId = signal<number | null>(null);
  catalog = signal<Catalog | null>(null);
  loading = signal(false);
  selected = signal<string | null>(null);
  h2 = NODE_H / 2;

  g = computed<Graph | null>(() => {
    const c = this.catalog();
    return c ? layout(c.tables, c.lineage) : null;
  });

  detail = computed(() => {
    const sel = this.selected();
    const c = this.catalog();
    if (!sel || !c) return null;
    return { table: c.tables.find((t) => t.table_name === sel),
            related: c.lineage.filter((l) => l.child_table === sel || l.parent_table === sel) };
  });

  constructor() {
    this.loadSources();
  }

  loadSources() {
    this.api.sources().subscribe((s) => {
      this.allSources.set(s);
      const visible = this.sources();
      if (visible.length && !visible.some((x) => x.source_id === this.sourceId())) this.pick(visible[0].source_id);
    });
  }

  setDomain(d: 'INSURANCE' | 'BANKING') {
    this.ds.set(d);
    const visible = this.sources();
    if (visible.length && !visible.some((x) => x.source_id === this.sourceId())) this.pick(visible[0].source_id);
    else if (!visible.length) { this.sourceId.set(null); this.catalog.set(null); }
  }

  pick(id: number) {
    this.sourceId.set(id);
    this.selected.set(null);
    this.loading.set(true);
    this.api.catalog(id).subscribe({
      next: (c) => { this.loading.set(false); this.catalog.set(c); },
      error: (e) => { this.loading.set(false); this.toasts.error(errorMessage(e)); },
    });
  }

  short(table: string): string {
    return table.length > 24 ? table.slice(0, 22) + '…' : table;
  }

  pct(v: number): string {
    return `${Math.round(v * 100)}%`;
  }

  touches(e: GEdge): boolean {
    const sel = this.selected();
    return !!sel && (e.from === sel || e.to === sel);
  }

  neighborOf(table: string): boolean {
    const sel = this.selected();
    const graph = this.g();
    if (!sel || !graph) return false;
    return graph.edges.some((e) => (e.from === sel && e.to === table) || (e.to === sel && e.from === table));
  }

  selectEdge(e: GEdge) {
    this.selected.set(this.selected() === e.from ? e.to : e.from);
  }
}
