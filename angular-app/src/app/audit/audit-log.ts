import { Component, inject, signal } from '@angular/core';
import { Api, errorMessage } from '../core/api';
import { pretty } from '../core/format';
import { ArchiveEntry, ArchiveFile, AuditEntry } from '../core/models';

@Component({
  selector: 'app-audit-log',
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1>Audit log</h1>
          <p>Every sign-in, scan, decision, approval and execution, newest first. This is the evidence trail.</p>
        </div>
        <button class="btn" (click)="load()">Refresh</button>
      </div>
      <div class="card">
        @if (error()) {
          <div class="alert alert-error" style="margin: 14px">{{ error() }}</div>
        } @else if (entries().length === 0) {
          <div class="empty">{{ loaded() ? 'No activity recorded yet.' : 'Loading…' }}</div>
        } @else {
          <div class="tbl-wrap">
            <table class="tbl">
              <thead><tr><th>Time</th><th>User</th><th>Entity</th><th>Action</th><th>Details</th></tr></thead>
              <tbody>
                @for (e of entries(); track e.audit_id) {
                  <tr>
                    <td class="mono">{{ e.ts.slice(0, 19).replace('T', ' ') }}</td>
                    <td>{{ e.username }}</td>
                    <td>{{ pretty(e.entity_type) }}@if (e.entity_id) { #{{ e.entity_id }} }</td>
                    <td><span class="badge" [class]="'badge ' + cls(e.action)">{{ e.action }}</span></td>
                    <td class="muted">{{ e.details }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </div>

      <div class="section-title"><h2>Archived records</h2><span class="muted small">Rows an ARCHIVE rule removed from the database - exported first, and findable here</span></div>
      <section class="card">
        @if (archiveError()) {
          <div class="alert alert-error" style="margin: 14px">{{ archiveError() }}</div>
        } @else if (archives().length === 0) {
          <div class="empty">{{ archivesLoaded() ? 'No records have been archived.' : 'Loading…' }}</div>
        } @else {
          <div class="tbl-wrap">
            <table class="tbl">
              <thead><tr><th>Table</th><th>Rows</th><th>Rule</th><th>When</th><th>By</th><th>File</th><th></th></tr></thead>
              <tbody>
                @for (a of archives(); track a.archive_id) {
                  <tr>
                    <td class="mono"><b>{{ a.table_name }}</b></td>
                    <td>{{ a.row_count }}</td>
                    <td class="small">{{ a.policy_code }}@if (a.anchor_column) { <div class="muted">{{ a.anchor_column }} &gt; {{ a.retention_days }}d</div> }</td>
                    <td class="mono small">{{ a.created_at.slice(0, 16).replace('T', ' ') }}</td>
                    <td>{{ a.created_by }}@if (a.task_id) { <div class="muted small">task #{{ a.task_id }}</div> }</td>
                    <td class="mono small" style="word-break:break-all">{{ a.file_path }}</td>
                    <td><button class="btn btn-sm" (click)="view(a)">View</button></td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </section>
    </main>

    @if (viewing(); as v) {
      <div class="backdrop" (click)="viewing.set(null)">
        <div class="modal wide" role="dialog" aria-modal="true" (click)="$event.stopPropagation()">
          <div class="modal-head"><h2>{{ v.entry.table_name }} archive</h2><button class="btn btn-sm" (click)="viewing.set(null)" aria-label="Close">✕</button></div>
          <div class="modal-body">
            @if (v.error) { <div class="alert alert-error">{{ v.error }}</div> }
            @if (v.file) {
              <p class="top muted">{{ v.file.row_count }} row(s), archived {{ v.file.archived_at.slice(0, 19).replace('T', ' ') }} by {{ v.file.archived_by }}.
                <span class="mono">{{ v.entry.file_path }}</span></p>
              <div class="tbl-wrap" style="max-height:50vh">
                <table class="tbl">
                  <thead><tr>@for (c of v.file.columns; track c) { <th>{{ c }}</th> }</tr></thead>
                  <tbody>
                    @for (row of v.file.rows.slice(0, 50); track $index) {
                      <tr>@for (c of v.file.columns; track c) { <td class="small mono">{{ fmt(row[c]) }}</td> }</tr>
                    }
                  </tbody>
                </table>
              </div>
              @if (v.file.rows.length > 50) { <p class="muted small">Showing the first 50 of {{ v.file.rows.length }} rows. The file itself has all of them.</p> }
            } @else if (!v.error) { <div class="empty">Loading…</div> }
          </div>
          <div class="modal-foot"><button class="btn" (click)="viewing.set(null)">Close</button></div>
        </div>
      </div>
    }
  `,
  styles: `
    .modal.wide { width: min(900px, 100%); }
  `,
})
export class AuditLog {
  private api = inject(Api);
  pretty = pretty;
  entries = signal<AuditEntry[]>([]);
  loaded = signal(false);
  error = signal('');

  archives = signal<ArchiveEntry[]>([]);
  archivesLoaded = signal(false);
  archiveError = signal('');
  viewing = signal<{ entry: ArchiveEntry; file: ArchiveFile | null; error: string } | null>(null);

  constructor() {
    this.load();
    this.loadArchives();
  }

  cls(a: string) {
    if (['DELETE', 'REJECTED', 'RESTORE', 'HOLD'].includes(a)) return 's-red';
    if (['EXECUTED', 'CREATE', 'APPROVED', 'CONFIRMED'].includes(a)) return 's-green';
    if (['UPDATE', 'PROPOSED', 'EVALUATE', 'SCAN_START', 'DISCOVER'].includes(a)) return 's-orange';
    if (a === 'ARCHIVED') return 's-teal';
    return 's-gray';
  }

  load() {
    this.api.audit().subscribe({
      next: (e) => { this.entries.set(e); this.loaded.set(true); },
      error: (e) => this.error.set(errorMessage(e)),
    });
  }

  loadArchives() {
    this.api.archives().subscribe({
      next: (a) => { this.archives.set(a); this.archivesLoaded.set(true); },
      error: (e) => this.archiveError.set(errorMessage(e)),
    });
  }

  fmt(v: unknown): string {
    return v === null || v === undefined ? '—' : String(v);
  }

  view(entry: ArchiveEntry) {
    this.viewing.set({ entry, file: null, error: '' });
    this.api.archiveFile(entry.archive_id).subscribe({
      next: (file) => this.viewing.set({ entry, file, error: '' }),
      error: (e) => this.viewing.set({ entry, file: null, error: errorMessage(e) }),
    });
  }
}
