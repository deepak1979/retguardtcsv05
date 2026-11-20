import { Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { Auth } from '../core/auth';
import { Branding } from '../core/branding';
import { Confirms } from '../core/confirm';
import { Toasts } from '../core/toast';

@Component({
  selector: 'app-shell',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <header class="bar">
      <div class="bar-in">
        <a class="brand" routerLink="/dashboard" [attr.aria-label]="brand.name() + ' RetentionGuard'">
          @if (brand.logo(); as logo) {
            <img class="logo-img" [src]="logo" [alt]="brand.name()" (error)="brand.logoFailed.set(true)" />
          } @else {
            <span class="co">{{ brand.name() }}</span>
          }
          <span class="sep"></span>
          <span class="prod">Retention<b>Guard</b></span>
        </a>
        <nav class="nav-scroll">
          <a routerLink="/dashboard" routerLinkActive="active">Overview</a>
          <a routerLink="/sources" routerLinkActive="active">Data sources</a>
          <a routerLink="/documents" routerLinkActive="active">Documents</a>
          <a routerLink="/findings" routerLinkActive="active">Findings</a>
          <a routerLink="/lineage" routerLinkActive="active">Lineage</a>
          <a routerLink="/policies" routerLinkActive="active">Policies</a>
          <a routerLink="/remediation" routerLinkActive="active">Remediation</a>
          <a routerLink="/redaction" routerLinkActive="active">Redaction</a>
          <!-- Semantic search hidden for now - no embedding model available on this workspace yet
               (see rg/vectorsearch.py; vectorsearch.enabled is also off). Route redirects too, in
               case someone has the URL - see app.routes.ts. -->
          <a routerLink="/erasure" routerLinkActive="active">Erasure</a>
          <a routerLink="/legal-holds" routerLinkActive="active">Legal holds</a>
          <a routerLink="/organisation" routerLinkActive="active">Organisation</a>
          <a routerLink="/audit" routerLinkActive="active">Audit</a>
        </nav>
        <div class="who">
          <span class="name">{{ auth.user()?.full_name }}</span>
          <span class="badge" [class]="'badge b-' + (auth.user()?.role === 'viewer' ? 'viewer' : 'admin')">{{ auth.user()?.role }}</span>
          <button class="btn btn-sm" (click)="auth.logout()">Sign out</button>
        </div>
      </div>
    </header>
    <router-outlet />
    <div class="toasts" aria-live="polite">
      @for (t of toasts.items(); track t.id) {
        <div class="toast" [class.error]="t.kind === 'error'">{{ t.text }}</div>
      }
    </div>
    @if (confirm.state(); as c) {
      <div class="confirm-backdrop" (click)="confirm.respond(false)">
        <div class="confirm-box" role="alertdialog" aria-modal="true" (click)="$event.stopPropagation()">
          <p>{{ c.message }}</p>
          <div class="confirm-actions">
            <button class="btn btn-sm" (click)="confirm.respond(false)">Cancel</button>
            <button class="btn btn-sm btn-danger" (click)="confirm.respond(true)">OK</button>
          </div>
        </div>
      </div>
    }
  `,
  styles: `
    .bar { background: var(--banner-bg); color: var(--banner-fg); border-bottom: 1px solid var(--banner-border); position: sticky; top: 0; z-index: 20; }
    .bar-in { max-width: 1240px; margin: 0 auto; padding: 0 24px; height: 60px; display: flex; align-items: center; gap: 22px; }
    .brand { display: flex; align-items: center; gap: 12px; color: var(--banner-fg); white-space: nowrap; flex-shrink: 0; }
    .brand:hover { text-decoration: none; }
    .logo-img { height: 30px; width: auto; max-width: 170px; object-fit: contain; display: block; }
    .co { font-weight: 700; font-size: 17px; }
    .sep { width: 1px; height: 24px; background: var(--banner-border); }
    .prod { font-size: 15px; color: var(--banner-fg-muted); letter-spacing: 0.01em; }
    .prod b { color: var(--primary); }
    nav.nav-scroll {
      display: flex; gap: 2px; flex: 1 1 auto; min-width: 0;
      overflow-x: auto; overflow-y: hidden; scrollbar-width: thin;
      mask-image: linear-gradient(to right, transparent 0, #000 12px, #000 calc(100% - 12px), transparent 100%);
    }
    nav.nav-scroll::-webkit-scrollbar { height: 5px; }
    nav.nav-scroll::-webkit-scrollbar-thumb { background: var(--banner-border); border-radius: 3px; }
    nav a { color: var(--banner-fg-muted); padding: 6px 9px; border-radius: 6px; font-weight: 500; white-space: nowrap; flex-shrink: 0; }
    nav a:hover { background: var(--banner-hover); text-decoration: none; }
    nav a.active { background: var(--banner-active); color: var(--banner-fg); }
    .who { display: flex; align-items: center; gap: 10px; white-space: nowrap; flex-shrink: 0; }
    .name { color: var(--banner-fg); }
    .who .btn { background: transparent; color: var(--banner-fg); border-color: var(--banner-border); }
    .who .btn:hover { background: var(--banner-hover) !important; }
    .toasts { position: fixed; right: 20px; bottom: 20px; display: flex; flex-direction: column; gap: 8px; z-index: 60; }
    .toast { background: var(--brand-dark); color: #fff; padding: 10px 16px; border-radius: 8px; box-shadow: 0 6px 20px rgba(0,0,0,.25); border-left: 4px solid var(--primary-soft); max-width: 420px; }
    .toast.error { border-left-color: #f87171; }
    .confirm-backdrop { position: fixed; inset: 0; background: rgba(15,23,32,.55); display: flex; align-items: center; justify-content: center; z-index: 70; padding: 20px; }
    .confirm-box { background: var(--surface, #fff); color: var(--text, #111); border-radius: 10px; padding: 20px 22px; max-width: 460px; width: 100%; box-shadow: 0 16px 40px rgba(0,0,0,.3); }
    .confirm-box p { margin: 0 0 16px; white-space: pre-line; line-height: 1.45; }
    .confirm-actions { display: flex; justify-content: flex-end; gap: 10px; }
    @media (max-width: 1300px) { .name { display: none; } .prod { display: none; } .sep { display: none; } }
    @media (max-width: 900px) { .bar-in { gap: 10px; padding: 0 12px; } }
  `,
})
export class Shell {
  auth = inject(Auth);
  brand = inject(Branding);
  toasts = inject(Toasts);
  confirm = inject(Confirms);
}
