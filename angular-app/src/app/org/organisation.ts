import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DomSanitizer } from '@angular/platform-browser';
import { RouterLink } from '@angular/router';
import { Api, errorMessage } from '../core/api';
import { Auth } from '../core/auth';
import { Branding, contrastText } from '../core/branding';
import { Confirms } from '../core/confirm';
import { pretty, tone } from '../core/format';
import { Country, Coverage, Hierarchy, JurisdictionReport, Organization, Region } from '../core/models';
import { Toasts } from '../core/toast';

interface OrgForm {
  org_id: number | null; name: string; tagline: string; logo_url: string; logo_data: string; banner_color: string;
  primary_color: string;
}
const BLANK: OrgForm = { org_id: null, name: '', tagline: '', logo_url: '', logo_data: '', banner_color: '#ffffff', primary_color: '#0f766e' };

@Component({
  selector: 'app-organisation',
  imports: [FormsModule, RouterLink],
  template: `
    <main class="page">
      <div class="page-head">
        <div>
          <h1>Organisation</h1>
          <p>The company this deployment is configured for, and the regions and countries its policies and classifiers are scoped to.</p>
        </div>
      </div>

      <div class="tabs">
        @for (t of tabs; track t.id) { <button class="tab" [class.active]="tab() === t.id" (click)="open(t.id)">{{ t.label }}</button> }
      </div>

      <!-- ================================================================= branding -->
      @if (tab() === 'branding') {
        <div class="layout-split" style="grid-template-columns: minmax(340px, 1fr) minmax(300px, 380px)">
          <section class="card card-pad">
            <h2>{{ form().org_id ? 'Company profile' : 'New company profile' }}</h2>
            <p class="muted small top">Name, logo and colours appear in the banner and on the sign-in page for everyone.</p>

            <div class="preview" [style.background]="form().banner_color" [style.color]="fg()" [style.border-color]="fg() + '33'">
              @if (previewLogo(); as l) { <img [src]="l" [alt]="form().name" /> } @else { <b>{{ form().name || 'Company name' }}</b> }
              <span class="sep" [style.background]="fg() + '33'"></span>
              <span>Retention<b [style.color]="form().primary_color">Guard</b></span>
              <span class="pill" [style.background]="form().primary_color" [style.color]="contrast(form().primary_color)">Button</span>
            </div>

            <div class="grid-2" style="margin-top:16px">
              <div class="field"><label for="on">Company name</label><input id="on" type="text" [disabled]="!auth.isAdmin()" [ngModel]="form().name" (ngModelChange)="set('name', $event)" /></div>
              <div class="field"><label for="ot">Tagline <span class="muted">(optional)</span></label><input id="ot" type="text" [disabled]="!auth.isAdmin()" [ngModel]="form().tagline" (ngModelChange)="set('tagline', $event)" /></div>
            </div>

            <div class="field">
              <span class="label">Logo</span>
              <div class="row">
                <input type="text" style="flex:1;min-width:220px" placeholder="https://…/logo.svg or /logos/logo.svg" aria-label="Logo address" [disabled]="!auth.isAdmin()"
                       [ngModel]="form().logo_url" (ngModelChange)="set('logo_url', $event); set('logo_data', '')" />
                @if (auth.isAdmin()) {
                  <label class="btn" style="cursor:pointer">Upload…<input type="file" accept="image/png,image/jpeg,image/svg+xml,image/webp,image/gif" hidden (change)="upload($event)" /></label>
                  @if (form().logo_url || form().logo_data) { <button class="btn" (click)="removeLogo()">Remove</button> }
                }
              </div>
              <span class="hint">PNG, JPEG, WebP, GIF or SVG up to 500 KB. SVGs containing scripts are rejected.</span>
            </div>

            <div class="grid-2">
              <div class="field">
                <label for="ob">Banner colour</label>
                <div class="row" style="flex-wrap:nowrap"><input id="ob" type="color" class="swatch" [disabled]="!auth.isAdmin()" [ngModel]="form().banner_color" (ngModelChange)="set('banner_color', $event)" />
                  <input type="text" class="mono" style="width:110px" aria-label="Banner colour hex" [disabled]="!auth.isAdmin()" [ngModel]="form().banner_color" (ngModelChange)="set('banner_color', $event)" /></div>
                <span class="hint">Text colour adapts automatically.</span>
              </div>
              <div class="field">
                <label for="op">Accent colour</label>
                <div class="row" style="flex-wrap:nowrap"><input id="op" type="color" class="swatch" [disabled]="!auth.isAdmin()" [ngModel]="form().primary_color" (ngModelChange)="set('primary_color', $event)" />
                  <input type="text" class="mono" style="width:110px" aria-label="Accent colour hex" [disabled]="!auth.isAdmin()" [ngModel]="form().primary_color" (ngModelChange)="set('primary_color', $event)" /></div>
                <span class="hint">Buttons, links and highlights.</span>
              </div>
            </div>

            @if (form().org_id === null) {
              <label class="check"><input type="checkbox" [(ngModel)]="seedHierarchy" /> Start with the standard region and country list</label>
            }
            @if (auth.isAdmin()) {
              <div class="row">
                <button class="btn btn-primary" (click)="save()" [disabled]="busy() || form().name.trim().length < 2">{{ busy() ? 'Saving…' : (form().org_id ? 'Save changes' : 'Create company') }}</button>
                @if (form().org_id === null) { <button class="btn" (click)="edit(activeOrg())">Cancel</button> }
              </div>
            } @else { <div class="note">Only an admin can change the company profile.</div> }
          </section>

          <section class="card">
            <div class="card-pad" style="padding-bottom:8px"><h2>Companies</h2><p class="muted small" style="margin:4px 0 0">One is active at a time. Activating another changes the banner, the regions and the classifier packs.</p></div>
            @for (o of orgs(); track o.org_id) {
              <div class="list-item" [class.sel]="o.org_id === form().org_id" (click)="edit(o)">
                <div class="row" style="flex-wrap:nowrap;gap:12px">
                  <span class="thumb" [style.background]="o.banner_color">@if (thumb(o); as t) { <img [src]="t" [alt]="o.name" /> } @else { <b [style.color]="contrast(o.banner_color)">{{ o.name.slice(0, 2) }}</b> }</span>
                  <div style="flex:1;min-width:0"><b>{{ o.name }}</b><div class="muted small">{{ o.code }} · {{ o.regions }} regions</div></div>
                  @if (o.is_active) { <span class="badge s-green">Active</span> }
                </div>
                @if (auth.isAdmin() && !o.is_active) {
                  <div class="row" style="margin-top:8px"><button class="btn btn-sm" (click)="activate(o); $event.stopPropagation()">Make active</button><button class="btn btn-sm btn-danger" (click)="remove(o); $event.stopPropagation()">Delete</button></div>
                }
              </div>
            }
            @if (auth.isAdmin()) { <div class="card-pad" style="padding-top:12px"><button class="btn" (click)="startNew()">＋ Add a company</button></div> }
          </section>
        </div>

        @if (auth.isAdmin()) {
          <section class="card card-pad reset-card">
            <h2>Clear all data</h2>
            <p class="muted small top">Wipes every finding, scan, catalog entry, violation, remediation task, erasure request, legal hold and archive file across
              <b>every data source</b> (all on Databricks), and restores each source's tables to its original snapshot. Also resets every document source back
              to "never scanned" - findings, redaction/index history and redacted copies are cleared, and their chunks are removed from the semantic search index -
              while the original PDF files themselves are left alone. Companies, regions, countries and policies are untouched. Use this to start a demo from a
              clean state for whichever domain you're resetting - for example right before switching to a different company above.</p>
            <button class="btn btn-danger" (click)="clearAll()" [disabled]="clearing()">{{ clearing() ? 'Clearing…' : 'Clear All' }}</button>
          </section>
        }
      }

      <!-- ================================================================= hierarchy -->
      @if (tab() === 'hierarchy') {
        @if (hier(); as h) {
          <div class="row" style="margin-bottom:12px">
            <span class="muted">Policies and classifiers can be scoped <b>Global</b>, to a <b>region</b>, or to one <b>country</b>.
              Global: {{ h.global.policies }} policies · {{ h.global.classifiers }} classifiers.</span>
            @if (auth.isAdmin()) { <button class="btn btn-primary right" (click)="openRegion({})">＋ Add region</button> }
          </div>
          @for (r of h.regions; track r.region_id) {
            <section class="card region" [class.off]="!r.is_active">
              <div class="region-head">
                <div>
                  <h2>{{ r.name }} <span class="muted mono small">{{ r.code }}</span> @if (!r.is_active) { <span class="badge s-gray">Inactive</span> }</h2>
                  <span class="muted small">{{ r.description }}</span>
                </div>
                <div class="row">
                  <span class="badge s-blue" title="Policies scoped to the whole region">{{ r.policies }} region policies</span>
                  <span class="badge s-purple" title="Classifiers scoped to the whole region">{{ r.classifiers }} region classifiers</span>
                  @if (auth.isAdmin()) {
                    <button class="btn btn-sm" (click)="openCountry({ region_id: r.region_id })">＋ Country</button>
                    <button class="btn btn-sm" (click)="openRegion(r)">Edit</button>
                    <button class="btn btn-sm btn-danger" (click)="deleteRegion(r)">Delete</button>
                  }
                </div>
              </div>
              <div class="tbl-wrap">
                <table class="tbl">
                  <thead><tr><th>Country</th><th>Privacy law</th><th>Regulator</th><th>Policies</th><th>Classifiers</th><th>Active</th><th></th></tr></thead>
                  <tbody>
                    @for (c of r.countries; track c.country_id) {
                      <tr [class.off]="!c.is_active">
                        <td><span class="iso">{{ c.iso2 }}</span> {{ c.name }}</td>
                        <td>{{ c.regulation ?? '—' }}</td>
                        <td class="muted">{{ c.regulator ?? '—' }}</td>
                        <td>{{ c.policies }}</td><td>{{ c.classifiers }}</td>
                        <td><label class="check" style="margin:0"><input type="checkbox" [checked]="c.is_active" [disabled]="!auth.isAdmin()" (change)="toggleCountry(c, $any($event.target).checked)" /></label></td>
                        <td style="white-space:nowrap">@if (auth.isAdmin()) { <button class="btn btn-sm" (click)="openCountry(c)">Edit</button> <button class="btn btn-sm btn-danger" (click)="deleteCountry(c)">Delete</button> }</td>
                      </tr>
                    } @empty { <tr><td colspan="7" class="muted">No countries yet.</td></tr> }
                  </tbody>
                </table>
              </div>
            </section>
          }
          <p class="muted small">Regulation names are a starting point for your legal team to confirm, not legal advice. Deactivating a country switches off the policies and classifier pack scoped to it.</p>
        }
      }

      <!-- ================================================================= coverage -->
      @if (tab() === 'coverage') {
        <div class="row" style="margin-bottom:14px">
          <label for="cc" class="label">What applies in</label>
          <select id="cc" style="width:260px" [ngModel]="country()" (ngModelChange)="pickCountry($event)">
            @for (r of hier()?.regions ?? []; track r.region_id) {
              <optgroup [label]="r.name">@for (c of r.countries; track c.country_id) { @if (c.is_active) { <option [value]="c.iso2">{{ c.name }} ({{ c.iso2 }})</option> } }</optgroup>
            }
          </select>
        </div>
        @if (cov(); as v) {
          @if (v.country) {
            <section class="card card-pad" style="margin-bottom:14px">
              <div class="kv">
                <div><span class="muted">Country</span><b>{{ v.country.name }}</b></div>
                <div><span class="muted">Region</span><b>{{ v.region?.name }}</b></div>
                <div><span class="muted">Privacy law</span><b>{{ v.country.regulation ?? '—' }}</b></div>
                <div><span class="muted">Regulator</span><b>{{ v.country.regulator ?? '—' }}</b></div>
              </div>
            </section>
          }
          <div class="chain">
            @for (g of v.groups; track g.level; let last = $last) {
              <section class="card card-pad link">
                <div class="row" style="justify-content:space-between"><h3>{{ g.title }}</h3><span class="badge" [class]="'badge s-' + (g.level === 'GLOBAL' ? 'gray' : g.level === 'REGION' ? 'blue' : 'teal')">{{ pretty(g.level) }}</span></div>
                @for (p of g.policies; track p.policy_id) {
                  <a class="pol" [routerLink]="['/policies', p.policy_id]">
                    <b>{{ p.name }}</b>
                    <span class="muted small">{{ p.policy_code }} · {{ pretty(p.data_category) }} · {{ p.rule_count }} rules @if (p.status !== 'ACTIVE') { · <span class="badge s-orange">{{ pretty(p.status) }}</span> }@if (p.override_parent) { · <span class="badge s-purple">overrides parent</span> }</span>
                  </a>
                } @empty { <span class="muted small">No policies at this level.</span> }
              </section>
              @if (!last) { <span class="arrow">→</span> }
            }
          </div>

          <div class="section-title"><h2>Rules in force</h2><span class="muted small">Inherited from broader scopes; a policy that overrides its parent replaces the broader rule.</span></div>
          <section class="card">
            <div class="tbl-wrap">
              <table class="tbl">
                <thead><tr><th>Rule</th><th>From</th><th>What it does</th><th>Status</th></tr></thead>
                <tbody>
                  @for (r of v.rules; track r.rule_id) {
                    <tr [class.struck]="!r.effective">
                      <td><b>{{ r.rule }}</b><div class="muted mono small">{{ r.policy_code }}</div></td>
                      <td><span class="badge" [class]="'badge s-' + (r.scope_level === 'GLOBAL' ? 'gray' : r.scope_level === 'REGION' ? 'blue' : 'teal')">{{ r.scope }}</span></td>
                      <td class="small">{{ r.detail }}</td>
                      <td>@if (r.effective) { <span class="badge s-green">In force</span> } @else { <span class="badge s-gray" title="A more specific policy overrides this rule for this country">Replaced by {{ r.overridden_by }}</span> }</td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          </section>

          <div class="section-title"><h2>Classifiers scanning for {{ v.country?.name ?? 'the organisation' }}</h2><span class="muted small">{{ v.classifiers.length }} in force</span></div>
          <section class="card card-pad">
            @for (grp of classifierGroups(); track grp.title) {
              <div style="margin-bottom:10px"><span class="muted small">{{ grp.title }} ({{ grp.items.length }})</span>
                <div class="row" style="gap:6px;margin-top:4px">@for (c of grp.items; track c.code) { <span class="chip soft" [title]="c.name">{{ c.name }}</span> }</div></div>
            }
          </section>
        }
      }

      <!-- ================================================================= jurisdiction -->
      @if (tab() === 'jurisdiction') {
        <div class="note">Country-specific rules need to know which country a row belongs to. A table either holds a country column itself, or inherits the country
          of the row it points at (a claim payment takes its customer's country). A table with neither is governed by global rules only.</div>
        @if (jur(); as j) {
          @if (j.unmapped_countries.length) { <div class="note warn">The data contains countries missing from the hierarchy: {{ j.unmapped_countries.join(', ') }}. Rows there follow global rules only.</div> }
          <section class="card">
            <div class="tbl-wrap">
              <table class="tbl">
                <thead><tr><th>Table</th><th>Country comes from</th><th>Rows by country</th></tr></thead>
                <tbody>
                  @for (t of j.tables; track t.table) {
                    <tr>
                      <td class="mono"><b>{{ t.table }}</b></td>
                      <td class="small">
                        <span class="badge" [class]="'badge s-' + (t.source === 'DIRECT' ? 'green' : t.source === 'INHERITED' ? 'blue' : 'gray')">{{ t.source === 'DIRECT' ? 'Own column' : t.source === 'INHERITED' ? 'Inherited' : 'None' }}</span>
                        @if (t.country_table) { <span class="mono"> {{ t.country_table }}.{{ t.country_column }}</span> }
                        @for (v of t.via; track v) { <div class="mono muted">{{ v }}</div> }
                      </td>
                      <td>@for (d of t.distribution; track d.country) { <span class="chip soft" style="margin-right:4px">{{ d.country ?? '?' }} {{ d.rows }}</span> } @empty { <span class="muted">—</span> }</td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          </section>
        }
      }
    </main>

    <!-- ===================================================================== dialogs -->
    @if (regionDialog(); as r) {
      <div class="backdrop" (click)="regionDialog.set(null)"><div class="modal" role="dialog" aria-modal="true" (click)="$event.stopPropagation()">
        <div class="modal-head"><h2>{{ r.region_id ? 'Edit region' : 'New region' }}</h2><button class="btn btn-sm" (click)="regionDialog.set(null)" aria-label="Close">✕</button></div>
        <div class="modal-body">
          @if (dialogError()) { <div class="alert alert-error">{{ dialogError() }}</div> }
          <div class="grid-2">
            <div class="field"><label for="rn">Name</label><input id="rn" type="text" [(ngModel)]="rf.name" /></div>
            <div class="field"><label for="rc">Code</label><input id="rc" type="text" class="mono" [disabled]="!!r.region_id" placeholder="AUTO" [(ngModel)]="rf.code" /></div>
          </div>
          <div class="field"><label for="rd">Description</label><input id="rd" type="text" [(ngModel)]="rf.description" /></div>
          @if (r.region_id) { <label class="check"><input type="checkbox" [(ngModel)]="rf.is_active" /> Region is active</label> }
        </div>
        <div class="modal-foot"><button class="btn" (click)="regionDialog.set(null)">Cancel</button><button class="btn btn-primary" (click)="saveRegion()">Save region</button></div>
      </div></div>
    }
    @if (countryDialog(); as c) {
      <div class="backdrop" (click)="countryDialog.set(null)"><div class="modal" role="dialog" aria-modal="true" (click)="$event.stopPropagation()">
        <div class="modal-head"><h2>{{ c.country_id ? 'Edit country' : 'New country' }}</h2><button class="btn btn-sm" (click)="countryDialog.set(null)" aria-label="Close">✕</button></div>
        <div class="modal-body">
          @if (dialogError()) { <div class="alert alert-error">{{ dialogError() }}</div> }
          <div class="grid-2">
            <div class="field"><label for="cn">Country name</label><input id="cn" type="text" [(ngModel)]="cf.name" /></div>
            <div class="field"><label for="ci">ISO code</label><input id="ci" type="text" class="mono" maxlength="2" [disabled]="!!c.country_id" placeholder="SG" [(ngModel)]="cf.iso2" /></div>
          </div>
          <div class="field"><label for="cr">Region</label><select id="cr" [(ngModel)]="cf.region_id">@for (r of hier()?.regions ?? []; track r.region_id) { <option [ngValue]="r.region_id">{{ r.name }}</option> }</select></div>
          <div class="grid-2">
            <div class="field"><label for="cl">Privacy law</label><input id="cl" type="text" [(ngModel)]="cf.regulation" /></div>
            <div class="field"><label for="cg">Regulator</label><input id="cg" type="text" [(ngModel)]="cf.regulator" /></div>
          </div>
          <div class="field"><label for="cno">Notes</label><input id="cno" type="text" [(ngModel)]="cf.notes" /></div>
        </div>
        <div class="modal-foot"><button class="btn" (click)="countryDialog.set(null)">Cancel</button><button class="btn btn-primary" (click)="saveCountry()">Save country</button></div>
      </div></div>
    }
  `,
  styles: `
    .small { font-size: 12.5px; } .top { margin: 2px 0 14px; }
    .preview { display: flex; align-items: center; gap: 14px; padding: 12px 16px; border: 1px solid; border-radius: 10px; min-height: 58px; }
    .preview img { height: 28px; max-width: 170px; object-fit: contain; }
    .preview .sep { width: 1px; height: 22px; }
    .preview .pill { margin-left: auto; padding: 4px 12px; border-radius: 8px; font-weight: 600; font-size: 13px; }
    .swatch { width: 46px; height: 38px; padding: 2px; border-radius: 8px; cursor: pointer; }
    .thumb { width: 54px; height: 34px; border-radius: 6px; border: 1px solid var(--border); display: grid; place-items: center; overflow: hidden; flex: none; }
    .thumb img { max-width: 48px; max-height: 26px; object-fit: contain; }
    .region { margin-bottom: 14px; } .region.off { opacity: 0.65; }
    .region-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; padding: 16px 18px 10px; flex-wrap: wrap; }
    .iso { display: inline-block; min-width: 26px; padding: 1px 6px; margin-right: 6px; border-radius: 5px; background: #eef2ff; color: #3730a3; font-weight: 700; font-size: 12px; text-align: center; }
    tr.off td { opacity: 0.55; }
    .chain { display: flex; gap: 8px; align-items: stretch; flex-wrap: wrap; }
    .chain .card { flex: 1; min-width: 210px; } .chain .arrow { align-self: center; color: var(--muted); font-size: 20px; }
    .pol { display: flex; flex-direction: column; padding: 8px 0; border-top: 1px solid var(--border); color: var(--text); } .pol:hover { text-decoration: none; background: #f8fafc; }
    tr.struck td { opacity: 0.55; } tr.struck td:first-child b { text-decoration: line-through; }
    .reset-card { margin-top: 14px; border-color: #fca5a5; }
  `,
})
export class Organisation {
  private api = inject(Api);
  private toasts = inject(Toasts);
  private confirm = inject(Confirms);
  private brand = inject(Branding);
  private sanitizer = inject(DomSanitizer);
  auth = inject(Auth);
  pretty = pretty; tone = tone; contrast = contrastText;

  tabs = [
    { id: 'branding', label: 'Company & banner' }, { id: 'hierarchy', label: 'Regions & countries' },
    { id: 'coverage', label: 'What applies where' }, { id: 'jurisdiction', label: 'Jurisdiction map' },
  ] as const;
  tab = signal<'branding' | 'hierarchy' | 'coverage' | 'jurisdiction'>('branding');

  orgs = signal<Organization[]>([]);
  form = signal<OrgForm>({ ...BLANK });
  seedHierarchy = true;
  busy = signal(false);
  clearing = signal(false);
  hier = signal<Hierarchy | null>(null);
  country = signal('');
  cov = signal<Coverage | null>(null);
  jur = signal<JurisdictionReport | null>(null);
  regionDialog = signal<Partial<Region> | null>(null);
  countryDialog = signal<Partial<Country> | null>(null);
  dialogError = signal('');
  rf = { name: '', code: '', description: '', is_active: true };
  cf = { region_id: 0, iso2: '', name: '', regulation: '', regulator: '', notes: '' };

  activeOrg = computed(() => this.orgs().find((o) => o.is_active) ?? null);
  fg = computed(() => contrastText(this.form().banner_color));
  previewLogo = computed(() => {
    const f = this.form();
    const l = f.logo_data || f.logo_url;
    return !l ? null : l.startsWith('data:image/') ? this.sanitizer.bypassSecurityTrustUrl(l) : l;
  });
  classifierGroups = computed(() => {
    const cs = this.cov()?.classifiers ?? [];
    const by = (lvl: string) => cs.filter((c) => c.scope_level === lvl);
    return [
      { title: 'Global library', items: by('GLOBAL') },
      { title: this.cov()?.region ? `${this.cov()!.region!.name} pack` : 'Region pack', items: by('REGION') },
      { title: this.cov()?.country ? `${this.cov()!.country!.name} pack` : 'Country pack', items: by('COUNTRY') },
    ].filter((g) => g.items.length);
  });

  constructor() { this.loadOrgs(true); }

  open(t: 'branding' | 'hierarchy' | 'coverage' | 'jurisdiction') {
    this.tab.set(t);
    if (t !== 'branding' && !this.hier()) this.loadHierarchy();
    if (t === 'coverage') this.loadCoverage();
    if (t === 'jurisdiction' && !this.jur()) this.api.jurisdiction().subscribe({ next: (j) => this.jur.set(j), error: (e) => this.toasts.error(errorMessage(e)) });
  }

  // ---- company
  loadOrgs(select = false) {
    this.api.orgs().subscribe((o) => {
      this.orgs.set(o);
      const cur = o.find((x) => x.org_id === this.form().org_id) ?? o.find((x) => x.is_active) ?? o[0];
      if (select && cur) this.edit(cur);
    });
  }
  edit(o: Organization | null) {
    if (!o) return;
    this.form.set({ org_id: o.org_id, name: o.name, tagline: o.tagline ?? '', logo_url: o.logo_url ?? '', banner_color: o.banner_color, primary_color: o.primary_color,
                    logo_data: o.logo?.startsWith('data:') ? o.logo : '' });
  }
  startNew() { this.form.set({ ...BLANK }); this.seedHierarchy = true; }
  set<K extends keyof OrgForm>(k: K, v: OrgForm[K]) { this.form.update((f) => ({ ...f, [k]: v })); }
  thumb(o: Organization) { return !o.logo ? null : o.logo.startsWith('data:image/') ? this.sanitizer.bypassSecurityTrustUrl(o.logo) : o.logo; }

  upload(ev: Event) {
    const file = (ev.target as HTMLInputElement).files?.[0];
    if (!file) return;
    if (file.size > 500 * 1024) { this.toasts.error('That logo is larger than 500 KB'); return; }
    const r = new FileReader();
    r.onload = () => this.form.update((f) => ({ ...f, logo_data: String(r.result), logo_url: '' }));
    r.readAsDataURL(file);
    (ev.target as HTMLInputElement).value = '';
  }
  removeLogo() { this.form.update((f) => ({ ...f, logo_data: '', logo_url: '' })); }

  save() {
    const f = this.form();
    const body = { name: f.name.trim(), tagline: f.tagline || null, logo_url: f.logo_url || null, logo_data: f.logo_data || null,
                   clear_logo: !f.logo_url && !f.logo_data, banner_color: f.banner_color, primary_color: f.primary_color, seed_hierarchy: this.seedHierarchy };
    this.busy.set(true);
    const call = f.org_id ? this.api.updateOrg(f.org_id, body) : this.api.createOrg(body);
    call.subscribe({
      next: (o) => {
        this.busy.set(false);
        this.toasts.ok(f.org_id ? 'Company profile saved' : `${o.name} added. Make it active to use it.`);
        this.loadOrgs();
        if (!f.org_id) this.form.update((x) => ({ ...x, org_id: o.org_id }));
        if (o.is_active) this.brand.load();
      },
      error: (e) => { this.busy.set(false); this.toasts.error(errorMessage(e)); },
    });
  }
  async activate(o: Organization) {
    if (!await this.confirm.ask(`Make ${o.name} the active company? The banner, regions and classifier packs switch to its configuration.`)) return;
    this.api.activateOrg(o.org_id).subscribe({
      next: () => { this.toasts.ok(`${o.name} is now active`); this.hier.set(null); this.jur.set(null); this.cov.set(null); this.loadOrgs(true); this.brand.load(); },
      error: (e) => this.toasts.error(errorMessage(e)),
    });
  }
  async remove(o: Organization) {
    if (!await this.confirm.ask(`Delete ${o.name} and its regions and countries?`)) return;
    this.api.deleteOrg(o.org_id).subscribe({ next: () => { this.toasts.ok('Company deleted'); this.loadOrgs(true); }, error: (e) => this.toasts.error(errorMessage(e)) });
  }
  async clearAll() {
    if (!await this.confirm.ask('Clear ALL findings, scans, violations, remediation tasks, erasure requests, legal holds and archive files, restore the source tables to '
      + 'their original snapshot, and reset every document source (findings, redaction history and semantic search index)? Companies, regions, countries '
      + 'and policies are kept. This cannot be undone.')) return;
    this.clearing.set(true);
    this.api.clearAll().subscribe({
      next: (r) => { this.clearing.set(false); this.toasts.ok(`Cleared. ${r.tables_restored} source table(s) restored, ${r.chunks_cleared ?? 0} vector chunk(s) removed from the index.`); },
      error: (e) => { this.clearing.set(false); this.toasts.error(errorMessage(e)); },
    });
  }

  // ---- hierarchy
  loadHierarchy(after?: () => void) {
    this.api.hierarchy().subscribe({ next: (h) => { this.hier.set(h); if (!this.country()) this.country.set(h.regions.flatMap((r) => r.countries).find((c) => c.iso2 === 'DE')?.iso2 ?? h.regions[0]?.countries[0]?.iso2 ?? ''); after?.(); }, error: (e) => this.toasts.error(errorMessage(e)) });
  }
  private reload() { this.hier.set(null); this.cov.set(null); this.loadHierarchy(() => { if (this.tab() === 'coverage') this.loadCoverage(); }); }

  saveRegion() {
    const r = this.regionDialog()!;
    const body = { name: this.rf.name, code: this.rf.code || null, description: this.rf.description || null, is_active: this.rf.is_active };
    (r.region_id ? this.api.updateRegion(r.region_id, body) : this.api.createRegion(body)).subscribe({
      next: () => { this.regionDialog.set(null); this.toasts.ok('Region saved'); this.reload(); },
      error: (e) => this.dialogError.set(errorMessage(e)),
    });
  }
  async deleteRegion(r: Region) {
    if (!await this.confirm.ask(`Delete region ${r.name}?`)) return;
    this.api.deleteRegion(r.region_id).subscribe({ next: () => { this.toasts.ok('Region deleted'); this.reload(); }, error: (e) => this.toasts.error(errorMessage(e)) });
  }
  saveCountry() {
    const c = this.countryDialog()!;
    const body = { region_id: this.cf.region_id, iso2: this.cf.iso2.toUpperCase(), name: this.cf.name, regulation: this.cf.regulation || null, regulator: this.cf.regulator || null, notes: this.cf.notes || null, is_active: c.is_active ?? true };
    (c.country_id ? this.api.updateCountry(c.country_id, body) : this.api.createCountry(body)).subscribe({
      next: () => { this.countryDialog.set(null); this.toasts.ok('Country saved'); this.reload(); },
      error: (e) => this.dialogError.set(errorMessage(e)),
    });
  }
  toggleCountry(c: Country, on: boolean) {
    this.api.updateCountry(c.country_id, { region_id: c.region_id, iso2: c.iso2, name: c.name, regulation: c.regulation, regulator: c.regulator, notes: c.notes, is_active: on }).subscribe({
      next: () => { this.toasts.ok(`${c.name} ${on ? 'activated' : 'deactivated'}`); this.reload(); }, error: (e) => this.toasts.error(errorMessage(e)),
    });
  }
  async deleteCountry(c: Country) {
    if (!await this.confirm.ask(`Delete ${c.name}?`)) return;
    this.api.deleteCountry(c.country_id).subscribe({ next: () => { this.toasts.ok('Country deleted'); this.reload(); }, error: (e) => this.toasts.error(errorMessage(e)) });
  }

  // ---- coverage
  pickCountry(iso: string) { this.country.set(iso); this.loadCoverage(); }
  loadCoverage() {
    if (!this.country()) { this.loadHierarchy(() => this.loadCoverage()); return; }
    this.api.coverage(this.country()).subscribe({ next: (c) => this.cov.set(c), error: (e) => this.toasts.error(errorMessage(e)) });
  }

  // ---- dialogs
  openRegion(v: Partial<Region>) {
    this.rf = { name: v.name ?? '', code: v.code ?? '', description: v.description ?? '', is_active: v.is_active ?? true };
    this.dialogError.set('');
    this.regionDialog.set(v);
  }
  openCountry(v: Partial<Country>) {
    this.cf = { region_id: v.region_id ?? this.hier()?.regions[0]?.region_id ?? 0, iso2: v.iso2 ?? '', name: v.name ?? '',
                regulation: v.regulation ?? '', regulator: v.regulator ?? '', notes: v.notes ?? '' };
    this.dialogError.set('');
    this.countryDialog.set(v);
  }
}
