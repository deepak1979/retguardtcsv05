import { Component, inject, input, output, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Api, errorMessage } from '../core/api';
import { pretty } from '../core/format';
import { Lookups, Policy } from '../core/models';

/** Create / edit dialog for a policy. Emits the saved policy or a cancel. */
@Component({
  selector: 'app-policy-form',
  imports: [ReactiveFormsModule],
  template: `
    <div class="backdrop" (click)="cancelled.emit()">
      <form class="modal" role="dialog" aria-modal="true" [formGroup]="form" (ngSubmit)="save()" (click)="$event.stopPropagation()">
        <div class="modal-head">
          <h2>{{ policy() ? 'Edit policy' : 'New policy' }}</h2>
          <button type="button" class="btn btn-sm" (click)="cancelled.emit()" aria-label="Close">✕</button>
        </div>
        <div class="modal-body">
          @if (error()) { <div class="alert alert-error">{{ error() }}</div> }

          <div class="field">
            <label for="pn">Policy name</label>
            <input id="pn" type="text" formControlName="name" [class.invalid]="touched('name')" />
            @if (touched('name')) { <span class="err">Enter a name of at least 3 characters.</span> }
          </div>
          <div class="field">
            <label for="pd">Description</label>
            <textarea id="pd" formControlName="description"></textarea>
          </div>
          <div class="grid-2">
            <div class="field">
              <label for="pc">Data category</label>
              <select id="pc" formControlName="data_category">
                @for (c of lookups().data_categories; track c) {
                  <option [value]="c">{{ pretty(c) }}</option>
                }
              </select>
              <span class="hint">{{ categoryHint() }}</span>
            </div>
            <div class="field">
              <label for="pr">Regulation</label>
              <select id="pr" formControlName="regulation">
                @for (r of lookups().regulations; track r) { <option [value]="r">{{ pretty(r) }}</option> }
              </select>
            </div>
            <div class="field">
              <label for="ps">Status</label>
              <select id="ps" formControlName="status">
                @for (s of lookups().policy_statuses; track s) { <option [value]="s">{{ pretty(s) }}</option> }
              </select>
            </div>
            <div class="field">
              <label for="pe">Effective from</label>
              <input id="pe" type="date" formControlName="effective_from" />
            </div>
          </div>

          <fieldset class="scope">
            <legend>Where it applies</legend>
            <div class="grid-2">
              <div class="field">
                <label for="psl">Scope</label>
                <select id="psl" formControlName="scope_level" (change)="scopeChanged()">
                  <option value="GLOBAL">Global (every country)</option>
                  <option value="REGION">A region</option>
                  <option value="COUNTRY">One country</option>
                </select>
              </div>
              @if (level() === 'REGION') {
                <div class="field">
                  <label for="psr">Region</label>
                  <select id="psr" formControlName="region_id">
                    @for (r of lookups().regions; track r.region_id) { <option [ngValue]="r.region_id">{{ r.name }}</option> }
                  </select>
                </div>
              }
              @if (level() === 'COUNTRY') {
                <div class="field">
                  <label for="psc">Country</label>
                  <select id="psc" formControlName="country_id">
                    @for (r of lookups().regions; track r.region_id) {
                      <optgroup [label]="r.name">@for (c of countriesOf(r.region_id); track c.country_id) { <option [ngValue]="c.country_id">{{ c.name }} ({{ c.iso2 }})</option> }</optgroup>
                    }
                  </select>
                </div>
              }
            </div>
            @if (level() !== 'GLOBAL') {
              <label class="check"><input type="checkbox" formControlName="override_parent" /> Override broader policies of the same kind</label>
              <span class="hint" style="display:block;margin:-8px 0 10px">Off: this policy adds to what the broader scopes already require (the longest retention and strongest masking win).
                On: for this scope it replaces the broader rule, so a country can shorten a retention period as well as extend it.</span>
            }
          </fieldset>
        </div>
        <div class="modal-foot">
          <button type="button" class="btn" (click)="cancelled.emit()">Cancel</button>
          <button type="submit" class="btn btn-primary" [disabled]="saving()">{{ saving() ? 'Saving…' : 'Save policy' }}</button>
        </div>
      </form>
    </div>
  `,
  styles: `
    .scope { border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px 2px; margin: 0 0 14px; }
    .scope legend { padding: 0 6px; font-weight: 600; font-size: 13px; color: var(--primary-dark); }
  `,
})
export class PolicyForm {
  private api = inject(Api);
  private fb = inject(FormBuilder).nonNullable;
  pretty = pretty;

  lookups = input.required<Lookups>();
  policy = input<Policy | null>(null);
  saved = output<Policy>();
  cancelled = output<void>();

  form = this.fb.group({
    name: ['', [Validators.required, Validators.minLength(3)]],
    description: [''],
    data_category: ['PII'],
    regulation: ['GDPR'],
    status: ['DRAFT'],
    effective_from: [''],
    scope_level: ['GLOBAL'],
    region_id: [null as number | null],
    country_id: [null as number | null],
    override_parent: [false],
  });
  level = toSignal(this.form.controls.scope_level.valueChanges, { initialValue: 'GLOBAL' });
  saving = signal(false);
  error = signal('');

  ngOnInit() {
    const p = this.policy();
    if (p) this.form.patchValue({ ...p, description: p.description ?? '', effective_from: (p.effective_from ?? '').slice(0, 10), override_parent: !!p.override_parent });
  }

  countriesOf(regionId: number) { return this.lookups().countries.filter((c) => c.region_id === regionId); }

  scopeChanged() {
    const f = this.form.controls;
    f.region_id.setValue(f.scope_level.value === 'REGION' ? this.lookups().regions[0]?.region_id ?? null : null);
    f.country_id.setValue(f.scope_level.value === 'COUNTRY' ? this.lookups().countries[0]?.country_id ?? null : null);
  }

  touched(c: 'name') { const x = this.form.controls[c]; return x.invalid && (x.dirty || x.touched); }

  categoryHint() {
    const n = this.lookups().data_elements.filter((e) => e.category === this.form.controls.data_category.value);
    const names = n.map((e) => e.name);
    return n.length ? `${n.length} classifiers, e.g. ${names.slice(0, 4).join(', ')}${names.length > 4 ? ' …' : ''}` : 'No classifier produces this category; use table-scoped rules';
  }

  save() {
    if (this.form.invalid) { this.form.markAllAsTouched(); return; }
    this.saving.set(true);
    this.error.set('');
    const v = this.form.getRawValue();
    const body = { ...v, effective_from: v.effective_from || null, region_id: v.scope_level === 'GLOBAL' ? null : v.region_id, country_id: v.scope_level === 'COUNTRY' ? v.country_id : null } as any;
    const p = this.policy();
    (p ? this.api.updatePolicy(p.policy_id, body) : this.api.createPolicy(body)).subscribe({
      next: (res) => this.saved.emit(res),
      error: (e) => { this.error.set(errorMessage(e)); this.saving.set(false); },
    });
  }
}
