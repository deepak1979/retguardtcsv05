import { Component, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { Auth } from '../core/auth';
import { errorMessage } from '../core/api';
import { Branding } from '../core/branding';

@Component({
  selector: 'app-login',
  imports: [ReactiveFormsModule],
  template: `
    <div class="split">
      <section class="brand-panel">
        <div class="brand-row">
          @if (brand.logo(); as logo) {
            <span class="logo-pill"><img [src]="logo" [alt]="brand.name()" (error)="brand.logoFailed.set(true)" /></span>
          } @else {
            <span class="co">{{ brand.name() }}</span>
          }
          <span class="prod">Retention<b>Guard</b></span>
        </div>
        <h1>Discover, classify and govern sensitive insurance data{{ brand.name() ? ' at ' + brand.name() : '' }}.</h1>
        <p>Scan your data, classify what is personal, and let policies for every region and country decide how it is masked, retained and erased.</p>
        <ul>
          <li>Find PII with pattern, dictionary and name evidence</li>
          <li>Apply retention and masking rules to what the scanner found</li>
          <li>Apply each country's rules, and honour erasure requests with retention and legal holds respected</li>
          <li>Approve, execute, verify, and keep the evidence</li>
        </ul>
      </section>

      <section class="form-panel">
        <form class="card card-pad" [formGroup]="form" (ngSubmit)="submit()">
          <h2>Sign in</h2>
          <p class="muted sub">Use your data governance account.</p>

          @if (error()) { <div class="alert alert-error" role="alert">{{ error() }}</div> }

          <div class="field">
            <label for="u">Username</label>
            <input id="u" type="text" formControlName="username" autocomplete="username" autofocus />
          </div>
          <div class="field">
            <label for="p">Password</label>
            <input id="p" type="password" formControlName="password" autocomplete="current-password" />
          </div>
          <button class="btn btn-primary full" type="submit" [disabled]="form.invalid || loading()">
            {{ loading() ? 'Signing in…' : 'Sign in' }}
          </button>
        </form>
      </section>
    </div>
  `,
  styles: `
    .split { display: grid; grid-template-columns: 1.1fr 1fr; min-height: 100vh; }
    .brand-panel { background: linear-gradient(160deg, var(--brand-dark), var(--brand-mid)); color: #fff; padding: 64px 56px; display: flex; flex-direction: column; justify-content: center; gap: 8px; }
    .brand-row { display: flex; align-items: center; gap: 16px; margin-bottom: 32px; flex-wrap: wrap; }
    .logo-pill { background: #fff; border-radius: 10px; padding: 8px 14px; display: inline-flex; }
    .logo-pill img { height: 30px; width: auto; max-width: 190px; display: block; }
    .co { font-size: 22px; font-weight: 700; }
    .prod { font-size: 18px; color: #e2e8f0; } .prod b { color: var(--primary-soft); }
    .brand-panel h1 { font-size: 32px; max-width: 460px; }
    .brand-panel p { color: #cbd5e1; max-width: 440px; font-size: 15px; }
    ul { color: #e2e8f0; padding-left: 18px; line-height: 2; margin-top: 12px; }
    .form-panel { display: grid; place-items: center; padding: 24px; }
    form { width: min(380px, 100%); }
    .sub { margin: 4px 0 18px; }
    .full { width: 100%; justify-content: center; padding: 10px; }
    @media (max-width: 820px) { .split { grid-template-columns: 1fr; } .brand-panel { display: none; } }
  `,
})
export class Login {
  private auth = inject(Auth);
  private router = inject(Router);
  private fb = inject(FormBuilder).nonNullable;
  brand = inject(Branding);

  form = this.fb.group({ username: ['', Validators.required], password: ['', Validators.required] });
  loading = signal(false);
  error = signal('');

  submit() {
    if (this.form.invalid) return;
    this.loading.set(true);
    this.error.set('');
    const { username, password } = this.form.getRawValue();
    this.auth.login(username, password).subscribe({
      next: () => this.router.navigateByUrl('/dashboard'),
      error: (e) => {
        this.error.set(errorMessage(e));
        this.loading.set(false);
      },
    });
  }
}
