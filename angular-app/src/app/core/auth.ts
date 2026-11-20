import { HttpClient, HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, tap, throwError } from 'rxjs';
import { errorMessage } from './api';
import { User } from './models';

const KEY = 'retention.session';

@Injectable({ providedIn: 'root' })
export class Auth {
  private http = inject(HttpClient);
  private router = inject(Router);

  private session = signal<{ token: string; user: User } | null>(this.restore());
  readonly user = computed(() => this.session()?.user ?? null);
  readonly token = computed(() => this.session()?.token ?? null);
  readonly isAdmin = computed(() => this.user()?.role === 'admin');
  /** admin or steward: can drive scans, review findings and author policies */
  readonly canEdit = computed(() => ['admin', 'steward'].includes(this.user()?.role ?? ''));

  login(username: string, password: string) {
    return this.http
      .post<{ token: string; user: User }>('/api/auth/login', { username, password })
      .pipe(tap((s) => this.persist(s)));
  }

  // v05 (TCS): called once at app startup (see app.config.ts's provideAppInitializer), before the
  // router's first guard check. Databricks Apps' reverse proxy already authenticated this browser via
  // Entra ID to even load the page - this just asks the backend who that is and what role their
  // workspace group membership resolves to (rg/api.py's current_user()/_resolve_obo()). No local
  // token needed for this path: an empty string keeps authInterceptor from attaching X-Rg-Token
  // (which is reserved for the deepak/deepak123 password fallback), while every other request still
  // carries whatever the browser/proxy already attaches for OBO on its own. Resolves either way -
  // failure just leaves the session unset, so the router falls through to the normal /login screen.
  // Set only when OBO was attempted and didn't produce a session - rg/api.py's current_user() puts a
  // real diagnostic in the error body (no OBO header at all vs. a header that failed to resolve vs. a
  // resolved identity with no matching group), surfaced on /login so this is visible without devtools.
  readonly oboError = signal('');

  tryObo(): Promise<void> {
    return new Promise((resolve) => {
      this.http.get<User>('/api/auth/me').subscribe({
        next: (user) => { this.persist({ token: '', user }); resolve(); },
        // Authoritative at boot: a stale/invalid session left over in sessionStorage from a previous
        // visit must not make the shell show as logged in while every real API call 401/403s underneath
        // it - clear it here so authGuard sends an unresolved visitor to a clean /login instead.
        error: (e: HttpErrorResponse) => {
          // errorMessage() (not ad-hoc e.error?.detail extraction) is the same robust parser every
          // other component in this app already relies on - it always returns a non-empty string,
          // unlike a hand-rolled chain of ?? fallbacks that silently produced "" when the Apps
          // reverse proxy returned something other than the exact JSON shape expected (confirmed
          // live: a blank login page, no banner, on a real failure).
          this.oboError.set(errorMessage(e));
          this.persist(null);
          resolve();
        },
      });
    });
  }

  logout() {
    if (this.token()) this.http.post('/api/auth/logout', {}).subscribe({ error: () => {} });
    this.clear();
  }

  /** Drop the local session and go to /login (also used when the API says 401). */
  clear() {
    this.persist(null);
    this.router.navigateByUrl('/login');
  }

  private persist(s: { token: string; user: User } | null) {
    this.session.set(s);
    try {
      s ? sessionStorage.setItem(KEY, JSON.stringify(s)) : sessionStorage.removeItem(KEY);
    } catch {}
  }

  private restore() {
    try {
      return JSON.parse(sessionStorage.getItem(KEY) ?? 'null');
    } catch {
      return null;
    }
  }
}

// v04: a custom header, not the standard Authorization header - confirmed by direct diagnostic
// logging that Databricks Apps' own reverse proxy (which gates every request behind its own OAuth
// check) does not forward an application-chosen `Authorization: Bearer ...` value through to the
// app container untouched (it reserves that header for its own SSO use). A custom header name isn't
// reserved the same way - see rg/api.py's current_user() for the matching backend side.
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(Auth);
  const token = auth.token();
  const authed = token ? req.clone({ setHeaders: { 'X-Rg-Token': token } }) : req;
  return next(authed).pipe(
    catchError((e: HttpErrorResponse) => {
      if (e.status === 401 && !req.url.endsWith('/auth/login') && token) auth.clear();
      return throwError(() => e);
    }),
  );
};

export const authGuard: CanActivateFn = () => {
  const auth = inject(Auth);
  return auth.user() ? true : inject(Router).parseUrl('/login');
};

// v05 (TCS): the inverse of authGuard, on the /login route itself. tryObo() (app.config.ts's
// provideAppInitializer) resolves BEFORE the router's first navigation, but only decides what the
// session signal holds - it never redirects anyone off whatever URL they actually landed on. Without
// this, a visitor who types/bookmarks /login directly stays stuck on the sign-in form even once OBO
// has silently authenticated them behind the scenes (confirmed live: a real 200 from /api/auth/me,
// session set, still sitting on the login page with no further action).
export const guestGuard: CanActivateFn = () => {
  const auth = inject(Auth);
  return auth.user() ? inject(Router).parseUrl('/dashboard') : true;
};
