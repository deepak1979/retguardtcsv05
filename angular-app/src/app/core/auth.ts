import { HttpClient, HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, tap, throwError } from 'rxjs';
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
