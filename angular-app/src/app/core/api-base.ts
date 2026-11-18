import { HttpInterceptorFn } from '@angular/common/http';
import { environment } from '../../environments/environment';

/** Prefixes relative /api/... calls with environment.apiBase. No-op in dev (apiBase is ''),
 * where the proxy.conf.json dev-server proxy still handles /api as before. */
export const apiBaseInterceptor: HttpInterceptorFn = (req, next) => {
  if (!environment.apiBase || !req.url.startsWith('/api')) return next(req);
  return next(req.clone({ url: environment.apiBase + req.url }));
};
