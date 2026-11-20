import { ApplicationConfig, inject, provideAppInitializer, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { provideRouter, withComponentInputBinding } from '@angular/router';
import { routes } from './app.routes';
import { Auth, authInterceptor } from './core/auth';
import { apiBaseInterceptor } from './core/api-base';
import { Branding } from './core/branding';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes, withComponentInputBinding()),
    provideHttpClient(withInterceptors([apiBaseInterceptor, authInterceptor])),
    provideAppInitializer(() => inject(Branding).load()),
    // Must resolve before the router's first navigation/guard check - see Auth.tryObo()'s own
    // comment for why.
    provideAppInitializer(() => inject(Auth).tryObo()),
  ],
};
