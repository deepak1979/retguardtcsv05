import { Routes } from '@angular/router';
import { authGuard, guestGuard } from './core/auth';
import { Login } from './login/login';
import { Shell } from './shell/shell';
import { Dashboard } from './dashboard/dashboard';
import { Sources } from './sources/sources';
import { Documents } from './documents/documents';
import { Redaction } from './redaction/redaction';
import { Findings } from './findings/findings';
import { Lineage } from './lineage/lineage';
import { PoliciesList } from './policies/policies-list';
import { PolicyDetail } from './policies/policy-detail';
import { Remediation } from './remediation/remediation';
import { Erasure } from './erasure/erasure';
import { LegalHolds } from './legalholds/legal-holds';
import { AuditLog } from './audit/audit-log';
import { Organisation } from './org/organisation';

export const routes: Routes = [
  { path: 'login', component: Login, canActivate: [guestGuard] },
  {
    path: '',
    component: Shell,
    canActivate: [authGuard],
    children: [
      { path: 'dashboard', component: Dashboard },
      { path: 'sources', component: Sources },
      { path: 'documents', component: Documents },
      { path: 'findings', component: Findings },
      { path: 'lineage', component: Lineage },
      { path: 'policies', component: PoliciesList },
      { path: 'policies/:id', component: PolicyDetail },
      { path: 'remediation', component: Remediation },
      { path: 'redaction', component: Redaction },
      // Hidden for now (no embedding model on this workspace) - redirect rather than remove, so
      // turning it back on later is just restoring these two lines plus the nav link in shell.ts.
      { path: 'semantic-search', redirectTo: 'dashboard' },
      { path: 'erasure', component: Erasure },
      { path: 'legal-holds', component: LegalHolds },
      { path: 'organisation', component: Organisation },
      { path: 'audit', component: AuditLog },
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
    ],
  },
  { path: '**', redirectTo: '' },
];
