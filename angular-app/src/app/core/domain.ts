import { Injectable, signal } from '@angular/core';

export type DomainCode = 'INSURANCE' | 'BANKING';

/** The business domain the demo is currently set up for (Insurance / Banking), shared across every page
 * that needs to filter by it - not just Data sources, where the toggle itself lives. Persisted so a reload
 * doesn't silently flip it back. A data source's own `domain` field (set at creation time, see rg/api.py's
 * source_create) is matched against `label()`; a source with no domain recorded stays visible under either
 * domain rather than silently vanishing. */
@Injectable({ providedIn: 'root' })
export class DomainScope {
  domain = signal<DomainCode>((localStorage.getItem('rg_domain') as DomainCode) || 'INSURANCE');

  set(d: DomainCode) {
    this.domain.set(d);
    localStorage.setItem('rg_domain', d);
  }

  label(): string {
    return this.domain() === 'BANKING' ? 'Banking' : 'Insurance';
  }

  /** True if a row belonging to `sourceDomain` (e.g. a Source's own `.domain`) should be visible right now. */
  matches(sourceDomain: string | null | undefined): boolean {
    return !sourceDomain || sourceDomain === this.label();
  }
}
