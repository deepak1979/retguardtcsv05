import { Injectable, computed, inject, signal } from '@angular/core';
import { DomSanitizer, SafeUrl } from '@angular/platform-browser';
import { firstValueFrom } from 'rxjs';
import { Api } from './api';
import { BrandingInfo } from './models';

const DEFAULT: BrandingInfo = { org_id: null, name: 'RetentionGuard', tagline: '', logo: null, banner_color: '#0f2a43', primary_color: '#0f766e' };

type RGB = [number, number, number];

function toRgb(hex: string): RGB {
  const h = /^#[0-9a-f]{6}$/i.test(hex) ? hex : '#0f766e';
  return [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
}
const toHex = (c: RGB) => '#' + c.map((v) => Math.round(Math.max(0, Math.min(255, v))).toString(16).padStart(2, '0')).join('');
const mix = (a: RGB, b: RGB, t: number): RGB => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
const luminance = ([r, g, b]: RGB) => {
  const f = (v: number) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
};

/** The company the app is configured for: name, logo and colours. Applied as CSS variables so every screen follows. */
@Injectable({ providedIn: 'root' })
export class Branding {
  private api = inject(Api);
  private sanitizer = inject(DomSanitizer);

  readonly info = signal<BrandingInfo>(DEFAULT);
  readonly logoFailed = signal(false);
  readonly name = computed(() => this.info().name);
  readonly tagline = computed(() => this.info().tagline);
  /** Uploaded logos are data: URLs. The server has already rejected scripts in SVGs, so they are safe to show. */
  readonly logo = computed<string | SafeUrl | null>(() => {
    const l = this.info().logo;
    if (!l || this.logoFailed()) return null;
    return l.startsWith('data:image/') ? this.sanitizer.bypassSecurityTrustUrl(l) : l;
  });

  async load(): Promise<void> {
    try {
      this.apply(await firstValueFrom(this.api.branding()));
    } catch {
      this.apply(DEFAULT);
    }
  }

  apply(b: BrandingInfo): void {
    this.logoFailed.set(false);
    this.info.set(b);
    const primary = toRgb(b.primary_color), banner = toRgb(b.banner_color);
    const white: RGB = [255, 255, 255], black: RGB = [0, 0, 0];
    const light = luminance(banner) > 0.5;                       // dark text on a light banner, white on a dark one
    const fg = light ? '#0f172a' : '#ffffff';
    const fgRgb = toRgb(fg);
    const vars: Record<string, string> = {
      '--primary': toHex(primary),
      '--primary-dark': toHex(mix(primary, black, 0.22)),
      '--primary-soft': toHex(mix(primary, white, 0.88)),
      '--brand-dark': toHex(mix(primary, black, 0.6)),
      '--brand-mid': toHex(mix(primary, black, 0.32)),
      '--banner-bg': toHex(banner),
      '--banner-fg': fg,
      '--banner-fg-muted': toHex(mix(fgRgb, banner, 0.3)),
      '--banner-hover': `rgba(${fgRgb.join(',')}, 0.08)`,
      '--banner-active': `rgba(${fgRgb.join(',')}, 0.14)`,
      '--banner-border': light ? '#e2e8f0' : 'rgba(255,255,255,0.12)',
    };
    const root = document.documentElement.style;
    for (const [k, v] of Object.entries(vars)) root.setProperty(k, v);
    document.title = b.name === 'RetentionGuard' ? 'RetentionGuard' : `${b.name} · RetentionGuard`;
  }
}

/** Readable text colour (dark or white) for a given background colour. */
export function contrastText(hex: string): string {
  return luminance(toRgb(hex)) > 0.5 ? '#0f172a' : '#ffffff';
}
