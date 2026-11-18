import { Injectable, signal } from '@angular/core';

export interface Toast { id: number; text: string; kind: 'ok' | 'error'; }

@Injectable({ providedIn: 'root' })
export class Toasts {
  readonly items = signal<Toast[]>([]);
  private next = 1;

  ok(text: string) { this.push(text, 'ok'); }
  error(text: string) { this.push(text, 'error'); }

  private push(text: string, kind: Toast['kind']) {
    const id = this.next++;
    this.items.update((l) => [...l, { id, text, kind }]);
    setTimeout(() => this.items.update((l) => l.filter((t) => t.id !== id)), 3500);
  }
}
