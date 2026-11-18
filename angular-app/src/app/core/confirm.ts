import { Injectable, signal } from '@angular/core';

interface ConfirmState { message: string; resolve: (ok: boolean) => void; }

@Injectable({ providedIn: 'root' })
export class Confirms {
  readonly state = signal<ConfirmState | null>(null);

  ask(message: string): Promise<boolean> {
    return new Promise((resolve) => this.state.set({ message, resolve }));
  }

  respond(ok: boolean) {
    this.state()?.resolve(ok);
    this.state.set(null);
  }
}
