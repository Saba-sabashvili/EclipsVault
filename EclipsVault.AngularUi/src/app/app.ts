import { Component, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { CurrentAccount } from './account/current-account';
import { AccountMenu } from './shell/account-menu';
import { SidebarNav } from './shell/sidebar-nav';
import { UiApiError } from './ui-api/ui-api-errors';

@Component({
  imports: [RouterOutlet, SidebarNav, AccountMenu],
  selector: 'app-root',
  template: `
    <div class="shell">
      <aside class="sidebar">
        <a class="brand" href="/">
          <span class="brand-mark" aria-hidden="true"></span>
          <span class="brand-name">EclipsVault</span>
        </a>
        @if (me.hasValue()) {
          <app-sidebar-nav [areas]="me.value().areas" />
          <div class="sidebar-footer">
            <app-account-menu [me]="me.value()" />
          </div>
        } @else if (me.error(); as error) {
          <p class="sidebar-error" role="alert">Could not load your account ({{ problemCode(error) }}).</p>
        }
      </aside>
      <main class="content">
        <!-- Shown only when the server sends it: it decides who may see a licence notice (ADR-0012). -->
        @if (me.hasValue() && me.value().licenseNotice; as notice) {
          <div class="notice notice-warn">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>
            <span>
              <strong>{{ notice.title }}</strong> {{ notice.text }}
              <a href="/License">View license</a>
            </span>
          </div>
        }
        <router-outlet />
        <footer class="content-footer">
          EclipsVault — envelope-encrypted secret management. Everything is audited.
        </footer>
      </main>
    </div>
  `,
})
export class App {
  protected readonly me = inject(CurrentAccount).me;

  protected problemCode(error: Error): string {
    return error instanceof UiApiError ? error.code : 'unknown';
  }
}
