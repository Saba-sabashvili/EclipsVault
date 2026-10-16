import { Component, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { CurrentAccount } from './account/current-account';
import { SidebarNav } from './shell/sidebar-nav';

@Component({
  imports: [RouterOutlet, SidebarNav],
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
        }
      </aside>
      <main class="content">
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
}
