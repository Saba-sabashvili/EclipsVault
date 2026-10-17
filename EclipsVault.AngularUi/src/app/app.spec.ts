import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Me } from './account/me';
import { App } from './app';
import { appConfig } from './app.config';

const me: Me = {
  username: 'vault-admin',
  displayName: 'Vault Administrator',
  clearance: 'Top Secret',
  project: 'GLOBAL',
  areas: ['access', 'profile', 'license'],
  avatarUrl: '/Profile/Avatar?v=0',
  licenseNotice: null,
};

describe('App shell', () => {
  let backend: HttpTestingController;

  async function render(answer: (request: ReturnType<HttpTestingController['expectOne']>) => void) {
    TestBed.configureTestingModule({ providers: [...appConfig.providers, provideHttpClientTesting()] });
    backend = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(App);
    // Not whenStable(): it would wait for the very request this test answers.
    fixture.detectChanges();
    answer(backend.expectOne('/api/ui/me'));
    await fixture.whenStable();
    return fixture.nativeElement as HTMLElement;
  }

  afterEach(() => backend.verify());

  it('shows the problem code instead of a blank sidebar when /api/ui/me fails', async () => {
    const shell = await render((request) =>
      request.flush(
        { status: 503, code: 'audit_unavailable', title: 'The audit trail is unavailable.' },
        { status: 503, statusText: 'Service Unavailable' },
      ));

    const alert = shell.querySelector('.sidebar [role="alert"]');
    expect(alert?.textContent).toContain('audit_unavailable');
    expect(shell.querySelector('.sidenav')).toBeNull();
    expect(shell.querySelector('.account-menu')).toBeNull();
  });

  it('renders the account menu and no licence notice when the server sends none', async () => {
    const shell = await render((request) => request.flush(me));

    expect(shell.querySelector('.sidebar-footer .account-menu .user-name')?.textContent?.trim()).toBe('Vault Administrator');
    expect(shell.querySelector('.notice')).toBeNull();
    expect(shell.textContent).not.toContain('unlicensed');
  });

  it('renders the licence notice the server sends, linking to the licence page', async () => {
    const shell = await render((request) => request.flush({
      ...me,
      licenseNotice: { title: 'Running unlicensed.', text: 'No license key is installed. This changes nothing.' },
    }));

    const notice = shell.querySelector('.content .notice.notice-warn');
    expect(notice?.querySelector('strong')?.textContent).toBe('Running unlicensed.');
    expect(notice?.textContent).toContain('No license key is installed. This changes nothing.');
    expect(notice?.querySelector('a')?.getAttribute('href')).toBe('/License');
  });
});
