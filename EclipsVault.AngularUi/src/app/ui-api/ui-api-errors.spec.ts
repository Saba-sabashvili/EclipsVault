import { HttpClient, HttpErrorResponse, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { DOCUMENT } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { signInUrl, UiApiError, uiApiErrors } from './ui-api-errors';

describe('uiApiErrors', () => {
  const assign = vi.fn();
  let http: HttpClient;
  let backend: HttpTestingController;

  beforeEach(() => {
    assign.mockReset();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([uiApiErrors])),
        provideHttpClientTesting(),
        { provide: DOCUMENT, useValue: { location: { pathname: '/Access', search: '?tab=grid', assign } } },
      ],
    });
    http = TestBed.inject(HttpClient);
    backend = TestBed.inject(HttpTestingController);
  });

  afterEach(() => backend.verify());

  it('sends a 401 to sign-in, returning to this page, and gives the page nothing', () => {
    const next = vi.fn();
    const error = vi.fn();
    http.get('/api/ui/me').subscribe({ next, error });

    backend.expectOne('/api/ui/me').flush(
      { status: 401, code: 'unauthenticated', title: 'Sign in to continue.' },
      { status: 401, statusText: 'Unauthorized' },
    );

    expect(assign).toHaveBeenCalledExactlyOnceWith('/Account/Login?ReturnUrl=%2FAccess%3Ftab%3Dgrid');
    expect(next).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
  });

  it.each([
    [503, 'audit_unavailable'],
    [404, 'not_found'],
    [403, 'forbidden'],
  ])('surfaces a %i problem to the page as its code %s', (status, code) => {
    let surfaced: unknown;
    http.get('/api/ui/me').subscribe({ error: (e: unknown) => (surfaced = e) });

    backend.expectOne('/api/ui/me').flush({ status, code, title: 'Refused.' }, { status, statusText: 'Refused' });

    expect(surfaced).toBeInstanceOf(UiApiError);
    expect(surfaced).toMatchObject({ status, code, title: 'Refused.' });
    expect(assign).not.toHaveBeenCalled();
  });

  it('surfaces a failure without Problem Details as an unknown code', () => {
    let surfaced: unknown;
    http.get('/api/ui/me').subscribe({ error: (e: unknown) => (surfaced = e) });

    backend.expectOne('/api/ui/me').flush('Bad gateway', { status: 502, statusText: 'Bad Gateway' });

    expect(surfaced).toMatchObject({ status: 502, code: 'unknown' });
  });

  it('leaves requests outside the UI API alone', () => {
    let surfaced: unknown;
    http.get('/Account/Login').subscribe({ error: (e: unknown) => (surfaced = e) });

    backend.expectOne('/Account/Login').flush(null, { status: 401, statusText: 'Unauthorized' });

    expect(surfaced).toBeInstanceOf(HttpErrorResponse);
    expect(assign).not.toHaveBeenCalled();
  });
});

describe('signInUrl', () => {
  it.each([
    ['/Access', '', '/Account/Login?ReturnUrl=%2FAccess'],
    ['/Access/Index', '?a=1&b=2', '/Account/Login?ReturnUrl=%2FAccess%2FIndex%3Fa%3D1%26b%3D2'],
    ['//evil.example/Access', '', '/Account/Login?ReturnUrl=%2F'],
    ['/\\evil.example', '', '/Account/Login?ReturnUrl=%2F'],
  ])('returns to %s%s only as a local path', (pathname, search, expected) => {
    expect(signInUrl({ pathname, search })).toBe(expected);
  });
});
