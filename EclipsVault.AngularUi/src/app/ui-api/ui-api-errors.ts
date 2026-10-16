import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { DOCUMENT, inject } from '@angular/core';
import { NEVER, catchError, throwError } from 'rxjs';

/** A failed UI API call, carrying the Problem Details `code` the server chose (ADR-0006). */
export class UiApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly title: string,
  ) {
    super(title);
    this.name = 'UiApiError';
  }
}

/**
 * The vault's sign-in page, returning to the page the browser is on. The return URL is always a
 * local path: `//host` or `/\host` would be another origin to a browser, so those return to `/`.
 */
export function signInUrl(location: Pick<Location, 'pathname' | 'search'>): string {
  const here = location.pathname + location.search;
  const local = /^\/(?![/\\])/.test(here) ? here : '/';
  return `/Account/Login?ReturnUrl=${encodeURIComponent(local)}`;
}

function toUiApiError(response: HttpErrorResponse): UiApiError {
  const problem = response.error as { code?: unknown; title?: unknown } | null;
  return new UiApiError(
    response.status,
    typeof problem?.code === 'string' ? problem.code : 'unknown',
    typeof problem?.title === 'string' ? problem.title : 'The vault could not complete the request.',
  );
}

/**
 * The one place the Angular UI reacts to UI API failures. A 401 (no session, or a revoked one)
 * sends the browser to sign-in; every other failure reaches the page as a {@link UiApiError}.
 */
export const uiApiErrors: HttpInterceptorFn = (request, next) => {
  if (!request.url.startsWith('/api/ui/')) {
    return next(request);
  }

  const document = inject(DOCUMENT);
  return next(request).pipe(
    catchError((error: unknown) => {
      if (!(error instanceof HttpErrorResponse)) {
        return throwError(() => error);
      }
      if (error.status === 401) {
        document.location.assign(signInUrl(document.location));
        // The page is being left: nothing more for it to show.
        return NEVER;
      }
      return throwError(() => toUiApiError(error));
    }),
  );
};
