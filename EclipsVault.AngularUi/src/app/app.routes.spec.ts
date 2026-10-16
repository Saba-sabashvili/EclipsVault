import { Route, UrlSegment, UrlSegmentGroup } from '@angular/router';
import { AccountPage } from './account/account-page';
import { routes } from './app.routes';

/** The route the router picks for `url`: the first whose matcher accepts its segments. */
function routeFor(url: string): Route | undefined {
  const segments = url
    .split('/')
    .filter((path) => path !== '')
    .map((path) => new UrlSegment(path, {}));
  const group = new UrlSegmentGroup(segments, {});
  return routes.find((route) => route.matcher?.(segments, group, route));
}

describe('routes', () => {
  it.each(['/Access', '/Access/Index', '/access', '/ACCESS/index'])(
    'opens My access at %s',
    async (url) => {
      const route = routeFor(url);

      expect(route).toBeDefined();
      expect(await route?.loadComponent?.()).toBe(AccountPage);
    },
  );

  it.each(['/', '/Index', '/Accessories', '/Access/Index/extra', '/Secrets'])(
    'leaves %s unmatched',
    (url) => {
      expect(routeFor(url)).toBeUndefined();
    },
  );
});
