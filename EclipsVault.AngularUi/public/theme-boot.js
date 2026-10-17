// Applies the theme stored in the cookie the Legacy UI shares, before the page first paints, so the
// Angular UI never flashes the other theme. The Legacy UI stamps the same attribute on the server.
// An external file, loaded without defer from <head>, because the CSP forbids inline script.
document.documentElement.setAttribute(
  'data-theme',
  /(?:^|;\s*)EclipsVault\.Theme=light(?:;|$)/.test(document.cookie) ? 'light' : 'dark',
);
