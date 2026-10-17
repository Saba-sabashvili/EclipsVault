export type Theme = 'light' | 'dark';

type ThemedDocument = Pick<Document, 'cookie'> & { readonly documentElement: HTMLElement };

/** The theme on the page: the one the boot script applied from the Legacy UI's cookie, or the last switch. */
export function currentTheme(document: ThemedDocument): Theme {
  return document.documentElement.dataset['theme'] === 'light' ? 'light' : 'dark';
}

/** The theme a switch would move to. */
export function otherTheme(theme: Theme): Theme {
  return theme === 'light' ? 'dark' : 'light';
}

/**
 * Switches the page to the other theme and stores it in the cookie the Legacy UI reads, written
 * exactly as its `site.js` writes it, so both UIs open in the theme last chosen in either.
 */
export function switchTheme(document: ThemedDocument): Theme {
  const next = otherTheme(currentTheme(document));
  document.documentElement.dataset['theme'] = next;
  document.cookie = `EclipsVault.Theme=${next}; path=/; max-age=31536000; SameSite=Strict; Secure`;
  return next;
}
