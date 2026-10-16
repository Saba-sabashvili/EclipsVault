// Tests for the build's own gates, run with `npm run test:build-checks` (node:test, no packages).
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { inlineCode } from './check-index.mjs';
import { disallowedRuntimePackages } from './check-runtime-deps.mjs';

/** A package-lock.json holding `packages`, keyed by install path as npm writes them. */
const lock = (packages) => ({ lockfileVersion: 3, packages: { '': { name: 'ui' }, ...packages } });

describe('disallowedRuntimePackages', () => {
  it('allows @angular/*, rxjs and tslib', () => {
    const result = disallowedRuntimePackages(
      lock({
        'node_modules/@angular/core': { version: '22.2.3' },
        'node_modules/rxjs': { version: '7.8.2' },
        'node_modules/tslib': { version: '2.8.1' },
      }),
    );

    assert.deepEqual(result, []);
  });

  it('flags any other runtime package, direct or transitive', () => {
    const result = disallowedRuntimePackages(
      lock({
        'node_modules/left-pad': { version: '1.3.0' },
        'node_modules/@angular/core/node_modules/is-odd': { version: '3.0.1' },
      }),
    );

    assert.deepEqual(result, ['left-pad', 'is-odd']);
  });

  it('flags names that only look allowed', () => {
    const result = disallowedRuntimePackages(
      lock({
        'node_modules/@angularx/core': {},
        'node_modules/rxjs-compat': {},
        'node_modules/tslib-extra': {},
      }),
    );

    assert.deepEqual(result, ['@angularx/core', 'rxjs-compat', 'tslib-extra']);
  });

  it('names an aliased package by what it really is', () => {
    const result = disallowedRuntimePackages(
      lock({ 'node_modules/@angular/x': { name: 'left-pad', version: '1.3.0' } }),
    );

    assert.deepEqual(result, ['left-pad']);
  });

  it('ignores dev dependencies', () => {
    const result = disallowedRuntimePackages(
      lock({ 'node_modules/vitest': { version: '5.0.5', dev: true } }),
    );

    assert.deepEqual(result, []);
  });
});

describe('inlineCode', () => {
  const page = (head, body = '<app-root></app-root>') =>
    `<!doctype html><html lang="en"><head>${head}</head><body>${body}</body></html>`;

  it('accepts a document that only links its scripts and styles', () => {
    const html = page(
      '<base href="/"><link rel="stylesheet" href="/ui/styles-X.css">',
      '<app-root></app-root><script src="/ui/main-X.js" type="module"></script>',
    );

    assert.deepEqual(inlineCode(html), []);
  });

  it('flags an inline <script>', () => {
    assert.deepEqual(inlineCode(page('<script>window.x = 1;</script>')), ['inline <script>']);
  });

  it('flags a <script> with no src even when it is empty', () => {
    assert.deepEqual(inlineCode(page('<SCRIPT type="importmap"></SCRIPT>')), ['inline <script>']);
  });

  it('flags a <style> element', () => {
    assert.deepEqual(inlineCode(page('<style>body{margin:0}</style>')), ['<style> element']);
  });

  it('flags an on…= event handler, in any case', () => {
    const html = page(
      '<link rel="stylesheet" href="/ui/styles-X.css" media="print" onload="this.media=\'all\'">',
      '<app-root ONCLICK = "go()"></app-root>',
    );

    assert.deepEqual(inlineCode(html), ['onload= handler', 'ONCLICK= handler']);
  });

  it('flags a style= attribute', () => {
    assert.deepEqual(inlineCode(page('', '<app-root style="display:block"></app-root>')), [
      'style= attribute',
    ]);
  });

  it('reads past a > inside an attribute value', () => {
    assert.deepEqual(inlineCode(page('', '<img alt="a>b" onerror="x()">')), ['onerror= handler']);
  });

  it('flags a handler after a slash instead of a space', () => {
    assert.deepEqual(inlineCode(page('', '<img/onerror=x()>')), ['onerror= handler']);
  });

  it('does not take a src inside another attribute value for the script source', () => {
    assert.deepEqual(inlineCode(page('<script data-x=" src=y">x()</script>')), ['inline <script>']);
  });

  it('does not mistake text or other attributes for a handler or element', () => {
    const html = page(
      '<meta name="description" content="one=two onload=x()">',
      '<p>Sign on=now</p><style-guide></style-guide>',
    );

    assert.deepEqual(inlineCode(html), []);
  });
});
