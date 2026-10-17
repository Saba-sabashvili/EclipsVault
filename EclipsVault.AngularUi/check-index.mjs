// Fails the build when its index.html would be public or would break the vault's CSP (ADR-0013:
// `script-src 'self'; style-src 'self'`, so no inline script, event handler or inline style).
// Angular's `index.output` ignores paths outside the output folder, so only move-index.mjs keeps
// the document out of wwwroot; this checks that it did.
import { existsSync, readFileSync } from 'node:fs';

/** What in `html` the CSP would block: inline scripts, on…= handlers, style elements and attributes. */
export function inlineCode(html) {
  const findings = [];
  for (const [tag, name] of html.matchAll(/<([a-z][a-z0-9-]*)(?:"[^"]*"|'[^']*'|[^"'>])*>/gi)) {
    // Quoted values blanked, so text inside one is never read as an attribute.
    const attributes = tag.replace(/"[^"]*"|'[^']*'/g, '""');
    const element = name.toLowerCase();
    if (element === 'script' && !/[\s/]src\s*=/i.test(attributes)) findings.push('inline <script>');
    if (element === 'style') findings.push('<style> element');
    for (const [, handler] of attributes.matchAll(/[\s/](on[a-z]+)\s*=/gi)) {
      findings.push(`${handler}= handler`);
    }
    if (/[\s/]style\s*=/i.test(attributes)) findings.push('style= attribute');
  }
  return findings;
}

if (import.meta.main) {
  const problems = [];
  if (existsSync('../EclipsVault.Web/wwwroot/ui/index.html')) {
    problems.push('EclipsVault.Web/wwwroot/ui/index.html exists, so anyone could fetch it');
  }
  const findings = inlineCode(readFileSync('../EclipsVault.Web/AngularUi/index.html', 'utf8'));
  for (const finding of findings) {
    problems.push(`EclipsVault.Web/AngularUi/index.html: ${finding}, which the CSP blocks`);
  }
  if (problems.length > 0) {
    console.error(problems.join('\n'));
    process.exit(1);
  }
}
