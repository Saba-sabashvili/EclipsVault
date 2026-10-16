import { spawn } from 'node:child_process';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import https from 'node:https';
import { fileURLToPath } from 'node:url';
import { setTimeout } from 'node:timers/promises';

const ui = fileURLToPath(new URL('../', import.meta.url));
const root = fileURLToPath(new URL('../../', import.meta.url));
const probes = process.argv.includes('--verify-guards');
const output = probes ? 'guard-results' : 'test-results';
const project = `eclipsvault-e2e-${randomUUID().slice(0, 8)}`;
const image = process.env.E2E_IMAGE || `${project}:test`;
const abort = new AbortController();
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => abort.abort());
}

function run(command, args, env, { capture = false, cleanup = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: ui, env, signal: cleanup ? undefined : abort.signal,
      stdio: capture ? ['ignore', 'pipe', 'inherit'] : 'inherit',
    });
    let stdout = '';
    child.stdout?.on('data', (data) => { stdout += data; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout: stdout.trim() }));
  });
}

async function checked(command, args, env, options) {
  const result = await run(command, args, env, options);
  if (result.code !== 0) throw new Error(`${command} ${args[0]} failed (exit ${result.code})`);
  return result.stdout;
}

async function waitForVault(baseURL) {
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    abort.signal.throwIfAborted();
    const status = await new Promise((resolve) => {
      const request = https.get(`${baseURL}/Account/Login`, { rejectUnauthorized: false }, (response) => {
        response.resume();
        resolve(response.statusCode);
      });
      request.setTimeout(2_000, () => request.destroy());
      request.on('error', () => resolve(0));
    });
    if (status === 200) return;
    await setTimeout(1_000, undefined, { signal: abort.signal });
  }
  throw new Error('The production vault did not serve sign-in within 180 seconds; see docker.log');
}

function verifyGuardFailures(report, exitCode) {
  const tests = [];
  function visit(suite) {
    for (const spec of suite.specs ?? []) tests.push(...spec.tests);
    for (const child of suite.suites ?? []) visit(child);
  }
  visit(report);
  const diagnostics = ['CSP violation:', 'console.error: e2e console sentinel', 'pageerror: e2e exception sentinel'];
  if (exitCode !== 1 || tests.length !== diagnostics.length || report.errors.length !== 0) {
    throw new Error('Guard probes did not produce exactly three ordinary test failures');
  }
  for (const diagnostic of diagnostics) {
    const match = tests.find((test) => test.results.some((result) =>
      result.status === 'failed' && result.errors.some((error) =>
        error.message?.includes('[browser-health]') && error.message.includes(diagnostic))));
    if (!match) throw new Error(`Guard probe did not fail in the shared fixture for ${diagnostic}`);
    console.log(`Verified real Playwright failure: ${diagnostic}`);
  }
}

async function main() {
  if (!process.env.Seed__AdminPassword || process.env.Seed__AdminPassword.length < 12) {
    throw new Error('Supply Seed__AdminPassword (at least 12 characters) in the test environment');
  }
  if (!process.env.ECLIPSVAULT_KEK || Buffer.from(process.env.ECLIPSVAULT_KEK, 'base64').length !== 32) {
    throw new Error('Supply ECLIPSVAULT_KEK (base64-encoded 32 bytes) in the test environment');
  }
  // A fresh signing identity for the disposable vault. It goes straight to the child environment;
  // private key material is never logged or written to test artifacts.
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const env = {
    ...process.env,
    E2E_IMAGE: image,
    E2E_SQL_PASSWORD: `Sa1!${randomBytes(24).toString('hex')}`,
    E2E_PROXY_IP: '127.0.0.1', // Replaced with the proxy's actual address before starting the vault.
    ECLIPSVAULT_AUDIT_SIGNING_KEY: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  };
  const composeArgs = ['compose', '--project-name', project, '--file', 'e2e/compose.yml'];
  const compose = (args, options) => checked('docker', [...composeArgs, ...args], env, options);
  await mkdir(new URL(`../${output}/`, import.meta.url), { recursive: true });
  let builtImage = false;
  try {
    if (!process.env.E2E_IMAGE) {
      await checked('docker', ['build', '--tag', image, root], env);
      builtImage = true;
    }
    // Discover the address Docker assigned instead of trusting arbitrary forwarded headers or
    // reserving a fixed subnet that could collide with another developer's network.
    await compose(['up', '-d', '--wait', '--wait-timeout', '180', 'sql', 'proxy']);
    const proxyId = await compose(['ps', '-q', 'proxy'], { capture: true });
    env.E2E_PROXY_IP = await checked('docker', ['inspect', '--format', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', proxyId], env, { capture: true });
    await compose(['up', '-d', 'vault']);
    const address = await compose(['port', 'proxy', '443'], { capture: true });
    env.E2E_BASE_URL = `https://localhost:${address.split(':').at(-1)}`;
    await waitForVault(env.E2E_BASE_URL);

    // A failed runner must never be mistaken for the previous invocation's expected failures.
    if (probes) await rm(new URL('../guard-results/results.json', import.meta.url), { force: true });
    const result = await run(process.execPath, ['node_modules/@playwright/test/cli.js', 'test'], {
      ...env, E2E_VERIFY_GUARDS: probes ? '1' : '0',
    });
    if (probes) {
      verifyGuardFailures(JSON.parse(await readFile(new URL('../guard-results/results.json', import.meta.url), 'utf8')), result.code);
    } else if (result.code !== 0) {
      throw new Error(`Playwright failed (exit ${result.code}); see test-results and playwright-report`);
    }
  } finally {
    try {
      const logs = await compose(['logs', '--no-color'], { capture: true, cleanup: true });
      await writeFile(new URL(`../${output}/docker.log`, import.meta.url), logs);
    } finally {
      await compose(['down', '--volumes', '--remove-orphans'], { cleanup: true });
      if (builtImage) await checked('docker', ['image', 'rm', image], env, { cleanup: true });
    }
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
