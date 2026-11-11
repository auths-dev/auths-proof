import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const syntheticServiceToken = 'synthetic-northstar-service-token-for-tests';
const authorization = `Bearer ${syntheticServiceToken}`;
const verifier = 'synthetic-pkce-verifier-for-state-ownership';
const redirectUri = 'http://localhost/callback';
const firewall = { incidentId: 'INC-2026-0811', region: 'eu-west-2', operation: 'apply-config' };

function bounded(promise, diagnostic, milliseconds = 10_000) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(diagnostic)), milliseconds); }),
  ]).finally(() => clearTimeout(timer));
}

// Expect: 100-continue acknowledges HTTP admission while retaining the entire
// body at the client. Both requests reach their body await before either can
// mutate state; no scheduler sleeps are used to manufacture overlap.
async function heldRequest(port, path, value, headers = {}) {
  const bytes = Buffer.from(JSON.stringify(value));
  let request;
  let admitted;
  const admission = new Promise((resolve, reject) => { admitted = { resolve, reject }; });
  const response = new Promise((resolve, reject) => {
    request = http.request({
      host: '127.0.0.1', port, path, method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': bytes.length, expect: '100-continue', ...headers },
    }, (incoming) => {
      const chunks = [];
      incoming.on('data', (chunk) => chunks.push(chunk));
      incoming.on('error', reject);
      incoming.on('end', () => resolve({ status: incoming.statusCode, body: JSON.parse(Buffer.concat(chunks)) }));
    });
    request.on('continue', admitted.resolve);
    request.on('error', (error) => { admitted.reject(error); reject(error); });
    request.setTimeout(10_000, () => request.destroy(new Error('held request exceeded diagnostic bound')));
    request.flushHeaders();
  });
  // A rejected admission must also have a consumer for its request result.
  response.catch(() => {});
  await admission;
  return { release: () => { request.end(bytes); return response; } };
}

async function request(port, path, value, headers = {}) {
  return (await heldRequest(port, path, value, headers)).release();
}

async function code(port, clientId = 'synthetic-test-client') {
  const query = new URLSearchParams({
    response_type: 'code', redirect_uri: redirectUri, client_id: clientId,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
  });
  const response = await fetch(`http://127.0.0.1:${port}/authorize?${query}`, { redirect: 'manual' });
  assert.equal(response.status, 302);
  return new URL(response.headers.get('location')).searchParams.get('code');
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'northstar-ownership-'));
  const statePath = join(directory, 'state.json');
  const child = spawn(process.execPath, [fileURLToPath(new URL('../dist/server.js', import.meta.url))], {
    env: { ...process.env, PORT: '0', NORTHSTAR_PUBLIC_URL: 'http://northstar.invalid',
      NORTHSTAR_STATE_PATH: statePath, AUTHS_INCIDENT_SERVICE_TOKEN: syntheticServiceToken,
      AUTHS_INCIDENT_ALLOW_INSECURE_LOCAL: '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let closed = false;
  // 'close' follows either exit or a failed spawn; failed spawn need not emit
  // 'exit'. Teardown must settle in both cases and has its own diagnostic bound.
  const close = new Promise((resolve) => child.once('close', () => { closed = true; resolve(); }));
  const lines = createInterface({ input: child.stdout });
  t.after(async () => {
    try {
      if (!closed) child.kill('SIGKILL');
      await bounded(close, 'Northstar child did not close after termination', 5_000);
    } finally {
      lines.close();
      await rm(directory, { recursive: true, force: true });
    }
  });
  const port = await bounded(new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => reject(new Error(`Northstar closed before readiness: code=${code}, signal=${signal}`)));
    lines.on('line', (line) => {
      const match = /\(port (\d+)\)/.exec(line);
      if (match) resolve(Number(match[1]));
    });
  }), 'Northstar failed to listen');
  return { port, state: async () => JSON.parse(await readFile(statePath, 'utf8')) };
}

test('held-body token redemption consumes exactly once, including distinct codes', { timeout: 20_000 }, async (t) => {
  const { port, state } = await fixture(t);
  const firstCode = await code(port);
  const token = { code: firstCode, code_verifier: verifier, redirect_uri: redirectUri };
  const a = await heldRequest(port, '/token', token);
  const b = await heldRequest(port, '/token', token);
  assert.equal((await a.release()).status, 200);
  assert.equal((await b.release()).status, 400);
  assert.deepEqual((await state()).codes, {});

  const codeA = await code(port);
  const codeB = await code(port);
  const c = await heldRequest(port, '/token', { ...token, code: codeA });
  const d = await heldRequest(port, '/token', { ...token, code: codeB });
  assert.equal((await d.release()).status, 200);
  assert.equal((await c.release()).status, 200);
  assert.deepEqual((await state()).codes, {}, 'later commits cannot resurrect another consumed code');
});

test('held-body firewall calls acknowledge one effect and retain truthful counters', { timeout: 20_000 }, async (t) => {
  const { port, state } = await fixture(t);
  const a = await heldRequest(port, '/api/firewall/apply', firewall, { authorization });
  const b = await heldRequest(port, '/api/firewall/apply', firewall, { authorization });
  assert.equal((await b.release()).status, 200);
  assert.equal((await a.release()).status, 409);
  const committed = await state();
  assert.equal(committed.firewallApplied, true);
  assert.equal(committed.providerCalls, 2);
  assert.equal(committed.timeline.filter((entry) => entry.type === 'effect').length, 1);
});

test('held-body approvals retain both committed increments and timeline events', { timeout: 20_000 }, async (t) => {
  const { port, state } = await fixture(t);
  const redeemed = await request(port, '/token', {
    code: await code(port, 'auths-incident-agent'), code_verifier: verifier, redirect_uri: redirectUri,
  });
  assert.equal(redeemed.status, 200);
  const headers = { authorization: `Bearer ${redeemed.body.access_token}` };
  const approval = { requestId: 'synthetic-request', transactionDigest: 'synthetic-digest', planCommitment: 'synthetic-plan' };
  const a = await heldRequest(port, '/api/approve', approval, headers);
  const b = await heldRequest(port, '/api/approve', approval, headers);
  assert.equal((await a.release()).status, 200);
  assert.equal((await b.release()).status, 200);
  const committed = await state();
  assert.equal(committed.approvals, 2);
  assert.equal(committed.timeline.filter((entry) => entry.type === 'approval').length, 2);
});

test('reset orders held token and provider requests against current state', { timeout: 20_000 }, async (t) => {
  const { port, state } = await fixture(t);
  const oldCode = await code(port);
  const token = await heldRequest(port, '/token', { code: oldCode, code_verifier: verifier, redirect_uri: redirectUri });
  const apply = await heldRequest(port, '/api/firewall/apply', firewall, { authorization });
  assert.equal((await request(port, '/api/reset', {}, { authorization })).status, 200);
  assert.equal((await apply.release()).status, 200);
  assert.equal((await token.release()).status, 400);
  let committed = await state();
  assert.deepEqual(committed.codes, {});
  assert.equal(committed.providerCalls, 1);
  assert.equal(committed.timeline.length, 1);

  // A reset admitted first but completed after an effect must reset that
  // committed effect; the next operation must evaluate the reset successor.
  const reset = await heldRequest(port, '/api/reset', {}, { authorization });
  assert.equal((await request(port, '/api/firewall/apply', firewall, { authorization })).status, 409);
  assert.equal((await reset.release()).status, 200);
  assert.equal((await request(port, '/api/firewall/apply', firewall, { authorization })).status, 200);
  committed = await state();
  assert.equal(committed.providerCalls, 1);
  assert.equal(committed.timeline.length, 1);
});

test('body bounds and existing operation guards reject before mutation', { timeout: 20_000 }, async (t) => {
  const { port, state } = await fixture(t);
  assert.equal((await request(port, '/api/firewall/apply', firewall)).status, 401);
  assert.equal((await request(port, '/api/firewall/apply', { ...firewall, region: 'elsewhere' }, { authorization })).status, 403);
  assert.equal((await request(port, '/token', { code: await code(port), code_verifier: 'wrong', redirect_uri: redirectUri })).status, 400);
  assert.equal((await request(port, '/api/firewall/apply', { padding: 'x'.repeat(32 * 1024) }, { authorization })).status, 413);
  const committed = await state();
  assert.equal(committed.firewallApplied, false);
  assert.equal(committed.providerCalls, 0);
  assert.equal(committed.timeline.length, 0);
});
