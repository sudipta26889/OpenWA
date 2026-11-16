// Run: node --test ops/mcp-oauth-gateway/*.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createGateway } from './gateway.mjs';

const GOOD_KEY = 'owa_k1_good';
const VIEWER_KEY = 'owa_k1_viewer';
const ROLES = { [GOOD_KEY]: 'admin', [VIEWER_KEY]: 'viewer' };
const liveKeys = new Set([GOOD_KEY, VIEWER_KEY]); // a test deletes a key here to "revoke it upstream"
let validateDelayMs = 0; // a test raises it to make concurrent requests overlap
let upstream, upPort, gateway, base, seen;

const listen = srv => new Promise(r => srv.listen(0, '127.0.0.1', () => r(srv.address().port)));

before(async () => {
  // Fake OpenWA: validates keys (with a role), records what /mcp received, echoes a WebSocket-ish upgrade.
  upstream = http.createServer((req, res) => {
    if (req.url === '/api/auth/validate') {
      const key = req.headers['x-api-key'];
      const ok = liveKeys.has(key);
      const answer = () => {
        res.writeHead(ok ? 200 : 401, { 'content-type': 'application/json' });
        res.end(JSON.stringify(ok ? { valid: true, role: ROLES[key] ?? 'operator' } : { message: 'Invalid API key' }));
      };
      return validateDelayMs ? setTimeout(answer, validateDelayMs) : answer();
    }
    seen = { url: req.url, method: req.method, headers: req.headers };
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ upstream: true }));
  });
  upstream.on('upgrade', (req, socket) => {
    seen = { url: req.url, headers: req.headers };
    socket.end('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\npong');
  });
  upPort = await listen(upstream);
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'owg-'));
  gateway = createGateway({ issuer: 'https://wa.example.test', upstream: `http://127.0.0.1:${upPort}`, stateDir });
  base = `http://127.0.0.1:${await listen(gateway)}`;
});
after(() => {
  gateway.closeAllConnections();
  gateway.close();
  upstream.closeAllConnections();
  upstream.close();
});

const form = (url, body) =>
  fetch(base + url, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://wa.example.test' },
    body: new URLSearchParams(body),
  });

test('full OAuth flow: register → consent → code → token → /mcp with the API key swapped in → refresh rotation', async () => {
  const meta = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
  assert.equal(meta.token_endpoint, 'https://wa.example.test/oauth/token');

  const reg = await fetch(`${base}/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: ['https://claude.ai/cb'], client_name: 'Claude' }),
  });
  assert.equal(reg.status, 201);
  const { client_id } = await reg.json();

  const verifier = crypto.randomBytes(32).toString('base64url');
  const q = {
    client_id,
    redirect_uri: 'https://claude.ai/cb',
    response_type: 'code',
    code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    state: 'xyz',
  };
  const page = await fetch(`${base}/oauth/authorize?${new URLSearchParams(q)}`);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Claude/);

  const denied = await form('/oauth/authorize', { ...q, api_key: 'wrong' });
  assert.equal(denied.status, 401);

  const approved = await form('/oauth/authorize', { ...q, api_key: GOOD_KEY });
  assert.equal(approved.status, 302);
  const cb = new URL(approved.headers.get('location'));
  assert.equal(cb.origin + cb.pathname, 'https://claude.ai/cb');
  assert.equal(cb.searchParams.get('state'), 'xyz');
  const code = cb.searchParams.get('code');

  const exchange = { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: q.redirect_uri, client_id };
  assert.equal((await form('/oauth/token', { ...exchange, code_verifier: 'nope' })).status, 400, 'PKCE enforced');
  const tok = await (await form('/oauth/token', exchange)).json();
  assert.ok(tok.access_token.startsWith('owga.'));

  const mcp = await fetch(`${base}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${tok.access_token}` }, body: '{}' });
  assert.equal(mcp.status, 200);
  assert.equal(seen.headers['x-api-key'], GOOD_KEY);
  assert.equal(seen.headers.authorization, undefined, 'our token never reaches OpenWA');

  const refresh = { grant_type: 'refresh_token', refresh_token: tok.refresh_token, client_id };
  const rotated = await form('/oauth/token', refresh);
  assert.equal(rotated.status, 200);
  // The just-rotated token stays usable for a 30 s retry window (see the Refresh tests), so it is only
  // dead once it is two rotations old.
  const second = await form('/oauth/token', { ...refresh, refresh_token: (await rotated.json()).refresh_token });
  assert.equal(second.status, 200);
  assert.equal((await form('/oauth/token', refresh)).status, 400, 'a rotated refresh token is dead');

  assert.equal((await form('/oauth/token', exchange)).status, 400, 'a code is single-use');
});

test('/mcp without credentials, or with a foreign JWT, asks the client to run the OAuth flow', async () => {
  const none = await fetch(`${base}/mcp`, { method: 'POST', body: '{}' });
  assert.equal(none.status, 401);
  assert.match(none.headers.get('www-authenticate'), /resource_metadata="https:\/\/wa\.example\.test\/\.well-known\/oauth-protected-resource"/);

  const jwt = `${Buffer.from('{"alg":"RS256","typ":"JWT"}').toString('base64url')}.e30.sig`;
  const old = await fetch(`${base}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${jwt}` }, body: '{}' });
  assert.equal(old.status, 401);
  assert.match(old.headers.get('www-authenticate'), /invalid_token/);

  const forged = await fetch(`${base}/mcp`, { method: 'POST', headers: { authorization: 'Bearer owga.AAAA' }, body: '{}' });
  assert.equal(forged.status, 401);
});

test('static API keys and everything else pass straight through, with X-Forwarded-For appended', async () => {
  await fetch(`${base}/mcp`, { method: 'POST', headers: { 'x-api-key': GOOD_KEY }, body: '{}' });
  assert.equal(seen.headers['x-api-key'], GOOD_KEY);

  const res = await fetch(`${base}/api/sessions?x=1`, { headers: { 'x-forwarded-for': '203.0.113.9' } });
  assert.deepEqual(await res.json(), { upstream: true });
  assert.equal(seen.url, '/api/sessions?x=1');
  assert.equal(seen.headers['x-forwarded-for'], '203.0.113.9, 127.0.0.1');

  assert.equal((await fetch(`${base}/.well-known/unknown`)).status, 404, 'OAuth surface never falls through to the SPA');
});

test('WebSocket upgrades are tunnelled to OpenWA', async () => {
  const port = new URL(base).port;
  const reply = await new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1', () =>
      s.write('GET /socket.io/?EIO=4 HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'),
    );
    let buf = '';
    s.on('data', d => (buf += d));
    s.on('end', () => resolve(buf));
    s.on('error', reject);
  });
  assert.match(reply, /^HTTP\/1\.1 101/);
  assert.match(reply, /pong$/);
  assert.equal(seen.url, '/socket.io/?EIO=4');
});

// ---- fleet-checklist gaps ----

const register = async redirect_uris => {
  const res = await fetch(`${base}/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris, client_name: 'T' }),
  });
  return { status: res.status, body: await res.json() };
};
const pkce = () => {
  const verifier = crypto.randomBytes(32).toString('base64url');
  return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') };
};
const authQuery = (client_id, redirect_uri, challenge, extra = {}) => ({
  client_id,
  redirect_uri,
  response_type: 'code',
  code_challenge: challenge,
  code_challenge_method: 'S256',
  state: 's1',
  ...extra,
});
const approve = (q, extra = {}) => form('/oauth/authorize', { ...q, api_key: GOOD_KEY, ...extra });
const mcpPost = headers => fetch(`${base}/mcp`, { method: 'POST', headers, body: '{}' });

test('POST /mcp rejects a foreign Origin with 403 before any auth handling', async () => {
  for (const origin of ['https://evil.example', 'http://localhost.evil.com', 'null', 'https://wa.example.test.evil.com']) {
    const res = await mcpPost({ origin, 'x-api-key': GOOD_KEY });
    assert.equal(res.status, 403, origin);
    const body = await res.json();
    assert.equal(body.jsonrpc, '2.0');
    assert.ok(body.error, 'JSON-RPC error body');
  }
  assert.equal((await mcpPost({ origin: 'https://evil.example' })).status, 403, 'checked before the 401');
});

test('POST /mcp accepts the issuer origin, localhost origins and no Origin at all', async () => {
  for (const origin of ['https://wa.example.test', 'http://localhost', 'http://localhost:3000', 'http://127.0.0.1:6274']) {
    assert.equal((await mcpPost({ origin, 'x-api-key': GOOD_KEY })).status, 200, origin);
  }
  assert.equal((await mcpPost({ 'x-api-key': GOOD_KEY })).status, 200, 'no Origin header');
  assert.equal((await mcpPost({})).status, 401, 'no Origin still goes to auth');
});

test('POST /mcp lets the hosted connector origins through to auth', async () => {
  for (const origin of ['https://claude.ai', 'https://chatgpt.com']) {
    assert.equal((await mcpPost({ origin })).status, 401, `${origin} without credentials`);
    assert.equal((await mcpPost({ origin, 'x-api-key': GOOD_KEY })).status, 200, `${origin} with a key`);
  }
});

test('POST /mcp still refuses look-alikes of the hosted origins', async () => {
  for (const origin of ['https://claude.ai.evil.example', 'https://evil.claude.ai']) {
    assert.equal((await mcpPost({ origin, 'x-api-key': GOOD_KEY })).status, 403, origin);
  }
});

test('a refused Origin writes one log line, clipped to 200 characters', async () => {
  const lines = [];
  const orig = console.log;
  console.log = (...a) => lines.push(a.join(' '));
  try {
    await mcpPost({ origin: 'https://evil.example', 'x-api-key': GOOD_KEY });
    await mcpPost({ origin: 'https://' + 'a'.repeat(300) + '.example' });
  } finally {
    console.log = orig;
  }
  const refused = lines.map(l => JSON.parse(l)).filter(l => l.msg === 'mcp origin refused');
  assert.equal(refused.length, 2);
  assert.equal(refused[0].origin, 'https://evil.example');
  assert.deepEqual(Object.keys(refused[0]).sort(), ['msg', 'origin', 'ts']);
  assert.equal(refused[1].origin.length, 200);
});

test('every 401 WWW-Authenticate carries scope="mcp" after resource_metadata', async () => {
  const none = (await mcpPost({})).headers.get('www-authenticate');
  assert.match(none, /resource_metadata="[^"]+", scope="mcp"$/);
  const forged = (await mcpPost({ authorization: 'Bearer owga.AAAA' })).headers.get('www-authenticate');
  assert.match(forged, /resource_metadata="[^"]+", scope="mcp", error="invalid_token"$/);
});

test('RFC 9207: the authorize redirect carries iss and the metadata advertises it', async () => {
  const meta = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
  assert.equal(meta.authorization_response_iss_parameter_supported, true);
  const { body } = await register(['https://claude.ai/cb']);
  const res = await approve(authQuery(body.client_id, 'https://claude.ai/cb', pkce().challenge));
  assert.equal(res.status, 302);
  const cb = new URL(res.headers.get('location'));
  assert.equal(cb.searchParams.get('iss'), 'https://wa.example.test');
  assert.equal(cb.searchParams.get('state'), 's1');
  assert.ok(cb.searchParams.get('code'));
});

test('RFC 8707: a resource other than the issuer /mcp is invalid_target; absent or exact is fine', async () => {
  const { body } = await register(['https://claude.ai/cb']);
  const uri = 'https://claude.ai/cb';
  const { verifier, challenge } = pkce();
  const q = authQuery(body.client_id, uri, challenge);

  assert.equal((await approve(q, { resource: 'https://other.example/mcp' })).status, 400, 'authorize rejects');
  assert.equal((await approve(q, { resource: 'https://wa.example.test' })).status, 400, 'bare issuer is not the resource');
  assert.equal((await approve(q)).status, 302, 'resource may be omitted');
  assert.equal((await approve(q, { resource: 'https://wa.example.test/mcp/' })).status, 302, 'trailing slash tolerated');
  const location = (await approve(q, { resource: 'https://wa.example.test/mcp' })).headers.get('location');
  const code = new URL(location).searchParams.get('code');

  const exchange = { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: uri, client_id: body.client_id };
  const bad = await form('/oauth/token', { ...exchange, resource: 'https://other.example/mcp' });
  assert.equal(bad.status, 400);
  assert.equal((await bad.json()).error, 'invalid_target');
  const ok = await form('/oauth/token', { ...exchange, resource: 'https://wa.example.test/mcp/' });
  assert.equal(ok.status, 200);

  const { refresh_token } = await ok.json();
  const refresh = { grant_type: 'refresh_token', refresh_token, client_id: body.client_id };
  const badRefresh = await form('/oauth/token', { ...refresh, resource: 'https://other.example/mcp' });
  assert.equal(badRefresh.status, 400);
  assert.equal((await badRefresh.json()).error, 'invalid_target');
  assert.equal((await form('/oauth/token', { ...refresh, resource: 'https://wa.example.test/mcp' })).status, 200);
});

test('RFC 8252: a loopback redirect URI matches on any port, everything else stays exact', async () => {
  const { challenge, verifier } = pkce();
  for (const reg of ['http://localhost/cb', 'http://127.0.0.1/cb']) {
    const { body } = await register([reg]);
    const withPort = reg.replace('/cb', ':54321/cb');
    const ok = await approve(authQuery(body.client_id, withPort, challenge));
    assert.equal(ok.status, 302, withPort);
    assert.equal(new URL(ok.headers.get('location')).origin, new URL(withPort).origin);
    assert.equal((await approve(authQuery(body.client_id, withPort.replace('/cb', '/other'), challenge))).status, 400, 'path differs');
    assert.equal((await approve(authQuery(body.client_id, withPort + '?a=1', challenge))).status, 400, 'query differs');
    assert.equal((await approve(authQuery(body.client_id, withPort.replace('http:', 'https:'), challenge))).status, 400, 'scheme differs');
  }
  const { body: lo } = await register(['http://localhost/cb']);
  assert.equal((await approve(authQuery(lo.client_id, 'http://127.0.0.1:1/cb', challenge))).status, 400, 'host differs');

  const { body: web } = await register(['https://claude.ai/cb']);
  assert.equal((await approve(authQuery(web.client_id, 'https://claude.ai:444/cb', challenge))).status, 400, 'non-loopback is exact');

  // The token step applies the same rule to redirect_uri.
  const uri = 'http://localhost:5000/cb';
  const code = new URL((await approve(authQuery(lo.client_id, uri, challenge))).headers.get('location')).searchParams.get('code');
  const exchange = { grant_type: 'authorization_code', code, code_verifier: verifier, client_id: lo.client_id };
  assert.equal((await form('/oauth/token', { ...exchange, redirect_uri: 'http://localhost:5000/other' })).status, 400);
  assert.equal((await form('/oauth/token', { ...exchange, redirect_uri: 'http://localhost:6000/cb' })).status, 200, 'port may differ');
});

test('DCR accepts cursor:// and vscode:// redirect URIs and refuses other custom schemes', async () => {
  const cursor = 'cursor://anysphere.cursor-mcp/oauth/callback';
  const vscode = 'vscode://ms-vscode.mcp/callback';
  const ok = await register([cursor, vscode]);
  assert.equal(ok.status, 201);
  assert.deepEqual(ok.body.redirect_uris, [cursor, vscode]);
  const res = await approve(authQuery(ok.body.client_id, cursor, pkce().challenge));
  assert.equal(res.status, 302);
  assert.ok(new URL(res.headers.get('location')).searchParams.get('code'));

  const bad = await register(['myapp://cb']);
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error, 'invalid_redirect_uri');
});

// ---- phase 2: grants, refresh, revoke ----

const ISSUER = 'https://wa.example.test';
const newStateDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'owg-'));
/** A second (or third) gateway on the same stateDir simulates a restart. */
async function startGateway({ stateDir = newStateDir(), now } = {}) {
  const gw = createGateway({ issuer: ISSUER, upstream: `http://127.0.0.1:${upPort}`, stateDir, now });
  const url = `http://127.0.0.1:${await listen(gw)}`;
  const stop = async () => {
    gw.closeAllConnections();
    await new Promise(r => gw.close(r)); // 'close' flushes lastUsedAt
  };
  return { gw, stateDir, base: url, stop };
}
const formAt = (b, url, body) =>
  fetch(b + url, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: ISSUER },
    body: new URLSearchParams(body),
  });
const grantsOf = dir => JSON.parse(fs.readFileSync(path.join(dir, 'grants.json'), 'utf8'));
const mcpAt = (b, token) => fetch(`${b}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${token}` }, body: '{}' });
/** Register, approve with `key`, and exchange the code. Returns everything a test needs to poke at it. */
async function connect(b, { key = GOOD_KEY, uri = 'https://claude.ai/cb', name = 'Claude' } = {}) {
  const reg = await (
    await fetch(`${b}/oauth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [uri], client_name: name }),
    })
  ).json();
  const { verifier, challenge } = pkce();
  const q = authQuery(reg.client_id, uri, challenge);
  const approved = await formAt(b, '/oauth/authorize', { ...q, api_key: key });
  assert.equal(approved.status, 302);
  const code = new URL(approved.headers.get('location')).searchParams.get('code');
  const exchange = { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: uri, client_id: reg.client_id };
  const res = await formAt(b, '/oauth/token', exchange);
  const tok = res.status === 200 ? await res.json() : null;
  const refresh = rt => formAt(b, '/oauth/token', { grant_type: 'refresh_token', refresh_token: rt, client_id: reg.client_id });
  return { client_id: reg.client_id, exchange, tok, refresh };
}
/** Seal a token the way the gateway does, to forge a pre-phase-2 token (no gid). */
function sealLegacy(stateDir, kind, prefix, obj) {
  const secret = Buffer.from(fs.readFileSync(path.join(stateDir, 'gateway-secret.key'), 'utf8').trim(), 'base64');
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', secret, iv).setAAD(Buffer.from(kind));
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return prefix + Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64url');
}
const sha16 = k => crypto.createHash('sha256').update(k).digest('hex').slice(0, 16);

test('Grants: approving writes a grant with the key fingerprint and role, never the key', async () => {
  const g = await startGateway();
  try {
    const c = await connect(g.base, { key: VIEWER_KEY, name: 'Claude Desktop' });
    const file = fs.readFileSync(path.join(g.stateDir, 'grants.json'), 'utf8');
    assert.ok(!file.includes(VIEWER_KEY), 'the API key is not stored');
    const grants = Object.values(JSON.parse(file));
    assert.equal(grants.length, 1);
    const [grant] = grants;
    assert.equal(grant.keyFp, sha16(VIEWER_KEY));
    assert.equal(grant.keyRole, 'viewer');
    assert.equal(grant.clientName, 'Claude Desktop');
    assert.equal(grant.clientHost, 'claude.ai');
    assert.equal(grant.codeUsed, true);
    assert.ok(grant.codeJti && grant.refreshJti && grant.createdAt);
    assert.equal(grant.revokedAt, undefined);
    assert.equal((await mcpAt(g.base, c.tok.access_token)).status, 200);
    assert.deepEqual(fs.readdirSync(g.stateDir).filter(f => f.endsWith('.tmp') || f === 'revoked-refresh.json'), []);
  } finally {
    await g.stop();
  }
});

test('Grants: lastUsedAt is kept in memory and flushed when the server closes', async () => {
  const dir = newStateDir();
  let t = 5_000_000;
  const g = await startGateway({ stateDir: dir, now: () => t });
  const c = await connect(g.base);
  const gid = Object.keys(grantsOf(dir))[0];
  const before = grantsOf(dir)[gid].lastUsedAt;
  t += 10_000;
  assert.equal((await mcpAt(g.base, c.tok.access_token)).status, 200);
  assert.equal(grantsOf(dir)[gid].lastUsedAt, before, 'a /mcp call does not write the file');
  await g.stop();
  assert.equal(grantsOf(dir)[gid].lastUsedAt, 5_010_000);
});

test('Grants: a code reused after a gateway restart revokes the grant, and the first access token gets 401', async () => {
  const a = await startGateway();
  const c = await connect(a.base);
  assert.equal((await mcpAt(a.base, c.tok.access_token)).status, 200);
  await a.stop();

  const b = await startGateway({ stateDir: a.stateDir });
  try {
    const again = await formAt(b.base, '/oauth/token', c.exchange);
    assert.equal(again.status, 400);
    assert.equal((await again.json()).error, 'invalid_grant');
    assert.ok(Object.values(grantsOf(b.stateDir))[0].revokedAt, 'grant revoked');
    const res = await mcpAt(b.base, c.tok.access_token);
    assert.equal(res.status, 401);
    assert.match(res.headers.get('www-authenticate'), /resource_metadata="[^"]+", scope="mcp", error="invalid_token"$/);
    const rt = await formAt(b.base, '/oauth/token', { grant_type: 'refresh_token', refresh_token: c.tok.refresh_token, client_id: c.client_id });
    assert.equal(rt.status, 400, 'its refresh token is dead too');
  } finally {
    await b.stop();
  }
});

test('Grants: a revoked grant stays revoked across a restart', async () => {
  const a = await startGateway();
  const c = await connect(a.base);
  await formAt(a.base, '/oauth/revoke', { token: c.tok.access_token });
  await a.stop();
  const b = await startGateway({ stateDir: a.stateDir });
  try {
    assert.equal((await mcpAt(b.base, c.tok.access_token)).status, 401);
  } finally {
    await b.stop();
  }
});

test('Grants: tokens from before phase 2 (no gid) are refused', async () => {
  const g = await startGateway();
  try {
    const { client_id } = await connect(g.base); // also creates the secret
    const old = {
      access: sealLegacy(g.stateDir, 'access', 'owga.', { k: GOOD_KEY, c: client_id, aud: `${ISSUER}/mcp`, exp: Date.now() + 60_000 }),
      refresh: sealLegacy(g.stateDir, 'refresh', 'owgr.', { k: GOOD_KEY, c: client_id, sc: 'mcp', jti: 'j1', exp: Date.now() + 60_000 }),
    };
    const res = await mcpAt(g.base, old.access);
    assert.equal(res.status, 401);
    assert.match(res.headers.get('www-authenticate'), /error="invalid_token"/);
    const rt = await formAt(g.base, '/oauth/token', { grant_type: 'refresh_token', refresh_token: old.refresh, client_id });
    assert.equal(rt.status, 400);
    assert.equal((await rt.json()).error, 'invalid_grant');

    const { verifier, challenge } = pkce();
    const code = sealLegacy(g.stateDir, 'code', 'owgc.', {
      k: GOOD_KEY, c: client_id, u: 'https://claude.ai/cb', ch: challenge, sc: 'mcp', jti: 'c1', exp: Date.now() + 60_000,
    });
    const ex = await formAt(g.base, '/oauth/token', {
      grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: 'https://claude.ai/cb', client_id,
    });
    assert.equal(ex.status, 400);
    assert.equal((await ex.json()).error, 'invalid_grant');
  } finally {
    await g.stop();
  }
});

test('Grants: loading prunes grants revoked over 30 days ago and grants idle past the refresh TTL', async () => {
  const dir = newStateDir();
  const day = 86400_000;
  const t = Date.now();
  fs.writeFileSync(
    path.join(dir, 'grants.json'),
    JSON.stringify({
      oldRevoked: { createdAt: t - 90 * day, lastUsedAt: t - 40 * day, revokedAt: t - 31 * day },
      recentRevoked: { createdAt: t - 5 * day, lastUsedAt: t - 2 * day, revokedAt: t - 1 * day },
      idle: { createdAt: t - 90 * day, lastUsedAt: t - 31 * day },
      neverUsedOld: { createdAt: t - 31 * day },
      live: { createdAt: t - 90 * day, lastUsedAt: t - 1 * day },
    }),
  );
  const g = await startGateway({ stateDir: dir });
  try {
    assert.deepEqual(Object.keys(grantsOf(dir)).sort(), ['live', 'recentRevoked']);
  } finally {
    await g.stop();
  }
});

test('Refresh: replaying an old refresh token revokes the grant', async () => {
  const g = await startGateway();
  try {
    const c = await connect(g.base);
    const r2 = await (await c.refresh(c.tok.refresh_token)).json();
    const r3 = await (await c.refresh(r2.refresh_token)).json();
    assert.equal((await c.refresh(c.tok.refresh_token)).status, 400, 'two rotations old');
    assert.ok(Object.values(grantsOf(g.stateDir))[0].revokedAt);
    assert.equal((await mcpAt(g.base, r3.access_token)).status, 401, 'the newest access token is cut off');
    assert.equal((await c.refresh(r3.refresh_token)).status, 400, 'and so is the newest refresh token');
  } finally {
    await g.stop();
  }
});

test('Refresh: the previous token works again within 30 s and revokes the grant after that', async () => {
  let t = 1_000_000;
  const g = await startGateway({ now: () => t });
  try {
    const a = await connect(g.base);
    const r2 = await (await a.refresh(a.tok.refresh_token)).json();
    t += 29_000;
    const retry = await a.refresh(a.tok.refresh_token); // the client lost the response to the first refresh
    assert.equal(retry.status, 200, 'inside the window');
    const r3 = await retry.json();
    assert.notEqual(r3.refresh_token, r2.refresh_token);
    assert.equal((await mcpAt(g.base, r3.access_token)).status, 200);
    assert.equal(grantsOf(g.stateDir)[Object.keys(grantsOf(g.stateDir))[0]].revokedAt, undefined);

    const b = await connect(g.base);
    await b.refresh(b.tok.refresh_token);
    t += 31_000;
    assert.equal((await b.refresh(b.tok.refresh_token)).status, 400, 'after the window');
    const gb = Object.values(grantsOf(g.stateDir)).filter(x => x.revokedAt);
    assert.equal(gb.length, 1, 'only the replayed grant is revoked');
  } finally {
    await g.stop();
  }
});

test('Refresh: a key revoked upstream makes the refresh fail and revokes the grant', async () => {
  const key = 'owa_k1_short_lived';
  liveKeys.add(key);
  const g = await startGateway();
  try {
    const c = await connect(g.base, { key });
    assert.equal((await mcpAt(g.base, c.tok.access_token)).status, 200);
    liveKeys.delete(key);
    const res = await c.refresh(c.tok.refresh_token);
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, 'invalid_grant');
    assert.ok(Object.values(grantsOf(g.stateDir))[0].revokedAt, 'grant revoked');
    assert.equal((await mcpAt(g.base, c.tok.access_token)).status, 401);
  } finally {
    liveKeys.delete(key);
    await g.stop();
  }
});

test('Refresh: two concurrent refreshes with the same token give exactly one success', async () => {
  const g = await startGateway();
  validateDelayMs = 100;
  try {
    const c = await connect(g.base);
    const [x, y] = await Promise.all([c.refresh(c.tok.refresh_token), c.refresh(c.tok.refresh_token)]);
    assert.deepEqual([x.status, y.status].sort(), [200, 400]);
    const winner = await (x.status === 200 ? x : y).json();
    validateDelayMs = 0;
    assert.equal((await mcpAt(g.base, winner.access_token)).status, 200, 'the grant survives the race');
  } finally {
    validateDelayMs = 0;
    await g.stop();
  }
});

test('Revoke: /oauth/revoke on an access token cuts off /mcp at the next call', async () => {
  const g = await startGateway();
  try {
    const c = await connect(g.base);
    assert.equal((await mcpAt(g.base, c.tok.access_token)).status, 200);
    const res = await formAt(g.base, '/oauth/revoke', { token: c.tok.access_token });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('access-control-allow-origin'), '*');
    assert.equal((await mcpAt(g.base, c.tok.access_token)).status, 401);
    assert.equal((await c.refresh(c.tok.refresh_token)).status, 400, 'the grant is gone, refresh too');
  } finally {
    await g.stop();
  }
});

test('Revoke: a refresh token revokes the grant, and unknown, garbage or missing tokens still answer 200', async () => {
  const g = await startGateway();
  try {
    const c = await connect(g.base);
    assert.equal((await formAt(g.base, '/oauth/revoke', { token: c.tok.refresh_token })).status, 200);
    assert.equal((await mcpAt(g.base, c.tok.access_token)).status, 401);
    for (const body of [{ token: 'owga.AAAA' }, { token: 'whatever' }, {}, { token: GOOD_KEY }]) {
      assert.equal((await formAt(g.base, '/oauth/revoke', body)).status, 200, JSON.stringify(body));
    }
    const junk = await fetch(`${g.base}/oauth/revoke`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{nope' });
    assert.equal(junk.status, 200);
    assert.equal((await mcpAt(g.base, c.tok.access_token)).status, 401);
    assert.equal((await fetch(`${g.base}/mcp`, { method: 'POST', headers: { 'x-api-key': GOOD_KEY }, body: '{}' })).status, 200, 'the static key is untouched');
  } finally {
    await g.stop();
  }
});

test('Revoke: another grant is not affected; the preflight answers 204; metadata advertises the endpoint', async () => {
  const g = await startGateway();
  try {
    const one = await connect(g.base);
    const two = await connect(g.base);
    await formAt(g.base, '/oauth/revoke', { token: one.tok.access_token });
    assert.equal((await mcpAt(g.base, two.tok.access_token)).status, 200);

    const pre = await fetch(`${g.base}/oauth/revoke`, { method: 'OPTIONS' });
    assert.equal(pre.status, 204);
    assert.equal(pre.headers.get('access-control-allow-origin'), '*');
    assert.match(pre.headers.get('access-control-allow-methods'), /POST/);

    const meta = await (await fetch(`${g.base}/.well-known/oauth-authorization-server`)).json();
    assert.equal(meta.revocation_endpoint, `${ISSUER}/oauth/revoke`);
    assert.deepEqual(meta.revocation_endpoint_auth_methods_supported, ['none']);
  } finally {
    await g.stop();
  }
});

// ---- phase 2: consent CSRF, client host, connections view ----

const rawPost = (b, url, body, headers = {}) =>
  fetch(b + url, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(body),
  });
const consentQuery = async (b, uri = 'https://claude.ai/cb', name = 'Claude') => {
  const reg = await (
    await fetch(`${b}/oauth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [uri], client_name: name }),
    })
  ).json();
  return authQuery(reg.client_id, uri, pkce().challenge);
};

test('Consent: a POST is refused with the consent page and 403 unless Origin is the issuer, or absent with Sec-Fetch-Site same-origin', async () => {
  const g = await startGateway();
  try {
    const q = { ...(await consentQuery(g.base)), api_key: GOOD_KEY };
    const refused = [
      { origin: 'https://evil.example' },
      { origin: 'null' },
      { origin: 'https://wa.example.test.evil.com' },
      { origin: 'https://evil.example', 'sec-fetch-site': 'same-origin' }, // Origin wins over Sec-Fetch-Site
      { 'sec-fetch-site': 'cross-site' },
      { 'sec-fetch-site': 'same-site' },
      { 'sec-fetch-site': 'none' },
      {}, // neither header
    ];
    for (const headers of refused) {
      const res = await rawPost(g.base, '/oauth/authorize', q, headers);
      assert.equal(res.status, 403, JSON.stringify(headers));
      assert.equal(res.headers.get('location'), null, 'no redirect with a code');
      const html = await res.text();
      assert.match(html, /<form/, 'the consent page is shown again');
      assert.ok(!html.includes(GOOD_KEY), 'the key is never echoed');
    }
    assert.equal(fs.existsSync(path.join(g.stateDir, 'grants.json')), false, 'a refused POST creates no grant');

    assert.equal((await rawPost(g.base, '/oauth/authorize', q, { origin: ISSUER })).status, 302, 'issuer Origin');
    assert.equal((await rawPost(g.base, '/oauth/authorize', q, { 'sec-fetch-site': 'same-origin' })).status, 302, 'same-origin, no Origin');
  } finally {
    await g.stop();
  }
});

test('Consent: the page shows the client host beside the client name, both HTML-escaped', async () => {
  const g = await startGateway();
  try {
    const q = await consentQuery(g.base, 'https://app.evil.example:8443/cb', '<b>Fake Claude</b>');
    const html = await (await fetch(`${g.base}/oauth/authorize?${new URLSearchParams(q)}`)).text();
    assert.match(html, /<code>app\.evil\.example:8443<\/code>/, 'redirect host (with port), visible beside the name');
    assert.match(html, /&lt;b&gt;Fake Claude&lt;\/b&gt;/, 'name escaped');
    assert.ok(!html.includes('<b>Fake Claude</b>'));

    // The host is also on the page re-rendered after a wrong key.
    const bad = await rawPost(g.base, '/oauth/authorize', { ...q, api_key: 'wrong' }, { origin: ISSUER });
    assert.equal(bad.status, 401);
    assert.match(await bad.text(), /<code>app\.evil\.example:8443<\/code>/);
  } finally {
    await g.stop();
  }
});

const connectionsPost = (b, key, headers = { origin: ISSUER }) => rawPost(b, '/oauth/connections', { api_key: key }, headers);
const tokensIn = html => [...html.matchAll(/name="vtoken" value="([^"]+)"/g)].map(m => m[1]);
const gidOf = (dir, name) => Object.entries(grantsOf(dir)).find(([, g]) => g.clientName === name)[0];
async function twoConnections() {
  const g = await startGateway();
  const admin = await connect(g.base, { key: GOOD_KEY, name: 'AdminClient', uri: 'https://admin.example.test/cb' });
  const viewer = await connect(g.base, { key: VIEWER_KEY, name: 'ViewerClient', uri: 'https://viewer.example.test/cb' });
  return { g, admin, viewer, adminGid: gidOf(g.stateDir, 'AdminClient'), viewerGid: gidOf(g.stateDir, 'ViewerClient') };
}

test('Connections: GET is a form that POSTs a key, with no key in any URL, and every page is framed-denied and uncached', async () => {
  const g = await startGateway();
  try {
    const res = await fetch(`${g.base}/oauth/connections?api_key=${GOOD_KEY}`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    const html = await res.text();
    assert.match(html, /<form[^>]*method="post"[^>]*action="\/oauth\/connections"/i);
    assert.match(html, /<input[^>]*type="password"[^>]*name="api_key"/);
    assert.ok(!html.includes(GOOD_KEY), 'a key in the query string is ignored and not echoed');
    assert.ok(!/<tr/.test(html), 'a GET lists nothing');

    const post = await connectionsPost(g.base, GOOD_KEY);
    assert.match(post.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.equal(post.headers.get('cache-control'), 'no-store');
    const bad = await connectionsPost(g.base, 'wrong');
    assert.equal(bad.status, 401);
    assert.match(bad.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.ok(!(await bad.text()).includes('wrong'), 'a bad key is not echoed either');
  } finally {
    await g.stop();
  }
});

test('Connections: a key sees only its own grants, an admin key sees all, and the key is never echoed', async () => {
  const { g, admin, viewer } = await twoConnections();
  try {
    const own = await (await connectionsPost(g.base, VIEWER_KEY)).text();
    assert.match(own, /ViewerClient/);
    assert.match(own, /viewer\.example\.test/);
    assert.match(own, /active/);
    assert.doesNotMatch(own, /AdminClient/);
    assert.equal(tokensIn(own).length, 1);

    const all = await (await connectionsPost(g.base, GOOD_KEY)).text();
    assert.match(all, /AdminClient/);
    assert.match(all, /ViewerClient/);
    assert.equal(tokensIn(all).length, 2);
    for (const html of [own, all]) {
      assert.ok(!html.includes(GOOD_KEY) && !html.includes(VIEWER_KEY), 'no key in the page');
      assert.match(html, /\d{4}-\d\d-\d\dT/, 'created and last used are shown');
    }
    assert.ok(admin.tok && viewer.tok);
  } finally {
    await g.stop();
  }
});

test('Connections: revoke cuts off the grant; revoked rows show their status', async () => {
  const { g, admin, viewer } = await twoConnections();
  try {
    const [token] = tokensIn(await (await connectionsPost(g.base, VIEWER_KEY)).text());
    const res = await rawPost(g.base, '/oauth/connections/revoke', { vtoken: token }, { origin: ISSUER });
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.equal((await mcpAt(g.base, viewer.tok.access_token)).status, 401);
    assert.equal((await mcpAt(g.base, admin.tok.access_token)).status, 200, 'other grants untouched');
    assert.match(await (await connectionsPost(g.base, VIEWER_KEY)).text(), /revoked/);
  } finally {
    await g.stop();
  }
});

test('Connections: an admin token revokes any grant; a non-admin token only its own key\'s grants', async () => {
  const { g, admin, viewer, adminGid, viewerGid } = await twoConnections();
  try {
    const vToken = (key, gid, role, exp = Date.now() + 60_000) =>
      sealLegacy(g.stateDir, 'v', 'owgv.', { keyFp: sha16(key), role, gid, exp });
    const revoke = token => rawPost(g.base, '/oauth/connections/revoke', { vtoken: token }, { origin: ISSUER });

    // a viewer-key token aimed at the admin grant is refused
    assert.equal((await revoke(vToken(VIEWER_KEY, adminGid, 'viewer'))).status, 403);
    assert.equal((await mcpAt(g.base, admin.tok.access_token)).status, 200);
    // a token claiming admin with the wrong key fingerprint is still only as good as its role claim; the
    // sealed role comes from our own validate call, so a viewer token cannot carry it
    // an admin token covers the viewer's grant
    assert.equal((await revoke(vToken(GOOD_KEY, viewerGid, 'admin'))).status, 200);
    assert.equal((await mcpAt(g.base, viewer.tok.access_token)).status, 401);
    // an unknown gid is refused
    assert.equal((await revoke(vToken(GOOD_KEY, 'no-such-gid', 'admin'))).status, 403);
  } finally {
    await g.stop();
  }
});

test('Connections: revoke refuses a foreign Origin, a missing Origin, a bad, expired or wrong-kind token', async () => {
  let t = 10_000_000;
  const g = await startGateway({ now: () => t });
  try {
    const c = await connect(g.base, { name: 'Solo' });
    const [token] = tokensIn(await (await connectionsPost(g.base, GOOD_KEY)).text());
    const revoke = (vtoken, headers = { origin: ISSUER }) => rawPost(g.base, '/oauth/connections/revoke', { vtoken }, headers);

    assert.equal((await revoke(token, { origin: 'https://evil.example' })).status, 403);
    assert.equal((await revoke(token, { 'sec-fetch-site': 'cross-site' })).status, 403);
    assert.equal((await revoke(token, {})).status, 403);
    assert.equal((await revoke('owgv.AAAA')).status, 403, 'forged');
    assert.equal((await revoke(c.tok.access_token)).status, 403, 'an access token is not a revoke token');
    assert.equal((await mcpAt(g.base, c.tok.access_token)).status, 200, 'still live after every refusal');

    t += 5 * 60_000 + 1000;
    assert.equal((await revoke(token)).status, 403, 'expired after 5 minutes');
    assert.equal((await mcpAt(g.base, c.tok.access_token)).status, 200);

    t -= 5 * 60_000; // inside the TTL again: the same token works
    assert.equal((await revoke(token)).status, 200);
    assert.equal((await mcpAt(g.base, c.tok.access_token)).status, 401);
  } finally {
    await g.stop();
  }
});
