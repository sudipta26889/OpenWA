// Run: node --test ops/mcp-oauth-gateway/
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
let upstream, gateway, base, seen;

const listen = srv => new Promise(r => srv.listen(0, '127.0.0.1', () => r(srv.address().port)));

before(async () => {
  // Fake OpenWA: validates GOOD_KEY, records what /mcp received, echoes a WebSocket-ish upgrade.
  upstream = http.createServer((req, res) => {
    if (req.url === '/api/auth/validate') {
      const ok = req.headers['x-api-key'] === GOOD_KEY;
      res.writeHead(ok ? 200 : 401, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(ok ? { valid: true } : { message: 'Invalid API key' }));
    }
    seen = { url: req.url, method: req.method, headers: req.headers };
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ upstream: true }));
  });
  upstream.on('upgrade', (req, socket) => {
    seen = { url: req.url, headers: req.headers };
    socket.end('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\npong');
  });
  const upPort = await listen(upstream);
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
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
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
  assert.equal((await form('/oauth/token', exchange)).status, 400, 'a code is single-use');

  const mcp = await fetch(`${base}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${tok.access_token}` }, body: '{}' });
  assert.equal(mcp.status, 200);
  assert.equal(seen.headers['x-api-key'], GOOD_KEY);
  assert.equal(seen.headers.authorization, undefined, 'our token never reaches OpenWA');

  const refresh = { grant_type: 'refresh_token', refresh_token: tok.refresh_token, client_id };
  const rotated = await form('/oauth/token', refresh);
  assert.equal(rotated.status, 200);
  assert.equal((await form('/oauth/token', refresh)).status, 400, 'a rotated refresh token is dead');
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
