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
