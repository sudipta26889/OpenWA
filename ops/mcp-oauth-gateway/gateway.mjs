// mcp-oauth-gateway — OAuth 2.1 for OpenWA's /mcp, kept OUTSIDE the OpenWA source tree so upstream
// upgrades merge without conflicts.
//
// Sits in front of OpenWA on the published port and transparently proxies everything (HTTP + WebSocket).
// It only owns the OAuth surface: discovery (/.well-known/*), dynamic client registration, the consent
// page (operator types an OpenWA API key) and the token endpoint. A POST /mcp carrying one of its access
// tokens is forwarded with the underlying API key in X-API-Key, so OpenWA only ever sees plain key auth.
//
// Client ids, auth codes, access and refresh tokens are AES-256-GCM sealed blobs under one secret in
// STATE_DIR. The one piece of state is STATE_DIR/grants.json: a record per approved connection (a "grant",
// keyed by the `gid` every code and token carries). It holds code use, the current refresh jti and
// revocation, so reuse, replay and /oauth/revoke can cut a connection off. One process only.
// Zero dependencies: Node 22 built-ins only.
import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const ACCESS_TTL_MS = 3600_000; // 1h
const REFRESH_TTL_MS = 30 * 86400_000; // 30d
const CODE_TTL_MS = 120_000; // 2m
const REFRESH_RETRY_MS = 30_000; // the just-rotated refresh token still works this long (lost response)
const REVOKED_KEEP_MS = 30 * 86400_000; // revoked grants are kept this long, then pruned
const FLUSH_MS = 60_000; // lastUsedAt reaches the disk this often
const SCOPE = 'mcp';
const MAX_BODY = 64 * 1024; // OAuth form/JSON bodies are tiny
// The prefix tells our tokens apart from OpenWA keys (owa_…); it is also the AES-GCM AAD, so a sealed
// blob of one kind can never be replayed as another (e.g. a client id as an access token).
const PREFIX = { access: 'owga.', refresh: 'owgr.', code: 'owgc.', client: 'owgk.' };
// Native-app redirect schemes DCR accepts besides https and http loopback. Any other custom scheme is refused.
const CUSTOM_REDIRECT_SCHEMES = ['cursor', 'vscode'];
const LOOPBACK_HOSTS = ['localhost', '127.0.0.1'];
const LOOPBACK_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;
// Browser-side origins of hosted MCP connectors; matched exactly, never by suffix.
const HOSTED_CLIENT_ORIGINS = ['https://claude.ai', 'https://chatgpt.com'];
const AUTHORIZE_PARAMS = ['client_id', 'redirect_uri', 'response_type', 'code_challenge', 'code_challenge_method', 'state', 'scope', 'resource'];

const log = (msg, extra = {}) => console.log(JSON.stringify({ ts: new Date().toISOString(), msg, ...extra }));

function loadSecret(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'gateway-secret.key');
  if (!fs.existsSync(file)) fs.writeFileSync(file, crypto.randomBytes(32).toString('base64'), { mode: 0o600 });
  const key = Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64');
  if (key.length !== 32) throw new Error(`${file} must hold 32 base64 bytes`);
  return key;
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return {};
  }
}

const esc = s =>
  String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function consentPage(q, error) {
  const hidden = AUTHORIZE_PARAMS.map(k => `<input type="hidden" name="${k}" value="${esc(q[k])}">`).join('\n');
  const errHtml = error ? `<p style="color:#c0392b;margin:0 0 12px">${esc(error)}</p>` : '';
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize — OpenWA</title><style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#1e293b;padding:28px 32px;border-radius:12px;max-width:380px;width:100%;box-shadow:0 10px 40px rgba(0,0,0,.4)}
h1{font-size:18px;margin:0 0 4px}p.sub{color:#94a3b8;font-size:13px;margin:0 0 20px}
label{display:block;font-size:13px;margin:0 0 6px}
input[type=password]{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;font-size:14px}
button{margin-top:18px;width:100%;padding:11px;border:0;border-radius:8px;background:#22c55e;color:#04240f;font-weight:600;font-size:14px;cursor:pointer}
code{color:#38bdf8}</style></head><body><form class="card" method="post" action="/oauth/authorize">
<h1>Authorize connection</h1><p class="sub"><code>${esc(q.client_name || 'An MCP client')}</code> is requesting access to your OpenWA MCP tools.</p>
${errHtml}<label for="k">Enter an OpenWA API key to approve</label>
<input id="k" type="password" name="api_key" placeholder="owa_k1_… or your master key" autocomplete="off" required>
${hidden}<button type="submit">Approve</button></form></body></html>`;
}

function looksLikeJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  try {
    return typeof JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')).alg === 'string';
  } catch {
    return false;
  }
}

/** RFC 8252: a registered http loopback URI matches any port; everything else is an exact match. */
function redirectMatches(registered, given) {
  if (registered === given) return true;
  try {
    const r = new URL(registered);
    const g = new URL(given);
    if (r.protocol !== 'http:' || !LOOPBACK_HOSTS.includes(r.hostname)) return false;
    return g.protocol === r.protocol && g.hostname === r.hostname && g.pathname === r.pathname && g.search === r.search;
  } catch {
    return false;
  }
}

class OAuthError extends Error {
  constructor(error, description, status = 400) {
    super(`${error}: ${description}`);
    Object.assign(this, { error, description, status });
  }
}

export function createGateway({ issuer, upstream, stateDir, now = () => Date.now() }) {
  issuer = issuer.replace(/\/$/, '');
  const resource = `${issuer}/mcp`;
  const resourceMetadataUrl = `${issuer}/.well-known/oauth-protected-resource`;
  const up = new URL(upstream);
  const agent = new http.Agent({ keepAlive: true });
  const secret = loadSecret(stateDir);
  const grantsFile = path.join(stateDir, 'grants.json');
  const grants = readJson(grantsFile); // gid -> grant record
  let dirty = false; // lastUsedAt changed in memory and is not on disk yet
  const refreshing = new Set(); // refresh jtis being handled right now

  const writeGrants = () => {
    fs.writeFileSync(`${grantsFile}.tmp`, JSON.stringify(grants), { mode: 0o600 });
    fs.renameSync(`${grantsFile}.tmp`, grantsFile);
    dirty = false;
  };
  const pruneGrants = () => {
    let changed = false;
    for (const [gid, g] of Object.entries(grants)) {
      const idle = (g.lastUsedAt ?? g.createdAt ?? 0) + REFRESH_TTL_MS < now();
      const goneLong = g.revokedAt !== undefined && g.revokedAt + REVOKED_KEEP_MS < now();
      if (idle || goneLong) {
        delete grants[gid];
        changed = true;
      }
    }
    return changed;
  };
  if (pruneGrants()) writeGrants();
  const revokeGrant = gid => {
    const g = grants[gid];
    if (!g || g.revokedAt !== undefined) return;
    g.revokedAt = now();
    writeGrants();
    log('grant revoked', { client_name: g.clientName });
  };
  /** The live grant behind a token's gid, or undefined (no gid, unknown, or revoked). */
  const liveGrant = gid => {
    const g = typeof gid === 'string' ? grants[gid] : undefined;
    return g && g.revokedAt === undefined ? g : undefined;
  };
  const touch = g => {
    g.lastUsedAt = now();
    dirty = true;
  };

  const seal = (kind, obj) => {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', secret, iv).setAAD(Buffer.from(kind));
    const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
    return PREFIX[kind] + Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64url');
  };
  const unseal = (kind, token, { ignoreExp = false } = {}) => {
    if (typeof token !== 'string' || !token.startsWith(PREFIX[kind])) return null;
    try {
      const raw = Buffer.from(token.slice(PREFIX[kind].length), 'base64url');
      const d = crypto.createDecipheriv('aes-256-gcm', secret, raw.subarray(0, 12)).setAAD(Buffer.from(kind));
      d.setAuthTag(raw.subarray(12, 28));
      const obj = JSON.parse(Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8'));
      return !ignoreExp && obj.exp !== undefined && obj.exp < now() ? null : obj;
    } catch {
      return null;
    }
  };

  // ---- OAuth protocol ----

  const protectedResourceMetadata = () => ({
    resource,
    authorization_servers: [issuer],
    scopes_supported: [SCOPE],
    bearer_methods_supported: ['header'],
    resource_documentation: issuer,
  });
  /** RFC 8707: a supplied resource must be this server's /mcp (trailing slash tolerated); omitting it is fine. */
  const checkResource = r => {
    if (r !== undefined && r !== '' && String(r).replace(/\/$/, '') !== resource) {
      throw new OAuthError('invalid_target', `resource must be ${resource}`);
    }
  };
  const authorizationServerMetadata = () => ({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oauth/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    scopes_supported: [SCOPE],
    authorization_response_iss_parameter_supported: true,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    revocation_endpoint_auth_methods_supported: ['none'],
  });

  function registerClient(body) {
    const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris.map(String) : [];
    if (redirectUris.length === 0) throw new OAuthError('invalid_client_metadata', 'redirect_uris is required');
    for (const uri of redirectUris) {
      const custom = CUSTOM_REDIRECT_SCHEMES.some(s => uri.startsWith(`${s}://`));
      if (!custom && !/^https:\/\//.test(uri) && !/^http:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(uri)) {
        throw new OAuthError('invalid_redirect_uri', `redirect_uri must be https (or http localhost): ${uri}`);
      }
    }
    const name = typeof body.client_name === 'string' ? body.client_name.slice(0, 200) : null;
    // Stateless client: the id IS the sealed registration, so nothing is stored.
    const clientId = seal('client', { r: redirectUris, n: name });
    log('client registered', { client_name: name });
    return {
      client_id: clientId,
      client_id_issued_at: Math.floor(now() / 1000),
      redirect_uris: redirectUris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      client_name: name,
      scope: SCOPE,
    };
  }

  function validateAuthorizeParams(q) {
    const client = unseal('client', q.client_id);
    if (!client) throw new OAuthError('unauthorized_client', 'Unknown client_id');
    if (!q.redirect_uri || !client.r.some(r => redirectMatches(r, q.redirect_uri))) {
      throw new OAuthError('invalid_request', 'redirect_uri does not match a registered value');
    }
    checkResource(q.resource);
    if (q.response_type !== 'code') throw new OAuthError('unsupported_response_type', 'response_type must be code');
    if (!q.code_challenge) throw new OAuthError('invalid_request', 'PKCE code_challenge is required');
    if (q.code_challenge_method !== 'S256') throw new OAuthError('invalid_request', 'code_challenge_method must be S256');
    return client;
  }

  /**
   * Ask OpenWA itself whether the key is valid — the gateway never sees OpenWA's key store.
   * Returns `{ role }` for a valid key, or null.
   */
  async function apiKeyIsValid(apiKey) {
    if (!apiKey) return null;
    try {
      const res = await fetch(new URL('/api/auth/validate', up), { method: 'POST', headers: { 'x-api-key': apiKey } });
      if (!res.ok) return null;
      const body = await res.json();
      return body.valid === true ? { role: typeof body.role === 'string' ? body.role : 'unknown' } : null;
    } catch (e) {
      log('key validation failed', { error: String(e) });
      throw new OAuthError('temporarily_unavailable', 'OpenWA is unreachable, try again', 503);
    }
  }

  async function approve(q) {
    const client = validateAuthorizeParams(q);
    const validated = await apiKeyIsValid(q.api_key);
    if (!validated) throw new OAuthError('access_denied', 'Invalid OpenWA API key', 401);
    const gid = crypto.randomUUID();
    const codeJti = crypto.randomUUID();
    grants[gid] = {
      clientName: client.n ?? null,
      clientHost: new URL(q.redirect_uri).host,
      keyFp: crypto.createHash('sha256').update(q.api_key).digest('hex').slice(0, 16),
      keyRole: validated.role,
      createdAt: now(),
      lastUsedAt: now(),
      codeJti,
      codeUsed: false,
      refreshJti: null,
    };
    writeGrants();
    const code = seal('code', {
      k: q.api_key,
      c: q.client_id,
      u: q.redirect_uri,
      ch: q.code_challenge,
      sc: q.scope || SCOPE,
      jti: codeJti,
      gid,
      exp: now() + CODE_TTL_MS,
    });
    const url = new URL(q.redirect_uri);
    url.searchParams.set('code', code);
    if (q.state) url.searchParams.set('state', q.state);
    url.searchParams.set('iss', issuer); // RFC 9207
    return url.toString();
  }

  /** Mint an access + refresh pair for a grant. The caller persists the grant (refreshJti changes here). */
  function issueTokens(gid, g, apiKey, clientId, scope) {
    const jti = crypto.randomUUID();
    g.refreshJti = jti;
    touch(g);
    return {
      access_token: seal('access', { k: apiKey, c: clientId, gid, aud: resource, exp: now() + ACCESS_TTL_MS }),
      token_type: 'Bearer',
      expires_in: ACCESS_TTL_MS / 1000,
      refresh_token: seal('refresh', { k: apiKey, c: clientId, sc: scope, gid, jti, exp: now() + REFRESH_TTL_MS }),
      scope,
    };
  }

  async function refreshGrant(b) {
    if (!b.refresh_token || !b.client_id) throw new OAuthError('invalid_request', 'refresh_token and client_id are required');
    const invalid = () => new OAuthError('invalid_grant', 'refresh_token is invalid or expired');
    // 1. Unseal and check the grant. A token without a gid (pre-grants) is refused.
    const rt = unseal('refresh', b.refresh_token);
    if (!rt || rt.c !== b.client_id || !liveGrant(rt.gid)) throw invalid();
    // A second request carrying a token that is already being refreshed is a race, not a lost-response retry
    // (that arrives after the first answer). It gets nothing, and the first request keeps its result.
    if (refreshing.has(rt.jti)) throw invalid();
    refreshing.add(rt.jti);
    try {
      // 2. The key must still be valid upstream. This is the only await: nothing below it yields.
      if (!(await apiKeyIsValid(rt.k))) {
        revokeGrant(rt.gid);
        throw invalid();
      }
      // 3. Compare-and-set against the grant as it is NOW (it may have been revoked or rotated meanwhile).
      const g = liveGrant(rt.gid);
      if (!g) throw invalid();
      const inRetryWindow = rt.jti === g.prevRefreshJti && now() < g.prevRefreshUntil;
      if (rt.jti !== g.refreshJti && !inRetryWindow) {
        revokeGrant(rt.gid); // an old token came back: assume it leaked
        throw invalid();
      }
      // Rotate (OAuth 2.1, public clients). The token being replaced stays usable for the retry window.
      g.prevRefreshJti = g.refreshJti;
      g.prevRefreshUntil = now() + REFRESH_RETRY_MS;
      const tokens = issueTokens(rt.gid, g, rt.k, rt.c, rt.sc);
      writeGrants();
      return tokens;
    } finally {
      refreshing.delete(rt.jti);
    }
  }

  async function token(b) {
    if (b.grant_type === 'authorization_code' || b.grant_type === 'refresh_token') checkResource(b.resource);
    if (b.grant_type === 'authorization_code') {
      if (!b.code || !b.code_verifier || !b.redirect_uri || !b.client_id) {
        throw new OAuthError('invalid_request', 'code, code_verifier, redirect_uri, client_id are required');
      }
      const code = unseal('code', b.code);
      const g = code && liveGrant(code.gid);
      if (!g || g.codeJti !== code.jti) throw new OAuthError('invalid_grant', 'Authorization code is invalid or expired');
      if (g.codeUsed) {
        revokeGrant(code.gid); // reuse: whoever holds the first tokens loses them too
        throw new OAuthError('invalid_grant', 'Authorization code is invalid or expired');
      }
      if (code.c !== b.client_id || !redirectMatches(code.u, b.redirect_uri)) throw new OAuthError('invalid_grant', 'client_id / redirect_uri mismatch');
      const challenge = crypto.createHash('sha256').update(b.code_verifier).digest('base64url');
      if (challenge.length !== code.ch.length || !crypto.timingSafeEqual(Buffer.from(challenge), Buffer.from(code.ch))) {
        throw new OAuthError('invalid_grant', 'PKCE verification failed');
      }
      g.codeUsed = true;
      const tokens = issueTokens(code.gid, g, code.k, code.c, code.sc);
      writeGrants();
      return tokens;
    }
    if (b.grant_type === 'refresh_token') return refreshGrant(b);
    throw new OAuthError('unsupported_grant_type', `Unsupported grant_type: ${b.grant_type}`);
  }

  /** RFC 7009: revoke the grant behind an access or refresh token. Anything else is ignored. */
  function revokeToken(t) {
    const parsed = unseal('access', t, { ignoreExp: true }) ?? unseal('refresh', t, { ignoreExp: true });
    if (parsed?.gid) revokeGrant(parsed.gid);
  }

  // ---- HTTP plumbing ----

  const send = (res, status, body, headers = {}) => {
    res.writeHead(status, {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'access-control-allow-origin': '*',
      ...headers,
    });
    res.end(JSON.stringify(body));
  };
  const sendConsent = (res, q, status, error) => {
    let origin = 'https:';
    try {
      origin = new URL(q.redirect_uri).origin;
    } catch {}
    const client = unseal('client', q.client_id);
    res.writeHead(status, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      // form-action also governs the 302 the POST follows to the client's callback origin.
      'content-security-policy': `default-src 'self'; style-src 'unsafe-inline'; form-action 'self' ${origin}; base-uri 'none'; frame-ancestors 'none'`,
    });
    res.end(consentPage({ ...q, client_name: client?.n }, error));
  };
  const fail = (res, e) => {
    if (e instanceof OAuthError) {
      log('oauth error', { error: e.error, description: e.description });
      return send(res, e.status, { error: e.error, error_description: e.description });
    }
    log('oauth route error', { error: e?.stack ?? String(e) });
    send(res, 500, { error: 'server_error', error_description: 'Internal error' });
  };
  const unauthorized = (res, invalidToken) =>
    send(res, 401, { jsonrpc: '2.0', error: { code: -32001, message: 'Unauthorized' }, id: null }, {
      'www-authenticate': `Bearer resource_metadata="${resourceMetadataUrl}", scope="${SCOPE}"${invalidToken ? ', error="invalid_token"' : ''}`,
    });

  async function readBody(req) {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > MAX_BODY) throw new OAuthError('invalid_request', 'Request body too large', 413);
      chunks.push(chunk);
    }
    const text = Buffer.concat(chunks).toString('utf8');
    if ((req.headers['content-type'] ?? '').includes('application/json')) {
      try {
        return JSON.parse(text || '{}');
      } catch {
        throw new OAuthError('invalid_request', 'Malformed JSON body');
      }
    }
    return Object.fromEntries(new URLSearchParams(text));
  }

  const forwardedHeaders = req => {
    const h = { ...req.headers };
    const peer = req.socket.remoteAddress ?? '';
    h['x-forwarded-for'] = h['x-forwarded-for'] ? `${h['x-forwarded-for']}, ${peer}` : peer;
    h['x-forwarded-proto'] ??= 'http';
    h['x-forwarded-host'] ??= h.host ?? '';
    return h;
  };

  function proxy(req, res, headers = forwardedHeaders(req)) {
    const upReq = http.request(
      { host: up.hostname, port: up.port || 80, method: req.method, path: req.url, headers, agent },
      upRes => {
        res.writeHead(upRes.statusCode ?? 502, upRes.headers);
        upRes.pipe(res);
      },
    );
    upReq.on('error', e => {
      log('upstream error', { error: String(e), path: req.url });
      if (!res.headersSent) send(res, 502, { error: 'bad_gateway' });
      else res.destroy();
    });
    req.pipe(upReq);
  }

  /** POST /mcp: swap our access token for the API key it carries; trigger the OAuth flow when missing. */
  function proxyMcp(req, res) {
    // DNS-rebinding guard: a present Origin must be the issuer or a loopback origin. No Origin passes.
    const origin = req.headers.origin;
    if (
      origin !== undefined &&
      origin !== new URL(issuer).origin &&
      !LOOPBACK_ORIGIN.test(origin) &&
      !HOSTED_CLIENT_ORIGINS.includes(origin)
    ) {
      log('mcp origin refused', { origin: String(origin).slice(0, 200) });
      return send(res, 403, { jsonrpc: '2.0', error: { code: -32000, message: 'Forbidden origin' }, id: null });
    }
    const auth = req.headers.authorization;
    const bearer = typeof auth === 'string' && /^bearer /i.test(auth) ? auth.slice(7).trim() : undefined;
    if (!bearer && !req.headers['x-api-key']) return unauthorized(res, false);
    if (bearer?.startsWith(PREFIX.access)) {
      const at = unseal('access', bearer);
      const g = at && at.aud === resource ? liveGrant(at.gid) : undefined;
      if (!g) return unauthorized(res, true);
      touch(g);
      const headers = forwardedHeaders(req);
      delete headers.authorization;
      headers['x-api-key'] = at.k;
      return proxy(req, res, headers);
    }
    // A JWT is a token minted by the old in-process OAuth module (or another issuer): tell the client to
    // re-run the flow instead of letting OpenWA reject it as an unknown API key without resource_metadata.
    if (bearer && looksLikeJwt(bearer)) return unauthorized(res, true);
    proxy(req, res); // static API key: OpenWA validates it as before
  }

  const routes = {
    'GET /.well-known/oauth-protected-resource': (req, res) => send(res, 200, protectedResourceMetadata()),
    'GET /.well-known/oauth-protected-resource/mcp': (req, res) => send(res, 200, protectedResourceMetadata()),
    'GET /.well-known/oauth-authorization-server': (req, res) => send(res, 200, authorizationServerMetadata()),
    'GET /.well-known/oauth-authorization-server/mcp': (req, res) => send(res, 200, authorizationServerMetadata()),
    'POST /oauth/register': async (req, res) => send(res, 201, registerClient(await readBody(req))),
    'GET /oauth/authorize': (req, res) => {
      const q = Object.fromEntries(new URL(req.url, issuer).searchParams);
      try {
        validateAuthorizeParams(q);
        sendConsent(res, q, 200);
      } catch (e) {
        if (!(e instanceof OAuthError)) throw e;
        sendConsent(res, q, e.status, e.description);
      }
    },
    'POST /oauth/authorize': async (req, res) => {
      const b = await readBody(req);
      try {
        const location = await approve(b);
        log('authorize approved');
        res.writeHead(302, { location, 'cache-control': 'no-store' }).end();
      } catch (e) {
        if (!(e instanceof OAuthError) || e.status >= 500) throw e;
        sendConsent(res, b, e.status, e.description);
      }
    },
    'POST /oauth/token': async (req, res) => {
      const t = await token(await readBody(req));
      log('token issued');
      send(res, 200, t);
    },
    'POST /oauth/revoke': async (req, res) => {
      // RFC 7009: always 200, whatever the token (or the body) was, so the endpoint tells a caller nothing.
      try {
        revokeToken((await readBody(req)).token);
      } catch (e) {
        if (!(e instanceof OAuthError)) throw e;
      }
      res.writeHead(200, { 'cache-control': 'no-store', 'access-control-allow-origin': '*' }).end();
    },
    'POST /mcp': proxyMcp,
  };
  const cors = {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'Content-Type, Authorization, MCP-Protocol-Version',
    'access-control-max-age': '86400',
  };

  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://x').pathname.replace(/\/$/, '') || '/';
    if (req.method === 'OPTIONS' && ['/oauth/register', '/oauth/token', '/oauth/revoke'].includes(pathname)) {
      return res.writeHead(204, cors).end();
    }
    const handler = routes[`${req.method} ${pathname}`];
    if (!handler) {
      // Anything else under the OAuth surface is ours to 404 (never fall through to the dashboard SPA).
      if (pathname.startsWith('/oauth/') || pathname.startsWith('/.well-known/')) return send(res, 404, { error: 'not_found' });
      return proxy(req, res);
    }
    Promise.resolve(handler(req, res)).catch(e => fail(res, e));
  });

  // WebSocket (dashboard socket.io /events): raw TCP tunnel to OpenWA.
  server.on('upgrade', (req, socket, head) => {
    const conn = net.connect(Number(up.port || 80), up.hostname, () => {
      const headers = forwardedHeaders(req);
      const lines = Object.entries(headers).flatMap(([k, v]) => (Array.isArray(v) ? v : [v]).map(x => `${k}: ${x}`));
      conn.write(`${req.method} ${req.url} HTTP/1.1\r\n${lines.join('\r\n')}\r\n\r\n`);
      conn.write(head);
      socket.pipe(conn).pipe(socket);
    });
    const close = () => {
      socket.destroy();
      conn.destroy();
    };
    conn.on('error', close);
    socket.on('error', close);
  });

  // lastUsedAt lives in memory; flush it on a timer and when the server closes (SIGTERM calls close).
  const flush = () => {
    if (dirty) writeGrants();
  };
  const timer = setInterval(flush, FLUSH_MS);
  timer.unref(); // never keep the process (or a test run) alive
  server.on('close', () => {
    clearInterval(timer);
    flush();
  });

  return server;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const issuer = process.env.OAUTH_ISSUER;
  if (!issuer) {
    console.error('OAUTH_ISSUER is required (public https origin, e.g. https://wa.example.com)');
    process.exit(1);
  }
  const port = Number(process.env.PORT ?? 2785);
  const server = createGateway({
    issuer,
    upstream: process.env.UPSTREAM_URL ?? 'http://openwa-api:2785',
    stateDir: process.env.STATE_DIR ?? '/data',
  });
  server.listen(port, () => log('mcp-oauth-gateway listening', { port, issuer }));
  const stop = () => {
    server.close(() => process.exit(0));
    server.closeIdleConnections();
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}
