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
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
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
const PREFIX = { access: 'owga.', refresh: 'owgr.', code: 'owgc.', client: 'owgk.', v: 'owgv.' };
const VIEW_TTL_MS = 300_000; // 5m: a connections-page revoke token
// Native-app redirect schemes DCR accepts besides https and http loopback. Any other custom scheme is refused.
const CUSTOM_REDIRECT_SCHEMES = ['cursor', 'vscode'];
const LOOPBACK_HOSTS = ['localhost', '127.0.0.1'];
const LOOPBACK_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;
// Browser-side origins of hosted MCP connectors; matched exactly, never by suffix.
const HOSTED_CLIENT_ORIGINS = ['https://claude.ai', 'https://chatgpt.com'];
const CIMD_MAX_BYTES = 64 * 1024; // a client metadata document is tiny
const CIMD_MAX_INFLIGHT = 4;
const CIMD_OK_TTL_MS = 600_000; // 10m
const CIMD_FAIL_TTL_MS = 120_000; // 2m
const CIMD_CACHE_MAX = 256;
// OpenWA returns any tool result over 32 KB as an embedded base64 resource with no upper bound; clients choke
// on that (claude.ai ~150k characters). The gateway caps what it relays until upstream does.
export const MAX_RESULT_CHARS = 100_000;
const MAX_BUFFERED_BYTES = 8 * 1024 * 1024; // a /mcp answer bigger than this is relayed untouched
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
<h1>Authorize connection</h1><p class="sub"><code>${esc(q.client_name || 'An MCP client')}</code>${q.client_host ? ` at <code>${esc(q.client_host)}</code>` : ''} is requesting access to your OpenWA MCP tools.</p>
${errHtml}<label for="k">Enter an OpenWA API key to approve</label>
<input id="k" type="password" name="api_key" placeholder="owa_k1_… or your master key" autocomplete="off" required>
${hidden}<button type="submit">Approve</button></form></body></html>`;
}

const PAGE_CSS = `body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#1e293b;padding:28px 32px;border-radius:12px;max-width:380px;width:100%;box-shadow:0 10px 40px rgba(0,0,0,.4)}
.card.wide{max-width:920px;overflow-x:auto}h1{font-size:18px;margin:0 0 4px}p.sub{color:#94a3b8;font-size:13px;margin:0 0 20px}
label{display:block;font-size:13px;margin:0 0 6px}
input[type=password]{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;font-size:14px}
button{padding:9px 14px;border:0;border-radius:8px;background:#22c55e;color:#04240f;font-weight:600;font-size:13px;cursor:pointer}
button.danger{background:#ef4444;color:#fff}.card>form>button{margin-top:18px;width:100%}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #334155}
a{color:#38bdf8}code{color:#38bdf8}`;
const pageShell = (title, inner, wide = false) => `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} — OpenWA</title><style>${PAGE_CSS}</style></head><body><div class="card${wide ? ' wide' : ''}">${inner}</div></body></html>`;
const errorHtml = error => (error ? `<p style="color:#c0392b;margin:0 0 12px">${esc(error)}</p>` : '');

function connectionsLoginPage(error) {
  return pageShell(
    'Connections',
    `<h1>Connections</h1><p class="sub">Enter an OpenWA API key to list and revoke the MCP connections it can manage.</p>
${errorHtml(error)}<form method="post" action="/oauth/connections"><label for="k">OpenWA API key</label>
<input id="k" type="password" name="api_key" autocomplete="off" required><button type="submit">Show connections</button></form>`,
  );
}

function connectionsPage(rows, role, message) {
  const body = rows
    .map(
      r => `<tr><td>${esc(r.name || '(unnamed)')}</td><td>${esc(r.host)}</td><td>${esc(r.created)}</td><td>${esc(r.lastUsed)}</td><td>${esc(r.status)}</td>
<td>${r.revoked ? '' : `<form method="post" action="/oauth/connections/revoke"><input type="hidden" name="vtoken" value="${esc(r.vtoken)}"><button class="danger" type="submit">Revoke</button></form>`}</td></tr>`,
    )
    .join('\n');
  const table = rows.length
    ? `<table><thead><tr><th>Client</th><th>Host</th><th>Created</th><th>Last used</th><th>Status</th><th></th></tr></thead><tbody>
${body}
</tbody></table>`
    : '<p class="sub">No connections.</p>';
  return pageShell(
    'Connections',
    `<h1>Connections</h1><p class="sub">${role === 'admin' ? 'All connections (admin key).' : 'Connections approved with this key.'}</p>${message ? `<p>${esc(message)}</p>` : ''}${table}`,
    true,
  );
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

// Addresses a CIMD fetch may never connect to (SSRF guard). A host is refused when ANY address it resolves
// to is in here. IPv4-mapped IPv6 addresses are checked as the IPv4 address they carry.
const BLOCKED = new net.BlockList();
for (const [addr, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4],
]) BLOCKED.addSubnet(addr, prefix, 'ipv4');
for (const [addr, prefix] of [['::', 96], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['64:ff9b::', 96], ['2002::', 16]]) {
  BLOCKED.addSubnet(addr, prefix, 'ipv6');
}

/** Expand an IPv6 text address to its 8 hextets, or null when it is malformed. */
function ipv6Hextets(text) {
  let a = text;
  const tail4 = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  if (tail4) {
    const p = tail4[2].split('.').map(Number);
    a = `${tail4[1]}${((p[0] << 8) | p[1]).toString(16)}:${((p[2] << 8) | p[3]).toString(16)}`;
  }
  const [head, rest, extra] = a.split('::');
  if (extra !== undefined) return null;
  const h = head ? head.split(':') : [];
  let parts = h;
  if (rest !== undefined) {
    const t = rest ? rest.split(':') : [];
    const fill = 8 - h.length - t.length;
    if (fill < 1) return null;
    parts = [...h, ...Array(fill).fill('0'), ...t];
  }
  if (parts.length !== 8 || parts.some(x => !/^[0-9a-f]{1,4}$/i.test(x))) return null;
  return parts.map(x => parseInt(x, 16));
}

function isBlockedAddress(address) {
  let a = String(address).toLowerCase();
  const family = net.isIP(a);
  if (!family) return true; // not an address: refuse
  if (family === 6) {
    const h = ipv6Hextets(a);
    if (!h) return true;
    if (h.slice(0, 5).every(x => x === 0) && h[5] === 0xffff) a = `${h[6] >> 8}.${h[6] & 255}.${h[7] >> 8}.${h[7] & 255}`;
  }
  return BLOCKED.check(a, net.isIP(a) === 4 ? 'ipv4' : 'ipv6');
}

class OAuthError extends Error {
  constructor(error, description, status = 400) {
    super(`${error}: ${description}`);
    Object.assign(this, { error, description, status });
  }
}

export function createGateway({
  issuer,
  upstream,
  stateDir,
  now = () => Date.now(),
  cimdLookup = dns.lookup, // injectable so tests never touch the network
  cimdRequest = https.request,
  cimdTimeoutMs = 5000,
  maxResultChars = MAX_RESULT_CHARS,
  maxBufferBytes = MAX_BUFFERED_BYTES,
}) {
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
    client_id_metadata_document_supported: true,
  });

  function checkRedirectUris(redirectUris) {
    for (const uri of redirectUris) {
      const custom = CUSTOM_REDIRECT_SCHEMES.some(s => uri.startsWith(`${s}://`));
      if (!custom && !/^https:\/\//.test(uri) && !/^http:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(uri)) {
        throw new OAuthError('invalid_redirect_uri', `redirect_uri must be https (or http localhost): ${uri}`);
      }
    }
  }

  function registerClient(body) {
    const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris.map(String) : [];
    if (redirectUris.length === 0) throw new OAuthError('invalid_client_metadata', 'redirect_uris is required');
    checkRedirectUris(redirectUris);
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

  // ---- CIMD: an https URL as client_id points at a client metadata document ----

  const hostOf = uri => {
    try {
      return new URL(uri).host;
    } catch {
      return '';
    }
  };

  /** The URL rules of the design (§2). Returns the parsed URL or throws `invalid_client`. */
  function parseCimdUrl(id) {
    const refuse = why => new OAuthError('invalid_client', `client_id URL refused: ${why}`);
    if (typeof id !== 'string' || id.length > 2048 || /[\\\s\x00-\x1f]/.test(id)) throw refuse('malformed');
    const m = /^https:\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/i.exec(id);
    if (!m) throw refuse('not an https URL');
    const [, authority, pathPart, , fragment] = m;
    if (fragment !== undefined) throw refuse('a fragment is not allowed');
    if (authority.includes('@')) throw refuse('userinfo is not allowed');
    if (pathPart === '' || pathPart === '/') throw refuse('the path must not be empty');
    for (const seg of pathPart.split('/')) {
      let decoded;
      try {
        decoded = decodeURIComponent(seg);
      } catch {
        throw refuse('malformed path');
      }
      if (decoded === '.' || decoded === '..') throw refuse('dot segments are not allowed');
    }
    let u;
    try {
      u = new URL(id);
    } catch {
      throw refuse('malformed');
    }
    if (u.port !== '') throw refuse('only port 443 is allowed');
    // An IP literal skips the custom lookup (and so the block list); refuse it outright.
    if (!u.hostname || u.hostname.startsWith('[') || net.isIP(u.hostname)) throw refuse('the host must be a name');
    return u;
  }

  /** dns.lookup with the block list applied to every address, handing the checked address to the socket. */
  const safeLookup = (hostname, options, cb) => {
    if (typeof options === 'function') [options, cb] = [{}, options];
    cimdLookup(hostname, { all: true }, (err, addrs) => {
      if (err) return cb(err);
      if (!Array.isArray(addrs) || addrs.length === 0) return cb(new Error('no address'));
      if (addrs.some(a => isBlockedAddress(a.address))) return cb(Object.assign(new Error('blocked address'), { code: 'EBLOCKED' }));
      if (options?.all) return cb(null, addrs);
      cb(null, addrs[0].address, addrs[0].family);
    });
  };

  function fetchCimdDocument(u) {
    return new Promise((resolve, reject) => {
      let req;
      let settled = false;
      const timer = setTimeout(() => fail('the document timed out'), cimdTimeoutMs);
      const fail = why => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        req?.destroy();
        reject(new OAuthError('invalid_client', `client metadata document: ${why}`));
      };
      req = cimdRequest(
        {
          protocol: 'https:',
          hostname: u.hostname,
          port: 443,
          path: u.pathname + u.search,
          method: 'GET',
          headers: { accept: 'application/json' },
          lookup: safeLookup,
          agent: false,
        },
        res => {
          const status = res.statusCode ?? 0;
          if (status !== 200) {
            res.destroy();
            return fail(status >= 300 && status < 400 ? 'redirects are refused' : `HTTP ${status}`);
          }
          if (!/^application\/(?:[\w.+-]+\+)?json\s*(;|$)/i.test(String(res.headers['content-type'] ?? ''))) {
            res.destroy();
            return fail('not JSON');
          }
          const chunks = [];
          let size = 0;
          res.on('data', c => {
            size += c.length; // counted as it streams: content-length is not trusted
            if (size > CIMD_MAX_BYTES) {
              res.destroy();
              return fail('too large');
            }
            chunks.push(c);
          });
          res.on('end', () => {
            if (settled) return;
            try {
              const doc = JSON.parse(Buffer.concat(chunks).toString('utf8'));
              settled = true;
              clearTimeout(timer);
              resolve(doc);
            } catch {
              fail('not valid JSON');
            }
          });
          res.on('error', () => fail('read error'));
          res.on('close', () => fail('truncated'));
        },
      );
      req.on('error', e => fail(e?.code === 'EBLOCKED' ? 'the host resolves to a blocked address' : 'could not be fetched'));
      req.end();
    });
  }

  /** Turn a fetched document into `{ name, host, redirectUris }`, or throw `invalid_client`. */
  function cimdClientFrom(id, u, doc) {
    const refuse = why => new OAuthError('invalid_client', `client metadata document: ${why}`);
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw refuse('not a JSON object');
    if (doc.client_id !== id) throw refuse('client_id does not match its URL');
    const uris = doc.redirect_uris;
    if (!Array.isArray(uris) || uris.length === 0 || !uris.every(x => typeof x === 'string')) throw refuse('redirect_uris is required');
    try {
      checkRedirectUris(uris);
    } catch (e) {
      throw refuse(e.description);
    }
    if (doc.token_endpoint_auth_method !== undefined && doc.token_endpoint_auth_method !== 'none') {
      throw refuse('token_endpoint_auth_method must be none');
    }
    const clip = v => (typeof v === 'string' && v.trim() ? v.slice(0, 200) : null);
    return { name: clip(doc.client_name), uri: clip(doc.client_uri), host: u.host, redirectUris: uris };
  }

  const cimdCache = new Map(); // url -> { exp, promise }; a failure is cached too (shorter)
  let cimdActive = 0;

  function loadCimdClient(id) {
    const u = parseCimdUrl(id);
    const hit = cimdCache.get(id);
    if (hit && hit.exp > now()) return hit.promise; // also joins a fetch that is still in flight
    if (cimdActive >= CIMD_MAX_INFLIGHT) {
      throw new OAuthError('temporarily_unavailable', 'Too many client metadata fetches are running, try again shortly', 503);
    }
    cimdCache.delete(id);
    // Bounded: the URL is attacker-chosen (an unauthenticated GET). Drop expired entries, then the oldest
    // settled one; entries still in flight are never evicted.
    if (cimdCache.size >= CIMD_CACHE_MAX) {
      for (const [k, v] of cimdCache) if (v.exp <= now()) cimdCache.delete(k);
    }
    if (cimdCache.size >= CIMD_CACHE_MAX) {
      for (const [k, v] of cimdCache) {
        if (v.exp !== Infinity) {
          cimdCache.delete(k);
          break;
        }
      }
    }
    cimdActive++;
    const entry = { exp: Infinity };
    entry.promise = fetchCimdDocument(u)
      .then(doc => cimdClientFrom(id, u, doc))
      .then(
        client => {
          entry.exp = now() + CIMD_OK_TTL_MS;
          return client;
        },
        e => {
          entry.exp = now() + CIMD_FAIL_TTL_MS;
          log('client metadata refused', { host: u.host, reason: e instanceof OAuthError ? e.description : String(e) });
          throw e instanceof OAuthError ? e : new OAuthError('invalid_client', 'client metadata document could not be used');
        },
      )
      .finally(() => cimdActive--);
    cimdCache.set(id, entry);
    return entry.promise;
  }

  /** The client behind a client_id: a CIMD document (https URL) or a sealed DCR registration. */
  async function resolveClient(clientId, redirectUri) {
    if (typeof clientId === 'string' && clientId.startsWith('https://')) return loadCimdClient(clientId);
    const c = unseal('client', clientId);
    if (!c) throw new OAuthError('unauthorized_client', 'Unknown client_id');
    return { name: c.n ?? null, host: hostOf(redirectUri), redirectUris: c.r };
  }

  async function validateAuthorizeParams(q) {
    const client = await resolveClient(q.client_id, q.redirect_uri);
    if (!q.redirect_uri || !client.redirectUris.some(r => redirectMatches(r, q.redirect_uri))) {
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
    const client = await validateAuthorizeParams(q);
    const validated = await apiKeyIsValid(q.api_key);
    if (!validated) throw new OAuthError('access_denied', 'Invalid OpenWA API key', 401);
    const gid = crypto.randomUUID();
    const codeJti = crypto.randomUUID();
    grants[gid] = {
      clientName: client.name ?? null,
      clientHost: client.host,
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
    if (b.grant_type === 'authorization_code' || b.grant_type === 'refresh_token') {
      checkResource(b.resource);
      // A URL client_id must still obey the URL rules. No fetch: the document was checked when the code was issued.
      if (typeof b.client_id === 'string' && b.client_id.startsWith('https://')) parseCimdUrl(b.client_id);
    }
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
  const sendConsent = async (res, q, status, error) => {
    let origin = 'https:';
    try {
      origin = new URL(q.redirect_uri).origin;
    } catch {}
    let client = null;
    try {
      client = await resolveClient(q.client_id, q.redirect_uri); // a cache hit when validation just ran
    } catch {}
    res.writeHead(status, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      // form-action also governs the 302 the POST follows to the client's callback origin.
      'content-security-policy': `default-src 'self'; style-src 'unsafe-inline'; form-action 'self' ${origin}; base-uri 'none'; frame-ancestors 'none'`,
    });
    const client_host = client?.host ?? hostOf(String(q.client_id).startsWith('https://') ? q.client_id : q.redirect_uri);
    res.end(consentPage({ ...q, client_name: client?.name, client_host }, error));
  };
  /** Self-contained HTML pages (connections view): never framed, never cached. */
  const sendPage = (res, status, html) => {
    res.writeHead(status, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    });
    res.end(html);
  };
  /**
   * CSRF / login-CSRF guard for the browser forms: Origin must be the issuer, or be absent with
   * Sec-Fetch-Site: same-origin. Anything else (including `Origin: null`) is refused.
   */
  const sameOriginPost = req => {
    const origin = req.headers.origin;
    if (origin !== undefined) return origin === new URL(issuer).origin;
    return req.headers['sec-fetch-site'] === 'same-origin';
  };
  const requireSameOrigin = req => {
    if (!sameOriginPost(req)) throw new OAuthError('access_denied', 'Cross-site request refused', 403);
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

  // ---- result cap (POST /mcp answers only) ----

  /** Cap one JSON-RPC message's `result.content` in place. Returns true when it changed. */
  function capMessage(msg) {
    const content = msg?.result?.content;
    if (!Array.isArray(content)) return false;
    const serialized = JSON.stringify(content).length;
    if (serialized <= maxResultChars) return false;
    // The payload is the decoded resource blob when there is one (the text item next to it is only a label);
    // otherwise the text items.
    const blobs = content.filter(i => i?.type === 'resource' && typeof i.resource?.blob === 'string');
    const text = blobs.length
      ? blobs.map(i => Buffer.from(i.resource.blob, 'base64').toString('utf8')).join('\n')
      : content
          .map(i => (i?.type === 'text' ? i.text : i?.type === 'resource' ? i.resource?.text : undefined))
          .filter(t => typeof t === 'string')
          .join('\n');
    let head = text.slice(0, maxResultChars);
    if (/[\ud800-\udbff]$/.test(head)) head = head.slice(0, -1); // never cut a surrogate pair in half
    const total = text.length || serialized;
    msg.result.content = [
      { type: 'text', text: `${head}\n…[truncated by gateway: ${total} characters in all; narrow the request (limit/offset) to see the rest]` },
    ];
    return true;
  }

  /** Apply the cap to a whole answer body. Returns the new body, or null when nothing needed changing. */
  function capBody(text, contentType) {
    if (/^text\/event-stream/i.test(contentType)) {
      let changed = false;
      const parts = text.split(/(\r?\n\r?\n)/); // events and their separators, kept
      const out = parts.map(part => {
        const lines = part.split(/\r?\n/);
        const at = lines.findIndex(l => l.startsWith('data:'));
        if (at < 0) return part;
        const data = lines.filter(l => l.startsWith('data:')).map(l => l.slice(5).replace(/^ /, '')).join('\n');
        let msg;
        try {
          msg = JSON.parse(data);
        } catch {
          return part;
        }
        const batch = Array.isArray(msg) ? msg : [msg];
        if (!batch.map(capMessage).some(Boolean)) return part;
        changed = true;
        const rest = lines.filter(l => !l.startsWith('data:'));
        rest.splice(at, 0, `data: ${JSON.stringify(msg)}`);
        return rest.join('\n');
      });
      return changed ? out.join('') : null;
    }
    let msg;
    try {
      msg = JSON.parse(text);
    } catch {
      return null;
    }
    const batch = Array.isArray(msg) ? msg : [msg];
    return batch.map(capMessage).some(Boolean) ? JSON.stringify(msg) : null;
  }

  function proxy(req, res, headers = forwardedHeaders(req), { capResult = false } = {}) {
    if (capResult) delete headers['accept-encoding']; // the answer must be readable to be capped
    const upReq = http.request(
      { host: up.hostname, port: up.port || 80, method: req.method, path: req.url, headers, agent },
      upRes => {
        const status = upRes.statusCode ?? 502;
        const type = String(upRes.headers['content-type'] ?? '');
        if (!capResult || upRes.headers['content-encoding'] || !/^(application\/json|text\/event-stream)/i.test(type)) {
          res.writeHead(status, upRes.headers);
          return upRes.pipe(res);
        }
        // Buffer the answer (up to a hard limit) so it can be measured. Past the limit, relay what we have
        // and stream the rest untouched.
        const chunks = [];
        let size = 0;
        let relaying = false;
        upRes.on('data', c => {
          if (relaying) {
            if (!res.write(c)) {
              upRes.pause();
              res.once('drain', () => upRes.resume());
            }
            return;
          }
          chunks.push(c);
          size += c.length;
          if (size > maxBufferBytes) {
            relaying = true;
            res.writeHead(status, upRes.headers);
            for (const b of chunks.splice(0)) res.write(b);
          }
        });
        upRes.on('end', () => {
          if (relaying) return res.end();
          const raw = Buffer.concat(chunks);
          const capped = capBody(raw.toString('utf8'), type);
          const body = capped === null ? raw : Buffer.from(capped, 'utf8');
          const outHeaders = { ...upRes.headers, 'content-length': String(body.length) };
          delete outHeaders['transfer-encoding'];
          res.writeHead(status, outHeaders);
          res.end(body);
        });
        upRes.on('error', () => res.destroy());
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
      return proxy(req, res, headers, { capResult: true });
    }
    // A JWT is a token minted by the old in-process OAuth module (or another issuer): tell the client to
    // re-run the flow instead of letting OpenWA reject it as an unknown API key without resource_metadata.
    if (bearer && looksLikeJwt(bearer)) return unauthorized(res, true);
    proxy(req, res, undefined, { capResult: true }); // static API key: OpenWA validates it as before
  }

  const routes = {
    'GET /.well-known/oauth-protected-resource': (req, res) => send(res, 200, protectedResourceMetadata()),
    'GET /.well-known/oauth-protected-resource/mcp': (req, res) => send(res, 200, protectedResourceMetadata()),
    'GET /.well-known/oauth-authorization-server': (req, res) => send(res, 200, authorizationServerMetadata()),
    'GET /.well-known/oauth-authorization-server/mcp': (req, res) => send(res, 200, authorizationServerMetadata()),
    'POST /oauth/register': async (req, res) => send(res, 201, registerClient(await readBody(req))),
    'GET /oauth/authorize': async (req, res) => {
      const q = Object.fromEntries(new URL(req.url, issuer).searchParams);
      try {
        await validateAuthorizeParams(q);
        await sendConsent(res, q, 200);
      } catch (e) {
        if (!(e instanceof OAuthError)) throw e;
        await sendConsent(res, q, e.status, e.description);
      }
    },
    'POST /oauth/authorize': async (req, res) => {
      const b = await readBody(req);
      try {
        requireSameOrigin(req);
        const location = await approve(b);
        log('authorize approved');
        res.writeHead(302, { location, 'cache-control': 'no-store' }).end();
      } catch (e) {
        if (!(e instanceof OAuthError) || e.status >= 500) throw e;
        await sendConsent(res, b, e.status, e.description);
      }
    },
    // Connections view: the key is typed into a form and POSTed, never put in a URL; it is not echoed back.
    'GET /oauth/connections': (req, res) => sendPage(res, 200, connectionsLoginPage()),
    'POST /oauth/connections': async (req, res) => {
      const b = await readBody(req);
      try {
        requireSameOrigin(req);
        const validated = await apiKeyIsValid(b.api_key);
        if (!validated) throw new OAuthError('access_denied', 'Invalid OpenWA API key', 401);
        const keyFp = crypto.createHash('sha256').update(b.api_key).digest('hex').slice(0, 16);
        const iso = ms => (ms ? new Date(ms).toISOString() : 'never');
        const rows = Object.entries(grants)
          .filter(([, g]) => validated.role === 'admin' || g.keyFp === keyFp)
          .sort(([, a], [, z]) => z.createdAt - a.createdAt)
          .map(([gid, g]) => ({
            name: g.clientName,
            host: g.clientHost,
            created: iso(g.createdAt),
            lastUsed: iso(g.lastUsedAt),
            status: g.revokedAt === undefined ? 'active' : `revoked ${iso(g.revokedAt)}`,
            revoked: g.revokedAt !== undefined,
            vtoken: seal('v', { keyFp, role: validated.role, gid, exp: now() + VIEW_TTL_MS }),
          }));
        sendPage(res, 200, connectionsPage(rows, validated.role));
      } catch (e) {
        if (!(e instanceof OAuthError) || e.status >= 500) throw e;
        sendPage(res, e.status, connectionsLoginPage(e.description));
      }
    },
    'POST /oauth/connections/revoke': async (req, res) => {
      const b = await readBody(req);
      try {
        requireSameOrigin(req);
        // The sealed token says which key listed the row and which grant the button belongs to. An admin
        // token covers any grant; any other key's token only grants carrying its own fingerprint.
        const v = unseal('v', b.vtoken);
        const g = v && typeof v.gid === 'string' ? grants[v.gid] : undefined;
        if (!g || (v.role !== 'admin' && v.keyFp !== g.keyFp)) {
          throw new OAuthError('access_denied', 'Revoke link is invalid or expired — list the connections again', 403);
        }
        revokeGrant(v.gid);
        sendPage(res, 200, pageShell('Connections', '<h1>Connection revoked</h1><p class="sub">Its tokens stop working at the next call.</p><p><a href="/oauth/connections">Back</a></p>'));
      } catch (e) {
        if (!(e instanceof OAuthError)) throw e;
        sendPage(res, e.status, pageShell('Connections', `<h1>Not revoked</h1>${errorHtml(e.description)}<p><a href="/oauth/connections">Back</a></p>`));
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
