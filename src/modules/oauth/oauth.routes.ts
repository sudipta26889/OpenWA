import { Logger } from '@nestjs/common';
import type { HttpAdapterHost } from '@nestjs/core';
import express, { type Request, type RequestHandler, type Response } from 'express';
import { OAuthService, OAuthError } from './oauth.service';

const logger = new Logger('OAuthRoutes');
type HttpAdapter = NonNullable<HttpAdapterHost['httpAdapter']>;
type Adapter = {
  get: (path: string, ...h: RequestHandler[]) => unknown;
  post: (path: string, ...h: RequestHandler[]) => unknown;
  options: (path: string, ...h: RequestHandler[]) => unknown;
  use: (path: string, ...h: RequestHandler[]) => unknown;
};

/** Permissive CORS for the token/registration endpoints (some MCP clients call them browser-side). */
const corsHeaders: RequestHandler = (_req, res, next) => {
  res
    .set('Access-Control-Allow-Origin', '*')
    .set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    .set('Access-Control-Allow-Headers', 'Content-Type, Authorization, MCP-Protocol-Version')
    .set('Access-Control-Max-Age', '86400');
  next();
};

function esc(s: unknown): string {
  return String(s ?? '').replace(
    /[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string,
  );
}

function json(res: Response, status: number, body: unknown): void {
  res.status(status).set('Access-Control-Allow-Origin', '*').set('Cache-Control', 'no-store').json(body);
}

function oauthErr(res: Response, e: unknown): void {
  if (e instanceof OAuthError) {
    logger.warn(`OAuth ${e.error}: ${e.description}`);
    json(res, e.status, { error: e.error, error_description: e.description });
  } else {
    logger.error('OAuth route error', e instanceof Error ? e.stack : String(e));
    json(res, 500, { error: 'server_error', error_description: 'Internal error' });
  }
}

const AUTHORIZE_PARAMS = ['client_id', 'redirect_uri', 'response_type', 'code_challenge', 'code_challenge_method', 'state', 'scope', 'resource'];

function consentPage(q: Record<string, string | undefined>, error?: string): string {
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
<h1>Authorize connection</h1><p class="sub"><code>${esc(q.client_id)}</code> is requesting access to your OpenWA MCP tools.</p>
${errHtml}<label for="k">Enter an OpenWA API key to approve</label>
<input id="k" type="password" name="api_key" placeholder="owa_k1_… or your master key" autocomplete="off" required>
${hidden}<button type="submit">Approve</button></form></body></html>`;
}

/**
 * Render the consent page with a page-scoped CSP that overrides Helmet's global `form-action 'self'`.
 * CSP form-action also governs the redirect a form submission follows, so the POST's 302 to the
 * client's cross-origin callback (e.g. https://claude.ai/...) is blocked unless that origin is allowed
 * here. The redirect_uri has already been validated against a registered client, so trusting its origin
 * is safe. Scoped to this response only — the dashboard's stricter CSP is unaffected.
 */
function sendConsent(res: Response, q: Record<string, string | undefined>, status: number, error?: string): void {
  let formAction = "'self'";
  try {
    formAction = `'self' ${new URL(q.redirect_uri as string).origin}`;
  } catch {
    formAction = "'self' https:";
  }
  res
    .status(status)
    .set('Content-Type', 'text/html; charset=utf-8')
    .set('Content-Security-Policy', `default-src 'self'; style-src 'unsafe-inline'; form-action ${formAction}; base-uri 'none'`)
    .send(consentPage(q, error));
}

/** Register the OAuth 2.1 AS + discovery endpoints as raw Express routes (root paths, no /api prefix). */
export function mountOAuthRoutes(httpAdapter: HttpAdapter, service: OAuthService): void {
  const app = httpAdapter as unknown as Adapter;
  const jsonBody = express.json();
  const formBody = express.urlencoded({ extended: false });

  // Trace every OAuth/discovery hit so a stuck client flow can be diagnosed from the logs.
  const trace: RequestHandler = (req, _res, next) => {
    logger.log(`${req.method} ${req.originalUrl.split('?')[0]}`);
    next();
  };
  app.use('/oauth', trace);
  app.use('/.well-known', trace);

  // CORS preflight for browser-side token/registration calls.
  app.options('/oauth/register', corsHeaders, (_req: Request, res: Response) => res.sendStatus(204));
  app.options('/oauth/token', corsHeaders, (_req: Request, res: Response) => res.sendStatus(204));

  // --- Discovery (RFC 9728 / RFC 8414) — both bare and path-suffixed variants Claude probes ---
  const prm: RequestHandler = (_req, res) => json(res, 200, service.protectedResourceMetadata());
  app.get('/.well-known/oauth-protected-resource', prm);
  app.get('/.well-known/oauth-protected-resource/mcp', prm);

  const asm: RequestHandler = (_req, res) => json(res, 200, service.authorizationServerMetadata());
  app.get('/.well-known/oauth-authorization-server', asm);
  app.get('/.well-known/oauth-authorization-server/mcp', asm);

  app.get('/.well-known/jwks.json', (_req, res) => json(res, 200, service.jwks()));

  // --- Dynamic Client Registration (RFC 7591) ---
  app.post('/oauth/register', jsonBody, formBody, (req: Request, res: Response) => {
    void (async () => {
      try {
        json(res, 201, await service.registerClient((req.body ?? {}) as Record<string, unknown>));
      } catch (e) {
        oauthErr(res, e);
      }
    })();
  });

  // --- Authorization endpoint (consent = enter an OpenWA API key) ---
  app.get('/oauth/authorize', (req: Request, res: Response) => {
    void (async () => {
      const q = req.query as unknown as Record<string, string | undefined>;
      try {
        await service.validateAuthorizeParams(q);
        sendConsent(res, q, 200);
      } catch (e) {
        if (e instanceof OAuthError) {
          sendConsent(res, q, e.status, e.description);
        } else {
          oauthErr(res, e);
        }
      }
    })();
  });

  app.post('/oauth/authorize', jsonBody, formBody, (req: Request, res: Response) => {
    void (async () => {
      const b = (req.body ?? {}) as Record<string, string | undefined>;
      try {
        const redirectUrl = await service.approveAuthorization(b, b.api_key ?? '');
        logger.log(`authorize approved client=${b.client_id} -> redirecting to callback`);
        res.redirect(302, redirectUrl);
      } catch (e) {
        if (e instanceof OAuthError) {
          sendConsent(res, b, e.error === 'access_denied' ? 401 : e.status, e.description);
        } else {
          oauthErr(res, e);
        }
      }
    })();
  });

  // --- Token endpoint (form-encoded) ---
  app.post('/oauth/token', jsonBody, formBody, (req: Request, res: Response) => {
    void (async () => {
      const b = (req.body ?? {}) as Record<string, string | undefined>;
      try {
        if (b.grant_type === 'authorization_code') {
          const t = await service.exchangeCode(b);
          logger.log(`token issued (authorization_code) client=${b.client_id}`);
          json(res, 200, t);
        } else if (b.grant_type === 'refresh_token') {
          const t = await service.refreshGrant(b);
          logger.log(`token issued (refresh_token) client=${b.client_id}`);
          json(res, 200, t);
        } else {
          throw new OAuthError('unsupported_grant_type', `Unsupported grant_type: ${b.grant_type}`, 400);
        }
      } catch (e) {
        oauthErr(res, e);
      }
    })();
  });

  logger.log('OAuth 2.1 endpoints mounted (/.well-known/*, /oauth/register, /oauth/authorize, /oauth/token)');
}
