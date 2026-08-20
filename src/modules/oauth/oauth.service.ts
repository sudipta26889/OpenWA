import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as path from 'path';
import type { ApiKey } from '../auth/entities/api-key.entity';
import { AuthService } from '../auth/auth.service';
import { OAuthClient } from './entities/oauth-client.entity';
import { OAuthAuthCode } from './entities/oauth-auth-code.entity';
import { OAuthRefreshToken } from './entities/oauth-refresh-token.entity';
import {
  loadOrCreateKeys,
  signJwt,
  verifyJwt,
  publicJwk,
  verifyPkceS256,
  randomToken,
  sha256Hex,
  type KeyMaterial,
} from './jwt.util';

/** OAuth protocol error carrying the RFC 6749 `error` code + HTTP status. */
export class OAuthError extends Error {
  constructor(
    readonly error: string,
    readonly description: string,
    readonly status = 400,
  ) {
    super(`${error}: ${description}`);
  }
}

const ACCESS_TTL_SEC = 3600; // 1h
const REFRESH_TTL_SEC = 60 * 60 * 24 * 30; // 30d
const CODE_TTL_SEC = 120; // 2m
const SCOPE = 'mcp';

/**
 * Empty-string-safe fallback. `??` only catches null/undefined, so a stored
 * row (or query param) with resource === '' minted tokens with aud: '' which
 * verifyAccessToken then rejected — every /mcp call 401'd until the row was
 * hand-repaired. Blank strings must fall back to the configured default.
 */
const orDefault = (v: string | null | undefined, d: string): string =>
  v && v.trim() ? v : d;

@Injectable()
export class OAuthService {
  private readonly logger = new Logger('OAuthService');
  private readonly keys: KeyMaterial;
  readonly issuer: string;
  readonly resource: string;

  constructor(
    @InjectRepository(OAuthClient, 'main') private readonly clients: Repository<OAuthClient>,
    @InjectRepository(OAuthAuthCode, 'main') private readonly codes: Repository<OAuthAuthCode>,
    @InjectRepository(OAuthRefreshToken, 'main') private readonly refresh: Repository<OAuthRefreshToken>,
    private readonly authService: AuthService,
  ) {
    const issuer = (process.env.OAUTH_ISSUER ?? '').replace(/\/$/, '');
    if (!issuer) {
      this.logger.error('OAUTH_ISSUER is not set — OAuth endpoints will not work. Set it to your public https origin.');
    }
    this.issuer = issuer;
    this.resource = `${issuer}/mcp`;
    const keyDir = process.env.OAUTH_KEY_DIR ?? path.join(process.cwd(), 'data', 'oauth');
    this.keys = loadOrCreateKeys(keyDir);
    this.logger.log(`OAuth AS ready (issuer=${issuer || 'UNSET'}, kid=${this.keys.kid})`);
  }

  // ---- Discovery metadata ----

  protectedResourceMetadataUrl(): string {
    return `${this.issuer}/.well-known/oauth-protected-resource`;
  }

  protectedResourceMetadata(): Record<string, unknown> {
    return {
      resource: this.resource,
      authorization_servers: [this.issuer],
      scopes_supported: [SCOPE],
      bearer_methods_supported: ['header'],
      resource_documentation: this.issuer,
    };
  }

  authorizationServerMetadata(): Record<string, unknown> {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/oauth/authorize`,
      token_endpoint: `${this.issuer}/oauth/token`,
      registration_endpoint: `${this.issuer}/oauth/register`,
      jwks_uri: `${this.issuer}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      scopes_supported: [SCOPE],
    };
  }

  jwks(): Record<string, unknown> {
    return { keys: [publicJwk(this.keys)] };
  }

  // ---- Dynamic Client Registration (RFC 7591) ----

  async registerClient(body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const redirectUris = Array.isArray(body.redirect_uris) ? (body.redirect_uris as unknown[]).map(String) : [];
    if (redirectUris.length === 0) {
      throw new OAuthError('invalid_client_metadata', 'redirect_uris is required', 400);
    }
    for (const uri of redirectUris) {
      if (!/^https:\/\//.test(uri) && !/^http:\/\/(localhost|127\.0\.0\.1)/.test(uri)) {
        throw new OAuthError('invalid_redirect_uri', `redirect_uri must be https (or http localhost): ${uri}`, 400);
      }
    }
    const grantTypes = Array.isArray(body.grant_types)
      ? (body.grant_types as unknown[]).map(String)
      : ['authorization_code', 'refresh_token'];
    const authMethod = typeof body.token_endpoint_auth_method === 'string' ? body.token_endpoint_auth_method : 'none';

    const client = this.clients.create({
      clientId: `owa-${randomToken(16)}`,
      clientName: typeof body.client_name === 'string' ? body.client_name : null,
      redirectUris,
      grantTypes,
      tokenEndpointAuthMethod: authMethod,
      scope: typeof body.scope === 'string' ? body.scope : SCOPE,
    });
    await this.clients.save(client);
    this.logger.log(`Registered OAuth client ${client.clientId} (${client.clientName ?? 'unnamed'})`);

    return {
      client_id: client.clientId,
      client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
      redirect_uris: client.redirectUris,
      grant_types: client.grantTypes,
      response_types: ['code'],
      token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      client_name: client.clientName,
      scope: client.scope,
    };
  }

  // ---- Authorization endpoint helpers ----

  async validateAuthorizeParams(q: Record<string, string | undefined>): Promise<OAuthClient> {
    const client = q.client_id ? await this.clients.findOne({ where: { clientId: q.client_id } }) : null;
    if (!client) throw new OAuthError('unauthorized_client', 'Unknown client_id', 400);
    if (!q.redirect_uri || !client.redirectUris.includes(q.redirect_uri)) {
      throw new OAuthError('invalid_request', 'redirect_uri does not match a registered value', 400);
    }
    if (q.response_type !== 'code') throw new OAuthError('unsupported_response_type', 'response_type must be code', 400);
    if (!q.code_challenge) throw new OAuthError('invalid_request', 'PKCE code_challenge is required', 400);
    if (q.code_challenge_method !== 'S256') {
      throw new OAuthError('invalid_request', 'code_challenge_method must be S256', 400);
    }
    return client;
  }

  /** Validate the operator's API key and mint an auth code bound to it. Returns the redirect URL. */
  async approveAuthorization(
    q: Record<string, string | undefined>,
    apiKeyRaw: string,
  ): Promise<string> {
    await this.validateAuthorizeParams(q);
    let apiKey: ApiKey;
    try {
      apiKey = await this.authService.validateApiKey(apiKeyRaw);
    } catch {
      throw new OAuthError('access_denied', 'Invalid OpenWA API key', 401);
    }

    const rawCode = randomToken(32);
    const code = this.codes.create({
      codeHash: sha256Hex(rawCode),
      clientId: q.client_id as string,
      redirectUri: q.redirect_uri as string,
      codeChallenge: q.code_challenge as string,
      codeChallengeMethod: 'S256',
      apiKeyId: apiKey.id,
      resource: orDefault(q.resource, this.resource),
      scope: orDefault(q.scope, SCOPE),
      expiresAt: new Date(Date.now() + CODE_TTL_SEC * 1000),
      used: false,
    });
    await this.codes.save(code);

    const url = new URL(q.redirect_uri as string);
    url.searchParams.set('code', rawCode);
    if (q.state) url.searchParams.set('state', q.state);
    return url.toString();
  }

  // ---- Token endpoint ----

  async exchangeCode(body: Record<string, string | undefined>): Promise<Record<string, unknown>> {
    const { code, code_verifier: verifier, redirect_uri: redirectUri, client_id: clientId } = body;
    if (!code || !verifier || !redirectUri || !clientId) {
      throw new OAuthError('invalid_request', 'code, code_verifier, redirect_uri, client_id are required', 400);
    }
    const record = await this.codes.findOne({ where: { codeHash: sha256Hex(code) } });
    if (!record || record.used || record.expiresAt < new Date()) {
      throw new OAuthError('invalid_grant', 'Authorization code is invalid or expired', 400);
    }
    if (record.clientId !== clientId || record.redirectUri !== redirectUri) {
      throw new OAuthError('invalid_grant', 'client_id / redirect_uri mismatch', 400);
    }
    if (!verifyPkceS256(verifier, record.codeChallenge)) {
      throw new OAuthError('invalid_grant', 'PKCE verification failed', 400);
    }
    record.used = true;
    await this.codes.save(record);

    return this.issueTokens(
      record.apiKeyId,
      record.clientId,
      orDefault(record.scope, SCOPE),
      orDefault(record.resource, this.resource),
    );
  }

  async refreshGrant(body: Record<string, string | undefined>): Promise<Record<string, unknown>> {
    const { refresh_token: token, client_id: clientId } = body;
    if (!token || !clientId) throw new OAuthError('invalid_request', 'refresh_token and client_id are required', 400);
    const record = await this.refresh.findOne({ where: { tokenHash: sha256Hex(token) } });
    if (!record || record.revoked || record.expiresAt < new Date() || record.clientId !== clientId) {
      throw new OAuthError('invalid_grant', 'refresh_token is invalid or expired', 400);
    }
    // OAuth 2.1: rotate refresh tokens for public clients.
    record.revoked = true;
    await this.refresh.save(record);
    return this.issueTokens(
      record.apiKeyId,
      record.clientId,
      orDefault(record.scope, SCOPE),
      orDefault(record.resource, this.resource),
    );
  }

  private async issueTokens(
    apiKeyId: string,
    clientId: string,
    scope: string,
    resource: string,
  ): Promise<Record<string, unknown>> {
    const accessToken = signJwt(
      { sub: apiKeyId, scope, aud: resource, iss: this.issuer, client_id: clientId, token_use: 'access' },
      this.keys,
      ACCESS_TTL_SEC,
    );
    const rawRefresh = randomToken(32);
    await this.refresh.save(
      this.refresh.create({
        tokenHash: sha256Hex(rawRefresh),
        clientId,
        apiKeyId,
        resource,
        scope,
        expiresAt: new Date(Date.now() + REFRESH_TTL_SEC * 1000),
        revoked: false,
      }),
    );
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TTL_SEC,
      refresh_token: rawRefresh,
      scope,
    };
  }

  // ---- Resource-server side: verify access tokens on /mcp ----

  /** Verify signature/exp and that iss+aud bind to this server. Returns claims or null. */
  verifyAccessToken(bearer: string): Record<string, unknown> | null {
    const payload = verifyJwt(bearer, this.keys);
    if (!payload) return null;
    if (payload.iss !== this.issuer) return null;
    if (payload.aud !== this.resource) return null;
    if (typeof payload.sub !== 'string') return null;
    return payload;
  }

  /** Resolve a valid access token to its underlying OpenWA API key principal, or null. */
  async resolveApiKey(bearer: string): Promise<ApiKey | null> {
    const payload = this.verifyAccessToken(bearer);
    if (!payload) return null;
    try {
      return await this.authService.getApiKeyByIdForAuth(payload.sub as string);
    } catch {
      return null;
    }
  }
}
