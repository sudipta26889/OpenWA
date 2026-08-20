/**
 * WHY: a stored refresh/auth-code row with resource === '' minted tokens with
 * aud: '' — `?? this.resource` only falls back on null/undefined, not empty
 * string — and verifyAccessToken (aud !== this.resource) then 401'd every
 * /mcp call. Regression pin: empty string must fall back to the configured
 * resource (and scope likewise to the default), while genuinely-absent values
 * keep their existing fallback semantics.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { OAuthService } from './oauth.service';

function decodeJwtPayload(token: string): Record<string, unknown> {
  const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
}

type AnyRepo = {
  findOne: jest.Mock;
  save: jest.Mock;
  create: jest.Mock;
};

function fakeRepo(): AnyRepo {
  return {
    findOne: jest.fn(),
    save: jest.fn(async (x: unknown) => x),
    create: jest.fn((x: unknown) => x),
  };
}

describe('OAuthService resource/scope fallback (empty-string safety)', () => {
  let keyDir: string;
  let clients: AnyRepo;
  let codes: AnyRepo;
  let refresh: AnyRepo;
  let authService: { validateApiKey: jest.Mock };
  let svc: OAuthService;

  beforeEach(() => {
    keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'owa-oauth-keys-'));
    process.env.OAUTH_ISSUER = 'https://wa.example.test';
    process.env.OAUTH_KEY_DIR = keyDir;
    clients = fakeRepo();
    codes = fakeRepo();
    refresh = fakeRepo();
    authService = { validateApiKey: jest.fn() };
    svc = new OAuthService(
      clients as never,
      codes as never,
      refresh as never,
      authService as never,
    );
  });

  afterEach(() => {
    fs.rmSync(keyDir, { recursive: true, force: true });
    delete process.env.OAUTH_ISSUER;
    delete process.env.OAUTH_KEY_DIR;
  });

  it('refreshGrant: record with resource="" mints aud = configured resource, not ""', async () => {
    refresh.findOne.mockResolvedValue({
      tokenHash: 'h',
      clientId: 'client-1',
      apiKeyId: 'key-1',
      resource: '', // the prod bug: empty string stored in the chain
      scope: '',
      revoked: false,
      expiresAt: new Date(Date.now() + 60_000),
    });

    const out = await svc.refreshGrant({
      refresh_token: 'raw-refresh',
      client_id: 'client-1',
    });

    const payload = decodeJwtPayload(out.access_token as string);
    expect(payload.aud).toBe('https://wa.example.test/mcp');
    expect(payload.aud).toBe(svc.resource);
    expect(payload.scope).toBe('mcp'); // empty scope falls back to default too
  });

  it('refreshGrant: record with a real resource keeps it verbatim', async () => {
    refresh.findOne.mockResolvedValue({
      tokenHash: 'h',
      clientId: 'client-1',
      apiKeyId: 'key-1',
      resource: 'https://wa.example.test/mcp',
      scope: 'mcp',
      revoked: false,
      expiresAt: new Date(Date.now() + 60_000),
    });

    const out = await svc.refreshGrant({
      refresh_token: 'raw-refresh',
      client_id: 'client-1',
    });

    expect(decodeJwtPayload(out.access_token as string).aud).toBe(
      'https://wa.example.test/mcp',
    );
  });

  it('approveAuthorization: q.resource="" stores the configured resource on the code', async () => {
    clients.findOne.mockResolvedValue({
      clientId: 'client-1',
      redirectUris: ['https://cb.example.test/callback'],
    });
    authService.validateApiKey.mockResolvedValue({ id: 'key-1' });

    await svc.approveAuthorization(
      {
        client_id: 'client-1',
        redirect_uri: 'https://cb.example.test/callback',
        response_type: 'code',
        code_challenge: 'challenge',
        code_challenge_method: 'S256',
        resource: '', // empty-string resource param must not stick
        scope: '',
      },
      'raw-api-key',
    );

    expect(codes.create).toHaveBeenCalledWith(
      expect.objectContaining({
        resource: 'https://wa.example.test/mcp',
        scope: 'mcp',
      }),
    );
  });
});
