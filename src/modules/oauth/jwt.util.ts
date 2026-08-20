/**
 * Dependency-free OAuth 2.1 crypto: RS256 JWT sign/verify, JWKS export, PKCE S256,
 * and RSA keypair load/generate. Uses only Node's built-in `crypto` — no jsonwebtoken/jose
 * (keeps the dependency surface minimal and avoids a native/transitive addition).
 */
import {
  createSign,
  createVerify,
  createHash,
  createPublicKey,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  timingSafeEqual,
  type KeyObject,
} from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export interface KeyMaterial {
  privateKey: KeyObject;
  publicKey: KeyObject;
  kid: string;
}

const b64urlBuf = (buf: Buffer): string => buf.toString('base64url');
const b64urlJson = (obj: unknown): string => Buffer.from(JSON.stringify(obj)).toString('base64url');

/** Load an RSA keypair from `dir`, generating + persisting one on first run. */
export function loadOrCreateKeys(dir: string): KeyMaterial {
  fs.mkdirSync(dir, { recursive: true });
  const privPath = path.join(dir, 'oauth-private.pem');
  const pubPath = path.join(dir, 'oauth-public.pem');

  let privPem: string;
  let pubPem: string;
  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    privPem = fs.readFileSync(privPath, 'utf8');
    pubPem = fs.readFileSync(pubPath, 'utf8');
  } else {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    privPem = privateKey;
    pubPem = publicKey;
    fs.writeFileSync(privPath, privPem, { mode: 0o600 });
    fs.writeFileSync(pubPath, pubPem);
  }

  const publicKey = createPublicKey(pubPem);
  const privateKey = createPrivateKey(privPem);
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const kid = createHash('sha256').update(der).digest('base64url').slice(0, 16);
  return { privateKey, publicKey, kid };
}

/** Sign a JWT (RS256). `payload` is merged over iat/exp. */
export function signJwt(payload: Record<string, unknown>, km: KeyMaterial, expiresInSec: number): string {
  const header = { alg: 'RS256', typ: 'JWT', kid: km.kid };
  const now = Math.floor(Date.now() / 1000);
  const body = { iat: now, exp: now + expiresInSec, ...payload };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(body)}`;
  const signature = createSign('RSA-SHA256').update(signingInput).sign(km.privateKey);
  return `${signingInput}.${b64urlBuf(signature)}`;
}

/** Verify an RS256 JWT signature + expiry. Returns the decoded payload, or null if invalid. */
export function verifyJwt(token: string, km: KeyMaterial): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  try {
    const ok = createVerify('RSA-SHA256').update(`${h}.${p}`).verify(km.publicKey, Buffer.from(s, 'base64url'));
    if (!ok) return null;
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')) as Record<string, unknown>;
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp === 'number' && payload.exp < now) return null;
    return payload;
  } catch {
    return null;
  }
}

/** Heuristic: is this bearer token one of our JWTs (vs a static API key)? */
export function looksLikeJwt(token: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as { typ?: string; alg?: string };
    return header.typ === 'JWT' && header.alg === 'RS256';
  } catch {
    return false;
  }
}

/** Public key as a JWK for the JWKS endpoint. */
export function publicJwk(km: KeyMaterial): Record<string, unknown> {
  const jwk = km.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  return { ...jwk, use: 'sig', alg: 'RS256', kid: km.kid };
}

/** RFC 7636 S256: base64url(sha256(code_verifier)) === code_challenge (constant-time). */
export function verifyPkceS256(codeVerifier: string, codeChallenge: string): boolean {
  const computed = createHash('sha256').update(codeVerifier).digest('base64url');
  const a = Buffer.from(computed);
  const b = Buffer.from(codeChallenge);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** URL-safe random token. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** SHA-256 hex — used to store auth codes / refresh tokens hashed at rest. */
export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
