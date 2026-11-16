# mcp-oauth-gateway

OAuth 2.1 for OpenWA's MCP endpoint, kept **outside** the OpenWA source tree so upstream releases merge
with no conflicts. It replaced the in-process `src/modules/oauth` module on 2026-10-23.

```
client ──► :2785 mcp-oauth-gateway ──► openwa-api:2785 (not published; 127.0.0.1:2786 for local debugging)
              │ owns /.well-known/oauth-*, /oauth/*
              │ POST /mcp + gateway token → swaps in X-API-Key
              └ everything else (REST, dashboard, socket.io) → proxied unchanged
```

- **Sign-in:** an MCP client (e.g. Claude) registers itself, the operator types an OpenWA API key on the
  consent page, and the gateway checks it against OpenWA's `POST /api/auth/validate`.
- **Tokens:** client ids, codes, access and refresh tokens are AES-256-GCM sealed blobs that carry the
  API key. Deleting `/data/gateway-secret.key` signs every client out. Revoking the API key in OpenWA
  cuts off its tokens at the next call, and at the next refresh the grant is revoked too.
- **Grants (`/data/grants.json`, volume `mcp-oauth-gateway-data`):** one record per approved connection,
  keyed by the `gid` that its code, access and refresh tokens all carry. Fields: `clientName`,
  `clientHost`, `keyFp` (first 16 hex characters of the key's sha256; the key itself is never stored),
  `keyRole`, `createdAt`, `lastUsedAt`, `revokedAt`, `codeJti`, `codeUsed`, `refreshJti`,
  `prevRefreshJti`, `prevRefreshUntil`. Writes are atomic (tmp + rename) on create, rotate and revoke;
  `lastUsedAt` is kept in memory and flushed every 60 s and when the server closes. Grants revoked over
  30 days ago, or idle past the 30-day refresh TTL, are pruned at startup. One gateway process only.
  - A token without a `gid` (issued before grants existed) is refused: `/mcp` answers 401
    `invalid_token`, and the token endpoint answers `invalid_grant`. The client re-runs the flow once.
  - Reusing an authorization code revokes its grant, and with it the tokens from the first exchange.
  - Refresh checks the grant, re-validates the key upstream (a dead key revokes the grant), then rotates
    the refresh token. The just-replaced token still works for 30 s (a client that lost the response);
    any other old refresh token revokes the grant. Two simultaneous refreshes with one token: the second
    gets `invalid_grant`.
- **Revocation (RFC 7009):** `POST /oauth/revoke` (form `token=`, CORS `*`, `OPTIONS` answers 204)
  revokes the grant behind an access or refresh token and always answers 200. AS metadata advertises
  `revocation_endpoint` and `revocation_endpoint_auth_methods_supported: ["none"]`.
- **Static keys** (`X-API-Key` or `Authorization: Bearer owa_k1_…`) pass through untouched.

## Fleet-checklist behaviours

1. **Origin check:** `POST /mcp` with an `Origin` header that is not the issuer origin, `http://localhost|127.0.0.1[:port]`, or a hosted connector origin (`https://claude.ai`, `https://chatgpt.com`, exact match only) gets 403 (JSON-RPC error) before auth, and the refusal logs one `mcp origin refused` line with the origin clipped to 200 characters; no `Origin` passes.
2. **`scope="mcp"`:** every 401 `WWW-Authenticate` carries it after `resource_metadata` (`error="invalid_token"` still follows when a token was sent).
3. **RFC 9207:** the authorize redirect adds `iss=<issuer>`; AS metadata sets `authorization_response_iss_parameter_supported: true`.
4. **RFC 8707:** a `resource` on authorize or `/oauth/token` (both grants) that is not `${issuer}/mcp` is `invalid_target` (400); omitting it is allowed.
5. **RFC 8252:** a registered `http://localhost` / `http://127.0.0.1` redirect URI matches any port (scheme, host, path, query equal), at authorize and at the token step; all other URIs are exact.
6. **DCR schemes:** `cursor://` and `vscode://` redirect URIs are accepted (`CUSTOM_REDIRECT_SCHEMES` in `gateway.mjs`); other custom schemes are refused.

## Config (root `.env`, forwarded by `docker-compose.override.yml`)

| Key            | Meaning                                                        |
| -------------- | -------------------------------------------------------------- |
| `OAUTH_ISSUER` | Public https origin clients reach, e.g. `https://wa.example.com` |

These keys are kept out of the root `.env.example` on purpose: that file belongs to upstream.

## Test

```
node --test ops/mcp-oauth-gateway/*.test.mjs
```
