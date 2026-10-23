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
  API key. The only state is `/data/gateway-secret.key` plus rotated refresh-token ids
  (`/data/revoked-refresh.json`) in the `mcp-oauth-gateway-data` volume. Deleting the secret signs every
  client out. Revoking the API key in OpenWA cuts off its tokens at the next call.
- **Static keys** (`X-API-Key` or `Authorization: Bearer owa_k1_…`) pass through untouched.

## Config (root `.env`, forwarded by `docker-compose.override.yml`)

| Key            | Meaning                                                        |
| -------------- | -------------------------------------------------------------- |
| `OAUTH_ISSUER` | Public https origin clients reach, e.g. `https://wa.example.com` |

These keys are kept out of the root `.env.example` on purpose: that file belongs to upstream.

## Test

```
node --test ops/mcp-oauth-gateway/
```
