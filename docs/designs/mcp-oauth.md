# Design: MCP OAuth to the fleet standard (phase 2)

Status: draft v2 by openwa-lead, 2026-11-16, revised after one Goldfish design review. Phase 1 (six small gaps)
is committed on `feat/mcp-oauth-gateway-gaps` (79093f361) and is not covered here.
Inputs: `~/fleet-tasks/studio-mcp-oauth-standard.md` (checklist), `~/fleet-tasks/openwa-to-guardian-mcp-oauth.md` (audit).

## Constraints

- All OAuth work stays in `ops/mcp-oauth-gateway/gateway.mjs`. It is zero-dependency, Node 22, and outside `src/`, so upstream merges stay clean.
- Static OpenWA API keys (`X-API-Key`, `Bearer owa_k1_…`) keep working unchanged.
- **Send tools stay MCP tools.** This is the owner's exception, recorded 2026-11-16. A 401 stays a 401: nothing is weakened to pass a check.
- One gateway replica. State lives in `STATE_DIR` (volume `mcp-oauth-gateway-data`).

## What changes

### 1. Grants: one small state file instead of fully stateless tokens

The checklist items "reuse revokes the grant", "replay revokes the grant", "revocation endpoint" and "admin list + revoke" all need a grant record.

- **Record:** `STATE_DIR/grants.json` maps a `gid` to `{ clientName, clientHost, keyFp, keyRole, createdAt, lastUsedAt, revokedAt?, codeJti, codeUsed, refreshJti, prevRefreshJti?, prevRefreshUntil? }`.
  - `keyFp` is the first 16 hex characters of the sha256 of the API key. The key itself stays only inside the sealed tokens, as today.
- **Tokens:** the code, access and refresh tokens each carry `gid`. Every use checks that the grant exists and has no `revokedAt`.
- **Code use is persisted in the grant:** `codeUsed: true`, replacing the in-memory `usedCodes` map, so a restart can't re-open a code.
  - A second exchange of a used code revokes the grant (`invalid_grant`), and so do the tokens issued from the first exchange.
- **Refresh:**
  1. Unseal the token and check its grant.
  2. Await `apiKeyIsValid(key)` (the checklist's re-check "on refresh"). If the key is no longer valid, revoke the grant and answer `invalid_grant`.
  3. Then compare-and-set synchronously, with no await in between: re-read the grant and require `rt.jti === g.refreshJti`. On a match, set `prevRefreshJti = g.refreshJti`, `prevRefreshUntil = now + 30 s` and `refreshJti = next`.
- **Replay:**
  - An older jti revokes the grant. The exception is `prevRefreshJti` within its 30 s window: a client that lost the refresh response and retries gets a fresh pair instead of losing the grant.
  - Ceiling: this is safe within one process. More replicas would need a shared store (SQLite on the volume).
- **Writes:** atomic (tmp + rename) on grant create, rotate and revoke. `lastUsedAt` lives in memory and is flushed every 60 s and on SIGTERM, never once per request.
- **Retired:** `revoked-refresh.json`. Pruning drops grants revoked more than 30 days ago or idle past the refresh TTL.

### 2. CIMD (client ID metadata documents)

- An `https://` URL as `client_id` at `/oauth/authorize` is fetched as a client metadata document.
- AS metadata gains `client_id_metadata_document_supported: true`.
- **URL rules:** https and port 443 only; refuse userinfo, a fragment, dot segments, and an empty path or bare `/`.
- **Fetch:** `https.request` with a custom `lookup`, not `fetch`, because Node's `fetch` cannot pin an address without undici.
  - The `lookup` resolves the host, checks every address against a `net.BlockList`, and returns the checked address. That checks and pins in one step, so DNS rebinding has no gap to use.
  - Blocked ranges: loopback, `0.0.0.0/8`, RFC 1918, CGNAT `100.64.0.0/10`, link-local, multicast, `::`, `::1`, ULA `fc00::/7`, link-local v6, `64:ff9b::/96`, and IPv4-mapped v6 (`::ffff:0:0/96`, checked on the mapped v4 address).
  - Redirects (any 3xx) are refused. The timeout is 5 s. The stream is aborted at 64 KB, without trusting `content-length`.
- **Document rules:**
  - `client_id` must equal the URL, and the requested `redirect_uri` must be in `redirect_uris` (with the phase-1 loopback-port rule).
  - `token_endpoint_auth_method` must be `none` or absent.
  - `client_name` and `client_uri` are clipped to 200 characters.
- **Abuse limits** (the fetch is triggered by an unauthenticated GET):
  - at most 4 fetches in flight;
  - a 10-minute cache keyed by URL, which also caches failures (negative cache, 2 minutes).
- **Code change:** `validateAuthorizeParams` and `sendConsent` become async and take the client (name, host, redirect URIs) from either the sealed DCR id or the CIMD document.
- The DCR path (`POST /oauth/register`, sealed `owgk.` ids) stays for Cursor and older clients.

### 3. Revocation endpoint (RFC 7009)

- `POST /oauth/revoke` (form) with `token`: when the token is an access or refresh token, its grant is revoked. It always answers 200.
- It gets CORS `*` and an `OPTIONS` preflight (added beside register and token).
- AS metadata advertises `revocation_endpoint` and `revocation_endpoint_auth_methods_supported: ["none"]`.

### 4. Consent page

- It shows the client host (the CIMD URL host, or the redirect URI host for DCR) next to the client name.
- **CSRF:** `POST /oauth/authorize` is refused unless `Origin` equals the issuer origin, or `Sec-Fetch-Site` is `same-origin` when Origin is absent.
  - Typing an API key already blocks classic CSRF. This check also blocks login-CSRF, where an attacker's key is posted into the victim's flow.
  - The sealed per-page token from v1 is dropped: it was not bound to the browser, so it protected nothing.
- Sign-in stays "type an OpenWA API key". That is the app's existing identity: keys are issued and revoked in the dashboard, so no new password exists.

### 5. Connections view

- `GET /oauth/connections` shows a form that POSTs a key, so a key never appears in a URL or a log.
- `POST /oauth/connections` validates the key with `POST /api/auth/validate`, which returns `role` (`src/modules/auth/auth-validate.controller.ts:45`). Grants are listed by key:
  - an `admin` key lists every grant;
  - any other key lists the grants matching its `keyFp`.
- Each row has a revoke button. Its POST carries a sealed `owgv.` token bound to `{ keyFp, role, gid }` with a 5-minute TTL, and passes the same Origin check as §4.
- The page sends `frame-ancestors 'none'` and `cache-control: no-store`.
- No dashboard change, since the dashboard is upstream code.

### 6. Scopes, and the read-only connection

- **No new scopes in the gateway.** OpenWA keys carry a role (`admin` / `operator` / `viewer`, `src/modules/auth/entities/api-key.entity.ts`), and `tool-invoker.ts:66` refuses a tool above the key's role. `hasPermission` is a role hierarchy.
- Every one of the 26 write tools sets `requiredRole`. Across all tools there are 34 `OPERATOR` and 1 `VIEWER` (verified 2026-11-16), so a viewer key cannot send.
- A read-only connection is therefore made by approving with a `viewer` key.
- `scopes_supported` stays `["mcp"]`. The 403 `insufficient_scope` row stays not applicable.

### 7. Every checklist item outside §1–§6

| Checklist item                                          | Where it stands                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `initialize` version negotiation                        | Done by the SDK (`server/index.js:266`)                                                                                                                                                                                                                                                                               |
| Unsupported `MCP-Protocol-Version` gives 400            | Done by the SDK (`webStandardStreamableHttp.js:780`)                                                                                                                                                                                                                                                                  |
| Foreign `Origin` gives 403                              | Phase 1 (gateway)                                                                                                                                                                                                                                                                                                     |
| Bad input as a tool result with `isError`               | **Done by the SDK** (corrected 2026-11-16): `@modelcontextprotocol/sdk` 1.32.2 catches the input-validation McpError in the `tools/call` handler and returns `{ isError: true }`, with the -32602 only as text (`dist/esm/server/mcp.js:175,187-192,204-211`). Verified with the real SDK over an in-memory transport |
| Tool `title` and `openWorldHint`                        | **Gap, upstream** (`mcp.server.ts:125-129`)                                                                                                                                                                                                                                                                           |
| Result size cap (~150k chars)                           | **Gap, upstream:** results over 32 KB become an uncapped base64 resource (`tool-result.ts:15,28`)                                                                                                                                                                                                                     |
| Tokens stored hashed                                    | Not applicable: nothing token-shaped is stored. Tokens are AES-256-GCM sealed and checked by their auth tag; grants hold only a key fingerprint                                                                                                                                                                       |
| Never pass the client token upstream                    | Done (the gateway swaps in X-API-Key)                                                                                                                                                                                                                                                                                 |
| Anthropic egress (`160.79.104.0/21`, `153.61.208.0/20`) | Done in practice: the claude.ai connector works. Recheck after any NPM or WAF change                                                                                                                                                                                                                                  |
| No apex-to-www redirect                                 | Done: the MCP URL is a subdomain with no redirect                                                                                                                                                                                                                                                                     |

The upstream gaps go to `rmyndharis/OpenWA` as two focused PRs (its CONTRIBUTING asks for one logical change per PR): tool `title` + `openWorldHint`, and a configurable result cap. Validation errors already come back as `isError` (see the table).

**Revised 2026-11-16 (owner's "finish everything"):** the result cap could not wait for upstream, so the gateway now caps it. This reverses v1's "no response rewriting":

- Only answers to OAuth-token callers (the claude.ai and ChatGPT path) are touched. Static-key callers keep OpenWA's resource-blob answer, which Claude Code saves to a file.
- A result is truncated, with a note, only when its payload is longer than 100,000 characters.
- JSON and SSE are both handled. Buffering is capped at 8 MB, beyond which the answer is relayed untouched.

The gateway cap comes out once upstream ships its own.

### 8. Accepted risks

- **CIMD fetch slots:** an unauthenticated caller can keep the 4 CIMD fetch slots busy with slow URLs (5 s each), delaying a CIMD client whose document is not cached. That is availability only, not access. DCR clients and cached documents are unaffected. Revisit if it is seen in the logs.

## Tests (written first, `gateway.test.mjs`)

- **Grants:**
  - a code reused after a gateway restart revokes the grant;
  - the access token from the first exchange then gets 401.
- **Refresh:**
  - replaying an old refresh token revokes the grant;
  - a retry with the previous jti within 30 s succeeds and after 30 s revokes;
  - a key revoked upstream makes the refresh fail and revokes the grant;
  - two concurrent refreshes with the same token give exactly one success.
- **Revoke:** `/oauth/revoke` cuts off `/mcp` at the next call, and its preflight answers 204.
- **CIMD:**
  - a good document passes;
  - refused cases: a mismatched `client_id`, an unlisted redirect, http, a non-443 port, userinfo, a fragment, dot segments, a bare path, a 3xx, an oversized streamed body, `token_endpoint_auth_method: client_secret_basic`, and hosts resolving to `10.0.0.1`, `127.0.0.1`, `::ffff:127.0.0.1` and `64:ff9b::a00:1` (stub the lookup);
  - the connection goes to the checked IP (pin test);
  - the cache serves a repeat request without a second fetch, and a failure is cached.
- **Consent:**
  - a POST with a foreign Origin, or with `Sec-Fetch-Site: cross-site`, is refused;
  - the page shows the client host.
- **Connections:**
  - a key sees only its own grants and an admin key sees all;
  - the key is never in a URL;
  - revoke works, and a revoke token for another key's grant is refused.
- **Regression:** static key pass-through, DCR flow, WebSocket tunnel, the phase-1 tests.

## Rollout

- Build it after Studio's reference is live, reusing any of its code that fits (fleet instruction).
- Deploys through the normal push to `main`, which rebuilds the gateway image and restarts the stack.
- Existing OAuth connections end at the first `/mcp` call after the deploy: old access tokens carry no `gid`, so they get 401 `invalid_token`. claude.ai then re-runs the flow, and the owner types a key once per connection. Static-key clients are unaffected.
- Done when: the four checklist curls give the wanted answers, claude.ai connects as a custom connector over CIMD (the owner tries it), and static-key clients still work.

## Open questions for the owner

1. Is "a viewer key = a read-only connection" acceptable, instead of separate `mcp:read` / `mcp:send` scopes? (The reviewer agreed it works.)
2. Is a forced one-time re-consent at rollout acceptable?
3. A JSON grant file is enough for one replica (the reviewer agreed). Is that acceptable?
