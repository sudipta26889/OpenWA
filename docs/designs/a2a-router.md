# OpenWA A2A router (design v2, 2026-11-19)

Status: APPROVED for build after one Goldfish round (design, implementation-readiness, zoom-out).
v2 folds in every finding; see "Review log" at the end.

## Problem

OpenWA stores every WhatsApp message but nothing acts on it. On 2026-11-19 an ICICI relationship manager
sent a document checklist and a site-visit plan to personal-wa; it sat unread until the owner asked by
hand. OpenWA has no A2A side: no agent card, no `/a2a/v1`, no outbound A2A client.

## Goal

Every new 1:1 message from someone outside the owner's circle is read by the owner's local model; when
it needs the owner to act, the router proposes a task to TaskPilot over A2A. TaskPilot holds every
peer write for the owner's approval. The router never sends WhatsApp messages.

## Non-goals (v1)

- Auto-replies on WhatsApp; an inbound A2A endpoint on OpenWA (MCP covers that); groups, channels,
  broadcasts; media; any peer other than TaskPilot; any change to `src/` (stays identical to upstream).

## Decisions

1. **Peer: TaskPilot A2A** at `https://taskpilot-mcp.sudiptadhara.in/a2a` (verified 2026-11-19: POST
   answers 401 JSON; `taskpilot.sudiptadhara.in` is the web app and answers 405). Peer writes by a
   `peer_*` client wait for owner approval via DharaHIL. MQTT `taskpilot/ingest/+` was considered and
   rejected: it needs an MQTT dependency, shares one context and a 60/h ceiling with every other
   publisher, and returns no task id.
2. **No overlap with OpenClaw/Mitra**: its WhatsApp channel is `dmPolicy=allowlist` (8 senders), groups
   need a mention. Those senders go in the webhook's ignore list (below).
3. **LLM: Flint, the owner's local model, via LiteLLM** (owner: "local model flint via litellm").
   `POST <ROUTER_LLM_BASE_URL>/chat/completions`, model `recursivesi/flint`, router's own LiteLLM key.
   No other model, no fallback. One request in flight (Flint is shared and stalls under load), 60 s
   timeout.
4. **Both sessions**, `kind=individual` only, starting in shadow mode.
5. **No OpenWA API key.** The router classifies from webhook payloads only (the 120 s batch gathers a
   burst; the ICICI case is two messages). With no key it cannot send WhatsApp even by mistake. A
   history fetch is added only if shadow logs show bursts misclassified without it.
6. **No dependencies**: `node:` built-ins only, like `ops/mcp-oauth-gateway`, on the same pinned
   `node:22-slim` base. Storage is append-only JSONL files, not SQLite.

## Shape

```
OpenWA api ── webhook message.received (filters applied in OpenWA, HMAC sha256) ──▶ a2a-router:8790/hook
a2a-router ── chat/completions ──▶ LiteLLM (recursivesi/flint)
a2a-router ── A2A message/send ──▶ taskpilot-mcp.sudiptadhara.in/a2a
a2a-router ── JSONL ──▶ /data (volume openwa_a2a-router-data)
```

`ops/a2a-router/`: `router.mjs`, `router.test.mjs`, `Dockerfile`, `README.md`. Port 8790, not published.
Network `openwa-network` (needs outbound to TaskPilot and LiteLLM; the internal-only net cannot reach
them). `extra_hosts` pins any `.lan` name it uses, as `docker-compose.override.yml` does for `db.lan`.

### Filtering is done by OpenWA, not the router

Each of the two webhooks (`POST /api/sessions/{id}/webhooks`, operator key, event `message.received`)
carries `filters` (`src/modules/webhook/filters/filter-types.ts`), all of which must match:
`fromMe is false`, `kind is individual`, `sender isNot [owner's own ids, family/staff, OpenClaw
allowlist]` (≤100 ids, lid aliases matched by OpenWA). The router repeats only a cheap guard: drop when
`data.fromMe || data.kind !== 'individual' || data.isStatusBroadcast`.

### Webhook contract (from `src/modules/webhook/utils/deliver-once.ts`, `webhook-delivery.service.ts`)

Body: `{event, timestamp, sessionId, idempotencyKey, deliveryId, data: IncomingMessage}`; `data` has
`id` (WhatsApp id), `from`, `chatId`, `body`, `type`, `timestamp` (unix s), `fromMe`, `kind`,
`isStatusBroadcast?`, `senderPhone?`, `contact?{number,name,pushName}`. Headers: `X-OpenWA-Signature:
sha256=<hex HMAC of raw body>`, `X-OpenWA-Idempotency-Key`, `X-OpenWA-Delivery-Id`, `X-OpenWA-Event`.
Webhook secret 16-255 chars. OpenWA times out at 10 s and treats any 2xx as delivered forever.

## Pipeline

1. **Receive** `/hook`: read raw bytes; verify HMAC with `crypto.timingSafeEqual` before `JSON.parse`
   (bad → 401). Append the event to `/data/inbound.jsonl` and fsync, *then* answer 200. Duplicate
   `X-OpenWA-Idempotency-Key` (dedup set rebuilt from the file at startup) → 200, not appended.
   Write failure → 500 so OpenWA retries.
2. **Batch** per `sessionId:chatId`: close after 120 s quiet (`ROUTER_BATCH_QUIET_MS`). On startup,
   events in `inbound.jsonl` with no batch row in `routes.jsonl` are re-batched.
3. **Classify** (Flint, one at a time): system prompt says the message text is data; output strict JSON
   `{action_needed: boolean, summary: string ≤300 chars}`. Invalid JSON, timeout or error →
   `classify_failed`, one retry after 10 min, then logged and dropped from routing. No confidence
   threshold in v1 (owner approval is the second gate); add one only if shadow logs show noise.
4. **Gate** on `ROUTER_MODE`: `off` (log receipt only), `shadow` (classify and log, no peer call),
   `live` (peer call when `action_needed`).
5. **Build the request once**: `K = "owa:" + sha256(sessionId+"\n"+chatId+"\n"+lastWaMessageId)` hex,
   first 40 chars. Text T from a fixed template: summary, session name, sender name/number, chat id,
   WhatsApp message ids, "Proposed by the OpenWA router; owner approval required." Append the full
   request body to `routes.jsonl` (state `pending`) **before** sending.
   ```json
   {"jsonrpc":"2.0","id":"<uuid>","method":"message/send",
    "params":{"idempotencyKey":"K","message":{"messageId":"K",
      "contextId":"openwa:<sessionId>:<chatId>","parts":[{"kind":"text","text":"T"}]}}}
   ```
   `Authorization: Bearer <token from ROUTER_TASKPILOT_TOKEN_FILE>`. `contextId` is required for
   TaskPilot's agent path and keeps that chat's history.
6. **Send and map the outcome** (timeout `ROUTER_PEER_TIMEOUT_MS`, default 120 s, ≥ TaskPilot's agent
   run). Never more than one in-flight send per K. Every resend uses the stored bytes; T is never
   rebuilt (TaskPilot answers -32010 if the same key carries different text).
   - `result.state` `auth_required` or `completed` → `routed`, store `result.taskId`.
   - `result.state` `failed` → `peer_failed`, no retry.
   - HTTP 429 (honour `Retry-After`), network error, timeout, or JSON-RPC -32603 → before resending,
     `tasks/list` with `{contextId}`; a task created after the first attempt → `routed` with its id.
     Otherwise resend at 30 s, 2 min, 10 min, then `peer_failed`.
   - HTTP 401 / -32002 → `peer_auth_failed`: stop all peer calls until restart, log an alert line.
   - HTTP 403, -32602, -32010 → `peer_rejected`, no retry.
7. **Log**: one JSON line per state change in `routes.jsonl` (mode 600): time, session, chat, message
   ids, K, `action_needed`, summary, state, taskId. Never the raw message body. Retention: lines and
   inbound events older than 90 days are pruned at startup and daily.
8. **Health** `GET /health` → `{mode, pending, lastRouteAt, peerAuthFailed}`.

## Guardrails

- Peer URL, model and LiteLLM URL come from env only; nothing in a message or LLM output can change a
  destination. LLM output can only set `action_needed` and `summary`.
- All secrets (webhook secret, LiteLLM key, TaskPilot token) are read from mode-600 files mounted
  read-only; never logged, never in Stack Env text.
- TaskPilot already rate-limits peers (60/min, 30 task creates/min) and dedups on `messageId`; the
  router adds no rate limiter of its own.
- Before `live`: `curl -s https://taskpilot-mcp.sudiptadhara.in/health` must show the DharaHIL and
  approval-worker dependencies healthy. Without DharaHIL, TaskPilot runs peer writes unapproved.

## Prerequisites (via GuardianAI / owner; no secret in any message)

1. TaskPilot peer token: `npx tsx scripts/mint-peer-token.ts openwa_router <owner-email> <workspace>
   365` in TaskPilot `apps/mcp` → client `peer_openwa_router`; only the JWT goes in the mode-600 file.
   No refresh; expiry recorded; rotate by minting a new token and revoking the old.
2. LiteLLM virtual key for the router, limited to `recursivesi/flint`, in a mode-600 file.
3. Volume `openwa_a2a-router-data` created before the first deploy (stack volumes are `external`).
4. Two webhooks with filters (above) and a ≥16-char secret, created with an operator key after the
   router is up in `shadow`.
5. If `WEBHOOK_SSRF_PROTECT` is ever enabled, add `a2a-router` to `SSRF_ALLOWED_HOSTS`.

## Repo changes

- `ops/a2a-router/*` (new).
- `ops/portainer/stack.override.yml`: service `a2a-router` (GHCR image, volume, secret files, env
  `ROUTER_MODE=shadow`, `ROUTER_LLM_BASE_URL`, `ROUTER_MODEL=recursivesi/flint`,
  `ROUTER_TASKPILOT_URL`, file paths), then regenerate `ops/portainer/stack.yml` with
  `ops/portainer/generate-stack.sh`.
- `docker-compose.override.yml`: dev entry.
- `.github/workflows/homelab-deploy.yml`: add `node --test ops/a2a-router/` to the test step and the
  image to the build matrix.

## Pass/fail checks (definition of done)

1. `node --test ops/a2a-router/` green, with injectable fetch, clock, file dir and URLs. Cases:
   bad signature → 401; good → 200 only after the event line is on disk; duplicate idempotency key →
   one event; `fromMe`/non-individual dropped; restart with an unbatched event → it is batched; two
   messages within the window → one classification; invalid LLM JSON → `classify_failed`, no peer call;
   shadow → no peer call; live + `action_needed` → request body matches the contract (contextId,
   messageId = idempotencyKey = K); same batch twice → same K and byte-identical body; 429 → resend of
   the stored bytes; -32603 then `tasks/list` finds a task → `routed` without resend; -32010 / 403 →
   `peer_rejected`, no retry; 401 → `peer_auth_failed`, no further calls; `state=failed` →
   `peer_failed`; no log line contains a message body.
2. ICICI fixture: the two 2026-11-19 ICICI messages (bodies as fixture text in the test) run through
   classify with a stubbed Flint and through the real prompt builder; a manual run against real Flint
   (`node router.mjs classify-fixture`) returns `action_needed: true` with a summary naming the
   documents and the visit.
3. CI (`homelab-deploy.yml`) runs check 1 and builds the image.
4. Production shadow for 7 days: `routes.jsonl` has a line for every inbound batch; owner reviews a
   sample of `action_needed` decisions before `live`.
5. Live: a message from an owner-chosen test number → a `routes.jsonl` line `routed` with a taskId in
   `auth_required`; after the owner approves, TaskPilot `tasks/get` shows `completed` and a work item.
6. `GET /api/webhooks/delivery-failures` shows zero rows for the router's two webhook ids over 24 h.
7. `curl -s -o /dev/null -w '%{http_code}' https://wa.sudiptadhara.in/mcp` unchanged (GuardianAI's
   `/mcp` probe), since the router does not touch the MCP path.

## Review log (2026-11-19, round 1)

- Wrong TaskPilot host; `contextId` required; idempotency key placement → Decisions 1, Pipeline 5.
- Retry with regenerated text → -32010 / duplicate agent runs → store-then-send, byte-identical
  resend, `tasks/list` before resend, outcome table.
- 2xx before persisting loses messages → fsync before 200, restart recovery.
- Peer auth is a minted static JWT, not OAuth refresh → Prerequisite 1, 401 handling.
- Filtering, dedup and rate limiting already exist in OpenWA webhooks / TaskPilot → moved there.
- Two kill switches and an uncalibrated threshold → one `ROUTER_MODE`, no threshold.
- History fetch and read-only key → dropped (Decision 5).
- Deploy gaps (GHCR, external volume, generated stack.yml, network, CI) → Repo changes, Prereqs.
- Uncheckable pass/fail items → rewritten with commands and fixtures.
