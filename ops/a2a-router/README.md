# a2a-router

Reads new 1:1 WhatsApp messages from OpenWA webhooks, asks the owner's local model (Flint, through
LiteLLM) whether the owner has to act, and proposes a task to TaskPilot over A2A. TaskPilot holds every
peer write for the owner's approval. The router never sends WhatsApp messages and holds no OpenWA API key.

The contract is `docs/designs/a2a-router.md`. This file only covers running it. It lives outside `src/`,
like `ops/mcp-oauth-gateway`, so upstream merges never conflict. No npm dependencies (Node 22 built-ins).

```
OpenWA ── webhook message.received (HMAC, filters set in OpenWA) ──▶ a2a-router:8790/hook
a2a-router ── chat/completions ──▶ LiteLLM (recursivesi/flint)
a2a-router ── A2A message/send ──▶ TaskPilot /a2a
a2a-router ── JSONL ──▶ /data
```

## Modes (`ROUTER_MODE`)

| mode     | does                                                                 |
| -------- | -------------------------------------------------------------------- |
| `off`    | stores events and logs each batch; no model call, no peer call        |
| `shadow` | classifies and logs; **no peer call**. Start here and review 7 days   |
| `live`   | also sends a task proposal to TaskPilot when `action_needed` is true  |

Before `live`: `curl -s https://taskpilot-mcp.sudiptadhara.in/health` must show the DharaHIL and
approval-worker dependencies healthy. Without DharaHIL, TaskPilot runs peer writes unapproved.

## Configuration

| variable                      | default                                        |
| ----------------------------- | ---------------------------------------------- |
| `ROUTER_MODE`                 | `off`                                          |
| `ROUTER_LLM_BASE_URL`         | required (LiteLLM base, e.g. `https://…/v1`)   |
| `ROUTER_MODEL`                | `recursivesi/flint`                            |
| `ROUTER_TASKPILOT_URL`        | `https://taskpilot-mcp.sudiptadhara.in/a2a`    |
| `ROUTER_WEBHOOK_SECRET_FILE`  | required: path, ≥16 characters inside          |
| `ROUTER_LLM_KEY_FILE`         | required: path of the router's LiteLLM key     |
| `ROUTER_TASKPILOT_TOKEN_FILE` | required: path of the minted peer JWT          |
| `ROUTER_BATCH_QUIET_MS`       | `120000`                                       |
| `ROUTER_PEER_TIMEOUT_MS`      | `120000`                                       |
| `ROUTER_LLM_TIMEOUT_MS`       | `60000`                                        |
| `ROUTER_CLASSIFY_RETRY_MS`    | `1800000` (30 min)                             |
| `ROUTER_CLASSIFY_GIVE_UP_MS`  | `86400000` (24 h)                              |
| `ROUTER_SESSION_NAMES`        | optional JSON `{"<sessionId>":"personal-wa"}`  |
| `ROUTER_DATA_DIR`, `PORT`     | `/data`, `8790`                                |

**Owner rule: WhatsApp text reaches `recursivesi/flint` and no other model.** `ROUTER_MODEL` may only be
`recursivesi/flint`; any other value makes the router refuse to start (and `classify-fixture` refuse to
run). LiteLLM must also have no fallback route from `recursivesi/flint` to a cloud model, otherwise a Flint
outage would send message text to that cloud model without the router knowing.

**Flint runs on the owner's MacBook Pro.** When the laptop is off or asleep, Flint is down, possibly for a
whole night. A classification that fails because the backend is unavailable (timeout, network error, HTTP
5xx, 429 or 404) is retried every `ROUTER_CLASSIFY_RETRY_MS` until `ROUTER_CLASSIFY_GIVE_UP_MS` after the
batch's first attempt, so messages wait up to 24 h for Flint. Only then is the batch final. Retries go one
at a time; once one fails as unavailable, the other waiting batches wait for the next tick instead of each
calling the model (`/health` shows `llmUnavailableUntil`). The retry state is read back from `routes.jsonl`
after a restart. Unusable model output (`invalid_json`, `invalid_shape`) still gets one retry after 10 min,
then is final. Inbound events of a batch that is still retrying are never pruned.

Secrets are only ever file paths. The files must be readable by the container user (uid 1000, `node`),
mode 600. The token file is re-read on every peer call, so a rotated token needs no restart.

## Data (`/data`, mode 600)

- `inbound.jsonl` holds each accepted webhook event (this is where message text lives). Written and
  fsynced before the 200 answer.
- `routes.jsonl` has one line per state change of a batch: `batched`, `classify_failed`, `shadow`,
  `no_action`, `pending` (with the exact request bytes, `request`), `retry_wait`, `routed`, `peer_failed`,
  `peer_rejected`, `peer_auth_failed`, `mode_off`. It never holds a raw message body.
- `inbound.jsonl` lines (raw message bodies) are pruned after 7 days (`INBOUND_RETENTION_MS`), but an event
  whose batch is not yet terminal is never pruned. `routes.jsonl` lines are pruned after 90 days. Pruning
  runs at startup and daily.

`GET /health` returns `{mode, pending, lastRouteAt, peerAuthFailed, llmUnavailableUntil}` (`llmUnavailableUntil`
is an ISO time while the model is known to be down, otherwise `null`).

## Webhooks (created by the owner after the router is up in `shadow`)

Two, one per session, `POST /api/sessions/{id}/webhooks` with an operator key: URL
`http://a2a-router:8790/hook`, event `message.received`, a secret of at least 16 characters (the content
of `ROUTER_WEBHOOK_SECRET_FILE`), and `filters` (all must match): `fromMe is false`, `kind is individual`,
`sender isNot [owner's ids, family/staff, OpenClaw allowlist]`. The router repeats only a cheap guard.

## Peer outcomes

`routed` (`auth_required` or `completed`, task id stored), `peer_failed` (`state=failed`, or retries used
up after 30 s, 2 min, 10 min), `peer_rejected` (403, -32602, -32010), `peer_auth_failed` (401 or -32002:
all peer calls stop until restart, an `ALERT` line is logged). Before every resend the router asks
`tasks/list {contextId}` and, if a task newer than the first attempt exists, records it as `routed`
instead. Every resend uses the stored bytes; the text is never rebuilt.

## Classify the fixture by hand

Runs the two 2026-11-19 ICICI messages (fake sender) through the real prompt against the real model:

```sh
ROUTER_LLM_BASE_URL=… ROUTER_LLM_KEY_FILE=… node ops/a2a-router/router.mjs classify-fixture
```

Expected: `action_needed: true`, and a summary naming the documents.

## Tests

`node --test ops/a2a-router/` (no network; fetch, clock, sleep and data dir are injected).
