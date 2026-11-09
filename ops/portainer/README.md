# Portainer production stack

`stack.yml` is the Git-backed Portainer stack `openwa-prod` on endpoint 11 (the NUC). CI builds the images on push to `main` (`.github/workflows/homelab-deploy.yml`) and fires the stack webhook.

- `stack.yml` is generated. After an upstream merge or an override change, run `./ops/portainer/generate-stack.sh` and commit the result.
- A new env key goes in `.env` and the stack Env, and must be forwarded in `docker-compose.yml` or the override.
- Rollback after cutover: pin the stack images to an older `:<short-sha>` and redeploy.

## State that must survive

| Volume | Mounted at | Holds |
|---|---|---|
| `openwa_openwa-data` | `/app/data` in openwa-api | WhatsApp LocalAuth sessions, generated keys |
| `openwa_mcp-oauth-gateway-data` | `/data` in the gateway | Sealed OAuth state |

Both are `external: true`, so a missing or misnamed volume fails the deploy instead of creating an empty one. Never run two API containers on these volumes. WhatsApp allows one live client per login.

## One-time cutover (run on the NUC, operator access needed)

Keep the running containers untouched until step 3.

1. Read-only checks: both volumes and both networks exist (on 2026-11-09 `openwa-network` was 10.201.6.0/24 and `openwa-internal-docker` 10.201.7.0/24; the stack assigns no subnet). Both GHCR images pull for linux/amd64, and the disk has room for the images and the volume backup.
2. Build the stack Env from the live containers' env, file to process, never printed. Add `API_PORT=2785`, which only the port mapping uses. Keep `NODE_ID=openwa-api`.
3. Stop the old containers with a grace period: `docker stop -t 90 openwa-mcp-oauth-gateway openwa-api openwa-docker-proxy`. Then `pg_dump` the database on db.lan.
4. With everything stopped, tar both volumes to `~/backups/`.
5. Rename the three stopped containers to `<name>-precutover`, because the stack reuses the names. Do not remove them.
6. Create the Git stack `openwa-prod`: endpoint 11, `refs/heads/main`, path `ops/portainer/stack.yml`.
7. Verify before any cleanup:
   - `:2785/api/health` is 200 and the public route answers.
   - Every session reaches `ready` with no QR.
   - An inbound message arrives and an MCP OAuth call works.
   - The new containers' env matches the stopped old containers on every stack key, compared by hash.
8. Create the webhook, then set the repo secret `PORTAINER_WEBHOOK_URL`.

**Rollback before step 8:** stop the stack, rename the old containers back, `docker start` them. The volumes are the same.

The watchdog runs in this stack from its own image (`ops/watchdog`).
