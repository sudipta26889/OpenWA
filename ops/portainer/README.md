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

1. Read-only checks: both volumes and both networks (`openwa-network`, `openwa-internal-docker`) exist, and `openwa-network` is inside `TRUSTED_PROXIES` (10.201.7.0/24). Both GHCR images pull for linux/amd64.
2. Create the stack Env from the live values, file to process, never printed. Keep `NODE_ID=openwa-api`.
3. `pg_dump` the database on db.lan. Then stop the old containers with a grace period: `docker stop -t 90 openwa-mcp-oauth-gateway openwa-api openwa-docker-proxy`.
4. With everything stopped, tar both volumes to `~/backups/`.
5. Rename the three stopped containers to `<name>-precutover`, because the stack reuses the names. Do not remove them.
6. Create the Git stack `openwa-prod`: endpoint 11, `refs/heads/main`, path `ops/portainer/stack.yml`.
7. Verify before any cleanup:
   - `:2785/api/health` is 200 and the public route answers.
   - Every session reaches `ready` with no QR.
   - An inbound message arrives and an MCP OAuth call works.
   - The container env hash matches `.env`.
8. Create the webhook, then set the repo secret `PORTAINER_WEBHOOK_URL`.

**Rollback before step 8:** stop the stack, rename the old containers back, `docker start` them. The volumes are the same.

The watchdog (`ops/watchdog`) is not in this stack. It has been exited since 2026-09-30 and bind-mounts `watchdog.sh` from the checkout, so it needs an owner decision and an image of its own if it returns.
