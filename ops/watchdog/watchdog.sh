#!/bin/sh
# openwa-watchdog — keep WhatsApp sessions live by self-healing the passive message stream.
#
# WHY: whatsapp-web.js drives a real Chrome against WhatsApp Web. When WA Web reloads the page
# ("Execution context was destroyed ... navigation"), the session auto-recovers to "ready" but the
# passive 'message' event stream silently dies — on-demand calls (getChats) keep working while NEW
# inbound messages stop syncing. There is no config that makes wwebjs immune to this; the fix is to
# detect it and do a FULL session stop+start, which re-attaches the stream. Local Chrome + LocalAuth
# means the restart needs NO QR re-scan.
#
# HOW: every POLL seconds — (1) scan recent logs for engine-death markers and restart the session(s)
# named in them; (2) backstop-restart any session not refreshed in BACKSTOP seconds (bounds the worst
# case even if a death is never logged). A per-session debounce prevents restart loops. If a restart
# lands on qr_ready (auth genuinely lost), that CANNOT self-heal — it's logged as an ALERT.
#
# Runs as a container (docker:cli) with the docker socket mounted; all API calls + the master key stay
# INSIDE openwa-api (via `docker exec`), so no secret is copied into this watchdog.
set -u

CONT="${OPENWA_CONTAINER:-openwa-api}"
POLL="${WATCHDOG_POLL_SECONDS:-60}"
BACKSTOP="${WATCHDOG_BACKSTOP_SECONDS:-21600}"   # 6h: max age before a proactive refresh
DEBOUNCE="${WATCHDOG_DEBOUNCE_SECONDS:-180}"     # min gap between restarts of the SAME session
STATE=/state
# Stream-death markers. Deliberately NOT plain "DISCONNECTED" (too noisy — a normal restart logs it).
DEATH='Execution context was destroyed|because of a navigation|Session engine failed|"action":"engine_error"|detached Frame|Target closed|Protocol error'

mkdir -p "$STATE"
log(){ echo "[$(date '+%Y-%m-%dT%H:%M:%S%z')] $*"; }

# Emit "<id> <status>" for every session (node one-liner run INSIDE openwa-api → its DB + creds).
list_sessions(){
  docker exec "$CONT" node -e '
    const {Client}=require("pg");
    const c=new Client({host:process.env.DATABASE_HOST,port:+process.env.DATABASE_PORT||5432,database:process.env.DATABASE_NAME,user:process.env.DATABASE_USERNAME,password:process.env.DATABASE_PASSWORD});
    c.connect().then(()=>c.query("SELECT id,status FROM sessions")).then(r=>{for(const x of r.rows)console.log(x.id+" "+x.status);return c.end();}).catch(()=>process.exit(0));' 2>/dev/null
}

# stop -> start one session via the in-container API + master key; prints the /start HTTP status.
do_restart(){
  sid="$1"
  docker exec "$CONT" node -e '
    const k=process.env.API_MASTER_KEY, sid=process.argv[1], B="http://localhost:2785/api/sessions/";
    const post=p=>fetch(B+sid+p,{method:"POST",headers:{"x-api-key":k}}).then(r=>r.status).catch(()=>0);
    (async()=>{ await post("/stop"); await new Promise(x=>setTimeout(x,4000)); console.log(await post("/start")); })();
  ' "$sid" 2>/dev/null
  date +%s > "$STATE/last_$sid"
}

# Restart if not debounced. reason is for the log line.
maybe_restart(){
  sid="$1"; reason="$2"
  now=$(date +%s)
  last=$(cat "$STATE/last_$sid" 2>/dev/null || echo 0)
  [ $(( now - last )) -lt "$DEBOUNCE" ] && return 0
  log "restarting session $sid (reason=$reason)"
  http=$(do_restart "$sid")
  log "  /start http=$http — verifying recovery..."
  i=0
  while [ "$i" -lt 12 ]; do
    sleep 5; i=$((i+1))
    st=$(list_sessions | awk -v s="$sid" '$1==s{print $2}')
    case "$st" in
      ready|connected) log "  session $sid healthy (status=$st)"; return 0;;
      qr_ready)        log "  ALERT: session $sid needs a QR re-scan — cannot self-heal (auth lost)"; return 1;;
    esac
  done
  log "  WARN: session $sid not ready within 60s (status=${st:-unknown})"
}

# Seed debounce timers so install doesn't restart healthy sessions immediately (backstop counts from now).
now=$(date +%s)
list_sessions | while read sid status; do
  [ -n "${sid:-}" ] && [ ! -f "$STATE/last_$sid" ] && echo "$now" > "$STATE/last_$sid"
done
log "openwa-watchdog started (container=$CONT poll=${POLL}s backstop=${BACKSTOP}s debounce=${DEBOUNCE}s)"

while true; do
  # (1) Heal on logged engine-death: restart exactly the session(s) named in recent death lines.
  docker logs "$CONT" --since "$((POLL+30))s" 2>&1 \
    | grep -iE "$DEATH" \
    | grep -oE '"sessionId":"[0-9a-fA-F-]+"' | sed 's/.*:"//; s/"$//' | sort -u \
    | while read sid; do
        [ -n "${sid:-}" ] && maybe_restart "$sid" "engine-death"
      done
  # (2) Backstop: proactively refresh any session older than BACKSTOP.
  # BACKSTOP=0 DISABLES this branch entirely (a 0 threshold would otherwise make every session
  # "overdue" on every poll and restart-loop it at the debounce interval). Since OpenWA v0.22.0 the
  # engine's own eventsAttached guard refuses to promote a session whose inbound bridge never
  # attached and reloads the page to reinject, so the blind proactive refresh is redundant — and the
  # restart it performs is itself a source of message gaps. The engine-death branch (1) above stays on.
  now=$(date +%s)
  if [ "$BACKSTOP" -le 0 ]; then sleep "$POLL"; continue; fi
  list_sessions | while read sid status; do
    [ -z "${sid:-}" ] && continue
    case "$status" in stopped|failed) continue;; esac
    last=$(cat "$STATE/last_$sid" 2>/dev/null || echo 0)
    [ $(( now - last )) -ge "$BACKSTOP" ] && maybe_restart "$sid" "backstop-refresh"
  done
  sleep "$POLL"
done
