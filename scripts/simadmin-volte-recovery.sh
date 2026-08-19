#!/bin/bash

set -u

TAG="SimAdmin-VoLTERecovery"
API_URL="${SIMADMIN_VOLTE_API_URL:-http://127.0.0.1:3000/api/volte}"
STATE_DIR="${SIMADMIN_VOLTE_RECOVERY_STATE_DIR:-/run/simadmin}"
THRESHOLD="${SIMADMIN_VOLTE_RECOVERY_THRESHOLD:-2}"
UDP_THRESHOLD="${SIMADMIN_VOLTE_RECOVERY_UDP_THRESHOLD:-4}"
COOLDOWN_SECS="${SIMADMIN_VOLTE_RECOVERY_COOLDOWN_SECS:-300}"
DRY_RUN="${SIMADMIN_VOLTE_RECOVERY_DRY_RUN:-0}"
STATE_FILE="$STATE_DIR/volte-recovery.state"
LOCK_DIR="$STATE_DIR/volte-recovery.lock"

log() {
  logger -t "$TAG" "$*"
}

mkdir -p "$STATE_DIR"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

RESPONSE="$(curl -fsS --max-time 5 "$API_URL/control" 2>/dev/null || true)"
if [ -z "$RESPONSE" ]; then
  log "VoLTE status API unavailable; leaving runtime untouched"
  exit 0
fi

CLASSIFICATION="$(printf '%s' "$RESPONSE" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin).get("data") or {}
    runtime = data.get("runtime") or {}
    enabled = bool(data.get("enabled", data.get("feature_enabled", False)))
    registered = bool(runtime.get("registered", False))
    phase = str(runtime.get("phase") or "")
    error = str(runtime.get("last_error") or "")
    timeout = "volte_udp_recv_timeout" in error or "volte_runtime_all_pcscf_failed" in error
    mode = str(runtime.get("registration_mode") or "").lower()
    if not enabled:
        print("inactive")
    elif registered and mode == "udp":
        print("udp_fallback")
    elif registered:
        print("registered")
    elif phase == "degraded" and timeout:
        print("pcscf_timeout")
    else:
        print("other")
except Exception:
    print("invalid")
')"

COUNT=0
COOLDOWN_UNTIL=0
LAST_CLASS="none"
if [ -r "$STATE_FILE" ]; then
  read -r COUNT COOLDOWN_UNTIL LAST_CLASS < "$STATE_FILE" || true
fi
case "$COUNT:$COOLDOWN_UNTIL" in
  *[!0-9:]*|:*) COUNT=0; COOLDOWN_UNTIL=0; LAST_CLASS="none" ;;
esac

NOW="$(date +%s)"
if [ "$CLASSIFICATION" != "pcscf_timeout" ] && [ "$CLASSIFICATION" != "udp_fallback" ]; then
  printf '0 0 none\n' > "$STATE_FILE"
  exit 0
fi

if [ "$NOW" -lt "$COOLDOWN_UNTIL" ]; then
  exit 0
fi

if [ "$LAST_CLASS" != "$CLASSIFICATION" ]; then
  COUNT=0
fi
COUNT=$((COUNT + 1))
REQUIRED="$THRESHOLD"
REASON="P-CSCF UDP timeout"
if [ "$CLASSIFICATION" = "udp_fallback" ]; then
  REQUIRED="$UDP_THRESHOLD"
  REASON="plain UDP fallback registration"
fi
printf '%s %s %s\n' "$COUNT" "$COOLDOWN_UNTIL" "$CLASSIFICATION" > "$STATE_FILE"
if [ "$COUNT" -lt "$REQUIRED" ]; then
  log "$REASON observed ($COUNT/$REQUIRED); waiting for confirmation"
  exit 0
fi

if [ "$DRY_RUN" = "1" ]; then
  log "Dry run: confirmed $REASON; would recycle the IMS bearer"
  exit 0
fi

log "Confirmed $REASON; recycling the IMS bearer through the VoLTE control API"
if ! curl -fsS --max-time 10 -X POST -H 'Content-Type: application/json' \
  -d '{"enabled":false}' "$API_URL/feature" >/dev/null; then
  log "Failed to disable VoLTE for bearer recovery"
  printf '0 %s none\n' "$((NOW + 60))" > "$STATE_FILE"
  exit 1
fi

sleep 3
if ! curl -fsS --max-time 10 -X POST -H 'Content-Type: application/json' \
  -d '{"enabled":true}' "$API_URL/feature" >/dev/null; then
  log "Failed to re-enable VoLTE after bearer recovery"
  printf '0 %s none\n' "$((NOW + 60))" > "$STATE_FILE"
  exit 1
fi

printf '0 %s none\n' "$((NOW + COOLDOWN_SECS))" > "$STATE_FILE"
log "IMS bearer recycle requested; cooldown ${COOLDOWN_SECS}s"
