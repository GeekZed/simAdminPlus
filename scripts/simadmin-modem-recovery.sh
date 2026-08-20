#!/bin/sh

set -u

TAG="${SIMADMIN_RECOVERY_TAG:-SimAdmin-ModemRecovery}"
MMCLI_BIN="${MMCLI_BIN:-mmcli}"
QMICLI_BIN="${QMICLI_BIN:-qmicli}"
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-systemctl}"
TIMEOUT_BIN="${TIMEOUT_BIN:-timeout}"
SLEEP_BIN="${SLEEP_BIN:-sleep}"
LOGGER_BIN="${LOGGER_BIN:-logger}"
QMI_DEVICE="${QMI_DEVICE:-/dev/wwan0qmi0}"
STATE_DIR="${STATE_DIR:-/run/simadmin}"
RPMSG_DEVICES_DIR="${RPMSG_DEVICES_DIR:-/sys/bus/rpmsg/devices}"

STARTUP_TIMEOUT_SECONDS="${STARTUP_TIMEOUT_SECONDS:-120}"
CHECK_INTERVAL_SECONDS="${CHECK_INTERVAL_SECONDS:-5}"
STALE_CONFIRMATIONS="${STALE_CONFIRMATIONS:-3}"
POST_RESTART_TIMEOUT_SECONDS="${POST_RESTART_TIMEOUT_SECONDS:-90}"
POST_DATA6_STABLE_CONFIRMATIONS="${POST_DATA6_STABLE_CONFIRMATIONS:-3}"
QMI_TIMEOUT_SECONDS="${QMI_TIMEOUT_SECONDS:-15}"

STATUS_FILE="${STATE_DIR}/modem-recovery-status"
IN_PROGRESS_FILE="${STATE_DIR}/modem-recovery-in-progress"

log() {
  message="$*"
  printf '%s\n' "$message"
  "$LOGGER_BIN" -t "$TAG" -- "$message" >/dev/null 2>&1 || true
}

set_status() {
  mkdir -p "$STATE_DIR"
  printf '%s\n' "$1" > "$STATUS_FILE"
}

cleanup() {
  rm -f "$IN_PROGRESS_FILE"
}

mm_snapshot() {
  "$MMCLI_BIN" -m any 2>&1 || true
}

mm_has_sim() {
  printf '%s\n' "$1" | grep -Eq \
    'primary sim path:[[:space:]]*/org/freedesktop/ModemManager1/SIM/'
}

mm_is_stale_sim_missing() {
  snapshot="$1"
  if printf '%s\n' "$snapshot" | grep -Eqi \
    'No modems were found|couldn.t find modem'; then
    return 0
  fi

  printf '%s\n' "$snapshot" | grep -Eqi \
    'failed reason:[[:space:]]*.*sim-missing'
}

uim_is_ready() {
  [ -e "$QMI_DEVICE" ] || return 1

  output="$($TIMEOUT_BIN "$QMI_TIMEOUT_SECONDS" "$QMICLI_BIN" \
    -d "$QMI_DEVICE" --device-open-proxy --uim-get-card-status 2>&1 || true)"
  printf '%s\n' "$output" | grep -Eq \
    "Card state:[[:space:]]*'present'" || return 1
  printf '%s\n' "$output" | grep -Eq \
    "Application type:[[:space:]]*'usim" || return 1
  printf '%s\n' "$output" | grep -Eq \
    "Application state:[[:space:]]*'ready'"
}

data6_present() {
  for name_file in "$RPMSG_DEVICES_DIR"/*/name; do
    [ -f "$name_file" ] || continue
    [ "$(cat "$name_file" 2>/dev/null)" = "DATA6_CNTL" ] && return 0
  done
  return 1
}

wait_for_mm_sim() {
  timeout_seconds="$1"
  elapsed=0
  while [ "$elapsed" -lt "$timeout_seconds" ]; do
    snapshot="$(mm_snapshot)"
    if mm_has_sim "$snapshot"; then
      return 0
    fi
    "$SLEEP_BIN" "$CHECK_INTERVAL_SECONDS"
    elapsed=$((elapsed + CHECK_INTERVAL_SECONDS))
  done
  return 1
}

wait_for_mm_sim_stable() {
  timeout_seconds="$1"
  required="$2"
  elapsed=0
  stable_count=0
  while [ "$elapsed" -lt "$timeout_seconds" ]; do
    snapshot="$(mm_snapshot)"
    if mm_has_sim "$snapshot"; then
      stable_count=$((stable_count + 1))
      if [ "$stable_count" -ge "$required" ]; then
        return 0
      fi
    else
      stable_count=0
    fi
    "$SLEEP_BIN" "$CHECK_INTERVAL_SECONDS"
    elapsed=$((elapsed + CHECK_INTERVAL_SECONDS))
  done
  return 1
}

trap cleanup EXIT INT TERM
mkdir -p "$STATE_DIR"
set_status "observing"
log "Cold-start modem observation started"

elapsed=0
stale_count=0
while [ "$elapsed" -lt "$STARTUP_TIMEOUT_SECONDS" ]; do
  snapshot="$(mm_snapshot)"
  if mm_has_sim "$snapshot"; then
    set_status "healthy"
    log "ModemManager SIM object is available; recovery is not needed"
    exit 0
  fi

  if uim_is_ready && mm_is_stale_sim_missing "$snapshot"; then
    stale_count=$((stale_count + 1))
    log "QMI reports USIM ready while ModemManager is stale (${stale_count}/${STALE_CONFIRMATIONS})"
    if [ "$stale_count" -ge "$STALE_CONFIRMATIONS" ]; then
      break
    fi
  else
    stale_count=0
  fi

  "$SLEEP_BIN" "$CHECK_INTERVAL_SECONDS"
  elapsed=$((elapsed + CHECK_INTERVAL_SECONDS))
done

if [ "$stale_count" -lt "$STALE_CONFIRMATIONS" ]; then
  set_status "no-safe-action"
  log "No safe automatic recovery condition was confirmed; leaving modem untouched"
  exit 0
fi

touch "$IN_PROGRESS_FILE"
set_status "restarting-modemmanager"
log "Confirmed QMI USIM ready with persistent ModemManager sim-missing; restarting ModemManager once"
if ! "$SYSTEMCTL_BIN" restart ModemManager.service; then
  set_status "restart-command-failed"
  log "ModemManager restart command failed; no further automatic action will be taken"
  exit 1
fi

if ! wait_for_mm_sim "$POST_RESTART_TIMEOUT_SECONDS"; then
  set_status "recovery-failed"
  log "ModemManager did not recover after one restart; MPSS and the operating system will not be restarted automatically"
  exit 1
fi

if data6_present; then
  set_status "reinitializing-data6"
  log "ModemManager recovered; rebuilding DATA6 after the primary QMI restart"
  if ! "$SYSTEMCTL_BIN" restart simadmin-secondary-qmi.service; then
    set_status "recovered-data6-failed"
    log "ModemManager recovered but DATA6 reinitialization failed"
    exit 1
  fi
  if ! wait_for_mm_sim_stable \
    "$POST_RESTART_TIMEOUT_SECONDS" "$POST_DATA6_STABLE_CONFIRMATIONS"; then
    set_status "recovered-data6-mm-unstable"
    log "DATA6 was rebuilt but ModemManager did not become stable; no further automatic action will be taken"
    exit 1
  fi
fi

set_status "recovered"
log "ModemManager SIM object recovered successfully"
exit 0
