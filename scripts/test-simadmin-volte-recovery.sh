#!/bin/bash

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/bin" "$TEST_DIR/state"

cat > "$TEST_DIR/bin/curl" <<'EOF'
#!/bin/bash
case " $* " in
  *"/control"*) printf '%s\n' "$MOCK_STATUS" ;;
  *) printf '%s\n' "$*" >> "$MOCK_ACTIONS" ;;
esac
EOF
cat > "$TEST_DIR/bin/logger" <<'EOF'
#!/bin/bash
exit 0
EOF
cat > "$TEST_DIR/bin/sleep" <<'EOF'
#!/bin/bash
exit 0
EOF
chmod +x "$TEST_DIR/bin/curl" "$TEST_DIR/bin/logger" "$TEST_DIR/bin/sleep"

export PATH="$TEST_DIR/bin:$PATH"
export MOCK_ACTIONS="$TEST_DIR/actions"
export SIMADMIN_VOLTE_API_URL="http://mock/api/volte"
export SIMADMIN_VOLTE_RECOVERY_STATE_DIR="$TEST_DIR/state"
export SIMADMIN_VOLTE_RECOVERY_THRESHOLD=2
export SIMADMIN_VOLTE_RECOVERY_UDP_THRESHOLD=4
export SIMADMIN_VOLTE_RECOVERY_COOLDOWN_SECS=300

run_check() {
  bash "$ROOT/scripts/simadmin-volte-recovery.sh"
}

MOCK_STATUS='{"data":{"enabled":true,"runtime":{"registered":true,"phase":"registered"}}}'
export MOCK_STATUS
run_check
test ! -e "$MOCK_ACTIONS"

MOCK_STATUS='{"data":{"enabled":true,"runtime":{"registered":false,"phase":"degraded","last_error":"volte_runtime_all_pcscf_failed:volte_udp_recv_timeout"}}}'
export MOCK_STATUS
run_check
test "$(cut -d' ' -f1 "$TEST_DIR/state/volte-recovery.state")" = "1"
test ! -e "$MOCK_ACTIONS"

run_check
test "$(wc -l < "$MOCK_ACTIONS")" = "2"
grep -q 'enabled.*false' "$MOCK_ACTIONS"
grep -q 'enabled.*true' "$MOCK_ACTIONS"

rm -f "$MOCK_ACTIONS"
MOCK_STATUS='{"data":{"enabled":true,"runtime":{"registered":false,"phase":"degraded","last_error":"volte_usim_aka_failed"}}}'
export MOCK_STATUS
run_check
test ! -e "$MOCK_ACTIONS"
test "$(cat "$TEST_DIR/state/volte-recovery.state")" = "0 0 none"

MOCK_STATUS='{"data":{"enabled":true,"runtime":{"registered":true,"phase":"registered","registration_mode":"udp"}}}'
export MOCK_STATUS
run_check
run_check
run_check
test ! -e "$MOCK_ACTIONS"
run_check
test "$(wc -l < "$MOCK_ACTIONS")" = "2"
grep -q 'enabled.*false' "$MOCK_ACTIONS"
grep -q 'enabled.*true' "$MOCK_ACTIONS"

echo "VoLTE recovery tests passed"
