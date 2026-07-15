#!/usr/bin/env bash
#
# Connection-churn stress: hammer a hub with adcrush (many bots connecting,
# logging in and disconnecting), then shut the hub down while clients are still
# attached. Built under a sanitizer, this exercises the accept / login / route /
# teardown lifecycle under load -- the churn the unit suite never produces.
#
# It is the regression guard for the shutdown-time user-manager use-after-free
# (a user disconnected while the hub was not running was freed while still
# linked, and the HUB_SHUTDOWN sweep then called uman_remove on freed memory).
# adcrush is a single-threaded load generator against the single-threaded hub;
# this is lifecycle/memory coverage, not a data-race test.
#
# Usage:  BUILD=/path/to/build  test/e2e/run_adcrush_asan.sh  [port]
# The build must have -DADC_STRESS=ON and a sanitizer enabled.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PORT=${1:-52123}

UHUB=$BUILD/uhub
CRUSH=$BUILD/adcrush
for f in "$UHUB" "$CRUSH"; do
	[ -x "$f" ] || { echo "MISSING: $f (build with -DADC_STRESS=ON)"; exit 2; }
done

DIR=$(mktemp -d)
HUB_PID=""
cleanup() { [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null; wait 2>/dev/null; rm -rf "$DIR"; }
trap cleanup EXIT

cat > "$DIR/uhub.conf" <<EOF
server_port = $PORT
server_bind_addr = 127.0.0.1
tls_enable = 0
EOF

# abort_on_error so a sanitizer report is a hard failure; no LSan on macOS.
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"

"$UHUB" -c "$DIR/uhub.conf" > "$DIR/hub.log" 2>&1 &
HUB_PID=$!

listening=0
for _ in $(seq 1 100); do
	if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then exec 3>&- 3<&-; listening=1; break; fi
	kill -0 "$HUB_PID" 2>/dev/null || break
	sleep 0.1
done
[ "$listening" = 1 ] || { echo "FAIL: hub did not start"; cat "$DIR/hub.log"; exit 1; }

# Storm: 50 aggressive bots for a few seconds, then stop the client.
"$CRUSH" "adc://127.0.0.1:$PORT" -n 50 -l 3 -q > "$DIR/adcrush.log" 2>&1 &
CRUSH_PID=$!
sleep 8
kill "$CRUSH_PID" 2>/dev/null; wait "$CRUSH_PID" 2>/dev/null

# A crash during the storm would have taken the hub down already.
if ! kill -0 "$HUB_PID" 2>/dev/null; then
	echo "FAIL: hub died during the storm"; cat "$DIR/hub.log"; HUB_PID=""; exit 1
fi

# Graceful shutdown while bots may still be attached: drives the teardown sweep.
kill -TERM "$HUB_PID"; wait "$HUB_PID"; rc=$?
HUB_PID=""

if grep -q "Sanitizer" "$DIR/hub.log"; then
	echo "FAIL: sanitizer error in the hub:"; cat "$DIR/hub.log"; exit 1
fi
if [ "$rc" -ne 0 ]; then
	echo "FAIL: hub exited non-zero ($rc)"; cat "$DIR/hub.log"; exit 1
fi
echo "PASS: adcrush storm + shutdown stayed sanitizer-clean"
