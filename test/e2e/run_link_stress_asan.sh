#!/usr/bin/env bash
#
# Federation churn stress: link two hubs, storm BOTH with adcrush so local user
# joins/quits propagate across the link, then shut both down while users (local
# and remote) are still attached. Built under a sanitizer, this exercises the
# federation code path -- remote-user create/destroy (user_create_remote /
# uman_add_remote / uman_remove_remote), roster propagation, and link teardown
# under load -- which the single-hub adcrush churn never touches.
#
# It complements run_adcrush_asan.sh (single hub). Like that one, this is
# lifecycle/memory coverage under load, not a data-race test.
#
# Usage:  BUILD=/path/to/build  test/e2e/run_link_stress_asan.sh  [portA] [portB]
# The build must have -DADC_STRESS=ON and a sanitizer enabled.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PA=${1:-52141}
PB=${2:-52142}
SECRET="link-stress-secret"

UHUB=$BUILD/uhub
CRUSH=$BUILD/adcrush
for f in "$UHUB" "$CRUSH"; do
	[ -x "$f" ] || { echo "MISSING: $f (build with -DADC_STRESS=ON)"; exit 2; }
done

DIR=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$DIR"; }
trap cleanup EXIT

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"

cat > "$DIR/hub_a.conf" <<EOF
server_port = $PA
server_bind_addr = 127.0.0.1
tls_enable = 0
link_secret = $SECRET
node_count = 2
node_id = 0
EOF
cat > "$DIR/hub_b.conf" <<EOF
server_port = $PB
server_bind_addr = 127.0.0.1
tls_enable = 0
link_secret = $SECRET
node_count = 2
node_id = 1
link_peer = 127.0.0.1:$PA
EOF

start_hub() { # conf log port -> sets HUB_PID
	"$UHUB" -c "$1" -v -v > "$2" 2>&1 &
	HUB_PID=$!
	PIDS+=("$HUB_PID")
	local i
	for i in $(seq 1 100); do
		(exec 3<>"/dev/tcp/127.0.0.1/$3") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
		kill -0 "$HUB_PID" 2>/dev/null || { echo "hub died:"; cat "$2"; return 1; }
		sleep 0.1
	done
	echo "hub not listening on $3:"; cat "$2"; return 1
}

wait_for() { # pattern file [tries]
	local pat=$1 file=$2 n=${3:-100} i
	for i in $(seq 1 "$n"); do grep -q "$pat" "$file" 2>/dev/null && return 0; sleep 0.1; done
	return 1
}

start_hub "$DIR/hub_a.conf" "$DIR/hubA.log" "$PA" || exit 1
HUBA_PID=$HUB_PID
start_hub "$DIR/hub_b.conf" "$DIR/hubB.log" "$PB" || exit 1
HUBB_PID=$HUB_PID

if ! { wait_for "link established" "$DIR/hubA.log" && wait_for "link established" "$DIR/hubB.log"; }; then
	echo "FAIL: link not established"; cat "$DIR/hubA.log" "$DIR/hubB.log"; exit 1
fi

# Storm both hubs so joins/quits propagate across the link in both directions.
"$CRUSH" "adc://127.0.0.1:$PA" -n 40 -l 3 -q > "$DIR/crushA.log" 2>&1 &
PIDS+=("$!"); CA=$!
"$CRUSH" "adc://127.0.0.1:$PB" -n 40 -l 3 -q > "$DIR/crushB.log" 2>&1 &
PIDS+=("$!"); CB=$!
sleep 10
kill "$CA" "$CB" 2>/dev/null; wait "$CA" "$CB" 2>/dev/null

for pair in "A:$HUBA_PID:$DIR/hubA.log" "B:$HUBB_PID:$DIR/hubB.log"; do
	name=${pair%%:*}; rest=${pair#*:}; pid=${rest%%:*}; log=${rest#*:}
	if ! kill -0 "$pid" 2>/dev/null; then
		echo "FAIL: hub $name died during the storm"; cat "$log"; exit 1
	fi
done

# Shut both down with local + remote users still attached (link teardown).
kill -TERM "$HUBA_PID" "$HUBB_PID"
wait "$HUBA_PID"; rcA=$?
wait "$HUBB_PID"; rcB=$?

for pair in "A:$rcA:$DIR/hubA.log" "B:$rcB:$DIR/hubB.log"; do
	name=${pair%%:*}; rest=${pair#*:}; rc=${rest%%:*}; log=${rest#*:}
	if grep -q "Sanitizer" "$log"; then
		echo "FAIL: sanitizer error in hub $name:"; cat "$log"; exit 1
	fi
	if [ "$rc" -ne 0 ]; then
		echo "FAIL: hub $name exited non-zero ($rc)"; cat "$log"; exit 1
	fi
done
echo "PASS: linked-hub federation churn + shutdown stayed sanitizer-clean"
