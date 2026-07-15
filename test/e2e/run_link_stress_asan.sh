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

# Best-effort dump of a stuck process: state, an all-thread backtrace (gdb if
# available) and the tail of its log. Never fails the shell. On CI gdb may need
# sudo to attach to a sibling (yama ptrace_scope); fall back to plain gdb, then
# to the kernel task stacks under /proc.
diag_stuck() { # pid label log
	local pid=$1 label=$2 log=$3 gdb_cmd="" t
	echo "===== DIAG $label (pid $pid) ====="
	ps -o pid,ppid,stat,etime,comm -p "$pid" 2>/dev/null || true
	if command -v gdb >/dev/null 2>&1; then
		if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then gdb_cmd="sudo gdb"; else gdb_cmd="gdb"; fi
		echo "----- $gdb_cmd: thread apply all bt (pid $pid) -----"
		$gdb_cmd -p "$pid" -batch -nx -ex 'set pagination off' \
			-ex 'thread apply all bt' -ex detach -ex quit 2>&1 | sed 's/^/  /' || true
	else
		echo "(gdb unavailable; kernel task stacks:)"
		for t in /proc/"$pid"/task/*/stack; do
			[ -r "$t" ] && { echo "-- $t --"; cat "$t" 2>/dev/null; }
		done
	fi
	echo "----- $label log tail -----"; tail -50 "$log" 2>/dev/null || true
	echo "===== END DIAG $label ====="
}

# Wait for a pid up to N seconds. Returns the child's exit status on a clean
# exit; on timeout, dumps diagnostics, SIGKILLs it, and returns 124. This turns
# a shutdown deadlock into a fast, self-diagnosing failure instead of a job that
# hangs until the CI limit.
wait_timeout() { # pid secs label log
	local pid=$1 secs=$2 label=$3 log=$4 i
	for (( i = 0; i < secs * 10; i++ )); do
		kill -0 "$pid" 2>/dev/null || { wait "$pid"; return $?; }
		sleep 0.1
	done
	echo "FAIL: $label (pid $pid) did not exit within ${secs}s -- likely deadlock"
	diag_stuck "$pid" "$label" "$log"
	kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
	return 124
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
kill "$CA" "$CB" 2>/dev/null
wait_timeout "$CA" 15 "adcrush A" "$DIR/crushA.log" || true
wait_timeout "$CB" 15 "adcrush B" "$DIR/crushB.log" || true

for pair in "A:$HUBA_PID:$DIR/hubA.log" "B:$HUBB_PID:$DIR/hubB.log"; do
	name=${pair%%:*}; rest=${pair#*:}; pid=${rest%%:*}; log=${rest#*:}
	if ! kill -0 "$pid" 2>/dev/null; then
		echo "FAIL: hub $name died during the storm"; cat "$log"; exit 1
	fi
done

# Shut both down with local + remote users still attached (link teardown).
# Bounded waits: a shutdown deadlock is reported (with a backtrace) and killed
# rather than hanging the job. 30s is far beyond a healthy shutdown (sub-second).
kill -TERM "$HUBA_PID" "$HUBB_PID"
wait_timeout "$HUBA_PID" 30 "hub A" "$DIR/hubA.log"; rcA=$?
wait_timeout "$HUBB_PID" 30 "hub B" "$DIR/hubB.log"; rcB=$?

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
