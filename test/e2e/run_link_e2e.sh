#!/usr/bin/env bash
#
# End-to-end test for cluster propagation across two linked hubs. Verifies that
# a ban issued on one node reaches the other over the link (LBAN) -- kicking a
# user connected to the far node and blocking their reconnect there -- and that
# an unban propagates too (LUBN).
#
# Each hub has its OWN auth/ban database, so the only path a ban can travel from
# node A to node B is the link itself (not shared storage).
#
# Usage:  BUILD=/path/to/build  test/e2e/run_link_e2e.sh  [portA] [portB]
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PA=${1:-51021}
PB=${2:-51022}
HUBA="adc://127.0.0.1:$PA"
HUBB="adc://127.0.0.1:$PB"
SECRET="e2e-link-secret"

UHUB=$BUILD/uhub
ADC=$BUILD/adc_cmd
PASSWD=$BUILD/uhub-passwd

for bin in "$UHUB" "$ADC" "$PASSWD"; do
	[ -x "$bin" ] || { echo "MISSING: $bin (build it first)"; exit 2; }
done
[ -f "$BUILD/mod_auth_sqlite.so" ] || { echo "MISSING: $BUILD/mod_auth_sqlite.so"; exit 2; }

DIR=$(mktemp -d)
HUB_PIDS=()
pass=0; fail=0

cleanup() {
	for p in "${HUB_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	rm -rf "$DIR"
}
trap cleanup EXIT

ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

wait_for() { # pattern file [tries]
	local pat=$1 file=$2 n=${3:-80} i
	for i in $(seq 1 "$n"); do grep -q "$pat" "$file" 2>/dev/null && return 0; sleep 0.1; done
	return 1
}

start_hub() { # conf log port
	"$UHUB" -c "$1" -v -v >"$2" 2>&1 &
	local pid=$! i
	HUB_PIDS+=("$pid")
	for i in $(seq 1 50); do
		(exec 3<>"/dev/tcp/127.0.0.1/$3") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
		kill -0 "$pid" 2>/dev/null || { echo "hub died:"; cat "$2"; return 1; }
		sleep 0.1
	done
	echo "hub not listening on $3:"; cat "$2"; return 1
}

# --- setup: two hubs, each with its own operator DB ---
for n in a b; do
	"$PASSWD" "$DIR/users_$n.db" create >/dev/null 2>&1
	"$PASSWD" "$DIR/users_$n.db" add admin adminpass admin >/dev/null 2>&1
	echo "plugin $BUILD/mod_auth_sqlite.so \"file=$DIR/users_$n.db\"" > "$DIR/plugins_$n.conf"
done

cat > "$DIR/hub_a.conf" <<EOF
server_port = $PA
server_bind_addr = 127.0.0.1
file_plugins = $DIR/plugins_a.conf
tls_enable = 0
link_secret = $SECRET
node_count = 2
node_id = 0
EOF

cat > "$DIR/hub_b.conf" <<EOF
server_port = $PB
server_bind_addr = 127.0.0.1
file_plugins = $DIR/plugins_b.conf
tls_enable = 0
link_secret = $SECRET
node_count = 2
node_id = 1
link_peer = 127.0.0.1:$PA
EOF

echo "== uhub linked-hub e2e (A=$PA node0, B=$PB node1, workdir $DIR) =="
start_hub "$DIR/hub_a.conf" "$DIR/hubA.log" "$PA" || exit 1
start_hub "$DIR/hub_b.conf" "$DIR/hubB.log" "$PB" || exit 1

if wait_for "link established" "$DIR/hubA.log" && wait_for "link established" "$DIR/hubB.log"; then
	ok "hubs A and B establish a link"
else
	bad "link not established (see $DIR/hubA.log / $DIR/hubB.log)"; echo "== result: $pass passed, $fail failed =="; exit 1
fi

# Victim connects to hub B and stays online.
"$ADC" "$HUBB" --nick victim --expect ok --linger 20 >"$DIR/victim.log" 2>&1 &
VPID=$!
if ! wait_for "LOGGED_IN" "$DIR/victim.log"; then
	bad "victim never logged in to B"; kill "$VPID" 2>/dev/null; echo "== result: $pass passed, $fail failed =="; exit 1
fi

# Roster propagates B->A: an observer on A should see the victim in the roster.
seen=1
for attempt in 1 2 3 4 5; do
	"$ADC" "$HUBA" --nick spy --linger 1 >"$DIR/spy.log" 2>&1
	grep -q "JOIN: victim" "$DIR/spy.log" && { seen=0; break; }
	sleep 0.4
done
[ $seen -eq 0 ] && ok "unified roster: A sees a user connected to B" || bad "A never saw victim in the roster (see $DIR/spy.log)"

# Operator on A bans the (remote) victim -> LBAN should reach B.
"$ADC" "$HUBA" --nick admin --password adminpass --send "!ban victim" --linger 3 >"$DIR/op_ban.log" 2>&1
wait "$VPID" 2>/dev/null || true
if grep -q "DISCONNECTED" "$DIR/victim.log"; then
	ok "ban on A disconnects the victim on B (LBAN propagated)"
else
	bad "victim on B not disconnected by ban on A (see $DIR/victim.log / $DIR/op_ban.log)"
fi

# Banned nick cannot reconnect to B.
if "$ADC" "$HUBB" --nick victim --expect fail --linger 1 >"$DIR/reconn_ban.log" 2>&1; then
	ok "banned nick is refused on B after ban on A"
else
	bad "banned nick still able to connect to B (see $DIR/reconn_ban.log)"
fi

# Operator on A unbans -> LUBN should reach B.
"$ADC" "$HUBA" --nick admin --password adminpass --send "!unban victim" --linger 3 >"$DIR/op_unban.log" 2>&1
if "$ADC" "$HUBB" --nick victim --expect ok --linger 1 >"$DIR/reconn_unban.log" 2>&1; then
	ok "unban on A restores access on B (LUBN propagated)"
else
	bad "nick still refused on B after unban on A (see $DIR/reconn_unban.log)"
fi

echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
