#!/usr/bin/env bash
#
# End-to-end test for the ban / unban / reconnect flow, driven with real ADC
# clients (adc_cmd) against a live uhub. Exercises the runtime path that the C
# unit tests cannot: an operator !ban disconnects an online user and blocks the
# reconnect (check_acl), and !unban lets them back in. Also checks a timed ban
# (temporary status) and persistence of a ban across a hub restart.
#
# Usage:  BUILD=/path/to/build  test/e2e/run_ban_e2e.sh  [port]
# Requires (from the build dir): uhub, adc_cmd, uhub-passwd, mod_auth_sqlite.so.
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PORT=${1:-51011}
HUB="adc://127.0.0.1:$PORT"

UHUB=$BUILD/uhub
ADC=$BUILD/adc_cmd
PASSWD=$BUILD/uhub-passwd

for bin in "$UHUB" "$ADC" "$PASSWD"; do
	[ -x "$bin" ] || { echo "MISSING: $bin (build it first)"; exit 2; }
done
[ -f "$BUILD/mod_auth_sqlite.so" ] || { echo "MISSING: $BUILD/mod_auth_sqlite.so"; exit 2; }

DIR=$(mktemp -d)
HUB_PID=""
pass=0; fail=0

cleanup() {
	[ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null
	wait 2>/dev/null
	rm -rf "$DIR"
}
trap cleanup EXIT

ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }

wait_for() { # pattern file [tries]
	local pat=$1 file=$2 n=${3:-60} i
	for i in $(seq 1 "$n"); do grep -q "$pat" "$file" 2>/dev/null && return 0; sleep 0.1; done
	return 1
}

start_hub() {
	"$UHUB" -c "$DIR/uhub.conf" >"$DIR/hub.log" 2>&1 &
	HUB_PID=$!
	local i
	for i in $(seq 1 50); do
		(exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
		kill -0 "$HUB_PID" 2>/dev/null || { echo "hub died on startup:"; cat "$DIR/hub.log"; return 1; }
		sleep 0.1
	done
	echo "hub did not start listening:"; cat "$DIR/hub.log"; return 1
}
stop_hub() { [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null; wait "$HUB_PID" 2>/dev/null; HUB_PID=""; }

# --- setup: operator account + config ---
"$PASSWD" "$DIR/users.db" create              >/dev/null 2>&1
"$PASSWD" "$DIR/users.db" add admin adminpass admin >/dev/null 2>&1

cat > "$DIR/plugins.conf" <<EOF
plugin $BUILD/mod_auth_sqlite.so "file=$DIR/users.db"
EOF

cat > "$DIR/uhub.conf" <<EOF
server_port = $PORT
server_bind_addr = 127.0.0.1
file_plugins = $DIR/plugins.conf
tls_enable = 0
EOF

echo "== uhub ban/unban e2e (port $PORT, workdir $DIR) =="
start_hub || exit 1

# 1. baseline: a guest can log in.
if "$ADC" "$HUB" --nick alice --expect ok --linger 1 >"$DIR/s1.log" 2>&1; then
	ok "guest login succeeds"; else bad "guest login (see $DIR/s1.log)"; fi

# 2. operator bans an online victim.
"$ADC" "$HUB" --nick victim --expect ok --linger 12 >"$DIR/victim_bg.log" 2>&1 &
VPID=$!
if wait_for "LOGGED_IN" "$DIR/victim_bg.log"; then
	"$ADC" "$HUB" --nick admin --password adminpass --send "!ban victim" --linger 3 >"$DIR/op_ban.log" 2>&1
	wait "$VPID" 2>/dev/null || true
	if grep -q "DISCONNECTED" "$DIR/victim_bg.log"; then ok "online victim is disconnected by !ban"; else bad "victim not kicked (see $DIR/victim_bg.log / $DIR/op_ban.log)"; fi
else
	bad "victim never logged in (see $DIR/victim_bg.log)"; kill "$VPID" 2>/dev/null
fi

# 3. the banned nick cannot reconnect.
if "$ADC" "$HUB" --nick victim --expect fail --linger 1 >"$DIR/s3.log" 2>&1; then
	ok "banned nick is refused on reconnect"; else bad "banned nick still able to reconnect (see $DIR/s3.log)"; fi

# 4. operator lifts the ban.
"$ADC" "$HUB" --nick admin --password adminpass --send "!unban victim" --linger 3 >"$DIR/op_unban.log" 2>&1

# 5. the nick can log in again.
if "$ADC" "$HUB" --nick victim --expect ok --linger 1 >"$DIR/s5.log" 2>&1; then
	ok "nick can reconnect after !unban"; else bad "nick still refused after !unban (see $DIR/s5.log)"; fi

# 6. timed ban is reported as temporary.
"$ADC" "$HUB" --nick tmpvic --expect ok --linger 12 >"$DIR/tmp_bg.log" 2>&1 &
TPID=$!
if wait_for "LOGGED_IN" "$DIR/tmp_bg.log"; then
	"$ADC" "$HUB" --nick admin --password adminpass --send "!ban tmpvic 1h" --linger 3 >"$DIR/op_tban.log" 2>&1
	wait "$TPID" 2>/dev/null
	# Reconnect: expect refusal with a temporary-ban status (232 = fatal + BANNED_TEMPORARILY).
	"$ADC" "$HUB" --nick tmpvic --expect fail --linger 1 >"$DIR/s6.log" 2>&1
	rc=$?
	if [ $rc -eq 0 ] && grep -q "LOGIN_ERROR 232" "$DIR/s6.log"; then ok "timed !ban reports a temporary ban (232)"; else bad "timed ban not reported as temporary (see $DIR/s6.log)"; fi
	"$ADC" "$HUB" --nick admin --password adminpass --send "!unban tmpvic" --linger 2 >/dev/null 2>&1
else
	bad "tmpvic never logged in"; kill "$TPID" 2>/dev/null
fi

# 7. a ban persists across a hub restart (mod_auth_sqlite storage).
"$ADC" "$HUB" --nick pvic --expect ok --linger 12 >"$DIR/pvic_bg.log" 2>&1 &
PBID=$!
if wait_for "LOGGED_IN" "$DIR/pvic_bg.log"; then
	"$ADC" "$HUB" --nick admin --password adminpass --send "!ban pvic" --linger 3 >/dev/null 2>&1
	wait "$PBID" 2>/dev/null
	stop_hub
	start_hub || exit 1
	if "$ADC" "$HUB" --nick pvic --expect fail --linger 1 >"$DIR/s7.log" 2>&1; then
		ok "ban persists across a hub restart"; else bad "ban lost across restart (see $DIR/s7.log)"; fi
else
	bad "pvic never logged in"; kill "$PBID" 2>/dev/null
fi

echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
