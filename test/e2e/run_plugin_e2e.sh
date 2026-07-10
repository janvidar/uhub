#!/usr/bin/env bash
#
# End-to-end test for plugin-facing hooks, using the mod_e2e_test plugin:
#   - on_validate_nick rejects a login (the reserved nick "denynick");
#   - a plugin-driven ban via hub.ban_user (chat trigger "PLZBANME");
#   - a plugin-driven unban via hub.unban  (operator chat trigger "PLZUNBAN <nick>").
#
# Usage:  BUILD=/path/to/build  test/e2e/run_plugin_e2e.sh  [port]
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PORT=${1:-51051}
HUB="adc://127.0.0.1:$PORT"

UHUB=$BUILD/uhub
ADC=$BUILD/adc_cmd
PASSWD=$BUILD/uhub-passwd

for f in "$UHUB" "$ADC" "$PASSWD" "$BUILD/mod_auth_sqlite.so" "$BUILD/mod_e2e_test.so"; do
	[ -e "$f" ] || { echo "MISSING: $f (build it first)"; exit 2; }
done

DIR=$(mktemp -d)
HUB_PID=""
pass=0; fail=0

cleanup() { [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null; wait 2>/dev/null; rm -rf "$DIR"; }
trap cleanup EXIT
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }
wait_for() { local pat=$1 file=$2 n=${3:-60} i; for i in $(seq 1 "$n"); do grep -q "$pat" "$file" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

start_hub() {
	"$UHUB" -c "$DIR/uhub.conf" >"$DIR/hub.log" 2>&1 &
	HUB_PID=$!
	local i
	for i in $(seq 1 50); do
		(exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
		kill -0 "$HUB_PID" 2>/dev/null || { echo "hub died:"; cat "$DIR/hub.log"; return 1; }
		sleep 0.1
	done
	echo "hub not listening:"; cat "$DIR/hub.log"; return 1
}

"$PASSWD" "$DIR/users.db" create >/dev/null 2>&1
"$PASSWD" "$DIR/users.db" add admin adminpass admin >/dev/null 2>&1

cat > "$DIR/plugins.conf" <<EOF
plugin $BUILD/mod_auth_sqlite.so "file=$DIR/users.db"
plugin $BUILD/mod_e2e_test.so
EOF
cat > "$DIR/uhub.conf" <<EOF
server_port = $PORT
server_bind_addr = 127.0.0.1
file_plugins = $DIR/plugins.conf
tls_enable = 0
EOF

echo "== uhub plugin-hook e2e (port $PORT, workdir $DIR) =="
start_hub || exit 1

# 1. on_validate_nick rejects "denynick"; a normal nick still logs in.
if "$ADC" "$HUB" --nick denynick --expect fail --linger 1 >"$DIR/deny.log" 2>&1; then
	ok "on_validate_nick rejects a login"; else bad "denynick was not rejected (see $DIR/deny.log)"; fi
if "$ADC" "$HUB" --nick gooduser --expect ok --linger 1 >"$DIR/good.log" 2>&1; then
	ok "on_validate_nick allows a normal nick"; else bad "gooduser rejected (see $DIR/good.log)"; fi

# 2. plugin-driven ban: the victim triggers hub.ban_user on itself.
"$ADC" "$HUB" --nick pvictim --send "PLZBANME" --linger 3 --expect ok >"$DIR/selfban.log" 2>&1
if grep -q "DISCONNECTED" "$DIR/selfban.log"; then
	ok "hub.ban_user disconnects the user (plugin-driven ban)"; else bad "plugin ban did not disconnect (see $DIR/selfban.log)"; fi
if "$ADC" "$HUB" --nick pvictim --expect fail --linger 1 >"$DIR/pban_reconn.log" 2>&1; then
	ok "plugin-banned nick is refused on reconnect"; else bad "plugin-banned nick still able to reconnect (see $DIR/pban_reconn.log)"; fi

# 3. plugin-driven unban: an operator triggers hub.unban.
"$ADC" "$HUB" --nick admin --password adminpass --send "PLZUNBAN pvictim" --linger 3 >"$DIR/punban.log" 2>&1
if "$ADC" "$HUB" --nick pvictim --expect ok --linger 1 >"$DIR/punban_reconn.log" 2>&1; then
	ok "hub.unban restores access (plugin-driven unban)"; else bad "nick still refused after plugin unban (see $DIR/punban_reconn.log)"; fi

echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
