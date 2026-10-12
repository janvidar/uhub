#!/usr/bin/env bash
#
# End-to-end test for mod_users, driven with real ADC clients (adc_cmd) against
# a live uhub with mod_auth_sqlite. Covers what test_mod_users.tcc cannot,
# because there the hub is a fake: the plugin loading at the current plugin
# API, the hub clearing passwords from !userlist, and finding a connected user
# to disconnect even when they logged in with a different case than the
# account's.
#
# Usage:  BUILD=/path/to/build  test/e2e/run_users_e2e.sh  [port]
# Requires (from the build dir): uhub, adc_cmd, uhub-passwd, mod_auth_sqlite.so,
# mod_users.so.
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PORT=${1:-51021}
HUB="adc://127.0.0.1:$PORT"

UHUB=$BUILD/uhub
ADC=$BUILD/adc_cmd
PASSWD=$BUILD/uhub-passwd

for bin in "$UHUB" "$ADC" "$PASSWD"; do
	[ -x "$bin" ] || { echo "MISSING: $bin (build it first)"; exit 2; }
done
for mod in mod_auth_sqlite mod_users; do
	[ -f "$BUILD/$mod.so" ] || { echo "MISSING: $BUILD/$mod.so"; exit 2; }
done

DIR=$(mktemp -d)
HUB_PID=""
pass=0; fail=0

cleanup() {
	[ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null
	wait 2>/dev/null
	if [ -n "${KEEP:-}" ]; then echo "workdir kept: $DIR"; else rm -rf "$DIR"; fi
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

# Run one command as an account and keep what came back. op <nick> <pass> <log> <command>
op() {
	"$ADC" "$HUB" --nick "$1" --password "$2" --send "$4" --linger 2 >"$DIR/$3" 2>&1
}

# A user who stays online in the background until disconnected. Sets BG_PID.
online() { # nick pass log
	"$ADC" "$HUB" --nick "$1" --password "$2" --expect ok --linger 12 >"$DIR/$3" 2>&1 &
	BG_PID=$!
	wait_for "LOGGED_IN" "$DIR/$3"
}

# --- setup ---
"$PASSWD" "$DIR/users.db" create                    >/dev/null 2>&1
"$PASSWD" "$DIR/users.db" add admin adminpass admin >/dev/null 2>&1
"$PASSWD" "$DIR/users.db" add oper operpass op      >/dev/null 2>&1

cat > "$DIR/plugins.conf" <<EOF
plugin $BUILD/mod_auth_sqlite.so "file=$DIR/users.db"
plugin $BUILD/mod_users.so
EOF

cat > "$DIR/uhub.conf" <<EOF
server_port = $PORT
server_bind_addr = 127.0.0.1
file_plugins = $DIR/plugins.conf
tls_enable = 0
EOF

echo "== uhub mod_users e2e (port $PORT, workdir $DIR) =="
start_hub || exit 1

# 1. an operator registers an account, and it can log in with its password.
op oper operpass add.log "!useradd dave davepass"
if grep -q 'Registered "dave" as user' "$DIR/add.log"; then
	ok "!useradd registers an account"; else bad "!useradd (see $DIR/add.log)"; fi
if "$ADC" "$HUB" --nick dave --password davepass --expect ok --linger 1 >"$DIR/dave.log" 2>&1; then
	ok "the new account logs in with its password"; else bad "new account login (see $DIR/dave.log)"; fi

# 2. an operator cannot create another operator.
op oper operpass addop.log "!useradd eve evepass op"
if grep -q "below your own" "$DIR/addop.log" && ! "$PASSWD" "$DIR/users.db" list 2>/dev/null | grep -q eve; then
	ok "an operator cannot register an operator"; else bad "operator created an operator (see $DIR/addop.log)"; fi

# 3. !userlist shows the accounts, and no password reaches the client.
op oper operpass list.log "!userlist"
if grep -q "3 accounts" "$DIR/list.log" && grep -q "dave" "$DIR/list.log" && grep -q "admin" "$DIR/list.log" \
	&& ! grep -qE "davepass|adminpass" "$DIR/list.log"; then
	ok "!userlist lists accounts without passwords"; else bad "!userlist (see $DIR/list.log)"; fi

# 4. !userdel disconnects the user still logged in to the account.
if online dave davepass dave_bg.log; then
	op oper operpass del.log "!userdel dave"
	wait "$BG_PID" 2>/dev/null
	if grep -q "DISCONNECTED" "$DIR/dave_bg.log" && ! "$PASSWD" "$DIR/users.db" list 2>/dev/null | grep -q dave; then
		ok "!userdel deletes the account and disconnects its user"; else bad "!userdel (see $DIR/dave_bg.log / $DIR/del.log)"; fi
else
	bad "dave never logged in (see $DIR/dave_bg.log)"; kill "$BG_PID" 2>/dev/null
fi

# 5. ... found even when they logged in as GRACE to the account "grace".
op admin adminpass addg.log "!useradd grace gracepass"
if online GRACE gracepass grace_bg.log; then
	op admin adminpass delg.log "!userdel grace"
	wait "$BG_PID" 2>/dev/null
	if grep -q "DISCONNECTED" "$DIR/grace_bg.log"; then
		ok "!userdel finds a user whose nick differs in case"; else bad "case-differing user kept online (see $DIR/grace_bg.log / $DIR/delg.log)"; fi
else
	bad "GRACE never logged in (see $DIR/grace_bg.log)"; kill "$BG_PID" 2>/dev/null
fi

# 6. a demoted operator loses the session that still carries operator rights.
op admin adminpass addop2.log "!useradd frank frankpass op"
if online frank frankpass frank_bg.log; then
	op admin adminpass demote.log "!usermod frank user"
	wait "$BG_PID" 2>/dev/null
	if grep -q "DISCONNECTED" "$DIR/frank_bg.log" && "$PASSWD" "$DIR/users.db" list 2>/dev/null | grep -qx "user	frank"; then
		ok "!usermod demotion takes effect and disconnects"; else bad "!usermod demotion (see $DIR/frank_bg.log / $DIR/demote.log)"; fi
else
	bad "frank never logged in (see $DIR/frank_bg.log)"; kill "$BG_PID" 2>/dev/null
fi

# 7. !userpass: the old password stops working, the new one works.
op admin adminpass pass.log "!userpass frank newfrank"
if "$ADC" "$HUB" --nick frank --password newfrank --expect ok --linger 1 >"$DIR/newpass.log" 2>&1 \
	&& "$ADC" "$HUB" --nick frank --password frankpass --expect fail --linger 1 >"$DIR/oldpass.log" 2>&1; then
	ok "!userpass replaces the password"; else bad "!userpass (see $DIR/newpass.log / $DIR/oldpass.log)"; fi

echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
