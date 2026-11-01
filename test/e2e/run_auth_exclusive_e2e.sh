#!/usr/bin/env bash
#
# End-to-end test for an "exclusive" auth plugin (issue #130): only accounts in
# its database may log in, whatever else is loaded and wherever the login
# arrives. Four hubs:
#
#   A  mod_auth_sqlite exclusive=1; the auth master
#   S  an auth_proxy slave of A, holding no accounts of its own
#   E  mod_auth_sqlite exclusive=1 and nothing else
#   G  mod_auth_sqlite without exclusive, the control: unknown nicks are guests
#
#  1. an account logs in on A with its password;
#  2. an unknown nick is refused on A;
#  3. the account logs in on S, verified through the master;
#  4. an unknown nick is refused on S, because the master refuses it;
#  5. on E an unknown nick is refused (before, the flag only gated
#     registration, and the nick logged in as a guest);
#  6. on G an unknown nick still logs in as a guest.
#
# Usage:  BUILD=/path/to/build  test/e2e/run_auth_exclusive_e2e.sh  [portA] [portS] [portG] [portE]
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PA=${1:-51071}
PS=${2:-51072}
PG=${3:-51073}
PE=${4:-51074}
HUBA="adc://127.0.0.1:$PA"
HUBS="adc://127.0.0.1:$PS"
HUBG="adc://127.0.0.1:$PG"
HUBE="adc://127.0.0.1:$PE"
SECRET="e2e-link-secret"

UHUB=$BUILD/uhub
ADC=$BUILD/adc_cmd
PASSWD=$BUILD/uhub-passwd

for bin in "$UHUB" "$ADC" "$PASSWD"; do
	[ -x "$bin" ] || { echo "MISSING: $bin (build it first)"; exit 2; }
done
for so in mod_auth_sqlite; do
	[ -f "$BUILD/$so.so" ] || { echo "MISSING: $BUILD/$so.so"; exit 2; }
done

DIR=$(mktemp -d)
HUB_PIDS=()
pass=0; fail=0

cleanup() {
	for p in "${HUB_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	[ -n "${KEEP:-}" ] || rm -rf "${DIR:?}"
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

expect() { # ok|fail description log adc_cmd-args...
	local want=$1 what=$2 log=$3
	shift 3
	if "$ADC" "$@" --expect "$want" --linger 1 >"$DIR/$log" 2>&1; then
		ok "$what"
	else
		bad "$what (see $DIR/$log)"
	fi
}

for n in a e g; do
	"$PASSWD" "$DIR/users_$n.db" create >/dev/null 2>&1
	"$PASSWD" "$DIR/users_$n.db" add admin adminpass admin >/dev/null 2>&1
done
echo "plugin $BUILD/mod_auth_sqlite.so \"file=$DIR/users_a.db exclusive=1\"" > "$DIR/plugins_a.conf"
echo "plugin $BUILD/mod_auth_sqlite.so \"file=$DIR/users_g.db\"" > "$DIR/plugins_g.conf"
echo "plugin $BUILD/mod_auth_sqlite.so \"file=$DIR/users_e.db exclusive=1\"" > "$DIR/plugins_e.conf"
: > "$DIR/plugins_s.conf"

cat > "$DIR/hub_a.conf" <<EOF
server_port = $PA
server_bind_addr = 127.0.0.1
file_plugins = $DIR/plugins_a.conf
tls_enable = 0
link_secret = $SECRET
node_count = 2
node_id = 0
EOF

cat > "$DIR/hub_s.conf" <<EOF
server_port = $PS
server_bind_addr = 127.0.0.1
file_plugins = $DIR/plugins_s.conf
tls_enable = 0
link_secret = $SECRET
node_count = 2
node_id = 1
link_peer = 127.0.0.1:$PA
auth_proxy = 1
EOF

cat > "$DIR/hub_g.conf" <<EOF
server_port = $PG
server_bind_addr = 127.0.0.1
file_plugins = $DIR/plugins_g.conf
tls_enable = 0
EOF

cat > "$DIR/hub_e.conf" <<EOF
server_port = $PE
server_bind_addr = 127.0.0.1
file_plugins = $DIR/plugins_e.conf
tls_enable = 0
EOF

echo "== uhub exclusive-auth e2e (A=$PA exclusive master, S=$PS slave, G=$PG control, workdir $DIR) =="
start_hub "$DIR/hub_a.conf" "$DIR/hubA.log" "$PA" || exit 1
start_hub "$DIR/hub_s.conf" "$DIR/hubS.log" "$PS" || exit 1
start_hub "$DIR/hub_g.conf" "$DIR/hubG.log" "$PG" || exit 1
start_hub "$DIR/hub_e.conf" "$DIR/hubE.log" "$PE" || exit 1
wait_for "link established" "$DIR/hubS.log" || { bad "slave never linked to the master (see $DIR/hubS.log)"; }

expect ok   "an account logs in on the exclusive hub"                    a_admin.log    "$HUBA" --nick admin --password adminpass
expect fail "an unknown nick is refused on the exclusive hub"            a_stranger.log "$HUBA" --nick stranger
expect ok   "the account logs in on the slave, through the master"       s_admin.log    "$HUBS" --nick admin --password adminpass
expect fail "an unknown nick is refused on the slave, as on the master"  s_stranger.log "$HUBS" --nick stranger
expect fail "exclusive alone refuses an unknown nick"                     e_stranger.log "$HUBE" --nick stranger
expect ok   "without exclusive, an unknown nick is still a guest"        g_stranger.log "$HUBG" --nick stranger

echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
