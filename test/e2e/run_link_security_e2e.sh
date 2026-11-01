#!/usr/bin/env bash
#
# End-to-end checks that the hub-to-hub link cannot be joined or driven by
# someone who does not hold the link secret. Two hubs: A, the master and
# cluster coordinator, and S, an auth_proxy slave that links to it.
#
#  1. A and S establish their link (the handshake works between real hubs).
#  2. A peer that echoes A's own challenge back is refused (issue #127).
#  3. A peer that plays A's own answer back to it is refused (issue #127).
#  4. A nick with an embedded newline, given to the slave, cannot inject a
#     command into its master link (issue #128): the injected LBAN never
#     reaches A, so the nick it names can still log in there.
#
# The reflection scenarios speak the link protocol directly over bash's
# /dev/tcp, since no real hub would send those lines.
#
# Usage:  BUILD=/path/to/build  test/e2e/run_link_security_e2e.sh  [portA] [portS]
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PA=${1:-51031}
PS=${2:-51032}
HUBA="adc://127.0.0.1:$PA"
HUBS="adc://127.0.0.1:$PS"
SECRET="e2e-link-secret"
NONCE="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
CID="GNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI"

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
	exec 3>&- 3<&- 2>/dev/null
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

# Read lines from fd 3 into LINES until a timeout or EOF. Sets EOF=1 when the
# hub closed the connection.
LINES=()
EOF=0
read_lines() {
	local line
	LINES=(); EOF=0
	while :; do
		if IFS= read -r -t 1 line <&3 2>/dev/null; then
			LINES+=("$line")
		else
			# read returns >128 on a timeout; anything else is end of stream.
			[ $? -gt 128 ] || EOF=1
			return
		fi
	done
}

line_value() { # prefix -> the rest of the first line in LINES with it
	local l
	for l in "${LINES[@]:-}"; do
		case "$l" in "$1"*) printf '%s' "${l#"$1"}"; return 0;; esac
	done
	return 1
}

established_count() { grep -c "link established" "$DIR/hubA.log"; }

# --- setup: master A with an account database, slave S proxying auth to A ---
"$PASSWD" "$DIR/users.db" create >/dev/null 2>&1
"$PASSWD" "$DIR/users.db" add admin adminpass admin >/dev/null 2>&1
echo "plugin $BUILD/mod_auth_sqlite.so \"file=$DIR/users.db\"" > "$DIR/plugins_a.conf"
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

echo "== uhub link security e2e (A=$PA master, S=$PS auth_proxy slave, workdir $DIR) =="
start_hub "$DIR/hub_a.conf" "$DIR/hubA.log" "$PA" || exit 1
start_hub "$DIR/hub_s.conf" "$DIR/hubS.log" "$PS" || exit 1

if wait_for "link established" "$DIR/hubA.log" && wait_for "link established" "$DIR/hubS.log"; then
	ok "hubs A and S establish a link"
else
	bad "link not established (see $DIR/hubA.log / $DIR/hubS.log)"; echo "== result: $pass passed, $fail failed =="; exit 1
fi
BASE=$(established_count)

# --- 2: echo A's own challenge back at it ---
exec 3<>"/dev/tcp/127.0.0.1/$PA"
printf 'LCHA %s\n' "$NONCE" >&3
read_lines
CHAL=$(line_value "LCHA ") || CHAL=""
if [ -z "$CHAL" ]; then
	bad "A did not challenge a link peer"
else
	# A answered our first challenge already; now ask it to answer its own.
	printf 'LCHA %s\n' "$CHAL" >&3
	read_lines
	if [ "$EOF" = 1 ] && ! line_value "LRES " >/dev/null; then
		ok "a peer echoing A's own challenge is disconnected unanswered"
	else
		bad "A answered its own challenge (lines: ${LINES[*]:-none}, eof $EOF)"
		# Finish the attack, so the check below sees whether it worked.
		ANSWER=$(line_value "LRES ") && printf 'LRES %s\nLACK\n' "$ANSWER" >&3
		read_lines
	fi
fi
exec 3>&- 3<&-

# --- 3: play A's own answer back to it ---
exec 3<>"/dev/tcp/127.0.0.1/$PA"
printf 'LCHA %s\n' "$NONCE" >&3
read_lines
RESP=$(line_value "LRES ") || RESP=""
if [ -z "$RESP" ]; then
	bad "A did not answer a link peer's challenge"
else
	printf 'LRES %s\nLACK\n' "$RESP" >&3
	read_lines
	if [ "$EOF" = 1 ] && line_value "LERR" >/dev/null && ! line_value "LACK" >/dev/null; then
		ok "a peer replaying A's own answer is refused (LERR)"
	else
		bad "A accepted its own answer (lines: ${LINES[*]:-none}, eof $EOF)"
	fi
fi
exec 3>&- 3<&-

sleep 0.3
if [ "$(established_count)" = "$BASE" ]; then
	ok "no link was established by either reflection attempt"
else
	bad "a reflection attempt established a link (see $DIR/hubA.log)"
fi

# --- 4: a newline in a nick given to the slave ---
EVIL=$'x\nLBAN 0 '"$CID"$' innocent injected'
"$ADC" "$HUBS" --nick "$EVIL" --expect fail --linger 1 >"$DIR/evil.log" 2>&1
sleep 0.5
if "$ADC" "$HUBA" --nick innocent --expect ok --linger 1 >"$DIR/innocent.log" 2>&1; then
	ok "a nick with a newline on the slave injects no ban on the master"
else
	bad "the nick named in the injected LBAN is refused on A (see $DIR/innocent.log / $DIR/hubA.log)"
fi
if wait_for "link established" "$DIR/hubS.log" 5 && "$ADC" "$HUBS" --nick regular --expect ok --linger 1 >"$DIR/regular.log" 2>&1; then
	ok "the slave still logs in an ordinary nick through the master"
else
	bad "an ordinary login on the slave failed afterwards (see $DIR/regular.log / $DIR/hubS.log)"
fi

echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
