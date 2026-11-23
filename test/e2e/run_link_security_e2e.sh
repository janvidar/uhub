#!/usr/bin/env bash
#
# End-to-end checks that the hub-to-hub link cannot be joined or driven by
# someone whose key the hub has not pinned. Two hubs: A, the master and
# cluster coordinator, and S, an auth_proxy slave that links to it, each
# listing the other's link key in link_keys.
#
#  1. A and S establish their link (TLS with pinned keys, between real hubs).
#  2. A plain-text link attempt is refused before A says a word.
#  3. A TLS link attempt without a certificate, or with one whose key A has
#     not pinned, gets no challenge -- so the reflection attacks of issue
#     #127 have nothing to reflect.
#  4. A nick with an embedded newline, given to the slave, cannot inject a
#     command into its master link (issue #128): the injected LBAN never
#     reaches A, so the nick it names can still log in there.
#
# Scenario 2 speaks the link protocol over bash's /dev/tcp, scenario 3 over
# openssl s_client, since no real hub would send those lines.
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
. "$SCRIPT_DIR/link_tls.sh"
link_tls_setup "$DIR"
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
$(link_tls_conf a)
node_count = 2
node_id = 0
EOF

cat > "$DIR/hub_s.conf" <<EOF
server_port = $PS
server_bind_addr = 127.0.0.1
file_plugins = $DIR/plugins_s.conf
plugin_defaults = no
$(link_tls_conf b)
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

# --- 2: a plain-text link attempt ---
exec 3<>"/dev/tcp/127.0.0.1/$PA"
printf 'LCHA %s\n' "$NONCE" >&3
read_lines
if [ "$EOF" = 1 ] && ! line_value "LCHA " >/dev/null && ! line_value "LRES " >/dev/null; then
	ok "a plain-text link attempt is disconnected unanswered"
else
	bad "A answered a plain-text link (lines: ${LINES[*]:-none}, eof $EOF)"
fi
exec 3>&- 3<&-

# --- 3: TLS without a pinned key ---
# tls_link_try [cert key]: what A says to an LCHA over TLS.
tls_link_try() {
	local args=()
	[ $# -eq 2 ] && args=(-cert "$1" -key "$2")
	printf 'LCHA %s\n' "$NONCE" | timeout 3 openssl s_client -connect "127.0.0.1:$PA" -quiet "${args[@]}" 2>/dev/null
}
if ! tls_link_try | grep -q "^LCHA \|^LRES "; then
	ok "a TLS link attempt without a certificate gets no challenge"
else
	bad "A challenged a link peer with no certificate"
fi
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout "$DIR/stranger-key.pem" -out "$DIR/stranger-cert.pem" -days 2 -subj /CN=stranger >/dev/null 2>&1
if ! tls_link_try "$DIR/stranger-cert.pem" "$DIR/stranger-key.pem" | grep -q "^LCHA \|^LRES "; then
	ok "a TLS link attempt with an unpinned key gets no challenge"
else
	bad "A challenged a link peer whose key it has not pinned"
fi
if wait_for "is not in link_keys" "$DIR/hubA.log" 10 && wait_for "presented no certificate" "$DIR/hubA.log" 10; then
	ok "A logs why it refused each"
else
	bad "no refusal reason in $DIR/hubA.log"
fi

sleep 0.3
if [ "$(established_count)" = "$BASE" ]; then
	ok "no link was established by any refused attempt"
else
	bad "a refused attempt established a link (see $DIR/hubA.log)"
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
