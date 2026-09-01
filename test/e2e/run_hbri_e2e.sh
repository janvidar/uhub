#!/usr/bin/env bash
#
# End-to-end test for HBRI (hub-bridged reverse init), the extension that lets a
# dual-stack client have its *other* address family published -- but only after
# proving it over a second connection the hub opens the address from itself.
#
# The whole point is that the client's advertised I4/I6 is a trigger and never
# the published value, so these scenarios all turn on the difference between
# what the client claims and what the hub observes. That difference cannot be
# tested in-process: it needs two real connections on two families.
#
# Usage:  BUILD=/path/to/build  test/e2e/run_hbri_e2e.sh  [port]
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PORT=${1:-51061}
HUB4="adc://127.0.0.1:$PORT"

UHUB=$BUILD/uhub
ADC=$BUILD/adc_cmd

for f in "$UHUB" "$ADC"; do
	[ -e "$f" ] || { echo "MISSING: $f (build it first)"; exit 2; }
done

DIR=$(mktemp -d)
HUB_PID=""
pass=0; fail=0

cleanup() { [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null; wait 2>/dev/null; rm -rf "$DIR"; }
trap cleanup EXIT
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

# No plugins: an explicitly named (empty) file replaces the built-in default
# set, which would otherwise want a users.db outside the work directory.
: > "$DIR/plugins.conf"

write_conf() {  # write_conf [extra config lines...]
	cat > "$DIR/uhub.conf" <<EOF
server_port = $PORT
server_bind_addr = any
file_plugins = $DIR/plugins.conf
hbri_enable = 1
hbri_address4 = 127.0.0.1
hbri_address6 = ::1
EOF
	local line
	for line in "$@"; do echo "$line" >> "$DIR/uhub.conf"; done
}

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

stop_hub() { [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null; wait 2>/dev/null; HUB_PID=""; }

# The token the hub put in the ITCP challenge recorded in a --dump log.
hbri_token_of() { grep -oE "^LINE: ITCP .* TO[A-Z2-7]+" "$1" | sed "s/.*TO//"; }

# Replay a validation reply over the IPv6 loopback and echo what the hub says.
# A validation connection takes no HSUP -- the token is its first and only line
# -- so this needs no client at all, which is the point: it can be sent long
# after the session that was issued the token has gone.
hbri_replay() {
	local token=$1 out
	exec 3<>"/dev/tcp/::1/$PORT" || return 1
	printf "HTCP TO%s\n" "$token" >&3
	out=$(timeout 2 head -c 200 <&3 | tr -d "\0")
	exec 3>&- 3<&-
	printf "%s" "$out"
}

echo "== uhub HBRI e2e (port $PORT, workdir $DIR) =="
write_conf "tls_enable = 0"
start_hub || exit 1

# HBRI needs both families. Test the precondition the scenarios actually rely
# on -- the hub answering on the IPv6 loopback -- rather than guessing from
# ping/ip, which are not available everywhere.
if ! (exec 3<>"/dev/tcp/::1/$PORT") 2>/dev/null; then
	echo "SKIP: hub is not reachable over the IPv6 loopback on this machine"
	exit 0
fi
exec 3>&- 3<&-

# 1. A client that supports HBRI and signals IPv6 connectivity is challenged,
#    answers on the second family, and gets the *observed* address published.
"$ADC" "$HUB4" --nick hbriuser --sup ADHBRI --inf "I6::1" --hbri --dump \
	--linger 3 --expect ok >"$DIR/1.log" 2>&1
if grep -q "^LINE: ITCP " "$DIR/1.log"; then
	ok "hub challenges a dual-stack client (ITCP)"; else bad "no ITCP challenge (see $DIR/1.log)"; fi
if grep -q "HBRI-VALIDATED" "$DIR/1.log"; then
	ok "client answers the challenge on the second family"; else bad "validation connection failed (see $DIR/1.log)"; fi
if grep -qE "^LINE: BINF .*I6::1" "$DIR/1.log"; then
	ok "validated IPv6 address is published in the INF"; else bad "I6 never published (see $DIR/1.log)"; fi

# 2. The claimed address is only a trigger: a client that advertises a bogus I6
#    and answers from ::1 has the observed address published, not its claim.
"$ADC" "$HUB4" --nick hbrilie --sup ADHBRI --inf "I62001:db8::99" --hbri --dump \
	--linger 3 --expect ok >"$DIR/2.log" 2>&1
if grep -qE "^LINE: BINF .*I6::1" "$DIR/2.log"; then
	ok "observed address wins over the advertised one"; else bad "observed address not published (see $DIR/2.log)"; fi
if grep -qE "^LINE: BINF .*I62001:db8::99" "$DIR/2.log"; then
	bad "the client's claimed I6 was published (see $DIR/2.log)"; else
	ok "the client's claimed I6 is never published"; fi

# 3. A client that is challenged but never answers stays primary-only. This is
#    the property that makes the advertised address safe to accept as a trigger.
"$ADC" "$HUB4" --nick hbrimute --sup ADHBRI --inf "I62001:db8::99" --dump \
	--linger 3 --expect ok >"$DIR/3.log" 2>&1
if grep -q "^LINE: ITCP " "$DIR/3.log"; then
	ok "an unanswered challenge is still issued"; else bad "no challenge issued (see $DIR/3.log)"; fi
if grep -qE "^LINE: BINF .*I6" "$DIR/3.log"; then
	bad "an I6 was published without validation (see $DIR/3.log)"; else
	ok "no I6 is published without validation"; fi

# 4. A client that never offered HBRI is never challenged.
"$ADC" "$HUB4" --nick plainuser --inf "I6::1" --dump \
	--linger 2 --expect ok >"$DIR/4.log" 2>&1
if grep -q "^LINE: ITCP " "$DIR/4.log"; then
	bad "a non-HBRI client was challenged (see $DIR/4.log)"; else
	ok "a client that never offered HBRI is not challenged"; fi

# 5. nat_override: the hub cannot observe a useful IPv4 for these clients and
#    trusts their claim, but that says nothing about IPv6 -- which HBRI can
#    still verify. The challenge must be issued, the validated IPv6 published,
#    and the trusted IPv4 claim left exactly as stated.
stop_hub
write_conf "tls_enable = 0" "nat_override = 127.0.0.0/8"
start_hub || exit 1

#    The claim has to be checked from *outside* the NAT: route_info_message()
#    deliberately rewrites I4 to the observed LAN address for users who are
#    themselves inside it, since a LAN peer cannot rely on NAT hairpinning. So
#    the observer joins over IPv6, which the nat_override range does not cover.
"$ADC" "adc://[::1]:$PORT" --nick v6observer --dump --linger 6 --expect ok >"$DIR/5obs.log" 2>&1 &
OBS=$!
sleep 1
"$ADC" "$HUB4" --nick natuser --sup ADHBRI --inf "I4192.0.2.66" --inf "I6::1" --hbri --dump \
	--linger 3 --expect ok >"$DIR/5.log" 2>&1
wait "$OBS"

if grep -q "^LINE: ITCP " "$DIR/5.log"; then
	ok "a nat_override client is still challenged"; else bad "nat_override client never challenged (see $DIR/5.log)"; fi
if grep -qE "^LINE: BINF .*NInatuser.*I6::1" "$DIR/5obs.log"; then
	ok "nat_override client gets its validated IPv6 published"; else bad "no validated I6 for nat_override client (see $DIR/5obs.log)"; fi
if grep -qE "^LINE: BINF .*NInatuser.*I4192\.0\.2\.66" "$DIR/5obs.log"; then
	ok "the trusted IPv4 claim survives validation"; else bad "nat_override IPv4 claim was lost (see $DIR/5obs.log)"; fi
if grep -qE "^LINE: BINF .*NInatuser.*I4127\.0\.0\.1" "$DIR/5.log"; then
	ok "a peer inside the NAT still sees the observed LAN address"; else bad "LAN address not shown to a peer inside the NAT (see $DIR/5.log)"; fi

# 6. A validation that arrives after the user has gone. The token is stateless
#    and the hub holds nothing for an outstanding challenge, so a reply can turn
#    up at any time -- including for a session that no longer exists.
stop_hub
write_conf "tls_enable = 0"
start_hub || exit 1

"$ADC" "$HUB4" --nick gonea --sup ADHBRI --inf "I6::1" --dump \
	--linger 1 --expect ok >"$DIR/6a.log" 2>&1
GONE_TOKEN=$(hbri_token_of "$DIR/6a.log")
if [ -n "$GONE_TOKEN" ]; then
	ok "captured a challenge token"
	REPLY=$(hbri_replay "$GONE_TOKEN")
	case "$REPLY" in
		*"ISTA 150"*) ok "a validation for a departed user is refused (150)" ;;
		*)            bad "unexpected reply to a stale validation: '$REPLY'" ;;
	esac
	if "$ADC" "$HUB4" --nick afterwards --expect ok --linger 1 >"$DIR/6b.log" 2>&1; then
		ok "the hub still serves after a stale validation"; else
		bad "hub unhealthy after a stale validation (see $DIR/6b.log)"; fi
else
	bad "no challenge token to replay (see $DIR/6a.log)"
fi

# 7. The same, but with the departed user's SID already handed to someone else.
#    A one-SID window (node_count = SID_MAX) forces the reuse that would
#    otherwise need the allocator's cursor to wrap the whole space. The MAC
#    binds the token to the connection time as well as the SID, so the stale
#    token must not validate on the new holder's behalf.
stop_hub
write_conf "tls_enable = 0" "node_count = 1048576" "node_id = 1"
start_hub || exit 1

"$ADC" "$HUB4" --nick sida --sup ADHBRI --inf "I6::1" --dump \
	--linger 1 --expect ok >"$DIR/7a.log" 2>&1
SID_TOKEN=$(hbri_token_of "$DIR/7a.log")

"$ADC" "$HUB4" --nick sidb --dump --linger 4 --expect ok >"$DIR/7b.log" 2>&1 &
SIDB=$!
sleep 1
SIDA=$(printf "%s" "$SID_TOKEN" | cut -c1-4)
SIDB_SID=$(grep -oE "^LINE: BINF [A-Z2-7]{4} NIsidb" "$DIR/7b.log" | head -1 | awk "{print \$3}")

if [ -n "$SID_TOKEN" ] && [ "$SIDA" = "$SIDB_SID" ]; then
	ok "the departed user's SID was handed to the next user ($SIDA)"
	REPLY=$(hbri_replay "$SID_TOKEN")
	case "$REPLY" in
		*"ISTA 150"*) ok "a stale token does not validate for the SID's new holder" ;;
		*)            bad "stale token was not refused on a recycled SID: '$REPLY'" ;;
	esac
else
	bad "could not recycle the SID (token '$SIDA', new holder '$SIDB_SID')"
fi
wait "$SIDB"
if grep -qE "^LINE: BINF .*NIsidb.*I6" "$DIR/7b.log"; then
	bad "the replay put an address in the new holder's INF (see $DIR/7b.log)"; else
	ok "the new holder's INF gained no address from the replay"; fi

# 8. The same over TLS. probe.c demuxes the validation connection exactly as it
#    demuxes a login, so on a TLS hub that second connection must be encrypted
#    too -- a path nothing else in test/e2e covers, since every other script
#    turns TLS off. tls_require makes the point sharp: a plaintext validation
#    would be refused, so a validation that succeeds here was TLS.
stop_hub
if ! command -v openssl >/dev/null 2>&1; then
	echo "  SKIP: no openssl utility, not testing HBRI over TLS"
else
	openssl req -x509 -newkey ed25519 -keyout "$DIR/hub.key" -out "$DIR/hub.crt" \
		-days 3650 -nodes -subj "/CN=uhub" >/dev/null 2>&1
	if [ ! -s "$DIR/hub.key" ] || [ ! -s "$DIR/hub.crt" ]; then
		echo "  SKIP: could not create a test certificate, not testing HBRI over TLS"
	else
		write_conf "tls_enable = 1" "tls_require = 1" \
			"tls_certificate = $DIR/hub.crt" "tls_private_key = $DIR/hub.key"
		start_hub || exit 1

		# Control: the hub really is TLS-only, so anything that got through did so
		# over TLS.
		"$ADC" "$HUB4" --nick plaintls --linger 2 >"$DIR/6ctl.log" 2>&1
		if grep -q "logged_in=0" "$DIR/6ctl.log"; then
			ok "a plaintext client is refused by the TLS hub (control)"; else
			bad "plaintext login was not refused (see $DIR/6ctl.log)"; fi

		"$ADC" "adcs://127.0.0.1:$PORT" --nick tlsuser --sup ADHBRI --inf "I6::1" --hbri --dump \
			--linger 3 --expect ok >"$DIR/6.log" 2>&1
		if grep -q "^LINE: ITCP " "$DIR/6.log"; then
			ok "hub challenges a client over TLS"; else bad "no ITCP on the TLS hub (see $DIR/6.log)"; fi
		if grep -q "HBRI-VALIDATED.*(TLS)" "$DIR/6.log"; then
			ok "the validation connection completes over TLS"; else bad "TLS validation failed (see $DIR/6.log)"; fi
		if grep -qE "^LINE: BINF .*I6::1" "$DIR/6.log"; then
			ok "validated IPv6 is published on a TLS hub"; else bad "no I6 published on the TLS hub (see $DIR/6.log)"; fi
	fi
fi

echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
