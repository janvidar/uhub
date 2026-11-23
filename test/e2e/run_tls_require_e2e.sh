#!/usr/bin/env bash
#
# End-to-end test for TLS by default (TODO "Retiring plain text", phase 1),
# against a live uhub:
#
#   1. with the defaults a plain-text ADC client is redirected to the hub's own
#      adcs:// address, keyprint included, and does not log in; ADCS works;
#   2. hub_address and tls_require_redirect_addr choose the redirect target,
#      and an adc:// hub_address is upgraded to adcs://;
#   3. tls_require = no admits plain-text clients again, with a startup warning;
#   4. the metrics endpoint answers plain HTTP from loopback only, HTTPS from
#      anywhere;
#   5. plain-text redirect targets are refused in the configuration, and an
#      http:// reg_server_url is refused at announce;
#   6. a hub that cannot create its certificate refuses to start (skipped when
#      the compiled-in state directory happens to be writable).
#
# Usage:  BUILD=/path/to/build  test/e2e/run_tls_require_e2e.sh  [port]
# Requires: uhub and adc_cmd in the build dir, curl and timeout.
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PORT=${1:-51101}

UHUB=$BUILD/uhub
ADC=$BUILD/adc_cmd
CERT=$REPO/autotest/tls-test-cert.pem
KEY=$REPO/autotest/tls-test-key.pem

for bin in "$UHUB" "$ADC"; do
	[ -x "$bin" ] || { echo "MISSING: $bin (build it first)"; exit 2; }
done
command -v curl >/dev/null || { echo "MISSING: curl"; exit 2; }
command -v timeout >/dev/null || { echo "MISSING: timeout"; exit 2; }

DIR=$(mktemp -d)
HUB_PID=""
pass=0; fail=0; skip=0

cleanup() {
	stop_hub
	if [ -n "${KEEP:-}" ]; then echo "workdir kept: $DIR"; else rm -rf "$DIR"; fi
}
trap cleanup EXIT

ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }
skipped() { echo "  SKIP: $1"; skip=$((skip+1)); }

stop_hub() {
	if [ -n "$HUB_PID" ]; then
		kill "$HUB_PID" 2>/dev/null
		wait "$HUB_PID" 2>/dev/null
		HUB_PID=""
	fi
}

# start_hub NAME: run $DIR/NAME.conf, log to $DIR/NAME.log.
start_hub() {
	stop_hub
	"$UHUB" -c "$DIR/$1.conf" >"$DIR/$1.log" 2>&1 &
	HUB_PID=$!
	local i
	for i in $(seq 1 50); do
		(exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
		kill -0 "$HUB_PID" 2>/dev/null || { echo "hub died on startup:"; cat "$DIR/$1.log"; HUB_PID=""; return 1; }
		sleep 0.1
	done
	echo "hub did not start listening:"; cat "$DIR/$1.log"; return 1
}

# write_conf NAME [extra lines...]: a TLS hub with the test certificate.
write_conf() {
	local name=$1; shift
	{
		echo "server_port = $PORT"
		echo "server_bind_addr = 0.0.0.0"
		echo "plugin_defaults = no"
		echo "tls_certificate = $CERT"
		echo "tls_private_key = $KEY"
		for line in "$@"; do echo "$line"; done
	} > "$DIR/$name.conf"
}

# plain_hello HOST: what a plain-text ADC client is told after its HSUP.
plain_hello() {
	timeout 3 bash -c "exec 3<>/dev/tcp/$1/$PORT; printf 'HSUP ADBASE ADTIGR\n' >&3; cat <&3" 2>/dev/null
}

# A non-loopback address of this host, to reach the hub as a remote peer would.
REMOTE=$(ip -4 -o addr show scope global 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4; exit}')

echo "== uhub TLS-required e2e (port $PORT, workdir $DIR) =="

# --- 1. defaults: plain text is redirected, ADCS logs in -------------------
write_conf defaults "metrics_enable = 1" "metrics_token = s3cr3t"
start_hub defaults || exit 1

plain_hello 127.0.0.1 > "$DIR/plain.txt"
if grep -q "^IQUI AAAB .*RDadcs://127.0.0.1:$PORT/?kp=SHA256/" "$DIR/plain.txt" \
	&& ! grep -q "^BINF\|^IINF .*CT32" "$DIR/plain.txt"; then
	ok "plain client redirected to the hub's own adcs:// address with its keyprint"
else
	bad "plain client redirect (see $DIR/plain.txt)"
fi

# Sent away before the login, the client never sees an error status either.
"$ADC" "adc://127.0.0.1:$PORT" --nick plain --timeout 5 >"$DIR/adc.log" 2>&1
if grep -q "RESULT: logged_in=0" "$DIR/adc.log"; then
	ok "plain client does not log in"; else bad "plain client logged in (see $DIR/adc.log)"; fi

if "$ADC" "adcs://127.0.0.1:$PORT" --nick secure --expect ok --linger 1 --timeout 10 >"$DIR/adcs.log" 2>&1; then
	ok "ADCS login works"; else bad "ADCS login (see $DIR/adcs.log)"; fi

if ! grep -q "TLS is optional\|TLS is off" "$DIR/defaults.log"; then
	ok "no plain-text warning with the defaults"; else bad "unexpected warning (see $DIR/defaults.log)"; fi

# --- 4. metrics: plain HTTP from loopback only -----------------------------
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Authorization: Bearer s3cr3t" "http://127.0.0.1:$PORT/metrics")
if [ "$code" = 200 ]; then ok "plain-text metrics from loopback"; else bad "plain metrics from loopback: $code"; fi

if [ -n "$REMOTE" ]; then
	code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Authorization: Bearer s3cr3t" "http://$REMOTE:$PORT/metrics")
	if [ "$code" = 403 ]; then ok "plain-text metrics from $REMOTE refused"; else bad "plain metrics from $REMOTE: $code"; fi
	code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 -H "Authorization: Bearer s3cr3t" "https://$REMOTE:$PORT/metrics")
	if [ "$code" = 200 ]; then ok "HTTPS metrics from $REMOTE"; else bad "HTTPS metrics from $REMOTE: $code"; fi
else
	skipped "no non-loopback IPv4 address to scrape from"
fi

# --- 2. the redirect target -------------------------------------------------
write_conf hubaddr "hub_address = adc://hub.example.org:$PORT"
start_hub hubaddr || exit 1
plain_hello 127.0.0.1 > "$DIR/hubaddr.txt"
if grep -q "RDadcs://hub.example.org:$PORT/?kp=SHA256/" "$DIR/hubaddr.txt"; then
	ok "an adc:// hub_address is redirected to as adcs://"; else bad "hub_address redirect (see $DIR/hubaddr.txt)"; fi

write_conf target "tls_require_redirect_addr = adcs://other.example.org:1511"
start_hub target || exit 1
plain_hello 127.0.0.1 > "$DIR/target.txt"
if grep -q "RDadcs://other.example.org:1511" "$DIR/target.txt"; then
	ok "tls_require_redirect_addr is the redirect target"; else bad "configured redirect (see $DIR/target.txt)"; fi

# --- 3. tls_require = no -----------------------------------------------------
write_conf optional "tls_require = no"
start_hub optional || exit 1
if "$ADC" "adc://127.0.0.1:$PORT" --nick plain --expect ok --linger 1 --timeout 10 >"$DIR/optional.adc.log" 2>&1; then
	ok "tls_require = no admits a plain client"; else bad "plain login with tls_require = no (see $DIR/optional.adc.log)"; fi
if grep -q "TLS is optional (tls_require=no)" "$DIR/optional.log"; then
	ok "tls_require = no warns at startup"; else bad "no startup warning (see $DIR/optional.log)"; fi

# --- 5. plain-text targets in the configuration ------------------------------
stop_hub
for bad_line in "http_redirect_addr = http://www.example.com/" "tls_require_redirect_addr = adc://other.example.org:1511"; do
	write_conf reject "$bad_line"
	if "$UHUB" -C -c "$DIR/reject.conf" >"$DIR/reject.log" 2>&1; then
		bad "accepted: $bad_line"; else ok "refused: $bad_line"; fi
done

write_conf regserver "reg_server_url = http://127.0.0.1:9/register" "hub_address = hub.example.org"
start_hub regserver || exit 1
sleep 0.5
if grep -q "refusing plain-text reg_server_url" "$DIR/regserver.log"; then
	ok "http:// reg_server_url refused"; else bad "reg_server_url (see $DIR/regserver.log)"; fi
stop_hub

# --- 6. no certificate, TLS required ----------------------------------------
{
	echo "server_port = $PORT"
	echo "server_bind_addr = 127.0.0.1"
	echo "plugin_defaults = no"
} > "$DIR/nocert.conf"
timeout 5 "$UHUB" -c "$DIR/nocert.conf" >"$DIR/nocert.log" 2>&1
status=$?
if grep -q "Unable to create a TLS certificate .* tls_require is on" "$DIR/nocert.log"; then
	if [ "$status" -ne 0 ] && [ "$status" -ne 124 ]; then
		ok "no certificate and TLS required: the hub refuses to start"
	else
		bad "certificate failure did not stop the hub (exit $status, see $DIR/nocert.log)"
	fi
else
	skipped "the hub could use its state directory, so certificate creation did not fail"
fi

echo "== result: $pass passed, $fail failed, $skip skipped =="
[ "$fail" -eq 0 ]
