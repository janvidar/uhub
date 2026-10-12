#!/usr/bin/env bash
#
# End-to-end test for http_redirect_addr: a web browser that opens the hub
# address is sent to the configured URL, over plain HTTP and HTTPS on the hub
# port, against a live uhub. Covers what the unit tests cannot -- the probe's
# handoff of the connection -- and checks that it gets in the way of neither
# the metrics endpoint nor an ADC login.
#
# Usage:  BUILD=/path/to/build  test/e2e/run_redirect_e2e.sh  [port]
# Requires: uhub and adc_cmd in the build dir, and curl.
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PORT=${1:-51061}

UHUB=$BUILD/uhub
ADC=$BUILD/adc_cmd

for bin in "$UHUB" "$ADC"; do
	[ -x "$bin" ] || { echo "MISSING: $bin (build it first)"; exit 2; }
done
command -v curl >/dev/null || { echo "MISSING: curl"; exit 2; }

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

# Plaintext and TLS on the same port, as the probe demultiplexes them.
cat > "$DIR/uhub.conf" <<EOF
server_port = $PORT
server_bind_addr = 127.0.0.1
plugin_defaults = no
tls_enable = 1
tls_certificate = $REPO/autotest/tls-test-cert.pem
tls_private_key = $REPO/autotest/tls-test-key.pem
metrics_enable = 1
metrics_token = s3cr3t
http_redirect_addr = https://www.example.com/hub
EOF

echo "== uhub HTTP redirect e2e (port $PORT, workdir $DIR) =="
start_hub || exit 1

# 1. a browser on the hub port is sent to the web site.
curl -s -o /dev/null -D "$DIR/http.hdr" --max-time 5 "http://127.0.0.1:$PORT/"
if grep -q "^HTTP/1.1 307" "$DIR/http.hdr" && grep -qi "^Location: https://www.example.com/hub" "$DIR/http.hdr"; then
	ok "HTTP request is redirected"; else bad "HTTP redirect (see $DIR/http.hdr)"; fi

# 2. ... over HTTPS on the same port as well.
curl -sk -o /dev/null -D "$DIR/https.hdr" --max-time 5 "https://127.0.0.1:$PORT/"
if grep -q "^HTTP/1.1 307" "$DIR/https.hdr"; then
	ok "HTTPS request is redirected"; else bad "HTTPS redirect (see $DIR/https.hdr)"; fi

# 3. the metrics endpoint is still there, and still wants its token.
code=$(curl -s -o "$DIR/metrics.txt" -w '%{http_code}' --max-time 5 -H "Authorization: Bearer s3cr3t" "http://127.0.0.1:$PORT/metrics")
nocode=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PORT/metrics")
if [ "$code" = 200 ] && grep -q "^uhub_" "$DIR/metrics.txt" && [ "$nocode" = 403 ]; then
	ok "metrics still served on its path"; else bad "metrics: got $code with token, $nocode without"; fi

# 4. ADC on the same port is unaffected, plain and over TLS.
if "$ADC" "adc://127.0.0.1:$PORT" --nick alice --expect ok --linger 1 >"$DIR/adc.log" 2>&1 \
	&& "$ADC" "adcs://127.0.0.1:$PORT" --nick bob --expect ok --linger 1 >"$DIR/adcs.log" 2>&1; then
	ok "ADC and ADCS logins still work"; else bad "ADC login (see $DIR/adc.log / $DIR/adcs.log)"; fi

echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
