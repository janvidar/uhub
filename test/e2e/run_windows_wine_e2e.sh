#!/usr/bin/env bash
#
# The Windows build, run under Wine and driven by the native adc_cmd. autotest
# does not build for Windows (it relies on POSIX socket semantics) and the CI
# windows job only checks that uhub.exe starts, so this is how the Winsock
# paths in src/network get exercised at all. Needs zig and wine; not run in CI.
#
# Checks the things that have gone wrong there:
#   1. an IPv4 client on a dual-stack listener keeps its address (it used to
#      come out as 0.0.0.0, through WSAAddressToStringA's "::ffff:" spelling);
#   2. an IPv6 listener reports its own address, not 0.0.0.0;
#   3. a socket error is reported as text, not as a bare Winsock number;
#   4. plain and TLS logins, and plugin DLLs loading.
#
# Usage:  BUILD=/path/to/native/build  test/e2e/run_windows_wine_e2e.sh  [port]
# BUILD must hold a native adc_cmd. The Windows build goes into a temp dir.
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PORT=${1:-51081}
ADC=$BUILD/adc_cmd

[ -x "$ADC" ] || { echo "MISSING: $ADC (build it first)"; exit 2; }
command -v zig  >/dev/null || { echo "MISSING: zig";  exit 2; }
command -v wine >/dev/null || { echo "MISSING: wine"; exit 2; }

DIR=$(mktemp -d)
pass=0; fail=0
export WINEDEBUG=-all

cleanup() {
	pkill -f "$DIR/" 2>/dev/null
	wait 2>/dev/null
	if [ -n "${KEEP:-}" ]; then echo "workdir kept: $DIR"; else rm -rf "$DIR"; fi
}
trap cleanup EXIT

ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }

# Start uhub.exe with a config and wait until it accepts connections.
start_hub() { # conf port
	(cd "$DIR" && timeout 60 wine bin/uhub.exe -c "$DIR/$1" >"$DIR/$1.log" 2>&1 &)
	local i
	for i in $(seq 1 100); do
		(exec 3<>"/dev/tcp/$3/$2") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
		sleep 0.2
	done
	echo "uhub.exe did not start ($1):"; cat "$DIR/$1.log"; return 1
}

echo "== uhub Windows build under Wine (port $PORT, workdir $DIR) =="
(cd "$REPO" && zig build -Dtarget=x86_64-windows-gnu --prefix "$DIR") >"$DIR/build.log" 2>&1 \
	|| { echo "zig build for Windows failed:"; tail -20 "$DIR/build.log"; exit 1; }
cp "$REPO/autotest/tls-test-cert.pem" "$REPO/autotest/tls-test-key.pem" "$DIR/"

# 1. + 4. dual-stack listener, TLS, a plugin DLL.
cat > "$DIR/ds.conf" <<EOF
server_port = $PORT
server_bind_addr = ::
plugin_defaults = no
file_plugins = $DIR/plugins.conf
tls_enable = 1
tls_certificate = $DIR/tls-test-cert.pem
tls_private_key = $DIR/tls-test-key.pem
EOF
printf 'plugin_dir %s/lib\nplugin mod_joins\n' "$DIR" > "$DIR/plugins.conf"
start_hub ds.conf "$PORT" 127.0.0.1 || exit 1

"$ADC" "adc://127.0.0.1:$PORT" --nick alice --send "!myip" --linger 2 --timeout 10 >"$DIR/v4.log" 2>&1
if grep -q 'Your address is "127.0.0.1"' "$DIR/v4.log"; then
	ok "IPv4 client on a dual-stack listener keeps its address"; else bad "IPv4 client address (see $DIR/v4.log)"; fi

"$ADC" "adcs://127.0.0.1:$PORT" --nick bob --linger 1 --timeout 10 >"$DIR/tls.log" 2>&1
if grep -q LOGGED_IN "$DIR/tls.log" && grep -q "Loaded plugin: .*mod_joins.dll" "$DIR/ds.conf.log"; then
	ok "TLS login, plugin DLL loaded"; else bad "TLS login / plugin (see $DIR/tls.log / $DIR/ds.conf.log)"; fi

# 2. IPv6 listener.
V6=$((PORT + 1))
printf 'server_port = %d\nserver_bind_addr = ::1\nplugin_defaults = no\ntls_enable = 0\n' "$V6" > "$DIR/v6.conf"
if start_hub v6.conf "$V6" "::1"; then
	if grep -q "listening on ::1:$V6" "$DIR/v6.conf.log"; then
		ok "IPv6 listener reports its address"; else bad "IPv6 listener address (see $DIR/v6.conf.log)"; fi
else
	bad "IPv6 listener did not start"
fi

# 3. a second hub on the same address cannot bind: the error must read as text.
cp "$DIR/v6.conf" "$DIR/dup.conf"
(cd "$DIR" && timeout 20 wine bin/uhub.exe -c "$DIR/dup.conf" >"$DIR/dup.log" 2>&1)
if grep -q "net_bind" "$DIR/dup.log" && ! grep -q "error code:" "$DIR/dup.log"; then
	ok "socket errors are reported as text"; else bad "socket error text (see $DIR/dup.log)"; fi

echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
