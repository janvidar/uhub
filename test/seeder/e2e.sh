#!/usr/bin/env bash
#
# uhub-seeder end-to-end harness.
#
# Runs a real uhub and a real uhub-seeder against each other on loopback, in a
# throwaway directory under /tmp, and checks the things that only show up when
# two actual processes talk to each other. It is deliberately not a unit test:
# the bugs this is here to catch (who speaks first, which port is bound, what
# survives a crash) were all invisible to the autotests.
#
# Usage:  test/seeder/e2e.sh [build-directory]        (default: build-macasan)
#
#   KEEP=1 test/seeder/e2e.sh   leave the hub, the seeder and the scratch
#                               directory running afterwards, so a human can do
#                               the manual steps printed at the end.
#
# Individual binaries can be overridden when a single build tree does not have
# all of them (which is the normal state while the split is in progress):
#
#   UHUB_BIN, UHUB_PASSWD_BIN, UHUB_SEEDER_BIN, UHUB_PLUGIN_DIR
#
#
# WHAT IS AUTOMATED HERE
#
#   * a self-signed certificate with an IP SAN for 127.0.0.1
#   * a hub configuration on a free loopback port, TLS on, rich text on, with
#     mod_auth_sqlite and mod_logging loaded
#   * a ubot account registered with uhub-passwd, as doc/seedcache.txt requires
#   * both configurations accepted by their own -C config check
#   * the hub starting, binding, and completing a real ADCS handshake
#   * the seeder starting against that hub and listening on its own client port
#   * the seeder logging in and appearing on the hub (observed in the hub's own
#     login log, not in the seeder's)
#   * the seeder's transfer port completing a real TLS handshake and presenting
#     the certificate it was configured with -- clients require ADCS for
#     transfers, so a transfer port that cannot do it serves nobody
#   * the CSUP exchange running over that decrypted stream, and over a plain
#     connection to the same port
#   * CRASH ISOLATION: SIGKILL the seeder, and the hub is still alive, still
#     completes an ADCS handshake, and has dropped the seeder from its roster
#   * the seeder restarting on the same cache directory, with the cache intact
#
# WHAT IS NOT, AND CANNOT BE, AUTOMATED HERE
#
#   Posting a magnet embed into rich-text chat, and downloading the cached file
#   back out of the seeder, both need a real DC client. Nothing in this script
#   simulates either, and no check below pretends to cover them. The steps a
#   human has to do with QuickDC or DC++ are printed at the end of the run,
#   with the connect URL and the keyprint.
#
# Checks that depend on daemon features not yet wired into src/seeder/main.c
# report SKIP with the reason, rather than being deleted or reported as PASS.
#

set -u

# ---------------------------------------------------------------- configuration

SRC_DIR=$(cd -- "$(dirname -- "$0")/../.." && pwd)
BUILD_DIR=${1:-$SRC_DIR/build-macasan}
case "$BUILD_DIR" in
	/*) ;;
	*) BUILD_DIR=$SRC_DIR/$BUILD_DIR ;;
esac

SEED_NICK='[seed]cache'
SEED_PASS='e2e-seeder-password-not-a-secret'

# The hub and (in an ASan build) the seeder are noisy about leaks on exit; a
# leak is not what this harness is testing, and a leak report on shutdown would
# otherwise be reported as a crash.
export ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0}
export MallocNanoZone=${MallocNanoZone:-0}

# ---------------------------------------------------------------- result bookkeeping

PASSED=0
FAILED=0
SKIPPED=0
RESULTS=""

pass()  { PASSED=$((PASSED + 1)); printf 'PASS  %s\n' "$1"; RESULTS="$RESULTS
PASS  $1"; }
fail()  { FAILED=$((FAILED + 1)); printf 'FAIL  %s\n' "$1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; RESULTS="$RESULTS
FAIL  $1"; }
skip()  { SKIPPED=$((SKIPPED + 1)); printf 'SKIP  %s\n' "$1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; RESULTS="$RESULTS
SKIP  $1${2+ -- $2}"; }
info()  { printf '      %s\n' "$1"; }

# ---------------------------------------------------------------- scratch + teardown

WORK=$(mktemp -d /tmp/uhub-seeder-e2e.XXXXXXXX) || { echo "cannot create scratch directory"; exit 2; }
HUB_PID=""
SEEDER_PID=""

kill_pid()
{
	# $1 = pid, $2 = signal
	[ -n "${1:-}" ] || return 0
	kill -0 "$1" 2>/dev/null || return 0
	kill "-$2" "$1" 2>/dev/null
	local n=0
	while kill -0 "$1" 2>/dev/null && [ $n -lt 50 ]; do
		sleep 0.1
		n=$((n + 1))
	done
	kill -0 "$1" 2>/dev/null && return 1
	return 0
}

cleanup()
{
	local rc=$?
	if [ "${KEEP:-0}" = "1" ]; then
		echo
		echo "KEEP=1: leaving everything running."
		echo "  scratch dir : $WORK"
		echo "  hub pid     : ${HUB_PID:-<not running>}"
		echo "  seeder pid  : ${SEEDER_PID:-<not running>}"
		echo "  stop with   : kill ${HUB_PID:-} ${SEEDER_PID:-} ; rm -rf $WORK"
		exit $rc
	fi
	kill_pid "${SEEDER_PID:-}" TERM || kill_pid "${SEEDER_PID:-}" KILL
	kill_pid "${HUB_PID:-}" TERM || kill_pid "${HUB_PID:-}" KILL
	rm -rf "$WORK"
	exit $rc
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- small helpers

# Connect once to a TCP port. Returns 0 if something accepted the connection.
port_is_open()
{
	( exec 3<>"/dev/tcp/127.0.0.1/$1" ) >/dev/null 2>&1
}

# A loopback port nothing is listening on. Not race free -- nothing portable is
# -- but the daemons are started immediately afterwards and their startup is
# verified, so a lost race is reported as a failed start rather than silently
# testing the wrong thing.
free_port()
{
	local port n=0
	while [ $n -lt 200 ]; do
		port=$(( 20000 + (RANDOM % 20000) ))
		if ! port_is_open "$port"; then
			echo "$port"
			return 0
		fi
		n=$((n + 1))
	done
	echo "no free loopback port found" >&2
	return 1
}

# wait_for <seconds> <shell condition...>  -- polls every 100ms
wait_for()
{
	local secs=$1; shift
	local deadline=$(( secs * 10 ))
	local n=0
	while [ $n -lt $deadline ]; do
		if "$@"; then return 0; fi
		sleep 0.1
		n=$((n + 1))
	done
	return 1
}

log_has() { grep -q -- "$2" "$1" 2>/dev/null; }

tail_logs()
{
	echo "--- tail of $WORK/hub.log"
	tail -n 25 "$WORK/hub.log" 2>/dev/null || echo "(no hub log)"
	echo "--- tail of $WORK/seeder.log"
	tail -n 25 "$WORK/seeder.log" 2>/dev/null || echo "(no seeder log)"
	echo "---"
}

# Speak enough ADC over TLS to prove the hub is really serving, not merely
# holding a listening socket open. A hub that answers this has run its TLS
# handshake, parsed an HSUP and allocated a SID.
#
# HSUP comes from a file rather than a pipe so that s_client is a single process
# with a single pid to kill: it does not close the connection when its stdin
# ends, and the hub keeps a half-logged-in client for its full login timeout, so
# something has to end the conversation once the answer has arrived.
hub_answers_adc()
{
	local out="$WORK/adc-probe.out"

	printf 'HSUP ADBASE ADTIGR\n' > "$WORK/adc-probe.in"
	: > "$out"
	openssl s_client -quiet -connect "127.0.0.1:$HUB_PORT" \
		< "$WORK/adc-probe.in" > "$out" 2>"$WORK/adc-probe.err" &
	local pid=$!

	local n=0
	while [ $n -lt 100 ]; do
		grep -q 'ISID' "$out" 2>/dev/null && break
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
		n=$((n + 1))
	done
	kill -9 "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null

	grep -q 'ISID' "$out" 2>/dev/null
}

# ---------------------------------------------------------------- checks

BIN_UHUB=""
BIN_PASSWD=""
BIN_SEEDER=""
PLUGIN_DIR=""

check_binaries()
{
	local name="binaries present in the build tree"
	local missing=""

	BIN_UHUB=${UHUB_BIN:-$BUILD_DIR/uhub}
	BIN_PASSWD=${UHUB_PASSWD_BIN:-$BUILD_DIR/uhub-passwd}
	BIN_SEEDER=${UHUB_SEEDER_BIN:-$BUILD_DIR/uhub-seeder}
	PLUGIN_DIR=${UHUB_PLUGIN_DIR:-$BUILD_DIR}

	[ -x "$BIN_UHUB" ]   || missing="$missing $BIN_UHUB"
	[ -x "$BIN_PASSWD" ] || missing="$missing $BIN_PASSWD"
	[ -x "$BIN_SEEDER" ] || missing="$missing $BIN_SEEDER"
	[ -f "$PLUGIN_DIR/mod_auth_sqlite.so" ] || missing="$missing $PLUGIN_DIR/mod_auth_sqlite.so"
	[ -f "$PLUGIN_DIR/mod_logging.so" ]     || missing="$missing $PLUGIN_DIR/mod_logging.so"

	if [ -n "$missing" ]; then
		fail "$name" "missing:$missing"
		echo
		echo "Build them with, for example:"
		echo "  cmake -S $SRC_DIR -B $BUILD_DIR && \\"
		echo "  make -C $BUILD_DIR uhub uhub-passwd uhub-seeder mod_auth_sqlite mod_logging"
		echo "Or point UHUB_BIN / UHUB_PASSWD_BIN / UHUB_SEEDER_BIN / UHUB_PLUGIN_DIR at"
		echo "whichever tree has each one."
		return 1
	fi

	pass "$name"
	info "uhub        $BIN_UHUB ($("$BIN_UHUB" -V 2>&1 | head -n 1))"
	info "uhub-seeder $BIN_SEEDER ($("$BIN_SEEDER" -V 2>&1 | head -n 1))"
	return 0
}

check_certificate()
{
	local name="self-signed certificate with an IP SAN for 127.0.0.1"

	cat > "$WORK/openssl.cnf" <<-EOF
	[req]
	distinguished_name = dn
	x509_extensions = v3
	prompt = no
	[dn]
	CN = 127.0.0.1
	[v3]
	subjectAltName = IP:127.0.0.1, DNS:localhost
	basicConstraints = critical, CA:false
	EOF

	if ! openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
		-keyout "$WORK/server.key" -out "$WORK/server.crt" \
		-config "$WORK/openssl.cnf" -extensions v3 >"$WORK/openssl.out" 2>&1
	then
		fail "$name" "openssl req failed; see $WORK/openssl.out"
		return 1
	fi

	if ! openssl x509 -in "$WORK/server.crt" -noout -text 2>/dev/null | grep -q 'IP Address:127.0.0.1'; then
		fail "$name" "the generated certificate has no IP:127.0.0.1 SAN"
		return 1
	fi

	# ADC keyprint: base32 of the SHA-256 of the DER certificate. The hub prints
	# the same string on startup; this is only a fallback for the manual steps.
	KEYPRINT=$(openssl x509 -in "$WORK/server.crt" -outform DER 2>/dev/null \
		| openssl dgst -sha256 -binary 2>/dev/null \
		| { base32 2>/dev/null || python3 -c 'import base64,sys; sys.stdout.write(base64.b32encode(sys.stdin.buffer.read()).decode())' 2>/dev/null; } \
		| tr -d '=\n')

	pass "$name"
	return 0
}

check_register_bot()
{
	local name="ubot account registered with uhub-passwd"

	if ! "$BIN_PASSWD" "$WORK/users.db" create >"$WORK/passwd.out" 2>&1; then
		fail "$name" "uhub-passwd create failed; see $WORK/passwd.out"
		return 1
	fi
	if ! "$BIN_PASSWD" "$WORK/users.db" add "$SEED_NICK" "$SEED_PASS" ubot >>"$WORK/passwd.out" 2>&1; then
		fail "$name" "uhub-passwd add failed; see $WORK/passwd.out"
		return 1
	fi

	# doc/seedcache.txt is specific about this: ubot, not bot, because
	# auth_cred_is_unrestricted is what keeps a busy seeder out of flood control.
	if ! "$BIN_PASSWD" "$WORK/users.db" list 2>/dev/null | grep -qF "$(printf 'ubot\t%s' "$SEED_NICK")"; then
		fail "$name" "the account is not listed as ubot"
		"$BIN_PASSWD" "$WORK/users.db" list 2>&1 | sed 's/^/        /'
		return 1
	fi

	pass "$name"
	return 0
}

write_configs()
{
	cat > "$WORK/plugins.conf" <<-EOF
	# Credentials for the seeder's bot account. bot/ubot are not accepted in
	# users.conf, so the account has to come from an auth plugin.
	plugin $PLUGIN_DIR/mod_auth_sqlite.so "file=$WORK/users.db"

	# Login/logout events, so the harness can see the seeder arrive from the
	# hub's side rather than believing the seeder's own log.
	plugin $PLUGIN_DIR/mod_logging.so "file=$WORK/hub-events.log"
	EOF

	cat > "$WORK/uhub.conf" <<-EOF
	server_port = $HUB_PORT
	server_bind_addr = 127.0.0.1
	hub_name = uhub-seeder e2e
	hub_description = end-to-end harness
	max_users = 20

	# The seeder only sees magnet embeds in rich text messages.
	chat_rich_text = yes

	# Real clients insist on ADCS for transfers.
	tls_enable = 1
	tls_require = 0
	tls_certificate = $WORK/server.crt
	tls_private_key = $WORK/server.key

	file_plugins = $WORK/plugins.conf
	EOF

	mkdir -p "$WORK/cache"
	write_seeder_config
}

# The URL is written in the form doc/seedcache.txt tells operators to use --
# scheme, host, port and a trailing slash. If that does not work, the harness
# retries without the slash and says so, rather than quietly using whichever
# form happens to work.
SEED_HUB_URL="" # set in main

write_seeder_config()
{
	cat > "$WORK/uhub-seeder.conf" <<-EOF
	seed_hub_url      = "$SEED_HUB_URL"
	seed_nick         = "$SEED_NICK"
	seed_password     = "$SEED_PASS"
	seed_description  = "e2e seed cache"

	seed_client_port      = $SEED_PORT
	seed_client_bind_addr = "127.0.0.1"

	# Transfers are ADCS or nothing as far as real clients are concerned. The
	# hub's own pair is reused deliberately: nothing verifies the seeder's
	# certificate -- the peer is identified by the CID in its CINF -- so a
	# self-signed pair, shared or not, is what an operator would use.
	seed_tls_certificate  = "$WORK/server.crt"
	seed_tls_private_key  = "$WORK/server.key"

	seed_cache_dir     = "$WORK/cache"
	seed_cache_size    = 16
	seed_max_file_size = 2
	seed_max_entries   = 64
	seed_entry_ttl     = 3600
	EOF
}

check_hub_config_valid()
{
	local name="hub configuration accepted by uhub -C"
	if "$BIN_UHUB" -C -c "$WORK/uhub.conf" >"$WORK/hub-check.out" 2>&1 \
		&& grep -q '^OK$' "$WORK/hub-check.out"; then
		pass "$name"
		return 0
	fi
	fail "$name" "see $WORK/hub-check.out"
	sed 's/^/        /' "$WORK/hub-check.out"
	return 1
}

check_seeder_config_valid()
{
	local name="seeder configuration accepted by uhub-seeder -C"
	if "$BIN_SEEDER" -C -c "$WORK/uhub-seeder.conf" >"$WORK/seeder-check.out" 2>&1 \
		&& grep -q '^OK$' "$WORK/seeder-check.out"; then
		pass "$name"
		return 0
	fi
	fail "$name" "see $WORK/seeder-check.out"
	sed 's/^/        /' "$WORK/seeder-check.out"
	return 1
}

start_hub()
{
	"$BIN_UHUB" -c "$WORK/uhub.conf" -l "$WORK/hub.log" -v -v >"$WORK/hub.stdout" 2>&1 &
	HUB_PID=$!
}

check_hub_starts()
{
	local name="hub starts and binds 127.0.0.1:$HUB_PORT"
	start_hub

	if ! wait_for 20 port_is_open "$HUB_PORT"; then
		fail "$name" "nothing accepted a connection on port $HUB_PORT within 20s"
		tail_logs
		return 1
	fi
	if ! log_has "$WORK/hub.log" "listening on 127.0.0.1:$HUB_PORT"; then
		fail "$name" "the port is open but the hub never logged that it was listening"
		tail_logs
		return 1
	fi
	pass "$name"

	# The hub prints the canonical connect URL, keyprint included. Keep it for
	# the manual steps; it is more authoritative than computing it here.
	CONNECT_URL=$(sed -n 's/.*Connect address: //p' "$WORK/hub.log" | head -n 1)
	[ -n "$CONNECT_URL" ] || CONNECT_URL="adcs://127.0.0.1:$HUB_PORT/?kp=SHA256/${KEYPRINT:-<unknown>}"
	return 0
}

check_hub_serves_adc()
{
	local name="hub completes an ADCS handshake (TLS + HSUP -> ISID)"
	if hub_answers_adc; then
		pass "$name"
		return 0
	fi
	fail "$name" "no ISID in the reply to HSUP over TLS"
	tail_logs
	return 1
}

start_seeder()
{
	"$BIN_SEEDER" -c "$WORK/uhub-seeder.conf" -l "$WORK/seeder.log" -v -v >"$WORK/seeder.stdout" 2>&1 &
	SEEDER_PID=$!
}

check_seeder_starts()
{
	local name="seeder starts against the hub"
	: > "$WORK/seeder.log"
	start_seeder

	if ! wait_for 20 log_has "$WORK/seeder.log" "uhub-seeder started"; then
		fail "$name" "the seeder did not report a successful start within 20s"
		tail_logs
		return 1
	fi
	if ! kill -0 "$SEEDER_PID" 2>/dev/null; then
		fail "$name" "the seeder exited immediately after starting"
		tail_logs
		return 1
	fi
	pass "$name"
	return 0
}

# Does this uhub-seeder build actually do anything once started? At the time of
# writing, src/seeder/main.c is still the process skeleton: config, signals and
# the reactor loop, with the cache, the hub connection and the client listener
# left as TODO markers. Everything below that needs one of those is skipped
# rather than failed, but the decision is made by observing the running daemon,
# not by assuming.
SEEDER_WIRED=unknown

probe_seeder_wiring()
{
	SEEDER_WIRED=no
	if wait_for 15 port_is_open "$SEED_PORT"; then
		SEEDER_WIRED=yes
		return
	fi
	# Every module the daemon is missing logs with a "seeder: " prefix
	# (hubconn.c, cc.c, cache.c). One such line means main() reached them.
	if grep -q 'seeder: ' "$WORK/seeder.log" 2>/dev/null; then
		SEEDER_WIRED=yes
	fi
}

UNWIRED_REASON='src/seeder/main.c is still the skeleton: the cache, the hub connection and the client listener are TODO markers in main_loop(), so the daemon starts and idles'

check_seeder_client_port()
{
	local name="seeder listens for transfers on 127.0.0.1:$SEED_PORT"
	if [ "$SEEDER_WIRED" = "no" ]; then
		skip "$name" "$UNWIRED_REASON"
		return 0
	fi
	if port_is_open "$SEED_PORT"; then
		pass "$name"
		return 0
	fi
	fail "$name" "nothing is listening on the configured seed_client_port"
	return 1
}

check_seeder_logged_in()
{
	local name="seeder logs in and appears on the hub"
	if [ "$SEEDER_WIRED" = "no" ]; then
		skip "$name" "$UNWIRED_REASON"
		return 0
	fi
	if wait_for 40 seeder_logged_in; then
		pass "$name"
		info "hub: $(grep 'LoginOK' "$WORK/hub-events.log" | head -n 1)"
		grep -q 'seeder: logged in' "$WORK/seeder.log" 2>/dev/null \
			&& info "seeder: $(sed -n 's/.*seeder: \(logged in.*\)/\1/p' "$WORK/seeder.log" | head -n 1)"
		return 0
	fi

	# It did not log in with the URL written the way doc/seedcache.txt writes it.
	# Before reporting that, find out whether the URL itself is the problem: a
	# trailing slash is part of the documented form, and if dropping it fixes the
	# login then the bug is in the URL parsing, not in the login.
	case "$SEED_HUB_URL" in
	*/)
		local retry_url=${SEED_HUB_URL%/}
		info "no login yet; retrying with seed_hub_url = \"$retry_url\" to tell a URL-parsing problem from a login problem"
		kill_pid "$SEEDER_PID" TERM || kill_pid "$SEEDER_PID" KILL
		SEEDER_PID=""
		SEED_HUB_URL=$retry_url
		write_seeder_config
		: > "$WORK/seeder.log"
		start_seeder
		if wait_for 40 seeder_logged_in; then
			fail "$name" "the seeder logs in only when the trailing slash is removed from seed_hub_url"
			info "\"${retry_url}/\" is the form doc/seedcache.txt section 3.2 tells operators to write, and it never connects:"
			info "  ADC_client_parse_address() in src/tools/adcclient.c takes everything after the last ':' as the port"
			info "  and rejects it when it is longer than 6 characters, so \":$HUB_PORT/\" fails while \":$HUB_PORT\" works."
			info "  A 4-digit port hides it: \":1511/\" is exactly 6 characters, which is why the documented example works."
			info "The rest of this run continues with the slash removed."
			return 1
		fi
		;;
	esac

	fail "$name" "the hub logged no successful login for $SEED_NICK"
	tail_logs
	return 1
}

seeder_logged_in()
{
	grep -F "$SEED_NICK" "$WORK/hub-events.log" 2>/dev/null | grep -q 'LoginOK'
}

# --- the SU field -------------------------------------------------------------
#
# SU is what makes the seeder usable at all. Without TCP4 every client reads it
# as passive and never dials it, so it serves nobody -- and serving passive
# users is the only reason it exists. Without ADCS no client offers an encrypted
# transfer, which leaves the certificate configured above doing nothing.
#
# What this checks is the wiring: that the value is derived from the certificate
# and the bound listener at runtime, and not hardcoded. That the field actually
# lands in the INF is asserted on the wire by seedhub_support_reaches_the_inf in
# autotest/test_seedhub.tcc -- observing it from the hub here would need a full
# ADC login with a valid CID/PID pair, which is not a shell script's job.
check_seeder_advertises_support()
{
	local name="seeder advertises TCP4 and ADCS"
	local su

	if [ "$SEEDER_WIRED" = "no" ]; then
		skip "$name" "$UNWIRED_REASON"
		return 0
	fi

	su=$(sed -n 's/.*seeder: advertising SU=\([A-Za-z0-9,]*\).*/\1/p' "$WORK/seeder.log" 2>/dev/null | head -n 1)

	if [ -z "$su" ]; then
		fail "$name" "the seeder logged no SU advertisement, so its INF claims nothing"
		info "a seeder without TCP4 in SU is treated as passive and never dialled"
		return 1
	fi

	case "$su" in
	*TCP4*) ;;
	*)
		fail "$name" "SU is \"$su\", which does not claim TCP4"
		return 1
		;;
	esac

	# The config written by write_seeder_config always carries a certificate, so
	# ADC0 must be claimed here. If it is not, seeder_advertise_support() is not
	# seeing the TLS context that check_seeder_serves_adcs proves is loaded.
	# ADCS, not the older ADC0: peers are understood either way, but this end
	# sends the current spelling.
	case "$su" in
	*ADCS*) ;;
	*)
		fail "$name" "SU is \"$su\": the transfer port has a certificate but ADCS is not claimed"
		return 1
		;;
	esac

	pass "$name"
	info "seeder: SU=$su"
	return 0
}

# --- the transfer port: ADCS, and plain ADC, on the same socket ---------------
#
# This is the check that the feature exists at all. A passive client -- the
# entire reason to run a seeder -- asks for ADCS/0.10 and will not fall back, so
# a transfer port that cannot complete a TLS handshake serves nobody, and the
# grant token and the file would cross the wire in the clear even for the
# clients that would tolerate it.

# Complete a handshake and keep whatever the peer presented. Backgrounded with a
# watchdog for the same reason hub_answers_adc() is: s_client is given a pid so
# a server that never answers cannot hang the run.
seeder_tls_handshake()
{
	local out=$1
	: > "$out"
	openssl s_client -showcerts -connect "127.0.0.1:$SEED_PORT" \
		</dev/null > "$out" 2>&1 &
	local pid=$!

	local n=0
	while [ $n -lt 100 ] && kill -0 "$pid" 2>/dev/null; do
		sleep 0.1
		n=$((n + 1))
	done
	kill -9 "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null

	grep -q 'BEGIN CERTIFICATE' "$out" 2>/dev/null
}

check_seeder_serves_adcs()
{
	local name="seeder transfer port completes a TLS handshake and presents its certificate"
	local out="$WORK/seed-tls.out"

	if [ "$SEEDER_WIRED" = "no" ]; then
		skip "$name" "$UNWIRED_REASON"
		return 0
	fi

	if ! seeder_tls_handshake "$out"; then
		fail "$name" "no TLS handshake on the transfer port; see $out"
		sed 's/^/        /' "$out" | head -n 15
		tail_logs
		return 1
	fi

	# It has to be the configured certificate, not merely some certificate.
	local want got
	want=$(openssl x509 -in "$WORK/server.crt" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//')
	got=$(openssl x509 -in "$out" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//')
	if [ -z "$want" ] || [ "$want" != "$got" ]; then
		fail "$name" "the certificate presented is not the one in seed_tls_certificate"
		info "configured: ${want:-<none>}"
		info "presented : ${got:-<none>}"
		return 1
	fi

	pass "$name"
	info "$(sed -n 's/^ *Protocol *: /TLS protocol /p' "$out" | head -n 1)"
	return 0
}

# Speak ADC over that handshake. A port that completes TLS but then does
# nothing with the decrypted bytes is the failure mode of getting the probe
# ordering wrong, and it looks identical from the outside until this runs.
check_seeder_adcs_speaks_adc()
{
	local name="seeder answers CSUP with CSUP/CINF over ADCS"
	local out="$WORK/seed-adcs-adc.out"

	if [ "$SEEDER_WIRED" = "no" ]; then
		skip "$name" "$UNWIRED_REASON"
		return 0
	fi

	printf 'CSUP ADBASE ADTIGR\n' > "$WORK/seed-adcs-adc.in"
	: > "$out"
	openssl s_client -quiet -connect "127.0.0.1:$SEED_PORT" \
		< "$WORK/seed-adcs-adc.in" > "$out" 2>"$WORK/seed-adcs-adc.err" &
	local pid=$!

	local n=0
	while [ $n -lt 100 ]; do
		grep -q 'CINF' "$out" 2>/dev/null && break
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
		n=$((n + 1))
	done
	kill -9 "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null

	if ! grep -q 'CSUP' "$out" 2>/dev/null; then
		fail "$name" "the handshake completed but no CSUP came back; see $out"
		tail_logs
		return 1
	fi
	# The side that was connected to sends its CINF first, without waiting.
	if ! grep -q 'CINF' "$out" 2>/dev/null; then
		fail "$name" "CSUP came back but the seeder's CINF did not follow it"
		sed 's/^/        /' "$out" | head -n 5
		return 1
	fi

	pass "$name"
	return 0
}

# The same port still serves an unencrypted client, which is what makes this a
# probe rather than a switch.
check_seeder_plain_still_works()
{
	local name="seeder still answers plain ADC on the same port"
	local out="$WORK/seed-plain.out"

	if [ "$SEEDER_WIRED" = "no" ]; then
		skip "$name" "$UNWIRED_REASON"
		return 0
	fi

	: > "$out"
	if ! exec 3<>"/dev/tcp/127.0.0.1/$SEED_PORT" 2>/dev/null; then
		fail "$name" "could not connect to the transfer port"
		return 1
	fi

	printf 'CSUP ADBASE ADTIGR\n' >&3

	local line n=0
	while [ $n -lt 20 ]; do
		IFS= read -r -t 2 line <&3 || break
		printf '%s\n' "$line" >> "$out"
		grep -q 'CINF' "$out" 2>/dev/null && break
		n=$((n + 1))
	done
	exec 3<&- 3>&-

	if grep -q 'CSUP' "$out" 2>/dev/null && grep -q 'CINF' "$out" 2>/dev/null; then
		pass "$name"
		return 0
	fi
	fail "$name" "no CSUP/CINF on a plaintext connection; see $out"
	sed 's/^/        /' "$out" | head -n 5
	tail_logs
	return 1
}

# The whole justification for running the seeder as its own process.
check_crash_isolation()
{
	local name="CRASH ISOLATION: SIGKILL on the seeder does not disturb the hub"

	if [ -z "$SEEDER_PID" ] || ! kill -0 "$SEEDER_PID" 2>/dev/null; then
		fail "$name" "the seeder was not running, so there was nothing to kill"
		return 1
	fi
	if ! kill -0 "$HUB_PID" 2>/dev/null; then
		fail "$name" "the hub was already dead before the seeder was killed"
		return 1
	fi

	local hub_log_size_before was_logged_in=no
	hub_log_size_before=$(wc -c < "$WORK/hub.log")
	seeder_logged_in && was_logged_in=yes

	kill -9 "$SEEDER_PID" 2>/dev/null
	if ! wait_for 10 sh -c "! kill -0 $SEEDER_PID 2>/dev/null"; then
		fail "$name" "the seeder survived SIGKILL (pid $SEEDER_PID)"
		return 1
	fi
	wait "$SEEDER_PID" 2>/dev/null
	local dead_pid=$SEEDER_PID
	SEEDER_PID=""

	# Give the hub a moment to notice the peer disappear, then check it is not
	# merely alive but still serving.
	sleep 1

	local ok=0
	if ! kill -0 "$HUB_PID" 2>/dev/null; then
		fail "$name" "the hub died when the seeder was killed (pid $dead_pid)"
		tail_logs
		return 1
	fi
	if ! port_is_open "$HUB_PORT"; then
		fail "$name" "the hub process is alive but no longer accepts connections"
		tail_logs
		return 1
	fi
	if ! hub_answers_adc; then
		fail "$name" "the hub accepts connections but no longer completes an ADCS handshake"
		tail_logs
		return 1
	fi
	if tail -c "+$((hub_log_size_before + 1))" "$WORK/hub.log" | grep -qiE 'AddressSanitizer|SEGV|assert|FATAL'; then
		fail "$name" "the hub logged an error after the seeder was killed"
		tail -c "+$((hub_log_size_before + 1))" "$WORK/hub.log" | sed 's/^/        /'
		return 1
	fi
	# A hub that survives but keeps the dead client in its user list has not
	# really handled the crash.
	if [ "$was_logged_in" = "yes" ]; then
		seeder_logged_out() { grep -F "$SEED_NICK" "$WORK/hub-events.log" 2>/dev/null | grep -q 'Logout'; }
		if ! wait_for 15 seeder_logged_out; then
			fail "$name" "the hub is fine, but never dropped $SEED_NICK from the user list"
			sed 's/^/        /' "$WORK/hub-events.log"
			return 1
		fi
	fi

	pass "$name"
	info "hub still answered HSUP with an ISID after the seeder was SIGKILLed"
	return $ok
}

cache_fingerprint()
{
	# Sorted list of every regular file under the cache with its size. Not a
	# checksum of contents -- the point is that entries are not lost, and a
	# sqlite WAL checkpoint may legitimately rewrite bytes.
	( cd "$WORK/cache" 2>/dev/null && find . -type f ! -name '*.db-wal' ! -name '*.db-shm' -exec ls -ld {} \; 2>/dev/null \
		| awk '{print $5, $NF}' | sort ) 2>/dev/null
}

check_seeder_restarts()
{
	local name="seeder restarts after being SIGKILLed"
	CACHE_BEFORE=$(cache_fingerprint)

	: > "$WORK/seeder.log"
	start_seeder
	if ! wait_for 20 log_has "$WORK/seeder.log" "uhub-seeder started"; then
		fail "$name" "the seeder did not come back up within 20s"
		tail_logs
		return 1
	fi
	if ! kill -0 "$SEEDER_PID" 2>/dev/null; then
		fail "$name" "the restarted seeder exited immediately"
		tail_logs
		return 1
	fi
	pass "$name"
	return 0
}

check_cache_survives_restart()
{
	local name="cache survives the crash and restart"

	if [ ! -d "$WORK/cache" ]; then
		fail "$name" "the cache directory is gone"
		return 1
	fi

	if [ -z "$CACHE_BEFORE" ]; then
		skip "$name" "the cache is empty, so nothing could be shown to survive: the seeder does not open or populate it yet ($UNWIRED_REASON). Populating it needs a real client to post a magnet embed -- see the manual steps below."
		return 0
	fi

	# Let a restarted seeder finish its startup sweep of data/ before looking.
	sleep 1
	local after
	after=$(cache_fingerprint)
	if [ "$after" = "$CACHE_BEFORE" ]; then
		pass "$name"
		info "$(printf '%s' "$CACHE_BEFORE" | grep -c . ) file(s) intact across SIGKILL + restart"
		return 0
	fi
	fail "$name" "the cache differs after the restart"
	printf '        before: %s\n' "$CACHE_BEFORE"
	printf '        after : %s\n' "$after"
	return 1
}

check_hub_still_healthy()
{
	local name="hub survived the whole run"
	if ! kill -0 "$HUB_PID" 2>/dev/null; then
		fail "$name" "the hub is no longer running"
		tail_logs
		return 1
	fi
	if grep -qiE 'AddressSanitizer|SEGV|Segmentation' "$WORK/hub.log" "$WORK/hub.stdout" 2>/dev/null; then
		fail "$name" "the hub log contains a sanitizer or crash report"
		grep -iE 'AddressSanitizer|SEGV|Segmentation' "$WORK/hub.log" "$WORK/hub.stdout" 2>/dev/null | sed 's/^/        /'
		return 1
	fi
	pass "$name"
	return 0
}

# ---------------------------------------------------------------- manual steps

print_manual_steps()
{
	cat <<-EOF

	================================================================
	MANUAL STEPS REMAINING (not automated, and not attempted above)
	================================================================

	Everything above is process-level: the two daemons, the hub connection and
	the crash isolation. The content path -- a magnet embed being posted,
	ingested, hashed and served back -- needs a real DC client, so it is not
	covered by any check in this script and nothing here simulates it.

	To finish the verification by hand, run:

	    KEEP=1 $0 $BUILD_DIR

	which leaves the hub and the seeder running, then:

	 1. Connect a DC client (QuickDC, DC++, AirDC++) to

	        $CONNECT_URL

	    The certificate is self-signed, so the keyprint in that URL is what
	    makes the client accept it. Do not strip it.

	 2. Confirm the seeder is in the user list as "$SEED_NICK".
	    In the hub's event log: grep LoginOK $WORK/hub-events.log

	 3. Take a small PNG (under 2 MiB -- seed_max_file_size), share it from the
	    client, and copy its magnet link ("Copy magnet link" in most clients).
	    Post it into main chat in CommonMark link syntax, so the hub relays it
	    as rich text:

	        ![shot.png](magnet:?xt=urn:tree:tiger:<39 char TTH>&xl=<size>&dn=shot.png)

	 4. Watch $WORK/seeder.log. A successful ingest ends in a line naming the
	    TTH, the size and the detected media type. A failure is logged with a
	    reason -- a hash mismatch prints both the announced and the computed
	    TTH, a refused type prints the type that was detected.
	    The client-to-client lines are logged as they go over the wire; check
	    the order against doc/seedcache.txt section 5.2 (the dialler sends CSUP
	    first, the side that was connected to sends its CINF first).

	 5. From a *second* client -- and ideally a passive one, since serving
	    passive clients is the reason the seeder exists -- search for that TTH
	    (paste the magnet into the search box). The result should be attributed
	    to "$SEED_NICK". Download it, and check the file is byte-identical to
	    the one you posted.

	 6. Disconnect the first client entirely, then repeat step 5. The download
	    still working with the poster gone is the whole feature.

	 7. As an operator, private-message the bot:
	        stats           -- size, entries, pinned, ingests, blocked, degraded
	        list            -- what is cached
	        info <tth>      -- provenance: nick, CID, address, first seen
	        block <tth>     -- delete and refuse to cache it again
	    A non-operator sending the same commands must get nothing but a refusal.

	Files from this run:
	    hub config      $WORK/uhub.conf
	    seeder config   $WORK/uhub-seeder.conf
	    hub log         $WORK/hub.log
	    hub events      $WORK/hub-events.log
	    seeder log      $WORK/seeder.log
	    cache           $WORK/cache
	EOF
}

# ---------------------------------------------------------------- main

echo "uhub-seeder end-to-end harness"
echo "  source     : $SRC_DIR"
echo "  build      : $BUILD_DIR"
echo "  scratch    : $WORK"
echo

check_binaries || { echo; echo "SUMMARY: FAIL (cannot run without the binaries)"; exit 2; }

HUB_PORT=$(free_port)  || exit 2
SEED_PORT=$(free_port) || exit 2
while [ "$SEED_PORT" = "$HUB_PORT" ]; do SEED_PORT=$(free_port) || exit 2; done
info "hub port $HUB_PORT, seeder client port $SEED_PORT"
echo

KEYPRINT=""
CONNECT_URL="adcs://127.0.0.1:$HUB_PORT/"
CACHE_BEFORE=""
SEED_HUB_URL="adcs://127.0.0.1:$HUB_PORT/"

check_certificate
check_register_bot
write_configs
check_hub_config_valid
check_seeder_config_valid

if check_hub_starts; then
	check_hub_serves_adc

	if check_seeder_starts; then
		probe_seeder_wiring
		check_seeder_client_port
		check_seeder_logged_in
		check_seeder_advertises_support
		check_seeder_serves_adcs
		check_seeder_adcs_speaks_adc
		check_seeder_plain_still_works
		check_crash_isolation
		check_seeder_restarts
		check_cache_survives_restart
	else
		skip "seeder listens for transfers"       "the seeder would not start"
		skip "seeder logs in and appears on hub"  "the seeder would not start"
		skip "seeder advertises TCP4 and ADCS"    "the seeder would not start"
		skip "seeder transfer port serves ADCS"   "the seeder would not start"
		skip "seeder answers CSUP over ADCS"      "the seeder would not start"
		skip "seeder answers plain ADC"           "the seeder would not start"
		skip "CRASH ISOLATION"                    "the seeder would not start"
		skip "seeder restarts after SIGKILL"      "the seeder would not start"
		skip "cache survives the crash"           "the seeder would not start"
	fi

	check_hub_still_healthy
else
	skip "hub completes an ADCS handshake"    "the hub would not start"
	skip "seeder starts against the hub"      "the hub would not start"
	skip "seeder listens for transfers"       "the hub would not start"
	skip "seeder logs in and appears on hub"  "the hub would not start"
	skip "seeder transfer port serves ADCS"   "the hub would not start"
	skip "seeder answers CSUP over ADCS"      "the hub would not start"
	skip "seeder answers plain ADC"           "the hub would not start"
	skip "CRASH ISOLATION"                    "the hub would not start"
	skip "seeder restarts after SIGKILL"      "the hub would not start"
	skip "cache survives the crash"           "the hub would not start"
	skip "hub survived the whole run"         "the hub would not start"
fi

print_manual_steps

echo
echo "================================================================"
echo "RESULTS"
echo "================================================================"
printf '%s\n' "$RESULTS" | sed '/^$/d'
echo
if [ $FAILED -eq 0 ]; then
	echo "SUMMARY: PASS  ($PASSED passed, $SKIPPED skipped, 0 failed)"
	exit 0
fi
echo "SUMMARY: FAIL  ($PASSED passed, $SKIPPED skipped, $FAILED failed)"
exit 1
