#!/usr/bin/env bash
#
# End-to-end test for uhub-fuse: mount a live hub and read it back through the
# filesystem. Exercises what the unit tests cannot -- a real login, a real
# roster, and the two threads answering a real kernel request.
#
# Usage:  BUILD=/path/to/build  test/e2e/run_fuse_e2e.sh  [port]
# Requires (from the build dir): uhub, uhub-fuse (-DFUSE_SUPPORT=ON), adc_cmd.
# Requires fusermount3 and permission to mount, which a container usually
# withholds; the test skips rather than fails when it cannot mount.
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PORT=${1:-51031}
HUB="adc://127.0.0.1:$PORT"

UHUB=$BUILD/uhub
FUSE=$BUILD/uhub-fuse
ADC=$BUILD/adc_cmd

for bin in "$UHUB" "$ADC"; do
	[ -x "$bin" ] || { echo "MISSING: $bin (build it first)"; exit 2; }
done
[ -x "$FUSE" ] || { echo "SKIP: $FUSE not built (cmake -DFUSE_SUPPORT=ON)"; exit 77; }
command -v fusermount3 >/dev/null || { echo "SKIP: fusermount3 not installed"; exit 77; }

DIR=$(mktemp -d)
MNT=$DIR/mnt
mkdir -p "$MNT"
HUB_PID=""
FUSE_PID=""
ALICE_PID=""
pass=0; fail=0

cleanup() {
	fusermount3 -u "$MNT" 2>/dev/null
	[ -n "$FUSE_PID" ] && kill "$FUSE_PID" 2>/dev/null
	[ -n "$ALICE_PID" ] && kill "$ALICE_PID" 2>/dev/null
	[ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null
	wait 2>/dev/null

	# KEEP=1 leaves the logs behind, which is the only way to read a
	# sanitizer report from a process this script started and then killed.
	if [ -n "${KEEP:-}" ]; then
		echo "== working directory kept: $DIR =="
	else
		rm -rf "$DIR"
	fi
}
trap cleanup EXIT

ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

is() { # description expected actual
	if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

wait_for() { # command... -- retried for 10 seconds
	local i
	for i in $(seq 1 100); do "$@" >/dev/null 2>&1 && return 0; sleep 0.1; done
	return 1
}

cat > "$DIR/uhub.conf" <<EOF
server_port = $PORT
server_bind_addr = 127.0.0.1
tls_enable = 0
hub_name = E2E hub
hub_description = mounted by a test
EOF

"$UHUB" -c "$DIR/uhub.conf" >"$DIR/hub.log" 2>&1 &
HUB_PID=$!
if ! wait_for bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT"; then
	echo "hub did not start listening:"; cat "$DIR/hub.log"; exit 1
fi

echo "== uhub-fuse e2e (port $PORT, workdir $DIR) =="

# A second user, so users/ holds somebody other than the mount itself.
"$ADC" "$HUB" --nick alice --expect ok --linger 120 >"$DIR/alice.log" 2>&1 &
ALICE_PID=$!

"$FUSE" --hub="$HUB" --nick=mounter -f "$MNT" >"$DIR/fuse.log" 2>&1 &
FUSE_PID=$!

if ! wait_for test -f "$MNT/hub/name"; then
	echo "the mount did not come up:"; cat "$DIR/fuse.log"; exit 1
fi
ok "the hub mounts"

# --- what the hub says about itself ---
is "hub/name"        "E2E hub"            "$(cat "$MNT/hub/name")"
is "hub/description" "mounted by a test"  "$(cat "$MNT/hub/description")"
is "hub/address"     "$HUB"               "$(cat "$MNT/hub/address")"
is "hub/state"       "online"             "$(cat "$MNT/hub/state")"
is "hub/tls"         "no"                 "$(cat "$MNT/hub/tls")"

wait_for bash -c "[ \"\$(cat '$MNT/hub/users')\" = 2 ]"
is "hub/users counts both"  "2"           "$(cat "$MNT/hub/users")"
is "me/nick"         "mounter"            "$(cat "$MNT/me/nick")"

# --- users are directories named by CID ---
count=$(ls "$MNT/users" | wc -l)
is "users/ holds one directory per user" "2" "$count"

for cid in $(ls "$MNT/users"); do
	case "$cid" in
		*[!A-Z2-7]* | ????????????????????????????????????????* )
			bad "users/$cid is not a CID"; break ;;
	esac
done
[ "$fail" -eq 0 ] && ok "every users/ entry is a 39 character base32 CID"

ALICE="$MNT/by-nick/alice"
if [ -L "$ALICE" ]; then ok "by-nick/alice is a symlink"; else bad "by-nick/alice is not a symlink"; fi
target=$(readlink "$ALICE")
linked=${target#../users/}
if [ "$linked" != "$target" ] && [ ${#linked} -eq 39 ]; then
	ok "the symlink names a CID under users/"
else
	bad "the symlink target is '$target'"
fi
is "following it lands on alice" "alice" "$(cat "$MNT/by-nick/alice/nick")"

is "alice's nick"       "alice"     "$(cat "$ALICE/nick")"
is "alice's ip"         "127.0.0.1" "$(cat "$ALICE/ip")"
is "alice's share size" "0"         "$(cat "$ALICE/share_size")"
is "an unadvertised field is empty" "" "$(cat "$ALICE/support")"

# The raw line is the one the hub sent, and carries the fields the mount does
# not model.
if grep -q "^BINF .*NIalice" "$ALICE/inf"; then ok "users/<cid>/inf is the raw INF"; else bad "inf is not the raw line"; fi

# --- a file's size has to agree with its contents ---
size=$(stat -c %s "$ALICE/nick")
bytes=$(wc -c < "$ALICE/nick")
is "stat size matches what read returns" "$size" "$bytes"

# --- what must not work ---
ls "$MNT/nope"            >/dev/null 2>&1 && bad "an unknown path resolved"      || ok "an unknown path is ENOENT"
cat "$MNT/users/AAAA"     >/dev/null 2>&1 && bad "a short CID resolved"          || ok "a malformed CID is ENOENT"
(echo x > "$MNT/hub/name") >/dev/null 2>&1 && bad "a metadata file was writable" || ok "the mount is read-only"
mkdir "$MNT/users/foo"    >/dev/null 2>&1 && bad "mkdir succeeded"               || ok "mkdir is refused"

# --- chat ---
echo "from the mount" > "$MNT/chat/main"
if wait_for grep -q "<mounter> from the mount" "$MNT/chat/main"; then
	ok "writing to chat/main says it in the hub's chat"
else
	bad "the message never came back (chat/main: $(cat "$MNT/chat/main"))"
fi

# One write, several messages: a newline ends each one.
printf 'first line\nsecond line\n' > "$MNT/chat/main"
wait_for grep -q "<mounter> second line" "$MNT/chat/main"
lines=$(grep -c "<mounter> \(first\|second\) line" "$MNT/chat/main")
is "a two line write is two messages" "2" "$lines"

# ... and no newline at all is still a message, sent when the file is closed.
printf 'no newline here' > "$MNT/chat/main"
if wait_for grep -q "<mounter> no newline here" "$MNT/chat/main"; then
	ok "a write without a newline is sent on close"
else
	bad "an unterminated write was never sent"
fi

"$ADC" "$HUB" --nick chatter --send "hello from chatter" --linger 2 >"$DIR/chatter.log" 2>&1
if wait_for grep -q "<chatter> hello from chatter" "$MNT/chat/main"; then
	ok "another user's chat arrives in chat/main"
else
	bad "chat from another user never arrived"
fi

# tail -f has to work, which means the size grows and reads at the end block
# on nothing -- the log is a stream, not a snapshot.
before=$(stat -c %s "$MNT/chat/main")
echo "growing" > "$MNT/chat/main"
wait_for bash -c "[ \"\$(stat -c %s '$MNT/chat/main')\" -gt $before ]"
after=$(stat -c %s "$MNT/chat/main")
if [ "$after" -gt "$before" ]; then ok "chat/main grows as things are said"; else bad "chat/main size stuck at $before"; fi

# A private message to ourselves is not possible, so the hub's own reply to a
# !command stands in for the receive path; it arrives as an ordinary message
# from the hub, named rather than numbered.
echo "!uptime" > "$MNT/chat/main"
if wait_for grep -q "<E2E hub> \*\*\* uptime" "$MNT/chat/main"; then
	ok "the hub speaks under its own name"
else
	bad "the hub's reply did not arrive (or is not named)"
fi

ALICE_CID=$(readlink "$ALICE" | sed 's|../users/||')
echo "psst" > "$MNT/users/$ALICE_CID/msg"
if wait_for grep -q -- "-> <alice> psst" "$MNT/chat/private"; then
	ok "a private message is recorded in chat/private"
else
	bad "the outgoing private message was not recorded"
fi

cat "$MNT/users/$ALICE_CID/msg" >/dev/null 2>&1 && bad "msg was readable" || ok "msg is write-only"
(echo x > "$MNT/chat/private") >/dev/null 2>&1 && bad "chat/private was writable" || ok "chat/private is read-only"

# --- the roster follows the hub ---
kill "$ALICE_PID" 2>/dev/null; wait "$ALICE_PID" 2>/dev/null; ALICE_PID=""
if wait_for bash -c "[ \"\$(cat '$MNT/hub/users')\" = 1 ]"; then
	ok "a user who leaves disappears from the mount"
else
	bad "the roster kept a user who left (users=$(cat "$MNT/hub/users"))"
fi
[ -e "$ALICE" ] && bad "by-nick kept a stale link" || ok "by-nick drops the stale link"

# --- and the hub going away does not take the mount with it ---
kill "$HUB_PID" 2>/dev/null; wait "$HUB_PID" 2>/dev/null; HUB_PID=""
if wait_for bash -c "[ \"\$(cat '$MNT/hub/state')\" != online ]"; then
	ok "hub/state stops saying online"
else
	bad "hub/state still claims online with no hub"
fi
is "users/ empties when the hub is gone" "0" "$(ls "$MNT/users" | wc -l)"
ls "$MNT" >/dev/null 2>&1 && ok "the mount still answers with no hub" || bad "the mount hung when the hub went away"

# --- unmount, with the process expected to leave of its own accord ---
fusermount3 -u "$MNT"
if wait_for bash -c "! kill -0 $FUSE_PID 2>/dev/null"; then
	ok "unmounting stops uhub-fuse"
	wait "$FUSE_PID" 2>/dev/null
	is "and it exits successfully" "0" "$?"
	FUSE_PID=""
else
	bad "uhub-fuse outlived its mount"
fi

if grep -qE "AddressSanitizer|runtime error:|Assertion .* failed" "$DIR/fuse.log"; then
	bad "the mount logged a sanitizer report or an assertion:"
	grep -E "AddressSanitizer|runtime error:|Assertion .* failed" "$DIR/fuse.log" | head -3
else
	ok "no sanitizer reports or assertions"
fi

echo
echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
