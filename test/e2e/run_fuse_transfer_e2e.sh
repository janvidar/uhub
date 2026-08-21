#!/usr/bin/env bash
#
# End-to-end test for uhub-fuse's by-tth: a file is read out of the mount that
# nothing on this machine has except another process on the hub.
#
# This is the client-to-client path -- search, CTM, CSUP/CINF/CGET/CSND, TTH
# verification, cache -- driven all the way through by a cat(1). The note at the
# top of test/seeder/e2e.sh says that path could not be automated because
# nothing could put content into a cache without a real DC client; seed_put is
# that missing piece, and this is what it unlocks.
#
# The source of the file is uhub-seeder, which is what a mount would fetch from
# on a real hub, and the two speak nothing but ordinary ADC to each other.
#
# Usage:  BUILD=/path/to/build  test/e2e/run_fuse_transfer_e2e.sh  [port]
# Requires: uhub, uhub-fuse (-DFUSE_SUPPORT=ON), uhub-seeder, uhub-passwd,
#           seed_put, mod_auth_sqlite.so, fusermount3.
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PORT=${1:-51051}
SEED_PORT=$((PORT + 1))
FUSE_PORT=$((PORT + 2))
HUB="adc://127.0.0.1:$PORT"

UHUB=$BUILD/uhub
FUSE=$BUILD/uhub-fuse
SEEDER=$BUILD/uhub-seeder
PASSWD=$BUILD/uhub-passwd
SEED_PUT=$BUILD/seed_put
PEER=$BUILD/filelist_peer

[ -x "$UHUB" ] || { echo "MISSING: $UHUB"; exit 2; }
[ -x "$FUSE" ] || { echo "SKIP: $FUSE not built (cmake -DFUSE_SUPPORT=ON)"; exit 77; }
for bin in "$SEEDER" "$PASSWD" "$SEED_PUT" "$PEER"; do
	[ -x "$bin" ] || { echo "MISSING: $bin (build it first)"; exit 2; }
done
[ -f "$BUILD/mod_auth_sqlite.so" ] || { echo "MISSING: $BUILD/mod_auth_sqlite.so"; exit 2; }
command -v fusermount3 >/dev/null || { echo "SKIP: fusermount3 not installed"; exit 77; }

DIR=$(mktemp -d)
MNT=$DIR/mnt
mkdir -p "$MNT" "$DIR/cache-seeder" "$DIR/cache-mount" "$DIR/plugins" "$DIR/share"
HUB_PID=""; SEED_PID=""; FUSE_PID=""; PEER_PID=""
pass=0; fail=0

cleanup() {
	fusermount3 -u "$MNT" 2>/dev/null
	for p in "$FUSE_PID" "$PEER_PID" "$SEED_PID" "$HUB_PID"; do
		[ -n "$p" ] && kill "$p" 2>/dev/null
	done
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
is()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi; }

wait_for() { local i; for i in $(seq 1 150); do "$@" >/dev/null 2>&1 && return 0; sleep 0.1; done; return 1; }

# The hub refuses a group- or world-writable plugin, and a build directory
# often is one. Copy it somewhere it can be trusted from.
cp "$BUILD/mod_auth_sqlite.so" "$DIR/plugins/" && chmod 755 "$DIR/plugins" && chmod 644 "$DIR/plugins/mod_auth_sqlite.so"

"$PASSWD" "$DIR/users.db" create >/dev/null 2>&1
"$PASSWD" "$DIR/users.db" add seedbot seedpass operator >/dev/null 2>&1

cat > "$DIR/plugins.conf" <<EOF
plugin $DIR/plugins/mod_auth_sqlite.so "file=$DIR/users.db"
EOF

cat > "$DIR/uhub.conf" <<EOF
server_port = $PORT
server_bind_addr = 127.0.0.1
tls_enable = 0
hub_name = Transfer hub
file_plugins = $DIR/plugins.conf
EOF

cat > "$DIR/seeder.conf" <<EOF
seed_hub_url = $HUB
seed_nick = seedbot
seed_password = seedpass
seed_client_port = $SEED_PORT
seed_client_bind_addr = 127.0.0.1
seed_cache_dir = $DIR/cache-seeder
seed_allowed_types = *
seed_bbs_enable = 0
EOF

# max_file_size is deliberately small: anything above it is read through a
# window instead of being fetched whole, and that path needs exercising.
cat > "$DIR/fuse.conf" <<EOF
hub = $HUB
nick = reader
transfer_port = $FUSE_PORT
transfer_bind_addr = 127.0.0.1
cache_dir = $DIR/cache-mount
max_file_size = 1
download_timeout = 20
EOF
chmod 600 "$DIR/fuse.conf"

echo "== uhub-fuse transfer e2e (hub $PORT, seeder $SEED_PORT, mount $FUSE_PORT) =="

# The file to be fetched. Random, so nothing can produce it except by having it.
head -c 300000 /dev/urandom > "$DIR/payload.bin"
TTH=$("$SEED_PUT" "$DIR/cache-seeder" "$DIR/payload.bin" payload.bin)
if [ ${#TTH} -eq 39 ]; then ok "seed_put put a file in a cache (TTH=$TTH)"; else bad "seed_put failed"; exit 1; fi

"$UHUB" -c "$DIR/uhub.conf" >"$DIR/hub.log" 2>&1 &
HUB_PID=$!
wait_for bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" || { echo "hub did not start:"; cat "$DIR/hub.log"; exit 1; }

"$SEEDER" -c "$DIR/seeder.conf" >"$DIR/seeder.log" 2>&1 &
SEED_PID=$!
if wait_for grep -q "logged in" "$DIR/seeder.log"; then
	ok "the seeder is on the hub holding the file"
else
	bad "the seeder did not log in"; cat "$DIR/seeder.log"; exit 1
fi

"$FUSE" --config="$DIR/fuse.conf" -f "$MNT" >"$DIR/fuse.log" 2>&1 &
FUSE_PID=$!
wait_for test -f "$MNT/hub/name" || { echo "the mount did not come up:"; cat "$DIR/fuse.log"; exit 1; }
ok "the mount is up"

# It has to be dialable, or a passive peer could never hand it anything.
support=$(cat "$MNT/me/support")
case "$support" in
	*TCP4*) ok "the mount advertises TCP4, so peers will dial it" ;;
	*) bad "me/support is '$support' -- the mount looks passive" ;;
esac

# by-tth has no listing: a content addressed directory has nothing to enumerate.
is "by-tth lists nothing" "" "$(ls "$MNT/by-tth")"

# The whole point. Nothing local has this file; the bytes come off the hub.
if cat "$MNT/by-tth/$TTH" > "$DIR/got.bin" 2>"$DIR/cat.err"; then
	ok "cat by-tth/<hash> succeeds"
else
	bad "cat failed: $(cat "$DIR/cat.err")"
fi

if cmp -s "$DIR/payload.bin" "$DIR/got.bin"; then
	ok "the bytes are the file, exactly"
else
	bad "the bytes differ (got $(stat -c %s "$DIR/got.bin" 2>/dev/null || echo 0) of $(stat -c %s "$DIR/payload.bin"))"
fi

# It really did come over the wire, rather than out of a cache that already had it.
if grep -q "accepted TTH=$TTH" "$DIR/fuse.log"; then
	ok "the file was fetched over a client-to-client transfer"
else
	bad "no transfer happened -- was it already cached?"
fi

# Once cached, stat() knows how big it is and a read costs nothing.
is "stat reports the true size once cached" "300000" "$(stat -c %s "$MNT/by-tth/$TTH")"
is "a second read returns the same bytes" "300000" "$(cat "$MNT/by-tth/$TTH" | wc -c)"

# A hash nobody has must end, and end as ENOENT rather than as a hang.
start=$SECONDS
cat "$MNT/by-tth/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" >/dev/null 2>&1 && bad "an unheld hash succeeded" || ok "an unheld hash fails"
elapsed=$((SECONDS - start))
if [ "$elapsed" -ge 15 ] && [ "$elapsed" -le 40 ]; then
	ok "it gives up after the configured timeout (${elapsed}s)"
else
	bad "gave up after ${elapsed}s, expected about 20"
fi

# A pending fetch must not stop the rest of the filesystem from working.
cat "$MNT/by-tth/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" >/dev/null 2>&1 &
PENDING=$!
sleep 1
if timeout 5 ls "$MNT/users" >/dev/null 2>&1; then
	ok "the mount answers while a download is pending"
else
	bad "a pending download blocked the whole mount"
fi
kill "$PENDING" 2>/dev/null; wait "$PENDING" 2>/dev/null

# --- browsing somebody's share -------------------------------------------
#
# A different peer entirely: uhub-seeder serves content by hash and publishes
# no file list, so browsing needs somebody who does. filelist_peer is that,
# and is as close to a real DC client as a fixture gets.

echo "hello from the share" > "$DIR/share/hello.txt"
head -c 50000 /dev/urandom > "$DIR/share/blob.bin"
head -c 5000000 /dev/urandom > "$DIR/share/big.bin"

"$PEER" "$HUB" sharer "$DIR/share" >"$DIR/peer.log" 2>&1 &
PEER_PID=$!
if wait_for grep -q "logged in as CID" "$DIR/peer.log"; then
	ok "a peer with a share is on the hub"
else
	bad "the share peer did not log in"; cat "$DIR/peer.log"
fi

wait_for test -L "$MNT/by-nick/sharer"
SHARER=$(readlink "$MNT/by-nick/sharer" 2>/dev/null | sed 's|../users/||')
if [ -n "$SHARER" ]; then ok "the peer appears in the mount"; else bad "the peer never appeared"; fi

# Stat'ing users/<cid>/ must not fetch a share list: `ls -l` on a user
# directory would otherwise start a download per user.
before=$(grep -c "asked .* for its file list" "$DIR/fuse.log" || true)
ls -l "$MNT/users/$SHARER/" >/dev/null 2>&1
after=$(grep -c "asked .* for its file list" "$DIR/fuse.log" || true)
is "listing a user does not fetch their share list" "$before" "$after"

# Listing files/ does.
entries=$(ls "$MNT/users/$SHARER/files/" 2>/dev/null | tr '\n' ' ')
is "the share lists its top level" "Shared " "$entries"

entries=$(ls "$MNT/users/$SHARER/files/Shared/" 2>/dev/null | sort | tr '\n' ' ')
is "and the directory below it" "big.bin blob.bin hello.txt " "$entries"

is "a shared file's size is what the list said" "50000" \
   "$(stat -c %s "$MNT/users/$SHARER/files/Shared/blob.bin")"

# The point of all of it: read a file out of somebody else's share, by name.
if [ "$(cat "$MNT/users/$SHARER/files/Shared/hello.txt")" = "hello from the share" ]; then
	ok "a file in the share reads back correctly"
else
	bad "reading a shared file gave the wrong bytes"
fi

if cat "$MNT/users/$SHARER/files/Shared/blob.bin" > "$DIR/blob.got" 2>/dev/null &&
   cmp -s "$DIR/share/blob.bin" "$DIR/blob.got"; then
	ok "a binary file in the share is byte for byte the same"
else
	bad "the binary file differs"
fi

# It is asked of the peer that has it, not broadcast to the hub: we know whose
# share it is.
if grep -q "asked $SHARER for TTH=" "$DIR/fuse.log"; then
	ok "the file was asked of the peer that has it"
else
	bad "the mount searched the hub for a file it knew the owner of"
fi

ls "$MNT/users/$SHARER/files/Shared/nope" >/dev/null 2>&1 && bad "a missing entry resolved" || ok "a missing entry is ENOENT"
ls "$MNT/users/$SHARER/files/Shared/hello.txt/deeper" >/dev/null 2>&1 && bad "a path below a file resolved" || ok "a path below a file is refused"

# --- a file too large to hold -------------------------------------------
#
# Above max_file_size a file is read through a sliding window: ranged requests,
# nothing written to disk. It cannot be verified against its hash -- a TTH
# covers a whole file -- which is exactly why the boundary is where it is.

if cat "$MNT/users/$SHARER/files/Shared/big.bin" > "$DIR/big.got" 2>/dev/null &&
   cmp -s "$DIR/share/big.bin" "$DIR/big.got"; then
	ok "a file larger than the cache ceiling reads back byte for byte"
else
	bad "the streamed file differs (got $(stat -c %s "$DIR/big.got" 2>/dev/null || echo 0))"
fi

ranges=$(grep -cE "CGET file TTH/[A-Z0-9]+ [0-9]+ [0-9]+$" "$DIR/fuse.log" || true)
if [ "$ranges" -ge 2 ]; then
	ok "it was fetched in ranges ($ranges of them), not in one piece"
else
	bad "expected several ranged requests, saw $ranges"
fi

# Streamed content is not cached: it was never verified, so storing it as
# though it had been would be a lie. Read the hash out of the peer's own
# listing rather than assuming one -- an empty pattern here would match every
# ingest line and quietly pass.
BIG_TTH=$(grep -oE "sharing big\.bin .*TTH=[A-Z0-9]+" "$DIR/peer.log" | sed 's/.*TTH=//')
if [ ${#BIG_TTH} -ne 39 ]; then
	bad "could not read the streamed file's TTH from the peer"
elif [ -z "$(grep "accepted TTH=$BIG_TTH" "$DIR/fuse.log" 2>/dev/null)" ]; then
	ok "streamed content is not cached"
else
	bad "a streamed file was cached as verified content"
fi

# Seeking has to work, or half of what a filesystem is for is missing.
dd if="$MNT/users/$SHARER/files/Shared/big.bin" bs=1 skip=4000000 count=64 \
	of="$DIR/seek.got" 2>/dev/null
dd if="$DIR/share/big.bin" bs=1 skip=4000000 count=64 of="$DIR/seek.want" 2>/dev/null
if cmp -s "$DIR/seek.want" "$DIR/seek.got"; then
	ok "reading from the middle of a streamed file gives the right bytes"
else
	bad "a seek into a streamed file gave the wrong bytes"
fi

kill "$PEER_PID" 2>/dev/null; wait "$PEER_PID" 2>/dev/null; PEER_PID=""

# A reader that gives up must be let go, rather than held for the rest of the
# timeout. This is what makes ^C on a download work.
cat "$MNT/by-tth/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" >/dev/null 2>&1 &
PENDING=$!
sleep 1
start=$SECONDS
# SIGTERM rather than SIGINT: a background job of a non-interactive shell has
# SIGINT ignored, so ^C's signal would never reach it here. Either way it is a
# fatal signal, which is what makes the kernel interrupt the request.
kill -TERM "$PENDING" 2>/dev/null
if wait_for bash -c "! kill -0 $PENDING 2>/dev/null"; then
	elapsed=$((SECONDS - start))
	if [ "$elapsed" -le 5 ]; then
		ok "interrupting a pending download returns at once (${elapsed}s)"
	else
		bad "an interrupted reader waited ${elapsed}s"
	fi
else
	bad "an interrupted reader never returned"
fi
wait "$PENDING" 2>/dev/null

# With nothing in flight the unmount goes through. (A request still in flight
# makes umount(2) report EBUSY, exactly as it does for any other filesystem
# with a file open on it -- that is the kernel's rule, not this one's.)
if timeout 15 fusermount3 -u "$MNT"; then
	ok "the mount unmounts"
else
	bad "the unmount failed"
fi

if wait_for bash -c "! kill -0 $FUSE_PID 2>/dev/null"; then
	ok "uhub-fuse exits after the unmount"
	wait "$FUSE_PID" 2>/dev/null
	status=$?
	FUSE_PID=""

	# Not just gone: gone cleanly. A crash on the way out still ends the
	# process, and checking only that it ended would call that a pass.
	is "and it exits successfully" "0" "$status"
else
	bad "uhub-fuse outlived its mount"
fi

# Anything the sanitizers or an assertion had to say is a failure, whatever
# the exit status was.
if grep -qE "AddressSanitizer|runtime error:|Assertion .* failed" "$DIR/fuse.log"; then
	bad "the mount logged a sanitizer report or an assertion:"
	grep -E "AddressSanitizer|runtime error:|Assertion .* failed" "$DIR/fuse.log" | head -3
else
	ok "no sanitizer reports or assertions"
fi

echo
echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
