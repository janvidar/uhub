#!/usr/bin/env bash
#
# End-to-end test for BBS0 bulletin boards, driving a live hub with real ADC
# clients over a socket:
#   - the feature is announced in ISUP, and board descriptors follow login;
#   - a board a session may not subscribe to is never mentioned to it;
#   - posting, the entry that acknowledges it, and fan-out to a subscriber;
#   - threading, permissions, withdrawal and the refusal codes;
#   - the index survives a restart of the hub.
#
# Usage:  BUILD=/path/to/build  test/e2e/run_bbs_e2e.sh  [port]
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}
PORT=${1:-51061}
HUB="adc://127.0.0.1:$PORT"

UHUB=$BUILD/uhub
ADC=$BUILD/adc_cmd
PASSWD=$BUILD/uhub-passwd

for f in "$UHUB" "$ADC" "$PASSWD" "$BUILD/mod_auth_sqlite.so"; do
	[ -e "$f" ] || { echo "MISSING: $f (build it first)"; exit 2; }
done

DIR=$(mktemp -d)
HUB_PID=""
pass=0; fail=0

cleanup() { [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null; wait 2>/dev/null; rm -rf "$DIR"; }
trap cleanup EXIT
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

start_hub() {
	"$UHUB" -c "$DIR/uhub.conf" >>"$DIR/hub.log" 2>&1 &
	HUB_PID=$!
	local i
	for i in $(seq 1 50); do
		(exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
		kill -0 "$HUB_PID" 2>/dev/null || { echo "hub died:"; cat "$DIR/hub.log"; return 1; }
		sleep 0.1
	done
	echo "hub not listening:"; cat "$DIR/hub.log"; return 1
}

stop_hub() { [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null; wait "$HUB_PID" 2>/dev/null; HUB_PID=""; }

# Two well-formed Tiger tree hash roots: 39 base32 characters each. Nothing
# hashes to these -- the hub never sees a post document, so it does not care.
TTH_ROOT=KX3TQ7ZVN5PLQGKD3NDBK6ZTZG5PYQXSNMFYVJH
TTH_REPLY=7ZQGKD3NDBK6ZTZG5PYQXSNMFYVJH4TXAVN6PLQ
TTH_NOTICE=VN6PLQ7ZQGKD3NDBK6ZTZG5PYQXSNMFYVJH4TXA
TTH_COMMENT=MFYVJH4TXAVN6PLQ7ZQGKD3NDBK6ZTZG5PYQXSN
# Never indexed anywhere: used only where something must not be found.
TTH_ABSENT=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

# A fixed PID yields a deterministic CID. Withdrawal of one's own post is
# decided on the CID the hub accepted it from and never on the nick, so an
# author coming back for its own post has to come back as the same CID --
# reconnecting under the same nick is not enough, and should not be.
POSTER_PID=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

"$PASSWD" "$DIR/users.db" create >/dev/null 2>&1
"$PASSWD" "$DIR/users.db" add admin adminpass admin >/dev/null 2>&1
"$PASSWD" "$DIR/users.db" add member memberpass user >/dev/null 2>&1

cat > "$DIR/plugins.conf" <<EOF
plugin_dir $BUILD
plugin mod_auth_sqlite "file=$DIR/users.db"
EOF

# general:       everyone reads, replies, posts and takes their own posts back.
# announcements: everyone reads and replies, only operators start a thread.
# staff:         registered users only -- a guest is never told it exists.
cat > "$DIR/boards.conf" <<EOF
board general title="General discussion" description="Anything about this hub" post=guest withdraw_own=guest
board announcements title="Announcements" post=operator max_size=65536
board staff title="Staff room" subscribe=reg
EOF

cat > "$DIR/uhub.conf" <<EOF
server_port = $PORT
server_bind_addr = 127.0.0.1
file_plugins = $DIR/plugins.conf
tls_enable = 0
bbs_enable = yes
file_bbs_boards = $DIR/boards.conf
file_bbs_index = $DIR/bbs.db
bbs_post_interval = 0
EOF

echo "== uhub BBS0 bulletin board e2e (port $PORT, workdir $DIR) =="
start_hub || exit 1

# 1. Feature negotiation, and the descriptors that follow login. PE15 on general
#    is 1+2+4+8 -- subscribe, post, reply and withdraw one's own, which this
#    board grants a guest; PE5 on announcements is subscribe and reply only,
#    which is the split that makes an announcements board possible.
if "$ADC" "$HUB" --nick reader --sup ADBBS0 --linger 2 --expect ok \
	--expect-line "ISUP *ADBBS0*" \
	--expect-line "IBBD BDgeneral *PE15 MS262144*" \
	--expect-line "IBBD BDannouncements *PE5 MS65536*" \
	>"$DIR/sup.log" 2>&1; then
	ok "BBS0 is announced in ISUP and descriptors follow login"
else bad "negotiation or descriptors wrong (see $DIR/sup.log)"; fi

# A guest is not told the registered-only board exists at all.
if grep -q "IBBD BDstaff" "$DIR/sup.log"; then
	bad "a guest was told about a registered-only board (see $DIR/sup.log)"
else ok "a board the session cannot subscribe to is never mentioned"; fi

# A registered user does see it.
if "$ADC" "$HUB" --nick member --password memberpass --sup ADBBS0 --linger 2 --expect ok \
	--expect-line "IBBD BDstaff *" >"$DIR/staff.log" 2>&1; then
	ok "a registered user is told about the registered-only board"
else bad "registered user did not receive the staff descriptor (see $DIR/staff.log)"; fi

# A client that never offered BBS0 receives no descriptors.
if "$ADC" "$HUB" --nick plainclient --dump --linger 2 --expect ok >"$DIR/nosup.log" 2>&1 \
	&& ! grep -q "IBBD" "$DIR/nosup.log"; then
	ok "a client that did not offer BBS0 receives no descriptors"
else bad "descriptors sent to a client that never offered BBS0 (see $DIR/nosup.log)"; fi

# 2. Posting: the entry that comes back is the acknowledgement, and it carries
#    the hub's own testimony -- the CID it accepted the post from, and TH.
if "$ADC" "$HUB" --nick poster --pid "$POSTER_PID" --sup ADBBS0 --linger 3 --expect ok \
	--raw "HBBP TR$TTH_ROOT SI412 BDgeneral SJHub\\supgrade\\son\\sSaturday" \
	--expect-line "IBBL TR$TTH_ROOT SI412 BDgeneral ID* NIposter TH$TTH_ROOT SJHub\\supgrade\\son\\sSaturday TS*" \
	>"$DIR/post.log" 2>&1; then
	ok "a post is accepted and the entry is the acknowledgement"
else bad "post not accepted or entry malformed (see $DIR/post.log)"; fi

# 3. A reply names its parent; the hub derives the thread root from it.
if "$ADC" "$HUB" --nick replier --sup ADBBS0 --linger 3 --expect ok \
	--raw "HBBP TR$TTH_REPLY SI298 BDgeneral PA$TTH_ROOT SJRe:\\sHub\\supgrade" \
	--expect-line "IBBL TR$TTH_REPLY *PA$TTH_ROOT TH$TTH_ROOT *" \
	>"$DIR/reply.log" 2>&1; then
	ok "a reply inherits the thread root the hub derived from its parent"
else bad "reply threading wrong (see $DIR/reply.log)"; fi

# 4. Subscribing replays the backlog: both posts arrive, oldest first.
if "$ADC" "$HUB" --nick catchup --sup ADBBS0 --linger 3 --expect ok \
	--raw "HBBL BDgeneral TS0" \
	--expect-line "IBBL TR$TTH_ROOT *" \
	--expect-line "IBBL TR$TTH_REPLY *" \
	>"$DIR/replay.log" 2>&1; then
	ok "subscribing from TS0 replays the whole board"
else bad "backlog not replayed (see $DIR/replay.log)"; fi

# 5. Refusals: an unknown board, an unindexed post, and a thread on a board
#    where only operators may start one.
if "$ADC" "$HUB" --nick refused --sup ADBBS0 --linger 3 --expect ok \
	--raw "HBBL BDgenrel TS0" \
	--raw "HBBL BDgeneral TR$TTH_ABSENT" \
	--raw "HBBP TR$TTH_ABSENT SI10 BDannouncements SJNot\\sallowed" \
	--raw "HBBP TR$TTH_ABSENT SI70000 BDannouncements" \
	--expect-line "ISTA 171 *FCBBL BDgenrel" \
	--expect-line "ISTA 176 *FCBBL TR$TTH_ABSENT" \
	--expect-line "ISTA 125 *FCBBP TR$TTH_ABSENT" \
	>"$DIR/refuse.log" 2>&1; then
	ok "refusals carry the right code and name what they refused"
else bad "refusal codes wrong (see $DIR/refuse.log)"; fi

# The announcements board in full: an operator starts the thread, and a guest --
# who was just refused a thread of its own there -- replies to it. Separating
# the two permissions is what makes that shape possible.
if "$ADC" "$HUB" --nick admin --password adminpass --sup ADBBS0 --linger 3 --expect ok \
	--raw "HBBP TR$TTH_NOTICE SI128 BDannouncements SJScheduled\\smaintenance" \
	--expect-line "IBBL TR$TTH_NOTICE *BDannouncements *" >"$DIR/notice.log" 2>&1; then
	ok "an operator may start a thread on the announcements board"
else bad "operator could not post an announcement (see $DIR/notice.log)"; fi

if "$ADC" "$HUB" --nick replyonly --sup ADBBS0 --linger 3 --expect ok \
	--raw "HBBP TR$TTH_COMMENT SI64 BDannouncements PA$TTH_NOTICE SJRe:\\sScheduled\\smaintenance" \
	--expect-line "IBBL TR$TTH_COMMENT *PA$TTH_NOTICE TH$TTH_NOTICE *" >"$DIR/replyok.log" 2>&1; then
	ok "a guest may reply where it may not start a thread"
else bad "guest reply refused (see $DIR/replyok.log)"; fi

# 6. Withdrawal by the author: the tombstone carries the hash, the board, a new
#    timestamp and RM1, and nothing else.
if "$ADC" "$HUB" --nick poster --pid "$POSTER_PID" --sup ADBBS0 --linger 3 --expect ok \
	--raw "HBBL BDgeneral TS0" \
	--raw "HBBP TR$TTH_ROOT BDgeneral RM1" \
	--expect-line "IBBL TR$TTH_ROOT BDgeneral TS* RM1" \
	>"$DIR/withdraw.log" 2>&1; then
	ok "an author may withdraw a post, and a tombstone is broadcast"
else bad "withdrawal failed (see $DIR/withdraw.log)"; fi

# Withdrawal is not deletion: the reply is a separate post and stays.
if "$ADC" "$HUB" --nick after --sup ADBBS0 --linger 3 --expect ok \
	--raw "HBBL BDgeneral TS0" \
	--expect-line "IBBL TR$TTH_REPLY *" >"$DIR/afterwithdraw.log" 2>&1; then
	ok "replies to a withdrawn post are not removed with it"
else bad "reply disappeared with its parent (see $DIR/afterwithdraw.log)"; fi

# Someone else's post cannot be withdrawn without permission 16 -- and "someone
# else" means a different CID, which is what a client reconnecting without a
# pinned PID has, whatever nick it uses.
if "$ADC" "$HUB" --nick meddler --sup ADBBS0 --linger 3 --expect ok \
	--raw "HBBP TR$TTH_REPLY BDgeneral RM1" \
	--expect-line "ISTA 125 *FCBBP TR$TTH_REPLY" >"$DIR/meddle.log" 2>&1; then
	ok "withdrawing someone else's post is refused"
else bad "another user's post was withdrawn (see $DIR/meddle.log)"; fi

# An operator holds permission 16 and may withdraw anything.
if "$ADC" "$HUB" --nick admin --password adminpass --sup ADBBS0 --linger 3 --expect ok \
	--raw "HBBP TR$TTH_REPLY BDgeneral RM1" \
	--expect-line "IBBL TR$TTH_REPLY BDgeneral TS* RM1" >"$DIR/opwithdraw.log" 2>&1; then
	ok "an operator may withdraw any post"
else bad "operator withdrawal refused (see $DIR/opwithdraw.log)"; fi

# 7. The index is on disk: it survives the hub going away and coming back.
stop_hub
start_hub || exit 1
if "$ADC" "$HUB" --nick restarted --sup ADBBS0 --linger 3 --expect ok \
	--raw "HBBL BDannouncements TS0" \
	--expect-line "IBBL TR$TTH_NOTICE *" \
	--expect-line "IBBL TR$TTH_COMMENT *" >"$DIR/restart.log" 2>&1; then
	ok "the index survives a restart of the hub"
else bad "index lost across restart (see $DIR/restart.log)"; fi

echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
