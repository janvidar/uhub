# End-to-end tests

Runtime tests that drive a **live `uhub`** with real ADC clients — covering the
paths the in-tree C unit tests (`autotest/`) can't, because they exercise the
actual login state machine over a socket.

## adc_cmd

A tiny scriptable ADC client built on the hub's own `libadcclient` (so the ADC
handshake and the Tiger password challenge are handled for us). It logs in as a
nick (optionally with a password), optionally sends chat lines (used to drive
`!commands`), lingers briefly, and exits 0/1 depending on whether login was
expected to succeed or be refused.

```
adc_cmd <adc://host:port> --nick N [--password P] [--send "text"]...
        [--inf FIELD]... [--hbri]
        [--linger SECONDS] [--timeout SECONDS] [--expect ok|fail]
```

`--inf` adds a named argument to the *login* INF (`--inf I6::1`), which is how a
test states something this client does not model and, unlike `--raw`, reaches
the hub before the login checks run. `--hbri` answers an HBRI challenge: on
`ITCP` it connects to the address the hub named and sends the token back as the
first line of that second connection. An IPv6 hub address is written bracketed,
`adc://[::1]:1511`.

It is built automatically (UNIX, alongside `uhub-admin`).

## run_ban_e2e.sh

Spins up a throwaway `uhub` (SQLite auth, an operator account, plaintext on a
local port), then verifies the ban/unban lifecycle end to end:

1. a guest can log in;
2. an operator `!ban` disconnects an online user;
3. the banned nick is refused on reconnect (`check_acl`);
4. `!unban` lets the nick back in;
5. a timed `!ban <nick> 1h` is reported as a *temporary* ban (status 232);
6. a ban survives a hub restart (persisted by `mod_auth_sqlite`).

```sh
# after a normal build:
BUILD=/path/to/build test/e2e/run_ban_e2e.sh [port]
```

Exit status is 0 only if every scenario passes. Requires `uhub`, `adc_cmd`,
`uhub-passwd`, and `mod_auth_sqlite.so` in the build dir.

## run_link_e2e.sh

Brings up **two linked hubs** (node 0 and node 1, a shared `link_secret`, node 1
linking to node 0), each with its **own** auth/ban database so the link is the
only path a ban can travel between them. Verifies cluster propagation:

1. the two hubs establish a link;
2. the roster is unified (a user on node B is visible on node A);
3. an operator `!ban` on node A disconnects the victim on node B (`LBAN`);
4. the banned nick is refused when it reconnects to node B;
5. `!unban` on node A restores access on node B (`LUBN`).

```sh
BUILD=/path/to/build test/e2e/run_link_e2e.sh [portA] [portB]
```

## run_plugin_e2e.sh

Loads the test-only `mod_e2e_test` plugin and verifies the plugin-facing hooks:

1. `on_validate_nick` rejects a login (the reserved nick `denynick`), and a
   normal nick still logs in;
2. `on_validate_cid` rejects a login by CID — the client pins a PID
   (`adc_cmd --pid`), giving it a deterministic CID that the plugin is told to
   deny (`deny_cid=<cid>`); a client with any other CID is unaffected;
3. a plugin-driven ban via `hub.ban_user` (chat trigger `PLZBANME`) disconnects
   the user and blocks their reconnect;
4. a plugin-driven unban via `hub.unban` (operator trigger `PLZUNBAN <nick>`)
   restores access.

```sh
BUILD=/path/to/build test/e2e/run_plugin_e2e.sh [port]
```

The CID test relies on `ADC_client_set_pid()` (added to `libadcclient`): a fixed
PID yields a fixed CID (`CID = base32(tiger(PID))`), so `adc_cmd --pid P --show-cid`
prints the CID to configure the plugin's `deny_cid`.

## run_hbri_e2e.sh

Drives HBRI — the extension that gets a dual-stack client's *other* address
family published, but only after the client proves it over a second connection
the hub opens the address from itself. The point is that the advertised `I4`/`I6`
is a trigger and never the published value, so every scenario turns on the gap
between what the client claims and what the hub observes — which is exactly what
an in-process test cannot reach:

1. a client offering `HBRI` and signalling IPv6 is challenged (`ITCP`), answers
   on the second family, and has the address published;
2. a client that advertises a bogus `I6` and answers from `::1` gets `::1`
   published — the claim is never what lands in the INF;
3. a client that is challenged and never answers stays primary-only;
4. a client that never offered `HBRI` is never challenged;
5. `nat_override` clients are still challenged, get their validated IPv6, and
   keep the IPv4 claim the option exists to trust.

```sh
BUILD=/path/to/build test/e2e/run_hbri_e2e.sh [port]
```

Needs an IPv6 loopback; it skips (exit 0) without one. Scenario 5 checks the
IPv4 claim from a *second* client that joined over IPv6, because
`route_info_message()` deliberately shows peers inside the same NAT the observed
LAN address instead — a LAN peer cannot rely on NAT hairpinning — so a client
inside the range never sees the claim at all.

## run_bbs_e2e.sh

Drives BBS0 bulletin boards over a socket with real clients — the hub side of
the extension end to end:

1. `BBS0` is announced in `ISUP`, and one `IBBD` per board follows login;
2. a board a session may not subscribe to is never mentioned to it, and a
   client that never offered `BBS0` receives no descriptors at all;
3. a post is accepted and the resulting `IBBL` is the acknowledgement — there
   is no success status in `BBS0`;
4. a reply's thread root is derived by the hub from its parent;
5. subscribing from `TS0` replays the whole board;
6. refusals carry the right code and name what they refused (`171` no such
   board, `176` no such post, `125` no permission, `172` too large);
7. an operator starts a thread on an announcements board and a guest replies to
   it, which is what separating the post and reply permissions is for;
8. an author withdraws a post, the tombstone reaches subscribers, replies to it
   survive, another user cannot withdraw it and an operator can;
9. the index survives a restart of the hub.

```sh
BUILD=/path/to/build test/e2e/run_bbs_e2e.sh [port]
```

Two things this leans on. `adc_cmd --raw` sends a line verbatim and
`--expect-line` matches received lines against a glob, which is how a client
that models none of these commands can still drive and assert on them. And the
author pins a PID (`--pid`), because withdrawing one's own post is decided on
the CID the hub accepted it from and never on the nick — reconnecting under the
same nick is a different author, and should be.
