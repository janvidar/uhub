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
        [--linger SECONDS] [--timeout SECONDS] [--expect ok|fail]
```

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
