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

## Not yet scripted

Cluster propagation (`LBAN`/`LUBN` across two linked hubs), plugin-driven bans
(`hub.ban_user`/`unban`), and the `on_validate_nick`/`on_validate_cid` hooks —
all extensions of the same harness.
