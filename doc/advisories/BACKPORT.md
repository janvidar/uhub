# Backport guidance (downstream / distribution maintainers)

This note maps the advisories to release lines so maintainers shipping an older
uhub (notably **Debian, which ships 0.4.1**) can see exactly what they are
exposed to and what to cherry-pick.

## TL;DR

- The clean fix is to ship **0.6.0 or later** (fixes the RCE and all the parser
  memory-safety bugs), and ideally **0.6.1** once released (adds the
  resource-exhaustion mitigations, UHUB-2026-003).
- **0.4.1 → 0.5.0 is not a security upgrade.** It fixes several DoS bugs but
  *introduces* the user-agent RCE (UHUB-2026-004) and leaves the unauthenticated
  parser OOB reads in place. Do not treat the jump to 0.5.0 as remediation.
- If you must stay on an old base, backport the four 0.6.0 commits listed under
  "Minimum backport set" below.

## Per-release exposure

| Issue | 0.4.1 | 0.5.0 | Fixed in |
|-------|:-----:|:-----:|----------|
| UHUB-2026-001 — unauth `adc_msg_parse()` OOB read (#85) | affected | affected | 0.6.0 |
| UHUB-2026-002 — parser/login memory-safety crashes | affected | affected | 0.6.0 |
| UHUB-2026-004 — user-agent heap write (RCE candidate) | **not affected** | **affected** | 0.6.0 |
| UHUB-2026-003 — resource-exhaustion DoS | affected | affected | pending 0.6.1 |
| TLS-mismatch assert → hub shutdown (`76ff2a1`) | affected | fixed | 0.5.0 |
| SSL poll infinite loop (`0426cb5`) | affected | fixed | 0.5.0 |
| Timer infinite loop, #198 (`550740f`) | affected | fixed | 0.5.0 |
| Flood-control enforcement (`e2b0757`) | weaker | fixed | 0.5.0 |

Verified by inspecting the 0.4.1 tree directly: the `adc_msg_parse()` F-loop,
`set_feature_cast_supports()`, `adc_msg_terminate()`, `adc_msg_escape_length()`,
`adc_msg_remove_named_argument()`, and the SID pool all carry the same defects
that were only fixed in 0.6.0.

## The 0.4.1-specific twist (UHUB-2026-004)

0.4.1's `check_user_agent()` is the **safe** single-field version:

```c
memcpy(user->id.user_agent, ua, MIN(strlen(ua), MAX_UA_LEN));  /* one bounded copy */
```

The vulnerable two-field (product + version) logic was introduced *during* the
0.4.1 → 0.5.0 cycle by `652ac5f` and then mis-fixed by `1da917e` ("Fix crash due
to negative max copy length"), which moved a parenthesis and turned a guaranteed
crash into an attacker-controlled heap write. Consequences for a backporter:

- **Do not** cherry-pick `652ac5f` / `1da917e` onto a 0.4.1 base in isolation —
  that imports the RCE. If they are pulled in, you **must** also apply the 0.6.0
  fix `7782f7d`.

## Minimum backport set (onto a pre-0.6.0 base)

Cherry-pick these four to clear the RCE and the unauthenticated parser bugs:

| Commit | Advisory | What it fixes |
|--------|----------|---------------|
| `7782f7d` | UHUB-2026-004 | user-agent heap write (RCE candidate) — **only needed if the two-field UA code is present**, i.e. on 0.5.0+ or after backporting `652ac5f`/`1da917e` |
| `fa0f9b5` | UHUB-2026-001 | unauthenticated `adc_msg_parse()` OOB read (#85) |
| `3eb13a3` | UHUB-2026-002 (002-b) | `set_feature_cast_supports()` OOB read |
| see 002 table | UHUB-2026-002 | remaining parser/SID memory-safety fixes (`12b653a`, `4ac65cd`, `061271a`, `438b102`, `d1c1315`, `c533661`, `5e14745`, `4a7bc70`, `fe45404`) |

For DoS-in-depth, also backport the UHUB-2026-003 commits (`d5314a2`,
`283e3ad`, `1471dab`, `ffd6070`) — these are not yet in any tagged release.

A pure 0.4.1 base does **not** need `7782f7d` (its UA code is already safe), but
**does** need everything else in this table.

## Operator mitigations (no rebuild)

Until a fixed package is available:

- Front the hub with a firewall connection-rate / max-connection limit.
- Set a conservative `max_send_buffer`.
- Restrict network reach (allowlist) — the OOB reads and the heap write both
  trigger before authentication, so config-level controls inside uhub cannot
  block them.
