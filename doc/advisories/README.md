# uhub security advisories

Remotely-triggerable security issues, indexed by advisory ID.

| ID | Summary | Severity | Affected | Fixed in |
|----|---------|----------|----------|----------|
| [UHUB-2026-001](UHUB-2026-001.md) | Unauthenticated heap OOB read in `adc_msg_parse()` (issue #85) | High | <= 0.5.0 | 0.6.0 |
| [UHUB-2026-002](UHUB-2026-002.md) | Multiple memory-safety crashes in the ADC parser and login path | High | <= 0.5.0 | 0.6.0 |
| [UHUB-2026-003](UHUB-2026-003.md) | Resource-exhaustion DoS (connection flood, send-queue, search amplification) | Medium | <= 0.6.0 | 0.6.1 (pending) |
| [UHUB-2026-004](UHUB-2026-004.md) | Remote heap memory corruption (code-execution candidate) in `check_user_agent()` | Critical | <= 0.5.0 | 0.6.0 |
| [UHUB-2026-005](UHUB-2026-005.md) | Hub-link authentication bypass by challenge reflection (issue #127) | Critical | 0.7.0 – 0.8.0, linking enabled | 0.8.1 |
| [UHUB-2026-006](UHUB-2026-006.md) | Link command injection through a nick on an `auth_proxy` slave (issue #128) | Critical | 0.7.0 – 0.8.0, `auth_proxy` enabled | 0.8.1 |
| [UHUB-2026-007](UHUB-2026-007.md) | Link command injection and ban removal through `!unban` (issue #129) | High | 0.8.0 | 0.8.1 |

See [BACKPORT.md](BACKPORT.md) for per-release exposure (incl. Debian's 0.4.1)
and downstream cherry-pick guidance.

CVSS scores and advisory IDs are suggestions pending CVE/GHSA assignment.
