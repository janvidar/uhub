# uhub security advisories

Remotely-triggerable denial-of-service issues, indexed by advisory ID.

| ID | Summary | Severity | Affected | Fixed in |
|----|---------|----------|----------|----------|
| [UHUB-2026-001](UHUB-2026-001.md) | Unauthenticated heap OOB read in `adc_msg_parse()` (issue #85) | High | <= 0.5.0 | 0.6.0 |
| [UHUB-2026-002](UHUB-2026-002.md) | Multiple memory-safety crashes in the ADC parser and login path | High | <= 0.5.0 | 0.6.0 |
| [UHUB-2026-003](UHUB-2026-003.md) | Resource-exhaustion DoS (connection flood, send-queue, search amplification) | Medium | <= 0.6.0 | 0.6.1 (pending) |
| [UHUB-2026-004](UHUB-2026-004.md) | Remote heap memory corruption (code-execution candidate) in `check_user_agent()` | Critical | <= 0.5.0 | 0.6.0 |

See [BACKPORT.md](BACKPORT.md) for per-release exposure (incl. Debian's 0.4.1)
and downstream cherry-pick guidance.

CVSS scores and advisory IDs are suggestions pending CVE/GHSA assignment.
