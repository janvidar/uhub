# Fuzzing uhub's parsers

uhub parses several kinds of untrusted text. The harnesses here build as
libFuzzer targets (requires **clang**) and are instrumented with
AddressSanitizer + UndefinedBehaviorSanitizer. They are built when CMake is
configured with `-DFUZZING=ON` and run for a short time on every CI run.

| Target | Source | Parser under test | Exposure |
|--------|--------|-------------------|----------|
| `fuzz_message`        | `src/tools/fuzz_message.c`        | `adc_msg_parse()` + the message accessor/mutator API | raw network bytes, **pre-auth** |
| `fuzz_adc_escape`     | `src/tools/fuzz_adc_escape.c`     | `adc_msg_escape()` / `adc_msg_unescape()` / `adc_msg_unescape_to_target()` | arbitrary strings (nicks, chat, user-agent) |
| `fuzz_ipcalc`         | `src/tools/fuzz_ipcalc.c`         | `ip_convert_address_to_range()` / `ip_convert_to_binary()` (IPv4/IPv6 + CIDR + ranges) and the address math | ACL `deny_ip`/range config, command IP args |
| `fuzz_command_parser` | `src/tools/fuzz_command_parser.c` | `command_parse()` (`!`/`+` commands), incl. the IP/number argument parsers | logged-in user chat input |
| `fuzz_config_token`   | `src/tools/fuzz_config_token.c`   | `cfg_tokenize()` / `cfg_settings_split()` | `uhub.conf` / `users.conf` file content |
| `fuzz_metrics`        | `src/tools/fuzz_metrics.c`        | `metrics_classify_request()` (HTTP method/path/bearer-token validation) | raw network bytes on the metrics endpoint |
| `fuzz_login`          | `src/tools/fuzz_login.c`          | `hub_handle_info_login()` -- the connect-time INF checks (CID/nick/network/user-agent/ACL) | INF from a not-yet-trusted client, **pre-auth** |

`fuzz_adc_escape` also checks a property: `escape()` followed by `unescape()`
must reproduce the original string exactly (a violation aborts the run).

`fuzz_message` and `fuzz_login` are the highest-value targets: both run
against attacker bytes before authentication. `fuzz_message` covers the ADC
parse; `fuzz_login` continues past it into the connect-time INF checks
(CID/nick/network/user-agent/ACL), the code with the OOB history.
`fuzz_command_parser` also exercises the ipcalc and `is_number` parsers via
the address/number argument codes.

## Build

```sh
CC=clang cmake -B build-fuzz -DFUZZING=ON -DSSL_SUPPORT=OFF -DRELEASE=ON .
cmake --build build-fuzz --target fuzz_message fuzz_adc_escape fuzz_ipcalc fuzz_config_token fuzz_command_parser fuzz_metrics fuzz_login -j
```

## Run

```sh
# UBSAN_OPTIONS=halt_on_error=1 makes undefined behaviour fail the run, not
# just memory errors. CI sets this; do the same locally.
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1

./build-fuzz/fuzz_message      -dict=autotest/fuzz/adc.dict autotest/fuzz/corpus/message
./build-fuzz/fuzz_adc_escape                                autotest/fuzz/corpus/adc_escape
./build-fuzz/fuzz_ipcalc                                    autotest/fuzz/corpus/ipcalc
./build-fuzz/fuzz_config_token                              autotest/fuzz/corpus/config_token
./build-fuzz/fuzz_command_parser                            autotest/fuzz/corpus/command_parser
./build-fuzz/fuzz_metrics      -dict=autotest/fuzz/metrics.dict autotest/fuzz/corpus/metrics
./build-fuzz/fuzz_login        -dict=autotest/fuzz/login.dict   autotest/fuzz/corpus/login
```

Add `-max_total_time=<seconds>` for a time-boxed run (what CI does). A crash
writes a `crash-<hash>` reproducer to the working directory; replay it with
`./build-fuzz/<target> crash-<hash>`.

## Corpus

`corpus/<target>/` holds hand-written seed inputs, one per file. libFuzzer
writes newly-discovered inputs back into the directory it is given, so a local
run will leave untracked `corpus/<target>/<hash>` files behind — `git clean`
them, or commit genuinely interesting ones back as permanent seeds. When you
fix a parser bug, add the crashing reproducer to the relevant corpus directory
so it becomes a regression seed.
