# uhub

[![CI](https://github.com/janvidar/uhub/actions/workflows/ci.yml/badge.svg)](https://github.com/janvidar/uhub/actions/workflows/ci.yml)
[![CodeQL](https://github.com/janvidar/uhub/actions/workflows/codeql.yml/badge.svg)](https://github.com/janvidar/uhub/actions/workflows/codeql.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](COPYING)

**uhub** is a small, fast, and secure peer-to-peer hub server for the
[ADC protocol](https://en.wikipedia.org/wiki/Advanced_Direct_Connect). It lets
ADC clients (DC++, AirDC++, and others) meet in a shared space to chat and to
search each other's shared files; the actual file transfers happen directly
between clients, peer to peer.

It is written in C as a single-threaded, event-driven server, so it stays
lightweight even with thousands of connected users. TLS is mandatory, and the
feature set can be extended at runtime through loadable plugins.

## Features

- **Efficient** — one thread, a hand-rolled event loop (epoll / kqueue / select),
  and coalesced broadcast writes keep CPU and memory low under load.
- **Secure by default** — TLS is required (OpenSSL or LibreSSL), passwords are
  compared in constant time, privileges are dropped and verified, and the wire
  parser is fuzzed and hardened against untrusted input.
- **Extensible** — loadable `mod_*.so` plugins for authentication, logging, chat
  history, topic control, flood handling, welcome messages, and more.
- **Federated** — multiple hubs can be linked into a single logical hub with a
  shared user list, cross-hub routing, and cluster-wide bans (see
  [`doc/linking.txt`](doc/linking.txt)).
- **Observable** — an optional Prometheus metrics endpoint exposes counters,
  gauges, and event-loop timing (see [`doc/prometheus.txt`](doc/prometheus.txt)).
- **Portable** — runs on Linux, macOS, and the BSDs.

## Who is this for?

- **Communities** who want to run their own private or public ADC hub for chat
  and file sharing among their members.
- **Operators** who need a hub that is cheap to host, easy to script with `!`
  commands, and can scale across processes or linked nodes.
- **Developers** interested in the ADC protocol, event-driven network servers,
  or writing hub plugins against a small C plugin API.

For a list of compatible clients, see the
[Comparison of ADC software](https://en.wikipedia.org/wiki/Comparison_of_ADC_software#Client_software).

## Building

uhub is distributed as source — there are no prebuilt binaries.

### Prerequisites

- A C compiler (C23) and [CMake](https://cmake.org/) ≥ 3.21
- [SQLite3](https://www.sqlite.org/) development headers
- A TLS library: **OpenSSL ≥ 3.0** or **LibreSSL ≥ 3.4** (mandatory)
- Perl 5 (used at build time to generate the test driver)

On Debian/Ubuntu:

```sh
sudo apt-get install build-essential cmake perl libsqlite3-dev libssl-dev
```

### Build with CMake

```sh
git clone https://github.com/janvidar/uhub.git
cd uhub
mkdir -p build && cd build
cmake ..
make -j
sudo make install    # optional
```

This produces the `uhub` binary, the `mod_*.so` plugins, and the `uhub-passwd`
helper. Useful CMake options: `-DRELEASE=OFF` (debug build),
`-DSYSTEMD_SUPPORT=ON`, and `-DADC_STRESS=ON` (build the stress tester). To
build against LibreSSL when both are installed, point CMake at its prefix with
`-DOPENSSL_ROOT_DIR=/path/to/libressl`.

### Build with Zig (self-contained, alternative)

The repository also ships a `build.zig` that fetches and statically links a
bundled LibreSSL and SQLite3, so no system TLS or SQLite packages are needed —
only [Zig](https://ziglang.org/download/) (≥ 0.14.1):

```sh
zig build                        # artifacts land in zig-out/bin
zig build -Dsystem-ssl=true      # link host OpenSSL/LibreSSL instead
zig build -Dtarget=aarch64-linux-musl   # cross-compile
zig build test                   # run the test suite
```

## Running

You can start uhub with no configuration at all — it will use sensible
defaults. To customize it, install the sample config files first:

```sh
sudo mkdir -p /etc/uhub
sudo cp doc/uhub.conf doc/users.conf /etc/uhub/
echo "Welcome to my hub" | sudo tee /etc/uhub/motd.txt
```

Start the hub in the foreground (stop it with Ctrl+C):

```sh
uhub
# INFO: Starting server, listening on :::1511...
```

Then connect an ADC client to `adcs://localhost:1511` (use the `adcs://` prefix
and the port number). To run as a background daemon under an unprivileged user:

```sh
uhub -f -l /var/log/uhub.log -u nobody -g nogroup
```

Common options (`uhub -h` lists them all): `-c <file>` config file,
`-C` check config and exit, `-f` fork to background, `-l <file>` log file,
`-u`/`-g` drop to user/group, `-p <file>` write a pid file, `-V` version.

After editing the config, reload it by sending `SIGHUP`:

```sh
killall -HUP uhub
```

## Operating

- **Configuration** — the hub is configured through `uhub.conf`; every option is
  documented inline in [`doc/uhub.conf`](doc/uhub.conf). Run `uhub -s` to print
  the effective configuration.
- **Access control** — credentialed users and bans live in a separate ACL file
  (`file_acl`, e.g. `users.conf`); see [`doc/users.conf`](doc/users.conf).
- **In-hub commands** — operators and users can control the hub from main chat
  with `!` commands. Type `!help` to see what is available at your level.
- **Registered users** — manage the SQLite user database with the `uhub-passwd`
  tool (`man uhub-passwd`), or enable the `!regme` / `!passwd` self-service
  commands in `mod_auth_sqlite`.
- **Plugins** — enable and configure plugins in a plugins config file; a fully
  commented example is in [`doc/plugins.conf`](doc/plugins.conf).
- **Scaling** — for more than ~1024 users, raise the file-descriptor limit
  (`ulimit -n`) above the configured `max_users`. Use `workers=N` for
  multi-process mode, or link multiple hubs together for federation.

More documentation lives in the [`doc/`](doc/) directory, including
[`doc/getstarted.txt`](doc/getstarted.txt),
[`doc/architecture.txt`](doc/architecture.txt) (the login state machine), and
[`doc/linking.txt`](doc/linking.txt).

## Contributing

Contributions are welcome!

- **Report bugs and request features** via
  [GitHub issues](https://github.com/janvidar/uhub/issues).
- **Submit changes** as pull requests against `master`. Please keep the coding
  style consistent with the surrounding code, and add or update tests where it
  makes sense.
- **Build and test** before opening a PR. The full test suite is a single
  binary:

  ```sh
  cd build && make -j && ./autotest-bin
  ```

  Because this codebase has a history of bounds bugs in the wire parser, running
  the test suite under AddressSanitizer is strongly encouraged:

  ```sh
  cmake -DCMAKE_C_FLAGS="-fsanitize=address -g -O1" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" ..
  ```

CI runs the build and test suite on Linux, macOS, and FreeBSD against both
OpenSSL and LibreSSL, plus CodeQL static analysis, on every push and pull
request.

## License

uhub is free software, licensed under the **GNU General Public License v3** (see
[`COPYING`](COPYING)). It links against OpenSSL/LibreSSL under the terms noted in
[`COPYING.OpenSSL`](COPYING.OpenSSL).

Copyright © 2007–2026 Jan Vidar Krey and contributors (see
[`AUTHORS`](AUTHORS)).
