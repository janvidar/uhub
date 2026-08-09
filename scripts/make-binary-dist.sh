#!/usr/bin/env bash
#
# Build a self-contained binary package for one platform.
#
# The zig build statically links LibreSSL (a build.zig.zon dependency) and the
# vendored SQLite, so the result has no runtime dependencies beyond libc, and
# zig cross-compiles every supported platform from any host.
#
#   Usage: scripts/make-binary-dist.sh <platform> [version]
#   Platforms: linux-x86_64 linux-aarch64 macos-x86_64 macos-aarch64 windows-x86_64
#   Output: dist/uhub-<version>-<platform>.tar.gz (.zip on Windows)
#
# The package is relocatable: unpack anywhere and run `bin/uhub -c etc/uhub.conf`
# from the package root. The configs shipped in etc/ are the ones from doc/ with
# their /usr/lib/uhub and /etc/uhub paths rewritten to package-relative ones.

set -euo pipefail

die()  { printf 'make-binary-dist: error: %s\n' "$*" >&2; exit 1; }
note() { printf 'make-binary-dist: %s\n' "$*" >&2; }

PLATFORM=${1:-}
[ -n "$PLATFORM" ] || die "usage: $0 <platform> [version]"

# Platform name -> zig target. The glibc pin matters: without it zig targets the
# build host's glibc and the binary refuses to start on older distributions.
# 2.28 is RHEL 8 / Debian 10 era, which covers anything still receiving updates.
case "$PLATFORM" in
	linux-x86_64)   ZIG_TARGET=x86_64-linux-gnu.2.28 ;;
	linux-aarch64)  ZIG_TARGET=aarch64-linux-gnu.2.28 ;;
	macos-x86_64)   ZIG_TARGET=x86_64-macos ;;
	macos-aarch64)  ZIG_TARGET=aarch64-macos ;;
	windows-x86_64) ZIG_TARGET=x86_64-windows-gnu ;;
	*) die "unknown platform: $PLATFORM" ;;
esac

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || die "not inside a git repository"
cd "$ROOT"

command -v zig >/dev/null 2>&1 || die "zig not found in PATH"

# GNU tar and bsdtar spell the reproducibility options differently; pick
# deliberately, as scripts/make-dist.sh does.
TAR="" TAR_FLAVOR=""
for cand in gtar tar; do
	command -v "$cand" >/dev/null 2>&1 || continue
	tv=$("$cand" --version 2>/dev/null | head -1) || tv=""
	case "$tv" in
		*"GNU tar"*) TAR=$cand TAR_FLAVOR=gnu; break ;;
		*bsdtar*)    [ -n "$TAR" ] || { TAR=$cand TAR_FLAVOR=bsd; } ;;
	esac
done
[ -n "$TAR" ] || die "no GNU tar or bsdtar found in PATH"

if [ -n "${2:-}" ]; then
	VER=$2
elif VER=$(git describe --exact-match --tags HEAD 2>/dev/null); then
	:
elif VER=$(git describe --tags --always HEAD 2>/dev/null); then
	:
else
	VER=$(git rev-parse --short HEAD)
fi

P="uhub-${VER}-${PLATFORM}"
OUT="$ROOT/dist"
EPOCH=$(git log -1 --format=%ct HEAD)

stage=$(mktemp -d)
prefix=$(mktemp -d)
trap 'rm -rf "$stage" "$prefix"' EXIT

# ReleaseSafe rather than ReleaseFast: this is a network daemon parsing
# attacker-controlled bytes before authentication, and a detected overflow
# aborting the process beats it being exploitable. -Dtests=false because the
# autotest binary is not part of a binary distribution (and does not build for
# Windows at all).
note "building $P ($ZIG_TARGET)"
zig build \
	-Dtarget="$ZIG_TARGET" \
	-Doptimize=ReleaseSafe \
	-Drelease=true \
	-Dtests=false \
	-Dstrip=true \
	--prefix "$prefix"

pkg="$stage/$P"
mkdir -p "$pkg/bin" "$pkg/lib" "$pkg/etc" "$pkg/doc"

# Copy whatever the target actually produced rather than a fixed list: uhub-admin
# and the plugins are POSIX-only, and Windows additionally emits .pdb files that
# have no place in a release package.
for f in "$prefix"/bin/*; do
	case "$f" in *.pdb) continue ;; esac
	[ -f "$f" ] && cp "$f" "$pkg/bin/"
done
for f in "$prefix"/lib/*; do
	case "$f" in *.pdb) continue ;; esac
	[ -f "$f" ] && cp "$f" "$pkg/lib/"
done
[ -n "$(ls -A "$pkg/bin")" ] || die "no binaries were produced for $ZIG_TARGET"

# Rewrite the shipped configs for a relocatable layout. Plugin names lose their
# extension so the same file works on Windows: the loader appends the platform's
# own (see plugin_add_extension in src/core/pluginloader.c).
# -E throughout: BSD sed (macOS) has no \? or \+ in basic regexes, and this
# script is meant to run on a developer's machine as well as in CI.
sed -E -e 's|^([[:space:]]*#?[[:space:]]*plugin[[:space:]]+)/usr/lib/uhub/|\1|' \
	-e 's|^([[:space:]]*#?[[:space:]]*plugin[[:space:]]+[A-Za-z0-9_]+)\.so|\1|' \
	-e 's|/etc/uhub/|etc/|g' \
	-e 's|/var/log/uhub\.log|uhub.log|g' \
	doc/plugins.conf >"$pkg/etc/plugins.conf.body"
{
	echo "# Plugin directory for this package. Paths here are relative to the"
	echo "# directory uhub is started from, which is meant to be the directory"
	echo "# this file's package was unpacked into."
	echo "plugin_dir lib"
	echo
	cat "$pkg/etc/plugins.conf.body"
} >"$pkg/etc/plugins.conf"
rm -f "$pkg/etc/plugins.conf.body"

sed -e 's|/etc/uhub/|etc/|g' doc/uhub.conf >"$pkg/etc/uhub.conf"
cp doc/users.conf "$pkg/etc/users.conf"
cp doc/rules.txt  "$pkg/etc/rules.txt"
if [ -f doc/motd.txt ]; then
	cp doc/motd.txt "$pkg/etc/motd.txt"
else
	printf 'Welcome to this uhub server.\n' >"$pkg/etc/motd.txt"
fi

cp README.md COPYING COPYING.OpenSSL AUTHORS ChangeLog "$pkg/"
cp doc/getstarted.txt doc/uhub.1 doc/uhub-passwd.1 "$pkg/doc/"

# Verify the rewrite actually produced a relocatable config: a leftover absolute
# path would only surface as a confusing runtime failure for whoever unpacks it.
if grep -qE '^[[:space:]]*(plugin|plugin_dir|file_acl|file_plugins)[[:space:]=]+/' \
	"$pkg/etc/plugins.conf" "$pkg/etc/uhub.conf"; then
	grep -nE '^[[:space:]]*(plugin|plugin_dir|file_acl|file_plugins)[[:space:]=]+/' \
		"$pkg/etc/plugins.conf" "$pkg/etc/uhub.conf" >&2
	die "config still contains absolute paths after rewriting"
fi

cat >"$pkg/RUNNING.txt" <<EOF
uhub $VER -- $PLATFORM

Everything here is self-contained: TLS (LibreSSL) and SQLite are linked in, so
there is nothing else to install.

Quick start, from this directory:

    bin/uhub -c etc/uhub.conf

The paths in etc/uhub.conf and etc/plugins.conf are relative to the directory
uhub is started from, so run it from here, or edit them to absolute paths if you
would rather install it somewhere permanent.

Register an operator account first (mod_auth_sqlite is enabled by default):

    bin/uhub-passwd etc/users.db create
    bin/uhub-passwd etc/users.db add <nick> <password> admin

These binaries are not code-signed.

  macOS: the system quarantines anything downloaded from a browser, so the first
  run is refused with "cannot be opened because the developer cannot be
  verified". Clear the quarantine flag on the unpacked directory:

      xattr -dr com.apple.quarantine .

  Windows: SmartScreen may warn that the publisher is unknown. Choose
  "More info" -> "Run anyway".

Verify what you downloaded against the SHA256SUMS file on the release page
before doing either.
EOF

# Normalise timestamps so repeated builds of the same commit package identically.
if TS=$(date -u -r "$EPOCH" +%Y%m%d%H%M.%S 2>/dev/null); then
	:
else
	TS=$(date -u -d "@$EPOCH" +%Y%m%d%H%M.%S)
fi
find "$pkg" -depth -exec touch -h -t "$TS" {} +

mkdir -p "$OUT"
case "$PLATFORM" in
windows-*)
	rm -f "$OUT/$P.zip"
	( cd "$stage" && find "$P" | LC_ALL=C sort | zip -q -X -@ "$OUT/$P.zip" )
	note "wrote $OUT/$P.zip"
	;;
*)
	rm -f "$OUT/$P.tar.gz"
	case "$TAR_FLAVOR" in
	gnu)
		"$TAR" --format=ustar --sort=name --owner=0 --group=0 --numeric-owner \
			-cf - -C "$stage" "$P" | gzip -9n >"$OUT/$P.tar.gz"
		;;
	bsd)
		( cd "$stage" && find "$P" | LC_ALL=C sort |
			"$TAR" --format=ustar -n --uid 0 --gid 0 --uname '' --gname '' \
				-cf - -T - ) | gzip -9n >"$OUT/$P.tar.gz"
		;;
	esac
	note "wrote $OUT/$P.tar.gz"
	;;
esac
