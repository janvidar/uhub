#!/usr/bin/env bash
#
# Build a complete uhub source archive: the superproject plus the contents of
# every git submodule.
#
# GitHub's auto-generated "Source code (zip/tar.gz)" release assets are a plain
# `git archive` of the superproject. Submodules are gitlinks, not files, so
# those assets can never contain third_party/exotic or third_party/quickjs --
# which leaves them unbuildable. This script produces the archive that gets
# attached to the release instead.
#
#   Usage: scripts/make-dist.sh [ref]        (ref defaults to HEAD)
#   Output: dist/uhub-<version>-src.{tar.gz,zip} and dist/SHA256SUMS
#
# Works with either GNU tar or bsdtar (macOS); the released artifacts are built
# by .github/workflows/release.yml on Linux, so byte-identical output is only
# promised for repeated runs on the same host.

set -euo pipefail

die()  { printf 'make-dist: error: %s\n' "$*" >&2; exit 1; }
note() { printf 'make-dist: %s\n' "$*" >&2; }

REF=${1:-HEAD}

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || die "not inside a git repository"
cd "$ROOT"

COMMIT=$(git rev-parse --verify --quiet "$REF^{commit}") || die "no such ref: $REF"

# Name the archive after the tag when building one, and after a describe-style
# string otherwise, so test runs from a branch are still self-identifying.
# DIST_VERSION overrides both, which is what the release workflow uses so the
# artifact name cannot drift from the tag being released.
if [ -n "${DIST_VERSION:-}" ]; then
	VER=$DIST_VERSION
elif VER=$(git describe --exact-match --tags "$COMMIT" 2>/dev/null); then
	:
elif VER=$(git describe --tags --always "$COMMIT" 2>/dev/null); then
	:
else
	VER=$(git rev-parse --short "$COMMIT")
fi

P="uhub-${VER}-src"
OUT="$ROOT/dist"
EPOCH=$(git log -1 --format=%ct "$COMMIT")

# GNU tar and bsdtar spell the reproducibility options differently and neither
# is guaranteed to be the one called "tar", so pick deliberately.
TAR="" TAR_FLAVOR=""
for cand in gtar tar; do
	command -v "$cand" >/dev/null 2>&1 || continue
	ver=$("$cand" --version 2>/dev/null | head -1) || ver=""
	case "$ver" in
		*"GNU tar"*) TAR=$cand TAR_FLAVOR=gnu; break ;;
		*bsdtar*)    [ -n "$TAR" ] || { TAR=$cand TAR_FLAVOR=bsd; } ;;
	esac
done
[ -n "$TAR" ] || die "no GNU tar or bsdtar found in PATH"
command -v zip >/dev/null 2>&1 || die "zip not found in PATH"

stage=$(mktemp -d)
work=$(mktemp -d)
trap 'rm -rf "$stage" "$work"' EXIT

included=()

# archive_tree <repo-dir> <commit> <prefix>
#
# Extract <commit> of <repo-dir> into the staging tree under $P/<prefix>, then
# recurse into every gitlink that commit records. The gitlinks are read out of
# the tree rather than out of the working copy, so the archive always matches
# the tagged commit even when the checkout sits on another branch.
archive_tree() {
	local repo=$1 commit=$2 pfx=$3
	local mode type sha path name update sub gmfile

	git -C "$repo" archive --prefix="$P/$pfx" "$commit" | "$TAR" -x -C "$stage"

	# Kept outside the staging tree (it must not end up in the archive) and
	# uniquely named, since this function recurses and each level needs its own.
	gmfile=$(mktemp "$work/gitmodules.XXXXXX")
	git -C "$repo" show "$commit:.gitmodules" >"$gmfile" 2>/dev/null || : >"$gmfile"

	while read -r mode type sha path; do
		[ "$type" = commit ] || continue

		# A submodule the parent marks `update = none` is an opt-in extra, not a
		# build dependency: quickjs pulls in the ~50k-file test262 conformance
		# suite that way. Skip those instead of bloating the release with them.
		name=$(git config -f "$gmfile" --get-regexp '^submodule\..*\.path$' 2>/dev/null \
			| awk -v p="$path" '$2 == p { print $1 }' \
			| sed -e 's/^submodule\.//' -e 's/\.path$//') || name=""
		update=""
		[ -n "$name" ] && update=$(git config -f "$gmfile" --get "submodule.$name.update" 2>/dev/null || true)
		if [ "$update" = none ]; then
			note "skipping ${pfx}${path} (update = none)"
			continue
		fi

		sub="$repo/$path"
		[ -e "$sub/.git" ] ||
			die "submodule ${pfx}${path} is not checked out. Run: git submodule update --init --recursive"
		git -C "$sub" cat-file -e "$sha^{commit}" 2>/dev/null ||
			die "submodule ${pfx}${path} does not have commit $sha. Run: git submodule update --init --recursive"

		included+=("${pfx}${path}")
		archive_tree "$sub" "$sha" "${pfx}${path}/"
	done < <(git -C "$repo" ls-tree -r "$commit")

	rm -f "$gmfile"
}

note "building $P from $COMMIT"
archive_tree "$ROOT" "$COMMIT" ""

# git archive substitutes .uhub-archive-version via export-subst, but only when
# the commit is described by a tag. Stamp the version we actually built so a
# tarball build always reports it (see UHUB_REVISION in CMakeLists.txt).
printf '%s\n' "$VER" >"$stage/$P/.uhub-archive-version"

# The bug this script exists to prevent: an archive that is missing a submodule.
for sm in ${included+"${included[@]}"}; do
	[ -n "$(ls -A "$stage/$P/$sm" 2>/dev/null)" ] || die "submodule $sm came out empty"
	note "included $sm"
done

# Normalise ownership and timestamps so repeated runs produce identical bytes.
# -depth so directories are stamped after their contents.
if TS=$(date -u -r "$EPOCH" +%Y%m%d%H%M.%S 2>/dev/null); then
	:
else
	TS=$(date -u -d "@$EPOCH" +%Y%m%d%H%M.%S)
fi
find "$stage/$P" -depth -exec touch -h -t "$TS" {} +

mkdir -p "$OUT"
rm -f "$OUT/$P.tar.gz" "$OUT/$P.zip"

# ustar deliberately: it carries no extended headers, so there is no atime/ctime
# to leak into the output and both tar flavors emit the same bytes. The longest
# path in the archive is well inside ustar's limit.
case "$TAR_FLAVOR" in
gnu)
	"$TAR" --format=ustar --sort=name --owner=0 --group=0 --numeric-owner \
		-cf - -C "$stage" "$P" | gzip -9n >"$OUT/$P.tar.gz"
	;;
bsd)
	# bsdtar has no --sort, so feed it an explicitly sorted list and stop it
	# from also recursing into the directories in that list (-n).
	( cd "$stage" && find "$P" | LC_ALL=C sort |
		"$TAR" --format=ustar -n --uid 0 --gid 0 --uname '' --gname '' \
			-cf - -T - ) | gzip -9n >"$OUT/$P.tar.gz"
	;;
esac

( cd "$stage" && find "$P" | LC_ALL=C sort | zip -q -X -@ "$OUT/$P.zip" )

( cd "$OUT" && if command -v sha256sum >/dev/null 2>&1; then
	sha256sum "$P.tar.gz" "$P.zip"
else
	shasum -a 256 "$P.tar.gz" "$P.zip"
fi >SHA256SUMS )

note "wrote:"
ls -l "$OUT/$P.tar.gz" "$OUT/$P.zip" "$OUT/SHA256SUMS" >&2
