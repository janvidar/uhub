#!/usr/bin/env bash
#
# Runs the mod_javascript host test against the built plugin and the shipped
# example scripts (doc/js). Requires a build configured with
# -DJAVASCRIPT_SUPPORT=ON.
#
# Usage:  BUILD=/path/to/build  test/js/run_js_test.sh
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD=${BUILD:-$REPO/build}

TEST=$BUILD/test_mod_javascript
SO=$BUILD/mod_javascript.so

for f in "$TEST" "$SO"; do
	[ -e "$f" ] || { echo "MISSING: $f (configure with -DJAVASCRIPT_SUPPORT=ON and build first)"; exit 2; }
done

# The test writes temp fixture scripts into the cwd; run it in a scratch dir.
DIR=$(mktemp -d)
trap 'rm -rf "$DIR"' EXIT
cd "$DIR" || exit 2

"$TEST" "$SO" "$REPO/doc/js"
