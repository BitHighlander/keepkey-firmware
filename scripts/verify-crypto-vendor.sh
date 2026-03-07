#!/usr/bin/env bash
# verify-crypto-vendor.sh — Diff vendored deps/crypto/ against upstream hw-crypto
#
# Usage: ./scripts/verify-crypto-vendor.sh
#
# Clones the upstream hw-crypto repo at the pinned commit and diffs
# against our vendored copy. Exit 0 = match, exit 1 = differences found.

set -euo pipefail

UPSTREAM_REPO="https://github.com/markrypt0/hw-crypto.git"
UPSTREAM_COMMIT="34dbef959435dcab8b13e3d4776294cc762e12e5"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDORED_DIR="$REPO_ROOT/deps/crypto"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "==> Cloning hw-crypto at $UPSTREAM_COMMIT ..."
git clone --quiet --no-checkout "$UPSTREAM_REPO" "$TMPDIR/hw-crypto"
cd "$TMPDIR/hw-crypto"
git checkout --quiet "$UPSTREAM_COMMIT"

UPSTREAM_DIR="$TMPDIR/hw-crypto/crypto"

echo "==> Comparing vendored files against upstream ..."
echo ""

DIFFS=0
MATCHED=0
MISSING_UPSTREAM=0
EXTRA_VENDORED=0

# Check each vendored file against upstream
while IFS= read -r vfile; do
    relpath="${vfile#$VENDORED_DIR/}"

    # Skip non-source files
    case "$relpath" in
        CMakeLists.txt|PROVENANCE.md) continue ;;
    esac

    upstream_file="$UPSTREAM_DIR/$relpath"

    if [ ! -f "$upstream_file" ]; then
        echo "  EXTRA (not in upstream): $relpath"
        EXTRA_VENDORED=$((EXTRA_VENDORED + 1))
    elif ! diff -q "$vfile" "$upstream_file" > /dev/null 2>&1; then
        echo "  DIFFERS: $relpath"
        diff -u "$upstream_file" "$vfile" --label "upstream/$relpath" --label "vendored/$relpath" | head -30
        echo "  ..."
        DIFFS=$((DIFFS + 1))
    else
        MATCHED=$((MATCHED + 1))
    fi
done < <(find "$VENDORED_DIR" -type f \( -name '*.c' -o -name '*.h' -o -name '*.table' \) | sort)

# Check for upstream files we intentionally stripped
echo ""
echo "==> Upstream files not vendored (intentionally stripped):"
while IFS= read -r ufile; do
    relpath="${ufile#$UPSTREAM_DIR/}"
    vendored_file="$VENDORED_DIR/$relpath"
    if [ ! -f "$vendored_file" ]; then
        echo "  STRIPPED: $relpath"
        MISSING_UPSTREAM=$((MISSING_UPSTREAM + 1))
    fi
done < <(find "$UPSTREAM_DIR" -type f \( -name '*.c' -o -name '*.h' -o -name '*.table' \) | sort)

echo ""
echo "==> Results:"
echo "  Matched:   $MATCHED"
echo "  Differs:   $DIFFS"
echo "  Extra:     $EXTRA_VENDORED (vendored but not in upstream)"
echo "  Stripped:  $MISSING_UPSTREAM (upstream but intentionally not vendored)"

if [ "$DIFFS" -gt 0 ] || [ "$EXTRA_VENDORED" -gt 0 ]; then
    echo ""
    echo "WARNING: Vendored crypto does not exactly match upstream."
    echo "Review differences above. Intentional modifications should be"
    echo "documented in deps/crypto/PROVENANCE.md."
    exit 1
else
    echo ""
    echo "OK: All vendored files match upstream hw-crypto at $UPSTREAM_COMMIT"
    exit 0
fi
