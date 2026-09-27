#!/bin/sh
# Mirror CI Stage-1 locally before any push. A red Stage-1 job skips the whole
# CI build graph, so every check here costs a full hosted round when missed.
# Exit status is non-zero if any check fails; each check says what to fix.
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2
CI=.github/workflows/ci.yml
failed=0
fail() { printf 'FAIL: %s\n' "$1"; failed=1; }
step() { printf '== %s\n' "$1"; }

step "whitespace (git diff --check)"
python3 -B scripts/preflight_checks.py whitespace ||
  fail "whitespace in push range/worktree (set PREFLIGHT_BASE when no upstream exists)"

step "submodules pinned and clean"
# Local qualification must run the pinned dependencies CI runs. A dirty or
# moved submodule makes a local pass describe a tree CI never builds.
if git submodule status | grep -q '^[-+U]'; then
  git submodule status | grep '^[-+U]'
  fail "submodule not at its pinned commit (or not initialised)"
fi
for path in $(git config --file .gitmodules --get-regexp path | awk '{print $2}'); do
  if [ -e "$path/.git" ] && [ -n "$(git -C "$path" status --porcelain)" ]; then
    fail "submodule $path has uncommitted changes"
  fi
done

step "duplicate nanopb options"
for f in $(git ls-files '*.options'); do
  awk -v f="$f" '
    { sub(/#.*/, "") }
    NF >= 2 { for (i = 2; i <= NF; i++) { split($i, kv, ":"); k = $1 " " kv[1];
      if (k in seen) { printf "%s:%d duplicates line %d (%s)\n", f, NR, seen[k], k; bad = 1 }
      else seen[k] = NR } }
    END { exit bad }' "$f" || fail "duplicate option in $f"
done

step "every unit test file is built"
python3 -B scripts/preflight_checks.py sources || fail "unit-test CMake source graph"

step "clang-format 20 (CI pins 20)"
CF=""
for c in clang-format-20 /opt/homebrew/opt/llvm@20/bin/clang-format clang-format; do
  if command -v "$c" >/dev/null 2>&1 && "$c" --version | grep -q ' 20\.'; then
    CF=$c; break
  fi
done
if [ -z "$CF" ]; then
  fail "clang-format 20 not found (brew install llvm@20)"
else
  for f in $(find include/keepkey lib/firmware lib/board lib/transport/src \
             \( -name '*.c' -o -name '*.h' \) 2>/dev/null | grep -v generated | grep -v '.pb.'); do
    "$CF" --style=file --dry-run --Werror "$f" 2>/dev/null ||
      fail "clang-format: $f"
  done
fi

step "shared cppcheck invocation regressions"
python3 -B -m unittest scripts/test_preflight_cppcheck.py scripts/test_preflight_checks.py || fail "cppcheck invocation tests"

step "cppcheck with CI's pinned package and shared arguments"
if ! python3 -B scripts/preflight_checks.py docker; then
  fail "docker unresponsive: cppcheck not run"
else
  version=$(cat scripts/cppcheck-version)
  case "$version" in ''|*[!0-9a-zA-Z.+:~-]*) fail "invalid cppcheck package pin" ;;
  *)
    image="kk-preflight-cppcheck:$version"
    mkdir -p .cppcheck-build || fail "cannot create cppcheck mount point"
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      printf 'FROM ubuntu:24.04\nARG CPPCHECK_VERSION\nRUN apt-get update -qq && apt-get install -y -qq cppcheck="$CPPCHECK_VERSION"\n' |
        docker build -q --build-arg "CPPCHECK_VERSION=$version" -t "$image" - >/dev/null ||
        fail "cannot build pinned cppcheck image"
    fi
    # The shared entry point verifies package AND executable versions on every
    # run, including cached images, and supplies argv directly without eval.
    rc=0
    docker run --rm -v "$PWD":/src:ro --tmpfs /src/.cppcheck-build -w /src "$image" \
      sh -c 'rc=0; sh scripts/cppcheck.sh /tmp/cppcheck-report.txt || rc=$?;
             if [ -f /tmp/cppcheck-report.txt ]; then cat /tmp/cppcheck-report.txt; fi;
             exit "$rc"' || rc=$?
    [ "$rc" -eq 0 ] || fail "cppcheck did not complete cleanly (exit $rc)"
    ;;
  esac
fi

step "release-report gate regressions"
# Execute once; preserve both diagnostics and the status of that invocation.
python3 -B -m unittest scripts/test_generate_test_report.py || fail "report gate tests"

step "workflow lint"
if command -v actionlint >/dev/null 2>&1; then
  actionlint "$CI" || fail "actionlint"
else
  fail "actionlint not installed (brew install actionlint)"
fi

if [ "$failed" -ne 0 ]; then
  printf '\npreflight: FAILED. Fix before pushing.\n'
  exit 1
fi
printf '\npreflight: all Stage-1 mirrors passed.\n'
