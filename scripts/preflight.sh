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
git diff --check HEAD || fail "whitespace errors in the working tree"

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

step "cppcheck with CI's exact arguments and version"
# Homebrew's cppcheck is a different version and does not reproduce CI's
# findings (verified: it missed the knownConditionTrueFalse CI raised on
# fd4a2d5ce). Run Ubuntu 24.04's build, natively on this machine's arch.
if ! timeout 20 docker info >/dev/null 2>&1; then
  fail "docker unresponsive: cppcheck not run. Hosted CI is then the only static-analysis evidence; record that in the push (SOP pre-push gate)"
else
  ARGS=$(awk '/^[[:space:]]+cppcheck \\$/{on=1} on{print} on&&/tools\//{exit}' "$CI" |
    sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*\\$//' -e 's/ || CPPCHECK_RC=\$?//' \
        -e 's/2>&1//' | grep -v -e '^--template' -e '^--output-file' -e '^cppcheck$' |
    tr '\n' ' ')
  case "$ARGS" in *--enable=*tools/*) ;; *) ARGS="" ;; esac
  if [ -z "$ARGS" ]; then
    fail "could not extract the cppcheck invocation from $CI"
  else
    docker image inspect kk-preflight-cppcheck:24.04 >/dev/null 2>&1 ||
      printf 'FROM ubuntu:24.04\nRUN apt-get update -qq && apt-get install -y -qq cppcheck\n' |
        docker build -q -t kk-preflight-cppcheck:24.04 - >/dev/null
    # Fail closed: a container that dies mid-run must not read as clean.
    out=$(docker run --rm -v "$PWD":/src:ro -w /src kk-preflight-cppcheck:24.04 \
      sh -c "cppcheck $ARGS --template='{file}:{line}: {severity}: {message} [{id}]' \
               >/tmp/log 2>&1; rc=\$?; grep -E '\\[[A-Za-z0-9_]+\\]\$' /tmp/log;
             echo CPPCHECK_DONE rc=\$rc" 2>&1)
    printf '%s\n' "$out" | grep -v '^CPPCHECK_DONE'
    case "$out" in
      *"CPPCHECK_DONE rc=0"*) ;;
      *CPPCHECK_DONE*) fail "cppcheck findings (zero-warning policy)" ;;
      *) fail "cppcheck did not complete (container error)" ;;
    esac
  fi
fi

step "release-report gate regressions"
python3 -m unittest scripts/test_generate_test_report.py 2>&1 | tail -1
python3 -m unittest scripts/test_generate_test_report.py >/dev/null 2>&1 ||
  fail "report gate tests"

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
