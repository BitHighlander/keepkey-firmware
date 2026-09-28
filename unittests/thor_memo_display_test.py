#!/usr/bin/env python3
"""Compile the real THORChain memo parser with captured confirmation pages.

No firmware dependencies or device required. This checks C display strings and
cancellation, not OLED layout or transaction signing. Run from any directory.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "lib/firmware/thorchain.c").read_text()
# Keep the production helper/parser bodies verbatim; replace only the UI and
# unrelated firmware dependencies. Missing markers fail instead of skipping.
helpers = source[source.index("/* THORChain swap memo limits"):
                 source.index("static CONFIDENTIAL HDNode node;")]
parser = source[source.index("static bool thorchain_memo_has_canonical_separators("):]
harness = r"""
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#define memzero(p,n) memset(p,0,n)
#define ButtonRequestType_ButtonRequest_ConfirmOutput 0
typedef enum { THORCHAIN_MEMO_CONFIRMED=0, THORCHAIN_MEMO_UNPARSED,
               THORCHAIN_MEMO_CANCELLED } ThorchainMemoResult;
static char screens[16][512];
static int count, cancel_at;
static bool confirm(int kind, const char *title, const char *fmt, ...) {
  (void)kind; (void)title;
  assert(count < 16);
  va_list args; va_start(args,fmt);
  int written = vsnprintf(screens[count], sizeof(screens[count]), fmt, args);
  va_end(args);
  assert(written >= 0 && (size_t)written < sizeof(screens[count]));
  return count++ != cancel_at;
}
static bool thorchain_confirm_full_memo(const char *title, const char *memo, size_t len) {
 (void)title; (void)memo; (void)len; return true;
}
"""
tests = r"""
static ThorchainMemoResult run(const char *memo, int cancel) {
  char input[257], original[257]; size_t n = strlen(memo);
  assert(n <= 256); memcpy(input,memo,n); memcpy(original,memo,n);
  count=0; cancel_at=cancel;
  ThorchainMemoResult r=thorchain_parseConfirmMemo(input,n);
  assert(memcmp(input,original,n)==0); return r;
}
int main(void) {
  const char *incident="=:ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7:0x27de622cc44c55b53caF299eCedccdAB29aC98A8:298628231219:keep:30";
  assert(run(incident,-1)==THORCHAIN_MEMO_CONFIRMED);
  assert(strcmp(screens[1],"Confirm to 0x27de622cc44c55b53caF299eCedccdAB29aC98A8")==0);
  assert(strcmp(screens[2],"Minimum output 2986.28231219 USDT")==0);
  assert(strcmp(screens[3],"Affiliate fee 30 bps to keep")==0);
  assert(count==4);
  const char *cases[][2]={
    {"1","Minimum output 0.00000001 USDT"},
    {"100000000","Minimum output 1 USDT"},
    {"1e8","Minimum output 1 USDT"},
    {"1234E6","Minimum output 12.34 USDT"},
    {"298628231219","Minimum output 2986.28231219 USDT"},
    {"1e20","Confirm limit 1e20"},
    {"1e","Confirm limit 1e"},
    {"1/1","Confirm limit 1/1"},
  };
  for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
    char memo[256]; snprintf(memo,sizeof(memo),"=:ETH.USDT:dest:%s",cases[i][0]);
    assert(run(memo,-1)==THORCHAIN_MEMO_CONFIRMED);
    assert(strcmp(screens[2],cases[i][1])==0);
  }
  const char *stream="=:ETH.USDT:dest:298628231219/1/0:keep:30";
  assert(run(stream,-1)==THORCHAIN_MEMO_CONFIRMED);
  assert(strcmp(screens[2],"Minimum output 2986.28231219 USDT")==0);
  assert(strcmp(screens[3],"Streaming interval 1 blocks")==0);
  assert(strcmp(screens[4],"Streaming swaps: network chooses")==0);
  assert(strcmp(screens[5],"Affiliate fee 30 bps to keep")==0);
  for(int i=0;i<6;i++) assert(run(stream,i)==THORCHAIN_MEMO_CANCELLED);
  assert(run("=:ETH.USDT:dest:1e8/0/5",-1)==THORCHAIN_MEMO_CONFIRMED);
  assert(strcmp(screens[4],"Streaming swaps: 5")==0);
  assert(run("=:ETH.USDT:dest::keep:30",-1)==THORCHAIN_MEMO_CONFIRMED);
  assert(strcmp(screens[2],"Confirm limit none")==0);
  puts("PASS: exact incident, eight limit formats, streaming and cancellation");
}
"""
with tempfile.TemporaryDirectory(prefix="thor-memo-display-") as tmp:
    c = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    c.write_text(harness + helpers + parser + tests)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                    "-Werror", "-fsanitize=address,undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
