#!/usr/bin/env python3
"""Test authorized Monero watch-key export in an anonymous native emulator."""
import argparse
import ctypes
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unicodedata

from test_wire import (Session, Checks, failure, fields, only, fv, fb,
                       load_wallet, expected_address, PUBLIC_FIXTURES, sha)

HERE = Path(__file__).resolve().parent


def helper_crypto(core, cases, out):
    """Independent known answers through the actual private-export helper."""
    parent = HERE.parent
    spec = importlib.util.spec_from_file_location("watch_primitives", parent / "run.py")
    primitives = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(primitives)
    entries = []
    for case in cases:
        for network in [0, 1, 2]:
            key = ",".join("0x" + case["key_seed"][i:i + 2] for i in range(0, 64, 2))
            watch = ",".join("0x" + case["view_secret"][i:i + 2] for i in range(0, 64, 2))
            entries.append("{ {" + key + "}, " + str(network) + "u, {" + watch
                           + "}, " + json.dumps(expected_address(case, network, core)) + "}")
    directory = out / "helper"
    directory.mkdir()
    driver = directory / "check.c"
    driver.write_text('''#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "watch-key.h"
static unsigned checks;
#define CHECK(x) do { ++checks; if(!(x)){fprintf(stderr,"line %d\\n",__LINE__);return 1;} }while(0)
static int zero(const void *p,size_t n){const uint8_t *b=p;uint8_t a=0;while(n--)a|=*b++;return a==0;}
void random_buffer(uint8_t *p,size_t n){(void)p;(void)n;abort();}
struct fixture {uint8_t node[32];uint32_t network;uint8_t watch[32];char address[96];};
static const struct fixture fixtures[]={
''' + ",\n".join(entries) + '''
};
int main(void){
 uint8_t watch[32],key[32]={0};char address[96];
 for(size_t i=0;i<sizeof(fixtures)/sizeof(fixtures[0]);++i){
  const struct fixture *v=&fixtures[i];
  CHECK(monero_research_get_watch_key(v->node,v->network,watch,address));
  CHECK(!memcmp(watch,v->watch,32));CHECK(!memcmp(address,v->address,96));
 }
 memset(watch,0xa5,sizeof(watch));memset(address,0xa5,sizeof(address));
 CHECK(!monero_research_get_watch_key(key,0,watch,address));
 CHECK(zero(watch,sizeof(watch)));CHECK(zero(address,sizeof(address)));
 CHECK(!monero_research_get_watch_key(fixtures[0].node,3,watch,address));
 CHECK(zero(watch,sizeof(watch)));CHECK(zero(address,sizeof(address)));
 CHECK(!monero_research_get_watch_key(NULL,0,watch,address));
 CHECK(!monero_research_get_watch_key(fixtures[0].node,0,NULL,address));
 CHECK(!monero_research_get_watch_key(fixtures[0].node,0,watch,NULL));
 printf("{\\"status\\":\\"pass\\",\\"cases\\":12,\\"checks\\":%u}\\n",checks);return 0;
}
''')
    executable = directory / "check"
    command = ["cc", "-std=gnu99", "-Os", "-fsanitize=address,undefined",
               "-fno-omit-frame-pointer", "-DEMULATOR", "-DBITCOIN_ONLY=0",
               "-DKK_MONERO_EMULATOR_RESEARCH=1", "-DUSE_MONERO=1",
               *["-D" + d for d in primitives.DEFINES], "-I", str(HERE),
               "-I", str(primitives.CRYPTO), str(driver),
               str(HERE / "watch-key.c"), str(HERE / "monero_research.c"),
               *[str(primitives.CRYPTO / source) for source in primitives.COMMON + primitives.MONERO],
               "-o", str(executable)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (directory / "build.log").write_text(json.dumps(command) + "\n" + result.stdout)
    if result.returncode:
        raise RuntimeError("watch helper sanitizer build failed; see helper/build.log")
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0", UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    result = subprocess.run([str(executable)], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (directory / "run.log").write_text(result.stdout)
    if result.returncode:
        raise RuntimeError("watch helper sanitizer checks failed; see helper/run.log")
    return json.loads(result.stdout)


def request(account=0, network=0, path=None):
    path = [0x8000002c, 0x80000080, 0x80000000 | account] if path is None else path
    return b"".join(fv(1, part) for part in path) + fv(2, network)


def public_passphrase_case(core, fixture, passphrase):
    sentence = unicodedata.normalize("NFKD", PUBLIC_FIXTURES[fixture]).encode()
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode()
    seed = hashlib.pbkdf2_hmac("sha512", sentence, salt, 2048)
    result = hmac.new(b"ed25519 seed", seed, "sha512").digest()
    key, chain = result[:32], result[32:]
    for n in [44, 128, 0]:
        result = hmac.new(chain, b"\0" + key + (n | 0x80000000).to_bytes(4, "big"), "sha512").digest()
        key, chain = result[:32], result[32:]
    spend = core.op("reduce", key)
    view = core.hs(spend)
    return {"major": 0, "minor": 0, "view_secret": view.hex(),
            "sub_spend_public": core.op("base", spend).hex(),
            "sub_view_public": core.op("base", view).hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--reference", type=Path, default=HERE.parent / "evidence/2026-11-04-interoperability/host.json")
    parser.add_argument("--core-library", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expect-unsupported", action="store_true")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    checks = Checks()
    if args.expect_unsupported:
        s = Session(args.library.resolve(), out, "ordinary-watch")
        try:
            msg, _, _ = s.rpc(542, request())
            failure(checks, "ordinary-build-refuses-watch-key", msg, [1])
            msg, _, _ = s.rpc(55)
            checks.record("ordinary-build-status-transport-recovers", msg[0] == 17)
        finally:
            s.close()
        (out / "result.json").write_text(json.dumps({"status": "pass", "checks": checks.items}, indent=2) + "\n")
        return
    reference = json.loads(args.reference.read_text())
    if "reference" in reference:
        reference = reference["reference"]
    if reference["fixture_mnemonics_public"] != PUBLIC_FIXTURES:
        parser.error("only fixed public disposable fixtures are supported")
    spec = importlib.util.spec_from_file_location("watch_reference", HERE.parent / "reference.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    core = module.Core(args.core_library.resolve())
    module.known_anchors(core)
    cases = [c for c in reference["cases"] if c["major"] == c["minor"] == c["output_index"] == 0]
    helper = helper_crypto(core, cases, out)
    sessions = []

    def new(label):
        session = Session(args.library.resolve(), out, label)
        sessions.append(session)
        return session

    def verify_export(label, session, message, case, network, events=None, screens=None):
        parsed = fields(message[1]) if message and message[0] == 543 else {}
        key = only(parsed, 1, b"")
        address = only(parsed, 2, b"")
        checks.record(label + "-exact-credentials", message is not None and message[0] == 543
                      and len(key) == 32 and key.hex() == case["view_secret"]
                      and address.decode() == expected_address(case, network, core),
                      address=address.decode(), view_key_sha256=sha(key))
        checks.record(label + "-fragmented-watch-response", message[2] == 3)
        checks.record(label + "-derived-node-scrubbed", session.derived_node_zero())
        # Inspect the owned response arena under the actual firmware lock.
        size = ctypes.c_size_t()
        lib = session.lib
        lib.fsm_test_responseArena.argtypes = [ctypes.POINTER(ctypes.c_size_t)]
        lib.fsm_test_responseArena.restype = ctypes.c_void_p
        until = time.monotonic() + 2
        while not lib.kkemu_trylock():
            if time.monotonic() > until:
                raise RuntimeError("response-arena scrub observer could not acquire lock")
            time.sleep(.001)
        try:
            ptr = lib.fsm_test_responseArena(ctypes.byref(size))
            arena = ctypes.string_at(ptr, size.value)
            checks.record(label + "-watch-key-scrubbed-from-response-arena", key not in arena)
        finally:
            lib.kkemu_unlock()
        if events is not None:
            checks.record(label + "-fresh-consent-required", events.count(26) >= 4)
        if screens is not None:
            checks.record(label + "-privacy-warning", any("incoming Monero transactions" in x["body"]
                          and "cannot spend funds" in x["body"] for x in screens))
            checks.record(label + "-bound-wallet-reviewed", any("Export view key" in x["body"]
                          and "Monero " in x["body"] for x in screens))

    s = new("watch-abandon")
    try:
        msg, _, _ = s.rpc(542, request())
        failure(checks, "watch-missing-seed-refused", msg, [11])
        load_wallet(s, checks, "abandon")
        for label, payload in [
            ("empty-path", request(path=[])),
            ("wrong-purpose", request(path=[0x8000002d, 0x80000080, 0x80000000])),
            ("wrong-coin", request(path=[0x8000002c, 0x80000081, 0x80000000])),
            ("unhardened-account", request(path=[0x8000002c, 0x80000080, 0])),
            ("too-long-path", request(path=[0x8000002c, 0x80000080, 0x80000000, 0x80000000])),
            ("bad-network", request(network=3)),
            ("truncated-protobuf", b"\x08\x80"),
        ]:
            msg, events, _ = s.rpc(542, payload)
            failure(checks, "watch-" + label, msg, [1, 3])
            checks.record("watch-" + label + "-no-consent-prompt", 26 not in events)

        # Open the first export without delivering any affirmative decision.
        s.send(542, request())
        first = s.receive()
        checks.record("watch-starts-with-consent", first is not None and first[0] == 26)
        screen = s.observe_screen("watch-held-consent")
        checks.record("watch-no-private-node-held-during-consent", s.derived_node_zero(parked=True))
        checks.record("watch-privacy-warning-before-export", "incoming Monero transactions" in screen["body"])
        checks.record("watch-not-exported-before-ack", s.receive(.04) is None)
        s.send(27)
        checks.record("watch-button-ack-is-not-consent", s.receive(.04) is None)
        s.send(100, fv(1, 1), iface=1)
        held_screens = [screen]
        events = [26]
        for _ in range(64):
            terminal = s.receive()
            if not terminal:
                raise RuntimeError("watch export timed out")
            events.append(terminal[0])
            if terminal[0] != 26:
                break
            held_screens.append(s.approve_button("watch-approve-wallet"))
        case = next(c for c in cases if c["label"] == "abandon-account0-sub0-0-output0")
        verify_export("watch-first", s, terminal, case, 0, events, held_screens)
        for fixture in ["abandon", "trezor"]:
            if fixture != "abandon":
                s.close()
                s = new("watch-" + fixture)
                load_wallet(s, checks, fixture)
            fixture_cases = [c for c in cases if c["label"].startswith(fixture + "-")]
            for c in fixture_cases:
                account = int(c["label"].split("-account")[1].split("-")[0])
                for network in [0, 1, 2]:
                    msg, ev, screens = s.rpc(542, request(account, network))
                    verify_export(f"watch-{fixture}-a{account}-n{network}", s, msg, c, network, ev, screens)

        # Every approval stage can be cancelled, even after an earlier export.
        for target in ["Export view key", "Derivation", "Address", "Address QR"]:
            s.send(542, request())
            reached = False
            for _ in range(64):
                prompt = s.receive()
                if not prompt or prompt[0] != 26:
                    raise RuntimeError(f"did not reach watch approval {target}")
                meta = s.observe_screen("watch-cancel-" + target.replace(" ", "-"))
                if meta["title"] == target:
                    s.send(20)
                    failure(checks, "watch-cancel-at-" + target, s.receive(), [4])
                    checks.record("watch-cancel-no-late-export-" + target, s.receive(.03) is None)
                    reached = True
                    break
                s.send(27)
                s.send(100, fv(1, 1), iface=1)
            checks.record("watch-cancel-stage-reached-" + target, reached)

        first, _, _ = s.rpc(542, request(), approve=None)
        checks.record("watch-requires-consent-after-previous-exports", first[0] == 26)
        s.approve_button("watch-explicit-no", False)
        failure(checks, "watch-explicit-no-refused", s.receive(), [4])
        first, _, _ = s.rpc(542, request(), approve=None)
        checks.record("watch-initialize-cancel-open", first[0] == 26)
        s.send(0)
        terminal = s.receive()
        checks.record("watch-initialize-aborts-export", terminal and terminal[0] == 17)
        checks.record("watch-initialize-no-late-export", s.receive(.03) is None)
        s.close()

        s = new("watch-pin")
        load_wallet(s, checks, "abandon", pin="1234")
        s.rpc(24)
        prompt, _, _ = s.rpc(542, request())
        checks.record("watch-locked-wallet-demands-pin", prompt[0] == 18)
        s.send(20)
        failure(checks, "watch-pin-cancel-refused", s.receive(), [6])
        msg, _, _ = s.rpc(542, request(), pin="9999")
        failure(checks, "watch-wrong-pin-refused", msg, [7])
        msg, ev, screens = s.rpc(542, request(), pin="1234")
        case = next(c for c in cases if c["label"] == "abandon-account0-sub0-0-output0")
        verify_export("watch-valid-pin", s, msg, case, 0, ev, screens)
        checks.record("watch-valid-pin-was-requested", 18 in ev)
        s.close()

        s = new("watch-passphrase")
        load_wallet(s, checks, "abandon", passphrase=True)
        prompt, _, _ = s.rpc(542, request())
        checks.record("watch-protected-wallet-demands-passphrase", prompt[0] == 41)
        s.send(20)
        failure(checks, "watch-passphrase-cancel-refused", s.receive(), [11])
        msg, ev, screens = s.rpc(542, request(), passphrase="public monero watch test")
        verify_export("watch-nonempty-passphrase", s, msg,
                      public_passphrase_case(core, "abandon", "public monero watch test"), 0, ev, screens)
        s.rpc(24)
        msg, ev, screens = s.rpc(542, request(), passphrase="")
        verify_export("watch-empty-passphrase-after-clear", s, msg, case, 0, ev, screens)
    finally:
        s.close()
    report = {"schema_version": 1, "status": "pass", "check_count": len(checks.items),
              "sanitizer_helper": helper,
              "checks": checks.items, "scope": "emulator-only explicit-consent private view-key export",
              "physical_device_accessed": False, "existing_flash_file_opened": False,
              "public_fixtures_only": True, "production_ready": False,
              "library_sha256": sha(args.library.read_bytes()),
              "reference_sha256": sha(args.reference.read_bytes()),
              "core_library_sha256": sha(args.core_library.read_bytes()),
              "source_sha256": sha(Path(__file__).read_bytes()),
              "session_frames": {x.label: x.frames for x in sessions}}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "pass", "checks": len(checks.items), "output": str(out)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        print(error, file=__import__("sys").stderr)
        raise SystemExit(1)
