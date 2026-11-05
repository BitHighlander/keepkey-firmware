#!/usr/bin/env python3
"""Continue only unfinished native cases without rebuilding the frozen firmware.

The first timed-out process remains an explicit failed attempt. Its completed
GoogleTest OK records and the continuation's real JUnit must cover every enabled
case enumerated by the unchanged executable. This tool never configures a build.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

NAME = re.compile(r"[A-Za-z0-9_/]+\.[A-Za-z0-9_/]+\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
TOOL = "tools/monero-feasibility/resume_compatibility.py"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def parse_listing(text):
    names, suite = [], None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip() or line.startswith(("Running main() from", "Note:")):
            continue
        if line[:1].isspace():
            require(suite is not None, "test name precedes its suite")
            name = suite + "." + line.strip()
            require(NAME.fullmatch(name) is not None, "invalid enumerated test name")
            names.append(name)
        else:
            require(line.endswith(".") and NAME.fullmatch(line + "placeholder") is not None,
                    "unexpected test enumeration output")
            suite = line[:-1]
    require(names and len(names) == len(set(names)), "empty or duplicate test enumeration")
    return names


def is_disabled(name):
    suite, test = name.split(".", 1)
    return any(part.startswith("DISABLED_") for part in suite.split("/")) or test.startswith("DISABLED_")


def parse_passed_log(text):
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    require(re.search(r"\[\s*FAILED\s*\]", text) is None and
            re.search(r"(?m)^(?:.*:\d+|unknown file): Failure\b", text) is None,
            "a failing assertion or test cannot be resumed as passing")
    running = re.findall(r"\[==========\] Running (\d+) tests? from", text)
    require(len(running) == 1, "expected exactly one original GoogleTest run")
    passed = {}
    for name, milliseconds in re.findall(r"\[\s*OK\s*\]\s+(\S+)\s+\((\d+) ms\)", text):
        require(NAME.fullmatch(name) is not None and name not in passed, "invalid or duplicate completed test")
        passed[name] = int(milliseconds)
    require(passed, "original log contains no completed passing tests")
    return int(running[0]), passed


def read_junit(path):
    result = {}
    for case in ET.parse(path).getroot().findall(".//testcase"):
        name = case.get("classname", "") + "." + case.get("name", "")
        require(NAME.fullmatch(name) is not None and name not in result, "invalid or duplicate JUnit case")
        require(case.find("failure") is None and case.find("error") is None, "JUnit contains a failed case")
        skipped = case.find("skipped") is not None or case.get("status") == "notrun"
        result[name] = (case, skipped)
    require(result, "JUnit contains no test cases")
    return result


def inside(root, relative):
    path = Path(relative)
    require(not path.is_absolute() and ".." not in path.parts, "artifact path escapes its result directory")
    candidate = root / path
    require(candidate.resolve().is_relative_to(root.resolve()) and not candidate.is_symlink(), "artifact uses an unsafe path")
    return candidate


def checked_copy(source, destination, expected):
    require(source.is_file() and expected is not None and sha(source) == expected, "retained artifact hash mismatch")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    require(sha(destination) == expected, "copied artifact hash mismatch")


def verify_frozen(report, library):
    require(sha(library) == report["library_sha256"], "firmware dylib changed")
    for field in ("firmware_archive", "core_library", "core_link_cmake"):
        require(sha(Path(report[field])) == report[field + "_sha256"], "frozen build dependency changed")
    build = Path(report["build_directory"])
    require(sha(build / "CMakeCache.txt") == report["cmake_cache_sha256"], "frozen build configuration changed")
    for relative, expected in report["firmware_object_sha256"].items():
        require(sha(inside(build, relative)) == expected, "compiled firmware object changed")
    require(report["firmware_object_sha256"], "missing compiled firmware object manifest")
    for suite in report["native_suites"]:
        require(sha(Path(suite["binary"])) == suite["binary_sha256"], "native executable changed")


def merged_junit(names, initial, continuation, path):
    root = ET.Element("testsuites", tests=str(len(names)), failures="0", errors="0",
                      disabled=str(sum(is_disabled(name) for name in names)))
    suites = {}
    for name in names:
        classname, method = name.split(".", 1)
        suite = suites.get(classname)
        if suite is None:
            suite = ET.SubElement(root, "testsuite", name=classname, tests="0", failures="0", errors="0", disabled="0")
            suites[classname] = suite
        suite.set("tests", str(int(suite.get("tests")) + 1))
        if is_disabled(name):
            case = ET.SubElement(suite, "testcase", classname=classname, name=method, status="notrun", result="suppressed")
            ET.SubElement(case, "skipped", message="Enumerated disabled test; not executed in either attempt")
            suite.set("disabled", str(int(suite.get("disabled")) + 1))
        elif name in initial:
            ET.SubElement(suite, "testcase", classname=classname, name=method, status="run", result="completed",
                          time="%.3f" % (initial[name] / 1000))
        else:
            suite.append(copy.deepcopy(continuation[name][0]))
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--validation-tools-commit", required=True)
    parser.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args()
    source, out, library = args.input.resolve(), args.output.resolve(), args.library.resolve()
    require(COMMIT.fullmatch(args.validation_tools_commit) is not None, "invalid validation tools commit")
    require(1 <= args.timeout <= 3600, "continuation timeout must be bounded")
    report_path = source / "result.json"
    report = json.loads(report_path.read_text())
    require(report["status"] == "fail" and report["same_artifact_unchanged"] is True, "input is not an unchanged failed compatibility run")
    suites = {suite["name"]: suite for suite in report["native_suites"]}
    require(set(suites) == {"firmware-unit", "board-unit", "crypto-unit", "zcash-display-unit"}, "unexpected native suite inventory")
    original = suites["firmware-unit"]
    require(original["returncode"] == 124 and original["failures"] == 0, "only an assertion-free timeout can be continued")
    binary = args.binary.resolve() if args.binary else Path(original["binary"]).resolve()
    require(sha(binary) == original["binary_sha256"], "continuation executable differs from original")
    verify_frozen(report, library)
    tool_source = Path(__file__).resolve()
    fw = tool_source.parents[2]
    tool_hashes = {}
    for relative in (TOOL, "tools/monero-feasibility/compatibility_emulator.py"):
        committed = subprocess.check_output(["git", "-C", str(fw), "show", args.validation_tools_commit + ":" + relative])
        tool_hashes[relative] = sha(fw / relative)
        require(hashlib.sha256(committed).hexdigest() == tool_hashes[relative], "validation tool does not match its reviewable commit")
    out.mkdir(parents=True, exist_ok=True)
    require(not any(out.iterdir()), "continuation output directory must be empty")
    scratch = out / "continuation"
    scratch.mkdir()
    listing = subprocess.run([str(binary), "--gtest_list_tests"], cwd=scratch, capture_output=True, timeout=60)
    require(listing.returncode == 0, "frozen executable could not enumerate tests")
    (out / "test-list.log").write_bytes(listing.stdout)
    names = parse_listing(listing.stdout.decode("utf-8"))
    enabled = [name for name in names if not is_disabled(name)]
    old_step = next(step for step in report["steps"] if step["name"] == "firmware-unit")
    require(old_step["returncode"] == 124 and old_step["command"][0] == original["binary"], "original timeout metadata is inconsistent")
    old_log = inside(source, old_step["log"])
    original_log = old_log.read_text(errors="replace")
    require(json.loads(original_log.splitlines()[0]) == old_step["command"] and "Timed out after " in original_log,
            "original process log lacks command or timeout provenance")
    running_count, passed = parse_passed_log(original_log)
    require(running_count == len(enabled) and set(passed) <= set(enabled), "original completed cases differ from executable inventory")
    remaining = [name for name in enabled if name not in passed]
    require(remaining, "there are no unfinished enabled cases")
    print(json.dumps({"enabled_cases": len(enabled), "completed_original": len(passed), "continuation_cases": len(remaining)}), flush=True)
    first_log = out / "attempt-1.log"
    checked_copy(old_log, first_log, sha(old_log))
    retry_log, retry_xml = out / "attempt-2.log", out / "attempt-2.xml"
    command = [str(binary), "--gtest_filter=" + ":".join(remaining), "--gtest_output=xml:" + str(retry_xml)]
    env = dict(os.environ)
    env.pop("KEEPKEY_UDP_PORT", None)
    started = time.monotonic()
    with retry_log.open("w") as stream:
        stream.write(json.dumps(command) + "\n")
        stream.flush()
        try:
            result = subprocess.run(command, cwd=scratch, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=args.timeout)
            returncode = result.returncode
        except subprocess.TimeoutExpired:
            stream.write("\nTimed out after %d seconds\n" % args.timeout)
            returncode = 124
    verify_frozen(report, library)
    require(returncode == 0 and retry_xml.is_file(), "continuation failed or timed out; original history remains retained")
    retry = read_junit(retry_xml)
    retry_running, retry_passed = parse_passed_log(retry_log.read_text(errors="replace"))
    require(retry_running == len(remaining) and set(retry) == set(remaining) == set(retry_passed) and
            not any(skipped for _, skipped in retry.values()), "continuation did not pass exactly its selected enabled cases")
    require(not set(passed) & set(retry), "continuation reran a previously completed case")
    require(set(passed) | set(retry) == set(enabled), "combined attempts leave missing cases")
    merged = out / "firmware-unit.xml"
    merged_junit(names, passed, retry, merged)
    combined = read_junit(merged)
    for suite in report["native_suites"]:
        if suite["name"] == "firmware-unit":
            continue
        require(suite["returncode"] == 0 and not suite["failures"] and not suite["errors"], "another native suite did not pass")
        relative = suite["junit"]
        checked_copy(inside(source, relative), inside(out, relative), suite["junit_sha256"])
    screenshot = report["dylib_screenshot_suite"]
    require(screenshot["returncode"] == 0 and screenshot["tests"] == 4 and not screenshot["failures"] and not screenshot["errors"], "original dylib screenshot controls did not pass")
    checked_copy(inside(source, screenshot["junit"]), inside(out, screenshot["junit"]), screenshot["junit_sha256"])
    image_base = Path(screenshot["junit"]).parent
    for frame in screenshot["frames"]:
        for path_key, hash_key in (("raw_path", "raw_sha256"), ("png_path", "png_sha256")):
            relative = image_base / frame[path_key]
            checked_copy(inside(source, relative), inside(out, relative), frame[hash_key])
    attempts = [
        {"returncode": 124, "reason": "timeout", "selected_tests": enabled, "passed_tests": list(passed),
         "log_file": first_log.name, "log_sha256": sha(first_log), "elapsed_seconds": old_step["elapsed_seconds"]},
        {"returncode": 0, "reason": "continuation", "selected_tests": remaining, "passed_tests": list(retry),
         "log_file": retry_log.name, "log_sha256": sha(retry_log), "junit_file": retry_xml.name,
         "junit_sha256": sha(retry_xml), "elapsed_seconds": time.monotonic() - started},
    ]
    original.update(execution="resumed", status="all_cases_passed_after_resume", all_enabled_cases_passed=True,
                    attempts=attempts, coverage={"expected_unique": len(enabled), "passed_unique": len(enabled),
                    "missing": [], "duplicates": [], "disabled_tests": [name for name in names if is_disabled(name)]},
                    junit=merged.name, junit_sha256=sha(merged), tests=len(combined), failures=0, errors=0,
                    skipped=sum(skipped for _, skipped in combined.values()),
                    classes=sorted({name.split(".", 1)[0] for name in combined}),
                    cases=[{"class": name.split(".", 1)[0], "name": name.split(".", 1)[1],
                            "status": "skipped" if skipped else "passed"} for name, (_, skipped) in combined.items()])
    report.update(status="pass", execution_status="all_cases_passed_after_resume", original_status="fail",
                  original_result_sha256=sha(report_path), validation_tools_commit=args.validation_tools_commit,
                  validation_tools_source_sha256=tool_hashes,
                  original_runner_source_sha256=report["source_sha256"]["tools/monero-feasibility/compatibility_emulator.py"],
                  enumeration={"log_file": "test-list.log", "log_sha256": sha(out / "test-list.log"),
                               "enabled": enabled, "disabled": [name for name in names if is_disabled(name)]})
    report["source_sha256"].update(tool_hashes)
    report["steps"].append({"name": "firmware-unit-continuation", "command": command, "cwd": str(scratch),
                            "returncode": 0, "elapsed_seconds": attempts[1]["elapsed_seconds"], "log": retry_log.name})
    verify_frozen(report, library)
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["execution_status"], "enabled_passed": len(enabled),
                      "initial_returncode": original["returncode"], "output": str(out)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, StopIteration, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
