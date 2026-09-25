#!/usr/bin/env python3
"""Build fail-closed, self-binding 7.14.2 presign evidence."""

import datetime
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
REPORT_GENERATOR = (
    ROOT / "deps" / "python-keepkey" / "scripts" /
    "generate-test-report.py"
)
REPORT_DIR = ROOT / "test-report"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
REPORT_PDF = REPORT_DIR / "test-report.pdf"
MERGED_JUNIT = REPORT_DIR / "junit-merged.xml"

BASE_REQUIRED_CASES = {
    "Eip712.MalformedHexNeverPublishesEncodedOutput",
    "Eip712.ByteEncodingMatchesIndependentHashAndRightPadding",
    "Eip712.MismatchedJsonShapesAndFixedArraysAreRejectedBeforeHashing",
    "Eip712.MalformedBytesAndAddressesRejectedBeforeAnyValueScreen",
    "Eip712.BytesNTypeWidthIsStrictInTypeHashAndEncoder",
    "Eip712.MissingFieldRefusedWithoutDereferenceOrHashMutation",
    "Eip712.DecimalSignPaddingMatchesParsedValue",
    "Eip712.IntegerWidthAndValueMustMatchBeforeHashing",
    "Eip712.NarrowIntegerBoundaryMatchesIndependentEncoding",
    "Recovery.DeleteKeepsTypedCipherCharactersNotTheCurrentMapping",
    "Ripple.TruncatedBufferFailsWithoutWritingPastEnd",
    "Storage.LegacyLanguageIsBoundedAndTerminated",
    "Storage.TruncatedLegacyCacheDoesNotMutateDestination",
    "EmulatorLifecycle.OverflowPreservesUnreadFramesAndRetriesDroppedFrame",
    "EmulatorLifecycle.ConcurrentCaptureNeverTearsOrReordersUnreadSlots",
    "EmulatorLifecycle.ShutdownStopsPollThreadAndAllowsRestart",
    "EmulatorLifecycle.ShutdownWakesConfirmationWaitingForHostDecision",
    "ReviewHandlers.ResetCancellationClearsScratchBeforeAndAfterFormatting",
    "ReviewHandlers.ResetWithoutBackupCommitsAndClearsScratch",
    "ReviewHandlers.ResetBackupCommitsAllStrengthsAndClearsScratch",
    "SetupCeremony.AbortScrubsEveryByteOfSharedMnemonicDisplayScratch",
    "test_msg_recoverydevice_cipher.TestDeviceRecovery."
    "test_unknown_word_count_failure_aborts_recovery",
}

EVM_REQUIRED_CASES = {
    "Ethereum.TransferAmountUsesTheRequestsSigningChain",
    "test_msg_ethereum_signtx_xfer.TestMsgEthereumSigntx."
    "test_transfer_review_uses_signing_chain_asset",
}

OSMOSIS_REQUIRED_CASES = {
    "Osmosis.RequiredValuesRejectEmptyAndNonDecimalAmounts",
    "test_msg_osmosis_validation.TestOsmosisValidation."
    "test_present_but_empty_amount_is_rejected_as_invalid",
    "test_msg_osmosis_validation.TestOsmosisValidation."
    "test_ibc_omitted_amount_and_receiver_are_rejected_before_review",
}

OSMOSIS_LEGACY_REQUIRED_CASES = {
    "Osmosis.RequiredValuesRejectEmptyAndNonDecimalAmounts",
    "test_msg_osmosis_validation.TestOsmosisValidation."
    "test_present_but_empty_amount_is_rejected_before_review",
    "test_msg_osmosis_validation.TestOsmosisValidation."
    "test_ibc_omitted_amount_and_receiver_are_rejected_before_review",
}

CAPABILITY_SKIP_PREFIX = (
    "Staged release tree does not yet provide capability: "
)


def fail(message):
    raise RuntimeError(message)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args):
    return subprocess.check_output(
        ["git"] + list(args), cwd=str(ROOT), text=True).strip()


def case_status(testcase):
    if testcase.find("failure") is not None:
        return "fail"
    if testcase.find("error") is not None:
        return "error"
    if testcase.find("skipped") is not None:
        return "skip"
    return "pass"


def merge_junit(paths):
    root = ET.Element("testsuites")
    cases = []
    inputs = []
    for path in paths:
        try:
            parsed = ET.parse(path)
        except ET.ParseError as exc:
            fail("malformed JUnit %s: %s" % (path, exc))
        source_root = parsed.getroot()
        suites = list(source_root.iter("testsuite"))
        if not suites:
            fail("JUnit contains no suites: %s" % path)
        if source_root.tag == "testsuite":
            root.append(source_root)
        else:
            for suite in source_root.findall("testsuite"):
                root.append(suite)
        for testcase in source_root.iter("testcase"):
            status = case_status(testcase)
            skipped = testcase.find("skipped")
            cases.append({
                "classname": testcase.get("classname", ""),
                "name": testcase.get("name", ""),
                "status": status,
                "skip_reason": (
                    skipped.get("message", "") if skipped is not None else ""
                ),
            })
        inputs.append({
            "path": str(path.relative_to(ROOT)),
            "sha256": sha256_file(path),
        })
    ET.ElementTree(root).write(
        MERGED_JUNIT, xml_declaration=True, encoding="unicode")
    return cases, inputs


def canonical_case_name(case):
    return "%s.%s" % (case["classname"], case["name"])


def firmware_version_tuple():
    raw = os.environ.get("FW_VERSION", "")
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", raw)
    if match is None:
        fail("FW_VERSION is missing or malformed: %r" % raw)
    return tuple(int(value) for value in match.groups())


def approved_capabilities(workflow_text=None):
    """The one staged-capability ledger: the integration job's
    KK_RELEASE_MISSING_CAPABILITIES line in ci.yml, bound to this checkout."""
    if workflow_text is None:
        workflow_text = CI_WORKFLOW.read_text()
    ledgers = re.findall(
        r"^[ \t]+KK_RELEASE_MISSING_CAPABILITIES:[ \t]*([a-z0-9,-]+)[ \t]*$",
        workflow_text, re.MULTILINE)
    if len(ledgers) != 1:
        fail("expected exactly one capability ledger in %s, found %d" %
             (CI_WORKFLOW, len(ledgers)))
    return {value for value in ledgers[0].split(",") if value}


def release_missing_capabilities(cases, approved=None):
    if approved is None:
        approved = approved_capabilities()
    missing_capabilities = {
        value.strip() for value in
        os.environ.get("KK_RELEASE_MISSING_CAPABILITIES", "").split(",")
        if value.strip()
    }
    # The report job consumes immutable JUnit from the integration job but
    # intentionally does not inherit that job's partial-stack environment.
    # Bind the report to the artifact itself by recovering the explicit
    # capability declarations from canonical skip reasons.
    missing_capabilities.update(
        case["skip_reason"][len(CAPABILITY_SKIP_PREFIX):]
        for case in cases
        if case["status"] == "skip" and
        case["skip_reason"].startswith(CAPABILITY_SKIP_PREFIX)
    )
    # A skip reason is free text. Never let it shrink the release gate
    # unless it names a capability the workflow ledger already waives.
    unapproved = sorted(missing_capabilities - approved)
    if unapproved:
        fail("capability waivers not in the ci.yml ledger: %s" %
             ", ".join(unapproved))
    return missing_capabilities


def validate_cases(cases):
    failures = [case for case in cases
                if case["status"] in ("fail", "error")]
    if failures:
        fail("authoritative JUnit has %d failure/error case(s)" % len(failures))
    passed = {canonical_case_name(case) for case in cases
              if case["status"] == "pass"}
    missing_capabilities = release_missing_capabilities(cases)
    required_cases = set(BASE_REQUIRED_CASES)
    if "evm-max-amount-review" not in missing_capabilities:
        required_cases.update(EVM_REQUIRED_CASES)
    if "osmosis-wire-guards" not in missing_capabilities:
        # Match the actual firmware version in the artifacts, rather than the
        # 7.15 audit program name. Block 00b still builds 7.14.3 and declares
        # this later-slice capability missing; once the product version is
        # raised to 7.15 and the capability is present, require the new case.
        if firmware_version_tuple() >= (7, 15, 0):
            required_cases.update(OSMOSIS_REQUIRED_CASES)
        else:
            required_cases.update(OSMOSIS_LEGACY_REQUIRED_CASES)
    # Match whole dotted components: "XEip712.Case" must not satisfy
    # "Eip712.Case". Python classnames may carry a module-path prefix.
    missing = sorted(required for required in required_cases
                     if not any(name == required or
                                name.endswith("." + required)
                                for name in passed))
    if missing:
        fail("required release controls missing or not passing: %s" %
             ", ".join(missing))


def validate_screenshots(screenshot_root):
    pngs = sorted(screenshot_root.rglob("*.png"))
    if not pngs:
        fail("no OLED PNGs were retained")
    sequences = []
    for manifest_path in sorted(screenshot_root.rglob("frames.json")):
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        directory = manifest_path.parent
        expected = manifest.get("frames", [])
        actual_pngs = sorted(directory.glob("btn*.png"))
        if manifest.get("frame_count") != len(expected):
            fail("frame_count mismatch: %s" % manifest_path)
        if [item.get("file") for item in expected] != [p.name for p in actual_pngs]:
            fail("frame list mismatch: %s" % manifest_path)
        for item, png in zip(expected, actual_pngs):
            if item.get("sha256") != sha256_file(png):
                fail("frame hash mismatch: %s" % png)
        sequences.append({
            "path": str(directory.relative_to(ROOT)),
            "manifest_sha256": sha256_file(manifest_path),
            "frame_count": len(actual_pngs),
        })
    if not sequences:
        fail("OLED frames have no completeness manifests")
    manifested = sum(item["frame_count"] for item in sequences)
    if manifested != len(pngs):
        fail("%d OLED PNGs exist but manifests account for %d" %
             (len(pngs), manifested))
    return pngs, sequences


def validate_arm_manifests(arm_dir, firmware_sha, python_sha):
    required = {"full", "bitcoin-only"}
    manifests = {}
    for manifest_path in sorted(arm_dir.glob("*/arm-build-manifest.json")):
        artifact = manifest_path.parent.name
        matches = [variant for variant in required
                   if artifact.endswith("-" + variant)]
        if len(matches) != 1:
            fail("unrecognized ARM artifact directory: %s" % artifact)
        variant = matches[0]
        if variant in manifests:
            fail("duplicate ARM manifest for %s" % variant)
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        if manifest.get("firmware_sha") != firmware_sha:
            fail("ARM manifest firmware SHA does not match checkout: %s" %
                 artifact)
        if manifest.get("python_sha") != python_sha:
            fail("ARM manifest Python SHA does not match gitlink: %s" %
                 artifact)
        if manifest.get("variant") != variant:
            fail("ARM manifest variant does not match artifact: %s" % artifact)
        files = manifest.get("files", [])
        if not files:
            fail("ARM manifest contains no binaries: %s" % artifact)
        for item in files:
            path = manifest_path.parent / item.get("name", "")
            if not path.is_file() or sha256_file(path) != item.get("sha256"):
                fail("ARM artifact hash mismatch: %s" % path)
        manifests[variant] = {
            "artifact": artifact,
            "manifest_path": manifest_path,
            "manifest": manifest,
            "manifest_sha256": sha256_file(manifest_path),
        }
    if set(manifests) != required:
        fail("expected full and bitcoin-only ARM manifests, found: %s" %
             ", ".join(sorted(manifests)))
    return manifests


def main():
    if not REPORT_GENERATOR.is_file():
        fail("report generator submodule is not initialized")

    firmware_sha = git("rev-parse", "HEAD")
    python_sha = git("rev-parse", "HEAD:deps/python-keepkey")
    expected_firmware = os.environ.get("KK_FIRMWARE_SHA", firmware_sha)
    expected_python = os.environ.get("KK_PYTHON_SHA", python_sha)
    if expected_firmware != firmware_sha or expected_python != python_sha:
        fail("workflow metadata does not match checked-out source")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    junit_paths = [ROOT / "test-reports" / "python-keepkey" / "junit.xml"]
    junit_paths += [Path(path) for path in sorted(glob.glob(
        str(ROOT / "test-reports" / "firmware-unit" / "*.xml")))]
    junit_paths.append(ROOT / "test-reports" / "dylib-junit.xml")
    junit_paths.append(ROOT / "test-reports" / "emulator" / "lifecycle.xml")
    missing_junit = [str(path) for path in junit_paths if not path.is_file()]
    if missing_junit:
        fail("required JUnit inputs missing: %s" % ", ".join(missing_junit))

    cases, junit_inputs = merge_junit(junit_paths)
    validate_cases(cases)
    # Normalize the artifact-bound staged capability ledger into the existing
    # canonical environment contract before invoking python-keepkey's report
    # validator.  The report job does not inherit the integration job's env;
    # its immutable JUnit is therefore the authority.
    missing_capabilities = release_missing_capabilities(cases)
    if missing_capabilities:
        os.environ["KK_RELEASE_MISSING_CAPABILITIES"] = ",".join(
            sorted(missing_capabilities))
    else:
        os.environ.pop("KK_RELEASE_MISSING_CAPABILITIES", None)

    screenshot_root = ROOT / "test-reports" / "screenshots"
    pngs, sequences = validate_screenshots(screenshot_root)

    arm_dir = ROOT / "test-reports" / "arm"
    arm_manifests = validate_arm_manifests(
        arm_dir, firmware_sha, python_sha)

    wrapper_hash = sha256_file(Path(__file__))
    renderer_hash = sha256_file(REPORT_GENERATOR)
    generator_hash = hashlib.sha256(
        (wrapper_hash + renderer_hash).encode("ascii")).hexdigest()
    arm_manifest_hash = hashlib.sha256(json.dumps({
        variant: item["manifest_sha256"]
        for variant, item in sorted(arm_manifests.items())
    }, sort_keys=True).encode("ascii")).hexdigest()
    run_url = os.environ.get("KK_RUN_URL", "")
    fw_version = os.environ.get("FW_VERSION", "")
    if not fw_version:
        fail("FW_VERSION is required")

    screenshot_junit = (
        ROOT / "test-reports" / "python-keepkey" /
        "junit-screenshots.xml")
    if not screenshot_junit.is_file():
        fail("screenshot-selection JUnit is missing")
    subprocess.run([
        sys.executable, str(REPORT_GENERATOR),
        "--screenshot-audit=%s" % screenshot_root,
        "--audit-junit=%s" % screenshot_junit,
        "--fw-version=%s" % fw_version,
    ], cwd=str(ROOT), check=True)

    subprocess.run([
        sys.executable, str(REPORT_GENERATOR),
        "--validate-junit",
        "--junit=%s" % MERGED_JUNIT,
        "--fw-version=%s" % fw_version,
    ], cwd=str(ROOT), check=True)

    subprocess.run([
        sys.executable, str(REPORT_GENERATOR),
        "--output=%s" % REPORT_PDF,
        "--junit=%s" % MERGED_JUNIT,
        "--screenshots=%s" % screenshot_root,
        "--fw-version=%s" % fw_version,
        "--firmware-sha=%s" % firmware_sha,
        "--python-sha=%s" % python_sha,
        "--run-url=%s" % run_url,
        "--generator-sha256=%s" % generator_hash,
        "--arm-manifest-sha256=%s" % arm_manifest_hash,
    ], cwd=str(ROOT), check=True)
    if not REPORT_PDF.is_file() or REPORT_PDF.stat().st_size == 0:
        fail("report PDF was not created")

    counts = {
        status: sum(1 for case in cases if case["status"] == status)
        for status in ("pass", "skip", "fail", "error")
    }
    counts["total"] = len(cases)
    generated_at = datetime.datetime.now(
        datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    evidence = {
        "schema": 1,
        "generated_at": generated_at,
        "firmware_sha": firmware_sha,
        "python_sha": python_sha,
        "firmware_pr": os.environ.get("KK_FIRMWARE_PR", ""),
        "python_pr": os.environ.get("KK_PYTHON_PR", ""),
        "run_url": run_url,
        "workflow_event": os.environ.get("KK_WORKFLOW_EVENT", ""),
        "generators": {
            "combined_sha256": generator_hash,
            "wrapper_sha256": wrapper_hash,
            "renderer_sha256": renderer_hash,
        },
        "junit": {
            "counts": counts,
            "inputs": junit_inputs,
            "merged_sha256": sha256_file(MERGED_JUNIT),
            "skips": [case for case in cases if case["status"] == "skip"],
        },
        "oled": {
            "frame_count": len(pngs),
            "selection_junit_sha256": sha256_file(screenshot_junit),
            "frames": [{
                "path": str(path.relative_to(ROOT)),
                "sha256": sha256_file(path),
            } for path in pngs],
            "sequences": sequences,
        },
        "arm": {
            "manifest_set_sha256": arm_manifest_hash,
            "variants": {
                variant: {
                    "artifact": item["artifact"],
                    "manifest_sha256": item["manifest_sha256"],
                    "files": item["manifest"]["files"],
                }
                for variant, item in sorted(arm_manifests.items())
            },
        },
        "pdf": {
            "path": REPORT_PDF.name,
            "sha256": sha256_file(REPORT_PDF),
        },
    }
    manifest_path = REPORT_DIR / "test-report-manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, sort_keys=True, indent=2)
        handle.write("\n")
    with open(REPORT_DIR / "test-report.pdf.sha256", "w",
              encoding="ascii") as handle:
        handle.write("%s  test-report.pdf\n" % evidence["pdf"]["sha256"])

    print("presign evidence: %d tests, %d OLED frames, PDF %s" %
          (counts["total"], len(pngs), evidence["pdf"]["sha256"]))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        sys.exit(1)
