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
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
REPORT_GENERATOR = (
    ROOT / "deps" / "python-keepkey" / "scripts" /
    "generate-test-report.py"
)
REPORT_DIR = ROOT / "test-report"
REPORT_PDF = REPORT_DIR / "test-report.pdf"
MERGED_JUNIT = REPORT_DIR / "junit-merged.xml"

BASE_REQUIRED_CASES = {
    "DiceCeremonyPrivacy.Mixed128DerivationAndDevicePagesUseIndependentFixture",
    "DiceCeremonyPrivacy.Mixed256DerivationAndDevicePagesUseIndependentFixture",
    "DiceCeremonyPrivacy.Only128DerivationAndDevicePagesUseIndependentFixture",
    "DiceCeremonyPrivacy.Only256DerivationAndDevicePagesUseIndependentFixture",
    "DiceCeremonyPrivacy.AbortAtEveryPhaseWipesAndAllowsOrdinaryRestart",
    "DiceCeremonyPrivacy.AbortClearsCanvasBeforeDiagnosticsResume",
    "test_msg_resetdevice.TestDeviceReset.test_reset_device_dice_mixed_is_verifiable",
    "test_msg_resetdevice.TestDeviceReset.test_reset_device_dice_only_is_verifiable",
    "test_p02_transport.TestP02Transport.test_mixed_entropy_pages_remain_private_and_cancel_clears_state",
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

_STACK07 = "test_stack07_regressions."
_STACK07_COINTABLE = (
    _STACK07 + "TestStack07CoinTableReuse."
    "test_cointable_response_reuses_decoded_request_without_truncation")
_STACK07_EVM = [_STACK07 + "TestStack07Regressions." + name for name in (
    "test_advanced_mode_off_refuses_preload",
    "test_all_typed_fields_are_reviewed_and_signature_is_unchanged",
    "test_calldata_signing_replay_change_is_refused",
    "test_calldata_signing_replay_succeeds_with_arguments",
    "test_certified_approval_refused_before_annotation_screens",
    "test_declining_source_intent_or_either_field_aborts",
    "test_domain_name_version_and_salt_mismatches_are_refused",
    "test_early_typed_failure_clears_preload",
    "test_empty_message_requires_explicit_consent",
    "test_failed_certified_domain_clears_preload",
    "test_intent_only_typed_definition_still_requires_source_and_intent",
    "test_selector_only_call_signs_after_certified_intent",
    "test_tampered_envelope_signature_is_refused_at_preload",
    "test_typed_replay_change_is_refused",
    "test_unknown_signer_is_refused_at_preload",
    "test_verifying_contract_mismatch_is_refused_before_certified_review",
    "test_domain_only_signature_refuses_certified_preload",
    "test_dirty_approval_spender_word_is_refused_before_any_screen",
    "test_preload_survives_get_features_and_is_discarded_by_initialize",
    "test_non_ascii_intent_is_escaped_not_drawn_as_glyphs",
)]
_ADDITIVE = [
    "test_msg_ethereum_clearsign_additive.TestClearSignAdditiveInvariant." + name
    for name in (
        "test_failed_signature_falls_back_to_the_unverified_review",
        "test_no_runtime_slot_can_reach_the_suppression_branch",
        "test_no_slot_verifies_without_a_runtime_load",
        "test_successful_decode_still_runs_the_raw_review",
        "test_v2_schema_decode_still_runs_the_raw_review",
    )]
_SESSION = "test_msg_session_trust_lifetime.TestSessionTrustLifetime."
_SESSION_BOTH = [_SESSION + "test_advanced_mode_survives_initialize_but_not_clear_session"]
_SESSION_FULL = [_SESSION + name for name in (
    "test_disabling_advanced_mode_revokes_the_signer",
    "test_signer_dropped_by_clear_session",
    "test_signer_dropped_by_initialize",
)]
_RIPPLE = [
    "test_msg_ripple_sign_tx.TestMsgRippleSignTx." + name for name in (
        "test_memo_length_prefix_boundaries",
        "test_ripple_sign_invalid_fee",
        "test_sign",
        "test_sign_with_thorchain_memo",
    )]
_STACK09_SLOT = (
    "test_stack09_integration.TestAuthenticatorSlotIntegration."
    "test_account_slot_text_cannot_wrap_or_ignore_suffixes")
_STACK10_EVM = [
    "test_stack10_regressions.TestStack10Disclosure." + name for name in (
        "test_cancel_every_disclosure_page_then_retry",
        "test_contract_substitution_changes_review_and_signature",
        "test_exact_raw_values_contract_and_counterparty",
        "test_noncanonical_transfers_keep_advanced_raw_fallback",
        "test_padded_zero_value_keeps_exact_token_review",
        "test_transfer_account_keeps_raw_review_and_recipient_binding",
        "test_transfer_account_padded_zero_keeps_contract_review",
        "test_transfer_account_rejects_noncanonical_total_length",
        "test_unlimited_approval_and_disabled_advanced_mode_still_refuse",
    )]

_STACK12_HIVE = [
    "test_stack12_regressions.TestStack12Hive." + name for name in (
        "test_account_authorities_ignore_host_keys_and_cancel",
        "test_all_operations_reject_malformed_domains_before_consent",
        "test_complete_memo_and_each_consent_cancellation",
        "test_custom_domain_is_disclosed_and_cancellable",
        "test_invalid_amounts_and_labels_before_consent",
    )]
HIVE_REQUIRED_CASES = {
    "Hive.TransferAssetShownIsAssetSigned",
    "Hive.TransferRejectsUnsupportedAssetsAndUntruncatedPrecision",
    "Hive.AllSigningOperationsRejectMalformedExplicitChainIds",
    "Hive.TransferRejectsInvalidAmountAndAccountLabels",
    "Hive.AccountCreateBytesMatchIndependentGrapheneLayout",
    "Hive.AccountUpdateBytesMatchIndependentGrapheneLayout",
}

# Dedicated contract suites run as separate pytest invocations. Each file and
# each named case is REQUIRED with an exact status per product, so deleting a
# CI step, a test, or a variant leg cannot go unnoticed. Bitcoin-only must
# SKIP the EVM/XRP contracts: a pass there would mean the product exposes them.
_STACK13_ENTROPY = [
    "test_block13_entropy.TestBlock13Entropy." + name for name in (
        "test_byte_budget_clamps_sizes_and_survives_session_changes",
        "test_initialized_locked_device_keeps_confirmation_and_budget",
        "test_missing_required_size_fails_decode_without_spending_budget",
        "test_recovery_refuses_entropy_preserves_cipher_and_budget",
        "test_reset_refuses_entropy_without_consuming_pending_ack",
    )]

CONTRACT_JUNIT = {
    "junit-stack12.xml": {
        "full": dict((case, "pass") for case in _STACK12_HIVE),
        "bitcoin-only": dict((case, "skip") for case in _STACK12_HIVE),
    },
    "junit-stack09-integration.xml": {
        "full": {_STACK09_SLOT: "pass"},
        "bitcoin-only": {_STACK09_SLOT: "pass"},
    },
    "junit-stack10.xml": {
        "full": dict((case, "pass") for case in _STACK10_EVM),
        "bitcoin-only": dict((case, "skip") for case in _STACK10_EVM),
    },
    "junit-stack13.xml": {
        variant: dict((case, "pass") for case in _STACK13_ENTROPY)
        for variant in ("full", "bitcoin-only")
    },
    "junit-stack07.xml": {
        "full": dict([(_STACK07_COINTABLE, "pass")] +
                     [(case, "pass") for case in _STACK07_EVM]),
        "bitcoin-only": dict([(_STACK07_COINTABLE, "pass")] +
                             [(case, "skip") for case in _STACK07_EVM]),
    },
    "junit-stack06-contracts.xml": {
        "full": dict((case, "pass") for case in
                     _ADDITIVE + _SESSION_BOTH + _SESSION_FULL + _RIPPLE),
        "bitcoin-only": dict(
            [(case, "pass") for case in _SESSION_BOTH] +
            [(case, "skip") for case in _ADDITIVE + _SESSION_FULL + _RIPPLE]),
    },
}
CONTRACT_JUNIT_DIRS = {
    "full": Path("test-reports") / "python-keepkey",
    "bitcoin-only": Path("test-reports") / "bitcoin-only" / "python-keepkey",
}

# Native identities are fixed independently of discovery and test counts. A
# nonempty firmware.xml must not certify a build that dropped an owned source
# file, one parameterized chain, or the original empty-character regression.
_BLOCK13_NATIVE_BOTH = {
    "AutoLockProgress.EmptyRecoveryCharacterAbortsWithoutRenewingDeadline",
} | {
    "Block13Confirmation." + name for name in (
        "UnknownAndMalformedTinyPacketsUnwindSigningOnce",
        "DeclineCancelAndInitializeDoNotSignAndAllowRetry",
        "RecoveryRejectionRestoresCipherAndPreservesProgress",
        "RecoveryRedrawDoesNotRenewDeadlineOrResurrectAfterLock",
        "AcceptedRecoveryStartRenewsThenEventuallyExpires",
        "DeclinedRecoveryStartDoesNotRenewDeadline",
        "PollingPreservesVisibleCipherAndAnimationProgress",
    )
} | {
    "Block13Entropy." + name for name in (
        "NewerNormalBandWalletRequiresConsent",
        "NewerBitcoinBandWalletRequiresConsent",
        "PendingResetRejectsWithoutRenewingDeadline",
        "NewerNormalBandRefusesAllWalletCreationUntilWipe",
        "NewerBitcoinBandRefusesAllWalletCreationUntilWipe",
        "ActiveRecoveryRejectsAndPreservesCipherUntilDeadline",
        "MissingSizeFailsDecodeAndZeroDoesNotRenewDeadline",
    )
} | {
    "Block13ResetProgress." + name for name in (
        "InitialRequestRenewsThenPollingExpires",
        "EntropyReplyAdvancesOnceIncludingAbsentAndEmpty",
        "InvalidInitialRequestDoesNotRenew",
    )
}
_BLOCK13_NATIVE_FULL_ONLY = {
    "Block13ResetProgress.GenericTendermintWireSurfaceRemainsUnmapped",
} | {
    "Block13OsmosisWire." + name for name in (
        "SendAcceptsCanonicalUint64BoundaryAndZero",
        "SendRejectsOverflowAndNoncanonicalBeforeReview",
        "MissingAmountAndInvalidDenomFailBeforeReview",
        "SwapAndPoolAmountsRemainWiderThanUint64",
        "NonNativeDenominationsAreNotCappedAtUint64",
        "NativeDenominationStaysCappedForWideAmounts",
    )
} | {
    "Chains/Block13CoinProgress.%s/%s" % (case, chain)
    for case in (
        "AcceptedInitialRequestRenewsDeadline",
        "InvalidInitialRequestCannotRenewDeadline",
        "AcceptedContinuationsRenewThenPollingExpires",
        "EmptyAndInvalidContinuationsAbortWithoutRenewal",
        "DeclinedContinuationCannotRenewAndFreshRetryWorks",
    )
    for chain in (
        "Binance", "Cosmos", "Osmosis", "Thorchain", "Mayachain",
        "TendermintDirectHandler",
    )
}
BLOCK13_NATIVE_CASES = {
    "full": _BLOCK13_NATIVE_BOTH | _BLOCK13_NATIVE_FULL_ONLY,
    "bitcoin-only": _BLOCK13_NATIVE_BOTH,
}
NATIVE_CONTRACT_JUNIT = {
    "full": Path("test-reports") / "firmware-unit" / "firmware.xml",
    "bitcoin-only": (Path("test-reports") / "bitcoin-only" /
                     "firmware-unit" / "firmware.xml"),
}

# These are the actual product guards, not arbitrary reasons for missing tests.
CONTRACT_SKIP_REASONS = dict(
    [(case, "Hive signing is unavailable in bitcoin-only firmware")
     for case in _STACK12_HIVE] +
    [(case, "Stack 10 EVM signing is absent from bitcoin-only")
     for case in _STACK10_EVM] +
    [(case, "Stack 07 EVM contracts are intentionally absent from bitcoin-only")
     for case in _STACK07_EVM] +
    [(case, "EthereumTxMetadata not supported by this firmware build")
     for case in _ADDITIVE] +
    [(case, "Full feature firmware required to run this test")
     for case in _SESSION_FULL + _RIPPLE])

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


def parse_capability_ledger(workflow_text):
    """Parse one unambiguous staged-capability declaration."""
    ledgers = re.findall(
        r"^[ \t]+KK_RELEASE_MISSING_CAPABILITIES:[ \t]*([a-z0-9,-]*)[ \t]*$",
        workflow_text, re.MULTILINE)
    if len(ledgers) != 1:
        fail("expected exactly one capability ledger in %s, found %d" %
             (CI_WORKFLOW, len(ledgers)))
    return {value for value in ledgers[0].split(",") if value}


def waiver_authority_commit():
    """Use GitHub's event base, never a candidate-authored authority constant.

    Local rehearsal uses the remote accepted 7b base's merge base. CI requires
    the platform event payload and fails if it cannot identify the authority.
    Replacing this validator/workflow itself remains a code-review boundary.
    """
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        try:
            event = json.loads(Path(event_path).read_text())
            if "pull_request" in event:
                commit = event["pull_request"]["base"]["sha"]
            elif os.environ.get("GITHUB_EVENT_NAME") in ("push", "workflow_dispatch"):
                # CI binds this from the repository Actions variable, outside
                # the candidate diff. No predecessor/selected-head fallback.
                commit = os.environ.get("KK_ACCEPTED_WAIVER_SHA", "")
                if not commit:
                    fail("non-PR waiver authority requires the independently "
                         "accepted repository variable KK_ACCEPTED_WAIVER_SHA")
            else:
                fail("unsupported event for waiver authority")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            fail("cannot read platform waiver authority: %s" % exc)
    elif os.environ.get("GITHUB_ACTIONS") == "true":
        fail("CI waiver authority requires the platform event payload")
    else:
        commit = git("merge-base", "HEAD",
                     "refs/remotes/origin/release/715-stack-07b-consolidated")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit) or commit == "0" * 40:
        fail("waiver authority must be a full nonzero commit SHA")
    return commit


def approved_capabilities(workflow_text=None):
    """Candidate waivers may only narrow the owner-accepted immutable ledger."""
    if workflow_text is None:
        workflow_text = CI_WORKFLOW.read_text()
    candidate = parse_capability_ledger(workflow_text)
    authority = waiver_authority_commit()
    try:
        trusted_text = git("show", authority +
                           ":.github/workflows/ci.yml")
    except subprocess.CalledProcessError:
        fail("immutable waiver authority is unavailable: " +
             authority)
    trusted = parse_capability_ledger(trusted_text)
    added = sorted(candidate - trusted)
    if added:
        fail("candidate adds waivers absent from immutable authority: " +
             ", ".join(added))
    return candidate


def release_missing_capabilities(cases, approved=None):
    if approved is None:
        approved = approved_capabilities()
    missing_capabilities = {
        value.strip() for value in
        os.environ.get("KK_RELEASE_MISSING_CAPABILITIES", "").split(",")
        if value.strip()
    }
    # The report job shares CI's staged-capability inventory with the Python
    # integration job. Recover declarations from the immutable JUnit as well
    # so the report records capabilities actually skipped by that suite.
    missing_capabilities.update(
        case["skip_reason"][len(CAPABILITY_SKIP_PREFIX):]
        for case in cases
        if case["status"] == "skip" and
        case["skip_reason"].startswith(CAPABILITY_SKIP_PREFIX)
    )
    # Environment and JUnit skip reasons are evidence, not authority to
    # waive additional controls. The candidate ledger must stay within the
    # separately accepted immutable authority before it can grant a waiver.
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
    if "hive-release-review" not in missing_capabilities:
        required_cases.update(HIVE_REQUIRED_CASES)
    if "evm-max-amount-review" not in missing_capabilities:
        required_cases.update(EVM_REQUIRED_CASES)
    if "osmosis-wire-guards" not in missing_capabilities:
        if firmware_version_tuple() >= (7, 15, 0):
            required_cases.update(OSMOSIS_REQUIRED_CASES)
        else:
            required_cases.update(OSMOSIS_LEGACY_REQUIRED_CASES)
    missing = sorted(required for required in required_cases
                     if not any(name == required or
                                name.endswith("." + required)
                                for name in passed))
    if missing:
        fail("required release controls missing or not passing: %s" %
             ", ".join(missing))
    # The Hive identities are owned by one native suite. A second copy with
    # another status (a pass beside a skip, say) must not be able to satisfy
    # the gate through the set above, so each must appear exactly once.
    if "hive-release-review" not in missing_capabilities:
        for required in sorted(HIVE_REQUIRED_CASES):
            found = [case["status"] for case in cases
                     if canonical_case_name(case) == required or
                     canonical_case_name(case).endswith("." + required)]
            if found != ["pass"]:
                fail("Hive control %s must appear exactly once and pass, "
                     "found %s" % (required, found or "nothing"))


def read_junit_cases(path):
    try:
        parsed = ET.parse(path)
    except ET.ParseError as exc:
        fail("malformed JUnit %s: %s" % (path, exc))
    cases = {}
    for testcase in parsed.getroot().iter("testcase"):
        name = "%s.%s" % (testcase.get("classname", ""),
                          testcase.get("name", ""))
        # A second copy could mask a failing one; evidence must be unambiguous.
        if name in cases:
            fail("duplicate JUnit testcase %s in %s" % (name, path))
        skipped = testcase.find("skipped")
        cases[name] = (case_status(testcase),
                       skipped.get("message", "") if skipped is not None else "")
    return cases


def validate_contract_junit(root):
    """Require every dedicated contract JUnit with exact per-case statuses."""
    inputs = []
    for variant, directory in sorted(CONTRACT_JUNIT_DIRS.items()):
        for filename, by_variant in sorted(CONTRACT_JUNIT.items()):
            path = Path(root) / directory / filename
            if not path.is_file() or path.stat().st_size == 0:
                fail("required %s contract JUnit missing: %s" % (variant, path))
            cases = read_junit_cases(path)
            if not cases:
                fail("contract JUnit contains no test cases: %s" % path)
            broken = sorted(name for name, (status, reason) in cases.items()
                            if status in ("fail", "error"))
            if broken:
                fail("%s %s has failing case(s): %s" %
                     (variant, filename, ", ".join(broken)))
            wrong = []
            for required, expected in sorted(by_variant[variant].items()):
                found = [result for name, result in cases.items()
                         if name == required or name.endswith("." + required)]
                expected_reason = CONTRACT_SKIP_REASONS[required] if expected == "skip" else ""
                if found != [(expected, expected_reason)]:
                    wrong.append("%s (expected %s, found %s)" % (
                        required, expected + ":" + expected_reason, repr(found) if found else "missing"))
            if wrong:
                fail("%s %s contract cases wrong: %s" %
                     (variant, filename, "; ".join(wrong)))
            inputs.append({
                "variant": variant,
                "path": str(path.relative_to(root)),
                "sha256": sha256_file(path),
            })
    return inputs


def validate_native_contract_junit(root):
    """Bind owned native controls to each product's actual GoogleTest run."""
    inputs = []
    for variant, relative in sorted(NATIVE_CONTRACT_JUNIT.items()):
        path = Path(root) / relative
        if not path.is_file() or path.stat().st_size == 0:
            fail("required %s native contract JUnit missing: %s" %
                 (variant, path))
        # Retain duplicate detection and reject errors before inspecting the
        # GoogleTest status attribute (disabled cases lack a failure node).
        cases = read_junit_cases(path)
        broken = sorted(name for name, (status, _) in cases.items()
                        if status in ("fail", "error"))
        if broken:
            fail("%s native contract JUnit has failing case(s): %s" %
                 (variant, ", ".join(broken)))
        statuses = {
            "%s.%s" % (case.get("classname", ""), case.get("name", "")):
            case.get("status", "")
            for case in ET.parse(path).getroot().iter("testcase")
        }
        wrong = sorted(
            name for name in BLOCK13_NATIVE_CASES[variant]
            if cases.get(name) != ("pass", "") or statuses.get(name) != "run")
        if wrong:
            fail("%s native contract cases missing or not passing/run: %s" %
                 (variant, ", ".join(wrong)))
        if variant == "bitcoin-only":
            unexpected = sorted(_BLOCK13_NATIVE_FULL_ONLY.intersection(cases))
            if unexpected:
                fail("bitcoin-only native evidence contains full-only cases: " +
                     ", ".join(unexpected))
        inputs.append({
            "variant": variant,
            "path": str(relative),
            "sha256": sha256_file(path),
        })
    return inputs


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


def require_native_junit(root):
    """Require each native suite before discovering any additional XML inputs."""
    native_dir = Path(root) / "test-reports" / "firmware-unit"
    required = ("firmware.xml", "board.xml", "crypto.xml", "zcash-crypto.xml")
    missing = [name for name in required
               if not (native_dir / name).is_file()
               or (native_dir / name).stat().st_size == 0]
    if missing:
        raise SystemExit("ERROR: required native JUnit inputs missing or empty: " +
                         ", ".join(missing))
    for name in required:
        try:
            parsed = ET.parse(native_dir / name)
        except ET.ParseError as exc:
            raise SystemExit("ERROR: malformed native JUnit %s: %s" % (name, exc))
        if next(parsed.iter("testcase"), None) is None:
            raise SystemExit("ERROR: native JUnit contains no test cases: " + name)
    return sorted(native_dir.glob("*.xml"))


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
    junit_paths += require_native_junit(ROOT)
    junit_paths.append(ROOT / "test-reports" / "dylib-junit.xml")
    junit_paths.append(ROOT / "test-reports" / "emulator" / "lifecycle.xml")
    missing_junit = [str(path) for path in junit_paths if not path.is_file()]
    if missing_junit:
        fail("required JUnit inputs missing: %s" % ", ".join(missing_junit))

    cases, junit_inputs = merge_junit(junit_paths)
    validate_cases(cases)
    contract_inputs = validate_contract_junit(ROOT)
    contract_inputs += validate_native_contract_junit(ROOT)
    # Normalize the shared staged-capability inventory plus the declarations
    # in immutable JUnit before invoking python-keepkey's report validator.
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
            "contract_inputs": contract_inputs,
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
