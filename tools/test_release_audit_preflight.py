#!/usr/bin/env python3
"""Tests for the release-audit preflight validator."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("release_audit_preflight.py")
SPEC = importlib.util.spec_from_file_location("release_audit_preflight", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PreflightTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Audit Test")
        self.git("config", "user.email", "audit@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.root / "a").write_text("base\n")
        self.git("add", "a")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")
        (self.root / "a").write_text("candidate\n")
        self.git("commit", "-am", "candidate", "-q")
        self.head = self.git("rev-parse", "HEAD")
        self.tree = self.git("rev-parse", "HEAD^{tree}")
        self.receipt = {
            "base": self.base,
            "head": self.head,
            "tree": self.tree,
            "ci": [{"name": "release", "head": self.head, "conclusion": "success", "url": "https://example.invalid/1"}],
            "threads": [{"pr": 1, "unresolved": 0, "queried_at": "2026-09-16T00:00:00Z"}],
            "findings": [{"id": "F1", "disposition": "fixed", "evidence": "test"}],
            "coverage": [{"path": "a", "invariants": ["storage"], "variants": ["full"], "reviewer": "Astra"}],
            "required_test_kinds": ["isolated", "shuffled", "mutation"],
            "tests": [{"name": kind, "kind": kind, "head": self.head, "status": "pass", "evidence": "log"}
                      for kind in ("isolated", "shuffled", "mutation")],
            "projections": [{"base": self.base, "head": self.head, "manifest": ["a"]}],
            "residual_risks": [],
        }

    def git(self, *args):
        return subprocess.check_output(("git", "-C", str(self.root), *args), text=True).strip()

    def test_complete_receipt_passes(self):
        self.assertEqual([], MODULE.validate(self.root, self.receipt))

    def test_stale_and_incomplete_evidence_fails_closed(self):
        broken = json.loads(json.dumps(self.receipt))
        broken["ci"][0]["head"] = self.base
        broken["threads"][0]["unresolved"] = 1
        broken["tests"] = broken["tests"][:-1]
        errors = MODULE.validate(self.root, broken)
        self.assertTrue(any("stale CI head" in error for error in errors))
        self.assertTrue(any("unresolved review threads" in error for error in errors))
        self.assertTrue(any("missing test evidence kinds: mutation" in error for error in errors))

    def test_projection_and_coverage_gaps_fail(self):
        broken = json.loads(json.dumps(self.receipt))
        broken["coverage"] = []
        broken["projections"][0]["manifest"] = []
        errors = MODULE.validate(self.root, broken)
        self.assertIn("coverage does not equal the candidate diff", errors)
        self.assertIn("projection union does not equal candidate diff", errors)


if __name__ == "__main__":
    unittest.main()
