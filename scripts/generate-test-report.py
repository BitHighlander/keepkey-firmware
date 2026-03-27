#!/usr/bin/env python3
"""Thin wrapper — delegates to python-keepkey's version-aware report generator."""
import subprocess, sys, os

script = os.path.join(
    os.path.dirname(__file__), '..', 'deps', 'python-keepkey',
    'scripts', 'generate-test-report.py'
)

if not os.path.exists(script):
    print(f"ERROR: {script} not found. Is deps/python-keepkey checked out?", file=sys.stderr)
    sys.exit(1)

sys.exit(subprocess.call([sys.executable, script] + sys.argv[1:]))
