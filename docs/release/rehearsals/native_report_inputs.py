"""Rehearse required native evidence using downloaded CI XMLs; no network calls."""
import argparse
import importlib.util
from pathlib import Path
import shutil
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("checkout", type=Path)
parser.add_argument("evidence", type=Path)
args = parser.parse_args()
spec = importlib.util.spec_from_file_location("report", args.checkout / "scripts/generate-test-report.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    native = root / "test-reports/firmware-unit"
    shutil.copytree(args.evidence, native)
    paths = module.require_native_junit(root)
    assert len(paths) == len(list(args.evidence.glob("*.xml")))
    rejected = 0
    for target in paths:
        original = target.read_bytes()
        for content in (None, b"", b"<broken>", b"<testsuites/>"):
            if content is None:
                target.unlink()
            else:
                target.write_bytes(content)
            try:
                module.require_native_junit(root)
            except SystemExit:
                rejected += 1
            else:
                raise AssertionError("invalid native input accepted: " + str(target))
            target.write_bytes(original)
    print("PASS: actual CI inputs accepted; %d missing/empty/malformed/no-case inputs rejected" % rejected)
