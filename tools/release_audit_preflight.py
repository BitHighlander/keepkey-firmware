#!/usr/bin/env python3
"""Validate a release-audit prediction receipt against local git objects."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


def git(root, *args):
    result = subprocess.run(
        ("git", "-C", str(root), *args), text=True, capture_output=True
    )
    if result.returncode:
        raise ValueError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout.strip()


def gh_json(*args):
    result = subprocess.run(("gh", *args), text=True, capture_output=True)
    if result.returncode:
        raise ValueError(f"gh {' '.join(args)}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def require(condition, message, errors):
    if not condition:
        errors.append(message)


def validate(root, receipt):
    errors = []
    base = receipt.get("base")
    head = receipt.get("head")
    require(bool(base and head), "base and head are required", errors)
    if not base or not head:
        return errors

    try:
        tree = git(root, "rev-parse", f"{head}^{{tree}}")
        changed = set(git(root, "diff", "--name-only", base, head).splitlines())
    except ValueError as exc:
        return [str(exc)]

    require(receipt.get("tree") == tree, "candidate tree does not match head", errors)

    dependencies = receipt.get("dependencies", {})
    require(bool(dependencies), "dependency gitlink evidence is required", errors)
    try:
        gitlinks = {}
        for line in git(root, "ls-tree", "-r", head).splitlines():
            metadata, path = line.split("\t", 1)
            mode, kind, oid = metadata.split()
            if mode == "160000" and kind == "commit":
                gitlinks[path] = oid
        require(dependencies == gitlinks,
                "dependency receipt does not equal candidate gitlinks", errors)
    except (ValueError, TypeError) as exc:
        errors.append(f"dependency inventory failed: {exc}")
    for path, expected in dependencies.items():
        try:
            entry = git(root, "ls-tree", head, "--", path).split()
            require(len(entry) >= 3 and entry[1] == "commit",
                    f"{path}: candidate entry is not a gitlink", errors)
            require(len(entry) >= 3 and entry[2] == expected,
                    f"{path}: dependency pin does not match candidate", errors)
        except ValueError as exc:
            errors.append(str(exc))

    checks = receipt.get("ci", [])
    require(bool(checks), "CI evidence is required", errors)
    for check in checks:
        label = check.get("name", "unnamed CI check")
        require(check.get("head") == head, f"{label}: stale CI head", errors)
        require(check.get("conclusion") == "success", f"{label}: CI is not successful", errors)
        require(bool(check.get("url")), f"{label}: CI URL is required", errors)

    thread_receipts = receipt.get("threads", [])
    require(bool(thread_receipts), "review-thread evidence is required", errors)
    for item in thread_receipts:
        label = f"PR {item.get('pr', '?')}"
        require(item.get("unresolved") == 0, f"{label}: unresolved review threads", errors)
        require(bool(item.get("queried_at")), f"{label}: query time is required", errors)

    findings = receipt.get("findings", [])
    finding_ids = [item.get("id") for item in findings]
    require(all(finding_ids), "every finding requires an ID", errors)
    require(len(finding_ids) == len(set(finding_ids)), "finding IDs are not unique", errors)
    for item in findings:
        label = f"finding {item.get('id', '?')}"
        require(bool(item.get("reviewed_sha")), f"{label}: reviewed SHA is required", errors)
        require(item.get("disposition") in {"fixed", "refuted", "deferred"},
                f"{label}: invalid disposition", errors)
        require(bool(item.get("evidence")), f"{label}: evidence is required", errors)
        if item.get("disposition") == "deferred":
            require(not item.get("release_blocking", True),
                    f"{label}: release-blocking finding is deferred", errors)
            require(bool(item.get("owner") and item.get("target_release")),
                    f"{label}: deferral owner and target release are required", errors)

    coverage = receipt.get("coverage", [])
    covered_paths = [item.get("path") for item in coverage]
    require(len(covered_paths) == len(set(covered_paths)), "coverage paths are duplicated", errors)
    require(set(covered_paths) == changed, "coverage does not equal the candidate diff", errors)
    for item in coverage:
        label = item.get("path", "unnamed path")
        require(bool(item.get("invariants")), f"{label}: no invariant assignment", errors)
        require(bool(item.get("variants")), f"{label}: no variant assignment", errors)
        require(bool(item.get("tests")), f"{label}: no test assignment", errors)
        require(bool(item.get("reviewer")), f"{label}: no reviewer assignment", errors)

    tests = receipt.get("tests", [])
    required_kinds = set(receipt.get("required_test_kinds", []))
    passed_kinds = set()
    for item in tests:
        label = item.get("name", "unnamed test evidence")
        require(item.get("head") == head, f"{label}: stale test head", errors)
        require(item.get("status") == "pass", f"{label}: test did not pass", errors)
        require(bool(item.get("evidence")), f"{label}: evidence is required", errors)
        if item.get("status") == "pass":
            passed_kinds.add(item.get("kind"))
    require(required_kinds <= passed_kinds,
            "missing test evidence kinds: " + ", ".join(sorted(required_kinds - passed_kinds)),
            errors)

    projected = []
    projections = receipt.get("projections", [])
    require(bool(projections), "audit projections are required", errors)
    for index, item in enumerate(projections, 1):
        label = f"projection {index}"
        projection_base = item.get("base")
        projection_head = item.get("head")
        manifest = item.get("manifest", [])
        try:
            require(git(root, "rev-parse", f"{projection_head}^") == projection_base,
                    f"{label}: base is not the direct parent", errors)
            require(git(root, "rev-parse", f"{projection_head}^{{tree}}") == tree,
                    f"{label}: head tree differs from candidate", errors)
            actual = git(root, "diff", "--name-only", projection_base, projection_head).splitlines()
            require(sorted(actual) == sorted(manifest), f"{label}: manifest differs from diff", errors)
            projected.extend(manifest)
        except ValueError as exc:
            errors.append(f"{label}: {exc}")
    require(len(projected) == len(set(projected)), "projection manifests overlap", errors)
    require(set(projected) == changed, "projection union does not equal candidate diff", errors)

    require("residual_risks" in receipt, "residual_risks must be stated explicitly", errors)
    return errors


def validate_github(receipt):
    """Re-query mutable GitHub facts instead of trusting receipt snapshots."""
    errors = []
    repository = receipt.get("repository")
    canonical_pr = receipt.get("canonical_pr")
    if not repository or not canonical_pr:
        return ["repository and canonical_pr are required for live GitHub validation"]
    try:
        pull = gh_json("api", f"repos/{repository}/pulls/{canonical_pr}")
        require(pull["head"]["sha"] == receipt.get("head"),
                "canonical PR head changed", errors)
        require(pull["base"]["sha"] == receipt.get("base"),
                "canonical PR base changed", errors)

        check_runs = gh_json(
            "api", f"repos/{repository}/commits/{receipt['head']}/check-runs?per_page=100"
        ).get("check_runs", [])
        for expected in receipt.get("ci", []):
            matches = [run for run in check_runs if run.get("name") == expected.get("name")]
            require(bool(matches), f"{expected.get('name')}: live CI check not found", errors)
            require(any(run.get("conclusion") == "success" for run in matches),
                    f"{expected.get('name')}: no successful live CI check", errors)

        query = """
query($owner:String!, $name:String!, $number:Int!) {
  repository(owner:$owner, name:$name) {
    pullRequest(number:$number) {
      reviewThreads(first:100) { nodes { isResolved } pageInfo { hasNextPage } }
    }
  }
}
"""
        for item in receipt.get("threads", []):
            thread_repo = item.get("repository", repository)
            owner, name = thread_repo.split("/", 1)
            response = gh_json(
                "api", "graphql", "-f", f"query={query}", "-F", f"owner={owner}",
                "-F", f"name={name}", "-F", f"number={item['pr']}"
            )
            connection = response["data"]["repository"]["pullRequest"]["reviewThreads"]
            require(not connection["pageInfo"]["hasNextPage"],
                    f"PR {item['pr']}: more than 100 threads; paginated query required", errors)
            unresolved = sum(not node["isResolved"] for node in connection["nodes"])
            require(unresolved == 0, f"PR {item['pr']}: {unresolved} live unresolved threads", errors)
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"live GitHub validation failed: {exc}")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--verify-github", action="store_true")
    args = parser.parse_args()
    receipt = json.loads(args.receipt.read_text())
    errors = validate(args.repo, receipt)
    if args.verify_github:
        errors.extend(validate_github(receipt))
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"head": receipt["head"], "tree": receipt["tree"], "status": "ready"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
