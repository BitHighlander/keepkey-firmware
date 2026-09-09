#!/usr/bin/env python3
"""Execute the 7.14.3 artifact selector against positive and negative fixtures.

Requires PyYAML. Run from a trusted, reviewed 7.14.3 firmware checkout. No network,
GitHub credentials, release tags or publishing are used.
"""
import json, os, re, tempfile
from pathlib import Path
import yaml
w = yaml.safe_load(Path('.github/workflows/release.yml').read_text())
job = w['jobs']['validate']
script = next((s for s in job['steps'] if s.get('id') == 'evidence'))['run']
blocks = re.findall("python3 - <<'PY'\n(.*?)\nPY", script, re.S)
selector = blocks[-1]
base = [{'name': 'test-report', 'expired': False}, {'name': 'firmware-v7.14.3-source-full', 'expired': False}, {'name': 'firmware-v7.14.3-source-bitcoin-only', 'expired': False}]
with tempfile.TemporaryDirectory() as d:
    p = Path(d)
    artifact_file = p / 'artifacts.json'
    output = p / 'outputs'
    code = selector.replace("'/tmp/ci-artifacts.json'", repr(str(artifact_file)))
    for label, artifacts, valid in [('complete', base, True), ('missing', base[:-1], False), ('duplicate', base + [base[1]], False), ('expired', base[:-1] + [dict(base[-1], expired=True)], False)]:
        artifact_file.write_text(json.dumps({'artifacts': artifacts}))
        output.write_text('')
        os.environ.update(FW_VERSION='7.14.3', GITHUB_OUTPUT=str(output))
        try:
            exec(compile(code, 'workflow-artifact-selector', 'exec'), {})
            success = True
        except SystemExit:
            success = False
        assert success == valid, (label, success)
        if valid:
            produced = dict((line.split('=', 1) for line in output.read_text().splitlines()))
            exported = {}
            for key, value in job['outputs'].items():
                match = re.fullmatch('\\$\\{\\{ steps\\.evidence\\.outputs\\.(arm_\\w+) \\}\\}', value)
                if match:
                    assert match[1] in produced, ('unproduced workflow output', key, match[1], produced)
                    exported[key] = produced[match[1]]
            build = w['jobs']['build-firmware']
            step = next((s for s in build['steps'] if s.get('name') == 'Download audited release inputs'))
            assert step['env']['ARM_ARTIFACT'] == '${{ needs.validate.outputs[matrix.arm_output] }}'
            for row in build['strategy']['matrix']['include']:
                name = exported[row['arm_output']]
                assert name == 'firmware-v7.14.3-source-' + row['variant'], (row, name)
        print(label, 'PASS')
