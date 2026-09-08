#!/usr/bin/env python3
"""Rehearse 7.14.2/7.14.3 release packaging without tags or publication.

Requires PyYAML. Run from the firmware checkout being reviewed. Executes its
actual local workflow packaging commands over synthetic inputs in a temporary
directory; use only with a trusted, reviewed checkout.
"""
import hashlib, json, os, re, shutil, subprocess, tempfile
from pathlib import Path
import yaml
w = yaml.safe_load(Path('.github/workflows/release.yml').read_text())
steps = w['jobs']['build-firmware']['steps']
version = re.search('project\\s*\\([^)]*?VERSION\\s+(\\d+\\.\\d+\\.\\d+)', Path('CMakeLists.txt').read_text(), re.S)[1]
assert version in ('7.14.2', '7.14.3'), 'this rehearsal covers the audited-input packaging workflows'
variants = w['jobs']['build-firmware'].get('strategy', {}).get('matrix', {}).get('include', [{'variant': 'full', 'suffix': ''}])
selected = [s for s in steps if s.get('name') in ('Prepare the audited binaries', 'Rename artifacts', 'Compute hashes')]
assert [s['name'] for s in selected] == ['Prepare the audited binaries', 'Rename artifacts', 'Compute hashes']
for row in variants:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / 'audited-arm').mkdir()
        (p / 'audited-report').mkdir()
        blob = b'KPKY' + 64 .to_bytes(4, 'little') + bytes(248) + b'x' * 64
        for suffix, content in [('firmware.keepkey.bin', blob), ('firmware.keepkey.elf', b'ELF fixture'), ('bootloader.bin', b'bootloader fixture')]:
            (p / 'audited-arm' / ('firmware.keepkey.v' + version + '-audited-' + suffix)).write_bytes(content)
        for name in ('test-report.pdf', 'test-report-manifest.json'):
            (p / 'audited-report' / name).write_text('{}')
        for step in selected:
            cmd = step['run'].replace('${{ needs.validate.outputs.fw_version }}', version).replace('${{ matrix.suffix }}', row['suffix'])
            if os.uname().sysname == 'Darwin':
                cmd = cmd.replace('stat -c%s', 'stat -f%z')
            assert '${{' not in cmd
            env = dict(os.environ, BASE_IMAGE='fixture-immutable-builder', GITHUB_SHA='fixture-source', PATH=os.path.dirname(shutil.which('python3')) + ':' + os.environ['PATH'])
            subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', cmd], cwd=p / step.get('working-directory', '.'), env=env, check=True, capture_output=True, text=True)
        files = {f.name for f in (p / 'release').iterdir()}
        assert not any(('bootloader' in f.lower() for f in files)), files
        binname = f"firmware.keepkey.v{version}{row['suffix']}.bin"
        assert binname in files
        manifest = (p / 'release' / f"HASHES{row['suffix']}.txt").read_text()
        entries = [line.split() for line in manifest.splitlines() if line.startswith('sha256 (full)')]
        assert len(entries) == 1, entries
        for entry in entries:
            name, digest = entry[2:4]
            assert name in files, (name, files)
            assert hashlib.sha256((p / 'release' / name).read_bytes()).hexdigest() == digest
        shutil.copytree(p / 'release', p / 'artifacts')
        stage = next((s for s in w['jobs']['create-release']['steps'] if s.get('name') == 'Prepare release assets'))
        subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', stage['run']], cwd=p, env=env, check=True, capture_output=True, text=True)
        assert not any(('bootloader' in f.name.lower() for f in (p / 'release-assets').iterdir()))
        print(version, row['variant'], 'PASS: firmware-only packaging and exact published filenames/hashes')
