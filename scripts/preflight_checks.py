"""Portable preflight checks using Git, Docker and CMake's actual source graph."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def docker_ready(timeout=20):
    try:
        subprocess.run(['docker', 'info'], check=True, timeout=timeout,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError('Docker unavailable or readiness probe timed out') from exc


def whitespace(root, base=None):
    # Inspect both committed changes to be pushed and staged/unstaged changes.
    # A first push without an upstream must identify its review base explicitly.
    if base is not None:
        # Freeze a commit identity before checking it; a descendant or unrelated
        # override must not silently collapse/broaden the requested push range.
        try:
            ancestor = subprocess.check_output(
                ['git', 'rev-parse', '--verify', '--end-of-options', base + '^{commit}'],
                cwd=root, text=True, stderr=subprocess.PIPE).strip()
            subprocess.run(['git', 'merge-base', '--is-ancestor', ancestor, 'HEAD'],
                           cwd=root, check=True, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError('PREFLIGHT_BASE must resolve to an ancestor of HEAD') from exc
    else:
        ancestor = subprocess.check_output(
            ['git', 'merge-base', 'HEAD', '@{upstream}'], cwd=root, text=True).strip()
    subprocess.run(['git', 'diff', '--check', ancestor, 'HEAD'], cwd=root, check=True)
    subprocess.run(['git', 'diff', '--check', 'HEAD'], cwd=root, check=True)


def unbuilt_tests(root):
    root = Path(root).resolve()
    tracked = subprocess.check_output(
        ['git', 'ls-files', '-z', 'unittests/'],
        cwd=root).decode().split('\0')
    expected = {str((root / p).resolve()) for p in tracked
                if Path(p).suffix.lower() in {'.c', '.cc', '.cpp', '.cxx'}}
    # Owned by hive-release-review; all other tracked suites must be reachable.
    expected.discard(str(root / 'unittests/firmware/hive.cpp'))
    with tempfile.TemporaryDirectory(prefix='kk-preflight-cmake-') as tmp:
        project = Path(tmp)
        # Preserve repository-root paths used by the actual test definitions.
        for name in ('lib', 'include', 'deps'):
            if (root / name).exists():
                (project / name).symlink_to(root / name, target_is_directory=True)
        # Configure the real test CMake tree with full features. No dependencies
        # are linked or firmware compiled: only translation-unit membership is
        # checked. Actual set/list/if/add_subdirectory semantics are retained.
        (project / 'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.16)
project(preflight_sources LANGUAGES C CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(KK_BITCOIN_ONLY OFF)
set(KK_ZCASH_PRIVACY ON)
function(target_link_libraries)
endfunction()
add_subdirectory("${FIRMWARE_ROOT}/unittests" unittests)
''')
        subprocess.run(['cmake', '-S', str(project), '-B', str(project / 'build'),
                        '-G', 'Unix Makefiles', '-DFIRMWARE_ROOT=' + str(root)],
                       check=True, stdout=subprocess.DEVNULL)
        commands = json.loads((project / 'build/compile_commands.json').read_text())
        built = {str((Path(c['directory']) / c['file']).resolve()) for c in commands}
    return sorted(str(Path(p).relative_to(root)) for p in expected - built)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('check', choices=['docker', 'sources', 'whitespace'])
    args = parser.parse_args()
    try:
        if args.check == 'docker':
            docker_ready()
        elif args.check == 'whitespace':
            whitespace(Path.cwd(), os.environ.get('PREFLIGHT_BASE'))
        else:
            missing = unbuilt_tests(Path.cwd())
            if missing:
                raise RuntimeError('Test sources absent from CMake targets: ' + ', '.join(missing))
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as exc:
        parser.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    main()
