"""Exercise the preflight boundaries with real Git/CMake fixtures."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.preflight_checks import docker_ready, unbuilt_tests, whitespace


class PreflightChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git('init', '-q')
        self.git('config', 'user.email', 'preflight@example.invalid')
        self.git('config', 'user.name', 'Preflight')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, stderr=subprocess.PIPE)

    def test_cmake_rejects_comment_unused_list_and_same_basename(self):
        names = ['same.c', 'same.cc', 'same.cpp', 'same.cxx', 'capital.C']
        for directory in ['one', 'two']:
            d = self.root / 'unittests' / directory
            d.mkdir(parents=True)
            for name in names:
                (d / name).write_text('int probe(void) { return 0; }\n')
        (self.root / 'lib').mkdir()
        (self.root / 'lib/helper.c').write_text('int helper(void) { return 0; }\n')
        (self.root / 'unittests/CMakeLists.txt').write_text('add_subdirectory(one)\nadd_subdirectory(two)\n')
        source_list = ' '.join(names)
        (self.root / 'unittests/one/CMakeLists.txt').write_text(
            'set(sources ' + source_list + ')\nadd_executable(one ${sources} ${CMAKE_SOURCE_DIR}/lib/helper.c)\n')
        p = self.root / 'unittests/two/CMakeLists.txt'
        p.write_text('# ' + source_list + '\nset(unused ' + source_list + ')\n')
        self.git('add', '.')
        self.assertEqual(sorted('unittests/two/' + n for n in names), unbuilt_tests(self.root))
        p.write_text('set(sources ' + source_list + ')\nadd_executable(two ${sources})\n')
        self.assertEqual([], unbuilt_tests(self.root))

    def test_whitespace_in_committed_push_range_and_worktree(self):
        p = self.root / 'file.txt'
        p.write_text('clean\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'base')
        base = self.git('rev-parse', 'HEAD').decode().strip()
        p.write_text('bad trailing space \n')
        self.git('add', '.')
        self.git('commit', '-qm', 'bad')
        with self.assertRaises(subprocess.CalledProcessError):
            whitespace(self.root, base)
        p.write_text('fixed\n')
        # An uncommitted cleanup cannot hide the bad committed push range.
        with self.assertRaises(subprocess.CalledProcessError):
            whitespace(self.root, base)
        self.git('add', '.')
        self.git('commit', '-qm', 'fix')
        whitespace(self.root, base)
        p.write_text('bad worktree \n')
        with self.assertRaises(subprocess.CalledProcessError):
            whitespace(self.root, 'HEAD')

    def test_explicit_base_rejects_descendant_divergent_missing_and_empty_refs(self):
        p = self.root / 'file.txt'
        p.write_text('base\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'base')
        base = self.git('rev-parse', 'HEAD').decode().strip()
        p.write_text('bad committed whitespace \n')
        self.git('add', '.')
        self.git('commit', '-qm', 'candidate')
        candidate = self.git('rev-parse', 'HEAD').decode().strip()
        p.write_text('descendant cleanup\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'descendant')
        descendant = self.git('rev-parse', 'HEAD').decode().strip()
        self.git('checkout', '--detach', base)
        p.write_text('different branch\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'divergent')
        divergent = self.git('rev-parse', 'HEAD').decode().strip()
        self.git('checkout', '--detach', candidate)
        for ref in (descendant, divergent, 'missing-ref', '', '--help'):
            with self.subTest(ref=ref), self.assertRaisesRegex(RuntimeError, 'ancestor of HEAD'):
                whitespace(self.root, ref)
        # A valid base still examines the candidate and catches its whitespace.
        with self.assertRaises(subprocess.CalledProcessError):
            whitespace(self.root, base)

    def test_explicit_ancestor_tag_and_current_head_are_valid(self):
        p = self.root / 'file.txt'
        p.write_text('base\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'base')
        self.git('tag', '-a', 'review-base', '-m', 'review base')
        p.write_text('clean candidate\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'candidate')
        whitespace(self.root, 'review-base')
        whitespace(self.root, 'HEAD')

    def test_missing_upstream_fails_without_explicit_base(self):
        with self.assertRaises(subprocess.CalledProcessError):
            whitespace(self.root)

    def test_docker_probe_needs_no_external_timeout_command(self):
        with patch('scripts.preflight_checks.subprocess.run') as run:
            docker_ready()
            self.assertEqual(['docker', 'info'], run.call_args.args[0])
            self.assertEqual(20, run.call_args.kwargs['timeout'])
            self.assertTrue(run.call_args.kwargs['check'])

    def test_docker_unavailable_failure_and_timeout_are_rejected(self):
        for error in [FileNotFoundError(), subprocess.CalledProcessError(1, 'docker'),
                      subprocess.TimeoutExpired('docker', 20)]:
            with self.subTest(error=error), patch('scripts.preflight_checks.subprocess.run', side_effect=error):
                with self.assertRaises(RuntimeError):
                    docker_ready()


if __name__ == '__main__':
    unittest.main()
