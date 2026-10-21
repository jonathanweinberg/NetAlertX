"""Regression checks for the container PHP security boundary."""

from pathlib import Path
import importlib.util
import json
import subprocess
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('check_php_runtime', ROOT / 'scripts/check_php_runtime.py')
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class ContainerBuildTests(unittest.TestCase):
    """Keep both distribution targets behind the same PHP runtime guard."""

    def test_alpine_checks_serving_binaries_before_hardening(self):
        """Reject an Alpine build without the patched runtime boundary."""
        dockerfile = (ROOT / 'Dockerfile').read_text()
        self.assertTrue('check_php_runtime.py --cli php83 --server php-fpm83 --server php-cgi83' in dockerfile)
        self.assertLess(dockerfile.index('check_php_runtime.py --cli'), dockerfile.index('FROM runner AS hardened'))
        for package in ('php83', 'php83-fpm', 'php83-cgi', 'php83-curl', 'php83-sqlite3', 'php83-session'):
            self.assertIn(f"'{package}>=8.3.36'", dockerfile)

    def test_debian_checks_its_serving_binary(self):
        """Keep the Debian target from silently retaining old PHP-FPM."""
        dockerfile = (ROOT / 'Dockerfile.debian').read_text()
        self.assertTrue('check_php_runtime.py --cli php8.3 --server php-fpm8.3' in dockerfile)


class RuntimeGuardTests(unittest.TestCase):
    """Exercise the security floor without depending on a local PHP install."""

    def test_affected_releases_are_rejected(self):
        """Reject the observed image and every branch's preceding release."""
        for version in ((8, 3, 29), (8, 2, 34), (8, 3, 35), (8, 4, 26), (8, 5, 11), (8, 1, 99), (8, 6, 0)):
            with self.subTest(version=version), self.assertRaises(ValueError):
                runtime.require_patched(version)

    def test_fixed_and_later_patch_releases_are_accepted(self):
        """Allow reviewed fixed versions and later patches in those branches."""
        for version in ((8, 2, 35), (8, 3, 36), (8, 3, 37), (8, 4, 27), (8, 5, 12)):
            runtime.require_patched(version)

    def test_native_banners_and_prereleases(self):
        """Parse serving SAPIs but do not treat a prerelease as stable."""
        for sapi in ('cli', 'fpm-fcgi', 'cgi-fcgi'):
            self.assertEqual(runtime.parse_version(f'PHP 8.3.36 ({sapi}) (NTS)\n'), (8, 3, 36))
        for output in ('PHP 8.3.36RC1 (cli)', 'PHP 8.3.36-dev (cli)', 'not PHP'):
            with self.subTest(output=output), self.assertRaises(ValueError):
                runtime.parse_version(output)

    def test_matching_runtimes_and_extensions(self):
        """Accept a fully patched CLI/FPM/CGI set with required extensions."""
        with patch.object(runtime, 'command_output', side_effect=[
                'PHP 8.3.36 (cli)', 'PHP 8.3.36 (fpm-fcgi)', 'PHP 8.3.36 (cgi-fcgi)',
                json.dumps(['curl', 'session', 'sqlite3'])]):
            self.assertEqual(runtime.check_runtime('php', ['fpm', 'cgi']), (8, 3, 36))

    def test_old_fpm_is_not_hidden_by_patched_cli(self):
        """Reject an affected serving binary even when the CLI is current."""
        with patch.object(runtime, 'command_output', side_effect=['PHP 8.3.36 (cli)', 'PHP 8.3.29 (fpm-fcgi)']), \
                self.assertRaises(ValueError):
            runtime.check_runtime('php', ['fpm'])

    def test_mixed_patched_versions_are_rejected(self):
        """Do not ship inconsistent runtime package families."""
        with patch.object(runtime, 'command_output', side_effect=['PHP 8.3.37 (cli)', 'PHP 8.3.36 (fpm-fcgi)']), \
                self.assertRaises(ValueError):
            runtime.check_runtime('php', ['fpm'])

    def test_missing_and_invalid_extensions_are_rejected(self):
        """Protect the application extension contract as well as version numbers."""
        for extensions in (['curl', 'session'], {}, [1, 'curl']):
            with patch.object(runtime, 'command_output', side_effect=[
                    'PHP 8.3.36 (cli)', 'PHP 8.3.36 (fpm-fcgi)', json.dumps(extensions)]), self.assertRaises(ValueError):
                runtime.check_runtime('php', ['fpm'])

    def test_command_is_bounded_and_diagnostics_fail(self):
        """Use argv and an explicit timeout without ignoring startup warnings."""
        with patch.object(runtime.subprocess, 'run', return_value=Mock(stdout='ok', stderr='')) as run:
            self.assertEqual(runtime.command_output(['php', '-v']), 'ok')
            self.assertEqual(run.call_args.kwargs['timeout'], 15)
            self.assertTrue(run.call_args.kwargs['check'])
            run.return_value.stderr = 'startup warning'
            with self.assertRaises(ValueError):
                runtime.command_output(['php', '-v'])

    def test_missing_binary_and_timeout_fail_closed(self):
        """Report unavailable serving binaries as failed checks."""
        for error in (FileNotFoundError('missing'), subprocess.TimeoutExpired('php', 15)):
            with patch.object(runtime, 'check_runtime', side_effect=error), \
                    patch.object(runtime.sys, 'stderr'):
                self.assertEqual(runtime.main(['--cli', 'php', '--server', 'fpm']), 1)


if __name__ == '__main__':
    unittest.main()
