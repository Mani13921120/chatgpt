"""Windows CI entry point; reports real test failures as check annotations."""
import io
import os
from pathlib import Path
import sys
import unittest
import ctypes


def annotation(value):
    return value.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    if os.name != 'nt':
        raise SystemExit('Windows validation requires real Windows, not mocks.')
    administrator = bool(ctypes.windll.shell32.IsUserAnAdmin())
    print(f'Administrator token: {administrator}', flush=True)
    suite = unittest.defaultTestLoader.loadTestsFromNames(['test_folder_gate', 'test_windows_commands', 'test_acl_policy'])
    report = io.StringIO()
    result = unittest.TextTestRunner(stream=report, verbosity=2).run(suite)
    print(report.getvalue(), flush=True)
    summary = f'Administrator token: {administrator}; tests: {result.testsRun}; failures: {len(result.failures)}; errors: {len(result.errors)}; skipped: {len(result.skipped)}'
    if os.environ.get('GITHUB_ACTIONS'):
        print('::notice title=Windows validation result::' + annotation(summary), flush=True)
    for test, trace in result.failures + result.errors:
        print('::error title=' + annotation(test.id()) + '::' + annotation(trace), flush=True)
    print(summary, flush=True)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        Path(os.environ['GITHUB_STEP_SUMMARY']).write_text('# Windows folder protection\n\n' + summary + '\n\n```text\n' + report.getvalue() + '\n```\n', encoding='utf-8')
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun and not result.skipped else 1)


if __name__ == '__main__':
    main()
