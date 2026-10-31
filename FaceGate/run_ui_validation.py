"""Headless real Qt event-loop tests; the camera and external launch are mocked."""
import io
import faulthandler
import os
from pathlib import Path
import sys
import unittest
import traceback
from run_windows_validation import annotation

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
suite = unittest.defaultTestLoader.loadTestsFromNames(['test_folder_ui', 'test_shell_integration', 'test_session_setup', 'test_explorer_sessions'])
faulthandler.enable()


class LiveReport(io.StringIO):
    def write(self, value):
        result = super().write(value)
        sys.stdout.write(value)
        sys.stdout.flush()
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            Path(os.environ['GITHUB_STEP_SUMMARY']).write_text(
                '# Qt validation progress\n\n```text\n' + self.getvalue() + '\n```\n', encoding='utf-8')
        return result


stream = LiveReport()
try:
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
except BaseException:
    print('::error title=Qt validation interrupted::' + annotation(traceback.format_exc()), flush=True)
    raise
summary = f'Qt tests: {result.testsRun}; failures: {len(result.failures)}; errors: {len(result.errors)}; skipped: {len(result.skipped)}'
print('::notice title=Windows UI validation::' + annotation(summary))
for test, trace in result.failures + result.errors:
    print('::error title=' + annotation(test.id()) + '::' + annotation(trace))
if os.environ.get('GITHUB_STEP_SUMMARY'):
    Path(os.environ['GITHUB_STEP_SUMMARY']).write_text(summary + '\n\n```\n' + stream.getvalue() + '\n```', encoding='utf-8')
raise SystemExit(0 if result.wasSuccessful() and result.testsRun and not result.skipped else 1)
