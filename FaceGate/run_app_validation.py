import io
import os
from pathlib import Path
import sys
import unittest
from run_windows_validation import annotation

if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8',errors='backslashreplace')
suite=unittest.defaultTestLoader.loadTestsFromNames(['test_app_catalog','test_app_runtime'])
stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
print(stream.getvalue())
summary=f'App tests: {result.testsRun}; failures: {len(result.failures)}; errors: {len(result.errors)}; skipped: {len(result.skipped)}'
print('::notice title=Windows app catalog::'+annotation(summary))
for test,trace in result.failures+result.errors:print('::error title='+annotation(test.id())+'::'+annotation(trace))
if os.environ.get('GITHUB_STEP_SUMMARY'):Path(os.environ['GITHUB_STEP_SUMMARY']).write_text(summary+'\n\n```\n'+stream.getvalue()+'\n```',encoding='utf-8')
raise SystemExit(0 if result.wasSuccessful() and result.testsRun and not result.skipped else 1)
