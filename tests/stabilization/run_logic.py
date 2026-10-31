# -*- coding: utf-8 -*-
"""Run the same source-logic cases on CPython or Jython and optionally write JSON."""
from __future__ import print_function

import argparse
import codecs
import hashlib
import json
import platform
import sys
import time
import unittest

import test_source_logic
from source_harness import SOURCE


class ReportResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        unittest.TextTestResult.__init__(self, *args, **kwargs)
        self.cases = []
        self.started = time.time()

    def startTest(self, test):
        self.started = time.time()
        unittest.TextTestResult.startTest(self, test)

    def record(self, test, outcome, detail=None):
        self.cases.append(dict(test=test.id(), outcome=outcome,
                               seconds=round(time.time() - self.started, 6), detail=detail))

    def addSuccess(self, test):
        self.record(test, 'passed')
        unittest.TextTestResult.addSuccess(self, test)

    def addExpectedFailure(self, test, err):
        if not isinstance(err[1], AssertionError):
            # A broken harness/import must never masquerade as a known defect.
            self.addError(test, err)
            return
        self.record(test, 'known_defect', self._exc_info_to_string(err, test))
        unittest.TextTestResult.addExpectedFailure(self, test, err)

    def addUnexpectedSuccess(self, test):
        self.record(test, 'unexpected_success_review_required')
        unittest.TextTestResult.addUnexpectedSuccess(self, test)

    def addFailure(self, test, err):
        self.record(test, 'failed', self._exc_info_to_string(err, test))
        unittest.TextTestResult.addFailure(self, test, err)

    def addError(self, test, err):
        self.record(test, 'error', self._exc_info_to_string(err, test))
        unittest.TextTestResult.addError(self, test, err)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', help='Optional JSON report path (parent must exist)')
    parser.add_argument('--suite', choices=['source', 'transport', 'templates', 'redirects', 'session', 'custom', 'runtime', 'filters', 'all'], default='source')
    args = parser.parse_args()
    suite = unittest.TestSuite()
    if args.suite in ('source', 'all'):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(test_source_logic))
    if args.suite in ('transport', 'all'):
        import test_transport
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(test_transport))
    if args.suite in ('templates', 'all'):
        import test_templates
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(test_templates))
    if args.suite in ('redirects', 'all'):
        import test_redirects
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(test_redirects))
    if args.suite in ('session', 'all'):
        import test_session_state
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(test_session_state))
    if args.suite in ('custom', 'all'):
        import test_custom_executor
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(test_custom_executor))
    if args.suite in ('runtime', 'all'):
        import test_runtime_session
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(test_runtime_session))
    if args.suite in ('filters', 'all'):
        import test_filters
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(test_filters))
    result = unittest.TextTestRunner(verbosity=2, resultclass=ReportResult).run(suite)
    with open(SOURCE, 'rb') as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    report = dict(kind='isolated-source-logic-not-burp-integration', suite=args.suite,
                  python=sys.version, implementation=platform.python_implementation(),
                  source_sha256=digest, cases=result.cases,
                  total=result.testsRun, passed=sum(c['outcome'] == 'passed' for c in result.cases),
                  known_defects=len(result.expectedFailures),
                  successful_baseline_run=result.wasSuccessful())
    if args.report:
        with codecs.open(args.report, 'w', 'utf-8') as handle:
            handle.write(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))
            handle.write('\n')
    print('Baseline: %d tests; %d known unfixed defects.' % (result.testsRun, len(result.expectedFailures)))
    print('Expected failures are reproduced defects, not fixed acceptance tests.')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
