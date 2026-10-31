# -*- coding: utf-8 -*-
"""Private K06 fixtures; no network and no changes to the main extension."""
from burp import IBurpExtender
import json
import os
import sys
import traceback


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName('BoberProxy K06 runtime verification')
        directory = os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        try:
            from probe_runtime_native import run_checks
            report = run_checks(callbacks)
            report['burp_version'] = list(callbacks.getBurpVersion())
            path = os.path.join(directory, 'runtime', 'k06-burp-runtime.json')
            with open(path, 'w') as handle:
                handle.write(json.dumps(report, indent=2, ensure_ascii=True) + '\n')
            callbacks.printOutput('K06_RUNTIME %s (%d session cases; %d native/UI checks)\n%s' % (
                'PASS' if report['passed'] else 'FAIL', report['session_cases'], len(report['checks']), path))
            if report['errors']:
                callbacks.printError('\n'.join(report['errors']))
        except BaseException:
            callbacks.printError(traceback.format_exc())
