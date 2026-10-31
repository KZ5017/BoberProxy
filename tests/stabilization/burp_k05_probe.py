# -*- coding: utf-8 -*-
"""Finite K05 verification with actual Burp helpers; no listener or traffic."""
from burp import IBurpExtender
import json
import os
import sys
import traceback


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName('BoberProxy K05 custom verification')
        directory = os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        try:
            from probe_custom_native import run_checks
            report = run_checks(callbacks.getHelpers())
            report['burp_version'] = list(callbacks.getBurpVersion())
            path = os.path.join(directory, 'runtime', 'k05-burp-custom.json')
            with open(path, 'w') as handle:
                handle.write(json.dumps(report, indent=2, ensure_ascii=True) + '\n')
            callbacks.printOutput('K05_CUSTOM %s (%d executor cases; %d native/UI checks)\n%s' % (
                'PASS' if report['passed'] else 'FAIL', report['executor_cases'], len(report['checks']), path))
            if report['errors']:
                callbacks.printError('\n'.join(report['errors']))
        except BaseException:
            callbacks.printError(traceback.format_exc())
