# -*- coding: utf-8 -*-
"""Temporary verification extension; load separately from BoberProxy in Burp.

No listener, tab or traffic. Writes synthetic checks using actual Burp helpers.
Remove this probe extension after collecting the report.
"""
from burp import IBurpExtender
import json
import os
import sys
import traceback


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName('BoberProxy K02 helper verification')
        directory = os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        try:
            from probe_template_native import run_checks
            report = run_checks(callbacks.getHelpers())
            report['burp_version'] = list(callbacks.getBurpVersion())
            path = os.path.join(directory, 'runtime', 'k02-burp-helper.json')
            with open(path, 'w') as handle:
                handle.write(json.dumps(report, indent=2, ensure_ascii=True) + '\n')
            callbacks.printOutput('K02_HELPERS %s (%d checks)\n%s' % (
                'PASS' if report['passed'] else 'FAIL', len(report['checks']), path))
            if report['errors']:
                callbacks.printError('\n'.join(report['errors']))
        except BaseException:
            callbacks.printError(traceback.format_exc())
