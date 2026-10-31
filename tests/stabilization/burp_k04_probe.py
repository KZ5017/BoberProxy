# -*- coding: utf-8 -*-
"""Temporary K04 helper verification, without listeners or network traffic."""
from burp import IBurpExtender
import json
import os
import sys
import traceback


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName('BoberProxy K04 session verification')
        directory = os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        try:
            from probe_session_native import run_checks
            report = run_checks(callbacks.getHelpers())
            report['burp_version'] = list(callbacks.getBurpVersion())
            path = os.path.join(directory, 'runtime', 'k04-burp-session.json')
            with open(path, 'w') as handle:
                handle.write(json.dumps(report, indent=2, ensure_ascii=True) + '\n')
            callbacks.printOutput('K04_SESSION %s (%d checks)\n%s' % (
                'PASS' if report['passed'] else 'FAIL', len(report['checks']), path))
            if report['errors']:
                callbacks.printError('\n'.join(report['errors']))
        except BaseException:
            callbacks.printError(traceback.format_exc())
