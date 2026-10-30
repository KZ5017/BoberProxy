# -*- coding: utf-8 -*-
"""Load after main K03; actual helper/interface and finite local API checks."""
import json
import os
import sys
import traceback
from burp import IBurpExtender
from java.lang import Exception as JavaException


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        directory = os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        from k03_action_listener import install
        self.listener = install(callbacks, 'after')
        try:
            from probe_k03_native import run_checks
            result = run_checks(callbacks)
            result['burp_version'] = list(callbacks.getBurpVersion())
            path = os.path.join(directory, 'runtime', 'k03-burp-native.json')
            with open(path, 'w') as handle:
                handle.write(json.dumps(result, indent=2) + '\n')
            callbacks.printOutput('K03_NATIVE %s (%d checks)\n%s' % (
                'PASS' if result['passed'] else 'FAIL', len(result['checks']), path))
            if result['errors']:
                callbacks.printError('\n'.join(result['errors']))
        except (Exception, JavaException):
            callbacks.printError(traceback.format_exc())
