# -*- coding: utf-8 -*-
import os
import sys
import json
import uuid
from burp import IBurpExtender


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        sys.path.insert(0,os.path.dirname(unicode(callbacks.getExtensionFilename())))
        from k11_manual import ManualObserver
        self.observer=ManualObserver()
        self.observer.ROLE='before'
        self.observer.registerExtenderCallbacks(callbacks)
        from probe_k11_selection import run
        report=run(callbacks,real_export=True)
        path=os.path.join(os.path.dirname(unicode(callbacks.getExtensionFilename())),'runtime',
                          'k11-burp-selection-'+uuid.uuid4().hex+'.json')
        with open(path,'w') as handle: json.dump(report,handle,indent=2)
        callbacks.printOutput('K11_SELECTION %s (%d checks)\n%s' % ('PASS' if report['passed'] else 'FAIL',len(report['checks']),path))
        if report['errors']: callbacks.printError('\n'.join(report['errors']))
        from probe_k11_redirect_api import run as redirect_run
        redirect=redirect_run(callbacks)
        redirect_path=path.replace('selection-','redirect-api-')
        with open(redirect_path,'w') as handle: json.dump(redirect,handle,indent=2)
        callbacks.printOutput('K11_REDIRECT_API %s\n%s' % ('PASS' if redirect['passed'] else 'FAIL',redirect_path))
        if redirect['errors']: callbacks.printError('\n'.join(redirect['errors']))
