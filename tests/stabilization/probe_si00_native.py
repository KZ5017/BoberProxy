# -*- coding: utf-8 -*-
"""Private native SI00 probe checks: real interfaces, fake jar, zero network."""
from __future__ import print_function
import argparse
import json
import sys
from java.io import IOException
from java.util import Date
from si00_cookie_probe import ProbeCookie, run_checks
from burp_session_probe import BurpExtender


class JarCallbacks(object):
    def __init__(self, path_aware=True, fail_write=None, close_after=None, broad_delete=False):
        self.path_aware = path_aware
        self.fail_write = fail_write
        self.close_after = close_after
        self.broad_delete = broad_delete
        self.writes = 0
        self.closed = False
        self.sentinel = ProbeCookie('unrelated.invalid', '/', 'EXISTING', 'DO_NOT_SERIALIZE', Date(9999999999999))
        self.jar = [self.sentinel]

    def getCookieJarContents(self): return list(self.jar)

    def updateCookieJar(self, cookie):
        self.writes += 1
        if self.writes == self.fail_write:
            raise IOException('Do not copy exception text into reports')
        domain, name, path = cookie.getDomain(), cookie.getName(), cookie.getPath()
        matches = [c for c in self.jar if c.getDomain() == domain and c.getName() == name
                   and (not self.path_aware or c.getPath() == path
                        or (self.broad_delete and cookie.getValue() is None))]
        self.jar = [c for c in self.jar if not (c.getDomain() == domain and c.getName() == name
                    and c in matches)]
        if cookie.getValue() is not None or not matches: self.jar.append(cookie)
        if self.writes == self.close_after: self.closed = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    checks, reports = {}, {}
    cookie = ProbeCookie('own.invalid', '/a', 'name', '', Date(123456789))
    checks['native_cookie_getters_no_bean_recursion'] = (cookie.getDomain() == 'own.invalid'
        and cookie.getPath() == '/a' and cookie.getName() == 'name' and cookie.getValue() == ''
        and cookie.getExpiration().getTime() == 123456789)
    for label, path_aware, broad_delete in [('path-aware', True, False), ('domain-name-only', False, False),
                                           ('path-aware-broad-delete', True, True)]:
        callbacks = JarCallbacks(path_aware, broad_delete=broad_delete)
        manifests = []
        report = run_checks(callbacks, persist=lambda value: manifests.append(bool(value['writes'])))
        reports[label] = report
        checks[label + '-probe-and-owned-cleanup'] = report['passed'] and report['cleanup_complete']
        checks[label + '-unrelated-cookie-preserved'] = callbacks.jar == [callbacks.sentinel]
        checks[label + '-manifest-before-first-write'] = manifests and manifests[0] is False
        expected_count = 2 if path_aware else 1
        checks[label + '-path-semantics-observed-not-assumed'] = report['observations']['same_name_path_behavior']['count'] == expected_count
        checks[label + '-no-unrelated-jar-values-in-report'] = 'DO_NOT_SERIALIZE' not in json.dumps(report)
    callbacks = JarCallbacks(fail_write=4)
    failed = run_checks(callbacks)
    reports['injected-api-error'] = failed
    checks['api-error-not-pass'] = not failed['passed'] and bool(failed['errors'])
    checks['api-error-owned-cleanup-and-unrelated-preserved'] = failed['cleanup_complete'] and callbacks.jar == [callbacks.sentinel]
    checks['api-error-text-not-in-report'] = 'Do not copy exception' not in json.dumps(failed)
    callbacks = JarCallbacks(close_after=2)
    cancelled = run_checks(callbacks, closed=lambda: callbacks.closed)
    reports['unload-during-probe'] = cancelled
    checks['unload-cancels-but-still-cleans-owned-data'] = (cancelled['cancelled'] and not cancelled['passed']
        and cancelled['cleanup_complete'] and callbacks.jar == [callbacks.sentinel])
    class Entry(BurpExtender):
        def _verify(self): self.verified = True
    class RegistrationCallbacks(object):
        def __init__(self, close_at):
            self.close_at = close_at
            self.actions = [self]
        def getExtensionFilename(self): return __file__
        def setExtensionName(self, name): pass
        def registerExtensionStateListener(self, extension):
            self.extension = extension
            if self.close_at == 'state': extension.extensionUnloaded()
        def registerSessionHandlingAction(self, action):
            self.actions.append(action)
            if self.close_at == 'action': self.extension.extensionUnloaded()
        def removeSessionHandlingAction(self, action): self.actions.remove(action)
    for close_at in ('state', 'action', None):
        callbacks = RegistrationCallbacks(close_at)
        extension = Entry()
        extension.registerExtenderCallbacks(callbacks)
        if hasattr(extension, '_probe_thread'): extension._probe_thread.join(5)
        extension.extensionUnloaded()
        checks['registration-cleanup-' + str(close_at)] = callbacks.actions == [callbacks]
    report = dict(kind='SI00-private-native-fake-cookie-jar', checks=checks, reports=reports,
                  passed=all(checks.values()), actual_burp_cookie_jar=False, network_requests=0)
    with open(args.report, 'w') as handle: json.dump(report, handle, indent=2)
    print('SI00_NATIVE %s (%d checks)' % ('PASS' if report['passed'] else 'FAIL', len(checks)))
    if not report['passed']: print(json.dumps(checks, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__': sys.exit(main())
