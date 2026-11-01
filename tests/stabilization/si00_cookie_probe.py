# -*- coding: utf-8 -*-
"""Finite cookie-jar characterization using only uniquely owned synthetic keys."""
from __future__ import print_function

import time
import uuid
from burp import ICookie
from java.lang import Throwable
from java.util import Date


class ProbeCookie(ICookie):
    # Private backing fields avoid Jython's JavaBean getter/setter recursion.
    def __init__(self, domain, path, name, value, expiration=None):
        self._probe_domain = domain
        self._probe_path = path
        self._probe_name = name
        self._probe_value = value
        self._probe_expiration = expiration

    def getDomain(self): return self._probe_domain
    def getPath(self): return self._probe_path
    def getName(self): return self._probe_name
    def getValue(self): return self._probe_value
    def getExpiration(self): return self._probe_expiration


class ProbeClosed(Exception):
    pass


def run_checks(callbacks, closed=lambda: False, persist=None):
    token = uuid.uuid4().hex
    domain = 'si00-' + token + '.invalid'
    prefix = 'BP_SI00_' + token + '_'
    names = [prefix + suffix for suffix in ('main', 'empty', 'deleted', 'expired')]
    checks, observations, errors, writes = {}, {}, [], []
    namespace_acquired = False
    started = int(time.time() * 1000)
    report = dict(kind='SI00-owned-synthetic-cookie-API-characterization',
                  domain=domain, cookie_names=names, checks=checks,
                  observations=observations, errors=errors, writes=writes,
                  network_requests=0, main_extension_settings_changed=False,
                  cleanup_complete=False, cancelled=False, passed=False)

    def save():
        if persist is not None:
            persist(report)

    def own(cookie):
        cookie_domain = cookie.getDomain()
        return (cookie_domain is not None
                and str(cookie_domain).lower().lstrip('.') == domain
                and str(cookie.getName()) in names)

    def owned():
        # Never serialize unrelated values, domains or names from the user's jar.
        return [cookie for cookie in callbacks.getCookieJarContents() if own(cookie)]

    def view():
        result = []
        for cookie in owned():
            expiry = cookie.getExpiration()
            value = cookie.getValue()
            path = cookie.getPath()
            result.append(dict(name=str(cookie.getName()), path=str(path) if path is not None else None,
                               value=str(value) if value is not None else None,
                               expiration_ms=int(expiry.getTime()) if expiry is not None else None))
        return sorted(result, key=lambda row: (row['name'], row['path'] or ''))

    def write(name, path, value, expiration=None, cleaning=False):
        if name not in names:
            raise AssertionError('Unowned cookie key')
        if closed() and not cleaning:
            raise ProbeClosed()
        # Log only synthetic operation metadata, never unrelated jar data.
        writes.append(dict(name=name, domain=domain, path=path,
                           deletion=value is None, cleanup=cleaning))
        callbacks.updateCookieJar(ProbeCookie(domain, path, name, value, expiration))

    def step(key, operation):
        if closed():
            raise ProbeClosed()
        operation()
        checks[key] = True  # API returned; detailed semantics are observations.
        observations[key] = view()
        save()

    try:
        save()  # Ownership manifest exists before the first jar mutation.
        checks['read_cookie_jar'] = callbacks.getCookieJarContents() is not None
        checks['owned_namespace_initially_empty'] = not owned()
        if not checks['owned_namespace_initially_empty']:
            raise AssertionError('Synthetic namespace collision')
        namespace_acquired = True
        step('add_returns', lambda: write(names[0], '/', 'ONE', Date(started + 3600000)))
        checks['added_value_readable'] = any(row['name'] == names[0] and row['value'] == 'ONE'
                                           for row in observations['add_returns'])
        step('update_returns', lambda: write(names[0], '/', 'TWO', Date(started + 7200000)))
        checks['updated_value_readable'] = any(row['name'] == names[0] and row['value'] == 'TWO'
                                             for row in observations['update_returns'])
        step('different_path_update_returns', lambda: write(names[0], '/si00/deep', 'PATH'))
        main = [row for row in observations['different_path_update_returns'] if row['name'] == names[0]]
        observations['same_name_path_behavior'] = dict(count=len(main), paths=[row['path'] for row in main])
        step('empty_value_update_returns', lambda: write(names[1], '/', ''))
        step('literal_deleted_update_returns', lambda: write(names[2], '/', 'deleted'))
        step('past_expiration_update_returns', lambda: write(names[3], '/', 'PAST', Date(started - 60000)))
        step('null_deletion_returns', lambda: write(names[2], '/', None))
        checks['null_deletes_existing_cookie'] = not any(cookie.getName() == names[2] for cookie in owned())
    except ProbeClosed:
        report['cancelled'] = True
    except (BaseException, Throwable) as error:
        # Do not render unknown host exception text, which may contain jar data.
        errors.append(dict(stage='probe', type=type(error).__name__))
    finally:
        try:
            # One pass over actual owned entries, then verify. Never clear the jar.
            keys = (set((str(cookie.getName()), str(cookie.getPath()) if cookie.getPath() is not None else None)
                        for cookie in owned()) if namespace_acquired else set())
            for name, path in sorted(keys, key=lambda pair: (pair[0], pair[1] or '')):
                try:
                    # A host may delete all paths for a domain/name at once.
                    # Never send a second null update for an already absent key.
                    if any(str(cookie.getName()) == name and cookie.getPath() == path for cookie in owned()):
                        write(name, path, None, cleaning=True)
                except (BaseException, Throwable) as error:
                    errors.append(dict(stage='owned-cookie-cleanup', type=type(error).__name__))
            remaining = view() if namespace_acquired else []
            observations['owned_after_cleanup'] = remaining
            observations['namespace_acquired'] = namespace_acquired
            report['cleanup_complete'] = not remaining
            checks['only_owned_cookie_writes'] = all(w['domain'] == domain and w['name'] in names for w in writes)
            checks['owned_cookies_removed'] = report['cleanup_complete']
        except (BaseException, Throwable) as error:
            errors.append(dict(stage='cleanup-verification', type=type(error).__name__))
        report['passed'] = bool(checks) and all(checks.values()) and not errors and not report['cancelled']
        report['elapsed_ms'] = int(time.time() * 1000) - started
        save()
    return report
