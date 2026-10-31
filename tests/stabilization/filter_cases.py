# -*- coding: utf-8 -*-
"""E35 valid legacy semantics, shared by old-source characterization and K07."""
ROWS = [
    (1, 'alpha', 'GET', '/api/a?x=1', 200, 'AbC\na,b aa', 10),
    (2, 'beta', 'POST', '/login', 302, 'xyz', 3),
    (3, 'alpha', 'GET', '/api/B', 404, '', 0),
    (4, 'gamma', 'PUT', '/asset', 500, 'ABC', 3),
    (5, 'ALPHA', 'GET', '/api/a', 204, '', None),
]


def display(field=None, values=(), mode='eq'):
    return {} if field is None else {field: dict(active=True, mode=mode, values=list(values))}


DISPLAY = [
    ('all', {}, [1,2,3,4,5]),
    ('host_case_sensitive', display('Host', ['alpha']), [1,3]),
    ('host_not_eq', display('Host', ['alpha'], 'not eq'), [2,4,5]),
    ('host_OR', display('Host', ['alpha','beta']), [1,2,3]),
    ('path_substring_case_sensitive', display('Path', ['/api/a']), [1,5]),
    ('method_exact', display('Method', ['GET']), [1,3,5]),
    ('status_exact', display('Status', ['200','500']), [1,4]),
    ('body_zero', display('BodyLen', ['0']), [3]),
    ('body_not_zero_includes_unknown', display('BodyLen', ['0'], 'not eq'), [1,2,4,5]),
    ('body_numbers_OR', display('BodyLen', ['3','10']), [1,2,4]),
    ('empty_active_rejects_even_not_eq', display('Host', [], 'not eq'), []),
    ('regex_case_insensitive', display('ResponseContent', ['abc']), [1,4]),
    ('regex_dotall_and_comma', display('ResponseContent', ['AbC.*a,b']), [1]),
    ('regex_on_headers', display('ResponseContent', ['X-Tag: mark']), [1,2,3,4,5]),
    ('regex_OR', display('ResponseContent', ['xyz','ABC']), [1,2,4]),
    ('regex_not_eq', display('ResponseContent', ['abc'], 'not eq'), [2,3,5]),
    ('regex_quantifier_comma', display('ResponseContent', ['a{1,3}']), [1,2,3,4,5]),
    ('fields_AND', dict(display('Host',['alpha']), **display('Status',['404'])), [3]),
]

CAPTURE = [
    ('all', {}, [1,2,3,4,5]),
    ('status_2xx', dict(statuses=(2,)), [1,5]),
    ('status_3xx_5xx', dict(statuses=(3,5)), [2,4]),
    ('body_min_uses_smallest', dict(size='2,4', len_type='Response body len', size_comp='Min Len'), [1,2,4]),
    ('body_max_uses_largest', dict(size='2,4', len_type='Response body len', size_comp='Max Len'), [2,3,4,5]),
    ('body_not_equal', dict(size='0,3', len_type='Response body len', size_comp='Not eq Len'), [1]),
    ('regex_case_sensitive', dict(log_regex='ABC'), [4]),
    ('regex_no_dotall', dict(log_regex='AbC.*a,b'), []),
    ('regex_on_headers', dict(log_regex='X-Tag: mark'), [1,2,3,4,5]),
    ('paused', dict(paused=True), []),
]
