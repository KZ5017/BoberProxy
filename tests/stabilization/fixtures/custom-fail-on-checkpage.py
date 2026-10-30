# -*- coding: utf-8 -*-
def custom_codeblock(payload1, payload2, csrf_token):
    """Controlled K01 failure only after the action supplies a CSRF token."""
    if csrf_token is not None:
        raise ValueError("K01 controlled CheckPage transform failure")
    return payload1, payload2, csrf_token
