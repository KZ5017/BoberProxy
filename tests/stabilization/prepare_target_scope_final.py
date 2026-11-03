# -*- coding: utf-8 -*-
"""Generate ignored pass-through trace code for direct-root TG05 gate."""
import json
from pathlib import Path
directory=Path(__file__).resolve().parent;runtime=directory/'runtime'
trace=runtime/'tg-final-custom-trace.jsonl'
code='''# -*- coding: utf-8 -*-
# Generated TG05 local synthetic trace; paste this runtime file, not a template.
def custom_codeblock(payload1, payload2, csrf_token):
    import json
    from java.lang import System
    trace_path = TRACE_PATH
    record = dict(payload1=payload1, payload2=payload2, csrf_token=csrf_token,
                  java_version=unicode(System.getProperty('java.version')))
    with open(trace_path, 'ab') as handle:
        handle.write((json.dumps(record, ensure_ascii=True) + '\\n').encode('utf-8'))
    return payload1, payload2, csrf_token
'''.replace('TRACE_PATH','u'+json.dumps(str(trace),ensure_ascii=True))
(runtime/'custom-tg-final-pass-through.py').write_text(code,encoding='utf-8')
print('TG05 final custom fixture ready')
