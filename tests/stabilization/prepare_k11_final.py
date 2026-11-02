"""Prepare only synthetic final K11 inputs; production source is untouched."""
import json
from pathlib import Path


def main():
    here=Path(__file__).resolve().parent
    runtime=here/'runtime'; runtime.mkdir(exist_ok=True)
    for original,final in [('request-template.http','k11-final-request-template.http'),
                           ('checkpage-template.http','k11-final-checkpage-template.http')]:
        data=(here/'fixtures'/original).read_bytes().replace(b'127.0.0.1:18765',b'127.0.0.1:18790')
        (here/'fixtures'/final).write_bytes(data)
    code=(here/'fixtures'/'custom-pass-through.py.in').read_text(encoding='utf-8')
    code=code.replace('"__TRACE_PATH__"','u'+json.dumps(str(runtime/'k11-final-custom-trace.jsonl')))
    code=code.replace('# Use the generated runtime/custom-pass-through.py in Burp, not this template.',
                      '# Generated K11 final trace; paste this entire runtime file into Burp.')
    code=code.replace('K00 synthetic-data trace','K11 synthetic-data trace')
    target=runtime/'custom-k11-final-pass-through.py'
    target.write_text(code,encoding='utf-8')
    print(target)


if __name__=='__main__': main()
