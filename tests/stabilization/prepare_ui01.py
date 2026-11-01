"""Generate the workspace-local UI01 normal pass-through trace."""
import json
from pathlib import Path


def main():
    base=Path(__file__).resolve().parent
    runtime=base/'runtime'
    runtime.mkdir(exist_ok=True)
    text=(base/'fixtures/custom-pass-through.py.in').read_text(encoding='utf-8')
    text=text.replace('"__TRACE_PATH__"','u'+json.dumps(str(runtime/'ui01-custom-trace.jsonl')))
    assert '__TRACE_PATH__' not in text
    (runtime/'custom-ui01-pass-through.py').write_text(text,encoding='utf-8')
    print('Prepared runtime/custom-ui01-pass-through.py; HTTP fixtures unchanged.')


if __name__=='__main__': main()
