"""Generate only the workspace-local normal pass-through trace for K07."""
import json
from pathlib import Path


def main():
    base=Path(__file__).resolve().parent
    runtime=base/'runtime'
    runtime.mkdir(exist_ok=True)
    text=(base/'fixtures/custom-pass-through.py.in').read_text(encoding='utf-8')
    text=text.replace('"__TRACE_PATH__"','u'+json.dumps(str(runtime/'k07-custom-trace.jsonl')))
    assert '__TRACE_PATH__' not in text
    (runtime/'custom-k07-pass-through.py').write_text(text,encoding='utf-8')
    print('Prepared runtime/custom-k07-pass-through.py; normal HTTP fixtures are unchanged.')


if __name__=='__main__':
    main()
