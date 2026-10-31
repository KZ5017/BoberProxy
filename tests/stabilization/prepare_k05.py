"""Generate executable trace code for this workspace; .py.in is not loadable."""
import json
from pathlib import Path


def main():
    base = Path(__file__).resolve().parent
    runtime = base / 'runtime'
    runtime.mkdir(exist_ok=True)
    for source, target, trace in [
        ('custom-k05-cases.py.in', 'custom-k05-cases.py', 'k05-cases-trace.jsonl'),
        ('custom-pass-through.py.in', 'custom-k05-pass-through.py', 'k05-custom-trace.jsonl'),
    ]:
        text = (base / 'fixtures' / source).read_text(encoding='utf-8')
        path = 'u' + json.dumps(str(runtime / trace), ensure_ascii=True)
        result = text.replace('"__TRACE_PATH__"', path)
        if target == 'custom-k05-pass-through.py':
            result = result.replace('from java.lang import Runtime, System', 'from java.lang import Runtime, System, Thread')
            result = result.replace('    with open(trace_path,',
                '    record.update(worker_thread_id=Thread.currentThread().getId(),\n'
                '                  worker_group=str(Thread.currentThread().getThreadGroup().getName()))\n'
                '    with open(trace_path,', 1)
        assert '__TRACE_PATH__' not in result
        (runtime / target).write_text(result, encoding='utf-8')
    print('Prepared runtime/custom-k05-cases.py and custom-k05-pass-through.py.')


if __name__ == '__main__':
    main()
