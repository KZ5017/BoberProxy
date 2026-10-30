"""Prepare ignored K02 inputs; production code is never changed here."""
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    directory = Path(__file__).resolve().parent
    runtime = directory / 'runtime'
    runtime.mkdir(exist_ok=True)
    baseline = subprocess.check_output(['git', 'show',
                                        '04d6398a14c412800a4a03a2268877cfa9305de7:BoberProxy.py'])
    baseline = baseline.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
    assert hashlib.sha256(baseline).hexdigest() == '3bf88a21442683c6135895125aac49ac09bd52a31be13b9ff75daaf8fcdfb111'
    (runtime / 'k02-baseline-source.py').write_bytes(baseline)
    trace = (directory / 'fixtures' / 'custom-pass-through.py.in').read_text(encoding='utf-8')
    path_literal = 'u' + json.dumps(str(runtime / 'k02-custom-trace.jsonl'), ensure_ascii=True)
    trace = trace.replace('"__TRACE_PATH__"', path_literal)
    trace = trace.replace('def custom_codeblock(', 'def _trace(')
    cases = (directory / 'fixtures' / 'custom-k02-cases.py.in').read_text(encoding='utf-8')
    path = runtime / 'custom-k02-cases.py'
    path.write_text(trace + '\n' + cases, encoding='utf-8')
    print(path)


if __name__ == '__main__':
    main()
