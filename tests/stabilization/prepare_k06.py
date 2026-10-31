"""Generate exact CRLF HTTP fixtures and workspace-local finite custom probes."""
import json
from pathlib import Path


def main():
    base = Path(__file__).resolve().parent
    runtime = base / 'runtime'
    runtime.mkdir(exist_ok=True)
    for step, target in [('action', 'k06-request-template.http'), ('check', 'k06-checkpage-template.http')]:
        body = 'csrf=c5rfm4rk3r&one=p4yl04dm4rk3r&two=53c0undm4rk3r'
        text = ('POST /k06/%s?case=p4yl04dm4rk3r HTTP/1.1\r\n'
                'Host: 127.0.0.1:18770\r\nX-Bober-Test-Run: k06-wire\r\n'
                'Content-Type: application/x-www-form-urlencoded\r\n'
                'Content-Length: %d\r\nConnection: close\r\n\r\n%s') % (step, len(body), body)
        (base / 'fixtures' / target).write_bytes(text.encode('ascii'))
    text = (base / 'fixtures/custom-k06-cases.py.in').read_text(encoding='utf-8')
    text = text.replace('"__TRACE_PATH__"', 'u' + json.dumps(str(runtime / 'k06-custom-cases.jsonl')))
    text = text.replace('"__RELEASE_DIRECTORY__"', 'u' + json.dumps(str(runtime)))
    assert '__TRACE_PATH__' not in text and '__RELEASE_DIRECTORY__' not in text
    (runtime / 'custom-k06-cases.py').write_text(text, encoding='utf-8')
    normal = (base / 'fixtures/custom-pass-through.py.in').read_text(encoding='utf-8')
    normal = normal.replace('"__TRACE_PATH__"', 'u' + json.dumps(str(runtime / 'k06-custom-trace.jsonl')))
    (runtime / 'custom-k06-pass-through.py').write_text(normal, encoding='utf-8')
    print('Prepared K06 CRLF fixtures and finite custom probes.')


if __name__ == '__main__':
    main()
