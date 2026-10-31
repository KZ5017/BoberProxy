"""Generate K04 templates with exact CRLF framing; no production edits."""
import json
from pathlib import Path


def main():
    base = Path(__file__).resolve().parent
    directory = base / 'fixtures'
    for name, path in [('k04-request-template.http', '/k04/action'),
                       ('k04-checkpage-template.http', '/k04/check')]:
        body = 'one=p4yl04dm4rk3r&two=53c0undm4rk3r&csrf=c5rfm4rk3r'
        text = ('POST %s?case=p4yl04dm4rk3r HTTP/1.1\r\nHost: 127.0.0.1:18769\r\n'
                'X-Bober-Test-Run: k04-workflow\r\nCookie: sid=template; untouched=x\r\n'
                'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n'
                'Connection: close\r\n\r\n%s') % (path, len(body), body)
        (directory / name).write_bytes(text.encode('ascii'))
    runtime = base / 'runtime'
    runtime.mkdir(exist_ok=True)
    custom = (directory / 'custom-pass-through.py.in').read_text(encoding='utf-8')
    trace_path = 'u' + json.dumps(str(runtime / 'k04-custom-trace.jsonl'), ensure_ascii=True)
    (runtime / 'custom-k04-pass-through.py').write_text(
        custom.replace('"__TRACE_PATH__"', trace_path), encoding='utf-8')
    print('Prepared K04 HTTP templates and runtime/custom-k04-pass-through.py.')


if __name__ == '__main__':
    main()
