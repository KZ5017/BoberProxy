"""Write fixed K00 templates with real CRLF and exact Content-Length."""
from pathlib import Path
import json


def main():
    directory = Path(__file__).parent / "fixtures"
    directory.mkdir(exist_ok=True)
    bodies = {
        "request-template.http": ("/workflow/action", "one=p4yl04dm4rk3r&two=53c0undm4rk3r"),
        "checkpage-template.http": ("/workflow/check", "csrf=c5rfm4rk3r&one=p4yl04dm4rk3r&two=53c0undm4rk3r"),
        "request-close.http": ("/accept-then-close", "one=p4yl04dm4rk3r&two=53c0undm4rk3r"),
    }
    for filename, (path, body) in bodies.items():
        text = ("POST %s HTTP/1.1\r\nHost: 127.0.0.1:18765\r\n"
                "X-Bober-Test-Run: k00-workflow\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: %d\r\nConnection: close\r\n\r\n%s") % (path, len(body), body)
        (directory / filename).write_bytes(text.encode("ascii"))
        print(directory / filename)
    runtime = directory.parent / 'runtime'
    runtime.mkdir(exist_ok=True)
    template = (directory / 'custom-pass-through.py.in').read_text(encoding='utf-8')
    path_literal = 'u' + json.dumps(str((runtime / 'burp-custom-trace.jsonl').resolve()), ensure_ascii=True)
    generated = template.replace('"__TRACE_PATH__"', path_literal)
    (runtime / 'custom-pass-through.py').write_text(generated, encoding='utf-8')
    print(runtime / 'custom-pass-through.py')


if __name__ == "__main__":
    main()
