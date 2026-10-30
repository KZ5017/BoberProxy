"""Generate exact HTTP fixtures, local trace code and an ignored test certificate."""
import json
import shutil
import subprocess
from pathlib import Path


def main():
    base = Path(__file__).resolve().parent
    runtime = base / 'runtime'
    runtime.mkdir(exist_ok=True)
    fixtures = base / 'fixtures'
    for name, target, body in [
        ('k03-request-template.http', '/k03/a/start?case=p4yl04dm4rk3r', 'one=p4yl04dm4rk3r&two=53c0undm4rk3r'),
        ('k03-checkpage-template.http', '/k03/check', 'csrf=c5rfm4rk3r&one=p4yl04dm4rk3r&two=53c0undm4rk3r'),
        ('k03-ready-template.http', '/echo', 'one=p4yl04dm4rk3r&two=53c0undm4rk3r'),
    ]:
        extra = 'X-Bober-K03-Probe: active-ready\r\n' if 'ready' in name else ''
        wire = ('POST %s HTTP/1.1\r\nHost: template.invalid:9\r\n'
                'User-Agent: K03-Fixture\r\nAuthorization: Bearer K03-SYNTHETIC\r\n'
                'X-Bober-Test-Run: k03-workflow\r\n%s'
                'Content-Type: application/x-www-form-urlencoded\r\n'
                'Content-Length: %d\r\nConnection: close\r\n\r\n%s') % (target, extra, len(body), body)
        (fixtures / name).write_bytes(wire.encode('ascii'))
    source = (fixtures / 'custom-pass-through.py.in').read_text(encoding='utf-8')
    trace_path = 'u' + json.dumps(str(runtime / 'k03-custom-trace.jsonl'), ensure_ascii=True)
    (runtime / 'custom-k03-pass-through.py').write_text(source.replace('"__TRACE_PATH__"', trace_path), encoding='utf-8')
    openssl = shutil.which('openssl') or 'C:/Program Files/Git/usr/bin/openssl.exe'
    cert, key = runtime / 'k03-cert.pem', runtime / 'k03-key.pem'
    if not cert.exists() or not key.exists():
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '2',
                        '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'],
                       check=True, capture_output=True)
    print('Prepared K03 HTTP fixtures, runtime/custom-k03-pass-through.py and ignored local TLS certificate.')


if __name__ == '__main__':
    main()
