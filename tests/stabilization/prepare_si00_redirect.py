"""Create separate exact-CRLF templates without changing previous evidence."""
import json
import re
from pathlib import Path


def main():
    base = Path(__file__).resolve().parent
    config = json.loads((base / 'runtime/si00-wire-config.json').read_text(encoding='utf-8'))
    name = config['cookie_name']
    if not re.fullmatch(r'BP_SI00_WIRE_[a-f0-9]{12}', name):
        raise ValueError('Own SI00 namespace required')
    for filename, target, body in (
            ('si00-redirect-request-template.http', 'start', 'one=p4yl04dm4rk3r&two=53c0undm4rk3r'),
            ('si00-redirect-checkpage-template.http', 'check', 'csrf=c5rfm4rk3r&one=p4yl04dm4rk3r&two=53c0undm4rk3r')):
        raw = ('POST /si00/%s?run=p4yl04dm4rk3r HTTP/1.1\r\nHost: 127.0.0.1:18781\r\n'
               'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n'
               'Cookie: %s=TEMPLATE\r\nConnection: close\r\n\r\n%s') % (target, len(body), name, body)
        path = base / 'fixtures' / filename
        data = raw.encode('ascii')
        if path.exists() and path.read_bytes() != data:
            raise RuntimeError('Preserve unexpected fixture: ' + str(path))
        path.write_bytes(data)
    print('Prepared si00-redirect-request/checkpage-template.http with owned TEMPLATE cookie.')


if __name__ == '__main__':
    main()
