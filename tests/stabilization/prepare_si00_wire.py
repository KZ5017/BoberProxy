"""Prepare a persistent synthetic namespace; never rotate a loaded probe's config."""
import json
import uuid
from pathlib import Path


def main():
    runtime = Path(__file__).resolve().parent / 'runtime'
    runtime.mkdir(exist_ok=True)
    path = runtime / 'si00-wire-config.json'
    if path.exists():
        config = json.loads(path.read_text())
    else:
        config = dict(cookie_name='BP_SI00_WIRE_' + uuid.uuid4().hex[:12],
                      hosts=['127.0.0.1', 'localhost'], ports=[18780, 18781, 18782])
        path.write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8')
    (runtime / 'si00-rule-cookie-name.txt').write_text(config['cookie_name'] + '\n', encoding='utf-8')
    print('Prepared SI00 wire config; cookie: ' + config['cookie_name'])


if __name__ == '__main__': main()
