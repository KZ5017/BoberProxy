#!/usr/bin/env python3
"""Build the minimal v1.0.0 archive without altering an existing artifact.

Only the explicitly listed files are packaged. ZIP_STORED, fixed timestamps,
permissions and ordering make the resulting bytes independent of filesystem
timestamps and zlib versions. Run from any directory with Python 3.
"""
import argparse
import hashlib
import io
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    'BoberProxy.py',
    'CHANGELOG.md',
    'LICENSE',
    'README.md',
    'lib/README.md',
    'lib/RSyntaxTextArea-LICENSE.txt',
    'lib/rsyntaxtextarea-3.6.3.jar',
    'screenshots/workspace.png',
)


def archive_bytes():
    missing = [name for name in FILES if not (ROOT / name).is_file()]
    if missing:
        raise SystemExit('Missing release inputs: ' + ', '.join(missing))
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name in FILES:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, (ROOT / name).read_bytes())
    return data.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist' / 'BoberProxy-v1.0.0.zip')
    args = parser.parse_args()
    data = archive_bytes()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with args.output.open('xb') as handle:
            handle.write(data)
    except FileExistsError:
        raise SystemExit('Output already exists; choose a new path: ' + str(args.output))
    print('Created:', args.output.resolve())
    print('SHA-256:', hashlib.sha256(data).hexdigest())
    print('Files:', len(FILES))


if __name__ == '__main__':
    main()
