"""External JVM bounds for nonterminating code; never load this into Burp."""
import argparse
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    java = Path(r'C:\Users\KZsolt\AppData\Local\Programs\BurpSuite\jre\bin\java.exe')
    jar = Path(r'C:\Users\KZsolt\Downloads\jython-standalone-2.7.4.jar')
    script = Path(__file__).with_name('probe_custom_isolated_child.py')
    args.directory.mkdir(parents=True, exist_ok=True)
    results = []
    for case in ('python-loop', 'java-wait'):
        report = args.directory / (case + '.json')
        if report.exists():
            raise RuntimeError('Do not overwrite an earlier isolated attempt')
        try:
            child = subprocess.run([str(java), '-Dpython.cachedir.skip=true', '-Xmx256m', '-jar', str(jar),
                                    '-B', str(script), '--case', case, '--report', str(report)],
                                   capture_output=True, timeout=45)
            passed = child.returncode == 0 and report.exists() and json.loads(report.read_text())['passed']
            results.append(dict(case=case, passed=passed, exit_code=child.returncode,
                                stdout=child.stdout.decode('utf-8', errors='replace'),
                                stderr=child.stderr.decode('utf-8', errors='replace')))
        except subprocess.TimeoutExpired:
            # subprocess.run kills and waits for its own child on timeout.
            results.append(dict(case=case, passed=False, externally_killed=True))
        print(case, 'PASS' if results[-1]['passed'] else 'FAIL', flush=True)
    (args.directory / 'summary.json').write_text(json.dumps(dict(
        kind='externally-bounded-dedicated-JVMs-not-running-Burp',
        passed=all(item['passed'] for item in results), results=results,
        external_timeout_seconds=45), indent=2) + '\n', encoding='utf-8')
    return 0 if all(item['passed'] for item in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
