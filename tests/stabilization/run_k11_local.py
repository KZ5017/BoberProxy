"""K11 local regression driver: isolated JVMs, immutable per-attempt reports.

Python 3 only. Never load this file as a Burp extension. No network traffic.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--only', help='Comma-separated task names for a focused rerun')
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=False)
    directory = args.directory.resolve()
    here = Path(__file__).resolve().parent
    root = here.parents[1]
    java = Path(os.environ['LOCALAPPDATA']) / 'Programs/BurpSuite/jre/bin/java.exe'
    jython = Path.home() / 'Downloads/jython-standalone-2.7.4.jar'
    burp = java.parents[2] / 'burpsuite.jar'
    digest = hashlib.sha256((root / 'BoberProxy.py').read_bytes()).hexdigest()
    native = [str(java), '--enable-native-access=ALL-UNNAMED', '-Xmx768m',
              '-Dpython.cachedir.skip=true', '-cp', str(jython) + os.pathsep + str(burp),
              'org.python.util.jython', '-B']
    python = [sys.executable, '-B']
    tasks = [('cpython-logic', python, 'run_logic.py', ['--suite', 'all'], 90),
             ('jython-logic', native, 'run_logic.py', ['--suite', 'all'], 120)]
    tasks += [(name, native, script, [], 120) for name, script in [
        ('native-template', 'probe_template_native.py'),
        ('native-redirect', 'probe_k03_native.py'),
        ('native-session', 'probe_session_native.py'),
        ('native-custom', 'probe_custom_native.py'),
        ('native-runtime', 'probe_runtime_native.py'),
        ('native-filters', 'probe_filters_native.py'),
        ('native-editor-layout-logging', 'probe_ui03_native.py'),
        ('native-aggregate', 'probe_k11_native.py'),
        ('native-k11-wrapper', 'probe_k11_wrapper.py'),
        ('native-k11-selection', 'probe_k11_selection.py'),
        ('native-k11-lifecycle', 'probe_logging_lifecycle.py'),
        ('native-k11-manual', 'probe_k11_manual_native.py')]]
    tasks += [('cpython-metadata', python, 'measure_store.py', [], 90),
              ('jython-metadata', native, 'measure_store.py', [], 120),
              ('isolated-regex', python, 'probe_filter_isolated.py', [], 45),
              ('isolated-custom', python, 'probe_custom_isolated.py', [], 110)]
    if args.only:
        names = set(args.only.split(','))
        if names - {task[0] for task in tasks}:
            parser.error('Unknown task name')
        tasks = [task for task in tasks if task[0] in names]
    driver_started_utc = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    runs = []
    for name, runtime, script, extra, bound in tasks:
        report = directory / (name + '.json')
        arguments = ['--directory', str(directory / name)] if name == 'isolated-custom' else ['--report', str(report)]
        command = runtime + [str(here / script)] + extra + arguments
        started = time.monotonic()
        timed_out = False
        with (directory / (name + '.stdout.txt')).open('wb') as output:
            try:
                result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT,
                                        timeout=bound, cwd=str(root))
                code = result.returncode
            except subprocess.TimeoutExpired:
                timed_out, code = True, None
        if name == 'isolated-custom':
            report = directory / name / 'summary.json'
        data = json.loads(report.read_text(encoding='utf-8')) if report.exists() else {}
        passed = code == 0 and not timed_out and bool(data)
        passed = bool(passed and data.get('successful_baseline_run', data.get('passed', True)))
        runs.append(dict(name=name, command=command, seconds=time.monotonic() - started,
                         report=str(report.relative_to(directory)), exit_code=code,
                         timed_out=timed_out, passed=passed))
        print(name, 'PASS' if passed else 'FAIL', flush=True)
        summary = dict(kind='K11-local-regression-not-live-Burp-acceptance',
                       source_sha256=digest, python=sys.version, os=platform.platform(),
                       started_utc=driver_started_utc,
                       runs=runs, complete=len(runs) == len(tasks),
                       passed=all(item['passed'] for item in runs),
                       network_requests=0, k11_closed=False)
        (directory / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    assert hashlib.sha256((root / 'BoberProxy.py').read_bytes()).hexdigest() == digest
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
