"""Combine one real proxy workflow with its incremental custom-code trace."""
import argparse
import json
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--expect-empty-token', action='store_true')
    parser.add_argument('--trace', type=Path, help='Optional generated pass-through trace path')
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    base = Path(__file__).resolve().parent
    trace = args.trace if args.trace is not None else base / 'runtime' / 'burp-custom-trace.jsonl'
    before = trace.read_text(encoding='utf-8').splitlines() if trace.exists() else []
    result = subprocess.run([sys.executable, '-B', str(base / 'probe_proxy.py'), '--scenario', 'checkpage',
                             '--report', str(args.directory / 'burp-checkpage-custom.json')],
                            capture_output=True, text=True, timeout=10)
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    after = trace.read_text(encoding='utf-8').splitlines() if trace.exists() else []
    records = [json.loads(line) for line in after[len(before):]]
    checks = dict(traffic_passed=result.returncode == 0,
                  exactly_two_custom_calls=len(records) == 2,
                  payloads_preserved=len(records) == 2 and all(
                      record['payload1'] == '%252F+%2B' and record['payload2'] == 'TWO' for record in records),
                  second_token_updated=len(records) == 2 and records[1]['csrf_token'] == 'csrf.k00-workflow.1')
    if args.expect_empty_token:
        checks['first_token_empty'] = len(records) == 2 and records[0]['csrf_token'] is None
    report = dict(kind='live-burp-custom-trace', checks=checks, passed=all(checks.values()),
                  records=records, trace_count_before=len(before), trace_count_after=len(after),
                  expected_initial_token='empty' if args.expect_empty_token else 'not asserted')
    (args.directory / 'burp-custom-trace.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'], checks=checks), indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
