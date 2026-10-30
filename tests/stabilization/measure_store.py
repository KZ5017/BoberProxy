# -*- coding: utf-8 -*-
"""Isolated metadata/list microbenchmark; not Burp traffic or full UI throughput."""
from __future__ import print_function

import argparse
import codecs
import gc
import hashlib
import json
import platform
import time

from source_harness import SOURCE, load_namespace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sizes', default='1000,10000,100000')
    parser.add_argument('--iterations', type=int, default=3)
    parser.add_argument('--report')
    args = parser.parse_args()
    sizes = [int(value) for value in args.sizes.split(',')]
    if any(value < 1 or value > 100000 for value in sizes) or not 1 <= args.iterations <= 3:
        parser.error('Baseline is capped at 100000 rows and 3 iterations')
    namespace = load_namespace()
    runs = []
    for size in sizes:
        for iteration in range(args.iterations):
            gc.collect()
            store = namespace['LogStore']()
            model = namespace['LogTableModel'](store)
            started = time.time()
            for index in range(size):
                entry = store.add('baseline', 'fixture', 'GET', '/echo', 200, 64, 1, None)
                model.add_entry_top(entry, True)
            elapsed = time.time() - started
            assert len(store.entries) == size and model.getRowCount() == size
            assert store.entries[0].index == size and store.entries[-1].index == 1
            runs.append(dict(size=size, iteration=iteration + 1, seconds=elapsed))
            print('%d rows, iteration %d: %.6fs' % (size, iteration + 1, elapsed))
            del entry, store, model
    with open(SOURCE, 'rb') as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    report = dict(kind='isolated-source-metadata-two-list-microbenchmark',
                  implementation=platform.python_implementation(), source_sha256=digest,
                  messages_contain_real_http_bodies=False, real_swing=False, runs=runs)
    if args.report:
        with codecs.open(args.report, 'w', 'utf-8') as handle:
            handle.write(json.dumps(report, indent=2, ensure_ascii=True) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
