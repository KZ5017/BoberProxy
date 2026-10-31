# -*- coding: utf-8 -*-
"""Freeze E35 behavior using the real legacy Java engine; no UI or network."""
from __future__ import print_function
import argparse
import hashlib
import json
import os
from source_harness import ROOT, new_ui, CapturedOutput
from probe_template_native import load_source
from filter_cases import ROWS, DISPLAY, CAPTURE


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    ns, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
    ui = new_ui(ns)
    cases = []
    class Message(object):
        def __init__(self, body, status):
            self.response = ui.helpers.stringToBytes('HTTP/1.1 %d Fixture\r\nX-Tag: mark\r\n\r\n%s' % (status, body))
        def getResponse(self):
            return self.response
    entries = []
    for index, host, method, path, status, body, body_len in ROWS:
        msg = Message(body, status)
        entries.append(ns['LogEntry'](index,'t',host,method,path,status,len(msg.response),body_len,msg))
    with CapturedOutput():
        for name, config, expected in DISPLAY:
            actual = [e.index for e in entries if ui._row_matches_filters(e, config)]
            cases.append(dict(kind='display', name=name, actual=actual, expected=expected, passed=actual==expected))
        for name, config, expected in CAPTURE:
            actual = [e.index for e in entries if ui.should_log(4,False,e.messageInfo,ns['RuntimeConfig'](config,0))]
            cases.append(dict(kind='admission', name=name, actual=actual, expected=expected, passed=actual==expected))
    ui.close_custom_runtime()
    report = dict(kind='K06-legacy-Java-filter-characterization-no-network', cases=cases,
                  source_sha256=hashlib.sha256(raw).hexdigest(), passed=all(c['passed'] for c in cases))
    with open(args.report,'w') as handle:
        json.dump(report,handle,indent=2)
    print(json.dumps(report,indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
