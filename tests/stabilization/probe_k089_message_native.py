# -*- coding: utf-8 -*-
"""Finite standalone Jython/Java interface regression; no Burp instance/network."""
import argparse
import json
import traceback
from java.lang import Class
from java.util import Arrays
from burp import IHttpService
from jarray import array
from burp_k089_storage_probe import SyntheticMessage


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    class Service(IHttpService):
        def getHost(self): return '127.0.0.1'
        def getPort(self): return 18765
        def getProtocol(self): return 'http'
    class Helpers(object):
        def buildHttpService(self, host, port, https): return Service()
    checks, errors = {}, []
    try:
        request = array([0, 127, -128, -1], 'b')
        response = array([-1, -128, 0, 127], 'b')
        message = SyntheticMessage(Helpers(), request, response)
        checks['construct_request_response'] = (Arrays.equals(message.getRequest(), request)
                                                and Arrays.equals(message.getResponse(), response))
        message.setRequest(response)
        message.setResponse(None)
        checks['setters_do_not_recurse'] = Arrays.equals(message.getRequest(), response) and message.getResponse() is None
        message.setComment('changed')
        message.setHighlight('red')
        checks['annotation_setters_do_not_recurse'] = message.getComment() == 'changed' and message.getHighlight() == 'red'
        message.setHttpService(Service())
        checks['service_setter_does_not_recurse'] = message.getHost() == '127.0.0.1' and message.getPort() == 18765
        interface = Class.forName('burp.IHttpRequestResponse')
        result = interface.getMethod('getRequest', []).invoke(message, [])
        checks['native_interface_dispatch'] = Arrays.equals(result, response)
        checks['native_response_null_dispatch'] = interface.getMethod('getResponse', []).invoke(message, []) is None
    except BaseException:
        errors.append(traceback.format_exc())
    report = dict(kind='K089-synthetic-message-Jython-JavaBean-regression', checks=checks, errors=errors,
                  passed=len(checks) == 6 and all(checks.values()) and not errors)
    with open(args.report, 'w') as handle:
        json.dump(report, handle, indent=2)
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
