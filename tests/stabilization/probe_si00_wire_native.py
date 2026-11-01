# -*- coding: utf-8 -*-
"""Real interfaces, private callback doubles and private file channels; no traffic."""
from __future__ import print_function
import argparse
import json
import os
import sys
import tempfile
import uuid
from java.io import IOException
from probe_logging_native import NativeHelpers
from probe_si00_native import JarCallbacks
from burp_si00_wire_probe import BurpExtender
from si00_wire import WireProbe


class Message(object):
    def __init__(self, helpers, host='127.0.0.1', port=18780, path='/si00/echo?run=si00-test', cookie=''):
        self.service = helpers.buildHttpService(host, port, False)
        self.request = helpers.stringToBytes('GET %s HTTP/1.1\r\nHost: %s:%d\r\n%s\r\n' % (
            path,host,port,'Cookie: '+cookie+'\r\n' if cookie else ''))
        self.response = helpers.stringToBytes('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')
    def getHttpService(self): return self.service
    def getRequest(self): return self.request
    def getResponse(self): return self.response


class Callbacks(JarCallbacks):
    def __init__(self, directory, close_at=None):
        JarCallbacks.__init__(self)
        self.helpers = NativeHelpers()
        self.directory, self.close_at = directory, close_at
        self.actions, self.http, self.proxy = [self], [], []
        self.sends, self.outputs, self.errors = 0, [], []
        self.fail_send = False
    def getHelpers(self): return self.helpers
    def getExtensionFilename(self): return os.path.join(self.directory,'burp_si00_wire_probe.py')
    def setExtensionName(self,name): pass
    def printOutput(self,value): self.outputs.append(value)
    def printError(self,value): self.errors.append(value)
    def registerExtensionStateListener(self,owner):
        self.owner = owner
        if self.close_at=='state': owner.extensionUnloaded()
    def registerSessionHandlingAction(self,item):
        self.actions.append(item)
        if self.close_at=='action': self.owner.extensionUnloaded()
    def removeSessionHandlingAction(self,item): self.actions.remove(item)
    def registerHttpListener(self,item):
        self.http.append(item)
        if self.close_at=='http': self.owner.extensionUnloaded()
    def removeHttpListener(self,item): self.http.remove(item)
    def registerProxyListener(self,item):
        self.proxy.append(item)
        if self.close_at=='proxy': self.owner.extensionUnloaded()
    def removeProxyListener(self,item): self.proxy.remove(item)
    def makeHttpRequest(self,service,request):
        self.sends += 1
        if self.fail_send: raise IOException('Synthetic accepted-but-unknown transport outcome')
        result = Message(self.helpers)
        result.service, result.request = service, request
        return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',required=True)
    args=parser.parse_args()
    runtime=os.path.join(os.path.dirname(os.path.abspath(__file__)),'runtime')
    directory=tempfile.mkdtemp(prefix='si00-native-private-',dir=runtime)
    channel=os.path.join(directory,'runtime')
    os.mkdir(channel)
    config=dict(cookie_name='BP_SI00_WIRE_'+uuid.uuid4().hex[:12])
    with open(os.path.join(channel,'si00-wire-config.json'),'w') as handle: json.dump(config,handle)
    checks, errors = {}, []
    def command(operation,**values):
        result=dict(instance='private',id=uuid.uuid4().hex,operation=operation)
        result.update(values)
        return result
    try:
        callbacks=Callbacks(directory)
        probe=WireProbe(callbacks,channel,'private',config)
        for label,host,port,path in [
            ('foreign-host','elsewhere.invalid',18780,'/si00/echo?run=si00-test'),
            ('foreign-port','127.0.0.1',80,'/si00/echo?run=si00-test'),
            ('unmarked','127.0.0.1',18780,'/si00/echo'),
            ('other-path','127.0.0.1',18780,'/echo?run=si00-test')]:
            before=probe.sequence
            probe.observe('scope-test',Message(callbacks.helpers,host,port,path),True)
            checks['ignore-'+label]=probe.sequence==before
        probe.observe('scope-test',Message(callbacks.helpers,cookie='UNRELATED=DO_NOT_KEEP'),True)
        checks['unowned-cookie-values-not-in-trace']=('DO_NOT_KEEP' not in json.dumps(probe.records)
            and probe.records[-1]['other_cookie_count']==1)
        probe.execute(command('seed'))
        checks['seed-is-owned-and-readable']=len(probe.jar())==1
        checks['cleanup-preserves-unrelated']=probe.cleanup()['cleanup_complete'] and callbacks.jar==[callbacks.sentinel]
        send=command('send',path='/si00/echo?run=si00-once')
        probe.execute(send)
        try: probe.execute(send)
        except ValueError: pass
        checks['duplicate-command-not-sent-twice']=callbacks.sends==1
        callbacks.fail_send=True
        uncertain=command('send',path='/si00/echo?run=si00-uncertain')
        try: probe.execute(uncertain)
        except IOException: pass
        try: probe.execute(uncertain)
        except ValueError: pass
        checks['uncertain-send-command-not-replayed']=callbacks.sends==2
        for label,values in [('host',dict(host='example.invalid',path='/si00/echo?run=si00-test')),
                             ('path',dict(path='/si00/echo')),
                             ('tls-disabled',dict(port=18782,path='/si00/echo?run=si00-test'))]:
            try: probe.execute(command('send',**values))
            except ValueError: pass
            checks['reject-send-'+label]=callbacks.sends==2
        macro=Message(callbacks.helpers,path='/si00/token?run=si00-macro')
        macro.response=callbacks.helpers.stringToBytes('HTTP/1.1 200 OK\r\n\r\n<input name="si00_token" value="SI00.ONE">')
        other=Message(callbacks.helpers,host='other.invalid',path='/si00/token?run=si00-macro')
        other.response=callbacks.helpers.stringToBytes('HTTP/1.1 200 OK\r\n\r\n<input name="si00_token" value="PRIVATE">')
        probe.actions[1].performAction(Message(callbacks.helpers),[macro,other])
        checks['only-scoped-macro-tokens-observed']=probe.records[-1]['macro_tokens']==['SI00.ONE']
        probe.closed=True
        try: probe.execute(command('send',path='/si00/echo?run=si00-closed'))
        except ValueError: pass
        checks['closed-probe-cannot-send']=callbacks.sends==2
        bounded=WireProbe(callbacks,channel,'bounded',config)
        for n in range(2050): bounded.emit(dict(phase='capacity'))
        checks['trace-buffer-bounded-with-visible-drops']=len(bounded.records)==2048 and bounded.dropped==2
        for stage in ('state','action','http','proxy',None):
            cb=Callbacks(directory,stage)
            owner=BurpExtender()
            owner.registerExtenderCallbacks(cb)
            owner.extensionUnloaded()
            if hasattr(owner,'_thread'): owner._thread.join(5)
            checks['withdraw-owned-handlers-'+str(stage)]=(cb.actions==[cb] and not cb.http and not cb.proxy
                and (not hasattr(owner,'_thread') or not owner._thread.is_alive()) and not cb.errors)
    except BaseException as error:
        import traceback
        errors.append(traceback.format_exc())
    finally:
        # Only explicit files in this newly created private directory are removed.
        for name in ('si00-wire-config.json','si00-wire-state.json','si00-wire-trace.jsonl'):
            path=os.path.join(channel,name)
            if os.path.isfile(path): os.remove(path)
        os.rmdir(channel)
        os.rmdir(directory)
    report=dict(kind='SI00-private-wire-observer-channel-no-network',checks=checks,errors=errors,
                passed=bool(checks) and all(checks.values()) and not errors,network_requests=0,
                actual_cookie_jar=False,live_channel_used=False)
    with open(args.report,'w') as handle: json.dump(report,handle,indent=2)
    print('SI00_WIRE_NATIVE %s (%d checks)' % ('PASS' if report['passed'] else 'FAIL',len(checks)))
    if not report['passed']: print(json.dumps(report,indent=2))
    return 0 if report['passed'] else 1


if __name__=='__main__': sys.exit(main())
