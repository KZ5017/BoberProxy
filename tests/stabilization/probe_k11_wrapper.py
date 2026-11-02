# -*- coding: utf-8 -*-
"""Standalone K11 channel/profile smoke, never beside a loaded live wrapper."""
import argparse
import hashlib
import json
import os
import time
import traceback
import uuid
from javax.swing import JPanel, SwingUtilities
from java.lang import Throwable
from source_harness import ROOT
from probe_k11_load import LoadHelpers
from burp_k11_instrumented import BurpExtender
from burp_k089_storage_probe import SyntheticMessage


def run():
    helpers=LoadHelpers()
    checks,errors={},[]
    class Editor(object):
        def __init__(self): self.value=helpers.stringToBytes('')
        def getMessage(self): return self.value
        def setMessage(self,value,request):
            if value is None: raise ValueError('Null editor value')
            self.value=value
        def getComponent(self): return JPanel()
    class Callbacks(object):
        def getExtensionFilename(self): return os.path.join(ROOT,'tests','stabilization','burp_k11_instrumented.py')
        def getHelpers(self): return helpers
        def getBurpVersion(self): return ['standalone fixture']
        def createMessageEditor(self,*args): return Editor()
        def setExtensionName(self,name): pass
        def registerExtensionStateListener(self,listener): pass
        def addSuiteTab(self,ui): pass
        def registerHttpListener(self,listener): pass
        def registerProxyListener(self,listener): pass
        def printOutput(self,text): pass
        def printError(self,text): errors.append(unicode(text))
    wrapper=BurpExtender()
    wrapper.channel_prefix='k11-smoke'
    def command(action):
        request=dict(instance=wrapper.instance,id=uuid.uuid4().hex,action=action)
        with open(wrapper.command_path,'w') as handle: json.dump(request,handle)
        end=time.time()+8
        while time.time()<end:
            try:
                with open(wrapper.ack_path) as handle: response=json.load(handle)
                if response.get('id')==request['id']:
                    if not response.get('ok'): raise AssertionError(response.get('error'))
                    return response
            except (IOError,ValueError): pass
            time.sleep(.01)
        raise AssertionError('Channel timeout: '+action)
    try:
        wrapper.registerExtenderCallbacks(Callbacks())
        checks['source_hash_matches']=wrapper.hash==hashlib.sha256(open(os.path.join(ROOT,'BoberProxy.py'),'rb').read()).hexdigest()
        for profile in ('passive','normal','rt-only','empty-cp','cp-error','custom-error','bad-return','top-timeout',
                        'function-timeout','cp-timeout','invalid-timeout','busy','close','redirect-off','redirect-on','loop','limit','workflow-timeout','held'):
            state=command('profile-'+profile)['state']
            checks['profile_'+profile]=state['profile']==profile and state['proxy']==(profile!='passive')
        checks['unknown_profile_rejected']=False
        try: command('profile-unknown')
        except AssertionError: checks['unknown_profile_rejected']=True
        command('profile-passive')
        command('metrics-reset')
        message=SyntheticMessage(helpers,helpers.stringToBytes('GET /bytes?size=1 HTTP/1.1\r\nHost: 127.0.0.1:18790\r\nX-Bober-Test-Run: k11-smoke\r\n\r\n'),helpers.stringToBytes('HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nX'))
        message.setHttpService(helpers.buildHttpService('127.0.0.1',18790,False))
        checks['only_tagged_loopback_scope']=wrapper.scoped(message)
        redirect=SyntheticMessage(helpers,helpers.stringToBytes('GET /k11/redirect/next?run=k11-smoke HTTP/1.1\r\nHost: 127.0.0.1:18790\r\n\r\n'),helpers.stringToBytes('HTTP/1.1 200 OK\r\n\r\n'))
        redirect.setHttpService(helpers.buildHttpService('127.0.0.1',18790,False))
        checks['minimal_redirect_query_tag_is_in_scope']=wrapper.scoped(redirect)
        redirect.setRequest(helpers.stringToBytes('GET /k11/redirect/next?run=foreign HTTP/1.1\r\n\r\n'))
        checks['foreign_query_tag_stays_out_of_scope']=not wrapper.scoped(redirect)
        wrapper.main.processHttpMessage(4,False,message)
        end=time.time()+5
        while command('state')['state']['stored']!=1 and time.time()<end: time.sleep(.02)
        result=command('metrics-stop')
        checks['source_callback_archive_and_metrics']=result['state']['stored']==1 and result['state']['raw_bytes']==0 and len(result['metrics']['http_ms'])==1 and len(result['metrics']['appearance_ms'])==1
        for name in ('display-bytes','display-none','pause','resume','clear-state','clear','tiny-budget','normal-budget'):
            command(name)
            checks['action_'+name]=True
    except (BaseException,Throwable): errors.append(traceback.format_exc())
    finally:
        if hasattr(wrapper,'main'):
            wrapper.main.extensionUnloaded()
            if hasattr(wrapper,'thread'): wrapper.thread.join(3)
            SwingUtilities.invokeAndWait(lambda:None)
            if wrapper.main.ui is not None:
                for worker in (wrapper.main.ui._custom_executor,wrapper.main.ui._filter_worker,wrapper.main.ui._log_writer,wrapper.main.ui._log_io):
                    if worker.worker is not None: worker.worker.join(5)
            checks['owned_controller_and_timer_stopped']=(not hasattr(wrapper,'thread') or not wrapper.thread.is_alive()) and (not hasattr(wrapper,'heartbeat') or not wrapper.heartbeat.isRunning())
    return dict(kind='K11-standalone-wrapper-no-network',checks=checks,errors=errors,passed=bool(checks) and all(checks.values()) and not errors,source_sha256=getattr(wrapper,'hash',None))


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--report',required=True)
    args=parser.parse_args()
    if os.path.exists(args.report): raise ValueError('Report exists')
    result=run()
    with open(args.report,'w') as handle: json.dump(result,handle,indent=2)
    print(json.dumps(result,indent=2))
    import sys
    sys.exit(0 if result['passed'] else 1)
