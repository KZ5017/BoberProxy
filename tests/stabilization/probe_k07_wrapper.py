# -*- coding: utf-8 -*-
"""Standalone fixed-profile/file-channel smoke. Never run beside live wrapper."""
from __future__ import print_function
import argparse
import json
import os
import time
import traceback
import uuid
from javax.swing import JTable, JPanel, SwingUtilities
from javax.swing.table import TableRowSorter
from source_harness import ROOT, Helpers, Response
from burp_k07_instrumented import BurpExtender


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',required=True)
    args=parser.parse_args()
    checks,errors={},[]
    class Editor(object):
        def getComponent(self):
            return JPanel()
        def getMessage(self):
            return None
    class Callbacks(object):
        _k07_skip_native=True
        def getExtensionFilename(self):
            return os.path.join(ROOT,'tests','stabilization','burp_k07_instrumented.py')
        def getHelpers(self):
            return Helpers()
        def createMessageEditor(self,*a):
            return Editor()
        def setExtensionName(self,name):
            pass
        def registerExtensionStateListener(self,listener):
            pass
        def addSuiteTab(self,ui):
            pass
        def registerHttpListener(self,listener):
            pass
        def registerProxyListener(self,listener):
            pass
        def printOutput(self,text):
            print(text)
        def printError(self,text):
            errors.append(str(text))
    wrapper=BurpExtender()
    def command(action):
        request=dict(instance=wrapper.instance,id=uuid.uuid4().hex,action=action)
        with open(wrapper.command_path,'w') as handle:
            json.dump(request,handle)
        end=time.time()+5
        while time.time()<end:
            try:
                with open(wrapper.ack_path) as handle:
                    reply=json.load(handle)
                if reply.get('id')==request['id'] and reply.get('instance')==wrapper.instance:
                    if not reply.get('ok'):
                        raise AssertionError(reply.get('error'))
                    return reply['state']
            except (IOError,ValueError):
                pass
            time.sleep(0.01)
        raise AssertionError('Command timeout: '+action)
    def wait_for(predicate):
        end=time.time()+5
        while time.time()<end:
            state=command('state')
            if predicate(state):
                return state
        raise AssertionError('Profile/gate did not settle')
    try:
        wrapper.registerExtenderCallbacks(Callbacks())
        SwingUtilities.invokeAndWait(lambda:None)
        checks['main_ready_on_edt']=wrapper.main.ui._creation_on_edt
        command('capture-alpha')
        active=wait_for(lambda s:s['capture_pattern']=='TOKEN_ALPHA' and not s['capture_error'])
        checks['capture_profile_compiled']=active['capture_pattern']=='TOKEN_ALPHA'
        command('capture-invalid')
        invalid=wait_for(lambda s:s['capture_error'] is not None)
        checks['invalid_keeps_plan']=invalid['capture_pattern']=='TOKEN_ALPHA'
        command('capture-none')
        ui=wrapper.main.ui
        def insert():
            message=Response(ui.helpers.stringToBytes('HTTP/1.1 200 OK\r\n\r\nTOKEN_ALPHA'))
            ui.logStore.add('t','demo','GET','/echo',200,len(message.data),11,message)
        SwingUtilities.invokeAndWait(insert)
        command('display-tokens')
        visible=wait_for(lambda s:len(s['displayed'])==1 and not s['rebuilding'])
        checks['display_profile_preserves_store']=len(visible['stored'])==1
        count=sum(p['count'] for p in visible['compile_patterns'])
        command('gate')
        wait_for(lambda s:s['gate_entered'])
        clear=command('clear')
        checks['clear_works_while_gated']=not clear['stored'] and not clear['displayed'] and clear['worker']['active']
        command('release')
        end=wait_for(lambda s:not s['worker']['active'] and not s['worker']['results'])
        checks['old_result_cannot_restore']=not end['stored'] and not end['displayed']
        checks['no_rowwise_compilation']=sum(p['count'] for p in end['compile_patterns'])==count
    except BaseException:
        checks['smoke']=False
        errors.append(traceback.format_exc())
    finally:
        if hasattr(wrapper,'main'):
            wrapper.main.extensionUnloaded()
            wrapper.thread.join(2)
            SwingUtilities.invokeAndWait(lambda:None)
            worker=wrapper.main.ui._filter_worker
            if worker.worker:
                worker.worker.join(2)
            checks['unload_stops_controller']=not wrapper.thread.is_alive()
            checks['unload_stops_filter_timer']=wrapper.main.ui._filter_timer is None
    report=dict(kind='K07-standalone-fixed-profile-wrapper-no-network',checks=checks,errors=errors,
                passed=bool(checks) and all(checks.values()) and not errors,
                source_sha256=getattr(wrapper,'hash',None))
    with open(args.report,'w') as handle:
        json.dump(report,handle,indent=2)
    print(json.dumps(report,indent=2))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    import sys
    sys.exit(main())
