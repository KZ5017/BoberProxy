# -*- coding: utf-8 -*-
"""Current source with actual Burp API: port/TLS redirects and shared deadline.

Private namespaces, no Proxy hook replacement or global settings changes.
Requires the owned K03 fixture on loopback18800/18801/18802.
"""
import hashlib
import json
import os
import traceback
import uuid
from java.lang import Throwable
from source_harness import ROOT, new_ui, Editor, Field, Check, as_text
from probe_template_native import load_source
from probe_k03_native import run_checks as deadline_checks


def run(callbacks):
    helpers=callbacks.getHelpers(); wire=helpers.stringToBytes
    ns,raw=load_source(os.path.join(ROOT,'BoberProxy.py'))
    checks,errors,cases={},[],[]
    for case in ('relative','cross-port','cross-scheme'):
        ui=new_ui(ns)
        try:
            run='k11-api-'+uuid.uuid4().hex[:12]
            ui.helpers,ui.callbacks=helpers,callbacks
            ui._http_sender=ns['HttpRequestSender'](callbacks,helpers)
            ui.useCheckPageTemplate=True;ui.autoUpdateCookies=True;ui.autoUpdateCsrf=True
            ui.autoFollowRTChk=Check(selected=True)
            ui.csrfRegexArea=Field(r'value="([^"]*)"');ui._on_csrf_regex_changed()
            ui.reqTemplateEditor=Editor(wire('POST /k03/a/start?case=p4yl04dm4rk3r&run='+run+' HTTP/1.1\r\nHost: 127.0.0.1:9\r\nX-Bober-Test-Run: '+run+'\r\n\r\n'))
            ui.checkPageEditor=Editor(wire('POST /k03/check HTTP/1.1\r\nHost: 127.0.0.1:9\r\nX-Bober-Test-Run: '+run+'\r\n\r\ncsrf=c5rfm4rk3r&one=p4yl04dm4rk3r'))
            result=ui.proxy_flow_process_request(wire('GET /entry?q='+case+' HTTP/1.1\r\n\r\n'),'127.0.0.1',18800,False)
            checks[case+'_ready']=result.status==ns['ProxyWorkflowResult'].READY
            response=None
            if checks[case+'_ready']:
                final=callbacks.makeHttpRequest(helpers.buildHttpService('127.0.0.1',18800,False),result.request_bytes)
                response=json.loads(as_text(final.getResponse()).split('\r\n\r\n',1)[1])
            checks[case+'_final_cookie_and_token']=bool(response and response.get('cookie_ok') and response.get('token_ok'))
            observed={}
            for port in (18800,18801,18802):
                control=callbacks.makeHttpRequest(helpers.buildHttpService('127.0.0.1',port,port==18802),
                    wire('GET /__control/events?run='+run+' HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n'%port))
                observed[str(port)]=json.loads(as_text(control.getResponse()).split('\r\n\r\n',1)[1])
            checks[case+'_exact_once_and_service']=sum(v['event_count'] for v in observed.values())==3 and observed['18800']['action_count']==1 and observed['18800']['event_count']==(3 if case=='relative' else 2)
            if case!='relative':checks[case+'_changed_target']=observed['18801' if case=='cross-port' else '18802']['event_count']==1
            cases.append(dict(case=case,run=run,target=observed,response=response,status=result.status))
        except (BaseException,Throwable):errors.append(traceback.format_exc())
        finally:ui.close_custom_runtime()
    deadline=deadline_checks(callbacks,target_port=18800)
    return dict(kind='K11-private-current-source-real-Burp-API-loopback-port-TLS-deadline',source_sha256=hashlib.sha256(raw).hexdigest(),checks=checks,cases=cases,errors=errors,deadline=deadline,passed=bool(checks) and all(checks.values()) and not errors and deadline['passed'])
