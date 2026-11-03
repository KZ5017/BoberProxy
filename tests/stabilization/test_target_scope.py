# -*- coding: utf-8 -*-
"""Target policy and workflow safety checks; identical CPython/Jython source blocks."""
from __future__ import print_function
import unittest
from source_harness import load_namespace, new_ui, as_bytes, as_text, Callbacks, Check, Response
from test_source_logic import SourceCase
from test_transport import Intercepted

class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.ns=load_namespace()
    def policy(self, origin='http://demo', prefix=''):
        return self.ns['TargetScopePolicy'](origin,prefix)
    def request(self,target='/admin/x',host='demo'):
        return as_bytes('GET %s HTTP/1.1\r\nHost: %s\r\n\r\n'%(target,host))
    def test_default_port_and_case(self):
        a=self.policy('HTTP://DeMo:80/')
        self.assertTrue(a.equivalent(self.policy()))
        self.assertTrue(a.allows('DEMO',80,False,'/'))
        for h,p,t in [('sub.demo',80,False),('demo',81,False),('demo',443,True),('127.0.0.1',80,False)]:
            self.assertFalse(a.allows(h,p,t,'/'))
    def test_invalid_origins(self):
        for value in ['', 'ftp://demo','http://u@demo','http://demo/?','http://demo/#','http://demo/app','http://*.demo','http://demo.','http://demo:0','http://demo:65536','http://demo:+80','http://demo:','http://demo\\x','http://demo\nHost:x','http://127.1','http://127.00.0.1','http://[:::1]']:
            with self.assertRaises(ValueError): self.policy(value)
    def test_idna_and_ipv6_without_name_resolution(self):
        self.assertTrue(self.policy(u'http://b\u00fccher.test').allows('xn--bcher-kva.test',80,False,'/'))
        a=self.policy('http://[::1]:8080')
        self.assertTrue(a.allows('0:0:0:0:0:0:0:1',8080,False,'/'))
        self.assertTrue(self.policy('http://[::ffff:127.0.0.1]').equivalent(self.policy('http://[0:0:0:0:0:ffff:7f00:1]')))
    def test_prefix_boundaries_and_encoded_paths(self):
        a=self.policy(prefix='/admin/')
        for path in ['/admin','/admin/x','/admin/a%20b','/%61dmin/x']:
            self.assertTrue(a.allows('demo',80,False,path),path)
        for path in ['/administrator','/Admin/x','/admin/../x','/admin/%2e%2e/x','/admin/%2Fx','/admin/%5cx','/admin/%252e/x','/admin//x','/admin/%xx','/admin/a\\b']:
            self.assertFalse(a.allows('demo',80,False,path),path)
        self.assertTrue(a.inspect('demo',80,False,self.request('/admin/x?q=%252f')))
    def test_long_authority_is_bounded_and_foreign_origin_needs_no_wire_conversion(self):
        for origin in ['http://'+('a'*254)+'.test','http://demo:'+('0'*10000)+'80']:
            with self.assertRaises(ValueError): self.policy(origin)
        class ForbiddenHelpers(object):
            def bytesToString(self,value):raise AssertionError('foreign wire decoded')
        with self.assertRaises(ValueError): self.policy().inspect('evil',80,False,object(),ForbiddenHelpers())
    def test_policy_is_immutable(self):
        with self.assertRaises(AttributeError): self.policy().prefix='/other'
    def test_host_and_service_and_absolute_authority(self):
        a=self.policy(prefix='/admin')
        self.assertTrue(a.inspect('demo',80,False,self.request('http://demo/admin/x')))
        for target,host in [('/admin/x','evil'),('http://evil/admin/x','demo'),('//evil/admin/x','demo'),('/other','demo'),('/admin/x','demo:81'),('/admin/x','p4yl04dm4rk3r')]:
            with self.assertRaises(ValueError): a.inspect('demo',80,False,self.request(target,host))
        with self.assertRaises(ValueError): a.inspect('evil',80,False,self.request())
        for head in ['GET /admin/x HTTP/1.1\r\n\r\n','GET /admin/x HTTP/1.1\r\nHost: demo\r\nHost: demo\r\n\r\n','GET /admin/x HTTP/1.1\r\nHost : demo\r\n\r\n']:
            with self.assertRaises(ValueError): a.inspect('demo',80,False,as_bytes(head))
    def test_dynamic_path_only_deferred_during_preflight(self):
        a=self.policy(prefix='/admin')
        request=self.request('/p4yl04dm4rk3r')
        self.assertTrue(a.inspect('demo',80,False,request,preflight=True))
        with self.assertRaises(ValueError): a.inspect('demo',80,False,request)
    def test_nondefault_port_required_in_host(self):
        a=self.policy('http://demo:8080')
        self.assertTrue(a.inspect('demo',8080,False,self.request('/', 'demo:8080')))
        with self.assertRaises(ValueError): a.inspect('demo',8080,False,self.request('/'))

class ScopeWorkflowTests(SourceCase):
    def request(self, host='demo', path='/entry?q=%252F+%2B&w=TWO'):
        return as_bytes('GET '+path+' HTTP/1.1\r\nHost: '+host+'\r\n\r\n')
    def proof(self):
        return self.ui._scope_request(self.ui._capture_runtime(),'demo',80,False,self.request())
    def context(self, key=1, managed=True):
        context,error=self.ui.sessions.register(key,self.ui._capture_runtime(),managed,self.proof())
        self.assertIsNone(error)
        return context
    def state_reply(self, value='A', location=None):
        return as_bytes('HTTP/1.1 '+('302 Found' if location else '200 OK')+'\r\n'+
            ('Location: '+location+'\r\n' if location else '')+'Set-Cookie: sid='+value+'\r\n\r\ntoken="'+value+'"')
    def run_flow(self):
        return self.ui.proxy_flow_process_request(self.request(),'demo',80,False)
    def test_unconfigured_is_closed_for_custom_network_and_collection(self):
        self.ui.sessions.replace_scope(None)
        self.ui.custom_codeblock_status=True
        self.ui.run_user_code=lambda *a: self.fail('custom executed')
        self.assertEqual(self.run_flow().status,'no_match')
        self.assertEqual(self.ui.callbacks.calls,[])
        self.assertEqual(self.ui.sessions.register(1,self.ui._capture_runtime(),False,self.proof() if False else None)[1],'SCOPE_NOT_CONFIGURED')
        self.assertEqual(self.ui.sessions.response(999,self.state_reply('B'))[0],'SCOPE_RESPONSE_IGNORED')
        self.assertEqual(self.ui.cookieManager.jar,{})
    def test_foreign_request_and_virtual_host_do_not_enter_workflow(self):
        self.ui.custom_codeblock_status=True
        self.ui.run_user_code=lambda *a: self.fail('custom executed')
        for host,service in [('evil','evil'),('evil','demo')]:
            r=self.ui.proxy_flow_process_request(self.request(host),service,80,False)
            self.assertEqual(r.status,'no_match')
        self.assertEqual(self.ui.callbacks.calls,[])
        self.assertEqual(self.ui._workflow_counter,0)
    def test_no_provenance_does_not_update_state(self):
        self.ui.autoUpdateCookies=self.ui.autoUpdateCsrf=True
        self.ui._update_cookies_and_csrf(self.state_reply('B'))
        self.assertEqual(self.ui.cookieManager.jar,{})
    def test_passive_in_scope_collects_with_rewrite_off(self):
        self.ui.autoUpdateCookies=self.ui.autoUpdateCsrf=True
        self.ui._proxy_mode_active=False
        context=self.context(managed=False)
        self.ui.sessions.response(1,self.state_reply())
        self.assertEqual(self.ui.cookieManager.jar,{'sid':'A'})
        self.assertEqual(self.ui.csrfManager.get_token(),'A')
    def test_target_change_clears_both_state_and_rejects_a_b_a_late_response(self):
        self.ui.autoUpdateCookies=self.ui.autoUpdateCsrf=True
        c=self.context(managed=False)
        self.ui.cookieManager.jar['old']='SECRET'
        self.ui.csrfManager.set_token('SECRET')
        for origin in ['http://evil','http://demo']:
            self.assertTrue(self.ui.sessions.replace_scope(self.ns['TargetScopePolicy'](origin)))
            self.assertEqual(self.ui.cookieManager.jar,{})
            self.assertIsNone(self.ui.csrfManager.get_token())
        self.assertFalse(self.ui.sessions.valid(c))
        self.ui.sessions.response(1,self.state_reply('OLD'))
        self.assertEqual(self.ui.cookieManager.jar,{})
    def test_equivalent_apply_does_not_reset(self):
        self.ui.cookieManager.jar['sid']='A'
        self.assertFalse(self.ui.sessions.replace_scope(self.ns['TargetScopePolicy']('HTTP://DEMO:80/')))
        self.assertEqual(self.ui.cookieManager.jar,{'sid':'A'})
    def test_foreign_redirect_preserves_own_response_state_and_continues_cp(self):
        self.ui.useCheckPageTemplate=True
        self.ui.autoFollowRTChk=Check(True)
        self.ui.autoUpdateCookies=self.ui.autoUpdateCsrf=True
        for location in ['http://evil/out','http://demo:81/out','https://demo/out','//evil/out','mailto:test@example.test','ftp://evil/out','javascript:alert(1)','file:///bad']:
            self.ui.callbacks=Callbacks(self.state_reply('OWN',location))
            self.ui._http_sender=None
            result=self.run_flow()
            self.assertEqual(result.status,'ready',location+' '+str(result.error_code))
            self.assertEqual(len(self.ui.callbacks.calls),1)
            self.assertIn('csrf=OWN',as_text(result.request_bytes))
            self.assertIn('sid=OWN',as_text(result.request_bytes))
    def test_prefix_guard_stops_redirect_but_allows_cp(self):
        self.ui.sessions.replace_scope(self.ns['TargetScopePolicy']('http://demo','/workflow'))
        self.ui.useCheckPageTemplate=True
        self.ui.autoFollowRTChk=Check(True)
        self.ui.callbacks=Callbacks(self.state_reply('A','/outside'))
        result=self.ui.proxy_flow_process_request(self.request(path='/workflow/carrier?q=ONE'),'demo',80,False)
        self.assertEqual(result.status,'ready')
        self.assertEqual(len(self.ui.callbacks.calls),1)
    def test_foreign_template_authority_is_rejected_before_custom_or_send(self):
        self.ui.useCheckPageTemplate=True
        self.ui.custom_codeblock_status=True
        self.ui.checkPageEditor.message=self.request('evil','/check')
        self.ui.run_user_code=lambda *a: self.fail('custom executed')
        result=self.run_flow()
        self.assertEqual(result.status,'error_before_send')
        self.assertEqual(result.error_code,'TEMPLATE_AUTHORITY_MISMATCH')
        self.assertEqual(self.ui.callbacks.calls,[])
    def test_dynamic_cp_path_rejection_is_post_send_no_replay(self):
        self.ui.sessions.replace_scope(self.ns['TargetScopePolicy']('http://demo','/workflow'))
        self.ui.checkPageEditor.message=self.request(path='/p4yl04dm4rk3r')
        self.ui.useCheckPageTemplate=True
        result=self.ui.proxy_flow_process_request(self.request(path='/workflow/carrier?q=OUTSIDE'),'demo',80,False)
        self.assertEqual(result.status,'error_after_send')
        self.assertEqual(len(self.ui.callbacks.calls),1)
        self.assertIsNone(result.request_bytes)
    def test_scope_change_during_rt_rejects_late_state_and_cp(self):
        self.ui.useCheckPageTemplate=True
        self.ui.autoUpdateCookies=self.ui.autoUpdateCsrf=True
        ui=self.ui;outer=self
        class Changing(Callbacks):
            def makeHttpRequest(self,*args):
                self.calls.append(args)
                ui.sessions.replace_scope(outer.ns['TargetScopePolicy']('http://evil'))
                return Response(outer.state_reply('OLD'))
        self.ui.callbacks=Changing()
        result=self.run_flow()
        self.assertEqual(result.status,'error_after_send')
        self.assertEqual(len(self.ui.callbacks.calls),1)
        self.assertEqual(self.ui.cookieManager.jar,{})
        self.assertIsNone(self.ui.csrfManager.get_token())
    def test_sender_without_valid_context_has_no_api_call(self):
        result=self.ui._send_http_request('demo',80,False,self.request())
        self.assertFalse(result.attempted)
        self.assertEqual(self.ui.callbacks.calls,[])
    def test_stale_handoff_cannot_replace_request(self):
        c=self.context()
        self.assertIsNone(self.ui.sessions.begin(c,self.ns['_monotonic_ms']()+1000))
        self.ui.sessions.replace_scope(None)
        calls=[]
        self.assertFalse(self.ui.sessions.authorize(c,self.proof() if False else None,lambda:calls.append(1)))
        self.assertEqual(calls,[])
    def test_outside_proxy_preserves_actions_in_both_phases(self):
        ext=self.ns['BurpExtender']();ext.ui=self.ui;ext.helpers=self.ui.helpers
        for action in range(4):
            intercepted=Intercepted()
            intercepted.action=action
            intercepted.message.request=self.request('evil')
            intercepted.message.getResponse=lambda:self.state_reply('EVIL')
            ext.processProxyMessage(True,intercepted)
            ext.processProxyMessage(False,intercepted)
            self.assertEqual(intercepted.action,action)
            self.assertEqual(intercepted.message.replacements,[])
        self.assertEqual(len(self.ui.sessions.records),0)
    def test_proxy_final_response_keeps_cp_provenance_and_releases_owner(self):
        self.ui.useCheckPageTemplate=True
        self.ui.autoUpdateCookies=self.ui.autoUpdateCsrf=True
        ext=self.ns['BurpExtender']();ext.ui=self.ui;ext.helpers=self.ui.helpers
        message=Intercepted()
        ext.processProxyMessage(True,message)
        self.assertEqual(message.action,message.ACTION_DONT_INTERCEPT)
        self.assertIsNotNone(self.ui.sessions.owner)
        self.assertIn('/workflow/check',as_text(message.message.getRequest()))
        message.message.getResponse=lambda:self.state_reply('FINAL')
        ext.processProxyMessage(False,message)
        self.assertIsNone(self.ui.sessions.owner)
        self.assertEqual(self.ui.csrfManager.get_token(),'FINAL')

class ScopeRaceTests(SourceCase):
    request=getattr(ScopeWorkflowTests.request,'im_func',ScopeWorkflowTests.request)
    proof=getattr(ScopeWorkflowTests.proof,'im_func',ScopeWorkflowTests.proof)
    context=getattr(ScopeWorkflowTests.context,'im_func',ScopeWorkflowTests.context)
    state_reply=getattr(ScopeWorkflowTests.state_reply,'im_func',ScopeWorkflowTests.state_reply)
    run_flow=getattr(ScopeWorkflowTests.run_flow,'im_func',ScopeWorkflowTests.run_flow)
    def test_scope_revokes_waiting_workflow(self):
        import threading,time
        first,second=self.context(1),self.context(2)
        co=self.ui.sessions
        self.assertIsNone(co.begin(first,self.ns['_monotonic_ms']()+2000))
        result=[]
        thread=threading.Thread(target=lambda:result.append(co.begin(second,self.ns['_monotonic_ms']()+2000)))
        thread.start()
        try:
            end=time.time()+1
            while second not in co.waiting and time.time()<end: time.sleep(.001)
            self.assertIn(second,co.waiting)
            co.replace_scope(self.ns['TargetScopePolicy']('http://evil'))
            thread.join(1)
            self.assertEqual(result,['SCOPE_CHANGED'])
            self.assertIsNone(co.owner)
        finally:
            co.close();thread.join(2)
    def test_queued_custom_is_cancelled_without_execution_or_worker_replacement(self):
        import threading
        executor=self.ui._custom_executor
        entered,release,ran=threading.Event(),threading.Event(),threading.Event()
        first=executor.submit('def custom_codeblock(a,b,c):\n a[0].set()\n a[1].wait(1)\n return "OK",b,c',1500,((entered,release),'B',None))
        self.assertTrue(entered.wait(1))
        worker=executor.worker
        context=self.context(managed=False)
        second=executor.submit('def custom_codeblock(a,b,c):\n a.set()\n return "BAD",b,c',1000,(ran,'B',None),lambda:self.ui.sessions.valid(context))
        try:
            self.ui.sessions.replace_scope(None)
            self.assertIn('CUSTOM_CANCELLED',executor.wait(second)[2])
            self.assertFalse(ran.is_set())
            self.assertIs(executor.worker,worker)
        finally:
            release.set();executor.wait(first)
    def test_running_custom_result_is_revoked_after_scope_change(self):
        import threading
        entered,release=threading.Event(),threading.Event()
        context=self.context(managed=False)
        job=self.ui._custom_executor.submit('def custom_codeblock(a,b,c):\n a[0].set()\n a[1].wait(1)\n return "OLD",b,c',1500,((entered,release),'B',None),lambda:self.ui.sessions.valid(context))
        try:
            self.assertTrue(entered.wait(1))
            self.ui.sessions.replace_scope(self.ns['TargetScopePolicy']('http://evil'))
            release.set()
            self.assertIn('CUSTOM_CANCELLED',self.ui._custom_executor.wait(job)[2])
        finally: release.set()
    def test_scope_change_at_final_handoff_never_retargets_or_replays(self):
        for cp in (False,True):
            self.ui.sessions.replace_scope(self.ns['TargetScopePolicy']('http://demo'))
            self.ui.useCheckPageTemplate=cp
            self.ui._http_sender=None
            self.ui.callbacks.calls=[]
            original=self.ui.sessions.authorize
            def swapping(context,proof,handoff=None):
                if handoff is not None: self.ui.sessions.replace_scope(self.ns['TargetScopePolicy']('http://evil'))
                return original(context,proof,handoff)
            self.ui.sessions.authorize=swapping
            message=Intercepted();message.action=message.ACTION_DO_INTERCEPT
            ext=self.ns['BurpExtender']();ext.ui=self.ui;ext.helpers=self.ui.helpers
            try: ext.processProxyMessage(True,message)
            finally: self.ui.sessions.authorize=original
            self.assertEqual(message.message.replacements,[])
            self.assertEqual(message.action,message.ACTION_DROP if cp else message.ACTION_DO_INTERCEPT)
            self.assertEqual(len(self.ui.callbacks.calls),1 if cp else 0)
    def test_scope_change_during_failed_custom_preserves_original_interception(self):
        self.ui.custom_codeblock_status=True
        def cancelled(*args):
            self.ui.sessions.replace_scope(self.ns['TargetScopePolicy']('http://evil'))
            return False,None,'CUSTOM_CANCELLED'
        self.ui.run_user_code=cancelled
        message=Intercepted();message.action=message.ACTION_DO_INTERCEPT
        ext=self.ns['BurpExtender']();ext.ui=self.ui;ext.helpers=self.ui.helpers
        ext.processProxyMessage(True,message)
        self.assertEqual(message.action,message.ACTION_DO_INTERCEPT)
        self.assertEqual(message.message.replacements,[])
        self.assertEqual(self.ui.callbacks.calls,[])

    def test_partial_replace_failure_drops_even_without_internal_send(self):
        ext=self.ns['BurpExtender']();ext.ui=self.ui;ext.helpers=self.ui.helpers
        message=Intercepted();message.action=message.ACTION_DO_INTERCEPT
        def broken(value):
            message.message.request=value
            raise ValueError('partially replaced')
        message.message.setRequest=broken
        ext.processProxyMessage(True,message)
        self.assertEqual(message.action,message.ACTION_DROP)
        self.assertIsNone(self.ui.sessions.owner)
    def test_non_http_service_is_not_misclassified_as_plain_http(self):
        class Service(object):
            def getHost(self):return 'demo'
            def getPort(self):return 80
            def getProtocol(self):return 'ftp'
        message=Intercepted();message.action=message.ACTION_DO_INTERCEPT
        message.message.getHttpService=lambda:Service()
        ext=self.ns['BurpExtender']();ext.ui=self.ui;ext.helpers=self.ui.helpers
        ext.processProxyMessage(True,message)
        self.assertEqual(message.action,message.ACTION_DO_INTERCEPT)
        self.assertEqual(self.ui.sessions.records,{})

    def test_post_custom_duplicate_host_is_not_dispatched(self):
        self.ui.custom_codeblock_status=True
        self.ui.reqTemplateEditor.message=as_bytes('GET /workflow/action HTTP/1.1\r\nHost: demo\r\nX-Payload: p4yl04dm4rk3r\r\n\r\n')
        self.ui.run_user_code=lambda *a:(True,('x\r\nHost: evil','',None),None)
        result=self.run_flow()
        self.assertEqual(result.status,'error_before_send')
        self.assertEqual(result.error_code,'TEMPLATE_AUTHORITY_MISMATCH')
        self.assertEqual(self.ui.callbacks.calls,[])

if __name__=='__main__': unittest.main()
