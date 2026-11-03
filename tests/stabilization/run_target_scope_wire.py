# -*- coding: utf-8 -*-
"""Finite actual-Burp TG05 scenarios; own tagged A/B/T fixtures only."""
import argparse, base64, concurrent.futures, json, statistics, time, traceback
from urllib.parse import urlencode
from target_scope_wire import Client, save_report

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--report',required=True);parser.add_argument('--only')
    args=parser.parse_args(); client=Client()
    report=dict(kind='TG05-actual-Burp-tagged-loopback',source_sha256=client.source,
                instance=client.session['instance'],cases=[],no_request_retries=True)
    def scenario(name, operation):
        if args.only and args.only not in name: return
        row=dict(name=name)
        try: row.update(evidence=operation(),passed=True)
        except BaseException:row.update(passed=False,error=traceback.format_exc())
        report['cases'].append(row)
        print(name+': '+('PASS' if row['passed'] else 'FAIL'),flush=True)
        if not row['passed']: print(row['error'],flush=True)
    def profile(**values):
        client.settle();client.command('profile',**values);client.command('clear')
        return client.command()
    def normal(mode='normal',kind='A',**values):
        profile(kind=kind,**values);run=client.runid(mode)
        before=len(client.command()['custom'])
        response=client.request(run,kind=kind,q=mode)
        a,b,t=[client.target(run,k) for k in ('A','B','T')]
        state=client.settle();target=dict(A=a,B=b,T=t)[kind]
        assert response['status']==200,response
        body=json.loads(response['body']);assert body['accepted'],body
        assert (target['actions'],target['checks'])==(1,1),target
        assert len(state['custom'])-before==2,state
        assert state['sid']=='sid.%s.%s.%d'%(kind,run,target['version']),state
        assert state['csrf']=='csrf.%s.%s.%d'%(kind,run,target['version']),state
        return dict(run=run,response=response,targets=dict(A=a,B=b,T=t),state=state)

    def no_scope():
        state=profile(kind='none');assert state['scope'] is None and not state['proxy']
        run=client.runid('none');before=len(state['custom'])
        response=client.request(run,q='normal');target=client.target(run);state=client.settle()
        assert response['status']==200 and target['actions']==target['checks']==0
        assert target['event_count']==1 and target['events'][0]['target'].startswith('/scope/entry?')
        assert not state['sid'] and not state['csrf'] and len(state['custom'])==before
        return dict(run=run,target=target,state=state)
    scenario('TG-S01 empty scope; automation ON; original only',no_scope)

    def passive_foreign():
        profile(kind='A',active=False)
        run=client.runid('seed');client.request(run,path='/scope/seed?run='+run)
        seeded=client.settle();assert seeded['sid']=='sid.A.%s.0'%run and seeded['csrf']=='csrf.A.%s.0'%run,seeded
        # Same scope apply and injection activation preserve existing state.
        client.command('profile',kind='A')
        before=len(client.command()['custom']);foreign=client.runid('foreign-pass')
        response=client.request(foreign,kind='B',q='normal')
        b=client.target(foreign,'B');after=client.settle()
        assert response['status']==200 and b['event_count']==1 and b['actions']==b['checks']==0,b
        raw=base64.b64decode(b['events'][0]['raw_base64'])
        assert b'/scope/entry?' in raw and b'Cookie:' not in raw and run.encode() not in raw,raw
        assert (after['sid'],after['csrf'])==(seeded['sid'],seeded['csrf']) and len(after['custom'])==before,after
        proof=client.runid('seed-reuse');r=client.request(proof,q='normal');a=client.target(proof)
        assert json.loads(r['body'])['accepted']
        first=base64.b64decode(a['events'][0]['raw_base64']);assert ('sid='+seeded['sid']).encode() in first,first
        return dict(seed=run,foreign=foreign,foreign_target=b,seeded=seeded,after_foreign=after,reuse_target=a)
    scenario('TG-S02/S03 passive A capture; B pass-through cannot poison A',passive_foreign)
    scenario('TG-F baseline normal two-step',normal)
    scenario('TG-R01 same-origin relative redirect',lambda:normal('relative'))
    for mode in ('foreign','foreign-host','foreign-tls','outside-path','non-http'):
        def outside(mode=mode):
            evidence=normal(mode,prefix=mode=='outside-path')
            a=evidence['targets']['A']
            assert a['nexts']==0 and a['event_count']==2,a
            assert all(evidence['targets'][k]['event_count']==0 for k in ('B','T')),evidence
            assert a['version']==1
            assert 'ACTION_DROP' not in evidence['response']['body']
            return evidence
        scenario('TG-R02/R03 neutral stop '+mode,outside)
    scenario('TG-R04 Follow OFF; CheckPage ON',lambda:normal('relative',follow=False))

    def rt_only():
        profile(kind='A',cp=False);run=client.runid('rt-only')
        before=len(client.command()['custom']);r=client.request(run,q='relative');a=client.target(run);state=client.settle()
        assert r['status']==302 and (a['actions'],a['checks'],a['nexts'],a['event_count'])==(1,0,0,1),(r,a)
        assert state['sid']=='sid.A.%s.1'%run and len(state['custom'])-before==1,state
        return dict(run=run,response=r,target=a,state=state)
    scenario('TG-R04 CheckPage OFF returns actual 302; no follow',rt_only)

    def raw_payload():
        profile(kind='A');run=client.runid('raw');raw='%252F+%2B'
        r=client.request(run,path='/scope/entry?q='+raw+'&w='+run);a=client.target(run);s=client.settle()
        assert json.loads(r['body'])['accepted'] and a['actions']==a['checks']==1
        for e in a['events']:
            body=base64.b64decode(e['body_base64']);assert ('one='+raw+'&two='+run).encode() in body,body
        calls=[c for c in s['custom'] if c['b']==run];assert len(calls)==2 and all(c['a']==raw for c in calls),calls
        return dict(run=run,target=a,custom=calls)
    scenario('TG-F raw payload percent/plus unchanged in both requests',raw_payload)

    for mode in ('bad-location','close'):
        def failure(mode=mode):
            profile(kind='A');run=client.runid(mode)
            r=client.request(run,q=mode);a=client.target(run);s=client.settle()
            assert (a['actions'],a['checks'],a['nexts'],a['event_count'])==(1,0,0,1),a
            # Burp extension-drop pages may carry HTTP200. Verify their body.
            assert 'dropped' in r['body'].lower() or 'drop' in r['body'].lower(),r
            assert s['failures'] and s['failures'][-1]['status']=='error_after_send',s['failures']
            return dict(run=run,response=r,target=a,state=s)
        scenario('TG-R05 '+mode+' post-attempt drop/no replay',failure)

    def denied_cp():
        profile(kind='A',prefix=True);client.command('bad-cp');run=client.runid('cp-path-deny')
        before=len(client.command()['custom']);r=client.request(run,q='normal');a=client.target(run);s=client.settle()
        assert a['actions']==a['checks']==0 and a['event_count']==1,a
        assert len(s['custom'])==before and a['events'][0]['target'].startswith('/scope/entry?'),s
        return dict(run=run,response=r,target=a,state=s)
    scenario('TG-P04 invalid edited CheckPage preflight; zero generated sends',denied_cp)

    def late_passive():
        profile(kind='A',active=False);run=client.runid('late-passive')
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            future=pool.submit(client.request,run,path='/scope/action?case=hold&run='+run)
            until=time.monotonic()+3
            while not client.target(run)['actions']:
                assert time.monotonic()<until;time.sleep(.02)
            client.command('scope',kind='B');client.command('scope',kind='A');r=future.result()
        s=client.settle();assert r['status']==200 and s['sid'] is None and s['csrf'] is None,s
        return dict(run=run,target=client.target(run),state=s)
    scenario('TG-S04 A-B-A late original response cannot refill state',late_passive)

    def mid_rt():
        profile(kind='A');run=client.runid('mid-rt')
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            future=pool.submit(client.request,run,q='hold')
            until=time.monotonic()+3
            while not client.target(run)['actions']:
                assert time.monotonic()<until;time.sleep(.02)
            client.command('scope',kind='B');r=future.result()
        a,b=client.target(run),client.target(run,'B');s=client.settle()
        assert a['actions']==1 and a['checks']==0 and b['event_count']==0
        assert s['sid'] is None and s['csrf'] is None and not s['proxy'],s
        assert 'drop' in r['body'].lower(),r
        return dict(run=run,response=r,A=a,B=b,state=s)
    scenario('TG-C01 scope replacement while RT accepted; no CP/replay/publication',mid_rt)

    def custom_scope():
        profile(kind='A');run=client.runid('custom-running');queued=client.runid('custom-waiting')
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            first=pool.submit(client.request,run,q='custom-hold')
            until=time.monotonic()+3
            while not any(c['b']==run for c in client.command()['custom']):
                assert time.monotonic()<until;time.sleep(.02)
            second=pool.submit(client.request,queued,q='normal')
            until=time.monotonic()+2
            while client.command()['waiting']<1:
                assert time.monotonic()<until;time.sleep(.02)
            client.command('scope',kind='B')
            responses=[first.result(),second.result()]
        s=client.settle();targets=[client.target(r) for r in (run,queued)]
        assert all(a['actions']==a['checks']==0 and a['event_count']==1 for a in targets),targets
        assert len([c for c in s['custom'] if c['b']==run])==1 and not any(c['b']==queued for c in s['custom']),s
        assert s['sid'] is None and s['csrf'] is None
        return dict(runs=[run,queued],responses=responses,targets=targets,state=s)
    scenario('TG-C01 running custom discarded; waiting workflow never starts custom',custom_scope)

    def final_handoff():
        profile(kind='A',cp=False);client.command('handoff-switch');run=client.runid('handoff')
        r=client.request(run,q='normal');a=client.target(run);b=client.target(run,'B');s=client.settle()
        assert a['event_count']==1 and a['actions']==a['checks']==0 and b['event_count']==0
        assert a['events'][0]['target'].startswith('/scope/entry?')
        assert s['scope']=='http://127.0.0.1:18811' and not s['proxy'] and s['sid'] is None,s
        return dict(run=run,response=r,A=a,B=b,state=s)
    scenario('TG-C02 real final Proxy authorization invalidated after guard',final_handoff)
    scenario('TG-F HTTPS positive RT/CheckPage on exact TLS origin',lambda:normal(kind='T'))

    def independence():
        profile(kind='A');before=client.command();after=client.command('burp-scope')
        assert (before['scope'],before['generation'])==(after['scope'],after['generation'])
        return dict(before=before['scope'],after=after['scope'],generation=after['generation'])
    scenario('TG-U03 Burp Target scope independent',independence)

    def burst():
        profile(kind='A',prefix=True);runs=[client.runid('burst-%02d'%i) for i in range(32)]
        began=time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            futures=[pool.submit(client.request,run,kind='B' if i%2 else 'A',
                                path='/outside?q=normal&w='+run) for i,run in enumerate(runs)]
            responses=[f.result() for f in futures]
        targets=[client.target(run,'B' if i%2 else 'A') for i,run in enumerate(runs)]
        s=client.settle()
        assert all(r['status']==200 for r in responses)
        assert all(t['event_count']==1 and t['actions']==t['checks']==0 for t in targets),targets
        assert not s['sid'] and not s['csrf'] and not s['owner'] and not s['records'] and not s['waiting'],s
        timings=[row['elapsed_ms'] for row in s['audit'] if row['request'] and row['run'] in runs]
        assert len(timings)==32,timings
        recovery=normal()
        return dict(runs=runs,targets=targets,elapsed=time.monotonic()-began,
                    callback_ms=dict(count=len(timings),median=statistics.median(timings),maximum=max(timings)),recovery=recovery)
    scenario('TG-C03 bounded mixed-origin/path burst32 then normal recovery',burst)
    # Restore passive A for the later controlled out-of-scope manual Intercept pair.
    client.command('profile',kind='A',active=False)
    report['passed']=all(row['passed'] for row in report['cases'])
    report['case_count']=len(report['cases']);save_report(args.report,report)
    print('TG05_WIRE '+('PASS' if report['passed'] else 'FAIL')+' (%d cases)'%len(report['cases']))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
