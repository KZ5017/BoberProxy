"""Finite SI00 collection/expiry/Secure characterization using the live observer."""
import argparse
import http.client
import json
import ssl
import time
import uuid
from pathlib import Path
from probe_proxy import exchange, snapshot
from probe_si00_wire import command, read_json


def tls_proxy(path):
    # Both endpoints are fixed loopback fixtures; this context is test-only.
    connection=http.client.HTTPSConnection('127.0.0.1',8080,timeout=8,
                                           context=ssl._create_unverified_context())
    connection.set_tunnel('127.0.0.1',18782)
    try:
        connection.request('GET',path,headers={'Host':'127.0.0.1:18782','Connection':'close'})
        reply=connection.getresponse()
        body=reply.read()
        try: value=json.loads(body)
        except ValueError: value=None
        return dict(status=reply.status,json=value)
    finally: connection.close()


def cookie_values(event):
    return [pair.strip().partition('=')[2] for key,value in event['headers'] if key.lower()=='cookie'
            for pair in value.split(';')]


def tls_snapshot(run):
    connection=http.client.HTTPSConnection('127.0.0.1',18782,timeout=5,
                                           context=ssl._create_unverified_context())
    try:
        connection.request('GET','/__control/events?run='+run,headers={'Connection':'close'})
        response=connection.getresponse()
        if response.status!=200: raise RuntimeError('TLS fixture control failed')
        return json.loads(response.read())
    finally: connection.close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--scenario',choices=['collection','expiry','secure'],required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    if args.report.exists(): raise RuntimeError('Preserve earlier reports; use a new path')
    runtime=Path(__file__).resolve().parent/'runtime'
    state=read_json(runtime/'si00-wire-state.json')
    if not state or state.get('state')!='ready': raise RuntimeError('Observer not ready')
    run='si00-'+args.scenario+'-'+uuid.uuid4().hex[:10]
    results,observations,error=[],{},None
    def cmd(op,**kw): return command(runtime,state,op,**kw)
    def api(path):
        result=cmd('send',port=18781,path=path)
        results.append(result)
        return result
    def proxy(path):
        result=exchange(path,target_port=18781)
        results.append(result)
        return result
    def path(route,extra=''): return '/si00/'+route+'?run='+run+extra
    try:
        cmd('cleanup')
        if args.scenario=='collection':
            api(path('cookie','&kind=root'))
            observations['jar_after_extension_response']=cmd('inspect')['jar']
            api(path('echo'))
        elif args.scenario=='expiry':
            proxy(path('cookie','&kind=short'))
            observations['jar_after_short_cookie']=cmd('inspect')['jar']
            api(path('echo','&phase=before-expiry'))
            time.sleep(2.1)
            observations['jar_after_wait']=cmd('inspect')['jar']
            api(path('echo','&phase=after-expiry'))
            proxy(path('cookie','&kind=root'))
            proxy(path('cookie','&kind=expired_root'))
            observations['jar_after_max_age_zero']=cmd('inspect')['jar']
            api(path('echo','&phase=after-delete'))
        else:
            proxy(path('cookie','&kind=secure'))
            observations['jar_after_secure_cookie']=cmd('inspect')['jar']
            api(path('secure/echo','&via=http'))
            results.append(tls_proxy(path('secure/echo','&via=https')))
        observations['final_jar']=cmd('inspect')['jar']
    except Exception as exc:
        error=dict(type=type(exc).__name__,detail=str(exc))
    try:
        observed=snapshot(run,18781)
        observed_tls=tls_snapshot(run) if args.scenario=='secure' else None
    except Exception as exc:
        error=error or dict(type=type(exc).__name__,detail=str(exc))
        observed=dict(action_count=None,event_count=None,recent_events=[])
        observed_tls=dict(action_count=None,event_count=None,recent_events=[]) if args.scenario=='secure' else None
    echoes=[event for event in observed['recent_events'] if '/echo?' in event['target']]
    capabilities={}
    if args.scenario=='collection' and echoes:
        capabilities['extension_response_collection']=cookie_values(echoes[-1])==['ROOT']
    elif args.scenario=='expiry' and len(echoes)==3:
        capabilities.update(short_cookie_initially_sent=cookie_values(echoes[0])==['SHORT'],
            expired_cookie_not_sent=not cookie_values(echoes[1]),
            max_age_zero_removes_cookie=not cookie_values(echoes[2]))
    elif args.scenario=='secure' and echoes and observed_tls['recent_events']:
        capabilities.update(secure_cookie_not_sent_over_http=not cookie_values(echoes[0]),
            secure_cookie_sent_over_https=cookie_values(observed_tls['recent_events'][-1])==['SECURE'])
    cleanup=dict(cleanup_complete=False,note='Pending/unknown command must be inspected before another command')
    if error is None:
        try: cleanup=cmd('cleanup')
        except Exception as exc: error=dict(type=type(exc).__name__,detail=str(exc))
    events=observed['recent_events']+(observed_tls['recent_events'] if observed_tls else [])
    expected={'collection':2,'expiry':6,'secure':3}[args.scenario]
    checks=dict(no_transport_error=error is None,exact_target_count=len(events)==expected,
        no_application_actions=observed['action_count']==0 and (not observed_tls or observed_tls['action_count']==0),
        no_unowned_cookie_values=all(event['other_cookie_count']==0 for event in events),
        own_cleanup_complete=cleanup['cleanup_complete'])
    report=dict(kind='SI00-cookie-edge-characterization',scenario=args.scenario,run=run,
        observer_instance=state['instance'],results=results,observed=observed,observed_tls=observed_tls,
        observations=observations,capabilities=capabilities,checks=checks,transport_error=error,
        cleanup=cleanup,passed=all(checks.values()),
        note='Transport/measurement PASS does not imply all native capabilities are true. Read capability flags.')
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'],checks=checks,capabilities=capabilities),indent=2))
    return 0 if report['passed'] else 1


if __name__=='__main__': raise SystemExit(main())
