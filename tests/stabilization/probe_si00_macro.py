"""Finite API/Proxy macro correlation, including two concurrent Proxy callers."""
import argparse
import concurrent.futures
import json
import uuid
from pathlib import Path
from urllib.parse import parse_qs,urlsplit
from probe_proxy import exchange,snapshot
from probe_si00_wire import command,read_json
from probe_si00_workflow import records


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    if args.report.exists():raise RuntimeError('Preserve previous attempts; choose new report')
    runtime=Path(__file__).resolve().parent/'runtime'
    state=read_json(runtime/'si00-wire-state.json')
    if not state or state.get('state')!='ready':raise RuntimeError('Live observer not ready')
    before=snapshot('si00-macro-template',18781)
    trials,errors=[],[]
    negative_after=None
    def run_id(label):return 'si00-macro-'+label+'-'+uuid.uuid4().hex[:10]
    def request(run,via,has_token=True):
        path='/si00/echo?run='+run+('&si00_token=OLD' if has_token else '')+'&value=%252F+%2B'
        try:
            if via=='api': result=command(runtime,state,'send',port=18781,path=path)
            else:result=exchange(path,target_port=18781,timeout=7)
            return dict(run=run,via=via,result=result,observed=snapshot(run,18781),has_token=has_token)
        except Exception as exc:
            return dict(run=run,via=via,error=dict(type=type(exc).__name__,detail=str(exc)),
                        observed=snapshot(run,18781),has_token=has_token)
    cleanup=dict(cleanup_complete=False)
    try:
        command(runtime,state,'cleanup')
        trials.append(request(run_id('unmatched'),'api',False))
        if 'error' in trials[-1]:raise RuntimeError('Negative client failed; inspect before more sends')
        negative_after=snapshot('si00-macro-template',18781)
        for via in ('api','proxy'):
            command(runtime,state,'cleanup')
            trial=request(run_id(via),via)
            trials.append(trial)
            if 'error' in trial:raise RuntimeError('Prior client failed; inspect before more sends')
        command(runtime,state,'cleanup')
        concurrent_runs=[run_id('parallel-a'),run_id('parallel-b')]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            trials.extend(list(executor.map(lambda run:request(run,'proxy'),concurrent_runs)))
        command(runtime,state,'inspect')  # Flush callbacks only, no application send.
        cleanup=command(runtime,state,'cleanup')
    except Exception as exc:errors.append(dict(type=type(exc).__name__,detail=str(exc)))
    after=snapshot('si00-macro-template',18781)
    last_sequence=max((e['sequence'] for e in before['recent_events']),default=0)
    new_macro_events=[e for e in after['recent_events'] if e['sequence']>last_sequence]
    wire=[r for r in records(runtime/'si00-wire-trace.jsonl') if r.get('instance')==state['instance']
          and r.get('run') in {trial['run'] for trial in trials}]
    positives=[trial for trial in trials if trial['has_token']]
    token_checks=[]
    token_values=[]
    for trial in positives:
        events=trial['observed']['recent_events']
        value=parse_qs(urlsplit(events[0]['target']).query).get('si00_token',[''])[0] if len(events)==1 else ''
        callbacks=[r for r in wire if r['run']==trial['run'] and r.get('macro_count')==1]
        matching=[r for r in callbacks if r.get('macro_tokens')==[value]]
        token_checks.append(bool(value and value!='OLD' and len(matching)==1))
        token_values.append(value)
    checks=dict(no_transport_error=not errors and all('error' not in trial for trial in trials),
        five_parent_clients=len(trials)==5,
        one_echo_each=all(trial['observed']['event_count']==1 for trial in trials),
        no_application_action=after['action_count']==0 and all(trial['observed']['action_count']==0 for trial in trials),
        negative_parameter_scope=(negative_after is not None and negative_after['event_count']==before['event_count']),
        exactly_four_macro_requests=after['event_count']-before['event_count']==4,
        raw_other_parameter_preserved=all('value=%252F+%2B' in event['target'].split('?',1)[1].split('&')
            for trial in trials for event in trial['observed']['recent_events']),
        fresh_macro_tokens_correlated=len(token_checks)==4 and all(token_checks),
        distinct_tokens_for_each_parent=len(set(token_values))==4,
        no_unowned_cookies=(all(event['other_cookie_count']==0 for trial in trials for event in trial['observed']['recent_events'])
                           and all(event['other_cookie_count']==0 for event in new_macro_events)),
        owned_cleanup=cleanup['cleanup_complete'])
    report=dict(kind='SI00-native-macroItems-and-parameter-characterization',checks=checks,
        passed=all(checks.values()),trials=trials,wire_records=wire,
        macro_before=before,macro_after=after,errors=errors,cleanup=cleanup,
        token_values=token_values,observer_instance=state['instance'],
        note='Macro-to-parent mapping only; no claim about server-side token validity under parallel invalidation or automatic integration into existing custom arguments.')
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'],checks=checks),indent=2))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
