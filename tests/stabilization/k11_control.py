"""Single-controller K11 channel client. CPython only; never retries HTTP."""
import json
from pathlib import Path
import time
import uuid

RUNTIME = Path(__file__).resolve().parent/'runtime'


def command(action, timeout=10):
    session=json.loads((RUNTIME/'k11-control-session.json').read_text())
    if session.get('target_port')!=18790: raise AssertionError('Wrong K11 wrapper/target')
    if session.get('scope_version')!=2: raise AssertionError('Reload K11 test entry: redirect-query scope version 2 required')
    request=dict(instance=session['instance'],id=uuid.uuid4().hex,action=action)
    temporary=RUNTIME/'k11-command.tmp'
    temporary.write_text(json.dumps(request),encoding='utf-8')
    end=time.monotonic()+1
    while True:
        try:
            temporary.replace(RUNTIME/'k11-command.json')
            break
        except PermissionError:
            if time.monotonic()>end: raise
            time.sleep(.005)  # Windows sharing race, never an HTTP retry.
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            response=json.loads((RUNTIME/'k11-ack.json').read_text())
            if response.get('instance')==session['instance'] and response.get('id')==request['id']:
                if not response.get('ok'): raise AssertionError(response.get('error'))
                return response
        except (OSError,ValueError): pass
        time.sleep(.01)
    raise AssertionError('K11 command not acknowledged: '+action)


def state(): return command('state')['state']


def idle(value):
    return not any(value[worker][key] for worker in ('writer','filter') for key in ('rows','controls','results','active')) and not value['rebuilding'] and not value['dirty']


def settled(timeout=15):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        value=state()
        if idle(value): return value
        time.sleep(.05)
    raise AssertionError('K11 pipeline did not drain')
