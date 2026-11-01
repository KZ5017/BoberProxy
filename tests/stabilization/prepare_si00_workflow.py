"""Generate exact SI00 HTTP templates and a scoped, finite custom trace."""
import json
from pathlib import Path


def main():
    base=Path(__file__).resolve().parent
    fixtures,runtime=base/'fixtures',base/'runtime'
    for name,target,body in [
        ('si00-request-template.http','action','one=p4yl04dm4rk3r&two=53c0undm4rk3r'),
        ('si00-checkpage-template.http','check','csrf=c5rfm4rk3r&one=p4yl04dm4rk3r&two=53c0undm4rk3r')]:
        raw=('POST /si00/%s?run=p4yl04dm4rk3r HTTP/1.1\r\nHost: 127.0.0.1:18781\r\n'
             'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n'
             'Connection: close\r\n\r\n%s') % (target,len(body),body)
        path=fixtures/name
        if path.exists() and path.read_bytes()!=raw.encode('ascii'):
            raise RuntimeError('Preserve unexpected existing fixture: '+str(path))
        path.write_bytes(raw.encode('ascii'))
    code=(fixtures/'si00-custom-pass-through.py.in').read_text(encoding='utf-8')
    code=code.replace('"__TRACE_PATH__"','u'+json.dumps(str(runtime/'si00-workflow-custom.jsonl')))
    code=code.replace('"__GATE_ROOT__"','u'+json.dumps(str(runtime)))
    (runtime/'custom-si00-workflow.py').write_text(code,encoding='utf-8')
    print('Prepared si00-request/checkpage-template.http and runtime/custom-si00-workflow.py.')


if __name__=='__main__':main()
