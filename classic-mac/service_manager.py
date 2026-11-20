"""Workspace service lifetimes, serialized startup and PID ownership."""
import fcntl, json, os, secrets, signal, subprocess, sys, time, urllib.request
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
PYTHON = '/home/harri/.local/venvs/c1-lab/bin/python'
RE_PYTHON = '/home/harri/.ghidra_mcp_venv_2/bin/python'

def definition(name):
    if name == 'lab':
        return ROOT / '.mac-lab', 8770, [PYTHON, str(ROOT / 'tools/mac-lab/service.py')], {}
    if name != 're': raise ValueError(name)
    state = ROOT / '.mac-re'
    return state, 8084, [RE_PYTHON, str(ROOT / 'tools/mac-re/vendor/ghidra_headless_server.py'), '--port', '8084'], {
        'GHIDRA_INSTALL_DIR':'/opt/ghidra_12.1_PUBLIC',
        'GHIDRA_MCP_INSTANCE_NAME':'oldmac-re',
        'GHIDRA_MCP_PROJECT_DIR':str(ROOT / 'MacRE/projects'),
        'GHIDRA_MCP_PROJECT_NAME':'OldMacRE',
        'GHIDRA_MCP_PROJECTS_FILE':str(state / 'projects.json'),
        'GHIDRA_MCP_IMPORT_ROOT':str(ROOT),
        'JAVA_TOOL_OPTIONS': '-Duser.home=' + str(state / 'home')}

def owned(pid, script):
    try: return script.encode() in Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
    except OSError: return False

def ensure_service(name):
    state, port, cmd, env = definition(name)
    state.mkdir(exist_ok=True)
    with open(state / 'startup.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        pidfile = state / 'pid'
        pid = int(pidfile.read_text()) if pidfile.exists() else 0
        running = owned(pid, cmd[1])
        if not running:
            if name == 'lab' and not (state / 'api-token').exists():
                fd=os.open(state / 'api-token', os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
                with os.fdopen(fd,'w') as out: out.write(secrets.token_urlsafe(32))
            if name == 're':
                (ROOT / 'MacRE/projects').mkdir(parents=True, exist_ok=True)
                (state / 'home').mkdir(exist_ok=True)
            log = open(state / 'service.log','ab',buffering=0)
            proc = subprocess.Popen(cmd, env={**os.environ, **env}, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
            log.close()
            pid = proc.pid
            pidfile.write_text(str(pid))
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            if not owned(pid,cmd[1]): raise RuntimeError(f'{name} exited; see {state}/service.log')
            try:
                if name=='lab':
                    token=(state/'api-token').read_text()
                    req=urllib.request.Request(f'http://127.0.0.1:{port}/api',data=b'{"action":"status"}',headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
                else: req=urllib.request.Request(f'http://127.0.0.1:{port}/')
                with urllib.request.urlopen(req,timeout=1) as response:
                    if response.status==200: return pid
            except OSError: time.sleep(.2)
        raise RuntimeError(f'{name} startup timeout; see {state}/service.log')

if __name__=='__main__':
    name, action=sys.argv[1:]
    state,port,cmd,env=definition(name)
    if action=='start': print(ensure_service(name))
    elif action=='stop':
        pid=int((state/'pid').read_text())
        if not owned(pid,cmd[1]): raise SystemExit('PID is not this service')
        if name=='lab':
            token=(state/'api-token').read_text()
            req=urllib.request.Request('http://127.0.0.1:8770/api',data=b'{"action":"status"}',headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
            with urllib.request.urlopen(req,timeout=5) as response: lab=json.load(response)
            if lab['running']: raise SystemExit('Shut down guest and call MCP close before stopping the lab service')
        os.kill(pid,signal.SIGTERM)
        print('Saving and stopping')
    elif action=='status':
        pid=int((state/'pid').read_text()) if (state/'pid').exists() else 0
        print(json.dumps({'running':owned(pid,cmd[1]),'pid':pid,'port':port}))
