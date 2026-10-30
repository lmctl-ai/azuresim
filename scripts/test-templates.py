#!/usr/bin/env python3
"""LMScript templates -> pinned native lmazure SDK -> real azuresim, no mocks."""
from auth_helpers import server, request, KEY, ACCOUNT
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
client = Path(sys.argv[2]).resolve()
local_engine = ROOT/'scripts/compiler/node_modules/@lmctl-ai/lmctl/bin/lmscript'
engine = os.environ.get('LMSCRIPT_BIN') or (str(local_engine) if local_engine.exists() else shutil.which('lmscript'))
if not engine:
    raise SystemExit('Set LMSCRIPT_BIN or install the pinned compiler from scripts/compiler')
# Node also runs the npm launcher portably on Windows; local mono is a JS launcher.
engine_command = ['node', str(Path(engine).resolve())]
script = ROOT/'examples/templates.lms'
env = {k:v for k,v in os.environ.items() if not k.startswith(('LMAZURE_', 'AZURE_'))}
env.update(LMAZURE_TEMPLATE_CLIENT=str(client), LMAZURE_LIVE='0', LMAZURE_ALLOW_WRITES='0')

def execute(root, mode, check=False):
    args = engine_command + (['--check'] if check else []) + [str(script), mode]
    result = subprocess.run(args, cwd=root, env=env, capture_output=True, text=True, encoding='utf-8', timeout=120)
    assert result.returncode == 0, (mode, result.stdout, result.stderr)
    assert KEY not in result.stdout + result.stderr, 'credential leaked'
    return result

with tempfile.TemporaryDirectory(prefix='azuresim-templates-') as tmp:
    root = Path(tmp)
    execute(root, 'prepare', check=True)
    assert not (root/'auth.json').exists(), 'check mode had effects'
    execute(root, 'prepare')
    config = json.loads((root/'auth.json').read_text(encoding='utf-8'))
    assert config['accounts'][ACCOUNT] == KEY
    payload = json.loads((root/'blob.json').read_text(encoding='utf-8'))
    assert payload['count'] == 3 and payload['tags'] == ['template', '雪']
    assert '${opaque}' in payload['name'], 'inserted text was rescanned'
    for mode in ['open', 'enforce']:
        with server(None, mode, config_path=root/'auth.json') as base:
            env['LMAZURE_SIM_ENDPOINT'] = base
            if mode == 'enforce': env['LMAZURE_SIM_KEY'] = KEY
            else: env.pop('LMAZURE_SIM_KEY', None)
            print(execute(root, mode).stdout.strip())
            auth = 'key' if mode == 'enforce' else None
            body = request(base, 'GET', '/'+ACCOUNT+'/template-container/payload.json', auth=auth)
            assert json.loads(body) == payload
            if mode == 'enforce':
                request(base, 'DELETE', '/'+ACCOUNT+'/template-container?restype=container',
                        auth='key', status=403, error='AuthorizationPermissionMismatch')
                request(base, 'GET', '/'+ACCOUNT+'/template-container/payload.json',
                        auth=None, status=403, error='AuthenticationFailed')
print('Templates: 13 SDK calls, 4 HTTP status/body checks; open + SharedKey/RBAC enforce passed')
