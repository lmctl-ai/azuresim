#!/usr/bin/env python3
"""Real lmazure Azure SDK binary -> azuresim, including auth/error propagation."""
from auth_helpers import server, base_config, KEY, TOKEN, ACCOUNT, BLOB, QUEUE
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

client = Path(sys.argv[2]).resolve()
command = ['dotnet', str(client)] if client.suffix == '.dll' else [str(client)]
checks = 0

def run(base, *args, code=0, credential='key', error=None):
    global checks
    env = {k:v for k,v in os.environ.items() if not k.startswith(('LMAZURE_', 'AZURE_'))}
    env.update(LMAZURE_LIVE='0', LMAZURE_ALLOW_WRITES='0', LMAZURE_SIM_ENDPOINT=base, LMAZURE_SIM_ACCOUNT=ACCOUNT)
    if credential == 'key': env['LMAZURE_SIM_KEY'] = KEY
    elif credential == 'token': env['LMAZURE_SIM_TOKEN'] = TOKEN
    elif credential == 'wrong': env['LMAZURE_SIM_TOKEN'] = 'wrong-client-token-secret'
    result = subprocess.run(command+['--simulator',*args], capture_output=True, text=True, env=env, timeout=45)
    assert result.returncode == code, (args[0], result.returncode, result.stdout, result.stderr)
    doc = json.loads(result.stdout)
    assert doc['ok'] == (code == 0), doc
    if error: assert doc['error'] == error and doc['status'] == 403, doc
    for secret in [KEY, TOKEN, 'wrong-client-token-secret']:
        assert secret not in result.stdout+result.stderr, 'credential leaked'
    checks += 1
    return doc

policy = [
 {'Effect':'Allow','ActionGlob':'Microsoft.Storage/*','ResourceGlob':['/'+ACCOUNT+'/blob/client-*','/'+ACCOUNT+'/queue/client-*']},
 {'Effect':'Deny','Action':'*/delete','ResourceGlob':'/'+ACCOUNT+'/blob/client-locked*'}
]
with tempfile.TemporaryDirectory(prefix='azuresim-client-') as tmp, server({**base_config,'Statement':policy}) as base:
    source = Path(tmp)/'input.bin'; source.write_bytes(b'Azure SDK blob round trip\x00\xff\n')
    output = Path(tmp)/'output.bin'
    run(base,'container-create','client-allowed',credential=None,code=3,error='AuthenticationFailed')
    run(base,'container-create','client-allowed',credential='wrong',code=3,error='AuthenticationFailed')
    run(base,'container-create','client-allowed')
    run(base,'blob-put','client-allowed','sdk file.bin',str(source))
    run(base,'blob-get','client-allowed','sdk file.bin',str(output))
    assert output.read_bytes() == source.read_bytes()
    run(base,'queue-create','client-queue')
    run(base,'queue-send','client-queue','hello from lmazure')
    assert run(base,'queue-peek','client-queue')['message'] == 'hello from lmazure'
    message = run(base,'queue-receive','client-queue')
    assert message['message'] == 'hello from lmazure'
    run(base,'queue-delete-message','client-queue',message['id'],message['receipt'])
    assert 'message' not in run(base,'queue-peek','client-queue')
    run(base,'queue-delete','client-queue')
    run(base,'container-create','client-locked',credential='token')
    run(base,'container-delete','client-locked',credential='token',code=3,error='AuthorizationPermissionMismatch')
    run(base,'container-create','outside-policy',code=3,error='AuthorizationPermissionMismatch')
    run(base,'container-delete','client-allowed')
# The explicit client mode must reject remote endpoints without sending requests.
run('https://management.azure.com','container-create','client-denied',code=2)
run('http://127.0.0.1.evil.example:4577','container-create','client-denied',code=2)
print(f'lmazure integration: {checks} SDK CLI checks passed; blob bytes, queue lifecycle, SharedKey, Bearer, 403 exit 3, no credential leakage')
