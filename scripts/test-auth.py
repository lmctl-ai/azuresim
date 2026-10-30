#!/usr/bin/env python3
from auth_helpers import *
import auth_helpers as helpers
container = '/' + ACCOUNT + '/allowed'
blob = container + '/a%20b.txt'
queue = '/' + ACCOUNT + '-queue/allowed'
with server(base_config) as base:
    for auth in [None, 'garbage', 'Bearer wrong-secret', 'SharedKey bad:not-base64', 'SharedKey ' + ACCOUNT + ':broken']:
        request(base, 'GET', container, auth=auth, status=403, error='AuthenticationFailed')
    request(base, 'PUT', container + '?restype=container', b'', status=403, error='AuthenticationFailed', key=base64.b64encode(b'wrong-key').decode())
    old = email.utils.format_datetime(datetime.now(timezone.utc)-timedelta(hours=1), usegmt=True)
    request(base, 'GET', container, headers={'x-ms-date':old}, status=403, error='AuthenticationFailed')
    request(base, 'PUT', container + '?restype=container', b'', status=201)
    request(base, 'PUT', blob, b'signed bytes', headers={'x-ms-blob-type':'BlockBlob', 'x-ms-meta-label':'  alpha   beta  '}, status=201)
    assert request(base, 'GET', blob) == b'signed bytes'
    request(base, 'GET', container+'?restype=container&comp=list&include=metadata&include=snapshots')
    request(base, 'GET', blob, auth='bearer')
    request(base, 'PUT', queue, b'', status=201)
    request(base, 'POST', queue+'/messages', b'<QueueMessage><MessageText>signed queue</MessageText></QueueMessage>', status=201)
    assert b'signed queue' in request(base, 'GET', queue+'/messages?peekonly=true', auth='bearer')
    # Host-style addressing signs the URI path once after the account prefix.
    request(base, 'GET', '/allowed/a%20b.txt', headers={'Host':ACCOUNT+'.blob.core.windows.net'})
    # A signed query/header tamper must fail before the handler executes.
    headers = signed('GET', blob, None, {})
    request(base, 'GET', blob+'?comp=metadata', auth=None, headers=headers, status=403, error='AuthenticationFailed')
    headers = signed('GET', blob, None, {'x-ms-meta-test':'original'})
    headers['x-ms-meta-test'] = 'tampered'
    request(base, 'GET', blob, auth=None, headers=headers, status=403, error='AuthenticationFailed')
    for path in ['/subscriptions', '/'+ACCOUNT+'/allowed?restype=container&comp=acl', '/'+ACCOUNT+'/allowed%2fescape/file', '/'+ACCOUNT+'/allowed/', '/'+ACCOUNT+'//allowed/file']:
        request(base, 'GET', path, auth='bearer', status=403, error='AuthorizationPermissionMismatch')

rules = [
 {'Effect':'Deny','ActionGlob':'*/DELETE','ResourceGlob':'/*','Principal':'*'},
 {'Effect':'Allow','Action':[BLOB+'/*', QUEUE+'/*'], 'ResourceGlob':['/'+ACCOUNT+'/blob/allowed*','/'+ACCOUNT+'/queue/allowed*'], 'Principal':[ACCOUNT,'alice']}
]
with server({**base_config, 'Statement':rules}) as base:
    request(base, 'PUT', container+'?restype=container', b'', status=201)
    request(base, 'PUT', blob, b'allowed', headers={'x-ms-blob-type':'BlockBlob'}, status=201)
    request(base, 'GET', blob, auth='bearer')
    request(base, 'DELETE', blob, status=403, error='AuthorizationPermissionMismatch')
    request(base, 'PUT', '/'+ACCOUNT+'/other?restype=container', b'', status=403, error='AuthorizationPermissionMismatch')
    request(base, 'PUT', queue, b'', auth='bearer', status=201)
    request(base, 'POST', queue+'/messages', b'<QueueMessage><MessageText>allowed</MessageText></QueueMessage>', auth='bearer', status=201)
    request(base, 'DELETE', queue, auth='bearer', status=403, error='AuthorizationPermissionMismatch')

with server({**base_config, 'Statement':[{'Effect':'Allow','Action':'*','ResourceGlob':'*','Principal':'someone-else'}]}) as base:
    request(base, 'PUT', container+'?restype=container', b'', status=403, error='AuthorizationPermissionMismatch')
with server({**base_config, 'Statement':[]}) as base:
    request(base, 'GET', container+'?restype=container', auth='bearer', status=403, error='AuthorizationPermissionMismatch')

with tempfile.TemporaryDirectory() as tmp:
    for value in [{}, {**base_config,'Statement':[{'Effect':'Typo','Action':'*','ResourceGlob':'*'}]},
                  {**base_config,'Statements':[]}, {**base_config,'Statement':None}, {**base_config,'Statement':[{'Effect':'Allow','Action':'*','ActionGlob':'*','ResourceGlob':'*'}]}]:
        file = Path(tmp)/'bad.json'; file.write_text(json.dumps(value))
        result = subprocess.run(command+['serve','--auth','enforce','--auth-config',str(file)], capture_output=True, text=True, timeout=30)
        assert result.returncode == 2 and json.loads(result.stdout)['ok'] is False
        assert KEY not in result.stdout+result.stderr and TOKEN not in result.stdout+result.stderr
        checks += 1
print(f'Auth: {helpers.checks + checks} HTTP/config checks passed (SharedKey, Bearer, policy allow/deny/default-deny, wildcards, redaction)')
