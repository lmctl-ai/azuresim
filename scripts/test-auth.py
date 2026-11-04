#!/usr/bin/env python3
from auth_helpers import *
import auth_helpers as helpers
container = '/' + ACCOUNT + '/allowed'
blob = container + '/a%20b.txt'
queue = '/' + ACCOUNT + '-queue/allowed'
with server({**base_config, 'accounts':{ACCOUNT:KEY,'otheraccount':KEY}}) as base:
    for auth in [None, 'garbage', 'Bearer wrong-secret', 'SharedKey bad:not-base64', 'SharedKey ' + ACCOUNT + ':broken']:
        request(base, 'GET', container, auth=auth, status=403, error='AuthenticationFailed')
    request(base, 'PUT', container + '?restype=container', b'', status=403, error='AuthenticationFailed', key=base64.b64encode(b'wrong-key').decode())
    old = email.utils.format_datetime(datetime.now(timezone.utc)-timedelta(hours=1), usegmt=True)
    request(base, 'GET', container, headers={'x-ms-date':old}, status=403, error='AuthenticationFailed')
    other_headers = signed('GET', container+'?restype=container', None, {}, account='otheraccount')
    request(base, 'GET', container+'?restype=container', auth=None, headers=other_headers, status=403, error='AuthenticationFailed')
    request(base, 'PUT', container + '?restype=container', b'', status=201)
    request(base, 'PUT', blob, b'signed bytes', headers={'x-ms-blob-type':'BlockBlob', 'x-ms-meta-label':'  alpha   beta  '}, status=201)
    assert request(base, 'GET', blob) == b'signed bytes'
    # Legitimately percent-encoded keys (%25, spaces, +, ?, #, Unicode) must succeed in enforce mode.
    special_blob = container + '/docs/2026/a%20b+c%25d%3Fe%23f-%E9%9B%AA.json'
    request(base, 'PUT', special_blob, b'special-pct-unicode', headers={'x-ms-blob-type':'BlockBlob'}, status=201)
    assert request(base, 'GET', special_blob) == b'special-pct-unicode'
    assert request(base, 'GET', special_blob, auth='bearer') == b'special-pct-unicode'
    assert request(base, 'GET', '/allowed/docs/2026/a%20b+c%25d%3Fe%23f-%E9%9B%AA.json',
                   headers={'Host':ACCOUNT+'.blob.core.windows.net'}) == b'special-pct-unicode'
    for pct_key in [container + '/100%25.txt', container + '/a%25default.txt', container + '/double%25%25pct.txt']:
        request(base, 'PUT', pct_key, b'pct-ok', headers={'x-ms-blob-type':'BlockBlob'}, status=201)
        assert request(base, 'GET', pct_key) == b'pct-ok'
        assert request(base, 'GET', pct_key, auth='bearer') == b'pct-ok'
    listing = request(base, 'GET', container+'?restype=container&comp=list&include=metadata&include=snapshots')
    assert 'docs/2026/a b+c%d?e#f-雪.json'.encode('utf-8') in listing
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
    for path in ['/subscriptions', '/'+ACCOUNT+'/allowed?restype=container&comp=acl', '/'+ACCOUNT+'/allowed%2fescape/file', '/'+ACCOUNT+'/allowed/', '/'+ACCOUNT+'//allowed/file', '/'+ACCOUNT+'/allowed/../allowed/file', '/'+ACCOUNT+'/allowed/%2e%2e/allowed/file']:
        request(base, 'GET', path, auth='bearer', status=403, error='AuthorizationPermissionMismatch')
    # Traversal, encoded slash/backslash, and double-encoding bypass attempts must fail closed.
    traversal_and_double_encoded = [
        '/'+ACCOUNT+'/allowed/../allowed/file',
        '/'+ACCOUNT+'/allowed/%2e%2e/allowed/file',
        '/'+ACCOUNT+'/allowed/%2E%2E/allowed/file',
        '/'+ACCOUNT+'/allowed/.%2e/allowed/file',
        '/'+ACCOUNT+'/allowed/%2f..%2fallowed/file',
        '/'+ACCOUNT+'/allowed/a%2f..%2fb',
        '/'+ACCOUNT+'/allowed%2fescape/file',
        '/'+ACCOUNT+'/allowed/a%5cb',
        '/'+ACCOUNT+'/allowed/%5c../allowed/file',
        '/'+ACCOUNT+'/allowed/%252e%252e/allowed/file',
        '/'+ACCOUNT+'/allowed/.%252e/allowed/file',
        '/'+ACCOUNT+'/allowed/%252f..%252fallowed/file',
        '/'+ACCOUNT+'/allowed%252fescape/file',
        '/'+ACCOUNT+'/allowed/a%255cb',
        '/'+ACCOUNT+'/allowed/%25252e%25252e/allowed/file',
    ]
    for path in traversal_and_double_encoded:
        request(base, 'GET', path, auth='bearer', status=403, error='AuthorizationPermissionMismatch')
        request(base, 'GET', path, auth='key', status=403, error='AuthorizationPermissionMismatch')

rules = [
 {'Effect':'Deny','ActionGlob':'*/DELETE','ResourceGlob':'/*','Principal':'*'},
 {'Effect':'Deny','Action':[BLOB+'/*'], 'ResourceGlob':['/'+ACCOUNT+'/blob/allowed/secret/*','/'+ACCOUNT+'/blob/allowed/locked%item.txt'], 'Principal':'*'},
 {'Effect':'Allow','Action':[BLOB+'/*', QUEUE+'/*'], 'ResourceGlob':['/'+ACCOUNT+'/blob/allow?d*','/'+ACCOUNT+'/queue/allowed*'], 'Principal':[ACCOUNT,'alice']}
]
with server({**base_config, 'Statement':rules}) as base:
    request(base, 'PUT', container+'?restype=container', b'', status=201)
    request(base, 'PUT', blob, b'allowed', headers={'x-ms-blob-type':'BlockBlob'}, status=201)
    request(base, 'GET', blob, auth='bearer')
    request(base, 'PUT', container+'/public/ok%251.txt', b'public-ok', headers={'x-ms-blob-type':'BlockBlob'}, status=201)
    assert request(base, 'GET', container+'/public/ok%251.txt', auth='bearer') == b'public-ok'
    # Resource-scoped deny must not be bypassable via percent-encoding or traversal variants.
    deny_bypass_variants = [
        container + '/secret/doc.txt',
        container + '/%73ecret/doc.txt',
        container + '/secret/%64oc.txt',
        container + '/%73%65%63%72%65%74/doc.txt',
        container + '/%2573ecret/doc.txt',
        container + '/secret%2fdoc.txt',
        container + '/secret%252fdoc.txt',
        container + '/public/../secret/doc.txt',
        container + '/public/%2e%2e/secret/doc.txt',
        container + '/public/%252e%252e/secret/doc.txt',
        container + '/locked%25item.txt',
        container + '/%6cocked%25item.txt',
        container + '/locked%2525item.txt',
    ]
    for denied_path in deny_bypass_variants:
        request(base, 'PUT', denied_path, b'nope', headers={'x-ms-blob-type':'BlockBlob'}, status=403, error='AuthorizationPermissionMismatch')
        request(base, 'GET', denied_path, auth='bearer', status=403, error='AuthorizationPermissionMismatch')
        request(base, 'GET', denied_path, auth='key', status=403, error='AuthorizationPermissionMismatch')
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
with tempfile.TemporaryDirectory() as tmp:
    file = Path(tmp)/'duplicate.json'
    file.write_text('{"tokens":{"test-token":"alice"},"Statement":[],"Statement":[{"Effect":"Allow","Action":"*","ResourceGlob":"*"}]}')
    result = subprocess.run(command+['serve','--auth','enforce','--auth-config',str(file)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 2 and 'test-token' not in result.stdout+result.stderr
    checks += 1
print(f'Auth: {helpers.checks + checks} HTTP/config checks passed (SharedKey, Bearer, policy allow/deny/default-deny, wildcards, redaction)')
