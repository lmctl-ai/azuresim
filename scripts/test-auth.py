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
        '/'+ACCOUNT+'/allowed/x%E2%80%A8%252Fy',
        '/'+ACCOUNT+'/allowed/x%C2%85%252Fy',
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

# Cross-service router/authorizer alignment: path-style /messages (and %6dessages), restype=queue,
# x-ms-queue-message-count, and x-ms-blob-type header-forced-blob dispatch must authorize the exact
# service and resource that AzureRoutingFilter dispatches to.
cross_service_config = {
    'accounts': {ACCOUNT: KEY},
    'tokens': {TOKEN: 'alice', 'bob-queue-token': 'bob', 'carol-token': 'carol', 'dave-token': 'dave'},
    'Statement': [
        {'Effect': 'Allow', 'ActionGlob': '*', 'ResourceGlob': '/*', 'Principal': ACCOUNT},
        {'Effect': 'Allow', 'ActionGlob': BLOB + '/blobs/read', 'ResourceGlob': '/' + ACCOUNT + '/blob/allowed*', 'Principal': 'alice'},
        {'Effect': 'Deny', 'ActionGlob': QUEUE + '/*', 'ResourceGlob': '/' + ACCOUNT + '/queue/*', 'Principal': 'alice'},
        {'Effect': 'Allow', 'ActionGlob': QUEUE + '/*', 'ResourceGlob': '/' + ACCOUNT + '/queue/allowed*', 'Principal': 'bob'},
        {'Effect': 'Deny', 'ActionGlob': BLOB + '/*', 'ResourceGlob': '/' + ACCOUNT + '/blob/*', 'Principal': 'bob'},
        # carol: container read only (no blob read); dave: blob write only. Both explicitly denied queue access.
        {'Effect': 'Allow', 'Action': BLOB + '/read', 'ResourceGlob': '/' + ACCOUNT + '/blob/*', 'Principal': 'carol'},
        {'Effect': 'Allow', 'Action': BLOB + '/blobs/write', 'ResourceGlob': '/' + ACCOUNT + '/blob/allowed*', 'Principal': 'dave'},
        {'Effect': 'Deny', 'ActionGlob': QUEUE + '/*', 'ResourceGlob': '/' + ACCOUNT + '/queue/*', 'Principal': ['carol', 'dave']},
    ]
}
with server(cross_service_config) as base:
    request(base, 'PUT', container + '?restype=container', b'', status=201)
    request(base, 'PUT', blob, b'BLOB_SECRET', headers={'x-ms-blob-type': 'BlockBlob'}, status=201)
    request(base, 'PUT', container + '/messages', b'BLOB_NAMED_MESSAGES', headers={'x-ms-blob-type': 'BlockBlob'}, status=201)
    request(base, 'PUT', queue, b'', status=201)
    request(base, 'POST', queue + '/messages', b'<QueueMessage><MessageText>DENIED_QUEUE_SECRET</MessageText></QueueMessage>', status=201)
    # Direct queue access and blob write are denied for blob-read-only alice.
    request(base, 'GET', queue + '/messages?peekonly=true', auth='bearer', status=403, error='AuthorizationPermissionMismatch')
    request(base, 'PUT', container + '/not-permitted', b'nope', auth='bearer', headers={'x-ms-blob-type': 'BlockBlob'}, status=403, error='AuthorizationPermissionMismatch')
    # Unsuffixed path-style /messages and %6dessages route to QueueServiceHandler unless x-ms-blob-type is set;
    # alice must be denied on both peek and receive/consume, as well as POST/DELETE and restype=queue / header selectors.
    for msg_path in [container + '/messages', container + '/%6dessages']:
        request(base, 'GET', msg_path + '?peekonly=true', auth='bearer', status=403, error='AuthorizationPermissionMismatch')
        request(base, 'GET', msg_path, auth='bearer', status=403, error='AuthorizationPermissionMismatch')
        request(base, 'POST', msg_path, b'<QueueMessage><MessageText>inject</MessageText></QueueMessage>', auth='bearer', status=403, error='AuthorizationPermissionMismatch')
        request(base, 'DELETE', msg_path, auth='bearer', status=403, error='AuthorizationPermissionMismatch')
    request(base, 'GET', container + '?restype=queue', auth='bearer', status=403, error='AuthorizationPermissionMismatch')
    request(base, 'GET', container, auth='bearer', headers={'x-ms-queue-message-count': '0'}, status=403, error='AuthorizationPermissionMismatch')
    # Queue message must remain unconsumed (DequeueCount == 0) after alice's denied attempts.
    admin_peek = request(base, 'GET', queue + '/messages?peekonly=true')
    assert b'DENIED_QUEUE_SECRET' in admin_peek and b'<DequeueCount>0</DequeueCount>' in admin_peek
    # Header-forced-blob variant: x-ms-blob-type forces AzureRoutingFilter to BlobServiceHandler.
    # Alice (blob-read) reads the blob named "messages" without touching the queue; bob (queue-only, blob-denied) is denied.
    for msg_path in [container + '/messages', container + '/%6dessages']:
        assert request(base, 'GET', msg_path, auth='bearer', headers={'x-ms-blob-type': 'BlockBlob'}) == b'BLOB_NAMED_MESSAGES'
        request(base, 'GET', msg_path, auth='Bearer bob-queue-token', headers={'x-ms-blob-type': 'BlockBlob'}, status=403, error='AuthorizationPermissionMismatch')
        assert b'DENIED_QUEUE_SECRET' in request(base, 'GET', msg_path + '?peekonly=true', auth='Bearer bob-queue-token')
    admin_peek_after = request(base, 'GET', queue + '/messages?peekonly=true')
    assert b'DENIED_QUEUE_SECRET' in admin_peek_after and b'<DequeueCount>0</DequeueCount>' in admin_peek_after
    # Query parser alignment: the JAX-RS parser splits on ';' as well as '&', so a smuggled selector must
    # never reach dispatch unauthorized. An escaped %3B stays literal and is not a separator.
    carol, dave, bob = 'Bearer carol-token', 'Bearer dave-token', 'Bearer bob-queue-token'
    root = '/' + ACCOUNT
    assert b'<Containers>' in request(base, 'GET', root + '?comp=list', auth=carol)
    assert b'<Containers>' in request(base, 'GET', root + '?comp=list&x=1%3Brestype=queue', auth=carol)
    denied = 'AuthorizationPermissionMismatch'
    for smuggled in ['?comp=list&x=1;restype=queue', '?comp=list;restype=queue', '?comp=list&;restype=queue']:
        request(base, 'GET', root + smuggled, auth=carol, status=403, error=denied)
    request(base, 'GET', container + '?restype=container&comp=list', auth=carol, status=403, error=denied)
    request(base, 'GET', container + '?restype=container&x=1;comp=list', auth=carol, status=403, error=denied)
    request(base, 'GET', blob + '?comp=tags', auth='bearer', status=403, error=denied)
    request(base, 'GET', blob + '?x=1;comp=tags', auth='bearer', status=403, error=denied)
    request(base, 'PUT', blob + '?comp=lease', b'', auth=dave, headers={'x-ms-lease-action': 'acquire', 'x-ms-lease-duration': '-1'}, status=403, error=denied)
    request(base, 'PUT', blob + '?x=1;comp=lease', b'', auth=dave, headers={'x-ms-lease-action': 'acquire', 'x-ms-lease-duration': '-1'}, status=403, error=denied)
    request(base, 'PUT', blob + '?comp=snapshot', b'', auth=dave, status=403, error=denied)
    request(base, 'PUT', blob + '?x=1;comp=snapshot', b'', auth=dave, status=403, error=denied)
    request(base, 'GET', queue + '?comp=acl', auth=bob, status=403, error=denied)
    request(base, 'GET', queue + '?x=1;comp=acl', auth=bob, status=403, error=denied)
    # Admin can still overwrite blob (confirming smuggled lease did not lock the blob).
    request(base, 'PUT', blob, b'BLOB_SECRET_2', headers={'x-ms-blob-type': 'BlockBlob'}, status=201)
    # Encoded query key spelling reaches the same service for both layers.
    request(base, 'GET', root + '?comp=list&%72estype=queue', auth=carol, status=403, error=denied)
    # Host-style routing: the service comes from the host and cannot be overridden by the path or headers.
    azure_host = {'Host': ACCOUNT + '.queue.core.windows.net'}
    request(base, 'GET', '/allowed/messages?peekonly=true', auth='bearer', headers=azure_host, status=403, error=denied)
    assert b'DENIED_QUEUE_SECRET' in request(base, 'GET', '/allowed/messages?peekonly=true', auth=bob, headers=azure_host)
    # Non-storage services stay closed to storage grants.
    for service_path in ['/' + ACCOUNT + '-table/Tables', '/' + ACCOUNT + '-cosmos/dbs', '/secrets/x', '/subscriptions', '/common/oauth2/v2.0/token']:
        request(base, 'GET', service_path, auth=carol, status=403, error=denied)
    admin_peek_final = request(base, 'GET', queue + '/messages?peekonly=true')
    assert b'DENIED_QUEUE_SECRET' in admin_peek_final and b'<DequeueCount>0</DequeueCount>' in admin_peek_final

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
