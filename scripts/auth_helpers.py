#!/usr/bin/env python3
"""Auth boundary: actual HTTP, canonicalization, negative paths and policy precedence."""
import base64
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import email.utils
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

exe = Path(sys.argv[1]).resolve()
command = ['java', '-jar', str(exe)] if exe.suffix == '.jar' else [str(exe)]
KEY = base64.b64encode(b'azuresim-only-test-key-32-bytes!!!').decode()
ACCOUNT = 'devstoreaccount1'
TOKEN = 'azuresim-dummy-bearer-secret'
BLOB = 'Microsoft.Storage/storageAccounts/blobServices/containers'
QUEUE = 'Microsoft.Storage/storageAccounts/queueServices/queues'
base_config = {'accounts': {ACCOUNT: KEY}, 'tokens': {TOKEN: 'alice'}}
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
checks = 0

@contextmanager
def server(config, mode='enforce'):
    with tempfile.TemporaryDirectory(prefix='azuresim-auth-') as tmp:
        root = Path(tmp)
        file = root / 'auth.json'
        file.write_text(json.dumps(config))
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        with tempfile.TemporaryFile() as log:
            env = {k:v for k,v in os.environ.items() if not k.startswith('AZURESIM_AUTH')}
            env.update(AZURESIM_AUTH=mode, AZURESIM_AUTH_CONFIG=str(file))
            process = subprocess.Popen(command + ['serve', '--port', str(port)], cwd=root, env=env, stdout=log, stderr=log)
            base = f'http://127.0.0.1:{port}'
            try:
                end = time.monotonic() + 90
                while time.monotonic() < end:
                    if process.poll() is not None:
                        raise AssertionError('emulator exited before readiness')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2):
                            break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise AssertionError('readiness timeout')
                yield base
            except BaseException:
                log.seek(0)
                print(log.read().decode(errors='replace'), file=sys.stderr)
                raise
            finally:
                process.terminate()
                try: process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=10)


def signed(method, path, body, headers, key=KEY, account=ACCOUNT):
    h = {k.lower():v for k,v in headers.items()}
    h.setdefault('x-ms-date', email.utils.format_datetime(datetime.now(timezone.utc), usegmt=True))
    h.setdefault('x-ms-version', '2023-11-03')
    if body is not None:
        h.setdefault('content-length', str(len(body)))
        h.setdefault('content-type', 'application/octet-stream')
    parts = [method]
    for name in ['content-encoding','content-language','content-length','content-md5','content-type','date',
                 'if-modified-since','if-match','if-none-match','if-unmodified-since','range']:
        value = h.get(name, '')
        if name == 'content-length' and value == '0' and h['x-ms-version'] > '2014-02-14': value = ''
        if name == 'date' and 'x-ms-date' in h: value = ''
        parts.append(value)
    canonical = '\n'.join(parts) + '\n'
    canonical += ''.join(k + ':' + ' '.join(v.split()) + '\n' for k,v in sorted(h.items()) if k.startswith('x-ms-'))
    uri = urllib.parse.urlsplit(path)
    canonical += '/' + account + uri.path
    query = {}
    for k,v in urllib.parse.parse_qsl(uri.query, keep_blank_values=True):
        query.setdefault(k.lower(), []).append(v)
    canonical += ''.join('\n' + k + ':' + ','.join(sorted(v)) for k,v in sorted(query.items()))
    h['authorization'] = 'SharedKey ' + account + ':' + base64.b64encode(hmac.new(base64.b64decode(key), canonical.encode(), hashlib.sha256).digest()).decode()
    return h


def request(base, method, path, body=None, auth='key', status=200, error=None, headers=None, key=KEY):
    global checks
    headers = headers or {}
    if auth == 'key': headers = signed(method, path, body, headers, key)
    elif auth == 'bearer': headers['Authorization'] = 'Bearer ' + TOKEN
    elif auth is not None: headers['Authorization'] = auth
    req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try: response = opener.open(req, timeout=10)
    except urllib.error.HTTPError as ex: response = ex
    with response:
        content = response.read()
        assert response.status == status, (method, path, response.status, content)
        if error:
            assert response.headers['x-ms-error-code'] == error
            assert ('<Code>' + error + '</Code>').encode() in content
            assert TOKEN.encode() not in content and KEY.encode() not in content
        checks += 1
        return content

