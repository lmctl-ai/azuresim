#!/usr/bin/env python3
"""Offline REST integration against OUR process: blob and queue lifecycle + restart."""
from contextlib import contextmanager
from pathlib import Path
import socket
import json
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

exe = Path(sys.argv[1]).resolve()
command = ['java', '-jar', str(exe)] if exe.suffix == '.jar' else [str(exe)]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
checks = 0

with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
base = f'http://127.0.0.1:{port}'

def request(method, path, body=None, status=200, headers=None):
    global checks
    headers = {'x-ms-version': '2023-11-03', **(headers or {})}
    req = urllib.request.Request(base + path, data=body, method=method, headers=headers)
    try:
        response = opener.open(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        content = response.read()
        assert response.status == status, (method, path, response.status, content)
        checks += 1
        return content

@contextmanager
def server(directory, persistent=True, alias='serve'):
    with tempfile.TemporaryFile(mode='w+b') as logs:
        args = command + [alias, '--port', str(port)]
        if persistent:
            args += ['--data-dir', str(directory / 'state')]
        process = subprocess.Popen(args, cwd=directory, stdout=logs, stderr=logs)
        try:
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError('Emulator exited before readiness')
                try:
                    with opener.open(base + '/devstoreaccount1?comp=list', timeout=1) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    time.sleep(.2)
            else:
                raise AssertionError('Emulator readiness timeout')
            yield
        except BaseException:
            logs.seek(0)
            print(logs.read().decode(errors='replace'), file=sys.stderr)
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)

container = '/devstoreaccount1/azuresim-test'
blob = container + '/hello.txt'
queue = '/devstoreaccount1-queue/azuresim-test'
payload = b'hello from azuresim\x00\xff\n'
with tempfile.TemporaryDirectory(prefix='azuresim-test-') as tmp:
    directory = Path(tmp)
    with server(directory):
        conflict = subprocess.run(command + ['serve', '--port', str(port)], cwd=directory,
                                  capture_output=True, text=True, timeout=45)
        assert conflict.returncode == 3, (conflict.returncode, conflict.stdout, conflict.stderr)
        assert json.loads(conflict.stdout)['ok'] is False
        request('PUT', container + '?restype=container', b'', 201)
        request('PUT', blob, payload, 201, {'x-ms-blob-type': 'BlockBlob'})
        assert request('GET', blob) == payload
        assert b'hello.txt' in request('GET', container + '?restype=container&comp=list')
        request('GET', container + '/missing', status=404)
        request('PUT', queue, b'', 201)
        request('POST', queue + '/messages', b'<QueueMessage><MessageText>hello-queue</MessageText></QueueMessage>', 201)
        peek = ET.fromstring(request('GET', queue + '/messages?peekonly=true'))
        assert peek.findtext('.//MessageText') == 'hello-queue'
        messages = ET.fromstring(request('GET', queue + '/messages?visibilitytimeout=30'))
        assert messages.findtext('.//MessageText') == 'hello-queue'
        message_id = messages.findtext('.//MessageId')
        receipt = messages.findtext('.//PopReceipt')
        assert message_id and receipt
        assert not ET.fromstring(request('GET', queue + '/messages')).findall('.//QueueMessage')
        request('DELETE', queue + '/messages/' + message_id + '?popreceipt=' + urllib.parse.quote(receipt, safe=''), status=204)
        request('DELETE', queue, status=204)
        request('GET', queue + '/messages', status=404)
    with server(directory, alias='start'):
        assert request('GET', blob) == payload
        request('DELETE', blob, status=202)
        request('DELETE', container + '?restype=container', status=202)
        request('GET', blob, status=404)
    with server(directory, persistent=False):
        request('PUT', container + '?restype=container', b'', 201)
        request('PUT', blob, payload, 201, {'x-ms-blob-type': 'BlockBlob'})
        assert request('GET', blob) == payload
    with server(directory, persistent=False):
        request('GET', blob, status=404)
print(f'Storage: {checks} REST checks passed; blob bytes, queue visibility/delete, persistence restart, start alias')
