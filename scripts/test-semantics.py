#!/usr/bin/env python3
"""Regression tests for Azure Blob and Queue semantics in azuresim."""
from contextlib import contextmanager
from pathlib import Path
import json
import socket
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

def request(method, path, body=None, status=200, headers=None, return_response=False):
    global checks
    req_headers = {'x-ms-version': '2023-11-03', **(headers or {})}
    req = urllib.request.Request(base + path, data=body, method=method, headers=req_headers)
    try:
        response = opener.open(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        content = response.read()
        resp_status = response.status
        resp_headers = dict(response.headers)
        assert resp_status == status, f"{method} {path} expected {status} got {resp_status}: {content}"
        checks += 1
        if return_response:
            return content, resp_status, resp_headers
        return content

@contextmanager
def server(directory):
    with tempfile.TemporaryFile(mode='w+b') as logs:
        args = command + ['serve', '--port', str(port), '--data-dir', str(directory / 'state')]
        process = subprocess.Popen(args, cwd=directory, stdout=logs, stderr=logs)
        try:
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError('azuresim exited before readiness')
                try:
                    with opener.open(base + '/devstoreaccount1?comp=list', timeout=1) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    time.sleep(.2)
            else:
                raise AssertionError('azuresim readiness timeout')
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

def main():
    with tempfile.TemporaryDirectory(prefix='azuresim-semantics-') as tmp:
        directory = Path(tmp)
        with server(directory):
            print("--- Running Azure Semantics Tests ---")

            # 1. Non-existent container delete -> 404 ContainerNotFound
            content, status, headers = request('DELETE', '/devstoreaccount1/never-created-c?restype=container', status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'ContainerNotFound', f"Expected x-ms-error-code ContainerNotFound, got {headers.get('x-ms-error-code')}"
            err_xml = ET.fromstring(content)
            assert err_xml.findtext('.//Code') == 'ContainerNotFound'

            # 2. Non-existent queue delete -> 404 QueueNotFound
            content, status, headers = request('DELETE', '/devstoreaccount1-queue/never-created-q', status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'QueueNotFound', f"Expected x-ms-error-code QueueNotFound, got {headers.get('x-ms-error-code')}"
            err_xml = ET.fromstring(content)
            assert err_xml.findtext('.//Code') == 'QueueNotFound'

            # 3. Non-empty container delete: creates container, adds blob, deletes container -> returns 202 and sweeps blob
            c_nonempty = '/devstoreaccount1/non-empty-c'
            blob_path = c_nonempty + '/file.txt'
            request('PUT', c_nonempty + '?restype=container', b'', status=201)
            request('PUT', blob_path, b'hello data', status=201, headers={'x-ms-blob-type': 'BlockBlob'})
            assert request('GET', blob_path) == b'hello data'
            request('DELETE', c_nonempty + '?restype=container', status=202)
            # Both container and blob should now be gone
            request('GET', c_nonempty + '?restype=container', status=404)
            request('GET', blob_path, status=404)

            # 4. PUT container twice -> 409 ContainerAlreadyExists
            c_idem = '/devstoreaccount1/idem-c'
            request('PUT', c_idem + '?restype=container', b'', status=201)
            content, status, headers = request('PUT', c_idem + '?restype=container', b'', status=409, return_response=True)
            assert headers.get('x-ms-error-code') == 'ContainerAlreadyExists'

            # 5. PUT queue twice:
            # Same metadata -> 204 No Content
            # Different metadata -> 409 QueueAlreadyExists
            q_idem = '/devstoreaccount1-queue/idem-q'
            request('PUT', q_idem, b'', status=201)
            request('PUT', q_idem, b'', status=204)  # same (empty) metadata -> 204
            content, status, headers = request('PUT', q_idem, b'', status=409, headers={'x-ms-meta-environment': 'production'}, return_response=True)
            assert headers.get('x-ms-error-code') == 'QueueAlreadyExists'

            q_meta = '/devstoreaccount1-queue/meta-q'
            request('PUT', q_meta, b'', status=201, headers={'x-ms-meta-color': 'blue'})
            request('PUT', q_meta, b'', status=204, headers={'x-ms-meta-color': 'blue'})  # same metadata -> 204
            content, status, headers = request('PUT', q_meta, b'', status=409, headers={'x-ms-meta-color': 'red'}, return_response=True)
            assert headers.get('x-ms-error-code') == 'QueueAlreadyExists'

            # 6. List blobs on non-existent container -> 404 ContainerNotFound
            content, status, headers = request('GET', '/devstoreaccount1/missing-container?restype=container&comp=list', status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'ContainerNotFound'

            # 7. Blob operations on non-existent container -> 404 ContainerNotFound
            missing_blob = '/devstoreaccount1/missing-c/blob.txt'
            content, status, headers = request('GET', missing_blob, status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'ContainerNotFound'

            content, status, headers = request('HEAD', missing_blob, status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'ContainerNotFound'

            content, status, headers = request('DELETE', missing_blob, status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'ContainerNotFound'

            content, status, headers = request('GET', missing_blob + '?comp=metadata', status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'ContainerNotFound'

            content, status, headers = request('PUT', missing_blob + '?comp=metadata', status=404, headers={'x-ms-meta-k': 'v'}, return_response=True)
            assert headers.get('x-ms-error-code') == 'ContainerNotFound'

            content, status, headers = request('GET', missing_blob + '?comp=tags', status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'ContainerNotFound'

            content, status, headers = request('GET', missing_blob + '?comp=blocklist', status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'ContainerNotFound'

            # 8. Blob operations on existing container with non-existent blob -> 404 BlobNotFound
            c_exist = '/devstoreaccount1/exist-c'
            request('PUT', c_exist + '?restype=container', b'', status=201)
            content, status, headers = request('GET', c_exist + '/no-such-blob.txt', status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'BlobNotFound'
            content, status, headers = request('HEAD', c_exist + '/no-such-blob.txt', status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'BlobNotFound'

            # 9. Operations on missing queue -> 404 QueueNotFound
            missing_q = '/devstoreaccount1-queue/missing-q'
            content, status, headers = request('POST', missing_q + '/messages', b'<QueueMessage><MessageText>hi</MessageText></QueueMessage>', status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'QueueNotFound'

            content, status, headers = request('GET', missing_q + '/messages', status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'QueueNotFound'

            content, status, headers = request('DELETE', missing_q + '/messages', status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'QueueNotFound'

            content, status, headers = request('DELETE', missing_q + '/messages/fake-id?popreceipt=fake', status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'QueueNotFound'

            content, status, headers = request('PUT', missing_q + '/messages/fake-id?popreceipt=fake&visibilitytimeout=10', b'', status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'QueueNotFound'

            # 10. UpdateMessage: empty body (visibility update only), receipt rotation, stale pop receipt rejection
            q_work = '/devstoreaccount1-queue/work-q'
            request('PUT', q_work, b'', status=201)
            request('POST', q_work + '/messages', b'<QueueMessage><MessageText>initial-payload</MessageText></QueueMessage>', status=201)

            resp_xml = ET.fromstring(request('GET', q_work + '/messages?visibilitytimeout=30'))
            msg_id = resp_xml.findtext('.//MessageId')
            pop1 = resp_xml.findtext('.//PopReceipt')
            assert msg_id and pop1

            # Update visibility with EMPTY body
            content, status, headers = request('PUT', f'{q_work}/messages/{msg_id}?popreceipt={urllib.parse.quote(pop1)}&visibilitytimeout=20',
                                               b'', status=204, return_response=True)
            pop2 = headers.get('x-ms-popreceipt')
            assert pop2, "Expected x-ms-popreceipt header in UpdateMessage response"
            assert pop2 != pop1, f"Expected rotated pop receipt, got {pop2} == {pop1}"
            assert headers.get('x-ms-time-next-visible'), "Expected x-ms-time-next-visible header"

            # Attempt delete with stale pop receipt -> 400 PopReceiptMismatch
            content, status, headers = request('DELETE', f'{q_work}/messages/{msg_id}?popreceipt={urllib.parse.quote(pop1)}',
                                               status=400, return_response=True)
            assert headers.get('x-ms-error-code') == 'PopReceiptMismatch'

            # Delete with current pop receipt -> 204 No Content
            request('DELETE', f'{q_work}/messages/{msg_id}?popreceipt={urllib.parse.quote(pop2)}', status=204)

            # Delete again -> 404 MessageNotFound
            content, status, headers = request('DELETE', f'{q_work}/messages/{msg_id}?popreceipt={urllib.parse.quote(pop2)}',
                                               status=404, return_response=True)
            assert headers.get('x-ms-error-code') == 'MessageNotFound'

            # 11. UpdateMessage: with new body and visibility 0 (immediate redelivery)
            request('POST', q_work + '/messages', b'<QueueMessage><MessageText>before-edit</MessageText></QueueMessage>', status=201)
            resp_xml = ET.fromstring(request('GET', q_work + '/messages?visibilitytimeout=30'))
            msg_id2 = resp_xml.findtext('.//MessageId')
            pop_orig = resp_xml.findtext('.//PopReceipt')

            update_body = b'<QueueMessage><MessageText>after-edit</MessageText></QueueMessage>'
            content, status, headers = request('PUT', f'{q_work}/messages/{msg_id2}?popreceipt={urllib.parse.quote(pop_orig)}&visibilitytimeout=0',
                                               update_body, status=204, return_response=True)
            pop_new = headers.get('x-ms-popreceipt')
            assert pop_new

            # Immediately receivable because visibilitytimeout=0
            recv_xml = ET.fromstring(request('GET', q_work + '/messages'))
            assert recv_xml.findtext('.//MessageText') == 'after-edit', f"Expected 'after-edit', got {recv_xml.findtext('.//MessageText')}"
            pop_after_recv = recv_xml.findtext('.//PopReceipt')
            request('DELETE', f'{q_work}/messages/{msg_id2}?popreceipt={urllib.parse.quote(pop_after_recv)}', status=204)

            # 12. GET and HEAD on queue with comp=metadata
            content, status, headers = request('GET', f'{q_work}?comp=metadata', status=200, return_response=True)
            assert 'x-ms-approximate-messages-count' in headers
            content, status, headers = request('HEAD', f'{q_work}?comp=metadata', status=200, return_response=True)
            assert 'x-ms-approximate-messages-count' in headers

            # 13. Clean up queues and containers
            request('DELETE', q_work, status=204)
            request('DELETE', q_idem, status=204)
            request('DELETE', q_meta, status=204)
            request('DELETE', c_idem + '?restype=container', status=202)
            request('DELETE', c_exist + '?restype=container', status=202)

            print(f"Semantics: {checks} checks passed successfully!")

if __name__ == '__main__':
    main()
