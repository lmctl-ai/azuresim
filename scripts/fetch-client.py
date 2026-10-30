#!/usr/bin/env python3
"""Fetch exactly the checksum-pinned lmazure release; cached use is offline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('--offline', action='store_true')
args = p.parse_args()
lock = json.loads((ROOT/'client.lock.json').read_text())
os_name = {'Linux':'linux', 'Darwin':'macos', 'Windows':'windows'}[platform.system()]
arch = {'x86_64':'x64', 'AMD64':'x64', 'aarch64':'arm64', 'arm64':'arm64'}[platform.machine()]
label = os_name + '-' + arch
suffix = '.exe' if os_name == 'windows' else ''
asset = 'lmazure-' + label + suffix
expected = lock['sha256'][asset]
output = ROOT/'target'/('lmazure'+suffix)
output.parent.mkdir(exist_ok=True)
def digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()
if not output.exists() or digest(output) != expected:
    if args.offline: raise SystemExit('Pinned lmazure is absent or its checksum differs; fetch once without --offline')
    url = f'https://github.com/{lock["repository"]}/releases/download/{lock["tag"]}/{asset}'
    fd, temporary = tempfile.mkstemp(prefix='lmazure-download-', dir=output.parent)
    try:
        with os.fdopen(fd, 'wb') as stream, urllib.request.urlopen(url, timeout=120) as response:
            while chunk := response.read(1024*1024): stream.write(chunk)
        downloaded = Path(temporary)
        if digest(downloaded) != expected: raise SystemExit('lmazure checksum mismatch')
        downloaded.chmod(0o755)
        os.replace(downloaded, output)
    finally:
        Path(temporary).unlink(missing_ok=True)
output.chmod(0o755)
version = subprocess.run([str(output), '--version'], check=True, capture_output=True, text=True, timeout=30)
if version.stdout.strip() != 'lmazure '+lock['version']: raise SystemExit('lmazure version mismatch')
print(output)
