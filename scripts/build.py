#!/usr/bin/env python3
"""Build pinned Floci-AZ with our entrypoint; reuse verified archive offline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('--native', action='store_true')
p.add_argument('--offline', action='store_true', help='require cached source and Maven dependencies')
args = p.parse_args()
lock = json.loads((ROOT / 'upstream.lock.json').read_text())
target = ROOT / 'target'
target.mkdir(exist_ok=True)
archive = target / 'upstream.tar.gz'
if not archive.exists():
    if args.offline:
        raise SystemExit('Offline build requires target/upstream.tar.gz')
    url = f'https://codeload.github.com/floci-io/floci-az/tar.gz/{lock["commit"]}'
    with urllib.request.urlopen(url, timeout=120) as response:
        content = response.read()
    if hashlib.sha256(content).hexdigest() != lock['sha256']:
        raise SystemExit('Upstream archive checksum mismatch')
    archive.write_bytes(content)
if hashlib.sha256(archive.read_bytes()).hexdigest() != lock['sha256']:
    raise SystemExit('Upstream archive checksum mismatch; remove target/upstream.tar.gz to retry')
source = target / ('floci-az-' + lock['commit'])
if not source.exists():
    with tarfile.open(archive) as tar:
        tar.extractall(target, filter='data')
entry = source / 'src/main/java/ai/lmctl/azuresim/Main.java'
entry.parent.mkdir(parents=True, exist_ok=True)
entry_source = (ROOT / 'src/main/java/ai/lmctl/azuresim/Main.java').read_text().replace(
    '@VERSION@', (ROOT / 'VERSION').read_text().strip())
if not entry.exists() or entry.read_text() != entry_source:
    entry.write_text(entry_source)
command = ['mvn.cmd' if os.name == 'nt' else 'mvn', '-B', 'package', '-Dmaven.test.skip=true',
           '-Dquarkus.package.main-class=ai.lmctl.azuresim.Main']
if args.offline:
    command.append('-o')
if args.native:
    command += ['-Dnative', '-Dquarkus.native.native-image-xmx=6g']
subprocess.run(command, cwd=source, check=True)
if args.native:
    suffix = '.exe' if os.name == 'nt' else ''
    shutil.copy2(source / f'target/floci-az-{lock["version"]}-runner{suffix}', target / ('azuresim' + suffix))
    print(target / ('azuresim' + suffix))
else:
    print(source / 'target/quarkus-app/quarkus-run.jar')
