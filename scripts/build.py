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
if source.exists():
    shutil.rmtree(source)
with tarfile.open(archive) as tar:
    tar.extractall(target, filter='data')

overlay_lock_path = ROOT / 'overlay.lock.json'
if overlay_lock_path.exists():
    olock = json.loads(overlay_lock_path.read_text(encoding='utf-8'))
    expected_upstream = f"{lock['version']}/{lock['commit']}"
    if olock.get('upstream') not in (expected_upstream, lock['commit']):
        raise SystemExit(
            f"overlay.lock.json upstream '{olock.get('upstream')}' does not match "
            f"upstream.lock.json '{expected_upstream}'. Please 3-way merge overlay files "
            f"(see durable-memory/semantics-overlay.md) and update overlay.lock.json."
        )
    for rel_path, expected_sha in olock.get('overlays', {}).items():
        upstream_file = source / 'src/main/java' / rel_path
        if not upstream_file.exists():
            raise SystemExit(
                f"Overlay target file '{rel_path}' does not exist in upstream source at {upstream_file}. "
                f"Please 3-way merge overlay files (see durable-memory/semantics-overlay.md) and update overlay.lock.json."
            )
        actual_sha = hashlib.sha256(upstream_file.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            raise SystemExit(
                f"Upstream file '{rel_path}' sha256 mismatch!\n"
                f"  Expected: {expected_sha}\n"
                f"  Actual:   {actual_sha}\n"
                f"Upstream file changed. Please 3-way merge overlay files "
                f"(see durable-memory/semantics-overlay.md) and update overlay.lock.json."
            )

for overlay in (ROOT / 'src/main/java').rglob('*.java'):
    entry = source / 'src/main/java' / overlay.relative_to(ROOT / 'src/main/java')
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry_source = overlay.read_text().replace('@VERSION@', (ROOT / 'VERSION').read_text().strip())
    if not entry.exists() or entry.read_text() != entry_source:
        entry.write_text(entry_source)
# docker-java's Unix domain socket initializer resolves libc symbols, which do
# not exist on Windows. Keep this unused transport out of Windows build-time init.
if os.name == 'nt':
    metadata = source / 'src/main/resources/META-INF/native-image/ai.lmctl/azuresim/native-image.properties'
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text('Args = --initialize-at-run-time=com.github.dockerjava.transport.DomainSocket\n')
command = ['mvn.cmd' if os.name == 'nt' else 'mvn', '-B', 'package', '-Dmaven.test.skip=true',
           '-Dquarkus.package.main-class=ai.lmctl.azuresim.Main']
if args.offline:
    command.append('-o')
if args.native:
    command += ['-Dnative', '-Dquarkus.native.native-image-xmx=4g']
subprocess.run(command, cwd=source, check=True)
if args.native:
    suffix = '.exe' if os.name == 'nt' else ''
    shutil.copy2(source / f'target/floci-az-{lock["version"]}-runner{suffix}', target / ('azuresim' + suffix))
    print(target / ('azuresim' + suffix))
else:
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    quarkus_dist = dist / 'quarkus-app'
    if quarkus_dist.exists():
        shutil.rmtree(quarkus_dist)
    shutil.copytree(source / 'target/quarkus-app', quarkus_dist)
    print(quarkus_dist / 'quarkus-run.jar')
