#!/usr/bin/env python3
"""Behavioral contract, exercised against either a jar or standalone binary."""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
exe = Path(sys.argv[1]).resolve()
command = ['java', '-jar', str(exe)] if exe.suffix == '.jar' else [str(exe)]
checks = 0

def run(args, code):
    global checks
    result = subprocess.run(command + args, capture_output=True, text=True, timeout=30)
    assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
    checks += 1
    return result.stdout

assert run(['--version'], 0).strip() == 'azuresim ' + (ROOT / 'VERSION').read_text().strip()
assert '127.0.0.1' in run(['--help'], 0)
assert 'Usage:' in run([], 0)
for args in [['nope'], ['serve', '--unknown'], ['serve', '--port'],
             ['serve', '--port', '0'], ['serve', '--port', '65536'],
             ['serve', '--port', 'x'], ['serve', '--port', '1', '--port', '2'],
             ['serve', '--data-dir'], ['serve', '--data-dir', '']]:
    assert json.loads(run(args, 2))['ok'] is False
print(f'CLI: {checks} checks passed')
