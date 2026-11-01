"""Run the official linter against exactly the SDK used by the tests."""
import sys
if not sys.flags.isolated:
    raise SystemExit('Run with python -I scripts/check_contracts.py')
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import gltest.direct.sdk_loader as loader

root = Path(__file__).resolve().parents[1]
os.chdir(root)
loader.CACHE_DIR = Path(os.environ.get('GENLAYER_TEST_CACHE', Path.home() / '.cache' / 'genlayer-v2-tests'))
loader.get_latest_version = lambda: 'v0.2.12'
loader.setup_sdk_paths(root / 'contracts/source_quorum.py')
sources = list((loader.CACHE_DIR / 'extracted' / 'v0.2.12' / 'py-lib-genlayer-std').glob('*/genlayer/__init__.py'))
if len(sources) != 1:
    raise SystemExit('Expected exactly one pinned SDK')
with tempfile.TemporaryDirectory(prefix='genlayer-lint-') as directory:
    target = Path(directory) / 'runners/genlayer-py-std/src'
    shutil.copytree(sources[0].parents[1], target)
    env = dict(os.environ, GENVMROOT=directory, PYTHONIOENCODING='utf-8')
    logs, failures = [], 0
    for name in ('source_quorum.py', 'rubric_milestone.py'):
        run = subprocess.run([sys.executable, '-I', '-X', 'utf8', '-c', 'from genvm_linter.cli import cli; cli()', 'check', 'contracts/' + name],
                             capture_output=True, text=True, encoding='utf-8', env=env)
        logs.append(name + '\n' + run.stdout + run.stderr)
        failures += run.returncode != 0
    (root / 'evidence').mkdir(exist_ok=True)
    (root / 'evidence/lint.txt').write_text('\n'.join(logs), encoding='utf-8')
    print('\n'.join(logs))
    raise SystemExit(1 if failures else 0)
