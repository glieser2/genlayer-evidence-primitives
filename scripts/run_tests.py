"""Run each SDK test in a fresh process; exit nonzero on collection or test failure."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
os.chdir(root)
parser = argparse.ArgumentParser()
parser.add_argument('--output', default='evidence/local-tests.json')
args = parser.parse_args()
env = dict(os.environ, PYTHONIOENCODING='utf-8')
collected = subprocess.run([sys.executable, '-m', 'pytest', '--collect-only', '-q', 'tests/test_security.py'],
                           text=True, encoding='utf-8', capture_output=True, env=env)
if collected.returncode:
    print(collected.stdout, collected.stderr)
    raise SystemExit(collected.returncode)
nodes = [x.strip() for x in collected.stdout.splitlines() if x.startswith('tests/test_security.py::')]
if not nodes or len(nodes) != len(set(nodes)):
    raise SystemExit('Empty or duplicate test collection')
results = []
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
for node in nodes:
    run = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-s', node], capture_output=True,
                         text=True, encoding='utf-8', env=env)
    print(('PASS ' if run.returncode == 0 else 'FAIL ') + node, flush=True)
    if run.returncode:
        print(run.stdout, run.stderr, flush=True)
    results.append({'test': node, 'exit_code': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr})
manifest = {str(p.relative_to(root)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
            for directory in ('contracts', 'tests', 'scripts') for p in sorted((root / directory).glob('*.py'))}
report = {'started_utc': started, 'finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'python': sys.version, 'platform': sys.platform, 'mode': 'SDK Direct Mode: mocked web and LLM',
          'count': len(results), 'passed': sum(r['exit_code'] == 0 for r in results),
          'source_sha256': manifest, 'results': results}
target = root / args.output
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(json.dumps(report, indent=2), encoding='utf-8')
print(f"{report['passed']}/{report['count']} passed; {target}")
raise SystemExit(0 if all(r['exit_code'] == 0 for r in results) else 1)
