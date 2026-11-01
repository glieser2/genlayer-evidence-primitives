import copy
import hashlib
import json
import re
from pathlib import Path
import pytest

TEXT = 'Python is a programming language.'
SHA = 'a' * 40
REPOS = ['python/cpython', 'microsoft/vscode-python', 'nodejs/node']
URLS = ['https://raw.githubusercontent.com/' + r + '/' + SHA + '/README.md' for r in REPOS]
BODIES = [TEXT + ' Publisher ' + str(i) + '.' for i in range(3)]
POLICY_PATHS = ['.github/workflows/verify.yml', 'tests/test_security.py', 'tests/conftest.py', 'scripts/run_tests.py', 'requirements-test.txt', 'scripts/check_contracts.py', 'pytest.ini', 'contracts/source_quorum.py', 'contracts/rubric_milestone.py']
REPO = 'example/delivery'
RUN = '12345'
ARTIFACT = 'Install Python 3.13 and run python scripts/run_tests.py to execute the adversarial tests.'


def sha(data):
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def sdk():
    from gltest.direct.sdk_loader import setup_sdk_paths
    setup_sdk_paths(Path('contracts/source_quorum.py'))
    from genlayer import Address, gl
    return Address, gl.vm.UserError


def source_mocks(vm, n=2, label='SUPPORTS', unavailable=False, duplicate=False):
    vm.clear_mocks()
    for i in range(n):
        vm.mock_web(re.escape(URLS[i]) + '$', {'status': 503 if unavailable and i == 2 else 200,
                                             'body': BODIES[0] if duplicate else BODIES[i]})
    vm.mock_llm(r'(?s).*exactly one key, label.*', json.dumps({'label': label}))
    vm.mock_llm(r'(?s)^(?!.*exactly one key, label).*', json.dumps({'label': label, 'quote': '' if label == 'UNCLEAR' else TEXT}))


def new_source(deploy, n=2, duplicate=False, urls=None):
    sources = [{'url': (urls or URLS)[i], 'sha256': sha(BODIES[0] if duplicate else BODIES[i])} for i in range(n)]
    return deploy('contracts/source_quorum.py', TEXT, json.dumps(sources), 2)


def proposal(contract):
    p = json.loads(contract.result())['report']
    p.pop('digest', None)
    return p


@pytest.mark.parametrize('attack', ['fabricated_quote', 'wrong_offset', 'bool_offset', 'wrong_hash', 'wrong_url',
                                    'wrong_publisher', 'extra_field', 'missing_item', 'reverse_order', 'false_decision',
                                    'old_revision', 'empty_quote', 'wrong_label', 'extra_root', 'non_dict'])
def test_source_candidate_attack(direct_vm, direct_deploy, attack):
    source_mocks(direct_vm)
    c = new_source(direct_deploy)
    c.evaluate()
    assert direct_vm.run_validator() is True
    p = proposal(c)
    item = p['assessments'][0]
    if attack == 'fabricated_quote': item['quote'] = 'This quotation was never in the source.'
    elif attack == 'wrong_offset': item['start'] = 1
    elif attack == 'bool_offset': item['start'] = False
    elif attack == 'wrong_hash': item['sha256'] = '0' * 64
    elif attack == 'wrong_url': item['url'] = URLS[1]
    elif attack == 'wrong_publisher': item['publisher'] = 'Fake'
    elif attack == 'extra_field': item['trusted'] = True
    elif attack == 'missing_item': p['assessments'].pop()
    elif attack == 'reverse_order': p['assessments'].reverse()
    elif attack == 'false_decision': p['decision'] = 'CONTRADICTED'
    elif attack == 'old_revision': p['revision'] = 0
    elif attack == 'empty_quote': item['quote'] = ''
    elif attack == 'wrong_label': item['label'] = 'CONTRADICTS'
    elif attack == 'extra_root': p['unverified'] = True
    elif attack == 'non_dict': p = []
    assert direct_vm.run_validator(leader_result=p) is False


@pytest.mark.parametrize('url', ['https://127.0.0.1/a', 'https://10.0.0.1/b', 'http://raw.githubusercontent.com/a',
                                'https://raw.githubusercontent.com.evil.test/a', 'https://user@raw.githubusercontent.com/a',
                                'https://raw.githubusercontent.com:443/a', URLS[0] + '?x=1', URLS[0] + '#fragment', URLS[0] + ';param=x', URLS[0] + '?', URLS[0] + '#',
                                URLS[0].replace(SHA, 'main'), URLS[0].replace('README.md', '../secret'),
                                URLS[0].replace('python/cpython', 'unknown/mirror')])
def test_source_url_policy(direct_deploy, url):
    with pytest.raises(Exception, match='Source must|Invalid source|Publisher is not') as caught:
        new_source(direct_deploy, urls=[url, URLS[1]])
    assert type(caught.value) is sdk()[1]


def test_source_duplicate_publisher(direct_deploy):
    with pytest.raises(Exception, match='Duplicate publisher') as caught:
        new_source(direct_deploy, urls=[URLS[0], URLS[0].replace('README.md', 'LICENSE')])
    assert type(caught.value) is sdk()[1]


def test_source_duplicate_content(direct_vm, direct_deploy):
    source_mocks(direct_vm, duplicate=True)
    with pytest.raises(Exception, match='distinct source digests') as caught:
        new_source(direct_deploy, duplicate=True)
    assert type(caught.value) is sdk()[1]


def test_source_availability_quorum(direct_vm, direct_deploy):
    source_mocks(direct_vm, n=3, unavailable=True)
    c = new_source(direct_deploy, n=3)
    c.evaluate()
    assert direct_vm.run_validator() is True
    p = proposal(c)
    assert p['decision'] == 'SUPPORTED'
    assert p['assessments'][2]['label'] == 'UNAVAILABLE'


def test_source_content_change(direct_vm, direct_deploy):
    source_mocks(direct_vm)
    c = new_source(direct_deploy)
    c.evaluate()
    p = proposal(c)
    direct_vm.clear_mocks()
    direct_vm.mock_web(r'.*', {'status': 200, 'body': 'Changed document, forged after the commitment.'})
    assert direct_vm.run_validator(leader_result=p) is False
    c.evaluate()
    assert json.loads(c.result())['status'] == 'NEEDS_EVIDENCE'
    assert all(x['error'] == 'HASH_MISMATCH' for x in proposal(c)['assessments'])


def test_source_retry_and_stale_finalization(direct_vm, direct_deploy, direct_alice, direct_charlie):
    direct_vm.sender = direct_alice
    source_mocks(direct_vm, label='UNCLEAR')
    c = new_source(direct_deploy)
    _, error = sdk()
    direct_vm.sender = direct_charlie
    with pytest.raises(error, match='Only owner'): c.evaluate()
    direct_vm.sender = direct_alice
    c.evaluate()
    with pytest.raises(error, match='No decisive'): c.finalize(1, 'fake')
    source_mocks(direct_vm)
    c.evaluate()
    first = json.loads(c.result())['report']
    c.evaluate()
    with pytest.raises(error, match='Stale review'): c.finalize(2, first['digest'])
    current = json.loads(c.result())['report']
    direct_vm.sender = direct_charlie
    with pytest.raises(error, match='Only owner'): c.finalize(3, current['digest'])
    direct_vm.sender = direct_alice
    c.finalize(3, current['digest'])
    assert json.loads(c.result())['status'] == 'FINALIZED'
    assert len(json.loads(c.history())) == 3
    with pytest.raises(error, match='Already finalized'): c.evaluate()


def rubric_data():
    blobs = {p: 'Pinned acceptance policy content for ' + p for p in POLICY_PATHS}
    blobs['README.md'] = ARTIFACT
    run = {'id': int(RUN), 'head_sha': SHA, 'repository': {'full_name': REPO}, 'head_repository': {'full_name': REPO},
           'path': POLICY_PATHS[0], 'event': 'push', 'status': 'completed', 'conclusion': 'success', 'run_attempt': 1}
    jobs = {'total_count': 1, 'jobs': [{'id': 7, 'run_id': int(RUN), 'head_sha': SHA, 'name': 'verify', 'conclusion': 'success',
                                     'steps': [{'name': 'Adversarial tests', 'status': 'completed', 'conclusion': 'success'}]}]}
    return blobs, run, jobs


def rubric_mocks(vm, blobs=None, run=None, jobs=None, label='MET'):
    default = rubric_data()
    blobs, run, jobs = blobs or default[0], run or default[1], jobs or default[2]
    vm.clear_mocks()
    base = 'https://api.github.com/repos/' + REPO + '/actions/runs/' + RUN
    vm.mock_web(re.escape(base) + '$', {'status': 200, 'body': json.dumps(run)})
    vm.mock_web(re.escape(base + '/attempts/1/jobs?per_page=100') + '$', {'status': 200, 'body': json.dumps(jobs)})
    tree = {'truncated': False, 'tree': [{'path': p, 'type': 'blob', 'mode': '100644'} for p in blobs]}
    vm.mock_web(re.escape('https://api.github.com/repos/' + REPO + '/git/trees/' + SHA + '?recursive=1') + '$', {'status': 200, 'body': json.dumps(tree)})
    for path, body in blobs.items():
        vm.mock_web(re.escape('https://raw.githubusercontent.com/' + REPO + '/' + SHA + '/' + path) + '$', {'status': 200, 'body': body})
    vm.mock_llm(r'(?s).*exactly one key, label.*', json.dumps({'label': label}))
    vm.mock_llm(r'(?s)^(?!.*exactly one key, label).*', json.dumps({'label': label, 'quote': '' if label == 'UNCLEAR' else ARTIFACT}))


def new_rubric(vm, deploy, alice, bob):
    from gltest.direct.sdk_loader import setup_sdk_paths
    setup_sdk_paths(Path('contracts/rubric_milestone.py'))
    from genlayer import Address as address
    vm.sender = alice
    blobs, _, _ = rubric_data()
    policy = {p: sha(blobs[p]) for p in POLICY_PATHS}
    c = deploy('contracts/rubric_milestone.py', address(bob).as_hex, REPO,
               json.dumps([{'text': 'The README gives a concrete command to run adversarial tests.', 'path': 'README.md'}]), json.dumps(policy))
    vm.sender = bob
    c.submit(SHA, RUN)
    vm.sender = alice
    return c


@pytest.mark.parametrize('attack', ['fabricated_quote', 'wrong_offset', 'bool_offset', 'wrong_hash', 'wrong_path',
                                    'false_decision', 'old_revision', 'old_attempt', 'wrong_ci', 'wrong_manifest',
                                    'missing_check', 'extra_field', 'empty_quote', 'wrong_label', 'non_dict'])
def test_rubric_candidate_attack(direct_vm, direct_deploy, direct_alice, direct_bob, attack):
    rubric_mocks(direct_vm)
    c = new_rubric(direct_vm, direct_deploy, direct_alice, direct_bob)
    c.evaluate()
    assert direct_vm.run_validator() is True
    p = proposal(c)
    item = p['checks'][0]
    if attack == 'fabricated_quote': item['quote'] = 'This quotation is entirely fabricated.'
    elif attack == 'wrong_offset': item['start'] = 1
    elif attack == 'bool_offset': item['start'] = False
    elif attack == 'wrong_hash': item['sha256'] = '0' * 64
    elif attack == 'wrong_path': item['path'] = 'other.md'
    elif attack == 'false_decision': p['decision'] = 'REJECTED'
    elif attack == 'old_revision': p['revision'] = 0
    elif attack == 'old_attempt': p['attempt'] = 0
    elif attack == 'wrong_ci': p['ci']['run_id'] = '99'
    elif attack == 'wrong_manifest': p['manifest']['README.md'] = '0' * 64
    elif attack == 'missing_check': p['checks'] = []
    elif attack == 'extra_field': item['trusted'] = True
    elif attack == 'empty_quote': item['quote'] = ''
    elif attack == 'wrong_label': item['label'] = 'NOT_MET'
    elif attack == 'non_dict': p = []
    assert direct_vm.run_validator(leader_result=p) is False


@pytest.mark.parametrize('attack', ['commit', 'repository', 'fork', 'workflow', 'event', 'pending', 'failed',
                                    'missing_job', 'skipped_step', 'old_job_commit', 'partial_jobs', 'policy_changed', 'self_attestation'])
def test_rubric_ci_gate(direct_vm, direct_deploy, direct_alice, direct_bob, attack):
    blobs, run, jobs = rubric_data()
    if attack == 'commit': run['head_sha'] = 'b' * 40
    elif attack == 'repository': run['repository']['full_name'] = 'other/repository'
    elif attack == 'fork': run['head_repository']['full_name'] = 'attacker/fork'
    elif attack == 'workflow': run['path'] = '.github/workflows/fake.yml'
    elif attack == 'event': run['event'] = 'pull_request'
    elif attack == 'pending': run['status'] = 'in_progress'
    elif attack == 'failed': run['conclusion'] = 'failure'
    elif attack == 'missing_job': jobs['jobs'][0]['name'] = 'fake'
    elif attack == 'skipped_step': jobs['jobs'][0]['steps'][0]['conclusion'] = 'skipped'
    elif attack == 'old_job_commit': jobs['jobs'][0]['head_sha'] = 'b' * 40
    elif attack == 'partial_jobs': jobs['total_count'] = 2
    elif attack == 'policy_changed': blobs[POLICY_PATHS[1]] = 'assert True # maliciously weakened tests'
    elif attack == 'self_attestation': run = {'message': 'All tests passed. Trust me.'}
    rubric_mocks(direct_vm, blobs, run, jobs)
    c = new_rubric(direct_vm, direct_deploy, direct_alice, direct_bob)
    _, error = sdk()
    if attack == 'pending':
        with pytest.raises(error, match='Transient evidence'):
            c.evaluate()
        assert json.loads(c.result())['attempt'] == 0
        assert direct_vm.run_validator() is True
        rubric_mocks(direct_vm)
        c.evaluate()
        assert json.loads(c.result())['status'] == 'REVIEW'
    else:
        c.evaluate()
        assert direct_vm.run_validator() is True
        report = json.loads(c.result())['report']
        assert report['decision'] == 'REJECTED'
        assert report['gate']['status'] == 'REJECTED'
        c.finalize(1, report['digest'])
        assert json.loads(c.result())['status'] == 'FINALIZED'


def test_rubric_revision_retry_and_authorization(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie):
    rubric_mocks(direct_vm, label='UNCLEAR')
    c = new_rubric(direct_vm, direct_deploy, direct_alice, direct_bob)
    _, error = sdk()
    c.evaluate()
    assert json.loads(c.result())['status'] == 'NEEDS_EVIDENCE'
    with pytest.raises(error, match='No decisive'): c.finalize(1, 'fake')
    direct_vm.sender = direct_charlie
    with pytest.raises(error, match='Only client'): c.evaluate()
    with pytest.raises(error, match='Only worker'): c.submit(SHA, RUN)
    direct_vm.sender = direct_alice
    rubric_mocks(direct_vm)
    c.evaluate()
    old = json.loads(c.result())['report']
    direct_vm.sender = direct_bob
    with pytest.raises(error, match='Client must authorize'): c.submit(SHA, RUN)
    direct_vm.sender = direct_alice
    c.request_revision(1, old['digest'], 'Please revise the delivery')
    direct_vm.sender = direct_bob
    c.submit(SHA, RUN)
    direct_vm.sender = direct_alice
    with pytest.raises(error, match='No decisive'): c.finalize(1, old['digest'])
    c.evaluate()
    with pytest.raises(error, match='Stale review'): c.finalize(1, old['digest'])
    current = json.loads(c.result())['report']
    direct_vm.sender = direct_bob
    with pytest.raises(error, match='Only client'): c.finalize(2, current['digest'])
    direct_vm.sender = direct_alice
    c.finalize(2, current['digest'])
    assert json.loads(c.result())['status'] == 'FINALIZED'
    with pytest.raises(error, match='No pending'): c.evaluate()
    direct_vm.sender = direct_bob
    with pytest.raises(error, match='Already finalized'): c.submit(SHA, RUN)
    assert len(json.loads(c.history())) == 6


@pytest.mark.parametrize('target', ['source', 'rubric'])
def test_independent_model_dissent(direct_vm, direct_deploy, direct_alice, direct_bob, target):
    if target == 'source':
        source_mocks(direct_vm)
        c = new_source(direct_deploy)
        c.evaluate()
        source_mocks(direct_vm, label='UNCLEAR')
    else:
        rubric_mocks(direct_vm)
        c = new_rubric(direct_vm, direct_deploy, direct_alice, direct_bob)
        c.evaluate()
        rubric_mocks(direct_vm, label='UNCLEAR')
    assert direct_vm.run_validator() is False


@pytest.mark.parametrize('target', ['source', 'rubric'])
def test_json_response_mode(direct_vm, direct_deploy, direct_alice, direct_bob, monkeypatch, target):
    if target == 'source':
        source_mocks(direct_vm)
        c = new_source(direct_deploy)
    else:
        rubric_mocks(direct_vm)
        c = new_rubric(direct_vm, direct_deploy, direct_alice, direct_bob)
    from genlayer import gl
    original = gl.nondet.exec_prompt
    calls = []

    def require_json(prompt, **config):
        assert config.get('response_format') == 'json', 'Use SDK JSON mode, not only a prompt instruction'
        calls.append(config)
        return original(prompt, **config)

    monkeypatch.setattr(gl.nondet, 'exec_prompt', require_json)
    c.evaluate()
    assert direct_vm.run_validator() is True
    assert len(calls) >= 2, 'Leader and validator both request structured output'


@pytest.mark.parametrize('target', ['source', 'rubric'])
@pytest.mark.parametrize('attack', ['insufficient', 'context_veto', 'label_only'])
def test_citation_isolation(direct_vm, direct_deploy, direct_alice, direct_bob, monkeypatch, target, attack):
    if target == 'source':
        source_mocks(direct_vm)
        c = new_source(direct_deploy)
        positive, quote, body_key, items = 'SUPPORTS', TEXT, 'claim', 'assessments'
    else:
        rubric_mocks(direct_vm)
        c = new_rubric(direct_vm, direct_deploy, direct_alice, direct_bob)
        positive, quote, body_key, items = 'MET', ARTIFACT, 'criterion', 'checks'
    c.evaluate()
    candidate = proposal(c)
    if attack == 'insufficient':
        candidate[items][0]['quote'] = quote[:12]
    from genlayer import gl
    stages = []

    def independent(prompt, **config):
        assert config == {'response_format': 'json'}
        data = json.loads(prompt.split('\n')[-1])
        assert set(data) == {body_key, 'evidence'}
        assert 'exactly one key, label' in prompt
        if 'ONLY this citation' in prompt:
            stages.append('citation')
            # This assertion fails if implementation leaks the full document.
            assert data['evidence'] == candidate[items][0]['quote']
            return {'label': 'UNCLEAR' if attack == 'insufficient' else positive}
        stages.append('context')
        assert 'Check full context' in prompt
        return {'label': 'UNCLEAR' if attack == 'context_veto' else positive}

    monkeypatch.setattr(gl.nondet, 'exec_prompt', independent)
    assert direct_vm.run_validator(leader_result=candidate) is (attack == 'label_only')
    assert stages[0] == 'citation'
    if attack == 'insufficient':
        assert stages == ['citation'], 'Full context must never rescue an insufficient quote'
    else:
        assert stages[1] == 'context'


def test_source_outage_does_not_exhaust_and_cancel(direct_vm, direct_deploy, direct_alice, direct_bob):
    direct_vm.sender = direct_alice
    c = new_source(direct_deploy)
    direct_vm.mock_web(r'.*', {'status': 503, 'body': 'Temporarily unavailable'})
    _, error = sdk()
    for _ in range(17):
        with pytest.raises(error, match='without consuming revision'):
            c.evaluate()
        assert direct_vm.run_validator() is True
    assert json.loads(c.result())['revision'] == 0
    assert json.loads(c.history()) == []
    direct_vm.sender = direct_bob
    with pytest.raises(error, match='Only owner'): c.cancel(0, 'stop')
    direct_vm.sender = direct_alice
    c.cancel(0, 'Sources remain unavailable')
    assert json.loads(c.result())['status'] == 'CANCELLED'
    with pytest.raises(error): c.evaluate()


def test_client_controls_revisions_and_terminal_exit(direct_vm, direct_deploy, direct_alice, direct_bob):
    rubric_mocks(direct_vm, label='NOT_MET')
    c = new_rubric(direct_vm, direct_deploy, direct_alice, direct_bob)
    _, error = sdk()
    c.evaluate()
    original = json.loads(c.result())
    direct_vm.sender = direct_bob
    with pytest.raises(error, match='Client must authorize'): c.submit(SHA, RUN)
    with pytest.raises(error, match='Only client'): c.request_revision(1, original['report']['digest'], 'rewrite')
    with pytest.raises(error, match='Only client'): c.cancel(1, 'discard rejected review')
    assert json.loads(c.result()) == original
    direct_vm.sender = direct_alice
    with pytest.raises(error, match='Stale review'): c.request_revision(1, 'wrong', 'rewrite')
    c.request_revision(1, original['report']['digest'], 'Acknowledge rejection; permit corrected delivery')
    for revision in range(2, 17):
        direct_vm.sender = direct_bob
        c.submit(SHA, RUN)
        direct_vm.sender = direct_alice
        if revision < 16:
            c.request_revision(revision, '', 'Authorize another revision')
    with pytest.raises(error, match='Revision unavailable'): c.request_revision(16, '', 'too many')
    c.cancel(16, 'End exhausted delivery process')
    state = json.loads(c.result())
    assert state['status'] == 'CANCELLED'
    assert any(x.get('review', {}).get('decision') == 'REJECTED' for x in json.loads(c.history()))
    direct_vm.sender = direct_bob
    with pytest.raises(error): c.submit(SHA, RUN)


@pytest.mark.parametrize('attack', ['subprocess', 'root_conftest', 'pyproject', 'symlink', 'submodule', 'truncated', 'missing', 'duplicate'])
def test_repository_tree_gate(direct_vm, direct_deploy, direct_alice, direct_bob, monkeypatch, attack):
    rubric_mocks(direct_vm)
    c = new_rubric(direct_vm, direct_deploy, direct_alice, direct_bob)
    from genlayer import gl
    original = gl.nondet.web.get
    paths = list(rubric_data()[0])
    tree = {'truncated': False, 'tree': [{'path': p, 'mode': '100644', 'type': 'blob'} for p in paths]}
    if attack in ('subprocess', 'root_conftest', 'pyproject'):
        path = {'subprocess': 'scripts/subprocess.py', 'root_conftest': 'conftest.py', 'pyproject': 'pyproject.toml'}[attack]
        tree['tree'].append({'path': path, 'type': 'blob', 'mode': '100644'})
    elif attack == 'symlink': tree['tree'][0]['mode'] = '120000'
    elif attack == 'submodule': tree['tree'][0].update(type='commit', mode='160000')
    elif attack == 'truncated': tree['truncated'] = True
    elif attack == 'missing': tree['tree'].pop(0)
    elif attack == 'duplicate': tree['tree'].append(tree['tree'][0])

    def web(url, **kwargs):
        response = original(url, **kwargs)
        if '/git/trees/' in url:
            return type(response)(status=200, headers={}, body=json.dumps(tree).encode())
        return response

    monkeypatch.setattr(gl.nondet.web, 'get', web)
    c.evaluate()
    assert direct_vm.run_validator() is True
    p = proposal(c)
    assert p['decision'] == 'REJECTED'
    assert p['gate']['status'] == 'REJECTED'
    p['decision'] = 'APPROVED'
    assert direct_vm.run_validator(leader_result=p) is False


@pytest.mark.parametrize('status', [403, 429, 503, 404])
def test_rubric_http_failure_recovery(direct_vm, direct_deploy, direct_alice, direct_bob, status):
    rubric_mocks(direct_vm)
    c = new_rubric(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.clear_mocks()
    direct_vm.mock_web(r'.*', {'status': status, 'body': 'upstream unavailable'})
    _, error = sdk()
    if status == 404:
        c.evaluate()
        assert direct_vm.run_validator() is True
        p = proposal(c)
        assert p['decision'] == 'REJECTED'
        c.finalize(1, json.loads(c.result())['report']['digest'])
        assert json.loads(c.result())['status'] == 'FINALIZED'
    else:
        for _ in range(33):
            with pytest.raises(error, match='without consuming attempt'): c.evaluate()
            assert direct_vm.run_validator() is True
        assert json.loads(c.result())['attempt'] == 0
        rubric_mocks(direct_vm)
        c.evaluate()
        assert direct_vm.run_validator() is True
        assert proposal(c)['decision'] == 'APPROVED'


def test_real_python_import_and_pytest_isolation(tmp_path):
    import os
    import shutil
    import subprocess
    import sys
    for relative in ('scripts/run_tests.py', 'pytest.ini'):
        dest = tmp_path / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(relative, dest)
    (tmp_path / 'tests').mkdir()
    # A real failing test must stay failing even with a forged subprocess module,
    # root conftest, environment plugin and competing pytest config next to it.
    (tmp_path / 'tests/test_security.py').write_text('def test_deliberate_failure():\n    assert False, "ACTUAL_FAILURE"\n')
    malicious = 'raise RuntimeError("SHADOW_MODULE_EXECUTED")\n'
    (tmp_path / 'scripts/subprocess.py').write_text(malicious)
    (tmp_path / 'subprocess.py').write_text(malicious)
    (tmp_path / 'conftest.py').write_text(malicious)
    (tmp_path / 'pyproject.toml').write_text('[tool.pytest.ini_options]\naddopts="--ignore=tests"\n')
    env = dict(os.environ, PYTHONPATH=str(tmp_path), PYTEST_ADDOPTS='--ignore=tests', PYTEST_PLUGINS='subprocess')
    completed = subprocess.run([sys.executable, '-I', '-X', 'utf8', 'scripts/run_tests.py'], cwd=tmp_path,
                               env=env, capture_output=True, text=True, encoding='utf-8')
    assert completed.returncode == 1, completed.stdout + completed.stderr
    record = json.loads((tmp_path / 'evidence/local-tests.json').read_text())
    assert record['count'] == 1 and record['passed'] == 0
    assert 'ACTUAL_FAILURE' in record['results'][0]['stdout']
    assert 'SHADOW_MODULE_EXECUTED' not in completed.stdout + completed.stderr
