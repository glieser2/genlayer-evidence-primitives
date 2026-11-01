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
POLICY_PATHS = ['.github/workflows/verify.yml', 'tests/test_security.py', 'tests/conftest.py', 'scripts/run_tests.py', 'requirements-test.txt']
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
    vm.mock_llm(r'.*', json.dumps({'label': label, 'quote': '' if label == 'UNCLEAR' else TEXT}))


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
                                'https://raw.githubusercontent.com:443/a', URLS[0] + '?x=1', URLS[0] + '#fragment',
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
    c = new_source(direct_deploy, duplicate=True)
    c.evaluate()
    assert direct_vm.run_validator() is True
    assert json.loads(c.result())['status'] == 'NEEDS_EVIDENCE'


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
    for path, body in blobs.items():
        vm.mock_web(re.escape('https://raw.githubusercontent.com/' + REPO + '/' + SHA + '/' + path) + '$', {'status': 200, 'body': body})
    vm.mock_llm(r'.*', json.dumps({'label': label, 'quote': '' if label == 'UNCLEAR' else ARTIFACT}))


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
    with pytest.raises(error, match='CI identity|Required CI|Incomplete CI|Pinned acceptance'):
        c.evaluate()
    assert json.loads(c.result())['status'] == 'SUBMITTED'
    rubric_mocks(direct_vm)
    c.evaluate()
    assert json.loads(c.result())['status'] == 'REVIEW'


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
    assert len(json.loads(c.history())) == 5


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
