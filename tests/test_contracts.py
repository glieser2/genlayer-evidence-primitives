import json
import pytest


def test_source_quorum_agreement_and_dissent(direct_vm, direct_deploy):
    direct_vm.mock_web(r'a\.example', {'status': 200, 'body': 'The launch was successful on Monday.'})
    direct_vm.mock_web(r'b\.example', {'status': 200, 'body': 'The launch was successful on Monday.'})
    direct_vm.mock_llm(r'.*', json.dumps({'label':'SUPPORTS','quote':'The launch was successful on Monday.'}))
    contract = direct_deploy('contracts/source_quorum.py', 'The launch was successful on Monday.', json.dumps(['https://a.example/a', 'https://b.example/b']), 2)
    contract.evaluate()
    assert json.loads(contract.result())['status'] == 'SUPPORTED'
    assert direct_vm.run_validator() is True
    direct_vm.clear_mocks()
    direct_vm.mock_web(r'a\.example', {'status': 200, 'body': 'The launch was successful on Monday.'})
    direct_vm.mock_web(r'b\.example', {'status': 200, 'body': 'The launch was successful on Monday.'})
    direct_vm.mock_llm(r'.*', json.dumps({'label':'UNCLEAR','quote':''}))
    assert direct_vm.run_validator() is False


def test_source_duplicate_hosts_rejected(direct_deploy):
    with pytest.raises(Exception):
        direct_deploy('contracts/source_quorum.py', 'Test claim', json.dumps(['https://a.example/1','https://a.example/2']), 2)


def test_milestone_authorization_and_validator(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie):
    from gltest.direct.sdk_loader import setup_sdk_paths
    from pathlib import Path
    setup_sdk_paths(Path('contracts/rubric_milestone.py'))
    from genlayer import Address
    direct_vm.sender = direct_alice
    contract = direct_deploy('contracts/rubric_milestone.py', Address(direct_bob).as_hex, json.dumps(['Evidence mentions completed testing']))
    direct_vm.sender = direct_charlie
    with pytest.raises(Exception):
        contract.submit('Completed testing on all supported platforms.')
    direct_vm.sender = direct_bob
    contract.submit('Completed testing on all supported platforms.')
    with pytest.raises(Exception):
        contract.submit('Second submission should fail')
    direct_vm.sender = direct_alice
    direct_vm.mock_llm(r'.*', json.dumps({'label':'MET','quote':'Completed testing on all supported platforms.'}))
    contract.evaluate()
    assert json.loads(contract.result())['status'] == 'APPROVED'
    assert direct_vm.run_validator() is True
    direct_vm.clear_mocks()
    direct_vm.mock_llm(r'.*', json.dumps({'label':'UNCLEAR','quote':''}))
    assert direct_vm.run_validator() is False
    with pytest.raises(Exception):
        contract.evaluate()


def test_milestone_rejects_fabricated_quote(direct_vm, direct_deploy, direct_alice, direct_bob):
    from gltest.direct.sdk_loader import setup_sdk_paths
    from pathlib import Path
    setup_sdk_paths(Path('contracts/rubric_milestone.py'))
    from genlayer import Address
    direct_vm.sender = direct_alice
    contract = direct_deploy('contracts/rubric_milestone.py', Address(direct_bob).as_hex, json.dumps(['Testing is completed']))
    direct_vm.sender = direct_bob
    contract.submit('There is no supporting evidence here.')
    direct_vm.sender = direct_alice
    direct_vm.mock_llm(r'.*', json.dumps({'label':'MET','quote':'This quotation was fabricated.'}))
    with pytest.raises(Exception):
        contract.evaluate()
