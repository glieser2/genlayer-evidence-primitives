# GenLayer evidence primitives

Two experimental standalone Intelligent Contracts, not production financial infrastructure.

## SourceQuorum

One instance assesses one fixed claim against two to five HTTPS sources. Each source is fetched and classified separately, and decisive classifications must contain an exact source quote. The decision is derived from the per-source labels: support or contradiction requires the configured quorum and no opposing source; otherwise it is inconclusive. Each validator repeats the retrieval and classification and compares every label and the decision. The contract stores the leader's citations and outcome.

The URL check only rejects identical hostnames, not related publishers, mirrors, redirects, IP addresses, or manipulated sources. Independent hostnames do not guarantee independent evidence. LLMs can misclassify or obey malicious source text. Exact quotes prove provenance within fetched text, not that the text entails the claim. Web content may change, and source failures revert rather than determine a verdict. No authenticity, safety, or fraud prevention is guaranteed. Do not use as a production oracle.

## RubricMilestone

An instance records a fixed worker and criteria; only that worker can submit evidence and only the client can request evaluation. Validators independently classify each criterion and must agree on every label and the derived decision. A `MET` result requires a quote from the submitted evidence. Inconclusive evidence stays inconclusive. Outcomes are terminal. The evidence is supplied by the worker and is not authenticated: a correct citation cannot establish its truth. This contract has no escrow, transfers, revisions, dispute mechanism or guarantees about external facts. It is not suitable for unattended payments.

## Validation status

The contract source was checked with genvm-linter 0.11.0 using GenVM v0.2.12 SDK. Four isolated direct-mode tests exercised expected agreement, validator disagreement, duplicate host, access control, terminal behavior and fabricated quote rejection. Tests use mocks and are not live-network consensus. On Windows, genlayer-test 0.29.2 needed a local patch to defer deleting its open temporary stdin file; each test ran in a separate Python process due to SDK global contract registration. See `TESTING.md`. No production security audit has been performed.

## Reproduce

Install Python 3.12+ and `genlayer-test==0.29.2` and `genvm-linter==0.11.0`. The tests pin GenVM v0.2.12; the first run downloads the official release. On Windows, use a Linux environment or address the test framework's open-file unlink issue. Execute each test in a separate pytest process, for example `pytest tests/test_contracts.py::test_source_quorum_agreement_and_dissent -q`; run each of the four names in the file. The cache location in `tests/conftest.py` is relative to the parent directory. Studio deployment and actual transactions must be verified separately.
