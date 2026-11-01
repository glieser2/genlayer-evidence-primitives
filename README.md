# GenLayer evidence primitives v2

Two standalone Intelligent Contracts with independently verified quotations, immutable evidence bindings and revision-aware review. Experimental review tools; no escrow or automatic payment. The previous v1 contracts are superseded by this security revision and should not be used as acceptance infrastructure.

## Reproduce in a clean checkout

Install Python 3.13, then run from the repository root:

```sh
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install -r requirements-test.txt
python scripts/run_tests.py
python scripts/check_contracts.py
```

The runner collects every case in `tests/test_security.py`, executes each in a fresh SDK process, writes the full results and source hashes to `evidence/local-tests.json`, and exits nonzero on any failure. Each test uses the real GenLayer SDK Direct Mode, with web and model responses mocked. This is not live consensus. The SDK archive is pinned to official GenVM v0.2.12. Initial setup needs network access and downloads the archive. Set `GENLAYER_TEST_CACHE` to choose its cache directory. A narrow in-memory Windows cleanup shim is in `tests/conftest.py`; it does not modify installed packages or contract behavior.

GitHub Actions runs the same tests on Linux, then lint/schema checks, with read-only repository permission. The job is named `verify`; its required test step is `Adversarial tests`. Actions themselves are pinned to full official commit SHAs. The complete logs are retained as a workflow artifact for 90 days. Direct dependency versions are pinned; transitive Python dependencies and hosted runners remain external supply-chain assumptions.

## SourceQuorum: publication-aware evidence review

Constructor: `claim`, `sources_json`, `quorum`. Each source is an object with `url` and the SHA-256 of its exact UTF-8 bytes. Version 2 deliberately supports a small curated registry of immutable raw GitHub documents: `python/cpython`, `microsoft/vscode-python`, `rust-lang/rust`, and `nodejs/node`. URLs must include a full 40-character commit SHA. The owner selects the documents and claim; the contract derives publisher groups from its fixed registry. One publisher can appear only once; byte-identical documents across publishers get only one vote. Credentials, custom ports, IP addresses, arbitrary hosts, branch names, traversal, queries and fragments are rejected.

Each validator fetches the document independently, checks its precommitted content hash, validates every result field, and checks each leader citation's exact offset and substring. The validator independently assesses the cited passage in full document context. A decision is then derived from verified labels: quorum support with no contrary source, quorum contradiction with no supporting source, or inconclusive. A failed source is explicitly recorded as unavailable. Sufficient remaining distinct documents can form a quorum; the report exposes missing coverage. Opposing available evidence vetoes a decisive verdict.

Only the owner can evaluate. Every evaluation creates an immutable history entry with revision and canonical report digest. Inconclusive results remain `NEEDS_EVIDENCE`; decisive results are only `REVIEW`. The owner may retry before finalization and must pass the exact current revision and digest to `finalize`. Finalized instances cannot be re-evaluated. A maximum of 16 revisions bounds storage growth; changed source commitments require a new instance.

This is **a curated publisher-diversity policy**, not proof of economic/editorial independence or factual truth. Different publishers may copy or coordinate; the duplicate check detects exact byte copies only. GitHub is a shared hosting dependency. The SDK web API does not expose final redirect URLs: content commitments protect accepted bytes, but this project does not claim transport redirect or DNS isolation. Future registry changes require a new policy version and deployment.

## RubricMilestone: commit-and-CI-bound delivery review

The client fixes the worker, GitHub repository, criteria and acceptance policy at deployment. Each criterion has `text` and `path`, binding the review to a specific file. `policy_json` maps paths to SHA-256 values and must include the workflow, adversarial tests, fixtures, runner and test requirements. Include `scripts/check_contracts.py` as well for the supplied workflow. The client must review this policy before pinning it.

The worker submits only a full commit SHA and numeric GitHub Actions run ID. Free-text claims such as "all tests passed" are not accepted as delivery evidence. The contract independently queries public GitHub API records and requires the configured repository and head repository, matching commit, approved workflow path, completed successful push/manual run, successful `verify` job and completed successful `Adversarial tests` step. It retrieves the jobs for that exact run attempt and rejects incomplete pagination. Every pinned policy file must have the agreed hash at the submitted commit, preventing silent test/workflow weakening.

Artifacts are fetched from that commit. Their hashes, CI run/attempt/job identity and exact quoted offsets are recorded in the report. Validators repeat the CI and policy checks, re-fetch artifacts, validate the full candidate schema, and independently assess each citation against its criterion. `APPROVED` is possible only when the CI gate passes and every criterion is MET. A failing fetch/CI/policy gate reverts the evaluation, leaving the submission retryable. A semantic UNCLEAR yields `NEEDS_EVIDENCE`. Both positive and negative decisive reviews require client finalization against the latest revision/digest. The worker can revise before finalization; old reviews cannot finalize new submissions. Submission and review history is preserved (16 revisions / 32 evaluations maximum).

This is a review record, not an escrow. It transfers no assets. GitHub API/TLS, the chosen repository and the client-reviewed fixed acceptance policy are trust assumptions. Passing finite tests does not prove arbitrary software correctness. A client who pins weak tests gets weak assurance. Rate limits and service failures reduce availability rather than authorize acceptance. LLM interpretation and prompt injection remain residual risks; mock-based adversarial tests prove structural enforcement and disagreement rejection, not universal resistance of real models.

## Evidence and scope

See `SECURITY.md` for the threat model and repair matrix, `TESTING.md` for measured results and deployment status, and `evidence/` for machine-readable logs. Do not equate a successful Studio transaction with correctness or production suitability. Studio transactions must show both successful execution and finalized consensus. Public portal submissions remain paused until live v2 verification is documented.
