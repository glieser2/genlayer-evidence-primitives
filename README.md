# GenLayer evidence primitives v3

Two experimental Intelligent Contracts for evidence review. SourceQuorum aggregates a curated set of publisher-distinct sources. RubricMilestone records client-controlled acceptance of a fixed software delivery and its public CI evidence. Neither contract transfers assets. v1 and v2 are superseded: finalized old transactions do not remove their subsequently reproduced defects.

## Reproduce in a clean checkout

Install Python 3.13 and run from the repository root:

```sh
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -I -m pip install -r requirements-test.txt
python -I -X utf8 scripts/run_tests.py
python -I -X utf8 scripts/check_contracts.py
```

The runner uses the official SDK in Direct Mode, separate processes for each collected case, explicit pytest configuration and plugin, disabled automatic plugins, isolated Python imports, and a conftest boundary at tests/. It writes every subprocess output, exit code and source hash to evidence/local-tests.json. HTTP and LLM responses are mocked; Direct Mode is not a live consensus proof. The official SDK is pinned to GenVM v0.2.12; initial setup downloads its archive. Set GENLAYER_TEST_CACHE to select a cache. The in-memory Windows cleanup shim only handles deletion of an open temporary stdin file.

GitHub Actions runs the same tests and GenVM checks on Linux. The verify job requires a successful Adversarial tests step. Actions use full commit pins, repository permission is read-only, and records are retained as an artifact for 90 days. Direct Python dependencies are version-pinned; transitive packages and hosted runners remain supply-chain assumptions.

## SourceQuorum

Constructor: claim, sources_json, quorum. Each source contains an immutable raw GitHub URL and SHA-256 of its exact UTF-8 bytes. Registry v1 maps python/cpython, microsoft/vscode-python, rust-lang/rust and nodejs/node to curated publisher groups. Only one source per publisher is permitted, and enough distinct committed content hashes must exist to meet the quorum. URLs reject credentials, ports, alternate hosts, mutable refs, traversal, semicolons, queries and fragments, including empty delimiters.

Validators independently fetch and hash every source and check candidate schemas, exact quote substrings and offsets. Citation validation has two label-only stages: first only the citation is supplied, requiring sufficient evidence for the whole claim; then full context can veto the result. The validator never needs to invent another quote. UNCLEAR results receive an independent full-document assessment. This restricts information flow; it cannot guarantee perfect LLM interpretation or prompt-injection resistance.

A quorum of distinct supporting documents with no opposing available source yields SUPPORTED; the inverse yields CONTRADICTED; otherwise INCONCLUSIVE. Unavailable sources are visible in the report. If every source fails transiently, evaluation reverts after validating the failure and consumes no revision. Other evaluations retain their report and digest in history, up to 16 revisions. Only the owner can evaluate, finalize the exact current revision/digest, or cancel with the current revision and a reason. Cancellation remains available at the revision limit. FINALIZED and CANCELLED are terminal; modified source commitments require a new instance.

Publisher diversity is a declared policy, not proof of economic or editorial independence. Distinct documents can coordinate or copy with small edits. GitHub is a shared host; the SDK does not expose final redirect URLs. Content hashes bind accepted bytes, not universal source truth.

## RubricMilestone

Constructor: worker, repository, criteria_json, policy_json. Each criterion contains text and path. Policy maps file paths to SHA-256 values. Required pins cover both contracts, the workflow, test suite, fixture, runner, linter script, requirements and pytest.ini. Every additional executable/configuration file must also be pinned. In this repository, pin tests/test_contracts.py as well. Review all pinned code before deployment: this is acceptance of a reviewed fixed implementation, not sandboxing arbitrary worker code.

The worker submits a full commit SHA and public Actions run ID. Validators check the complete non-truncated Git tree, reject unpinned files outside the exact inert-document allowlist, symlinks, executable modes and submodules; verify every pinned hash; check repository/head repository/commit/workflow/event/run attempt, successful verify job and successful Adversarial tests step. Criteria artifacts come from that same commit. Missing, oversized, malformed or mismatching evidence cannot authorize approval.

Permanent gate failures become independently verified REJECTED reviews with reason codes. Network errors, HTTP 403/408/429/5xx and pending CI are retryable without consuming evaluation attempts. A 404 is a reviewable rejection rather than an endless retry. Valid evidence then receives exact-citation and two-stage semantic verification. APPROVED requires every criterion MET; NOT_MET produces REJECTED; UNCLEAR produces NEEDS_EVIDENCE.

The worker can submit only in OPEN or REVISION_REQUESTED. SUBMITTED, NEEDS_EVIDENCE and REVIEW cannot be overwritten. Only the client can authorize a revision using the current revision and review digest (empty before a report exists), or cancel any nonterminal process with a reason. REVIEW is locked against re-evaluation; the client finalizes or explicitly requests revision. Both approvals and rejections finalize against the current revision/digest. History retains submissions, reviews, revision authorizations and cancellation. Limits are 16 submissions and 32 nontransient evaluations; cancellation remains available at either limit.

## Verification and limits

See SECURITY.md for the repair matrix, TESTING.md for local measurements, and LIVE_VERIFICATION.md for new deployment evidence. Old v2 results are historical only. Gemini supplied an AI review and substitute-harness findings; local follow-up reproduced selected defects using the real SDK and CPython. This is not an independent human audit. Passing finite tests and live examples cannot establish universal correctness or promise a contribution score. Portal submissions remain paused for user review.
