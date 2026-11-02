# GenLayer evidence primitives: SourceQuorum failure-policy v2 / RubricMilestone v3.2

Review repair candidate: the SourceQuorum failure policy below changes code. Earlier finalized instances and CI runs verify their historical source hashes, not this candidate. New verification results belong in TESTING.md; Portal submissions remain paused.

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

Install the test dependencies with `python -I -m pip install -r requirements-test.txt`, then run the adversarial test suite with `python -I -X utf8 scripts/run_tests.py`.

The runner uses the official SDK in Direct Mode, separate processes for each collected case, explicit pytest configuration and plugin, disabled automatic plugins, isolated Python imports, and a conftest boundary at tests/. It writes every subprocess output, exit code and source hash to evidence/local-tests.json. HTTP and LLM responses are mocked; Direct Mode is not a live consensus proof. The official SDK is pinned to GenVM v0.2.12; initial setup downloads its archive. Set GENLAYER_TEST_CACHE to select a cache. The in-memory Windows cleanup shim only handles deletion of an open temporary stdin file.

GitHub Actions runs the same tests and GenVM checks on Linux. The verify job requires a successful Adversarial tests step. Actions use full commit pins, repository permission is read-only, and records are retained as an artifact for 90 days. Direct Python dependencies are version-pinned; transitive packages and hosted runners remain supply-chain assumptions.

## SourceQuorum

Constructor: claim, sources_json, quorum. Each source contains an immutable raw GitHub URL and SHA-256 of its exact UTF-8 bytes. Registry v1 maps python/cpython, microsoft/vscode-python, rust-lang/rust and nodejs/node to curated publisher groups. Only one source per publisher is permitted, and enough distinct committed content hashes must exist to meet the quorum. URLs reject credentials, ports, alternate hosts, mutable refs, traversal, semicolons, queries and fragments, including empty delimiters.

Validators independently fetch and hash every source and check candidate schemas, exact quote substrings and offsets. Citation validation has two label-only stages: first only the citation is supplied, requiring sufficient evidence for the whole claim; then full context can veto the result. The validator never needs to invent another quote. Leader and UNCLEAR validator share the same evidence rule: a decisive result needs one contiguous exact 10..500-character quote that independently establishes every subcondition. Code evidence must contain the actual checks. When supporting facts cannot fit in one qualifying quote, the result is UNCLEAR even if the full document supports the statement. This restricts information flow; it cannot guarantee perfect LLM interpretation or prompt-injection resistance.

A quorum of distinct supporting documents with no opposing available source yields SUPPORTED; the inverse yields CONTRADICTED. HTTP 403/408/429/5xx and network failures are transient. HTTP 404/410, other non-success HTTP responses, hash mismatch, invalid size and invalid UTF-8 are explicitly classified as invalid committed evidence. If the number of distinct hashes that remain valid or transiently unavailable is below the quorum, the report is EVIDENCE_INVALID and enters REVIEW. This concerns the configured evidence, not whether the claim is false. The owner can finalize that report using its current revision/digest, re-evaluate before finalization, or cancel. An invalid third source does not defeat a quorum already supported by two valid distinct sources; missing coverage remains visible. If a recovered transient source could still restore quorum, the result remains INCONCLUSIVE / NEEDS_EVIDENCE. If every source fails transiently, evaluation reverts without consuming a revision. Other evaluations retain their report and digest in history, up to 16 revisions. Cancellation remains available at the limit. FINALIZED and CANCELLED are terminal; changed source commitments require a new instance. result().failure_policy identifies this behavior as source-failure-v2.

Publisher diversity is a declared policy, not proof of economic or editorial independence. Distinct documents can coordinate or copy with small edits. GitHub is a shared host; the SDK does not expose final redirect URLs. Content hashes bind accepted bytes, not universal source truth.

## RubricMilestone

Constructor: worker, repository, criteria_json, policy_json. Every criterion must contain text, path and required_quote_terms. The client commits an ordered list of 1..8 distinct, nonblank exact phrases of 3..200 characters each before any submission. Choose complete phrases that cover the necessary conditions, including actual checks and rejection paths for code. There is no unanchored fallback. Policy maps file paths to SHA-256 values. Required pins cover both contracts, the workflow, test suite, fixture, runner, linter script, requirements and pytest.ini. Every additional executable/configuration file must also be pinned. In this repository, pin tests/test_contracts.py as well. Review all pinned code before deployment: this is acceptance of a reviewed fixed implementation, not sandboxing arbitrary worker code.

Rubric quotes are selected deterministically, not generated by an LLM. The contract finds the unique shortest contiguous window containing every committed phrase in the committed order without overlap. A quote must contain 10..500 characters. Missing, reversed or overlapping anchors, tied shortest windows, overlong windows, and more than 32 occurrences of any phrase yield UNCLEAR without model calls. Repetition is allowed within that bound when the shortest ordered window is unique. Validators recompute both the exact quote and its offset and reject alternate or shortened quotes before consulting a model. This guarantees inclusion of the committed text, not its truth or semantic sufficiency. A label-only model first checks only the selected quote; a separate full-document assessment can veto it. Disagreement between these stages yields UNCLEAR.

The worker submits a full commit SHA and public Actions run ID. Validators check the complete non-truncated Git tree, reject unpinned files outside the exact inert-document allowlist, symlinks, executable modes and submodules; verify every pinned hash; check repository/head repository/commit/workflow/event/run attempt, successful verify job and successful Adversarial tests step. Criteria artifacts come from that same commit. Missing, oversized, malformed or mismatching evidence cannot authorize approval.

Permanent gate failures become independently verified REJECTED reviews with reason codes. Network errors, HTTP 403/408/429/5xx and pending CI are retryable without consuming evaluation attempts. A 404 is a reviewable rejection rather than an endless retry. Criteria artifacts are decoded inside the gate; invalid UTF-8 produces REJECTED/INVALID_UTF8 before model assessment. Valid evidence then receives deterministic anchor selection and two-stage semantic assessment. APPROVED requires every criterion MET; NOT_MET produces REJECTED; UNCLEAR produces NEEDS_EVIDENCE.

The worker can submit only in OPEN or REVISION_REQUESTED. SUBMITTED, NEEDS_EVIDENCE and REVIEW cannot be overwritten. Only the client can authorize a revision using the current revision and review digest (empty before a report exists), or cancel any nonterminal process with a reason. REVIEW is locked against re-evaluation; the client finalizes or explicitly requests revision. Both approvals and rejections finalize against the current revision/digest. History retains submissions, reviews, revision authorizations and cancellation. Limits are 16 submissions and 32 nontransient evaluations; cancellation remains available at either limit.

Revision authorization is stage-specific: in SUBMITTED there is no review report, so expected_digest must be the empty string; authorization is the client identity plus current revision only. In NEEDS_EVIDENCE or REVIEW, expected_digest must match the current report digest as well. No extra cryptographic report binding is claimed for the empty-report stage.

### Client anchor preflight

Before deploying, inspect the exact artifact bytes and confirm that all ordered phrases fit one unique, nonoverlapping 10..500-character window. A single phrase appearing twice produces tied shortest windows and therefore UNCLEAR; select a longer unique phrase or additional ordered context. Do not resolve ambiguity by accepting the first occurrence. Repeat this check when delivery documents change. Phrase inclusion does not establish truth: negated examples or comments containing the phrases still require semantic and context assessment.

### Verification and archive provenance

check_contracts.py invokes the official genvm-linter check command, including its built-in Validation output and method summary. It does not invoke an independent ABI-checking tool. Historical CI step names containing "ABI validation" must be interpreted in that limited sense; the repaired workflow uses the precise name.

Keep code and documentation revisions separate. Historical code commit 298d4f077b378a6886d399b301426979b0609bc0 was verified with 117 tests; final verification documents for those deployments are at a88b4f1a97db4c620a9d080ec515995689b64148. Documents inside the original code commit describe their then-current state and cannot certify later deployments. The previous delivery ZIP intentionally combined that code with later final documents and evidence; it was not a pure git-archive snapshot. New archives must list each file hash, code provenance and documentation provenance explicitly.

## Verification and limits

See SECURITY.md for the repair matrix, TESTING.md for local measurements, and LIVE_VERIFICATION.md for deployment evidence. Both contracts retain result.version=3; source hashes identify their implementations. Historical SourceQuorum v3.1 live records are preserved; they do not verify the new source-failure-v2 code. Rubric v3.1 revision 2 reached APPROVED/REVIEW with a quote containing only commands and omitting their required adversarial-test purpose; it was not finalized. That concrete omission motivated v3.2's mandatory deterministic anchors. Existing v3 and v3.1 Rubric records do not verify the new code. Old v2 results are historical only. Gemini supplied an AI review and substitute-harness findings; local follow-up reproduced selected defects using the real SDK and CPython. This is not an independent human audit. Passing finite tests and live examples cannot establish universal correctness or promise a contribution score. Portal submissions remain paused for user review.
