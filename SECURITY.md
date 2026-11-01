# v3 security review

## Repairs and adversarial evidence

| Reproduced v2 defect | v3 control | Regression |
| --- | --- | --- |
| Unpinned subprocess/import/config hijack can fabricate CI output | Python -I; explicit isolated pytest configuration/plugin; pinned full executable policy; complete Git tree gate | test_real_python_import_and_pytest_isolation; test_repository_tree_gate |
| Worker overwrites rejected review or exhausts revisions unilaterally | Client authorizes every revision; locked REVIEW; client cancellation at limits; retained history | test_client_controls_revisions_and_terminal_exit |
| Validator rejects matching semantics due to redundant generated quote | Exact label-only schema for validator | test_citation_isolation[label_only-*] |
| Full body rescues an insufficient leader quote | Citation-only first stage; independent context veto second stage | test_citation_isolation |
| Service outages consume all attempts; permanent failure cannot finish | Independently agreed structured gate failures; transient no-consumption; rejected finalization; cancellation | test_rubric_http_failure_recovery; test_source_outage_does_not_exhaust_and_cancel |
| Semicolon and empty delimiters accepted; committed duplicates make quorum impossible | Reject raw ;?#; require enough distinct hashes | test_source_url_policy; test_source_duplicate_content |

Original fabricated quotes, bad offsets, forged hashes/identities, stale reports and CI substitutions remain covered by positive controls followed by tampered-candidate rejection.

## Trust and limitations

Untrusted inputs include worker submissions, leader proposals, document prose and model output. Trusted assumptions include GenLayer execution/consensus and retrieval infrastructure, public GitHub metadata/TLS, the maintained publisher registry and the client-reviewed pinned policy. The client intentionally governs final acceptance. Full executable pinning prevents unnoticed additions/changes; it does not prove that originally reviewed code is benign. Direct Mode executes code and is not a hostile-code sandbox.

The policy is deliberately narrow: complete trees are limited to 200 entries and 300 KB, files to 64 KB, and criteria to four. Only exact inert documentation paths may vary outside pins. GitHub run/job checks accept push or manual execution; full commit/attempt binding and policy hashes must agree. A finite suite does not prove arbitrary functionality, and hosted CI/transitive package supply chains remain external dependencies.

Two-stage citation prompts prevent full-source leakage into the sufficiency stage. They do not mathematically prove semantic sufficiency, factual truth, or resistance to every prompt injection. Label-only verifier schema intentionally rejects extra model fields. Real models can still disagree or emit invalid output, causing an evaluation to fail without approval. These contracts hold no funds and are unsuitable for unattended high-stakes decisions.

SourceQuorum's registry expresses publisher diversity, not independently audited editorial control. Only identical bytes are deduplicated. Owners must inspect missing coverage and choose useful claims. Permanent rubric failures produce a report which the client can finalize as rejected or explicitly supersede. Transient failures revert without counters changing; operational details remain in transaction records rather than on-chain history.
