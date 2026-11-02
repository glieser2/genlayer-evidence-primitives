# v3 / v3.1 / Rubric v3.2 security review

## Independent-review repairs (2026-11-02)

M-01: SourceQuorum now classifies missing/rejected HTTP responses, hash mismatch, invalid size and invalid UTF-8 separately from transient network/403/408/429/5xx failures. If even recovered transient sources cannot provide a distinct-content quorum, EVIDENCE_INVALID is a reviewable and finalizable evidence-set failure. It is not a contradiction of the claim. Valid remaining quorum may still decide the claim, while every unavailable source remains visible. A partial transient outage that could restore quorum remains retryable. The new result failure_policy is source-failure-v2; the old v3.1 deployment does not verify this implementation.

M-02: Rubric authorization in SUBMITTED binds client identity and revision; expected_digest is empty because no report exists. NEEDS_EVIDENCE/REVIEW additionally bind the nonempty report digest. The contract behavior is unchanged; no stronger empty-stage digest guarantee is claimed.

L-01/L-04: historical code and later document commits are separate provenance. Mixed delivery bundles must declare their code, documentation and evidence sources and per-file hashes, rather than claiming to be a pure fixed-commit export.

L-02: the check script invokes genvm-linter check with its built-in Validation; it is not a separate ABI checker. Historical "ABI validation" labels describe this same invocation, not another tool.

L-03: single-anchor repetition deliberately yields ambiguous shortest windows. Clients must preflight the committed phrases, order, nonoverlap, occurrence counts and 10..500-character bound. The ambiguity rule is retained, not relaxed.

## Repairs and adversarial evidence

| Reproduced v2 defect | v3 control | Regression |
| --- | --- | --- |
| Unpinned subprocess/import/config hijack can fabricate CI output | Python -I; explicit isolated pytest configuration/plugin; pinned full executable policy; complete Git tree gate | test_real_python_import_and_pytest_isolation; test_repository_tree_gate |
| Worker overwrites rejected review or exhausts revisions unilaterally | Client authorizes every revision; locked REVIEW; client cancellation at limits; retained history | test_client_controls_revisions_and_terminal_exit |
| Validator rejects matching semantics due to redundant generated quote | Exact label-only schema for validator | test_citation_isolation[label_only-*] |
| Full body rescues an insufficient leader quote | Citation-only first stage; independent context veto second stage | test_citation_isolation |
| Service outages consume all attempts; permanent failure cannot finish | Independently agreed structured gate failures; transient no-consumption; rejected finalization; cancellation | test_rubric_http_failure_recovery; test_source_outage_does_not_exhaust_and_cancel |
| Semicolon and empty delimiters accepted; committed duplicates make quorum impossible | Reject raw ;?#; require enough distinct hashes | test_source_url_policy; test_source_duplicate_content |
| Full-document leader decision and stricter single-quote validator can leave no acceptable candidate when evidence is spread over more than 500 characters | Shared leader/UNCLEAR evidence rule; every subcondition must fit one actual 10..500-character quote; otherwise UNCLEAR | test_single_quote_evidence_protocol (short and separated evidence, both contracts) |
| Invalid UTF-8 criterion artifact raises outside the permanent-failure gate | Decode criteria bytes inside the shared gate; independently agreed REJECTED/INVALID_UTF8 can finalize | test_rubric_invalid_utf8_is_reviewable |
| Live v3.1 Rubric approved a quote omitting the required adversarial-test purpose despite strengthened sufficiency prompts | Every criterion commits ordered exact phrases; a deterministic unique shortest window supplies the quote; validators reject noncanonical quotes before any model call | test_anchored_quote_rejects_noncanonical (including models that always return MET); test_anchored_quote_boundaries |

Original fabricated quotes, bad offsets, forged hashes/identities, stale reports and CI substitutions remain covered by positive controls followed by tampered-candidate rejection.

## Trust and limitations

Untrusted inputs include worker submissions, leader proposals, document prose and model output. Trusted assumptions include GenLayer execution/consensus and retrieval infrastructure, public GitHub metadata/TLS, the maintained publisher registry and the client-reviewed pinned policy. The client intentionally governs final acceptance. Full executable pinning prevents unnoticed additions/changes; it does not prove that originally reviewed code is benign. Direct Mode executes code and is not a hostile-code sandbox.

The policy is deliberately narrow: complete trees are limited to 200 entries and 300 KB, files to 64 KB, and criteria to four. Only exact inert documentation paths may vary outside pins. GitHub run/job checks accept push or manual execution; full commit/attempt binding and policy hashes must agree. A finite suite does not prove arbitrary functionality, and hosted CI/transitive package supply chains remain external dependencies.

Two-stage citation prompts prevent full-source leakage into the sufficiency stage. They do not mathematically prove semantic sufficiency, factual truth, or resistance to every prompt injection. Label-only verifier schema intentionally rejects extra model fields. Real models can still disagree or emit invalid output, causing an evaluation to fail without approval. These contracts hold no funds and are unsuitable for unattended high-stakes decisions.

The v3.1 live Rubric revision 2 is a concrete P2 evidence-integrity counterexample to relying on semantic prompts to enforce every required citation condition: its APPROVED report quotes only two commands, not their adversarial-test purpose. The underlying README does contain the necessary information; this finding concerns the accepted citation, not a claim that the delivery failed the criterion. The instance was left in REVIEW. The preserved record is evidence/rubric-v31-rev2-live-report.json. v3.2 replaces free quotation entirely for Rubric; missing required_quote_terms is a constructor error. Its deterministic guarantee is exact inclusion of the client's precommitted phrases in one canonical ordered window. Terms are not a semantic proof, and poor anchor choices or model errors remain possible. The client must review full phrases before deployment; model checks still evaluate the citation and full-context qualifications independently. At the v3.2 release SourceQuorum v3.1 was kept byte-identical. The current source-failure-v2 candidate is a subsequent change; its verification must be recorded separately.

Anchor selection accepts only a unique shortest ordered, nonoverlapping window of 10..500 characters. More than 32 occurrences of any of the at most eight phrases, a missing phrase, an impossible order, overlap, or a tied shortest window yields UNCLEAR deterministically. During targeted testing, an unordered prototype could select a cross-paragraph reversed window; the ordered algorithm fixes that case, and the initial test log is retained. Existing Rubric candidate-tampering, CI, retry and lifecycle tests now all use mandatory anchors. Boundary tests and universally affirmative model mocks demonstrate that omitted or alternate quotes are rejected without consulting an LLM. They do not establish universal semantic accuracy or live consensus success.

The v3.1 changes address two bounded reliability findings; no new authorization or CI-integrity bypass was identified in this review. Its quote-protocol regression uses a deterministic semantic oracle that computes whether both facts fit within the quote bound, and exercises the actual leader/validator prompts and SDK transitions. It does not prove that live models will follow that protocol. An old v3 live rubric attempt ended with ConsensusUndetermined and model schema/quotation errors; a successful leader candidate also quoted only the revision/digest condition for a criterion requiring owner authorization. That evidence supports requiring complete subconditions, but does not establish that the synthetic separated-evidence case caused the live failure. Existing v3 live evidence remains historical for the new source hashes.

SourceQuorum's registry expresses publisher diversity, not independently audited editorial control. Only identical bytes are deduplicated. Owners must inspect missing coverage and choose useful claims. Permanent rubric failures produce a report which the client can finalize as rejected or explicitly supersede. Transient failures revert without counters changing; operational details remain in transaction records rather than on-chain history.
