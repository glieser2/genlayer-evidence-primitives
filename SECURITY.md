# Security review and residual assumptions

## Repair matrix

| v1 issue | v2 control | Reproduction |
| --- | --- | --- |
| Leader can store fabricated citation | Exact schema, source/artifact hash, quote range and independent citation assessment | `test_source_candidate_attack`, `test_rubric_candidate_attack` |
| Anyone can permanently finish a claim | Owner-only evaluate/finalize | `test_source_retry_and_stale_finalization` |
| Inconclusive result cannot retry | NEEDS_EVIDENCE -> new review; no automatic finalization | Both lifecycle tests |
| Old review can authorize changed work | Revision plus canonical report digest required | Both lifecycle tests |
| Arbitrary hosts and misleading independence | Fixed publisher registry + immutable commit URLs + exact-copy de-duplication | URL, duplicate publisher/content tests |
| Single dead source blocks all progress | Unavailable evidence recorded; remaining distinct-source quorum possible | `test_source_availability_quorum` |
| Worker self-report treated as delivery | Actual GitHub run and job records + pinned commit and acceptance-policy hashes | `test_rubric_ci_gate` |
| Fake/weak success assertions | Positive control plus forged-candidate rejection; exact UserError identity/message on failed construction | Entire suite |

## Trust boundaries

Untrusted: worker input, leader proposal, retrieved prose, LLM output. Trusted within this experiment: GenLayer execution/consensus, SDK serialization, HTTPS retrieval infrastructure, GitHub service metadata, the client-reviewed acceptance policy and curated publisher registry. Owner/client authorization is intentional governance, not decentralization of final acceptance.

Schema checks cannot establish source truth. An exact quote can be misleading; independent model assessment reduces but does not eliminate interpretation errors. Same-body hashing rejects byte-identical mirrors only. Publisher groups are a maintained policy, not automatically discovered ownership. Public repository ownership can change. Both contracts remain unsuitable for unattended high-stakes or financial decisions.

GitHub CI gates prove the selected run succeeded according to GitHub and the fixed tested policy. They do not prove arbitrary requirements not encoded in tests/criteria. Hosted runner state and transitive dependencies can change. A malicious contract implementation could target known tests; the fixed tests are evidence, not a full formal verification.

Failed web calls, hash mismatches, malformed output or validator disagreement fail closed with respect to acceptance. SourceQuorum may still reach a declared quorum with unavailable sources; reviewers must examine coverage. Rubric CI gate failures revert and allow retry. Before finalization the authorized actor can re-evaluate; after finalization a correction needs a new deployment. No funds are locked, refunded, minted or transferred.

## Reproducibility boundaries

Direct Mode uses the genuine SDK storage and serialization layer, mocked web/model responses and explicit validator callbacks. It bypasses WASM execution and is not a consensus test. Real Studio deployments and explorer receipts are a separate required check. The runner uses isolated subprocesses because this SDK version keeps contract registration globally. The Windows workaround changes only cleanup of a temporary stdin file.
