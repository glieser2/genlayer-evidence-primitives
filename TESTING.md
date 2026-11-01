# Verification record for v2

Date: 2026-11-01. This document describes the local v2 release candidate only. Public v1 addresses and transactions do **not** verify v2.

## Local verification

- SDK: official GenVM v0.2.12, genlayer-test 0.29.2, genvm-linter 0.11.0; Python 3.13.5 on Windows.
- `python scripts/run_tests.py`: 62 isolated SDK Direct Mode cases. See `evidence/local-tests.json` for exact counts, timestamps, source SHA-256 values and every subprocess output.
- `python scripts/check_contracts.py`: both contracts pass the linter and ABI validation; see `evidence/lint.txt`.
- Models and network responses are mocked in these tests. Each forged-leader test first verifies that an honest candidate is accepted, then requires rejection of a tampered candidate.
- The first-generation fabricated-citation vulnerability is covered for both contracts. Coverage also includes malformed candidate schemas, altered hashes/paths/publishers, quote offsets, stale revisions, private/forged/unpinned source URLs, duplicate publishers/content, unavailable-source quorum, changed documents, authority boundaries, retry, finalization, foreign/fork CI runs, wrong commits/workflows/events, incomplete or failed jobs, skipped test steps, weakened pinned tests and independent validator dissent.
- Constructor rejection tests check both the expected message and exact SDK UserError type, preventing dependency/setup exceptions from counting as a pass.
- The installed test framework has been restored to its original cleanup logic. The repository's in-memory Windows shim is used for reproduction; no manual dependency edit is required. Linux requires no shim.

## Pending external verification

Browser access has been restored and this v2 release is being published. GitHub Actions and fresh Studio deployments are the next gates; no v2 live success is claimed until actual receipts are recorded below. Portal submissions remain paused.

After browser access is restored:

1. Publish the exact release contents to `glieser2/genlayer-evidence-primitives`, replacing obsolete v1 tests and documenting that v1 deployments are superseded.
2. Wait for the `verify` job to finish successfully. Save its exact commit, run ID, run attempt, job ID and logs. If anything fails, fix and rerun; do not pin a failing run.
3. Build `policy_json` from the exact files at the successfully tested commit, including `scripts/check_contracts.py`. Local policy hashes are prepared in `evidence/deployment-inputs.json`.
4. Deploy SourceQuorum with the fixed source manifest, evaluate, inspect the complete quote/hash report, exercise re-evaluation and a stale-finalize rejection, then finalize the current review. Verify execution SUCCESS and FINALIZED consensus in the Studio explorer.
5. Deploy RubricMilestone with distinct client/worker accounts, actual repository, criteria and pinned policy. Submit the successful commit/run as the worker; evaluate as the client; inspect CI identity, artifact hashes and quotes. Exercise unauthorized and stale-review failures, then finalize the current review. Verify explorer receipts.
6. Record new addresses, transactions, inputs and final states in this file and the Chinese audit document. Reassess submission readiness. CAPTCHA and final Portal submission remain with the user.

## Superseded v1 evidence

The earlier SourceQuorum `0x2F24d145B61E234114daDb74ae77553b25413795` and RubricMilestone `0x44306Fc44C913DF45C577EA615B874e817b7C0Ae` demonstrated basic Studio execution. They have the audit defects fixed in the local v2 code. Do not use their finalized transactions as evidence for the new implementation.
