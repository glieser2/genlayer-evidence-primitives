# Verification record for v2

Date: 2026-11-01. This document describes the local v2 release candidate only. Public v1 addresses and transactions do **not** verify v2.

## Local verification

- SDK: official GenVM v0.2.12, genlayer-test 0.29.2, genvm-linter 0.11.0; Python 3.13.5 on Windows.
- `python scripts/run_tests.py`: 64 isolated SDK Direct Mode cases. See `evidence/local-tests.json` for exact counts, timestamps, source SHA-256 values and every subprocess output.
- `python scripts/check_contracts.py`: both contracts pass the linter and ABI validation; see `evidence/lint.txt`.
- Models and network responses are mocked in these tests. Each forged-leader test first verifies that an honest candidate is accepted, then requires rejection of a tampered candidate.
- The first-generation fabricated-citation vulnerability is covered for both contracts. Coverage also includes malformed candidate schemas, altered hashes/paths/publishers, quote offsets, stale revisions, private/forged/unpinned source URLs, duplicate publishers/content, unavailable-source quorum, changed documents, authority boundaries, retry, finalization, foreign/fork CI runs, wrong commits/workflows/events, incomplete or failed jobs, skipped test steps, weakened pinned tests and independent validator dissent.
- Constructor rejection tests check both the expected message and exact SDK UserError type, preventing dependency/setup exceptions from counting as a pass.
- The installed test framework has been restored to its original cleanup logic. The repository's in-memory Windows shim is used for reproduction; no manual dependency edit is required. Linux requires no shim.

## Live verification

The tested release is commit `40a48e11c9cb8d13da762cc122bef291bd86a6c0`. GitHub Actions run `41313296729` succeeded. Both final Studio contracts reached application status FINALIZED, with SourceQuorum decision SUPPORTED and RubricMilestone decision APPROVED. See `LIVE_VERIFICATION.md` for exact addresses, transaction links, failure records and limitations. Both contracts explicitly request SDK JSON response mode after a real-network JSONDecodeError exposed the text-output assumption. Portal submissions remain paused.

## Superseded v1 evidence

The earlier SourceQuorum `0x2F24d145B61E234114daDb74ae77553b25413795` and RubricMilestone `0x44306Fc44C913DF45C577EA615B874e817b7C0Ae` demonstrated basic Studio execution. They have the audit defects fixed in the local v2 code. Do not use their finalized transactions as evidence for the new implementation.
