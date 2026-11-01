# v3 verification record

Date: 2026-11-02 (Asia/Shanghai). See evidence/local-tests.json for exact measured count, timestamps, outputs and source hashes. The official GenVM v0.2.12 SDK, genlayer-test 0.29.2, genvm-linter 0.11.0 and Python 3.13 are used. Each test runs in a fresh SDK process. Web and LLM are mocked; validator callbacks are explicitly exercised. A separate real CPython subprocess test verifies that malicious sibling imports, root conftest and environment/config injection cannot convert an actual failing test into success.

Run the exact README commands. Both contracts must pass GenVM lint and ABI checks. Clean Linux GitHub Actions and real Studio consensus are separate verification gates, recorded in LIVE_VERIFICATION.md when completed. v2's 64-case CI run and old deployments do not verify v3.

Gemini's earlier review used a substitute harness because its environment could not run the official SDK. Selected findings were subsequently reproduced locally against v2 using the SDK and a real Python import attack. Those original defect probes remain historical evidence, not v3 success criteria. The new tests assert corrected behavior.
