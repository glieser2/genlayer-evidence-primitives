# v3.1 verification record

The official SDK Direct Mode local run passed 93/93 tests; both contracts passed GenVM lint and ABI validation. The tests mock HTTP and LLM responses, so they are not live consensus evidence. The earlier v3.1 initial local run had 91 passes and two fixture initialization failures; the fixtures were corrected before the final 93/93 run.

Public Linux CI passed 93/93 tests, lint and ABI checks on [commit 1e7a0a2763f0c46781d8094a6db7a859b886e181, run 41358111627, job 125002446893](https://github.com/glieser2/genlayer-evidence-primitives/actions/runs/41358111627/job/125002446893), attempt 1. The prior v3.1 code commit dda9c8ff7de76732a689c3fea5c7bdfde73e83d3 also passed 93/93 on run 41357020896. The later commit clarifies README commands; all ten policy-pinned blobs are unchanged. v3's 88-case run and v2 records are historical, not evidence of the new sources.

Live consensus observations and limitations are in LIVE_VERIFICATION.md. Passing finite tests does not establish universal correctness or resistance to all prompt injection.
