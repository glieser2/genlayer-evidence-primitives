# Live verification on 2026-11-01

Portal submissions remain paused. This release is an experimental review primitive with no escrow or asset transfers. Scores remain at reviewers' discretion.

## Tested release

- Commit: `40a48e11c9cb8d13da762cc122bef291bd86a6c0`.
- [Successful GitHub Actions run](https://github.com/glieser2/genlayer-evidence-primitives/actions/runs/41313296729), run attempt 1, job `124867998208`. Adversarial tests, GenVM lint/ABI validation and evidence preservation all succeeded. The same release passed 64/64 isolated SDK Direct Mode cases locally.
- A preceding live evaluation returned non-JSON model text and failed with JSONDecodeError. Both contracts now explicitly request `response_format='json'`. Two regression cases enforce the SDK configuration on both leader and validator paths. Failures were retained rather than described as successful execution.

## SourceQuorum

- [Final contract](https://explorer-studio.genlayer.com/address/0x15A2409FbF3069903e17483Cd815a076f6079AcA).
- Deployment: `0x9f7893c6a6fabf70d0de7e99b2814837e69cab257428beacc5cd9c572fb31e90`.
- Evaluation: `0xc44003ec871832ee34e930cf5460302b98b145937883270454a6f6db5e9e42c0`.
- Finalization: `0xc5e521b5b2a1a0b49b7d77e193f70c349195d1fbd242ab743b9a98814aff4ebd`.
- Claim: The Python project has a public website at https://www.python.org/.
- Sources: immutable CPython and Microsoft vscode-python README files, full commit URLs and precommitted content hashes. Both assessments SUPPORTS, with exact offsets and quotes. Current report: revision 1, decision SUPPORTED, contract status FINALIZED.
- Report digest: `f1417b80655e4be25437c5e1e9e2d4868cec7d3b690b8dea9738503419df07a7`.
- Earlier v2 evaluation of installation instructions at `0x2A019AF70176a9bFb083723e89504F58e2B74221` ended with consensus Undetermined: `0xffaeb2901a905da67ba1734072fe074bbe41ef2c4fdad223f28dcdff2151727c`. The explorer displayed weak candidate citations, but did not establish each validator's exact rejection reason. Semantic inadequacy is an interpretation, not a verified diagnosis. A later explicit website claim succeeded; do not hide the failed broader claim or claim universal semantic reliability.

## RubricMilestone

- [Final contract](https://explorer-studio.genlayer.com/address/0x029DA0711f9871755860fEf1F22323F6dC2241e4).
- Deployment: `0x703e0d626ed50a71cb58b0c441079b79e26dc5029625af2bb9d0d752cbd4dc91`.
- Worker submission: `0x83c7ea81f22059bf8fdb212056f83d9ad88293634824caa28741b526232b33ba`.
- [Evaluation](https://explorer-studio.genlayer.com/tx/0x7f312dab4a72b3a191d06f26f2e05f4adda76c3c060a6e1cd636a4d5c0e5d127): execution SUCCESS, consensus Accepted, transaction FINALIZED, Normal mode with five initial validators and zero leader rotations.
- Finalization: `0x259579252dc051abe28cfe8de376dee26e0955c355ab88ca614d205d85cd3a91`.
- Actual submission binds the tested commit and run above. The report independently records CI run/attempt/job identity, six pinned policy files and the hashes of README and source artifact. Both criteria MET; decision APPROVED; revision 1; attempt 1; contract status FINALIZED.
- Report digest: `1b43a2913dd177c49b4e7ac015b0c4423233b53a7ca3b816934af62126cc7461`.
- Failed pre-JSON-mode evaluation: `0x69b0dc6b15cd13a1f9de94e0db987ae52fe979b221590334387bd3b1a5113f2a`. Explorer showed Contract Error with JSONDecodeError and consensus Undetermined, despite eventual transaction FINALIZED. The submission remained SUBMITTED. Finalized transaction status alone is not successful execution.

## Interpretation

The implementation now has public code, repeatable adversarial cases, a successful Linux CI record and real Studio evidence for both primitives. This improves reviewability; it does not establish production readiness or guarantee a high contribution score. The publisher registry is a curated policy, exact-copy checks do not detect paraphrased mirrors, GitHub is a common external dependency, and semantic model judgments can disagree. The owner/client's explicit confirmation is part of the design. Review SECURITY.md before reuse.
