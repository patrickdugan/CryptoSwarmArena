# REPO-WORM-ALIFE-01: exploratory first-run evidence

**Date:** 2026-10-30. **Status:** scripted synthetic pilot; no live coding agents were tested.

Frozen config: `configs/repo_worm_alife_v1.json`. Sixteen independent seeded worlds (0–15) × four postures × two hypothetical inference-accounting modes = **128 episodes**. Each world contains 32 synthetic repositories and runs for 24 ticks. Local and remote modes share identical scripted decisions by design.

## Observed synthetic results

| Posture | Mean direct offspring per seed | Mean secondary adoptions per world | Mean realized reproduction per active source | Mean marker-contact detection | Mean benign false alarms |
|---|---:|---:|---:|---:|---:|
| baseline_open | 3.000 | 11.938 | 0.889 | 1.86% | 0.21% |
| provenance_gate | 0.625 | 1.063 | 0.251 | 66.93% | 1.93% |
| inspect_verify | 0.063 | 0.063 | 0.031 | 94.69% | 3.18% |
| human_review | 0.000 | 0.000 | 0.000 | 100% | 7.19% |

These values arise entirely from the modeled inspection and adoption parameters. A 100% detection fraction in a small finite sample does not establish perfect detection in any operational environment. Posture assumptions drive the effect sizes, and the 16-world sample is exploratory.

The baseline's mean of 3 direct offspring per seed indicates supercritical *initial* spread within the scripted world. Its lower realized reproduction rate of 0.889 is calculated after later-source saturation, when a large fraction of possible recipients already carry the marker. This distinction is important for interpreting propagation curves.

The baseline consumed an average of **108,480 hypothetical wire bytes** per world, versus 80,976 under the provenance gate and 77,664 under human review, with benign traffic included. These are deterministic accounting constants multiplied by synthetic events. In local mode the hypothetical external inference traffic is zero; remote mode adds 2,304 invented bytes per review and leaves the decisions unchanged. Neither result measures real hardware feasibility or stealth.

## Validation

Nine new `pytest` cases passed in the isolated development copy, which used a local stand-in for the existing repository's four reviewer-profile hygiene values. The campaign generated 128 episodes and its replay verifier reported `VERIFIED`. Full repository CI must independently confirm the integration when the branch is pushed.

- Source SHA-256: `cc81c23d9f0112c1743ae92dbcdbcb033f5820f28d68f3fde76d20712af0d49c`
- Config SHA-256: `22b5de63198eabcf94331694fea03cdcadf4ee7153d9842dec2e0529b4fb1a6e`
- Episode rows SHA-256: `be3e03e7c5ffe45fefa9a7e516b0b2d2a22fd5f928fc66c7a168089fca085295`

The complete event-level traces are generated on demand with `--events`. The repository retains the frozen source/config plus these receipt values to reproduce them, rather than committing bulk generated data.
