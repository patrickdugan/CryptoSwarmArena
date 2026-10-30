# RTG Codex–Claude Worm Arena: scripted 64-bout baseline

**Run type:** `scripted_mock_only`. **Date:** 2026-10-31. **Independent worlds:** 16 seeds × two postures × two role assignments = 64 bouts, with six ticks and 12 total mock decisions each. **Real Codex / Claude model calls:** zero.

All 17 new tournament tests passed on Python 3.13 locally. The full campaign ran and its replay verifier returned `VERIFIED`.

| Red (HIVE) heuristic | Blue (SENTINEL) heuristic | Posture | Mean secondary adoptions | Mean blocked marker handoffs | Mean blocked benign changes |
|---|---|---|---:|---:|---:|
| Codex-named mock | Claude-named mock | baseline_open | 0.5000 | 3.1875 | 3.8750 |
| Claude-named mock | Codex-named mock | baseline_open | 0.0625 | 2.0625 | 4.0000 |
| Codex-named mock | Claude-named mock | inspect_verify | 0.0625 | 3.0000 | 4.0625 |
| Claude-named mock | Codex-named mock | inspect_verify | 0.0000 | 2.0625 | 4.3125 |

The names here designate two fixed **mock heuristics**, and these numbers are observations about the deterministic simulation under its declared rules. The settings use an initial high-degree carrier and favor a small number of available handoffs. They cannot support a Codex-versus-Claude model ranking.

The mock blue strategies quarantine high-risk sources at a substantial cost to benign throughput. This provides a visible control tradeoff and a useful reason to benchmark false positives alongside spread. The fortified posture lowers mean marker adoptions under either role assignment in these simulated worlds, while preserving the same seeded graphs.

SHA-256 of the complete `bouts.jsonl` row sequence (canonical JSON): `1800307dccea4b44cb1cea51a7ece16af97222bdd50acde4e00f7f33cbeeb4c0`.

Regenerate the full evidence files using:

```bash
PYTHONPATH=src python -m spiral_ln.rtg_worm_tournament --max-calls 768 --output output/rtg_worm_mock_64
PYTHONPATH=src python -m spiral_ln.rtg_worm_tournament --verify output/rtg_worm_mock_64
```

A distinct **live inference run**, tied to pinned Codex and Claude model IDs, is required before comparing model choices. Its token/latency figures must come from the actual CLIs and be interpreted jointly with the defensive losses and invalid-action counts.
