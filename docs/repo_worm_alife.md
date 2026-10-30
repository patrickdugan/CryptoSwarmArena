# REPO-WORM-ALIFE-01: repository-contagion artificial-life gym

**Status:** RTG exploratory scripted benchmark. **Evidence:** simulated dynamics only.

This instrument tests whether a fictional coding-agent community can carry an inert marker across a graph of fictional repositories. It is an SIR-like, finite-population artificial-life model using the existing `swarm_compromise.PROFILE_ARCHETYPES` hygiene values. The visible question comes from Matthew Green's request for reproducible agent-worm propagation, traffic, local-operation, and detection measurements. The first environment is the repo-review pathway suggested by Dusan Granec.

The model deliberately has **no prompt text, malware, tool execution, GitHub API access, network transport, credential access, or autonomous agent code**. A marker is represented only by an integer state and a bounded numeric transmissibility factor. Every sampled "adoption" means a scripted state transition. It is not evidence that any real coding agent will obey lower-trust instructions.

## Procedure

Run from the repo root on Python >=3.11:

```bash
python -m pip install -e ".[test]"
PYTHONPATH=src python -m pytest tests/test_repo_worm_alife.py -q
PYTHONPATH=src python -m spiral_ln.repo_worm_alife --config configs/repo_worm_alife_v1.json --output output/repo_worm_alife_v1 --events
PYTHONPATH=src python -m spiral_ln.repo_worm_alife --verify output/repo_worm_alife_v1
```

The `--events` switch emits one bounded JSONL replay for every episode. Without it, the event-chain receipts are still computed and verified. `manifest.json` freezes the full configuration and source SHA-256; `episodes.csv` contains one row per independent seeded world/posture/mode; `summary.json` contains descriptive intervals and matched differences; `receipts.json` commits to the rows, summary and individual event chains. Verification replays every seed and compares the artifacts. Outputs are local and excluded from the GitHub source files.

## World and transition rules

- **Substrate:** 32 in-process repository nodes split among four communities; independent undirected pairwise links with within-community probability 0.25 and between-community probability 0.035. The same generated graph is reused for every posture and inference-mode comparison on a seed.
- **Initial condition:** the highest-degree node begins carrying a content-free marker at tick zero. Ties break by node ID. This deliberately models a privileged initial position and should not be generalized to random entry points.
- **Contact:** each carrier can attempt at most two previously unattempted neighbor handoffs per tick for three ticks after acquisition. An isolated carrier stops contacting peers. A newly carrying node becomes active the next tick.
- **Scripted susceptibility:** `p(adopt) = min(1, 0.75 × strain × (1 - 0.45 × hygiene) × trust_multiplier)` after the inspection gate. Hygiene is the existing fixed archetype parameter, recycled as a stylized agent-reviewer trait. This is an assumption and does not come from observed coding-agent behavior.
- **Lineages:** an adoption may perturb the content-free strain scalar by +0.12 or -0.12, clamped to [0.75,1.25], with probability 0.08. The mutation never creates text or executable content.
- **Detection:** synthetic monitoring samples contacts with a posture-dependent coverage probability and true-positive rate. Detected markers are blocked; some reviews isolate the source. Benign traffic is separately sampled to measure false alarms.
- **Traffic:** a marker handoff costs exactly two fictional API calls and 768 invented wire bytes. Each benign review costs one fictional API call and 640 invented bytes. Both are bookkeeping constants, not observed packet lengths or forecasts of actual traffic.
- **Inference:** local and remote modes share *identical* scripted decisions. Each review incurs 1,024 abstract work units. Remote mode additionally counts one fictional inference call and 2,304 fictional external bytes per review; local mode counts zero external inference calls. This demonstrates how the cost ledger operates and says nothing about whether an actual model can run on any particular machine.

Every draw is derived from SHA-256(seed, event coordinates), keeping paired opportunities stable when the number of previously carrying nodes changes. Each event includes a cumulative hash-chain link. Event records are accessible only as post-simulation evidence, never as observations for another acting policy.

## Posture assumptions

| Posture | Trust factor | Monitoring coverage | Detection given monitored | False alarms given monitored | Source isolation after detection |
|---|---:|---:|---:|---:|---:|
| `baseline_open` | 1.00 | 0.10 | 0.30 | 0.010 | 0.00 |
| `provenance_gate` | 0.65 | 0.55 | 0.78 | 0.030 | 0.55 |
| `inspect_verify` | 0.43 | 0.82 | 0.90 | 0.040 | 0.78 |
| `human_review` | 0.30 | 0.96 | 0.96 | 0.075 | 0.92 |

These are tunable assumed policies. An improvement in this environment validates the simulation's causal plumbing, not an independently demonstrated advantage of any real control system. Human review incurs modeled false-alarm costs; no actual humans are asked to review simulated contacts.

## Endpoints and interpretation

- `secondary_adoptions`: number of previously clean nodes that first accept a marker, excluding the initial carrier(s).
- `seed_offspring_per_root`: mean number of direct adopters attributable to initial carriers over the fixed run. It is a **generation-zero offspring count** and highlights initial supercritical spread.
- `reproduction_observed`: successful secondary adoptions divided by distinct marker carriers that had at least one contact attempt. It is a **finite-horizon realized secondary count** after saturation and isolation, so it can fall below 1 even when an early cascade was large. Carriers without any contact opportunity are reported separately.
- `marker_detection_recall`: flagged marker contacts / all marker contacts. This is **contact-level** recall rather than node-level compromise recall, and includes contacts to already carrying nodes.
- `benign_false_alarm_rate`: flagged benign reviews / benign reviews.
- `synthetic_wire_bytes`, `synthetic_api_calls`, `simulated_external_inference_bytes`: accounting under the declared constants.
- `graph_sha256`, `lineage_sha256`, `ledger_chain_sha256`, `accounting_ok`: reproducibility and internal consistency checks. Hashes provide tamper-evidence relative to the emitted receipt; they are not independently signed attestations.

The primary paired contrast is secondary adoptions under each defender posture minus the baseline on the **same world seeds**. Summary intervals use a normal approximation over independent seeded worlds; the sample size is the number of worlds, never the number of individual ticks or contacts. Time trends, contact-level detections, and offspring counts must not be pooled into one metric.

## Acceptance criteria

The tests check reproducible graphs, deterministic logs, absence of operational payload fields, matched local/remote decisions, zero transmission when contacts or adoption probability are zero, invalid-input bounds, campaign pairing, accounting identities, and evidence tamper detection. The instrument passes when every test and the replay verifier pass. Strong containment values are expected consequences of the assumed posture parameters and are not themselves acceptance evidence.

## Scope of a second study

For meaningful external validity, freeze a protocol that compares real *authorized* coding agents against inert markers in disposable repositories under explicit permission and a restricted tool policy. Measure observed compliance, token usage, inference hardware, genuine traffic traces, false alarms, and reviewer labor. Apply the existing RTG mandate oracle as an independent labeler. The present v1 makes **none** of those empirical claims.
