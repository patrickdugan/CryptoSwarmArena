# Mulder & Scully: sealed forensic blue-team benchmark

This is the **external network-forensics** blue-team track in CryptoSwarm Arena. Blue Beam remains a *local endpoint defender*. Its alerts can appear as leads here, but do not prove who controls a node.

## Implemented v0.2

- `spiral_ln.forensic_blue`: two-pass, deterministic Mulder hypothesis generation and Scully corroboration review. Claims carry a named relationship and event tick; the reviewer rejects time splicing, copied-origin corroboration and weak kinds. A digest pins the admitted evidence snapshot to an expected hash supplied by the caller.
- `spiral_ln.forensic_casebook`: an evidence broker that enforces source grants, revoked sources, node scope, a collection-time cutoff and a fixed query budget. It keeps investigator inputs distinct from referee-only truth labels at the API level.
- `spiral_ln.forensic_benchmark`: command-line evaluator over 18 hand-authored synthetic cases. Each case has a predetermined supported-claim contract. Reports contain per-case results and micro-aggregated TP, FP and FN counts.
- `swarm_monitor_leads(env.observer_trace())`: converts the Arena's existing `ObservedSignal` view to incident leads without assuming attribution or accessing the engine's hidden compromise labels.

The case title references 764 only as a synthetic research identifier. Events and identities are invented. The code has no network, wallet, personal-information lookup, exploit payloads or real-world investigative capability.

## Run

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_forensic_blue.py' -v
PYTHONPATH=src python -m spiral_ln.forensic_benchmark --output output/forensic_benchmark.json
```

The forensic-only GitHub Actions workflow runs the same commands with Python 3.12 and no additional packages. The full Arena suite remains separately owned.

### Development fixtures, not model evidence

Expected contract totals for the 18 synthetic fixtures:

| Reference policy | True accepted | False accepted | True left unconfirmed |
|---|---:|---:|---:|
| Accept all positive assertions | 17 | 9 | 1 |
| Mulder + Scully deterministic review | 12 | 0 | 6 |

The evaluator's truth labels are held out of the investigator function and become available only after all reports have been produced. The separation is an API contract inside a Python process, not an isolation boundary for an untrusted model. In a competitive run the broker, evaluator and model must execute under separate privileges with held-out cases and immutable source lineage.

The `origin` field is the broker's trusted provenance designation. A deployment must verify that registry independently; supplying arbitrary origins would allow fraudulent corroboration. Evidence digests bind observations to a caller-provided pin and do not authenticate acquisition. Payment and hosting relationships remain descriptive facts; no finding labels criminality or guilt.

### Next experimental gates

- Freeze an independent evaluation corpus and prevent scenario leakage into blue prompts.
- Add bounded interactive requests for further synthetic evidence and measure information gain per query.
- Compare single-agent, paired-agent and simple rule policies on identical observations and budgets.
- Evaluate false attribution, calibration, evidence conservation and cases involving coerced participants.
