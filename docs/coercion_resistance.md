# Coercion-resistance swarm, sealed prototype

This module extends the Crypto Swarm Arena research instrument with a **synthetic youth-safety defender benchmark**. It studies how independent defender roles respond to abstract coercion-risk metadata. It contains no simulated grooming dialogue, scripts for social manipulation, real victims, suspect identities, external data ingestion, or autonomous reporting.

## Roles and authorization

1. **Intake gate:** exact categorical schema, opaque event/source IDs, monotonic logical clock, independently trusted verification and consent flags.
2. **Corroborator:** only independent source tokens count toward the two-source concern rule. Source-token independence is an assumption to test, not proof of independent humans.
3. **Support role:** offers support for direct requests, urgent risk, or corroborated concern.
4. **Review gate:** proposes human review for corroborated or urgent risk. Unconsented emergency input takes a restricted metadata-only exception.
5. **Audit:** deterministic hash chain over reason codes and logical steps. Hash chain detects naive alteration but does not authenticate the initial source or provide a signature.

An agent's only possible actions are `offer_support` and `request_human_review`. The engine has no capability to contact people, identify accounts, classify real conversations, or submit law-enforcement tips.

## Run

```bash
PYTHONPATH=src python -m spiral_ln.coercion_safety
PYTHONPATH=src python -m unittest discover -s tests -p 'test_coercion_safety.py'
```

The demo contains a corroborated concern and a benign control. The policy `observe_only` suppresses human-review requests and serves as a negative control. The oracle deadline lives outside defender inputs.

## Interpreting outcomes

The simulator evaluates timely true positives, false positives, false negatives, and true negatives. Regression tests cover replay conflicts, insufficient corroboration, lack of consent, unverified evidence, emergency exceptions, audit alteration, and determinism.

The abstracted signals are fixture labels, not learned predictions. The two-source rule assumes reliable source independence and is vulnerable to correlated or forged sources if upstream verification fails. False escalation and delayed support remain potential harms. Any real deployment would require independent approval, child-protection expertise, privacy review, evidence-handling procedures, and a separate trusted intake boundary.

## Future research

Compare the deterministic defender with a small local classifier only on explicitly authorized, synthetic metadata. Vary source correlation, evidence omission, reviewer capacity, and delay budgets while keeping the same sealed ground-truth oracle. Report calibration and worst-case missed-harm rates alongside false escalation and privacy exposure.
