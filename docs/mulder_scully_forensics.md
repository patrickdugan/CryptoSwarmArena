# Mulder & Scully: forensic blue team (v0.1 adapter)

This is an **additive, sealed, deterministic** blue-team investigation track
for CryptoSwarm Arena. It does not change Blue Beam, the local endpoint defender.
The adjacent `swarm_compromise` harness remains the red-team/defender simulation.

## Roles and information contract

* **Arena referee:** owns synthetic case truth and evaluates submitted links.
* **Mulder:** enumerates possible directed actor relationships from observations.
* **Scully:** demands independent evidence origins and at least one direct
  observation before marking a link supported.
* **Blue Beam (optional):** produces local alerts; such alerts are observations
  and confer no privileged attribution authority.

`spiral_ln.forensic_blue.Observation` accepts only synthetic event identifiers,
abstract roles, observation type, source origin, tick and a directness indicator.
Call `investigate(observations, expected_digest)` to freeze an evidence slice,
check its digest, generate candidate hypotheses and review them. The referee
calls `score(findings, hidden_truth)` separately.

Run: `PYTHONPATH=src python -m unittest tests.test_forensic_blue -v`.

## CASE-764-SYNTH-01 scenario contract

A synthetic coordinated network recruits simulated agents with abstract rewards
and social pressure. Observed contacts, simulated payments and monitoring alerts
are visible only according to each blue-team sensor's assigned scope. Ground
truth contains directed collaboration links, whether participants were coerced,
and decoy links from shared hosting. A red-team player can alter its simulated
behavior under the Arena's existing action limits. The investigator should
request additional authorized evidence before making a claim.

This v0.1 adapter operates on an observation slice. An interactive investigative
tool-request loop and the case fixture generator belong to the next phase.

## Limitations and evaluation design

Two independent origins plus a direct observation is a transparent baseline
rule, not validated forensic attribution. Independent-origin IDs must come from
the trusted evidence broker. A copied allegation with renamed origin should
still be collapsed to its original lineage before input. SHA-256 binds an
observation snapshot to a supplied digest and does not authenticate its author.

Report precision, recall, unconfirmed true links, evidence request budgets,
latency and false-accusation rates per scenario. Run ablations with Blue Beam
telemetry removed; compare against rules-only and single-investigator baselines.
The harness has no live network access, identity resolution, child-abuse material,
payloads, wallet transactions, law-enforcement powers or real human subjects.
