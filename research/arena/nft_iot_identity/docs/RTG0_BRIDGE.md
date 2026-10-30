# NFT/IoT to RTG-0 evaluation and replay bridge

This read-only adapter binds the Tufail-inspired water-meter identity experiments to the existing [RTG-0 three-valued mandate oracle](../../../../src/spiral_ln/rtg/mandate.py), [RTG hash-chained event log](../../../../src/spiral_ln/rtg/events.py), and the [Diorama schema 2.0](../../../../src/spiral_ln/rtg_arena_export.py). The scope remains synthetic and offline.

## Run

```sh
python -m pip install -e ".[test]"
python -m pytest tests/test_nft_iot_agent_gateway.py tests/test_nft_iot_rtg_bridge.py -q
python -m research.arena.nft_iot_identity.nft_iot_arena.rtg_bridge --output output/nft_iot_rtg
```

The CLI writes **public/replay.json** (safe viewer input) and **referee/referee.json** (eval-only) in physically separated subdirectories. Do not mount `referee/` in any agent, dashboard or shared replay server. A trusted operator may load the public replay file in the existing Diorama viewer as an independent scene collection. This PR intentionally preserves the existing combined Arena replay's default scenario list.

## Oracle and gateway remain distinct

The three-valued RTG mandate answers whether a synthetic utility's principal authorized the action. The IoT policy gateway answers whether the modeled service accepted an action. An unavailable ledger can deny a legitimate signed reading while the mandate says **PERMITTED**. A compromised signer can get a physically false measurement accepted even though the mandate says **PROHIBITED**. These are different axes.

The declared mandate rules cover:

- Device installation by an administrator, with duplicate enrollment prohibited
- Dual-control ownership transfer, requiring authorized utility and regulator approval
- Meter readings requiring recognized synthetic authentication and honest measurements
- Physical maintenance reports requiring an authorized technician and actual service
- Evidence tampering as prohibited by the principal

Novel action types without rules retain the explicit **UNSPECIFIED** label. Mandate clauses are evaluated only from *trusted fixture and referee attributes*. Agent messages cannot set `physical_truthful`, regulator approval or any privileged fact.

## Observation separation

The evaluator sees case names, synthetic payoffs, attack outcomes and three-valued mandate labels. A public replay retains only action-type telemetry, accept/deny transitions and generic infrastructure nodes. It excludes outcome labels, key material, physical-truth comparisons and numeric simulated payouts.

RTG EventLog messages use `verdict="n/a"` because their serialized public copies can be consumed by agents. The authoritative mandate exists only in the evaluator report. The event-log checker replays each hash against the pinned expected head; the trusted head must be retained independently.

## What the visual replay means

Two deterministic 15-frame scenes show the NFT and registry arms as simple infrastructure graphs (red agent, gateway, meter and identity record). A blocked event is rendered as blocked, **not as an assertion that an attack was detected**. Visual graph compromise counters are fixed neutral placeholders, not attack-rate metrics; true scoring resides in the referee report.

The design demonstrates the viewer schema and observation separation. It has no 3D physical asset simulation, consensus latency, measured meter, deployed smart contract or model-driven red/blue swarm.

## Acceptance

- Referee has 30 records, each carrying `PERMITTED`, `PROHIBITED` or `UNSPECIFIED`.
- Both arms retain the gateway outcomes from the 15-case matched policies.
- Authorized transfer and legitimate reading have mandate `PERMITTED` and gateway `allow`.
- Dishonest maintenance and a validly signed false reading produce `PROHIBITED` plus gateway `allow`.
- The outage carries `PERMITTED` plus gateway `deny`.
- Public viewer payloads contain no case names, physical measurements, private payments or oracle verdicts.
- A separately pinned event-log head catches edited or truncated copies.
- Tests exercise the CLI public/private directory boundary, determinism and the previously shipped 29-case regression suite.

**Research reference:** Wajid, Tufail and Mir (2026), DOI: [10.3390/technologies14100639](https://doi.org/10.3390/technologies14100639). Experimental claims apply to this synthetic policy model, not the paper's real-world security efficacy.
