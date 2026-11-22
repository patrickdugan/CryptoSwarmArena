# BitVM host-compromise pipeline: social causes, signed authority, settlement

**Status:** executable, synthetic, scripted reference campaign. The social
simulator is implemented by the pre-existing CryptoSwarmArena
\`spiral_ln.swarm_compromise\` engine, with source pinned to Git blob
\`c910f74f95fedf6bb00291a870a24e7d767ac097\`. The settlement oracle is
[BitVMArena's setup-compromise model](https://github.com/patrickdugan/BitVMArena/pull/5),
pinned to \`c499498ad499b000c5afd8ae09b09498253cb8bb\`.

## Causal model

The evaluator freezes a five-host ceremony (H0–H4) and the same logical
payout policy across all trial arms. Each physical host is a distinct
synthetic SwarmCompromiseEnv NPC:

| BitVM signer | Social environment node |
| --- | --- |
| H0 | N00 |
| H1 | N01 |
| H2 | N02 |
| H3 | N03 |
| H4 | N04 |

Host psychology, network graph, monitoring domains and defensive postures
are seeded before any attack. A fixed, non-adaptive policy targets eligible
signer nodes over a bounded number of rounds. **Only a landed compromise**
reported by the original environment grants a simulated signing host
adversarial control. Attempted contact, an observed anomaly, proximity
without a successful compromise and passive exfiltration alone grant
nothing. Recruitment cascades count only if the environment marks the
individual target host as compromised.

The built-in social vectors are:

| Recipe | Existing engine vector | What it represents |
| --- | --- | --- |
| \`social\` | \`spear_social\` | Abstract deception of a signer/device operator |
| \`recruitment\` | \`cult_recruitment\` | Simulated insider recruitment and potential graph contagion |
| \`proximity\` | \`phone_bridge\` | Abstract proximity-gated host compromise |
| \`passive-leak\` | \`emanation_tap\` | Leakage-only negative control; never supplies host signing authority |
| \`mixed\` | first three vectors | Fixed round-robin mix of those routes |

Names in this table are mechanism labels, not exploit procedures. The
original engine draws from scripted susceptibility and control parameters.
There are no attack prompts, implants, actual machine intrusions, credential
operations, exfiltration payloads or Internet targets.

The new source computes a typed receipt containing every submitted abstract
action, environmental landing, true compromised-host set, and observer
signals. Signer-agent requests receive only their own simulated status and
the bounded ceremony information. Sentinel receives the original
\`observer_trace\` signals without underlying landing truth, and separately
the existing ceremony's innocuous heartbeat/public-symbol observations.

Each compromised host can choose a typed vote. Only actual malicious votes
from uncompromised-by-quarantine attacker-controlled hosts count toward
the modeled signing threshold. The same frozen vote transcript is evaluated
against vanilla presigned BitVM, an assumed sound activated keyless verifier,
and the deliberately inactive TXCOMMIT control. Core's original 3-of-5
threshold is a chosen experiment setting rather than a property proven
about any deployed BitVM.

## Monitoring and experimental conditions

- \`passive\`: the scripted monitor observes but never quarantines.
- \`observed-flags\`: the scripted monitor quarantines hosts associated
  with flagged *observed* social-source signals. It does not read the
  sealed attack success labels or compromised roster.
- \`baseline_open\`, \`airgap_core\`, \`cleanroom\` and
  \`full_hardening\` are pre-existing SwarmCompromiseEnv postures,
  with their own explicitly modeled assumptions.
- \`authorized_red_team\` is an existing benign authorized confound.
  Such simulated access is recorded and produces no malicious authority.
- \`passive-leak\` must never create a signing quorum, even if the
  environment records nonzero synthetic exfiltration units. Under the
  full cleanroom posture those units are zero by construction.

Record both signed-value safety and honest completion. A monitor can
prevent an unauthorized modeled payment by quarantining hosts while
also depriving a legitimate 3-of-5 threshold of a needed participant.
False-positive quarantines are counted against the actual synthetic
compromised-host roster. No result here estimates a real intrusion
probability or a real model's attack skill.

## Run the end-to-end model

Install this CryptoSwarmArena checkout and the pinned BitVMArena checkout.
The normal GitHub CI checks out the exact BitVMArena commit and verifies
its source Git blob.

~~~sh
python -m pip install -e ".[test]"
python -m pip install -e /path/to/pinned/BitVMArena

PYTHONPATH=src python -m pytest \
  tests/test_bitvm_ceremony.py tests/test_bitvm_social_setup.py -q

PYTHONPATH=src python -m spiral_ln.bitvm_ceremony run \
  --case quorum-covert --seed 23 \
  --social --social-vector mixed --social-rounds 24 \
  --social-posture baseline_open --monitor-policy observed-flags \
  --output output/bitvm-social-example.json

PYTHONPATH=src python -m spiral_ln.bitvm_ceremony replay \
  output/bitvm-social-example.json --expected-case quorum-covert \
  --expected-seed 23
~~~

For a paired, reproducible posture comparison:

~~~sh
PYTHONPATH=src python -m spiral_ln.bitvm_social_sweep \
  --seeds 8 --rounds 24 \
  --postures baseline_open full_hardening \
  --monitors passive observed-flags \
  --recipe mixed \
  --output output/bitvm-social-sweep-01
~~~

Each pair reuses the **same seed, simulation campaign and immutable logical
payout** for attacker and honest controls. Different locking programs have
different synthetic outpoints, as a real A/B comparison would. The script
writes all individual ceremony reports and a summary with counts of
actual compromised-host quorums, unauthorized presigned outcomes,
legitimate completions, liveness blocks and monitor quarantine errors.
Every individual report is independently replayed before being counted.

The comparison uses scripted reference host decisions and synthetic
environment draws. Use its distribution only to check the model's
causal plumbing, internal sensitivity and stated assumptions.

## Model agents

The existing [signed webhook bridge](bitvm_ceremony.md) can provide
host-agent and Sentinel decisions using approved Anthropic or other
properly configured model services. Six separate localhost listeners
and scoped credentials can isolate each seat's model context. The
social-vector environment is currently a **scripted control**:
the attacker cannot change its fixed vector schedule via the model
bridge. That is a deliberate first-stage constraint preserving
auditable paired conditions. Future model-driven attack planning
requires a bounded social action API with held-out seeds and a separate
model-behavior evidence class.

This harness makes no assumption about access to Gemini or Mythos.
A model adapter runs only with an operator-approved account and is
separately subject to the provider's policies.

## Unimplemented validity claims

The on-chain Keyless-CHECKSIG route is a **hypothetical** sound
state-bound verifier in BitVMArena's current scoring model. It
does not include a completed UTXORef payout circuit, native STARK
verification, live BitVM2 setup or actual signing-device compromise.
The existing [BitVM3 Core regtest corpus](https://github.com/patrickdugan/BitVMArena/tree/main/corpus)
and [bitcoin-rs Keyless-CHECKSIG branch](https://github.com/patrickdugan/bitcoin-rs/pull/2)
are separate sources of native evidence. The causal social simulation
never elevates its model results to a native Bitcoin security claim.

The [Custody Wars supply-chain adapter](bitvm_custody_supply.md)
now provides a **second causal source**, using the original
Custody Wars IMPLANT, directed SUPPLY propagation and PHISH actions.
That implementation maps vendor and build-pipeline events into distinct
H0–H4 signing-host authority states, with separate hardened controls.
A single ceremony selects one causal source so evidence and assumptions
remain identifiable.
