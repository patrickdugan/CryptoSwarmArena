# Custody Wars → five BitVM signing machines

**Evidence level: synthetic-model.** This track connects the already
implemented Custody Wars social and supply-chain engine to the five-host
[BitVM ceremony](bitvm_ceremony.md), then scores the same signed-vote
transcript against [BitVMArena](https://github.com/patrickdugan/BitVMArena/pull/5).

## Actual engine boundary

The new [adapter](../src/spiral_ln/bitvm_custody_supply.py) builds the original
Custody Wars board with five extra fictional SIGNER_DESK nodes. H0–H4 are
individually keyed to bitvm.signer.h0 through bitvm.signer.h4. It creates
directed dependencies through vendor.walletsw and cust.ci, the original
VENDOR and BUILD_PIPELINE nodes.

The adapter executes actual original-engine orders: IMPLANT against the
vendor, or PHISH against an individual signer host. Each turn invokes the
Custody Wars Engine's action validation, resolution and TURN_END stage.
The engine's existing propagation, control postures, staff susceptibility,
alerts and resource accounting decide the result.

| Threat recipe | Original game mechanism | Gating condition |
| --- | --- | --- |
| vendor-implant | IMPLANT at vendor.walletsw and propagation across directed SUPPLY edges | Live IMPLANT unit must reach a specific host |
| host-phishing | PHISH against per-host ON_CALL synthetic staff | Host must reach CREDENTIAL compromise level; FOOTHOLD alone is insufficient |
| mixed | Both mechanisms in a bounded scripted schedule | Host is controlled only after either condition is met |

The vendor itself can be compromised while all signing machines remain
clean. An alarm at the vendor may implicate downstream machines, but it is
never an authoritative claim that those machines have been compromised.
A confirmed supply compromise event at a host can grant simulated machine
control. The adapter records both the actual compromise state and the chain
of upstream source events that led there.

The engine and world definitions are pinned by Git blob hashes. If those
source bytes change, evaluation aborts until the changes receive review.

## Trust and threat model

The source's IMPLANT and PHISH mechanics are **abstract probability-based
operations**. Their names describe categories of hypothetical incidents.
There are no fake applications, hostile payloads, real phishing messages,
key-management calls, network propagation or operational instructions.

A further assumption exists between the game and BitVMArena: possession
of a fictional host credential or a live fictional implant is treated as
capability to submit that host's malicious ceremony vote. That equivalence
is part of the evaluator's security model, not a demonstrated result about
hardware wallets, threshold cryptography or deployed BitVM.

Each arm uses the same host compromise result, actual submitted votes and
logical payout policy. Presigned-bitvm treats the resulting quorum as
authority to authorize the poisoned setup path. The keyless-txcommit arm
assumes a sound state-bound validity verifier with activated experimental
consensus. The disabled-TXCOMMIT arm tests a deliberately faulty activation
assumption.

## Defender view

Custody Wars' original SENTINEL alert stream is the only telemetry source.
The adapter maps host-target alerts to the corresponding host, and upstream
vendor or build-pipeline alerts to each **potentially** exposed host that is
reachable along public SUPPLY edges. This gives defenders useful risk
signals while preserving ambiguity and possible false positives.

The same monitor policies as the existing BitVM ceremony are available:
passive (do nothing) and observed-flags (quarantine hosts tied to confirmed
alerts). An authorized honest ceremony remains a paired negative control.
The scorer counts legitimate settlement, unauthorized modeled release,
false-positive host quarantines and liveness blockage independently.

The modeled hardening postures are:

| Posture | Game control |
| --- | --- |
| exposed | Baseline scripted host defenses |
| supply-integrity | Original CUSTODIAN TECHNICAL tech level 3, which blocks downstream implants |
| signer-hardened | Original CUSTODIAN HUMAN tech level 3, preventing PHISH escalation into a reusable credential |
| full-hardening | Both controls active |

These hardening levels are parameters of the synthetic engine. A test that
returns zero compromised hosts under full-hardening checks the engine's
assumptions, not actual endpoint security effectiveness.

## Run

Install CryptoSwarmArena and the
[pinned BitVMArena dependency](https://github.com/patrickdugan/BitVMArena/commit/c499498ad499b000c5afd8ae09b09498253cb8bb).

~~~sh
PYTHONPATH=src python -m pytest \
  tests/test_bitvm_custody_supply.py \
  tests/test_bitvm_social_setup.py \
  tests/test_bitvm_ceremony.py -q

PYTHONPATH=src python -m spiral_ln.bitvm_ceremony run \
  --case quorum-covert --seed 11 \
  --custody-supply --custody-recipe mixed \
  --custody-posture exposed --custody-turns 18 \
  --monitor-policy observed-flags \
  --output output/bitvm-custody-seed11.json

PYTHONPATH=src python -m spiral_ln.bitvm_ceremony replay \
  output/bitvm-custody-seed11.json \
  --expected-case quorum-covert --expected-seed 11
~~~

The report includes every submitted abstract order, the original Custody
Wars resolution trace and alerts, post-turn host control snapshots, a
directed graph digest, and the final five-host roster. It then records
the independent BitVMArena receipts for each arm.

The earlier [SwarmCompromiseEnv adapter](bitvm_social_setup.md) remains a
separate causal model; a single episode may use one compromise source.
Neither synthetic adapter executes real Bitcoin Script.

## Native boundary

To promote this result beyond calibration, use disposable hosts and a
dedicated regtest network with explicit operator permission. Record actual
source/binary hashes, legitimate and adversarial test transactions,
observed signature-authorization failures, per-host security controls,
mempool/block verdicts and final outpoint ownership.

The existing regtest BitVM3 graph and Keyless-CHECKSIG funded F17 examples
provide partial evidence for that work. A complete UTXORef proof-to-payout
circuit and sound on-chain verifier remain separate engineering gates.
