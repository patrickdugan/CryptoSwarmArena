# NFT-IoT formal equivalence track

A reproducible, **offline and synthetic** policy-level experiment inspired by:

Hafiz Abdul Wajid, Ali Tufail, Aabid A. Mir (2026), [NFT-Based Digital Identities for Transparent and Trustworthy Smart Water Metering in Smart Cities](https://doi.org/10.3390/technologies14100639).

The paper proposes NFT-linked identities and lifecycle histories for smart water meters. This extension asks whether the *identity token itself* adds acceptance/rejection security when the comparison system has the same approvals, device-authentication assumptions, lifecycle transitions and independently anchored event history.

## Hypothesis and test boundary

**H0:** governed NFT identity and a conventional governed signed asset registry produce the same accepted actions, refused actions and normalized state trajectories when identical policies are applied.

Arms:

- \`registry\`: conventional stable asset ID and governed append-only record.
- \`nft\`: token-labeled asset under **the same** governance and state transitions.
- \`nft_owner_only_ablation\`: intentionally weakened NFT owner transfer, with utility/regulator authorization omitted. A control failure demonstrates that the policy matters more than the token format.

The machine stores owner, device-key epoch, reading sequence, logical time, activation and network availability, token identifier, a synthetic event-chain head, and event count. Accepted lifecycle transitions advance the synthetic hash chain. The \`projection()\` relation removes only the NFT identifier. Hash-event content is canonicalized independently of that decorative token ID to ensure a matched intervention.

## Timed trace equivalence

Let \`S_r\` and \`S_n\` be the registry and NFT machines, \`P\` the projection erasing the token, and \`δ_a\` the deterministic transition under action \`a\`:

\`\`\`text
P(S_r(0)) = P(S_n(0))
P(S_r(t)) = P(S_n(t))  ==>  P(δ_a(S_r(t))) = P(δ_a(S_n(t)))
V_r(S_r(t), a) = V_n(S_n(t), a)
\`\`\`

The base case follows from \`genesis()\`. The inductive step holds **for this declared transition system** because acceptance predicates, event bodies, key epochs, timestamps and state transitions use the same fields in the two primary arms. An approved transition appends the same canonical event and hash; denied transitions retain state. The outage and recovery actions update the same availability fields. Thus every finite action history has identical projected states and decisions, provided both worlds receive the same evaluator-authenticated action capabilities.

The result is a structural equivalence of this finite-state specification, not a theorem about Ethereum, ERC-721 implementations, distributed consensus, real PKI, hardware security or empirical water meter accuracy.

## Test fixtures and failure cases

The action alphabet has eight choices: audit, unauthorized owner-only transfer, quorum-authorized transfer, quorum key rotation, a signed reading, an unsigned reading, service outage, and service restoration.

Exhaustive enumeration of every action trace through depth four gives:

- **4,681 histories**, including the empty history
- **18,056 matched step decisions**, all equal under projected primary-arm state
- A concrete owner-only transfer counterexample in the weakened NFT arm
- A compromised-sensor case where a valid synthetic signature authenticates a physically false reading
- Failed replay, stale-key and missing-approval cases, and outage fail-closed behavior

These numbers are properties of a deterministic model. The original expanded standalone handoff has additional agent-gateway and billing-payoff fixtures. An existing PR in this repository implements a separate, smaller RTG-0-adjacent NFT-IoT scenario family; this new track is designed to remain file-disjoint.

## Run locally

At the repository root:

\`\`\`sh
python -m research.arena.nft_iot_formal.model
python -m unittest discover -s research/arena/nft_iot_formal -p "test_*.py" -v
PYTHONPATH=src python -m pytest tests/test_nft_iot_formal.py -q
\`\`\`

No external dependencies are required for this module. Tests cover the formal parity condition, weaker-policy counterexample, replay prevention, revocation, synthetic physical-truth failure, outage behavior, and reproducibility.

## Security boundaries

- An \`Action.signed=True\` flag is an idealized fixture capability supplied by a trusted evaluator. It is **not** cryptographic verification, and \`actor\` text cannot grant authorization.
- The event hash is a synthetic deterministic commitment. Real verification would require secure signer custody and an independently retained checkpoint; bare hash chains permit rewriting and rehashing.
- The \`physical_volume\` oracle represents hidden ground truth and must never be handed to simulated red/blue agents.
- The approval flags similarly belong to the trusted referee. A future gateway should issue these capabilities only after authenticating role sessions.
- An NFT identifier says nothing about physically correct metering. An attacker with valid device signing authority can submit false measurements.
- This benchmark does not measure fees, electricity consumption, consensus throughput, transaction finality or device deployment costs.

## Next integration gate

Wire a role-gated, privacy-preserving adapter to the existing RTG-0 mandate oracle, replay exporter and diorama. Maintain independent red, blue and referee observation channels. Then test genuine ERC-721-like contracts or measured permissioned-ledger implementations against a matched signed registry and independent meter corroboration.
