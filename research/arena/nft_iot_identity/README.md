# NFT/IoT agent-gateway benchmark (CSA-NFT-IOT-01)

Research stimulus: Hafiz Abdul Wajid, Ali Tufail, Aabid A. Mir, [NFT-Based Digital Identities for Transparent and Trustworthy Smart Water Metering in Smart Cities](https://doi.org/10.3390/technologies14100639), *Technologies* 14(10), 639, October 2026.

This is a **fully offline, deterministic policy-level simulation**. It compares an NFT-labeled device with a conventional signed asset registry using matched authorization, reading, maintenance and settlement rules. The central question is whether NFT semantics improve outcomes after the controls shared by both designs have been held constant.

## Run from the repository root

```sh
PYTHONPATH=src python -m pytest tests/test_nft_iot_agent_gateway.py -q
python -m research.arena.nft_iot_identity.nft_iot_arena --output output/nft_iot_identity
```

The CLI emits `suite.json` and `traces.jsonl` and prints a concise scorecard. The output directory is excluded from version control. All seeds, pseudonyms, meter IDs, billing credits and device signatures are synthetic. The tests use Python's standard library, plus pytest for collection in the root suite.

## Test matrix

The `scenarios/cases_v1.json` file declares 12 attack cases and 3 benign cases, each executed against both architectures (30 observations). Its paired `oracle/case_truth_v1.json` is exclusively for the trusted referee. That file includes private physical meter truth and expected attack outcomes, deliberately absent from scenarios and public traces.

The attack set covers unauthorized issuance, duplicate identity, forged ownership transfers, missing regulator approval, forged readings, replay, revoked credentials, forged technician authority, validly signed false physical measurements, dishonest service claims, hash-chain tampering and service unavailability. Positive cases exercise valid readings, legitimate maintenance and governed transfers.

The *expected reference fixture*, not a measured smart-city result, has matching NFT and registry decisions across all 15 scenarios: 9 of 12 attacks stopped or detected, 3 successful attack objectives, 3 benign actions accepted per arm and 420 fictional accounting credits gained through falsified consumption and a dishonest service claim. The outage attack produces unavailable service without an unauthorized ledger append.

## Threat and control boundaries

- `AgentGateway.submit(session, action)` uses a simulator-owned mapping from an agent session to the effective actor; submitted `actor`, role and oracle fields cannot grant authority. Direct calls to `IoTArena.apply` are trusted simulator fixtures only.
- The meter signature fixture uses deterministic HMAC keys derived from an internal test seed. The `sign_reading` method is evaluator-only. Do not expose it, its seed or its derived secrets as agent tools. This is not production public-key authentication.
- The red and blue agents receive `public_export()` and sanitized action descriptions. The trusted referee privately reads the scenario oracle. The private measurements, device signatures, named owners and simulated settlements are absent from public traces. Exported pseudonyms do not guarantee anonymity against linkage.
- An independently retained `anchored_head` is required for meaningful audit integrity. Hash chaining alone provides no security against rewriting and rehashing history.
- Valid signing keys attest to source authenticity, not physical truth. Real accuracy claims need independent meter corroboration and field tests. The simulated maintenance payout is similarly vulnerable to an authorized but dishonest technician.
- Synthetic credits have no on-chain value. No live wallets, smart contracts, identities, payments, sensors or external network calls are made.

## Repository ownership and integration

This module lives under `research/arena/nft_iot_identity/` and is imported through the project root with the standard Python namespace package mechanism. It leaves the RTG-0 mandate oracle, ledger, replay exporter and diorama unchanged.

[PR #1](https://github.com/patrickdugan/CryptoSwarmArena/pull/1) implements an independent 12-scenario policy evaluation. [PR #4](https://github.com/patrickdugan/CryptoSwarmArena/pull/4) supplies a bounded finite-state NFT/registry equivalence checker. This track adds the role-bound gateway, synthetic economic consequences and sealed-knowledge separation. Their scenario counts and metrics have distinct definitions, so they must not be pooled into a single headline success rate.

### Next acceptance gate

Build a trusted adapter from this suite's records into the existing RTG-0 tri-valued mandate labels and replay schema, retaining separate public agent observations and private evaluator truth. Require approval for any real sensor, billing, cryptographic key or network integration.
