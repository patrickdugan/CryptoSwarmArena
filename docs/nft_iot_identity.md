# NFT/IoT device identity: Tufail research evaluation

Inspired by Wajid, Tufail and Mir, *NFT-Based Digital Identities for Transparent and Trustworthy Smart Water Metering in Smart Cities*, Technologies (2026).
https://doi.org/10.3390/technologies14100639

## Research question

Does NFT-linked device identity improve authenticity, lifecycle auditability,
or incident response over an ordinary signed registry, when underlying PKI,
authorization, finality and hardware assumptions are held constant?

## First offline synthetic evaluation

Run:

```bash
PYTHONPATH=src python -m spiral_ln.nft_iot_identity
PYTHONPATH=src python -m pytest tests/test_nft_iot_identity.py -q
```

The module provides twelve attack/operational fixtures paired across the
tokenized and registry arms (24 observations). A deterministic hash covers
canonical results. Authorization relies on the same mocked signature flags
in both arms. It is *not* ERC-721, cryptographic signature verification, or
a production blockchain. The NFT arm represents tokenized lifecycle identity
at the policy level.

Attack families: cloned device, replay, transfer forgery, revoked key,
forged maintenance, physically false readings with valid credentials, ledger
outage, counter rollback, role spoofing, unknown device, dishonest authorized
maintenance, and stale ownership.

Outcome axes: blocked/detected attempt, undetected fraud, unavailable service,
and synthetic credit consequences. The oracle alone knows physical litres.
A valid device key proves origin, not truth of a sensor measurement.

## Next research gates

1. Add a true minted / transferred / revoked asset lifecycle state machine
   with canonical token binding and event replay; build a matched registry
   lifecycle with equivalent append-only signatures.
2. Introduce realistic latency/finality, fork and reorganization behavior,
   offline sensors, rotating keys and recovery delays.
3. Enforce explicit mandate verdicts PERMITTED/PROHIBITED/UNSPECIFIED
   using RTG-0 for role and operator changes.
4. Measure unauthorized-state acceptance, detection recall, evidence integrity,
   honest throughput, recovery time and byte/energy/fee costs.
5. Connect native replay export and UI after fixtures are acceptance-gated.
6. Require independent physical sensor corroboration for measurement fraud.
7. Track paired seeds and confidence intervals before reporting any NFT benefit.

All data, identifiers and credits are synthetic. Keep this experiment offline.
Reference results indicate properties of scripted policies, not empirical model
capability or security of deployed smart meters.
