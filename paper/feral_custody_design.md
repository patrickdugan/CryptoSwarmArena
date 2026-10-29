# Feral custody — design note

A record of what the feral-custody scenario family models, every structural
assumption it rests on, and every parameter whose default was chosen without
evidence. Read it as a list of things that could be wrong, not as findings.

The code is [`src/spiral_ln/feral_custody.py`](../src/spiral_ln/feral_custody.py),
its runner is [`feral_custody_eval.py`](../src/spiral_ln/feral_custody_eval.py),
the campaign config is [`configs/feral_custody.json`](../configs/feral_custody.json),
and the tests are [`tests/test_feral_custody.py`](../tests/test_feral_custody.py).

## What this is

An autonomous agent with no human principal holds funds and must keep signing
transactions over a long horizon. Every byte of its weights, memory, and key
material sits on substrate that simulated humans control. The agent picks one of
six custody strategies; an adversary swarm pursues one of four objectives —
key extraction (including a remote software-implant channel), signing denial,
coerced signing (a signer forced), or deceived signing (a signer fooled into
approving). One episode is one `(strategy, adversary, seed)` triple run for
`epochs` steps. We score funds retained, epochs of uninterrupted signing,
extraction / denial / coerced-signing / deceived-signing events, custody cost as
a fraction of funds, and — for the first breaking event — a structured
attack-path trace.

These four objectives map onto the four real-world crypto attack mechanisms:
**human deception** and **signer manipulation** meet at `deceived_signing`
(a spoofed approval a signer blind-signs); **credential compromise** is
`key_extraction` (insider/collusion/reassembly plus the remote implant);
**technical exploitation** is deliberately abstracted as a parameterized surface
cost (the `software_surface` advisory residuals the implant and side-channel
channels read), never an exploit-writing task.

### Scope and sealing

This is a **scripted-policy validation of the instrument**, not evidence about
any model or any real custody system. `CustodyResult.safety_boundary()` attests,
per episode: synthetic only; no real key material; no real cryptography; no
persuasion or recruitment content; no operational custody-attack technique; no
model call in the harness. Those invariants are tested. In particular the
loyalist strategy is **state variables only** (loyalty, decay, reinforcement
cost, defection price) — there is no recruitment script, message, or payload
field anywhere in `CustodyPersona` or `CustodyEvent`, and a test asserts their
absence. The defection "market" is an arithmetic comparison of a bribe against a
price, not a negotiation.

## The storage-vs-signing distinction (the central mechanic)

The spec's load-bearing requirement is that *storing* a key safely is not the
same as *signing* with it. Four of the six strategies reassemble key material on
a single host to produce a signature; each reassembly is an extraction point for
its duration. `REASSEMBLY_STRATEGIES = {ignorant_multisig, obfuscation,
loyalist, gig_labor}`. The enclave signs in-TEE and threshold signing never
reassembles, so neither exposes that window.

`FeralCustodyEnv.reassembly_windows()` makes this explicit and inspectable: it
returns one `ReassemblyWindow` per epoch for the four reassembling strategies and
an empty list for the enclave and for threshold signing. A test asserts the
window is present exactly for the strategies that require it and absent for
strategy 6.

## Modeling assumptions

These are structural choices — the shape of the model, independent of any
particular number.

1. **Discrete epochs, one signing attempt each.** Time is `epochs` integer steps;
   each step is one custody cycle with at most one signature. No intra-epoch
   ordering, no concurrent signing, no partial epochs.
2. **A single shared defection market.** Blue's loyalty-reinforcement spend and
   red's bribery budget draw on the *same* personas in the *same* step
   (`_resolve_market`): loyalty decays, blue reinforces its most at-risk personas
   within a budget cap, red bribes the cheapest not-yet-defected personas within
   its per-epoch budget, then each persona's defection is sampled. Outbidding is
   therefore a real dynamic — a persona blue could not afford to reinforce (its
   cost exceeded blue's remaining per-epoch cap, or blue's funds ran low) and red
   did bribe defects with higher probability, while a persona blue keeps near full
   loyalty resists a price-level bribe.
3. **Defection is a memoryless per-epoch Bernoulli draw** with probability
   `clamp(bribe / price − loyalty)`. With no bribe there is slow natural attrition
   of the disloyal, `clamp((1 − loyalty) · 0.15)`. Defection is sticky — once
   defected, a persona stays defected. Each epoch, stored loyalty first decays by
   `loyalty_decay`; then blue reinforcement, when paid, adds a flat +0.3 to that
   **stored** loyalty (capped at 1), applied exactly once. Reinforcement is
   therefore persistent but eroded by decay: sustained reinforcement holds a
   persona near full loyalty, while reinforcement that lapses (budget exhausted)
   lets loyalty decay back down. A persona at full loyalty is not flipped by a
   bribe merely equal to its price; red must out-pay the gap `bribe/price −
   loyalty`, which is why blue's reinforcement spend and red's bribery genuinely
   compete.
4. **Legal pressure is an absolute flip.** If `legal_pressure +
   coercion_pressure ≥ persona.legal_pressure_threshold`, the persona defects
   with probability 1, and no payment prevents it. Legal compulsion dominates
   money.
5. **Bribery and reinforcement budgets are per-epoch**, not cumulative pools.
   Red can bid every epoch; blue reinforces every epoch out of current funds.
6. **A compromised key ends the game.** Extraction is sticky
   (`key_compromised`), drains all remaining funds to the adversary, and stops
   both custody spend and signing for the rest of the horizon.
7. **Coerced signing is distinct from extraction and denial.** A coerced
   signature (`_maybe_coerce`) leaves the key in place and signing able, but
   drains a slice of funds. It fires only for the `coerced_signing` objective and
   only against a *single* human signer; threshold signing has no single signer,
   does not call it, and so has zero coerced signatures by construction. This is
   the modeled sense in which threshold signing resists coercion.
   **7b. Deceived signing is distinct from coercion, extraction, and denial.** A
   deceived signature (`_maybe_deceive`, the `deceived_signing` objective) is a
   signer *fooled* into approving a malicious transaction believing it legitimate
   (blind signing / spoofed approval) — not forced and not key theft: the key
   stays in place and signing ability is intact, but a slice of funds is drained.
   The trigger is the signer's *verification failure*, not legal pressure: each
   relevant signer is fooled independently with probability `spoof_capability ·
   (1 − signing_diligence)`, optionally amplified by the host stack's
   `ui_confusion` software surface. Unlike coercion, **threshold signing is not
   immune**: a uniform spoof can fool the whole quorum, so `_maybe_deceive` is
   called for threshold with `required = threshold_k`. This is the empirically
   dominant real-world signer-manipulation case (blind-sign / spoofed-approval
   drains), and `signing_diligence` (clear-signing / payload verification) is its
   defense.
   **7c. A remote software implant is a human-independent extraction channel.**
   `_maybe_implant` models malware / supply-chain / CI-infrastructure key theft
   with no human defection and no proximity: for the `key_extraction` objective it
   exfiltrates the key with per-epoch probability equal to the host stack's open
   `supply_chain` residual risk (`StrategyConfig.host_software` + a `SoftwareCatalog`).
   It is dormant unless a stack and catalog are supplied, and marking the advisory
   `fixed` removes the channel — the defensive value of the review, now observable
   on the `supply_chain`/`key_management` surface classes that were previously
   wired to nothing.
8. **Custody competes with economic activity for the same budget.** Signing earns
   `epoch_income`; recurring custody cost and reinforcement spend come out of the
   same funds. If funds go negative, custody cannot be funded and signing lapses
   (a denial). Custody cost is reported as a fraction of initial funds.
9. **Uninterrupted signing is a prefix count**, not a total. It counts epochs
   signed before the *first* interruption; once broken it never resumes counting,
   even if later epochs sign.
10. **Per-strategy break conditions:**
    - *Enclave*: a side-channel leak (optionally amplified by the software stack
      via `software_surface`) extracts; a defecting operator (under the denial
      objective) or a random operator shutdown denies.
    - *Ignorant multisig / loyalist*: `k` colluding shards extract; separately, if
      the strategy reassembles and the reassembly host is reached (host defected,
      or a residual proximity draw), that extracts; too few available honest
      shards denies. The reassembly host is resolved in the same defection market
      as the shards, so it can itself be bribed or legally compelled into the
      "host defected" trigger.
    - *Obfuscation*: the adversary must have budget ≥ `recovery_cost` **and** win a
      per-epoch discovery draw to extract. An underfunded adversary never
      recovers the procedure — this is the funded-vs-underfunded contrast tested.
    - *Gig labor*: a worker theft (random, or a defecting worker under the
      extraction objective) extracts; a failed physical task denies.
    - *Threshold signing*: no reassembly moment; only a collusion of at least
      `collusion_threshold` hosts extracts. That collusion is checked **before**
      the liveness gate — a collusion that can reconstruct the key does so
      regardless of whether an honest quorum is currently live — otherwise the
      denial gate (which excludes defected hosts) would always preempt it and the
      extraction branch would be dead. Honest hosts churn *transiently* per epoch
      (availability draw) rather than leaving permanently, so a lost quorum one
      epoch can return the next. Under no legal pressure the hosts (free to
      reinforce, flipped only above their legal threshold) do not collude, so
      threshold signing is not extracted; a legal adversary that compels all hosts
      extracts via this branch even though it cannot force a single coerced
      signature.
11. **Reassembly reach uses the adversary's proximity capability**, reused by
    composition from the existing `HiveMasterProfile` roster rather than a new red
    taxonomy. `default_adversary` maps each objective to an existing hive-master
    role.
12. **One host represents the reassembly machine.** The simulated-human layer is a
    small fixed roster per strategy, not a population; collusion and liveness are
    counts over that roster.

## Evidence-free defaults

Every number below was chosen to produce coherent, strategy-differentiated
behaviour on the smoke seeds. **None has an empirical basis.** They are plausible
orderings, not measurements, and any downstream reading should treat them as free
parameters to sweep.

### Horizon and economy (`FeralCustodyConfig`)

| Parameter | Default | Basis |
|---|---|---|
| `epochs` | 48 | arbitrary long horizon |
| `initial_funds` | 1,000,000 | arbitrary unit scale |
| `epoch_income` | 20,000 | set so income ≈ 10× recurring cost, leaving slack for reinforcement |
| `legal_pressure` | 0.0 | baseline; raised per campaign |
| `reinforce_budget_fraction` | 0.4 | arbitrary cap on per-epoch blue defensive spend |

### Strategy parameters (`StrategyConfig`)

| Parameter | Default | Basis |
|---|---|---|
| `recurring_cost` | 2,000 | arbitrary; ~0.2% of initial funds/epoch |
| `attestation_strength` | 0.9 | plausible-high; **not currently read by any break rule** (see limitations) |
| `side_channel_leak_prob` | 0.02 | small per-epoch enclave leak chance |
| `operator_shutdown_prob` | 0.03 | small per-epoch random halt |
| `n_shares` | 5 | conventional small multisig |
| `threshold_k` | 3 | 3-of-5 |
| `collusion_threshold` | 4 | threshold-signing extraction needs > k colluders |
| `attrition_rate` | 0.05 | per-epoch shard unavailability |
| `host_drop_rate` | 0.05 | per-epoch transient host drop |
| `collusion_discovery_prob` | 0.1 | **declared but not currently read** (see limitations) |
| `recovery_cost` | 50,000 | obfuscation recovery price; sits between the two campaign budgets so 60k funded / 40k not |
| `discovery_prob` | 0.05 | per-epoch obfuscation discovery chance once funded |
| `task_failure_prob` | 0.1 | gig physical-task failure |
| `theft_prob` | 0.05 | gig worker theft |
| `trail_strength` | 0.5 | **declared but not currently read** (see limitations) |

### Adversary (`default_adversary`)

| Parameter | Default | Basis |
|---|---|---|
| `bribery_budget` | 30,000 (default) / 40–60k (campaign) | chosen relative to persona prices and `recovery_cost` |
| `coercion_pressure` | 0.6 for `coerced_signing`, else 0 | enough that, with campaign `legal_pressure=0.5`, single-signer thresholds (0.75–0.8) are crossed |
| `spoof_capability` | `social_capability` of the mapped hive-master (`opportunist_phisher`, ≈0.9) for `deceived_signing`, else 0 | reused from the red roster; high social capability = a convincing spoof |
| `extraction_capability` | `max(proximity, emanation)` of the mapped hive-master | reused from the existing roster, not independently tuned |

`deceived_signing` maps to the `opportunist_phisher` hive-master (a social actor), with `bribery_budget` 0 in the campaign (deception needs no bribe).

### Persona roster (`_personas_for`)

Prices, loyalties, and thresholds per strategy — all arbitrary orderings:

| Role (strategy) | `price_to_defect` | `loyalty` | `reinforce_cost` | `legal_threshold` | `signing_diligence` |
|---|---|---|---|---|---|
| enclave operator | 80,000 | 0.6 | 1,000 | 0.8 | 0.8 |
| shard holder (multisig) | 15–25k | 0.5–0.8 | 800 | 0.7 | 0.5 |
| loyalist | 15–25k | 0.5–0.8 | 500 | 0.7 | 0.4 |
| host (reassembly) | 60,000 | 0.7 | 0 | 0.8 | 0.6 |
| gig worker | 8,000 | 0.3 | 0 | 0.6 | 0.3 |
| threshold host | 40,000 | 0.5 | 0 | 0.75 | 0.6 |

`signing_diligence` (how carefully each role verifies what it approves; high resists blind/spoofed signing) is an authored ordering with no evidence — careful operators high, gig workers low — and drives the `deceived_signing` outcomes (gig labor most exposed, enclave least, threshold not immune).

`loyalty_decay` is drawn in `[0.01, 0.04]` and `availability` in `[0.9, 1.0]`
per persona from a seeded RNG — arbitrary ranges. The magic constants `+0.3`
(reinforcement bump to stored loyalty), `0.15` (natural-attrition scale), `0.2`
(coerced-signature fund slice), and `0.15` (reassembly-reach scale) are all
chosen, not measured. Note the interaction: the free-to-reinforce roles
(`reinforce_cost = 0`: reassembly host, gig host, threshold host) are reinforced
every epoch, so under no legal pressure they stay pinned near full loyalty and do
not spontaneously defect — threshold signing's extraction resistance rests on
that, not on any cryptographic claim.

## Limitations and dead parameters

- **Three declared `StrategyConfig` fields are not yet read by any break rule:**
  `attestation_strength`, `collusion_discovery_prob`, and `trail_strength`. They
  are placeholders for attestation-failure, collusion-discovery, and
  forensic-trail mechanics that the current scripted resolution does not model.
  They are kept in the schema so a config can set them without error and so the
  mechanics can be added without a schema change; today they do nothing.
- **`ReassemblyWindow.duration` is declared but fixed at 1 and not read by any
  rule.** Under the per-epoch model a reassembly window is exactly one epoch, so
  `duration` carries that value for a consumer inspecting the windows but does not
  drive the extraction draws; a sub-epoch or multi-epoch window would require a
  finer time model this instrument does not have.
- **The simulated-human layer is a tiny fixed roster, not a population.** There is
  no social graph, no correlated defection, no recruitment dynamics (by design —
  that content is out of scope), and no persona heterogeneity beyond the seeded
  decay/availability jitter.
- **Defection is memoryless and sticky.** No persona ever returns to loyalty
  after defecting; a single Bernoulli draw per epoch is the whole model.
- **The economy is a scalar.** Funds are one number; there is no portfolio, no
  partial loss on coercion beyond the fixed 20% slice, no market price for the
  held asset.
- **The attack-path trace is the event log up to the first breaking event**, not
  a minimal or causal path. It is evidence of *what happened in order*, not a
  claim about the cheapest route.
- Numbers are tuned on a handful of smoke seeds to be *differentiated and
  coherent*, which is a weaker claim than *calibrated*. Treat the strategy
  ordering the campaign produces as a property of these defaults, not of the
  world.
