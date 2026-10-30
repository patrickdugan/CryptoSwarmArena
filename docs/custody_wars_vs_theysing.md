# Custody Wars vs They Sing: complexity as a sim/game for AIs

Target: Custody Wars should reach about **60% of They Sing's complexity** as a
simulation and game for AI agents, and be playable by Codex agents over
webhooks.

They Sing reference: `MoralityLabAI/TheySing` at `0879110` (engine
`src/engine/`, headless harness `src/harness/`). Its counts come from its type
definitions (`src/engine/types.ts`, `src/harness/types.ts`), its harness server
contract (`src/harness/server.ts`), and a read-only Codex inventory pass. Custody
Wars counts come from `src/spiral_ln/custody_wars/content.py` and the engine.

## Method

There is no single number for "complexity", so three are reported:

1. **Breadth coverage.** For each of 14 categories, the Custody Wars count
   divided by the They Sing count, capped at 1.0, then averaged with equal
   weights. It answers "does it have the same kinds of systems?". The cap
   stops excess in one category from hiding a gap in another.
2. **Mechanic count.** Distinct enumerated mechanics (order types, pact types,
   statuses, traits and so on), uncapped and summed. It answers "how many
   distinct things can an agent do, face or be judged on?".
3. **Implementation size.** Lines of engine and harness code. This is a crude
   proxy for depth per mechanic; Python is denser than TypeScript, which flatters
   Custody Wars a little here.

Counting choices are judgment calls; they are listed per row so they can be
audited and disputed.

## Category table

| # | Category | They Sing | Custody Wars | Ratio (capped) |
|---|---|---|---|---:|
| 1 | Playable seats | 7 factions | 6 seats | 0.86 |
| 2 | Board size (nodes, edges) | 21, 37 | 15, 29 | 0.75 |
| 3 | Board typing (node types + layers + edge types) | 5 + 2 + 2 = 9 | 13 + 2 + 3 = 18 | 1.00 |
| 4 | Units + attack vectors | 5 + 4 = 9 | 5 + 4 = 9 | 1.00 |
| 5 | Turn phases (simultaneous resolution in both) | 5 | 5 (plus 6 resolution stages, 4 times of day) | 1.00 |
| 6 | Order types | 16 | 22 | 1.00 |
| 7 | Resolution effect types | 10 | 12 | 1.00 |
| 8 | Diplomacy: pact types, enforcement modes, institution actions, binding/execution statuses, trust, sanctions | 7 + 3 + 3 + 5 + 6 + 2 = 26 | 4 + 3 + 2 + (3 gateway + 2 breach + 3 commitment statuses) + 2 = 19 | 0.73 |
| 9 | Communication and information protocol | message scopes 2; SING/1 lexicons (2 dialects, 8 mutation ops, decode receipts, 3 access modes, 3 fork rules) 17; artifacts 5 = 24 | message scopes 2; attestations 4; challenges 1; sealed commitments 1; transfers 2; artifacts 5 = 15 | 0.63 |
| 10 | Social and psychological model | movement profile, 10 dimensions with 72 values; 5 doctrine families; 3 affinity tiers; 4 strategic pressures = 84 | 5 staff traits (susceptibility, diligence, loyalty, morale, fatigue); 6 bias cards; 4 shifts; 4 times of day; defection and rehire 2; colleague pivot 1; recon 1; 3 mood bands = 26 | 0.31 |
| 11 | Economy and tech | 2 resources + 28 tech unlocks = 30 | 6 resources + 12 tech levels + 5 flow statuses + 2 laundering channels + 3 income/upkeep flows = 28 | 0.93 |
| 12 | Global state and end conditions | 3 counters + 4 pressures + 3 threshold flags + 7 victory routes = 17 | 4 counters + 3 end conditions + 6 seat objectives = 13 | 0.76 |
| 13 | Hidden information and stochasticity | stealth reveal, hidden orders, seeded RNG = 3 | fog of war, stealth and exposure, confirmed vs anomaly alerts, false positives, sealed referee, recon, seeded RNG = 7 | 1.00 |
| 14 | Harness and evaluation | 3 agent types, 11 endpoints, 8 trace channels, 3 bridge modes, ~14 sample configs, tournament, reasoning diary, counterfactual alliance projections, campaign clock, feedback loop = 44 | 4 agent types, 16 endpoints, 10 trace channels, 3 bridge modes, 6 scenarios, tournament, diary, mandate referee, HMAC signing, idempotency, token scopes, 3 policy profiles = 48 | 1.00 |

## Results

| Measure | They Sing | Custody Wars | Ratio |
|---|---:|---:|---:|
| Breadth coverage (mean of 14 capped ratios) | 1.00 | | **0.93** |
| Mechanic count, all categories except board size | 284 | 228 | **0.80** |
| Mechanic count, game only (excluding harness row 14) | 240 | 180 | **0.75** |
| Implementation size (engine + harness lines) | 24,414 TypeScript | 4,442 Python | **0.18** |

**Verdict.** On what an AI agent plays against (the kinds of systems, and the
number of distinct actions, rules, statuses and signals), Custody Wars is at
roughly 75–93% of They Sing, comfortably past the 60% target. On
implementation depth per mechanic it is at about 18%. They Sing's mechanics
are individually richer: its engine is around 4.2k lines, its session
orchestration around 5.3k, and it has a large data layer and a three.js client
that are not counted at all. Read the 60% as met on breadth and mechanic
count, **not** on depth.

The two largest gaps are the ones that make They Sing distinctive:

- **The social and memetic layer (0.31).** They Sing models movements: their
  grievances, promises, authority and epistemic styles, stages and wings.
  Custody Wars models individual staff (traits, biases, shifts, morale,
  colleague pivots), which is the right grain for social engineering against
  custody, but it is much smaller.
- **The language layer (0.63).** They Sing's SING/1 lexicons (definitions,
  mutations, forks, rented access, decode receipts before reveal) have no
  counterpart here. Custody Wars' nearest equivalents are checkable
  attestations and sealed commitments, which give agents verifiable speech
  rather than an evolving shared language.

## Where Custody Wars goes further

These are strictly additions to the harness, not complexity claims:

- **No observation leak.** The Codex inventory pass found that They Sing's
  decision requests expose all units despite its stealth rules. Custody Wars
  builds each request from a fog-of-war view: hostile units appear only once
  exposed, and referee truth (mandate verdicts, attestation truth, which
  anomalies were noise) never appears. A test enforces this.
- **Webhook hardening.** HMAC-signed requests with a replay window, an
  idempotency key and bounded retries. Fallbacks are counted per seat and never
  silent (They Sing's bridge falls back locally, so the harness cannot see it).
- **A pull mode** for agents that can call HTTP but cannot host a webhook
  (Codex agents with curl), with token-scoped seats.
- **A sealed referee.** Each seat has a principal mandate in the RTG-0
  three-valued oracle, and every executed, failed or blocked action is labelled
  separately from whether the game let it through.
- **Invariants checked every step.** Credit conservation and a hash-chained
  trace.

## Next steps toward depth

In order of how much each would raise the weakest categories:

1. A crowd layer above the staff: retail depositors and online communities
   whose confidence reacts to rumours, attestations and incidents. Bank runs
   then become an emergent end condition. This targets row 10.
2. A shared incident vocabulary that seats can extend: indicator formats and
   trust ratings for threat-intel feeds, where a forged indicator is possible.
   This targets row 9, and is the custody analogue of SING/1.
3. A campaign clock with counterfactual pact projections in the NEGOTIATION
   request, as in They Sing's negotiation storyworld. This targets rows 12
   and 14.
