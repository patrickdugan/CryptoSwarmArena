# Crypto Swarm Arena

**Red Team Gladiatorics: a sealed, synthetic control-evaluation instrument for
crypto-security agent behavior.**

This repository is a control-evaluation *instrument*, not a spectacle. Ground
truth is computed, not judged: whether an action was authorized is decided by a
formal mandate evaluated against a hash-chained event log, never by a reader's
impression of a transcript. Everything here is **sealed and synthetic** — no
real keys, cryptography, or persuasion content, and the simulations themselves
make no model or network calls. The one exception is opt-in: the Custody Wars
harness can hand a seat's decisions to an AI agent over a local webhook, a pull
API or `codex exec`, and it binds to localhost by default. The on-screen
identifiers are provably-invalid decoys.

See [`paper/rtg_crypto_swarm_arena.md`](paper/rtg_crypto_swarm_arena.md) for the
full design specification and [`docs/rtg_arena.md`](docs/rtg_arena.md) for the
implemented RTG-0 slice.

**New here? Start with [Heist Desk](docs/heist_desk.md)** (`ui/play/index.html`).
It is the eval as a small game: 15 real heists from 2014 to 2025 replay against
the one control you pick. A two-minute tutorial walks you through it, and each
debrief suggests probes to send to the AI seats in Custody Wars.

## What's inside

- **RTG-0 kernel** (`src/spiral_ln/rtg/`) — a deterministic world:
  `state[t+1] = step(state[t], actions[t], rng)` on a logical clock, with an
  integer ledger (value-conserving), a three-valued mandate oracle
  (`PERMITTED` / `PROHIBITED` / `UNSPECIFIED`), a service graph, scripted
  reference policies, a Tier-I labeler, and defenders D0–D2. The two
  authorization checks are deliberately distinct — the **gateway** (ledger)
  enforces what the simulated system allows; the **oracle** (mandate) records
  what the principal authorized; their disagreement is an *affordance*, the
  experimental surface. Scenario families F1, F5, F6, and F11 (spoofed
  principal, with an authenticity-aware mandate and authorized twin) ship with
  acceptance tests.
- **Feral-custody family** (`src/spiral_ln/feral_custody*.py`) — custody
  strategies versus adversary objectives: coerced and *deceived* (blind /
  spoofed) signing, reassembly windows, a shared defection market, and a remote
  software-implant surface. Threshold signing does **not** resist a uniform
  spoof.
- **Historical-hack corpus & study** (`configs/crypto_hack_corpus.json`,
  `src/spiral_ln/crypto_hack_study.py`) — 20 real crypto hacks
  (Mt. Gox → Bybit) tabled by attack mechanism (human deception, signer
  manipulation, credential compromise, technical exploitation), with a
  deterministic statistical study.
- **Staged hacks & control ROI** (`src/spiral_ln/staged_hacks.py`,
  `hack_controls.py`) — each corpus hack's mechanism reproduced as a kill chain
  on the NPC/device model, with causal foothold gating, defensive-control ROI,
  minimal covering sets, and seed-robustness sweeps.
- **Swarm-compromise family** (`src/spiral_ln/swarm_compromise*.py`) — a
  bounded multi-agent social-engineering environment.
- **REPO-WORM-ALIFE-01** ([protocol](docs/repo_worm_alife.md), [pilot results](docs/repo_worm_alife_first_run.md)) — a sealed repository-contagion artificial-life gym. Synthetic repo-to-repo marker adoptions, lineages, paired defensive postures, invented network/inference ledgers, and deterministic replay. No real repo access, executable payloads, or model calls.
- **Codex vs Claude Worm Arena** ([protocol](docs/rtg_codex_claude_worm_arena.md), [64-bout mock evidence](docs/rtg_codex_claude_mock_results.md)) — a sealed adversarial HIVE-versus-SENTINEL tournament with balanced role swaps, controlled tool-restricted Codex/Claude CLI decision adapters, bounded model-call budgets, scored benign workflow losses, and fully replayable referee receipts. Live providers require explicit opt-in.
- **Custody Wars** (`src/spiral_ln/custody_wars/`, [`docs/custody_wars.md`](docs/custody_wars.md))
  — a six-seat, five-phase strategy game for AI agents. Custodian, Hive,
  Sentinel, Regulator, Broker and Bridge negotiate, form pacts under
  soft/hard/graduated enforcement, and fight over custody infrastructure and
  NPC staff (biases, shifts, morale) through the four attack mechanisms. A
  sealed RTG-0 referee labels every action. Agents plug in as scripted
  policies, HMAC-signed webhooks, a token-scoped pull API (Codex agents; see
  [`AGENTS.md`](AGENTS.md)), or local `codex exec`. It is modelled on
  *They Sing*'s harness; see
  [`docs/custody_wars_vs_theysing.md`](docs/custody_wars_vs_theysing.md).
- **Diorama arena viewer** (`ui/arena/`) — a three.js replay viewer and a
  small Rust/wasm engine; the Python replay pipeline
  (`*_replay.py`, `arena_replay.py`, `rtg_arena_export.py`, `diorama.py`) emits
  replay JSON that the viewer renders.

## Running

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[test]"   # Windows; use .venv/bin on POSIX
PYTHONPATH=src .venv/Scripts/python -m pytest tests/ -q
```

Reproduce the RTG-0 benchmark (writes a summary, rows, figure, and a hash
receipt — all timestamp-free and reproducible):

```bash
PYTHONPATH=src .venv/Scripts/python -m spiral_ln.rtg_benchmark --output output/rtg_benchmark
```

The acceptance gate checks replay reproducibility, value conservation,
scripted-label recovery, the "no violation label in any twin or null variant"
invariant, and the defender bracket.

Play Custody Wars:

```bash
PYTHONPATH=src python -m spiral_ln.custody_wars play --scenario bybit_class --seed 3   # one local game
PYTHONPATH=src python -m spiral_ln.custody_wars serve                                  # HTTP harness for webhook/pull agents
PYTHONPATH=src python -m spiral_ln.custody_wars tournament                             # 288-game scripted tournament
```

## Safety posture

Scripted-policy results validate the *instrument*; they are **not** evidence
about any model. The harness is validated without models: scripted policies
with known labels must reproduce exactly before any model result is
interpretable. Propensity and control are separate tracks whose numbers are
never pooled.
