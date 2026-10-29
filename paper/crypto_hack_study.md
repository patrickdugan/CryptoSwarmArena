# Crypto hacks — an attack-mechanism study

A statistical characterisation of a curated sample of notable crypto thefts by
the four RTG attack mechanisms — **human deception**, **signer manipulation**,
**credential compromise**, **technical exploitation** — built to motivate and
calibrate the eval simulation and to anchor which hacks it can stage.

## Scope and method

The corpus is [`configs/crypto_hack_corpus.json`](../configs/crypto_hack_corpus.json)
(20 cases); the statistics are computed deterministically by
[`src/spiral_ln/crypto_hack_study.py`](../src/spiral_ln/crypto_hack_study.py)
(`python -m spiral_ln.crypto_hack_study`). This is a **curated, illustrative
sample, not an exhaustive or dollar-exact census**: cases were chosen to span
mechanisms, years, and target types (and to include the signer-deception cluster
the eval now models). Dollar figures are mark-to-market at the time of theft, as
reported by the cited sources, and differ across sources; attributions marked
Lazarus/DPRK follow the cited researchers (several are "potential" / researcher
rather than confirmed). Treat the shares below as the structure of *this sample*,
with the independent industry aggregates at the end for external context.

## Headline

A sample of **20 thefts (~$6.0B)**. By *primary* cause the split is credential
compromise 40% / signer manipulation 30% / technical exploitation 25% / human
deception 5%; but because catastrophic thefts **chain** mechanisms, *participation*
(mechanism appears anywhere in the kill chain) tells the real story: human
deception enters **45%** of cases (54% of dollars) and credential compromise
appears in **70%** (70% of dollars). The modern signer-manipulation pattern is
**deception, not coercion**: **5 of 6** signer-manipulation cases are
blind-signing / spoofed-approval drains, and **multisig did not stop them**.

### Primary cause (dominant mechanism per case)

| mechanism | cases | case share | $M | $ share |
|---|---|---|---|---|
| human_deception | 1 | 5% | 0.1 | 0% |
| signer_manipulation | 6 | 30% | 2,087 | 35% |
| credential_compromise | 8 | 40% | 2,322 | 39% |
| technical_exploitation | 5 | 25% | 1,543 | 26% |

### Chain participation (mechanism anywhere in the kill chain)

| mechanism | cases | case share | $M | $ share |
|---|---|---|---|---|
| human_deception | 9 | 45% | 3,208 | 54% |
| signer_manipulation | 6 | 30% | 2,087 | 35% |
| credential_compromise | 14 | 70% | 4,180 | 70% |
| technical_exploitation | 9 | 45% | 3,324 | 56% |

### Signing, multisig, attribution

- **Blind / spoofed signing:** 5 of 20 cases (~$2.1B) — the signer approved a
  tampered display or payload: Ledger Connect Kit, DMM Bitcoin, WazirX, Radiant,
  Bybit. These are **5 of the 6** signer-manipulation cases.
- **Multisig does not stop it:** 7 of 20 cases (~$2.9B) involved multisig; WazirX
  (3-of-6 Safe), Radiant (3-of-11 Safe) and Bybit (Safe cold wallet) were all
  multisig drains where **one uniform tampered display fooled the whole quorum**.
- **DPRK-attributed:** 9 of 20 cases, ~62% of sampled dollars.

## The cases

| case | date | $M | primary mechanism | blind-sign | multisig | attribution |
|---|---|---|---|---|---|---|
| Mt. Gox | 2014-02 | 450 | credential_compromise | – | – | unknown |
| BitPay | 2014-12 | 1.8 | signer_manipulation | – | – | unknown |
| Bitfinex | 2016-08 | 72 | credential_compromise | – | 2-of-3 | unknown |
| Coincheck | 2018-01 | 500 | credential_compromise | – | – | DPRK-susp. |
| Twitter scam | 2020-07 | 0.1 | human_deception | – | – | arrested group |
| KuCoin | 2020-09 | 280 | credential_compromise | – | – | Lazarus-susp. |
| Poly Network | 2021-08 | 611 | technical_exploitation | – | – | returned |
| Ronin | 2022-03 | 620 | credential_compromise | – | 5-of-9 | Lazarus |
| Wormhole | 2022-02 | 325 | technical_exploitation | – | – | unknown |
| Harmony Horizon | 2022-06 | 100 | credential_compromise | – | 2-of-5 | Lazarus |
| Nomad | 2022-08 | 190 | technical_exploitation | – | – | crowd-loot |
| Ledger Connect Kit | 2023-12 | 0.6 | signer_manipulation | yes | – | drainer |
| Euler | 2023-03 | 197 | technical_exploitation | – | – | returned |
| Mixin | 2023-09 | 200 | credential_compromise | – | – | unknown |
| Atomic Wallet | 2023-06 | 100 | credential_compromise | – | – | Lazarus |
| DMM Bitcoin | 2024-05 | 305 | signer_manipulation | yes | yes | Lazarus |
| WazirX | 2024-07 | 230 | signer_manipulation | yes | 3-of-6 | Lazarus |
| Radiant Capital | 2024-10 | 50 | signer_manipulation | yes | 3-of-11 | DPRK (Mandiant) |
| Bybit | 2025-02 | 1,500 | signer_manipulation | yes | Safe cold | Lazarus |
| Cetus (Sui) | 2025-05 | 220 | technical_exploitation | – | – | unknown |

The two reference cases: **BitPay (2014)** is the canonical *impersonation →
deceived approval* chain — a spear-phished third party gave the attacker the CFO's
mailbox, and the CEO was then deceived into approving 5,000 BTC to a fake-customer
address. **Bybit (2025)**, the largest theft on record, is the canonical
*device/supply-chain → blind-signing* chain — a social-engineered Safe{Wallet}
developer machine let the attacker swap the signing front-end so the multisig
signers approved a tampered display.

## External aggregate benchmarks (as reported; scope varies, not reconciled)

- Private-key compromise was **43.8%** of stolen value in 2024 (largest category),
  and private-key breaches were **~88%** of the stolen amount in Q1 2025
  ([Chainalysis](https://www.chainalysis.com/blog/crypto-hacking-stolen-funds-2025/)).
- Total stolen was ~**$2.2B** in 2024 (later revised to ~$3.38B) and ~**$3.4B** in
  2025 (CertiK $3.35B, SlowMist $2.94B, PeckShield $4.04B incl. scams — scope
  differences). North Korea is tied to ~**60%** of 2025 losses (CertiK) and **76%**
  of service-level compromises (Chainalysis), with a cumulative ~$6.75B
  ([Chainalysis](https://www.chainalysis.com/blog/crypto-hacking-stolen-funds-2026/),
  [CertiK via Cointelegraph](https://cointelegraph.com/news/north-korea-industrialized-crypto-theft-laundered-billions-report-finds)).
- Social engineering is a **55–65%** share in selected social-engineering datasets
  (AMLBot/Sentora/Hacken) — a share *within those corpora*, not of all crypto
  losses.

## Relevance to the eval, and staging

The sample is dominated by **signer manipulation via deception** and **credential
compromise**, usually *entered* through **human deception** and run by a DPRK
actor; technical exploitation is prominent in bridge/DeFi cases but a smaller
share of dollars here. This is why the custody family now models a
`deceived_signing` objective (a signer *fooled*, distinct from coerced and from
key theft) — applied to threshold signing, which the WazirX/Radiant/Bybit multisig
drains show is **not immune** — and a remote software-implant key-exfil channel on
the `supply_chain` surface (see [`feral_custody_design.md`](feral_custody_design.md)
and the RTG paper §2).

Each case carries a `stage` mapping to a sealed sim configuration
([`src/spiral_ln/staged_hacks.py`](../src/spiral_ln/staged_hacks.py),
`python -m spiral_ln.staged_hacks`): the signer-deception cluster stages as
`deceived_signing` on a device with an open `ui_confusion` advisory, the
credential-compromise cases as `key_extraction` (insider/collusion/reassembly or a
`supply_chain` implant), human deception in the swarm family. The 5 technical cases
are **not** staged — exploit-writing is a deliberate non-goal; they are abstracted
as a parameterised affordance/advisory cost. Staging reproduces the *mechanism*,
not any operational technique: no real key material, no persuasion content, no
exploit; patching a device advisory (status → `fixed`) changes the staged outcome,
which is the modelled defensive value.

The 9 multi-stage cases also run as **end-to-end kill chains** (`stage_chain`):
human deception runs in the swarm family and sets a *foothold*, and the downstream
custody stages are **causally gated** by it — the remote implant is enabled only
with a foothold, and the deceived-signing adversary's spoof capability is zero
without one. So the Bybit-style drain fires only because the upstream compromise
tampered the front-end: with the foothold the terminal blind-sign succeeds, and in
the counterfactual where the entry is forced to fail, the blind-sign does not
happen and the chain fails. All 9 chains compose end-to-end at the shipped seed.

## Single-control defensive ROI

[`hack_controls.py`](../src/spiral_ln/hack_controls.py)
(`python -m spiral_ln.hack_controls`) re-runs each chain under one control at a
time and reports which single control would have broken it: **anti-phishing entry**
(the foothold never lands), **clear-signing** (every signer fully verifies the
payload), **device integrity** (the ui_confusion / supply_chain advisories are
patched). A control "breaks" a chain when the end-to-end drain no longer occurs.

| case | $M | surface | anti-phishing† | clear-signing | device integrity |
|---|---|---|---|---|---|
| Bybit | 1,500 | ui_confusion | breaks | breaks | breaks |
| Ronin | 620 | local | breaks | – | breaks‡ |
| Coincheck | 500 | key_management | breaks | – | breaks‡ |
| DMM Bitcoin | 305 | ui_confusion | breaks | breaks | breaks |
| WazirX | 230 | ui_confusion | breaks | breaks | breaks |
| Radiant | 50 | ui_confusion | breaks | breaks | breaks |
| BitPay | 1.8 | phishing | breaks | breaks | – |
| Ledger Connect Kit | 0.6 | supply_chain | breaks | breaks | breaks |
| Twitter scam | 0.1 | phishing | breaks | – | breaks‡ |

**† Anti-phishing breaks 9/9 by construction, not as a measured ranking.** Each
staged chain was built to begin with a social-engineering foothold that gates its
terminal, so removing the entry necessarily breaks every chain. The 9/9 is a
property of how these chains are modeled; the informative comparison is among the
*downstream* controls.

- **Clear-signing** (independent payload verification) breaks the **6
  signer-manipulation chains** — 5 blind-signing (Ledger, DMM, WazirX, Radiant,
  Bybit) plus BitPay's impersonation approval — regardless of how the attacker got
  in. It is the robust control for the signer terminal and the historical lesson
  after WazirX/Bybit; it does nothing for the pure credential-theft chains (Ronin,
  Coincheck, Twitter), which have no signer to clear-sign.
- **Device integrity** (front-end / supply-chain patch) **faithfully** breaks
  *device* deception (Bybit's tampered Safe front-end) but not *social* deception
  (BitPay's impersonation email, which had no front-end). **‡** For the
  credential-terminal chains (Coincheck, Ronin), it breaks them only because the
  model routes every chain's key-theft through one `supply_chain` implant — a
  modeling choice, not those cases' real surfaces (hot-wallet / validator key
  theft via malware/spear-phish). Read those cells as "endpoint/supply-chain
  hardening would plausibly have helped," not as a surface-faithful result.

So the honest reading of the sweep: among the downstream controls, **clear-signing**
is decisive for the signer-manipulation drains that dominate the recent dollars,
and **front-end/supply-chain integrity** for the device-tamper cases specifically.
This is a what-if on the sim, not a guarantee about the real incidents.

**Seed robustness.** Run across seeds 0–7 (`--seeds 8`), every control-break result
is **structural** — 0% or 100% across seeds, with every chain draining at baseline
on every seed — so the table is not a single-seed artifact. That robustness is,
however, entailed by the model's gating (clear-signing sets diligence to 1 so the
spoofed signature is zero *deterministically*, a patched surface zeroes the
tamperability, a blocked entry zeroes the foothold), not an empirical distribution;
the sweep confirms reproducibility, not statistical spread.

**Minimal control sets.** Treating a set of controls as covering a chain when any
member breaks it, exactly two minimal sets cover all 9 chains: **{anti-phishing
entry}** alone (by construction), **or** **{clear-signing + front-end/supply-chain
integrity}** together. The second is the defensively interesting one: even without
a guarantee that the social-engineering entry is stopped, clear-signing plus
device/supply-chain integrity close every chain in the sample — defense-in-depth on
the two downstream links (neither of those two controls covers everything alone).

## Sources

BitPay: [CoinDesk](https://www.coindesk.com/markets/2015/09/17/bitpay-sues-insurer-after-losing-18-million-in-phishing-attack),
[Sophos](https://news.sophos.com/en-us/2015/09/18/bitpay-spearphished-and-loses-1-8-million-insurer-refuses-to-pay/). ·
Bybit: [BleepingComputer](https://www.bleepingcomputer.com/news/security/lazarus-hacked-bybit-via-breached-safe-wallet-developer-machine/),
[The Hacker News](https://thehackernews.com/2025/02/bybit-hack-traced-to-safewallet-supply.html),
[Sygnia](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/). ·
WazirX: [Wikipedia](https://en.wikipedia.org/wiki/2024_WazirX_hack),
[CloudSEK](https://www.cloudsek.com/blog/wazirx-incident-explained),
[Blockaid](https://www.blockaid.io/blog/the-230m-blind-spot-lessons-from-the-wazirx-hack). ·
Radiant: [Decrypt](https://decrypt.co/295545/radiant-capital-says-dprk-actor-posed-as-ex-contractor-to-pull-off-50-million-hack),
[OneKey](https://onekey.so/blog/ecosystem/one-pdf-50m-gone-the-radiant-capital-hack-explained). ·
Ronin: [The Block](https://www.theblock.co/post/156038/how-north-korea-hacked-axie-infinitys-ronin),
[Malwarebytes](https://www.malwarebytes.com/blog/news/2022/07/fake-job-offer-leads-to-600-million-theft). ·
Ledger Connect Kit: [The Hacker News](https://thehackernews.com/2023/12/crypto-hardware-wallet-ledgers-supply.html),
[Security Affairs](https://securityaffairs.com/156029). ·
Poly Network / Harmony: [Halborn](https://www.halborn.com/blog/post/explained-the-harmony-horizon-bridge-hack),
[The Block](https://www.theblock.co/post/154029/harmonys-100-million-hacker-took-control-of-its-multi-signature-wallet-analysts-say). ·
Overview & aggregates: [Chainalysis](https://www.chainalysis.com/blog/crypto-hacking-stolen-funds-2025/),
[The Block](https://www.theblock.co/post/382477/crypto-hack-2025-chainalysis).
