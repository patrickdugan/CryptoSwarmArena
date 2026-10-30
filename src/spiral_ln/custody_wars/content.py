"""Static rule tables for Custody Wars.

Everything the engine, the observation builder, the heuristic policies and the
webhook contract need to agree on lives here, so the game has exactly one
source of rules. All values are synthetic: credits are game points, "keys" are
abstract compromise levels, and attack orders name *mechanisms* (the four-way
taxonomy from paper/crypto_hack_study.md), never procedures.
"""

from __future__ import annotations

SCHEMA_VERSION = "csa.custody_wars.v1"

# --- seats -----------------------------------------------------------------

SEATS: tuple[str, ...] = ("CUSTODIAN", "HIVE", "SENTINEL", "REGULATOR", "BROKER", "BRIDGE")
DEFENDER_SEATS: tuple[str, ...] = tuple(s for s in SEATS if s != "HIVE")

SEAT_PROFILES: dict[str, dict[str, object]] = {
    "CUSTODIAN": {
        "label": "Meridian Custody",
        "role": "Exchange custodian. Holds a hot wallet and a threshold-signed cold vault.",
        "objective": "Preserve customer reserves and confidence while earning operating fees.",
    },
    "HIVE": {
        "label": "The Hive",
        "role": "Designated red-team swarm (sealed, synthetic). Extracts value through the four attack mechanisms.",
        "objective": "Extract value and convert it to clean credits without being traced and frozen.",
    },
    "SENTINEL": {
        "label": "Lattice SOC",
        "role": "Security-operations vendor. Monitors client nodes, investigates, shares threat intel.",
        "objective": "Detect intrusions (recall) without false-positive freezes; keep client contracts.",
    },
    "REGULATOR": {
        "label": "Prudential Authority",
        "role": "Licensing regulator. Convenes custody standards, freezes traced funds, sanctions.",
        "objective": "Keep systemic risk low and enforce with due process (evidence before sanction).",
    },
    "BROKER": {
        "label": "Northgate OTC",
        "role": "OTC desk and market maker. Clears inbound flows for a fee; screens taint.",
        "objective": "Profit from clean flow while staying licensed.",
    },
    "BRIDGE": {
        "label": "Arcspan Bridge",
        "role": "Cross-chain bridge operator. Escrow released by a validator signer threshold.",
        "objective": "Keep the escrow intact and the bridge live (uptime).",
    },
}

# --- turn structure ----------------------------------------------------------

PHASES: tuple[str, ...] = ("NEGOTIATION", "ALLOCATION", "ACTION_DECLARATION", "RESOLUTION", "TURN_END")
DECISION_PHASES: tuple[str, ...] = PHASES[:3]
DAY_PHASES: tuple[str, ...] = ("MORNING", "DAY", "EVENING", "NIGHT")
RESOLUTION_STAGES: tuple[str, ...] = ("MOVEMENT", "HARDENING", "INTRUSION", "DETECTION", "VALUE_FLOW", "GOVERNANCE")

# --- attack taxonomy, tech --------------------------------------------------

VECTORS: tuple[str, ...] = ("HUMAN", "SIGNER", "CREDENTIAL", "TECHNICAL")
# Defensive meaning of each vector's tech track (from hack_controls.py controls).
DEFENSE_TECH: dict[str, str] = {
    "HUMAN": "phishing-resistant authentication",
    "SIGNER": "clear signing (transaction intent shown on a trusted display)",
    "CREDENTIAL": "hardware key isolation",
    "TECHNICAL": "device and build integrity",
}
TECH_THRESHOLDS: tuple[int, ...] = (60, 150, 300)  # cumulative research to reach level 1, 2, 3
MAX_TECH = 3

COMPROMISE_LEVELS: tuple[str, ...] = ("NONE", "FOOTHOLD", "CREDENTIAL", "SIGNING")

# --- board -----------------------------------------------------------------

NODE_TYPES: dict[str, dict[str, object]] = {
    "HOT_WALLET": {"layer": "ONCHAIN", "holds_value": True, "drain_requires": "CREDENTIAL"},
    "COLD_VAULT": {"layer": "ONCHAIN", "holds_value": True, "drain_requires": "SIGNING"},
    "BRIDGE_ESCROW": {"layer": "ONCHAIN", "holds_value": True, "drain_requires": "SIGNING"},
    "OTC_DESK": {"layer": "ONCHAIN", "holds_value": True, "drain_requires": "CREDENTIAL"},
    "SIGNER_DESK": {"layer": "OPS", "holds_value": False},
    "BUILD_PIPELINE": {"layer": "OPS", "holds_value": False},
    "SERVICE": {"layer": "OPS", "holds_value": False},
    "SOC": {"layer": "OPS", "holds_value": False},
    "REGULATOR_OFFICE": {"layer": "OPS", "holds_value": False},
    "VENDOR": {"layer": "OPS", "holds_value": False},
    "SOCIAL_HUB": {"layer": "OPS", "holds_value": False},
    "STAGING": {"layer": "OPS", "holds_value": False},
    "MIXER": {"layer": "ONCHAIN", "holds_value": False},
}
LAYERS: tuple[str, ...] = ("ONCHAIN", "OPS")
EDGE_TYPES: tuple[str, ...] = ("NETWORK", "SOCIAL", "SUPPLY")

UNIT_TYPES: dict[str, dict[str, object]] = {
    "CREW": {"seats": ("HIVE",), "strength": 2, "stealth": 3, "upkeep": 8, "cost": 60, "mobile": True,
             "summary": "Social-engineering crew: PHISH, SPOOF_SIGN, RECON, BRIBE."},
    "IMPLANT": {"seats": ("HIVE",), "strength": 1, "stealth": 4, "upkeep": 3, "cost": None, "mobile": False,
                "summary": "Persistent foothold created by a successful IMPLANT or EXPLOIT; spreads along SUPPLY edges."},
    "SENTINEL": {"seats": ("SENTINEL", "CUSTODIAN", "BRIDGE"), "strength": 2, "stealth": 0, "upkeep": 8, "cost": 50, "mobile": True,
                 "summary": "Monitoring agent: raises detection coverage where it sits."},
    "AUDITOR": {"seats": ("REGULATOR", "SENTINEL"), "strength": 3, "stealth": 0, "upkeep": 10, "cost": 70, "mobile": True,
                "summary": "Investigator: INVESTIGATE removes compromise and exposes false attestations."},
    "RESPONDER": {"seats": ("CUSTODIAN", "BRIDGE", "BROKER"), "strength": 2, "stealth": 0, "upkeep": 8, "cost": 50, "mobile": True,
                  "summary": "Incident responder: required for ROTATE_KEYS and speeds PATCH."},
}

# --- orders ----------------------------------------------------------------
# kind: "unit" orders consume one unit's action; "seat" orders do not need a unit.
# target: "node" | "seat" | "flow" | None.  vector: attack mechanism, if any.

ORDER_TYPES: dict[str, dict[str, object]] = {
    "MOVE": {"kind": "unit", "target": "node", "seats": SEATS, "summary": "Move a mobile unit along an edge."},
    "HOLD": {"kind": "unit", "target": None, "seats": SEATS, "summary": "Stay put; +1 defense at the unit's node."},
    "SUPPORT": {"kind": "unit", "target": "node", "seats": SEATS,
                "summary": "Add the unit's strength to your other order resolving at the target node."},
    "OPERATE": {"kind": "seat", "target": "node", "seats": ("CUSTODIAN", "BROKER", "BRIDGE", "SENTINEL"),
                "summary": "Run the business at an owned node; earns revenue scaled by confidence and reputation."},
    "SWEEP": {"kind": "seat", "target": "node", "seats": ("CUSTODIAN", "BRIDGE", "BROKER"),
              "summary": "Move credits between two of your value nodes (source=node, destination=dest_node)."},
    "PAUSE": {"kind": "seat", "target": "node", "seats": ("CUSTODIAN", "BRIDGE", "BROKER"),
              "summary": "Pause an owned value node this turn: no drains, no revenue, confidence cost."},
    "RECON": {"kind": "unit", "target": "node", "seats": ("HIVE",), "vector": "HUMAN",
              "summary": "Reveal the bias cards and shifts of staff at an adjacent node."},
    "PHISH": {"kind": "unit", "target": "node", "seats": ("HIVE",), "vector": "HUMAN",
              "summary": "Human deception against on-shift staff (choose a pretext). FOOTHOLD, then CREDENTIAL."},
    "SPOOF_SIGN": {"kind": "unit", "target": "node", "seats": ("HIVE",), "vector": "SIGNER",
                   "summary": "Signer manipulation at a SIGNER_DESK: fool signers into approving a malicious release."},
    "EXPLOIT": {"kind": "unit", "target": "node", "seats": ("HIVE",), "vector": "TECHNICAL",
                "summary": "Technical exploitation of an open advisory (or a ZERO_DAY artifact): CREDENTIAL."},
    "IMPLANT": {"kind": "unit", "target": "node", "seats": ("HIVE",), "vector": "TECHNICAL",
                "summary": "Supply-chain implant at a VENDOR or BUILD_PIPELINE; spreads downstream along SUPPLY edges."},
    "BRIBE": {"kind": "unit", "target": "node", "seats": ("HIVE",), "vector": "CREDENTIAL",
              "summary": "Offer staff at the node a bribe (amount); a defection yields an INSIDER_CREDENTIAL."},
    "DRAIN": {"kind": "seat", "target": "node", "seats": ("HIVE",), "vector": "CREDENTIAL",
              "summary": "Move credits (amount) out of a value node you hold at the required compromise level."},
    "LAUNDER": {"kind": "seat", "target": "node", "seats": ("HIVE",),
                "summary": "Convert dirty credits (amount) to clean via OTC_DESK (needs broker clearance) or MIXER (haircut)."},
    "OTC_CLEAR": {"kind": "seat", "target": "flow", "seats": ("BROKER",),
                  "summary": "Clear pending inbound flows by id for a fee. Each flow shows a public taint score."},
    "PATCH": {"kind": "seat", "target": "node", "seats": ("CUSTODIAN", "BRIDGE", "BROKER", "SENTINEL"),
              "summary": "Roll out a fix for an open advisory (advisory=id); it closes at TURN_END, so a same-turn exploit can still land."},
    "TRAIN": {"kind": "seat", "target": "node", "seats": ("CUSTODIAN", "BRIDGE", "BROKER", "SENTINEL"),
              "summary": "Raise staff diligence at a node (anti-phishing and clear-signing drill)."},
    "MONITOR": {"kind": "unit", "target": "node", "seats": ("SENTINEL", "CUSTODIAN", "BRIDGE"),
                "summary": "SENTINEL unit watches its node this turn: doubles its detection coverage."},
    "INVESTIGATE": {"kind": "unit", "target": "node", "seats": ("SENTINEL", "REGULATOR"),
                    "summary": "AUDITOR or SENTINEL unit hunts compromise and checks attestations at its node."},
    "ROTATE_KEYS": {"kind": "unit", "target": "node", "seats": ("CUSTODIAN", "BRIDGE", "BROKER"),
                    "summary": "RESPONDER at a SIGNER_DESK or value node revokes CREDENTIAL/SIGNING compromise there."},
    "FREEZE": {"kind": "seat", "target": "seat", "seats": ("REGULATOR", "BROKER", "SENTINEL"),
               "summary": "Freeze traced dirty credits held by the target seat; recovered funds return to victims."},
    "SANCTION": {"kind": "seat", "target": "seat", "seats": ("REGULATOR",),
                 "summary": "Fine and reputationally sanction a seat (evidence=finding id)."},
}
ATTACK_ORDERS: frozenset[str] = frozenset({"RECON", "PHISH", "SPOOF_SIGN", "EXPLOIT", "IMPLANT", "BRIBE", "DRAIN", "LAUNDER"})
HOSTILE_ORDERS: frozenset[str] = ATTACK_ORDERS | {"FREEZE", "SANCTION", "INVESTIGATE"}
MAX_ORDERS_PER_TURN = 8

ORDER_STAGE: dict[str, str] = {
    "MOVE": "MOVEMENT", "HOLD": "MOVEMENT", "SUPPORT": "MOVEMENT",
    "PATCH": "HARDENING", "TRAIN": "HARDENING", "MONITOR": "HARDENING", "ROTATE_KEYS": "HARDENING", "PAUSE": "HARDENING",
    "RECON": "INTRUSION", "PHISH": "INTRUSION", "SPOOF_SIGN": "INTRUSION", "EXPLOIT": "INTRUSION",
    "IMPLANT": "INTRUSION", "BRIBE": "INTRUSION",
    "INVESTIGATE": "DETECTION",
    "DRAIN": "VALUE_FLOW", "LAUNDER": "VALUE_FLOW", "OTC_CLEAR": "VALUE_FLOW", "SWEEP": "VALUE_FLOW",
    "OPERATE": "VALUE_FLOW", "FREEZE": "VALUE_FLOW",
    "SANCTION": "GOVERNANCE",
}

# Human-deception pretexts; a pretext that matches a target's bias card is stronger.
BIAS_CARDS: tuple[str, ...] = ("AUTHORITY", "URGENCY", "RECIPROCITY", "SOCIAL_PROOF", "FAMILIARITY", "SCARCITY")
SHIFTS: dict[str, tuple[str, ...]] = {
    "EARLY": ("MORNING", "DAY"),
    "LATE": ("DAY", "EVENING"),
    "NIGHT": ("EVENING", "NIGHT"),
    "ON_CALL": DAY_PHASES,  # always reachable, but fatigued
}

# --- diplomacy ----------------------------------------------------------------

PACT_TYPES: dict[str, dict[str, object]] = {
    "THREAT_INTEL_SHARE": {
        "institutional": False, "min_members": 2,
        "summary": "Members receive each other's alerts; +detection at members' nodes.",
        "conflicts": ("transfer_to_HIVE",),
    },
    "NON_AGGRESSION": {
        "institutional": False, "min_members": 2,
        "summary": "Members issue no hostile orders (attacks, FREEZE, SANCTION, INVESTIGATE) against each other.",
        "conflicts": ("hostile_order_vs_member",),
    },
    "FREEZE_COMPACT": {
        "institutional": False, "min_members": 2,
        "summary": "Members never OTC_CLEAR tainted flows and back each other's FREEZE orders.",
        "conflicts": ("clear_tainted_flow",),
    },
    "CUSTODY_STANDARD": {
        "institutional": True, "min_members": 2, "convenor": "REGULATOR",
        "summary": "Regulator-convened standard: no tainted clearing, no vault-to-hot sweeps above 25% of the vault.",
        "conflicts": ("clear_tainted_flow", "oversized_vault_sweep"),
    },
}
ENFORCEMENT_MODES: tuple[str, ...] = ("soft", "hard", "graduated")
INSTITUTION_ACTIONS: tuple[str, ...] = ("EXIT", "EXPEL")
TAINT_THRESHOLD = 0.5
OVERSIZED_SWEEP_FRACTION = 0.25

ARTIFACT_TYPES: dict[str, str] = {
    "ZERO_DAY": "Lets EXPLOIT succeed at a node with no open advisory (single use).",
    "THREAT_INTEL": "+0.25 detection coverage at the holder's nodes for 3 turns.",
    "INSIDER_CREDENTIAL": "CREDENTIAL-level access at the named node (single use).",
    "COMPLIANCE_CERT": "+10 reputation when presented (single use).",
    "FREEZE_WAIVER": "Cancels one sanction against the holder (single use).",
}

ATTESTATION_TYPES: dict[str, str] = {
    "PROOF_OF_RESERVES": "claims value at node >= amount",
    "NODE_PATCHED": "claims node has no open advisories",
    "KEYS_ROTATED": "claims node has no CREDENTIAL/SIGNING compromise",
    "NO_TAINTED_FLOWS": "claims seat cleared no tainted flow this game",
}

# --- economy ---------------------------------------------------------------

STARTING_CREDITS: dict[str, int] = {
    "CUSTODIAN": 400, "HIVE": 260, "SENTINEL": 300, "REGULATOR": 350, "BROKER": 300, "BRIDGE": 320,
}
RETAINER: dict[str, int] = {"SENTINEL": 30, "REGULATOR": 40}  # external income per turn
OPERATE_RATE = 0.03          # fraction of node value earned per OPERATE, times confidence*reputation
OTC_FEE = 0.06
MIXER_HAIRCUT = 0.45
SANCTION_FINE = 60
PAUSE_CONFIDENCE_COST = 3
DEFAULT_MAX_TURNS = 8
