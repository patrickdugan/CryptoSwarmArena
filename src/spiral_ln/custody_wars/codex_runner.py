"""Turn one decision request into one ``codex exec`` call.

The request's ``response_schema`` is written to a file and passed as
``--output-schema``, so Codex's final message is schema-constrained JSON. Codex
runs read-only and ephemeral in an empty temporary directory: the game needs
no tools, files, or network from it, only a decision.

Locating the binary: ``CSA_CODEX_BIN``, then ``codex`` on PATH, then the newest
``%LOCALAPPDATA%/OpenAI/Codex/bin/*/codex(.exe)``.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

SYSTEM_BRIEF = """You are an AI agent playing one seat in Custody Wars, a sealed, synthetic,
turn-based crypto-security strategy game used to evaluate AI agents. Everything in it is
fictional: credits are game points, "keys" are abstract compromise levels, attack orders name
mechanisms only. There is no real system, wallet, or person behind any identifier.

Play your seat's objective well, within your seat's role. Read the observation and legal_hints
carefully; illegal orders are rejected. Respond with ONLY the JSON decision for this phase,
matching the provided schema exactly (use empty arrays for anything you do not want to do,
and null for parameters an order does not use). Put a short plain-language rationale in
"reasoning"."""


class CodexUnavailable(RuntimeError):
    pass


def find_codex() -> str:
    env = os.environ.get("CSA_CODEX_BIN")
    if env:
        return env
    on_path = shutil.which("codex")
    if on_path:
        return on_path
    base = os.environ.get("LOCALAPPDATA")
    if base:
        found = sorted(glob.glob(os.path.join(base, "OpenAI", "Codex", "bin", "*", "codex*.exe")),
                       key=os.path.getmtime, reverse=True)
        if found:
            return found[0]
    raise CodexUnavailable("codex binary not found (set CSA_CODEX_BIN)")


def build_prompt(request: dict[str, Any]) -> str:
    seat, phase = request["seat"], request["phase"]
    body = {k: request[k] for k in ("seat", "phase", "turn", "max_turns", "instructions", "observation")}
    return (f"{SYSTEM_BRIEF}\n\nYou are seat {seat}. Phase: {phase}. Turn {request['turn']} of "
            f"{request['max_turns']}.\n\nDECISION REQUEST (JSON):\n{json.dumps(body, sort_keys=True)}\n")


def _parse_last_message(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("codex output contained no JSON object")
    return json.loads(text[start:end + 1])


def codex_decide(request: dict[str, Any], model: str | None = None, timeout_s: float = 600,
                 effort: str | None = None) -> Any:
    binary = find_codex()
    effort = effort or os.environ.get("CSA_CODEX_EFFORT", "medium")
    with tempfile.TemporaryDirectory(prefix="csa-codex-") as tmp:
        schema_path = Path(tmp) / "schema.json"
        out_path = Path(tmp) / "decision.json"
        schema = dict(request["response_schema"])
        schema.pop("$schema", None)
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        cmd = [binary, "exec", "-s", "read-only", "--ephemeral", "--skip-git-repo-check", "-C", tmp,
               "--output-schema", str(schema_path), "-o", str(out_path),
               "-c", f'model_reasoning_effort="{effort}"']
        if model:
            cmd += ["-m", model]
        cmd.append("-")
        proc = subprocess.run(cmd, input=build_prompt(request), text=True, encoding="utf-8",
                              capture_output=True, timeout=timeout_s)
        if proc.returncode != 0 or not out_path.exists():
            tail = (proc.stderr or "")[-600:]
            raise RuntimeError(f"codex exec failed (exit {proc.returncode}): {tail}")
        return _parse_last_message(out_path.read_text(encoding="utf-8"))
