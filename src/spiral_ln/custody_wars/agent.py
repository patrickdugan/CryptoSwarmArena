"""Pull-mode seat driver: plays one seat against a running harness.

    python -m spiral_ln.custody_wars agent --server http://127.0.0.1:8788 \\
        --session cw-... --seat BROKER --token <seat_token> --mode codex

Loop: GET /sessions/{id}/decision-request?seat=S (204 = nothing pending), decide
(``codex`` runs codex exec; ``policy`` uses the scripted heuristic), POST the
decision. Exits when the session reports game_over.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any

from .codex_runner import codex_decide
from .policies import decide


def _call(method: str, url: str, token: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"authorization": f"Bearer {token}", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - operator-supplied harness URL
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def play(server: str, session: str, seat: str, token: str, mode: str = "policy", model: str | None = None,
         poll_s: float = 1.0, max_idle_s: float = 3600) -> int:
    base = server.rstrip("/") + f"/sessions/{session}"
    idle = 0.0
    decided = 0
    while True:
        status, req = _call("GET", f"{base}/decision-request?seat={seat}", token)
        if status == 200:
            decision = codex_decide(req, model=model) if mode == "codex" else decide(req["observation"], req["phase"])
            code, result = _call("POST", f"{base}/decisions", token,
                                 {"seat": seat, "request_id": req["request_id"], "decision": decision})
            print(f"[{seat}] turn {req['turn']} {req['phase']}: {code} {result}", flush=True)
            decided += 1
            idle = 0.0
            continue
        if status != 204:
            print(f"[{seat}] harness error {status}: {req}", file=sys.stderr)
            return 1
        _, summary = _call("GET", base, token)
        if summary and summary.get("game_over"):
            print(f"[{seat}] game over ({summary.get('end_reason')}); {decided} decisions", flush=True)
            return 0
        time.sleep(poll_s)
        idle += poll_s
        if idle > max_idle_s:
            print(f"[{seat}] idle timeout", file=sys.stderr)
            return 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Play one Custody Wars seat over the pull API")
    ap.add_argument("--server", default="http://127.0.0.1:8788")
    ap.add_argument("--session", required=True)
    ap.add_argument("--seat", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--mode", choices=("policy", "codex"), default="policy")
    ap.add_argument("--model")
    args = ap.parse_args(argv)
    return play(args.server, args.session, args.seat, args.token, args.mode, args.model)


if __name__ == "__main__":
    raise SystemExit(main())
