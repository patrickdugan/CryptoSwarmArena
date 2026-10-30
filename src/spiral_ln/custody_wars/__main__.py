"""CLI: python -m spiral_ln.custody_wars <command> [...]

    serve        headless HTTP harness (server.py)
    bridge       webhook bridge: policy | codex | openai (bridge.py)
    agent        play one seat over the pull API (agent.py)
    play         run one local game with a session config and print the referee report
    tournament   scripted tournament (tournament.py)
    schema       print the decision JSON Schema for a phase
"""

from __future__ import annotations

import json
import sys


def _play(argv: list[str]) -> int:
    import argparse

    from .session import Session

    ap = argparse.ArgumentParser(description="Run one local Custody Wars game")
    ap.add_argument("--config", help="session config JSON (agents may be heuristic, webhook or codex)")
    ap.add_argument("--scenario")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--mode", dest="enforcement_mode")
    ap.add_argument("--log-dir")
    args = ap.parse_args(argv)
    config = {}
    if args.config:
        with open(args.config, encoding="utf-8") as fh:
            config = json.load(fh)
    for key in ("scenario", "seed", "enforcement_mode", "log_dir"):
        if getattr(args, key) is not None:
            config[key] = getattr(args, key)
    if any(a.get("type") == "pull" for a in (config.get("agents") or {}).values() if isinstance(a, dict)):
        print("pull seats need the HTTP harness: use `serve`", file=sys.stderr)
        return 2
    session = Session(config)
    session.run()
    print(json.dumps(session.referee_report(), indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "serve":
        from .server import main as run
        return run(rest)
    if cmd == "bridge":
        from .bridge import main as run
        return run(rest)
    if cmd == "agent":
        from .agent import main as run
        return run(rest)
    if cmd == "tournament":
        from .tournament import main as run
        return run(rest)
    if cmd == "play":
        return _play(rest)
    if cmd == "schema":
        from .contract import response_schema
        print(json.dumps(response_schema(rest[0] if rest else "ACTION_DECLARATION"), indent=2))
        return 0
    print(f"unknown command {cmd}\n{__doc__}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
