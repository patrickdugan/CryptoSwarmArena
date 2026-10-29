"""Inline a replay JSON (and the animation engine) into the arena template to produce a self-contained page.

Run from the repository root after generating a replay:

    # swarm-compromise arena (defaults)
    python -m spiral_ln.swarm_replay --output output/swarm_compromise/replay.json
    python ui/arena/build_arena.py

    # RTG control arena
    python -m spiral_ln.rtg_arena_export --output output/rtg_arena/replay.json
    python ui/arena/build_arena.py --replay output/rtg_arena/replay.json --out ui/arena/rtg_index.html

The page also carries the Rust animation engine (``ui/arena/engine/diorama_engine.wasm``,
base64) and its JavaScript reference (``ui/arena/engine/engine_ref.js``), which the viewer
falls back to if WebAssembly is unavailable.  If the .wasm is missing the page still works
on the reference alone.
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parent / "engine"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", default="ui/arena/index.template.html")
    parser.add_argument("--replay", default="output/swarm_compromise/replay.json")
    parser.add_argument("--out", default="ui/arena/index.html")
    parser.add_argument("--title", default=None, help="override the page <title>")
    parser.add_argument("--engine", default=str(ENGINE_DIR / "diorama_engine.wasm"))
    parser.add_argument("--engine-ref", default=str(ENGINE_DIR / "engine_ref.js"))
    args = parser.parse_args(argv)

    template = Path(args.template).read_text(encoding="utf-8")
    data = Path(args.replay).read_text(encoding="utf-8")
    if "</script" in data.lower():
        raise ValueError("replay data contains a closing script tag; refusing to inline")
    ref = Path(args.engine_ref).read_text(encoding="utf-8")
    if "</script" in ref.lower():
        raise ValueError("engine reference contains a closing script tag; refusing to inline")
    html = template.replace("/*__ENGINE_REF_JS__*/", ref)
    wasm = Path(args.engine)
    if wasm.exists():
        html = html.replace("__ENGINE_WASM_B64__", base64.b64encode(wasm.read_bytes()).decode("ascii"))
    html = html.replace("__REPLAY_JSON__", data)
    if args.title:
        import re

        html = re.sub(r"<title>.*?</title>", f"<title>{args.title}</title>", html, count=1)
    Path(args.out).write_text(html, encoding="utf-8")
    print(f"wrote {args.out} ({len(html)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
