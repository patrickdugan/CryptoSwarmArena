"""Inline the Heist Desk scenarios JSON into the page template.

Run from the repository root after generating the scenarios:

    python -m spiral_ln.hack_game --out ui/play/scenarios.json
    python ui/play/build_play.py

The template carries ``__SCENARIOS_JSON__`` inside
``<script id="scenarios-data" type="application/json">``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

PLACEHOLDER = "__SCENARIOS_JSON__"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", default="ui/play/index.template.html")
    parser.add_argument("--scenarios", default="ui/play/scenarios.json")
    parser.add_argument("--out", default="ui/play/index.html")
    args = parser.parse_args(argv)

    template = Path(args.template).read_text(encoding="utf-8")
    if PLACEHOLDER not in template:
        raise ValueError(f"template has no {PLACEHOLDER} placeholder")
    data = json.loads(Path(args.scenarios).read_text(encoding="utf-8"))
    compact = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    if "</script" in compact.lower():
        raise ValueError("scenarios data contains a closing script tag; refusing to inline")
    html = template.replace(PLACEHOLDER, compact)
    Path(args.out).write_text(html, encoding="utf-8", newline="\n")
    print(f"wrote {args.out} ({len(html)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
