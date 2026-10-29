"""Build the Rust engine to WebAssembly and copy it next to the viewer.

    python ui/arena/engine/build_engine.py

The resulting ``diorama_engine.wasm`` is committed, so building the arena page
(``ui/arena/build_arena.py``) never needs a Rust toolchain; rebuild it only after
changing ``src/lib.rs`` (and keep ``engine_ref.js`` in lockstep; the parity test
in ``tests/test_engine.py`` checks them against each other).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    cargo = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / ("cargo.exe" if os.name == "nt" else "cargo"))
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", HERE / "target"))
    env = dict(os.environ, CARGO_TARGET_DIR=str(target_dir))
    subprocess.run([cargo, "build", "--release", "--target", "wasm32-unknown-unknown"], cwd=HERE, check=True, env=env)
    built = target_dir / "wasm32-unknown-unknown" / "release" / "diorama_engine.wasm"
    shutil.copyfile(built, HERE / "diorama_engine.wasm")
    print(f"wrote {HERE / 'diorama_engine.wasm'} ({built.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
