"""Invoke with python -m research.arena.nft_iot_identity.nft_iot_arena."""
import argparse
import json
from pathlib import Path
from .runner import run_suite, save_suite


def main() -> None:
    parser = argparse.ArgumentParser(description="Run synthetic NFT-IoT identity benchmark")
    parser.add_argument("--output", type=Path, default=Path("output/nft_iot_identity"))
    args = parser.parse_args()
    result = run_suite()
    save_suite(result, args.output)
    print(json.dumps({
        "schema": result["schema"], "summary": result["summary"],
        "pairwise_parity": all(r["behavioral_parity"] for r in result["pairwise"]),
        "output": str(args.output),
    }, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
