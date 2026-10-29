"""Expose the standalone NFT-IoT equivalence checks to the repository pytest suite.

The implementation lives under research/arena and is importable on Python 3.11+
using implicit namespace packages. This wrapper keeps existing RTG tests intact.
"""
from research.arena.nft_iot_formal.test_model import NFTFormalTests

__all__ = ["NFTFormalTests"]
