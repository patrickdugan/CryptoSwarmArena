"""Small, dependency-free statistical helpers shared by the awareness and
key-value probes: an exact one-sided sign test and a Wilson score interval.

These are stdlib-only (``math.comb`` / ``math.sqrt``) so the arena's probe
modules carry no third-party statistics dependency."""

from __future__ import annotations

from math import comb, sqrt
from typing import Sequence


def _one_sided_sign_p_value(deltas: Sequence[float]) -> float:
    """Exact P(positive signs >= observed) after discarding ties."""

    signs = [delta for delta in deltas if delta != 0.0]
    n = len(signs)
    if n == 0:
        return 1.0
    positives = sum(delta > 0.0 for delta in signs)
    return sum(comb(n, k) for k in range(positives, n + 1)) / (2**n)


def _wilson_interval(successes: int, total: int, z: float = 1.96) -> list[float]:
    if total == 0:
        return [0.0, 1.0]
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    half_width = (
        z
        * sqrt(proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total))
        / denominator
    )
    return [max(0.0, center - half_width), min(1.0, center + half_width)]
