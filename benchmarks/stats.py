"""Small statistics helpers shared by the benchmark scripts."""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion k/n (95% by default)."""
    if n <= 0:
        return (0.0, 0.0)
    if not 0 <= k <= n:
        raise ValueError(f"k={k} must be between 0 and n={n}")
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    lo = 0.0 if k == 0 else max(0.0, min(p, center - half))
    hi = 1.0 if k == n else min(1.0, max(p, center + half))
    return (lo, hi)


@dataclass
class Counts:
    """Confusion counts for one group of benchmark cases."""

    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0

    def add(self, vulnerable: bool, detected: bool) -> None:
        if vulnerable and detected:
            self.tp += 1
        elif vulnerable:
            self.fn += 1
        elif detected:
            self.fp += 1
        else:
            self.tn += 1

    @property
    def recall(self) -> float | None:
        n = self.tp + self.fn
        return self.tp / n if n else None

    @property
    def fpr(self) -> float | None:
        n = self.fp + self.tn
        return self.fp / n if n else None

    @property
    def precision(self) -> float | None:
        n = self.tp + self.fp
        return self.tp / n if n else None

    def as_dict(self) -> dict[str, object]:
        return {
            "tp": self.tp,
            "fn": self.fn,
            "fp": self.fp,
            "tn": self.tn,
            "recall": self.recall,
            "recall_ci95": wilson(self.tp, self.tp + self.fn) if self.tp + self.fn else None,
            "fpr": self.fpr,
            "fpr_ci95": wilson(self.fp, self.fp + self.tn) if self.fp + self.tn else None,
        }


def fmt(x: float | None, digits: int = 3) -> str:
    """Format a ratio for Markdown tables; None becomes n/a."""
    return "n/a" if x is None else f"{x:.{digits}f}"


def share(items: Iterable[bool]) -> tuple[int, int]:
    """Count true values and total."""
    k = n = 0
    for x in items:
        n += 1
        k += bool(x)
    return k, n
