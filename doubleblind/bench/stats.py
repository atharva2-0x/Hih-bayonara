"""Tiny, dependency-free statistics for the benchmarks."""

from __future__ import annotations

import math
import random
import statistics


def percentile(xs: list[float], p: float) -> float:
    if not xs:
        return float("nan")
    s = sorted(xs)
    k = (len(s) - 1) * p / 100
    f, c = math.floor(k), math.ceil(k)
    return s[f] if f == c else s[f] + (s[c] - s[f]) * (k - f)


def summary(xs: list[float]) -> dict:
    return {"n": len(xs), "p50": round(percentile(xs, 50), 2), "p95": round(percentile(xs, 95), 2),
            "mean": round(statistics.fmean(xs), 2) if xs else None}


def _standardize(X: list[list[float]]) -> list[list[float]]:
    cols = list(zip(*X))
    mus = [statistics.fmean(c) for c in cols]
    sds = [statistics.pstdev(c) or 1.0 for c in cols]
    return [[(v - m) / s for v, m, s in zip(row, mus, sds)] for row in X]


def _folds(n: int, k: int, rng: random.Random) -> list[list[int]]:
    idx = list(range(n))
    rng.shuffle(idx)
    return [idx[i::k] for i in range(k)]


def knn_cv_accuracy(X: list[list[float]], y: list[int], k: int = 5, folds: int = 5, seed: int = 0) -> float:
    Xs = _standardize(X)
    rng = random.Random(seed)
    correct = 0
    for test in _folds(len(Xs), folds, rng):
        tset = set(test)
        train = [i for i in range(len(Xs)) if i not in tset]
        for i in test:
            d = sorted(train, key=lambda j: sum((a - b) ** 2 for a, b in zip(Xs[i], Xs[j])) + rng.random() * 1e-9)[:k]
            vote = sum(y[j] for j in d)
            pred = 1 if vote * 2 > k else 0 if vote * 2 < k else rng.randrange(2)
            correct += pred == y[i]
    return correct / len(Xs)


def stump_cv_accuracy(X: list[list[float]], y: list[int], folds: int = 5, seed: int = 0) -> float:
    """Best single-feature threshold, chosen on train folds, scored on test folds."""
    rng = random.Random(seed)
    correct = 0
    for test in _folds(len(X), folds, rng):
        tset = set(test)
        train = [i for i in range(len(X)) if i not in tset]
        best = (0.0, 0, 0.0, 1)
        for f in range(len(X[0])):
            vals = sorted({X[i][f] for i in train})
            mids = [(a + b) / 2 for a, b in zip(vals, vals[1:])] or vals
            for thr in mids:
                for sign in (1, -1):
                    acc = sum((1 if sign * (X[i][f] - thr) > 0 else 0) == y[i] for i in train) / len(train)
                    if acc > best[0]:
                        best = (acc, f, thr, sign)
        _, f, thr, sign = best
        correct += sum((1 if sign * (X[i][f] - thr) > 0 else 0) == y[i] for i in test)
    return correct / len(X)


def wilson_ci(p: float, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for an accuracy p measured on n samples."""
    if n == 0:
        return (0.0, 1.0)
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3))


def balance(samples: list[tuple[list[float], int]], seed: int = 0) -> list[tuple[list[float], int]]:
    rng = random.Random(seed)
    pos = [s for s in samples if s[1] == 1]
    neg = [s for s in samples if s[1] == 0]
    n = min(len(pos), len(neg))
    return rng.sample(pos, n) + rng.sample(neg, n)
