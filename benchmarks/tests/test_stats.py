import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from stats import Counts, fmt, share, wilson


def test_wilson_known_value():
    lo, hi = wilson(81, 263)
    assert math.isclose(lo, 0.2553, abs_tol=1e-3)
    assert math.isclose(hi, 0.3662, abs_tol=1e-3)


def test_wilson_edges():
    assert wilson(0, 0) == (0.0, 0.0)
    lo, hi = wilson(0, 10)
    assert lo == 0.0 and 0 < hi < 0.35
    lo, hi = wilson(10, 10)
    assert hi == 1.0 and 0.65 < lo < 1
    with pytest.raises(ValueError):
        wilson(5, 3)


@given(st.integers(min_value=1, max_value=5000), st.data())
def test_wilson_contains_point_estimate(n, data):
    k = data.draw(st.integers(min_value=0, max_value=n))
    lo, hi = wilson(k, n)
    assert 0.0 <= lo <= k / n <= hi <= 1.0


def test_counts():
    c = Counts()
    for v, d in [(True, True), (True, False), (False, True), (False, False), (False, False)]:
        c.add(v, d)
    assert (c.tp, c.fn, c.fp, c.tn) == (1, 1, 1, 2)
    assert c.recall == 0.5 and c.fpr == 1 / 3 and c.precision == 0.5
    d = c.as_dict()
    assert d["recall_ci95"][0] < 0.5 < d["recall_ci95"][1]
    empty = Counts()
    assert empty.recall is None and empty.fpr is None and empty.precision is None
    assert empty.as_dict()["recall_ci95"] is None


def test_fmt_and_share():
    assert fmt(None) == "n/a" and fmt(0.5) == "0.500" and fmt(1 / 3, 1) == "0.3"
    assert share([True, False, True]) == (2, 3)
