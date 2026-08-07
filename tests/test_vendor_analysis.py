from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pytest

from kev_analysis.cleaner import prepare_kev_dataframe
from kev_analysis.loader import load_kev_json
from kev_analysis.vendor_analysis import analyze_vendors

ROOT = Path(__file__).resolve().parents[1]
COURSE_JSON = ROOT / "data" / "CISA_KEV_2026-07-29.json"


def test_vendor_analysis_applies_frozen_sorting_and_concentration_formulas() -> None:
    _, raw = load_kev_json(COURSE_JSON)
    prepared = prepare_kev_dataframe(raw)
    before = prepared.copy(deep=True)

    result = analyze_vendors(prepared)

    assert result.vendor_summary.iloc[0]["vendor_clean"] == "Microsoft"
    assert result.vendor_summary.iloc[0]["record_count"] == 382
    assert result.vendor_summary["record_count"].sum() == 1656
    assert result.vendor_summary["share"].sum() == pytest.approx(1.0)
    assert result.vendor_summary.iloc[-1]["cumulative_share"] == pytest.approx(1.0)
    assert result.vendor_product_summary["record_count"].sum() == 1656
    assert result.vendor_product_top30["rank"].tolist() == list(range(1, 31))
    assert result.vendor_product_top30.iloc[0]["vendor_clean"] == "Microsoft"
    assert result.vendor_product_top30.iloc[0]["product_clean"] == "Windows"

    metrics = result.concentration_metrics.set_index("metric")["value"]
    shares = result.vendor_summary["share"]
    assert metrics["CR5"] == pytest.approx(shares.head(5).sum())
    assert metrics["CR10"] == pytest.approx(shares.head(10).sum())
    assert metrics["HHI"] == pytest.approx((shares**2).sum())
    assert 0 < metrics["HHI"] <= metrics["CR5"] <= metrics["CR10"] <= 1
    assert "plotly" in result.html["vendor_product_treemap"].lower()
    assert set(result.figures) == {
        "vendor_top15",
        "vendor_cumulative_share",
        "vendor_product_top30",
        "vendor_product_count_distribution",
    }
    assert prepared.equals(before)
    plt.close("all")


def test_vendor_product_top30_ties_are_sorted_lexically() -> None:
    _, raw = load_kev_json(COURSE_JSON)
    prepared = prepare_kev_dataframe(raw)
    result = analyze_vendors(prepared)
    summary = result.vendor_product_summary

    for _, tied in summary.groupby("record_count", sort=False):
        observed = list(zip(tied["vendor_clean"], tied["product_clean"], strict=True))
        assert observed == sorted(observed)
    plt.close("all")
