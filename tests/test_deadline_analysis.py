from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pytest

from kev_analysis.cleaner import prepare_kev_dataframe
from kev_analysis.deadline_analysis import analyze_deadlines
from kev_analysis.loader import load_kev_json

ROOT = Path(__file__).resolve().parents[1]
COURSE_JSON = ROOT / "data" / "CISA_KEV_2026-07-29.json"


def test_deadline_analysis_preserves_counts_and_required_statistics() -> None:
    _, raw = load_kev_json(COURSE_JSON)
    prepared = prepare_kev_dataframe(raw)
    before = prepared.copy(deep=True)

    result = analyze_deadlines(prepared)

    metrics = result.descriptive.set_index("metric")["value"]
    assert metrics["minimum"] == 1
    assert metrics["first_quartile"] == 21
    assert metrics["median"] == 21
    assert metrics["mean"] == pytest.approx(43.6865942029)
    assert metrics["third_quartile"] == 21
    assert metrics["maximum"] == 184
    assert result.frequency["record_count"].sum() == 1656
    assert result.frequency["share"].sum() == pytest.approx(1.0)
    assert result.by_year["record_count"].sum() == 1656
    assert result.by_year["added_year"].tolist() == [2021, 2022, 2023, 2024, 2025, 2026]
    assert set(result.figures) == {
        "deadline_distribution",
        "deadline_by_year",
        "deadline_interval_by_year",
    }
    assert prepared.equals(before)
    plt.close("all")


def test_deadline_analysis_rejects_negative_windows() -> None:
    _, raw = load_kev_json(COURSE_JSON)
    prepared = prepare_kev_dataframe(raw)
    prepared.loc[prepared.index[0], "deadline_days"] = -1

    with pytest.raises(ValueError, match="non-negative"):
        analyze_deadlines(prepared)
