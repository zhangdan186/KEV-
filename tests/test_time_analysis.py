from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from kev_analysis.cleaner import prepare_kev_dataframe
from kev_analysis.loader import load_kev_json
from kev_analysis.time_analysis import analyze_added_time

ROOT = Path(__file__).resolve().parents[1]
COURSE_JSON = ROOT / "data" / "CISA_KEV_2026-07-29.json"


def test_time_analysis_builds_continuous_months_and_comparable_years() -> None:
    _, raw = load_kev_json(COURSE_JSON)
    prepared = prepare_kev_dataframe(raw)
    before = prepared.copy(deep=True)

    result = analyze_added_time(prepared)

    assert len(result.monthly_counts) == 57
    assert result.monthly_counts.iloc[0]["added_month"] == "2021-11"
    assert result.monthly_counts.iloc[-1]["added_month"] == "2026-07"
    assert result.monthly_counts["record_count"].sum() == 1656
    expected_annual = {2021: 311, 2022: 555, 2023: 187, 2024: 186, 2025: 245, 2026: 172}
    observed_annual = result.annual_summary.set_index("added_year")["record_count"].to_dict()
    assert observed_annual == expected_annual
    complete = result.annual_summary.set_index("added_year")["is_complete_year"].to_dict()
    assert complete == {
        2021: False,
        2022: True,
        2023: True,
        2024: True,
        2025: True,
        2026: False,
    }
    assert result.same_period_comparison["added_year"].tolist() == [2022, 2023, 2024, 2025, 2026]
    assert set(result.figures) == {
        "monthly_added_trend",
        "annual_added_count",
        "same_period_comparison",
    }
    assert prepared.equals(before)
    plt.close("all")


def test_time_analysis_rejects_missing_prepared_date_column() -> None:
    with pd.option_context("mode.copy_on_write", True):
        frame = pd.DataFrame({"added_year": [2026]})
    try:
        analyze_added_time(frame)
    except ValueError as exc:
        assert "dateAdded" in str(exc)
    else:
        raise AssertionError("missing dateAdded should be rejected")
