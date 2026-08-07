from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pytest

from kev_analysis.cleaner import prepare_kev_dataframe
from kev_analysis.loader import load_kev_json
from kev_analysis.ransomware_analysis import analyze_ransomware_status

ROOT = Path(__file__).resolve().parents[1]
COURSE_JSON = ROOT / "data" / "CISA_KEV_2026-07-29.json"


def test_ransomware_analysis_uses_official_statuses_and_year_denominators() -> None:
    _, raw = load_kev_json(COURSE_JSON)
    prepared = prepare_kev_dataframe(raw)
    before = prepared.copy(deep=True)

    result = analyze_ransomware_status(prepared)

    overall = result.overall.set_index("status")
    assert overall["record_count"].to_dict() == {"Known": 332, "Unknown": 1324}
    assert overall["share"].sum() == pytest.approx(1.0)
    assert result.by_year["total_count"].sum() == 1656
    assert (
        result.by_year["known_count"] + result.by_year["unknown_count"]
    ).equals(result.by_year["total_count"])
    assert (
        result.by_year["known_share"] + result.by_year["unknown_share"]
    ).to_numpy() == pytest.approx(1.0)
    assert set(result.figures) == {
        "ransomware_overall",
        "ransomware_by_year",
        "ransomware_known_share",
    }
    assert prepared.equals(before)
    plt.close("all")


def test_ransomware_analysis_rejects_non_official_status() -> None:
    _, raw = load_kev_json(COURSE_JSON)
    prepared = prepare_kev_dataframe(raw)
    prepared.loc[prepared.index[0], "knownRansomwareCampaignUse"] = "No"

    with pytest.raises(ValueError, match="unsupported"):
        analyze_ransomware_status(prepared)
