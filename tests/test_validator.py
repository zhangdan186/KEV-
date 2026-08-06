from __future__ import annotations

from pathlib import Path

from kev_analysis.loader import load_kev_json
from kev_analysis.validator import validate_raw_kev

ROOT = Path(__file__).resolve().parents[1]
COURSE_JSON = ROOT / "data" / "CISA_KEV_2026-07-29.json"


def test_course_snapshot_passes_all_validation_checks() -> None:
    metadata, frame = load_kev_json(COURSE_JSON)
    report = validate_raw_kev(metadata, frame)

    assert report.is_valid
    assert report.issues == ()
    assert report.summary["passed"].all()
    assert report.details.empty
    assert len(report.field_profile) == 11
    cwes_profile = report.field_profile.set_index("field").loc["cwes"]
    assert cwes_profile["null_count"] == 0
    assert cwes_profile["non_null_count"] == 1656


def test_validator_collects_multiple_business_issues_without_mutating_input() -> None:
    metadata, frame = load_kev_json(COURSE_JSON)
    broken = frame.copy(deep=True)
    broken.at[0, "cveID"] = broken.at[1, "cveID"]
    broken.at[2, "dateAdded"] = "2026-99-01"
    broken.at[3, "dueDate"] = "2000-01-01"
    broken.at[4, "knownRansomwareCampaignUse"] = "No"
    broken.at[5, "cwes"] = "CWE-79"
    broken.at[6, "cwes"] = ["79"]
    broken.at[7, "vendorProject"] = "   "
    before = broken.copy(deep=True)

    report = validate_raw_kev(metadata, broken)

    assert not report.is_valid
    assert {issue.code for issue in report.issues} >= {
        "KEV-VAL-003",
        "KEV-VAL-005",
        "KEV-VAL-006",
        "KEV-VAL-007",
        "KEV-VAL-008",
        "KEV-VAL-009",
        "KEV-VAL-010",
        "KEV-VAL-011",
    }
    assert broken.equals(before)
