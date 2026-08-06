from __future__ import annotations

import pandas as pd
import pytest
from pandas.testing import assert_frame_equal

from kev_analysis.constants import PREPARED_FIELDS
from kev_analysis.errors import (
    InvalidCweError,
    InvalidDateRangeError,
    InvalidRansomwareStatusError,
    MissingPreparedColumnError,
)
from kev_analysis.models import ExtendedKevFilter
from kev_analysis.query import filter_kev, filter_kev_extended


def _prepared_frame() -> pd.DataFrame:
    rows = [
        {
            "cveID": "CVE-2024-0002",
            "vendorProject": "Microsoft",
            "product": "Exchange Server",
            "vulnerabilityName": "V2",
            "dateAdded": pd.Timestamp("2024-03-10"),
            "shortDescription": "D2",
            "requiredAction": "A2",
            "dueDate": pd.Timestamp("2024-03-31"),
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
            "cwes": ["CWE-79"],
            "vendor_clean": "Microsoft",
            "product_clean": "Exchange Server",
            "added_year": 2024,
            "added_month": "2024-03",
            "deadline_days": 21,
            "has_cwe": True,
            "cwe_count": 1,
        },
        {
            "cveID": "CVE-2024-0001",
            "vendorProject": "Adobe",
            "product": "Acrobat Reader",
            "vulnerabilityName": "V1",
            "dateAdded": pd.Timestamp("2024-03-10"),
            "shortDescription": "D1",
            "requiredAction": "A1",
            "dueDate": pd.Timestamp("2024-03-20"),
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "N",
            "cwes": ["CWE-787"],
            "vendor_clean": "Adobe",
            "product_clean": "Acrobat Reader",
            "added_year": 2024,
            "added_month": "2024-03",
            "deadline_days": 10,
            "has_cwe": True,
            "cwe_count": 1,
        },
        {
            "cveID": "CVE-2023-0003",
            "vendorProject": "Microsoft",
            "product": "Windows",
            "vulnerabilityName": "V3",
            "dateAdded": pd.Timestamp("2023-01-01"),
            "shortDescription": "D3",
            "requiredAction": "A3",
            "dueDate": pd.Timestamp("2023-01-15"),
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": [],
            "vendor_clean": "Microsoft",
            "product_clean": "Windows",
            "added_year": 2023,
            "added_month": "2023-01",
            "deadline_days": 14,
            "has_cwe": False,
            "cwe_count": 0,
        },
    ]
    return pd.DataFrame(rows, columns=PREPARED_FIELDS)


def test_no_condition_returns_all_sorted_and_does_not_modify_input() -> None:
    frame = _prepared_frame()
    before = frame.copy(deep=True)
    result, summary = filter_kev(frame)

    assert result["cveID"].tolist() == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2023-0003"]
    assert summary.record_count == 3
    assert summary.vendor_count == 2
    assert summary.known_count == 1
    assert summary.max_date == pd.Timestamp("2024-03-10")
    assert_frame_equal(frame, before)


def test_combined_filters_use_and_and_cwe_is_normalized() -> None:
    result, summary = filter_kev(
        _prepared_frame(),
        start_date="2024-03-10",
        end_date="2024-03-10",
        vendor="micro",
        ransomware="Known",
        cwe=" cwe-79 ",
    )
    assert result["cveID"].tolist() == ["CVE-2024-0002"]
    assert summary.record_count == 1


def test_vendor_literal_substring_not_regex() -> None:
    result, _ = filter_kev(_prepared_frame(), vendor="Micro.*")
    assert result.empty


def test_empty_result_preserves_columns_and_summary_contract() -> None:
    frame = _prepared_frame()
    result, summary = filter_kev(frame, vendor="不存在")
    assert result.columns.tolist() == frame.columns.tolist()
    assert summary.record_count == 0
    assert summary.vendor_count == 0
    assert summary.known_count == 0
    assert summary.max_date is None


def test_extended_filter_adds_product_condition() -> None:
    result, summary = filter_kev_extended(
        _prepared_frame(),
        ExtendedKevFilter(vendor="microsoft", product="exchange"),
    )
    assert result["cveID"].tolist() == ["CVE-2024-0002"]
    assert summary.record_count == 1


def test_invalid_parameters_raise_defined_errors() -> None:
    frame = _prepared_frame()
    with pytest.raises(InvalidDateRangeError):
        filter_kev(frame, start_date="2024-02-01", end_date="2024-01-01")
    with pytest.raises(InvalidDateRangeError):
        filter_kev(frame, start_date="not-a-date")
    with pytest.raises(InvalidRansomwareStatusError):
        filter_kev(frame, ransomware="known")
    with pytest.raises(InvalidCweError):
        filter_kev(frame, cwe="79")
    with pytest.raises(MissingPreparedColumnError):
        filter_kev(frame.drop(columns="product_clean"))
