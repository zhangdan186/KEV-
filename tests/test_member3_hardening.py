from __future__ import annotations

import matplotlib.pyplot as plt
import pandas as pd
import pytest

from kev_analysis.constants import CWE_DENOMINATORS, PREPARED_FIELDS
from kev_analysis.cwe_analysis import analyze_cwe, build_cwe_long_table
from kev_analysis.errors import KevRecordSchemaError, MissingPreparedColumnError
from kev_analysis.query import filter_kev, filter_kev_extended
from kev_analysis.models import ExtendedKevFilter
from kev_analysis.visualization import make_cwe_known_unknown_figure


def _prepared_frame() -> pd.DataFrame:
    rows = [
        {
            "cveID": "CVE-2024-0001",
            "vendorProject": "Vendor A",
            "product": "Product A",
            "vulnerabilityName": "V1",
            "dateAdded": pd.Timestamp("2024-01-01"),
            "shortDescription": "D1",
            "requiredAction": "A1",
            "dueDate": pd.Timestamp("2024-01-22"),
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
            "cwes": ["CWE-79"],
            "vendor_clean": "Vendor A",
            "product_clean": "Product A",
            "added_year": 2024,
            "added_month": "2024-01",
            "deadline_days": 21,
            "has_cwe": True,
            "cwe_count": 1,
        },
        {
            "cveID": "CVE-2024-0002",
            "vendorProject": "Vendor B",
            "product": "Product B",
            "vulnerabilityName": "V2",
            "dateAdded": pd.Timestamp("2024-01-02"),
            "shortDescription": "D2",
            "requiredAction": "A2",
            "dueDate": pd.Timestamp("2024-01-23"),
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": ["CWE-79", "CWE-89"],
            "vendor_clean": "Vendor B",
            "product_clean": "Product B",
            "added_year": 2024,
            "added_month": "2024-01",
            "deadline_days": 21,
            "has_cwe": True,
            "cwe_count": 2,
        },
    ]
    return pd.DataFrame(rows, columns=PREPARED_FIELDS)


def test_cwe_empty_input_and_illegal_status_are_handled() -> None:
    empty = _prepared_frame().iloc[0:0]
    result = analyze_cwe(empty)
    assert result.long_table.empty
    assert result.overall.columns.tolist() == [
        "cwe",
        "distinct_cve_count",
        "denominator",
        "share",
    ]

    invalid = _prepared_frame()
    invalid.loc[0, "knownRansomwareCampaignUse"] = "Invalid"
    with pytest.raises(KevRecordSchemaError):
        analyze_cwe(invalid)


def test_cwe_shares_and_sorting_follow_contract() -> None:
    result = analyze_cwe(_prepared_frame())
    assert result.overall["denominator"].eq(CWE_DENOMINATORS["overall"]).all()
    assert result.overall["share"].between(0, 1).all()
    assert result.overall["cwe"].tolist() == ["CWE-79", "CWE-89"]

    figure = make_cwe_known_unknown_figure(result.known, result.unknown, top_n=10)
    assert figure.axes
    assert "占比" in figure.axes[0].get_xlabel()
    plt.close(figure)


def test_query_single_sided_dates_boundaries_blank_conditions_and_product_literal() -> None:
    frame = _prepared_frame()

    from_start, _ = filter_kev(frame, start_date="2024-01-02")
    assert from_start["cveID"].tolist() == ["CVE-2024-0002"]

    to_end, _ = filter_kev(frame, end_date="2024-01-01")
    assert to_end["cveID"].tolist() == ["CVE-2024-0001"]

    all_rows, _ = filter_kev(frame, vendor="   ", cwe="   ")
    assert len(all_rows) == len(frame)

    literal, _ = filter_kev_extended(
        frame,
        ExtendedKevFilter(product="Product.*"),
    )
    assert literal.empty


def test_query_rejects_non_list_cwes_when_cwe_filter_is_used() -> None:
    frame = _prepared_frame()
    frame.at[0, "cwes"] = "CWE-79"
    with pytest.raises(MissingPreparedColumnError):
        filter_kev(frame, cwe="CWE-79")


def test_long_table_handles_all_empty_cwe_lists() -> None:
    frame = _prepared_frame()
    frame["cwes"] = [[], []]
    result = build_cwe_long_table(frame)
    assert result.empty
    assert result.columns.tolist() == [
        "cveID",
        "cwe",
        "knownRansomwareCampaignUse",
        "dateAdded",
        "vendor_clean",
        "product_clean",
    ]
