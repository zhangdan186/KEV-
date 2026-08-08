from __future__ import annotations

import pandas as pd
import pytest
from pandas.testing import assert_frame_equal

from kev_analysis.constants import CWE_DENOMINATORS
from kev_analysis.cwe_analysis import analyze_cwe, build_cwe_long_table
from kev_analysis.errors import KevRecordSchemaError, MissingPreparedColumnError


def _frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "cveID": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"],
            "cwes": [["CWE-79", "CWE-89", "CWE-79"], ["CWE-79"], [], ["CWE-787"]],
            "knownRansomwareCampaignUse": ["Known", "Unknown", "Known", "Unknown"],
            "dateAdded": pd.to_datetime(["2024-01-01", "2024-01-02", "2024-01-03", "2024-01-04"]),
            "vendor_clean": ["A", "B", "C", "D"],
            "product_clean": ["P1", "P2", "P3", "P4"],
        }
    )


def test_build_long_table_expands_deduplicates_sorts_and_preserves_input() -> None:
    source = _frame()
    before = source.copy(deep=True)
    result = build_cwe_long_table(source)

    assert result.columns.tolist() == [
        "cveID",
        "cwe",
        "knownRansomwareCampaignUse",
        "dateAdded",
        "vendor_clean",
        "product_clean",
    ]
    assert result[["cveID", "cwe"]].values.tolist() == [
        ["CVE-2024-0001", "CWE-79"],
        ["CVE-2024-0001", "CWE-89"],
        ["CVE-2024-0002", "CWE-79"],
        ["CVE-2024-0004", "CWE-787"],
    ]
    assert_frame_equal(source, before)


def test_analyze_cwe_uses_distinct_cve_counts_and_frozen_denominators() -> None:
    result = analyze_cwe(_frame())

    overall_79 = result.overall.loc[result.overall["cwe"].eq("CWE-79")].iloc[0]
    known_79 = result.known.loc[result.known["cwe"].eq("CWE-79")].iloc[0]
    unknown_79 = result.unknown.loc[result.unknown["cwe"].eq("CWE-79")].iloc[0]

    assert overall_79["distinct_cve_count"] == 2
    assert overall_79["denominator"] == CWE_DENOMINATORS["overall"]
    assert overall_79["share"] == pytest.approx(2 / CWE_DENOMINATORS["overall"])
    assert known_79["denominator"] == CWE_DENOMINATORS["Known"]
    assert unknown_79["denominator"] == CWE_DENOMINATORS["Unknown"]
    assert set(result.figures) == {"cwe_top20", "cwe_known_unknown"}


def test_missing_columns_raise_contract_error() -> None:
    with pytest.raises(MissingPreparedColumnError):
        build_cwe_long_table(_frame().drop(columns="vendor_clean"))


def test_invalid_cwe_member_raises_schema_error() -> None:
    frame = _frame()
    frame.at[0, "cwes"] = ["CWE-79", "INVALID"]
    with pytest.raises(KevRecordSchemaError):
        build_cwe_long_table(frame)
