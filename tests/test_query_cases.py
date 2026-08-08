from __future__ import annotations

import pandas as pd

from kev_analysis.constants import PREPARED_FIELDS
from kev_analysis.query_cases import (
    QUERY_CASE_SUMMARY_COLUMNS,
    build_default_query_cases,
    execute_query_cases,
    export_query_cases,
)


def _prepared_frame() -> pd.DataFrame:
    rows = [
        {
            "cveID": "CVE-2024-0001",
            "vendorProject": "Microsoft",
            "product": "Windows",
            "vulnerabilityName": "V1",
            "dateAdded": pd.Timestamp("2024-02-01"),
            "shortDescription": "D1",
            "requiredAction": "A1",
            "dueDate": pd.Timestamp("2024-02-22"),
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
            "cwes": ["CWE-79"],
            "vendor_clean": "Microsoft",
            "product_clean": "Windows",
            "added_year": 2024,
            "added_month": "2024-02",
            "deadline_days": 21,
            "has_cwe": True,
            "cwe_count": 1,
        },
        {
            "cveID": "CVE-2024-0002",
            "vendorProject": "Microsoft",
            "product": "Exchange",
            "vulnerabilityName": "V2",
            "dateAdded": pd.Timestamp("2024-03-01"),
            "shortDescription": "D2",
            "requiredAction": "A2",
            "dueDate": pd.Timestamp("2024-03-22"),
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
            "cwes": ["CWE-89"],
            "vendor_clean": "Microsoft",
            "product_clean": "Exchange",
            "added_year": 2024,
            "added_month": "2024-03",
            "deadline_days": 21,
            "has_cwe": True,
            "cwe_count": 1,
        },
        {
            "cveID": "CVE-2023-0003",
            "vendorProject": "Adobe",
            "product": "Reader",
            "vulnerabilityName": "V3",
            "dateAdded": pd.Timestamp("2023-05-01"),
            "shortDescription": "D3",
            "requiredAction": "A3",
            "dueDate": pd.Timestamp("2023-05-15"),
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": ["CWE-79", "CWE-787"],
            "vendor_clean": "Adobe",
            "product_clean": "Reader",
            "added_year": 2023,
            "added_month": "2023-05",
            "deadline_days": 14,
            "has_cwe": True,
            "cwe_count": 2,
        },
        {
            "cveID": "CVE-2023-0004",
            "vendorProject": "Adobe",
            "product": "Acrobat",
            "vulnerabilityName": "V4",
            "dateAdded": pd.Timestamp("2023-06-01"),
            "shortDescription": "D4",
            "requiredAction": "A4",
            "dueDate": pd.Timestamp("2023-06-15"),
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": ["CWE-79"],
            "vendor_clean": "Adobe",
            "product_clean": "Acrobat",
            "added_year": 2023,
            "added_month": "2023-06",
            "deadline_days": 14,
            "has_cwe": True,
            "cwe_count": 1,
        },
    ]
    return pd.DataFrame(rows, columns=PREPARED_FIELDS)


def test_default_cases_cover_required_condition_combinations_and_are_nonempty() -> None:
    frame = _prepared_frame()
    cases = build_default_query_cases(frame)

    assert len(cases) == 3
    assert cases[0]["start_date"] is not None
    assert cases[0]["vendor"] is not None
    assert cases[0]["ransomware"] == "Known"
    assert cases[1]["vendor"] is not None
    assert cases[1]["cwe"] is not None
    assert cases[2]["start_date"] is not None
    assert cases[2]["ransomware"] == "Unknown"
    assert cases[2]["cwe"] is not None

    summary, results = execute_query_cases(frame, cases)
    assert summary.columns.tolist() == list(QUERY_CASE_SUMMARY_COLUMNS)
    assert summary["case_id"].tolist() == [1, 2, 3]
    assert set(results) == {1, 2, 3}
    assert all(not result.empty for result in results.values())


def test_query_case_export_writes_summary_and_actual_records(tmp_path) -> None:
    summary, results, paths = export_query_cases(_prepared_frame(), tmp_path)

    assert len(paths) == 4
    assert (tmp_path / "queries" / "query_cases_summary.csv").exists()
    for case_id in results:
        assert (tmp_path / "queries" / f"query_case_{case_id}.csv").exists()
    assert summary["record_count"].gt(0).all()

    exported_case = pd.read_csv(
        tmp_path / "queries" / "query_case_1.csv",
        encoding="utf-8-sig",
    )
    assert exported_case.columns.tolist() == list(PREPARED_FIELDS)
    assert exported_case["cwes"].str.startswith("[").all()
