from __future__ import annotations

import matplotlib.pyplot as plt
import pandas as pd

from kev_analysis.gui_service import (
    make_filtered_monthly_figure,
    make_filtered_vendor_figure,
    summarize_filtered_cwe,
    summarize_filtered_monthly,
    summarize_filtered_vendors,
)


def _frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "cveID": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
            "cwes": [["CWE-79", "CWE-89"], ["CWE-79"], []],
            "knownRansomwareCampaignUse": ["Known", "Unknown", "Unknown"],
            "dateAdded": pd.to_datetime(["2024-01-01", "2024-01-02", "2024-02-01"]),
            "vendor_clean": ["Vendor B", "Vendor A", "Vendor A"],
            "product_clean": ["P1", "P2", "P3"],
            "added_month": ["2024-01", "2024-01", "2024-02"],
        }
    )


def test_filtered_summaries_use_subset_counts_without_frozen_denominators() -> None:
    frame = _frame()

    monthly = summarize_filtered_monthly(frame)
    assert monthly.to_dict("records") == [
        {"added_month": "2024-01", "record_count": 2},
        {"added_month": "2024-02", "record_count": 1},
    ]

    vendors = summarize_filtered_vendors(frame)
    assert vendors.to_dict("records") == [
        {"vendor_clean": "Vendor A", "record_count": 2},
        {"vendor_clean": "Vendor B", "record_count": 1},
    ]

    cwe = summarize_filtered_cwe(frame)
    assert cwe.to_dict("records") == [
        {"cwe": "CWE-79", "distinct_cve_count": 2},
        {"cwe": "CWE-89", "distinct_cve_count": 1},
    ]
    assert "denominator" not in cwe.columns
    assert "share" not in cwe.columns


def test_filtered_figures_support_empty_and_nonempty_data() -> None:
    monthly = summarize_filtered_monthly(_frame())
    vendors = summarize_filtered_vendors(_frame())

    monthly_figure = make_filtered_monthly_figure(monthly)
    vendor_figure = make_filtered_vendor_figure(vendors, top_n=10)
    empty_figure = make_filtered_monthly_figure(
        pd.DataFrame(columns=["added_month", "record_count"])
    )

    assert monthly_figure.axes
    assert vendor_figure.axes
    assert empty_figure.axes

    plt.close(monthly_figure)
    plt.close(vendor_figure)
    plt.close(empty_figure)
