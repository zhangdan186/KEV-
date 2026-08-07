from __future__ import annotations

import matplotlib.pyplot as plt
import pandas as pd
import pytest

from kev_analysis.errors import MlConfigurationError
from kev_analysis.ml_analysis import analyze_text_clusters


def _synthetic_text_data() -> pd.DataFrame:
    topics = (
        (
            "SQL injection database query input",
            "SQL injection in a web application database query allows an attacker to alter data",
            "DatabaseVendor",
        ),
        (
            "Buffer overflow memory corruption",
            "Buffer overflow causes memory corruption and remote code execution in a service",
            "SystemsVendor",
        ),
        (
            "Authentication bypass credentials access",
            "Authentication bypass permits improper access without valid credentials",
            "IdentityVendor",
        ),
    )
    rows = []
    for topic_id, (name, description, vendor) in enumerate(topics):
        for offset in range(12):
            rows.append(
                {
                    "cveID": f"CVE-2026-{topic_id * 100 + offset + 1000}",
                    "vulnerabilityName": name,
                    "shortDescription": description,
                    "vendor_clean": vendor,
                    "knownRansomwareCampaignUse": "Known" if offset % 4 == 0 else "Unknown",
                }
            )
    return pd.DataFrame(rows)


def test_text_clustering_compares_k_and_returns_explainable_outputs() -> None:
    frame = _synthetic_text_data()
    before = frame.copy(deep=True)

    result = analyze_text_clusters(frame, candidate_k=(2, 3), random_state=20260806)

    assert result.cluster_selection["k"].tolist() == [2, 3]
    assert result.cluster_selection["selected"].sum() == 1
    assert result.cluster_results["cveID"].nunique() == len(frame)
    assert result.cluster_summary["record_count"].sum() == len(frame)
    assert result.cluster_summary["share"].sum() == pytest.approx(1.0)
    assert result.cluster_summary["known_count"].sum() == 9
    assert result.cluster_keywords.groupby("cluster_id")["keyword_rank"].min().eq(1).all()
    assert set(result.figures) == {"ml_clusters"}
    assert frame.equals(before)
    plt.close("all")


def test_text_clustering_rejects_invalid_candidate_k() -> None:
    with pytest.raises(MlConfigurationError, match="2 <= k < record_count"):
        analyze_text_clusters(_synthetic_text_data(), candidate_k=(1, 3))
