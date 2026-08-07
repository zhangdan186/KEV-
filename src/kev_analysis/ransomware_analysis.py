from __future__ import annotations

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.figure import Figure

from .constants import RANSOMWARE_VALUES
from .models import RansomwareAnalysisResult


def analyze_ransomware_status(df: pd.DataFrame) -> RansomwareAnalysisResult:
    """Analyze official Known/Unknown confirmation status."""
    _require_columns(df, ("knownRansomwareCampaignUse", "added_year"))
    work = df.loc[:, ["knownRansomwareCampaignUse", "added_year"]].copy(deep=True)
    if work.empty:
        raise ValueError("ransomware analysis requires at least one record")
    if work.isna().any().any():
        raise ValueError("ransomware status and added_year must not contain missing values")

    observed = set(work["knownRansomwareCampaignUse"].unique())
    invalid = sorted(observed - RANSOMWARE_VALUES)
    if invalid:
        raise ValueError(f"ransomware status contains unsupported values: {invalid}")
    work["added_year"] = pd.to_numeric(work["added_year"], errors="raise").astype("int64")

    status_order = ("Known", "Unknown")
    overall = (
        work["knownRansomwareCampaignUse"]
        .value_counts()
        .reindex(status_order, fill_value=0)
        .rename_axis("status")
        .rename("record_count")
        .reset_index()
    )
    overall["record_count"] = overall["record_count"].astype("int64")
    overall["share"] = overall["record_count"] / len(work)
    overall["status_order"] = range(1, len(status_order) + 1)

    cross_table = pd.crosstab(
        work["added_year"],
        work["knownRansomwareCampaignUse"],
    ).reindex(columns=status_order, fill_value=0)
    by_year = cross_table.rename(columns={"Known": "known_count", "Unknown": "unknown_count"})
    by_year["total_count"] = by_year["known_count"] + by_year["unknown_count"]
    by_year["known_share"] = by_year["known_count"] / by_year["total_count"]
    by_year["unknown_share"] = by_year["unknown_count"] / by_year["total_count"]
    by_year = by_year.reset_index().loc[
        :,
        [
            "added_year",
            "known_count",
            "unknown_count",
            "total_count",
            "known_share",
            "unknown_share",
        ],
    ]
    count_columns = ("known_count", "unknown_count", "total_count")
    by_year.loc[:, list(count_columns)] = by_year.loc[:, list(count_columns)].astype("int64")
    by_year = by_year.sort_values("added_year", kind="mergesort").reset_index(drop=True)

    figures = {
        "ransomware_overall": _make_overall_figure(overall),
        "ransomware_by_year": _make_by_year_figure(by_year),
        "ransomware_known_share": _make_known_share_figure(by_year),
    }
    return RansomwareAnalysisResult(overall=overall, by_year=by_year, figures=figures)


def _require_columns(df: pd.DataFrame, columns: tuple[str, ...]) -> None:
    missing = [column for column in columns if column not in df.columns]
    if missing:
        raise ValueError(f"ransomware analysis requires prepared columns: {missing}")


def _make_overall_figure(overall: pd.DataFrame) -> Figure:
    display_labels = ("Known (confirmed)", "Unknown (not confirmed)")
    figure, axis = plt.subplots(figsize=(7.5, 5.5))
    axis.pie(
        overall["record_count"],
        labels=display_labels,
        autopct="%1.1f%%",
        startangle=90,
        colors=("#dc2626", "#94a3b8"),
        wedgeprops={"edgecolor": "white"},
    )
    axis.set_title("CISA ransomware-campaign confirmation status")
    figure.tight_layout()
    return figure


def _make_by_year_figure(by_year: pd.DataFrame) -> Figure:
    figure, axis = plt.subplots(figsize=(9, 5.5))
    axis.bar(
        by_year["added_year"].astype(str),
        by_year["known_count"],
        label="Known (confirmed)",
        color="#dc2626",
    )
    axis.bar(
        by_year["added_year"].astype(str),
        by_year["unknown_count"],
        bottom=by_year["known_count"],
        label="Unknown (not confirmed)",
        color="#94a3b8",
    )
    axis.set(
        title="Ransomware-campaign confirmation status by year added",
        xlabel="Year added to KEV",
        ylabel="Record count",
    )
    axis.legend()
    axis.grid(axis="y", alpha=0.2)
    figure.tight_layout()
    return figure


def _make_known_share_figure(by_year: pd.DataFrame) -> Figure:
    figure, axis = plt.subplots(figsize=(9, 5.5))
    axis.plot(
        by_year["added_year"],
        by_year["known_share"] * 100,
        color="#dc2626",
        linewidth=2,
        marker="o",
    )
    axis.set(
        title="Share marked Known by year added",
        xlabel="Year added to KEV",
        ylabel="Known share (%)",
    )
    axis.grid(alpha=0.25)
    figure.tight_layout()
    return figure
