from __future__ import annotations

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.figure import Figure

from .constants import INCOMPLETE_YEARS, MONTHLY_END, MONTHLY_START
from .models import TimeAnalysisResult


def analyze_added_time(df: pd.DataFrame) -> TimeAnalysisResult:
    """Analyze continuous monthly sequence, annual coverage and comparable periods."""
    _require_columns(df, ("dateAdded",))
    dates = pd.to_datetime(df["dateAdded"], errors="raise").dt.normalize()
    if dates.isna().any():
        raise ValueError("dateAdded must not contain missing values")

    month_index = pd.period_range(MONTHLY_START, MONTHLY_END, freq="M")
    observed_months = dates.dt.to_period("M")
    observed_month_labels = observed_months.astype(str)
    outside_contract = observed_month_labels.lt(MONTHLY_START) | observed_month_labels.gt(
        MONTHLY_END
    )
    if outside_contract.any():
        invalid = sorted(observed_months[outside_contract].astype(str).unique())
        raise ValueError(f"dateAdded contains months outside the frozen range: {invalid}")

    monthly_counts = (
        observed_months.value_counts()
        .reindex(month_index, fill_value=0)
        .rename_axis("added_month")
        .rename("record_count")
        .reset_index()
    )
    monthly_counts["added_month"] = monthly_counts["added_month"].astype(str)
    monthly_counts["record_count"] = monthly_counts["record_count"].astype("int64")

    annual_work = monthly_counts.assign(
        added_year=monthly_counts["added_month"].str[:4].astype("int64"),
        month_number=monthly_counts["added_month"].str[5:7].astype("int64"),
    )
    annual_summary = (
        annual_work.groupby("added_year", sort=True, as_index=False)
        .agg(
            record_count=("record_count", "sum"),
            first_month=("month_number", "min"),
            last_month=("month_number", "max"),
            covered_months=("month_number", "size"),
        )
        .sort_values("added_year", kind="mergesort")
        .reset_index(drop=True)
    )
    annual_summary["is_complete_year"] = annual_summary["covered_months"].eq(12) & ~annual_summary[
        "added_year"
    ].isin(INCOMPLETE_YEARS)

    same_period_work = annual_work[
        annual_work["added_year"].ge(month_index.min().year + 1)
        & annual_work["month_number"].between(1, 7)
    ]
    same_period_comparison = (
        same_period_work.groupby("added_year", sort=True, as_index=False)["record_count"]
        .sum()
        .assign(period_start_month=1, period_end_month=7)
        .loc[:, ["added_year", "period_start_month", "period_end_month", "record_count"]]
    )

    figures = {
        "monthly_added_trend": _make_monthly_figure(monthly_counts),
        "annual_added_count": _make_annual_figure(annual_summary),
        "same_period_comparison": _make_same_period_figure(same_period_comparison),
    }
    return TimeAnalysisResult(
        monthly_counts=monthly_counts,
        annual_summary=annual_summary,
        same_period_comparison=same_period_comparison,
        figures=figures,
    )


def _require_columns(df: pd.DataFrame, columns: tuple[str, ...]) -> None:
    missing = [column for column in columns if column not in df.columns]
    if missing:
        raise ValueError(f"time analysis requires prepared columns: {missing}")


def _make_monthly_figure(monthly_counts: pd.DataFrame) -> Figure:
    months = pd.to_datetime(monthly_counts["added_month"] + "-01")
    figure, axis = plt.subplots(figsize=(12, 5.5))
    axis.plot(months, monthly_counts["record_count"], color="#2563eb", linewidth=2)
    axis.fill_between(months, monthly_counts["record_count"], color="#93c5fd", alpha=0.3)
    axis.set(
        title="Monthly records added to the KEV catalog",
        xlabel="Month (2021-11 to 2026-07)",
        ylabel="Record count",
    )
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    return figure


def _make_annual_figure(annual_summary: pd.DataFrame) -> Figure:
    colors = [
        "#f59e0b" if not complete else "#2563eb" for complete in annual_summary["is_complete_year"]
    ]
    figure, axis = plt.subplots(figsize=(8.5, 5.5))
    bars = axis.bar(
        annual_summary["added_year"].astype(str),
        annual_summary["record_count"],
        color=colors,
    )
    axis.bar_label(bars, padding=3)
    axis.set(
        title="Annual records added to the KEV catalog",
        xlabel="Year (orange denotes incomplete coverage)",
        ylabel="Record count",
    )
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    return figure


def _make_same_period_figure(same_period: pd.DataFrame) -> Figure:
    figure, axis = plt.subplots(figsize=(8.5, 5.5))
    bars = axis.bar(
        same_period["added_year"].astype(str),
        same_period["record_count"],
        color="#0f766e",
    )
    axis.bar_label(bars, padding=3)
    axis.set(
        title="Comparable January-July KEV additions",
        xlabel="Year",
        ylabel="Record count (January-July)",
    )
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    return figure
