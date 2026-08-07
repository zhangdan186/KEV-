from __future__ import annotations

import inspect

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.figure import Figure

from .models import DeadlineAnalysisResult


def analyze_deadlines(df: pd.DataFrame) -> DeadlineAnalysisResult:
    """Analyze the CISA action-window term structure."""
    _require_columns(df, ("deadline_days", "added_year"))
    values = pd.to_numeric(df["deadline_days"], errors="raise")
    years = pd.to_numeric(df["added_year"], errors="raise")
    if values.isna().any() or years.isna().any():
        raise ValueError("deadline_days and added_year must not contain missing values")
    if values.lt(0).any():
        raise ValueError("deadline_days must be non-negative")
    if not np.allclose(values, np.round(values)):
        raise ValueError("deadline_days must contain whole calendar days")
    if values.empty:
        raise ValueError("deadline analysis requires at least one record")

    work = pd.DataFrame(
        {
            "deadline_days": values.astype("int64"),
            "added_year": years.astype("int64"),
        }
    )
    quantiles = work["deadline_days"].quantile([0.25, 0.5, 0.75])
    descriptive = pd.DataFrame(
        {
            "metric": (
                "minimum",
                "first_quartile",
                "median",
                "mean",
                "third_quartile",
                "maximum",
            ),
            "value": (
                float(work["deadline_days"].min()),
                float(quantiles.loc[0.25]),
                float(quantiles.loc[0.5]),
                float(work["deadline_days"].mean()),
                float(quantiles.loc[0.75]),
                float(work["deadline_days"].max()),
            ),
            "metric_order": range(1, 7),
        }
    )

    frequency = (
        work["deadline_days"]
        .value_counts(sort=False)
        .sort_index(kind="mergesort")
        .rename_axis("deadline_days")
        .rename("record_count")
        .reset_index()
    )
    frequency["record_count"] = frequency["record_count"].astype("int64")
    frequency["share"] = frequency["record_count"] / len(work)

    by_year_rows: list[dict[str, float | int]] = []
    for year, group in work.groupby("added_year", sort=True):
        year_quantiles = group["deadline_days"].quantile([0.25, 0.5, 0.75])
        by_year_rows.append(
            {
                "added_year": int(str(year)),
                "record_count": int(len(group)),
                "min_days": float(group["deadline_days"].min()),
                "q1_days": float(year_quantiles.loc[0.25]),
                "median_days": float(year_quantiles.loc[0.5]),
                "mean_days": float(group["deadline_days"].mean()),
                "q3_days": float(year_quantiles.loc[0.75]),
                "max_days": float(group["deadline_days"].max()),
            }
        )
    by_year = pd.DataFrame(by_year_rows).sort_values("added_year", kind="mergesort")
    by_year = by_year.reset_index(drop=True)

    interval_counts = _deadline_interval_counts(work)
    figures = {
        "deadline_distribution": _make_distribution_figure(frequency, work["deadline_days"]),
        "deadline_by_year": _make_by_year_figure(by_year),
        "deadline_interval_by_year": _make_interval_figure(interval_counts),
    }
    return DeadlineAnalysisResult(
        descriptive=descriptive,
        frequency=frequency,
        by_year=by_year,
        figures=figures,
    )


def _require_columns(df: pd.DataFrame, columns: tuple[str, ...]) -> None:
    missing = [column for column in columns if column not in df.columns]
    if missing:
        raise ValueError(f"deadline analysis requires prepared columns: {missing}")


def _deadline_interval_counts(work: pd.DataFrame) -> pd.DataFrame:
    labels = ("1-7", "8-14", "15-30", "31-60", "61+")
    intervals = pd.cut(
        work["deadline_days"],
        bins=(-np.inf, 7, 14, 30, 60, np.inf),
        labels=labels,
        ordered=True,
    )
    interval_counts = (
        work.assign(deadline_interval=intervals)
        .groupby(["added_year", "deadline_interval"], observed=False)
        .size()
        .unstack(fill_value=0)
        .reindex(columns=labels, fill_value=0)
        .sort_index()
    )
    return interval_counts


def _make_distribution_figure(frequency: pd.DataFrame, values: pd.Series) -> Figure:
    figure, (frequency_axis, box_axis) = plt.subplots(
        2,
        1,
        figsize=(11, 7.5),
        gridspec_kw={"height_ratios": (3, 1)},
    )
    frequency_axis.bar(
        frequency["deadline_days"],
        frequency["record_count"],
        color="#2563eb",
        width=2.5,
    )
    frequency_axis.set(
        title="Distribution of CISA prescribed action windows",
        xlabel="Action-window length (calendar days)",
        ylabel="Record count",
    )
    frequency_axis.grid(axis="y", alpha=0.25)
    if "orientation" in inspect.signature(box_axis.boxplot).parameters:
        box_axis.boxplot(
            values,
            orientation="horizontal",
            patch_artist=True,
            boxprops={"facecolor": "#93c5fd"},
        )
    else:
        box_axis.boxplot(
            values,
            vert=False,
            patch_artist=True,
            boxprops={"facecolor": "#93c5fd"},
        )
    box_axis.set(xlabel="Action-window length (calendar days)", yticks=[])
    figure.tight_layout()
    return figure


def _make_by_year_figure(by_year: pd.DataFrame) -> Figure:
    figure, axis = plt.subplots(figsize=(9, 5.5))
    axis.plot(
        by_year["added_year"],
        by_year["mean_days"],
        marker="o",
        linewidth=2,
        label="Mean",
    )
    axis.plot(
        by_year["added_year"],
        by_year["median_days"],
        marker="s",
        linewidth=2,
        label="Median",
    )
    axis.set(
        title="CISA action-window length by year added",
        xlabel="Year added to KEV",
        ylabel="Calendar days",
    )
    axis.legend()
    axis.grid(alpha=0.25)
    figure.tight_layout()
    return figure


def _make_interval_figure(interval_counts: pd.DataFrame) -> Figure:
    figure, axis = plt.subplots(figsize=(9, 5.5))
    interval_counts.plot(kind="bar", stacked=True, ax=axis, colormap="Blues")
    axis.set(
        title="CISA action-window bands by year added",
        xlabel="Year added to KEV",
        ylabel="Record count",
    )
    axis.legend(title="Calendar days", bbox_to_anchor=(1.02, 1), loc="upper left")
    axis.grid(axis="y", alpha=0.2)
    figure.tight_layout()
    return figure
