from __future__ import annotations

from typing import Any

import matplotlib.pyplot as plt
import pandas as pd
import plotly.express as px  # type: ignore[import-untyped]
from matplotlib.figure import Figure

from .models import VendorAnalysisResult


def analyze_vendors(df: pd.DataFrame) -> VendorAnalysisResult:
    """Analyze vendor/product labels and CR5, CR10 and unscaled HHI."""
    _require_columns(df, ("vendor_clean", "product_clean"))
    work = df.loc[:, ["vendor_clean", "product_clean"]].copy(deep=True)
    if work.empty:
        raise ValueError("vendor analysis requires at least one record")
    for column in ("vendor_clean", "product_clean"):
        invalid = ~work[column].map(lambda value: isinstance(value, str) and bool(value.strip()))
        if invalid.any():
            raise ValueError(f"{column} must contain non-empty cleaned strings")

    total_records = len(work)
    vendor_summary = (
        work.groupby("vendor_clean", sort=False)
        .agg(
            record_count=("product_clean", "size"),
            product_count=("product_clean", "nunique"),
        )
        .reset_index()
        .sort_values(
            ["record_count", "vendor_clean"],
            ascending=[False, True],
            kind="mergesort",
        )
        .reset_index(drop=True)
    )
    vendor_summary["record_count"] = vendor_summary["record_count"].astype("int64")
    vendor_summary["product_count"] = vendor_summary["product_count"].astype("int64")
    vendor_summary["share"] = vendor_summary["record_count"] / total_records
    vendor_summary["cumulative_share"] = vendor_summary["share"].cumsum()
    vendor_summary = vendor_summary.loc[
        :,
        ["vendor_clean", "record_count", "share", "cumulative_share", "product_count"],
    ]

    vendor_product_summary = (
        work.groupby(["vendor_clean", "product_clean"], sort=False)
        .size()
        .rename("record_count")
        .reset_index()
        .sort_values(
            ["record_count", "vendor_clean", "product_clean"],
            ascending=[False, True, True],
            kind="mergesort",
        )
        .reset_index(drop=True)
    )
    vendor_product_summary["record_count"] = vendor_product_summary["record_count"].astype("int64")
    vendor_product_summary["share"] = vendor_product_summary["record_count"] / total_records

    vendor_product_top30 = vendor_product_summary.head(30).copy(deep=True)
    vendor_product_top30.insert(0, "rank", range(1, len(vendor_product_top30) + 1))

    shares = vendor_summary["share"]
    scope = (
        "Concentration of KEV directory records across vendor text labels only; "
        "not market share or product security."
    )
    concentration_metrics = pd.DataFrame(
        {
            "metric": ("CR5", "CR10", "HHI"),
            "value": (
                float(shares.head(5).sum()),
                float(shares.head(10).sum()),
                float(shares.pow(2).sum()),
            ),
            "interpretation_scope": (scope, scope, scope),
            "metric_order": (1, 2, 3),
        }
    )

    figures = {
        "vendor_top15": _make_top_vendor_figure(vendor_summary, top_n=15),
        "vendor_cumulative_share": _make_cumulative_figure(vendor_summary),
        "vendor_product_top30": _make_top_product_figure(vendor_product_top30),
        "vendor_product_count_distribution": _make_product_count_figure(vendor_summary),
    }
    treemap = _make_treemap(vendor_product_summary)
    html = {
        "vendor_product_treemap": treemap.to_html(
            full_html=True,
            include_plotlyjs=True,
            config={"displaylogo": False, "responsive": True},
        )
    }
    return VendorAnalysisResult(
        vendor_summary=vendor_summary,
        vendor_product_summary=vendor_product_summary,
        vendor_product_top30=vendor_product_top30,
        concentration_metrics=concentration_metrics,
        figures=figures,
        html=html,
    )


def _require_columns(df: pd.DataFrame, columns: tuple[str, ...]) -> None:
    missing = [column for column in columns if column not in df.columns]
    if missing:
        raise ValueError(f"vendor analysis requires prepared columns: {missing}")


def _make_top_vendor_figure(vendor_summary: pd.DataFrame, *, top_n: int) -> Figure:
    plotted = vendor_summary.head(top_n).iloc[::-1]
    figure, axis = plt.subplots(figsize=(10, 7))
    bars = axis.barh(plotted["vendor_clean"], plotted["record_count"], color="#2563eb")
    axis.bar_label(bars, padding=3)
    axis.set(
        title=f"Top {min(top_n, len(vendor_summary))} vendor labels in the KEV snapshot",
        xlabel="KEV record count",
        ylabel="Vendor label",
    )
    axis.grid(axis="x", alpha=0.25)
    figure.tight_layout()
    return figure


def _make_cumulative_figure(vendor_summary: pd.DataFrame) -> Figure:
    plotted = vendor_summary.reset_index(drop=True)
    ranks = plotted.index + 1
    figure, count_axis = plt.subplots(figsize=(11, 6))
    count_axis.bar(ranks, plotted["record_count"], color="#93c5fd", label="Record count")
    count_axis.set(
        title="Vendor-label record counts and cumulative share",
        xlabel="Vendor rank under the frozen ordering",
        ylabel="Record count",
    )
    share_axis = count_axis.twinx()
    share_axis.plot(
        ranks,
        plotted["cumulative_share"] * 100,
        color="#dc2626",
        linewidth=2,
        label="Cumulative share",
    )
    share_axis.set_ylabel("Cumulative share (%)")
    share_axis.set_ylim(0, 105)
    count_axis.grid(axis="y", alpha=0.2)
    lines, labels = count_axis.get_legend_handles_labels()
    share_lines, share_labels = share_axis.get_legend_handles_labels()
    count_axis.legend(lines + share_lines, labels + share_labels, loc="center right")
    figure.tight_layout()
    return figure


def _make_top_product_figure(top30: pd.DataFrame) -> Figure:
    plotted = top30.copy(deep=True)
    plotted["label"] = plotted["vendor_clean"] + " - " + plotted["product_clean"]
    plotted = plotted.iloc[::-1]
    figure, axis = plt.subplots(figsize=(12, 10))
    axis.barh(plotted["label"], plotted["record_count"], color="#0f766e")
    axis.set(
        title="Top 30 vendor-product label combinations",
        xlabel="KEV record count",
        ylabel="Vendor-product label",
    )
    axis.grid(axis="x", alpha=0.25)
    figure.tight_layout()
    return figure


def _make_product_count_figure(vendor_summary: pd.DataFrame) -> Figure:
    figure, axis = plt.subplots(figsize=(8.5, 5.5))
    axis.hist(vendor_summary["product_count"], bins="auto", color="#7c3aed", alpha=0.8)
    axis.set(
        title="Distribution of distinct product labels per vendor label",
        xlabel="Distinct product-label count",
        ylabel="Vendor-label count",
    )
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    return figure


def _make_treemap(vendor_product_summary: pd.DataFrame) -> Any:
    figure = px.treemap(
        vendor_product_summary,
        path=[px.Constant("All vendor labels"), "vendor_clean", "product_clean"],
        values="record_count",
        color="record_count",
        color_continuous_scale="Blues",
        title="KEV records by vendor and product text labels",
        hover_data={"share": ":.2%"},
    )
    figure.update_layout(margin={"t": 50, "l": 10, "r": 10, "b": 10})
    return figure
