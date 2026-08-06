from __future__ import annotations

from typing import Any

import matplotlib.pyplot as plt
import pandas as pd

from .cwe_analysis import build_cwe_long_table
from .errors import MissingPreparedColumnError


def _require_columns(df: pd.DataFrame, required: tuple[str, ...], name: str) -> None:
    missing = [column for column in required if column not in df.columns]
    if missing:
        raise MissingPreparedColumnError(
            f"{name}输入缺少清洗后字段",
            context={"missing": missing},
        )


def summarize_filtered_monthly(df: pd.DataFrame) -> pd.DataFrame:
    """统计当前GUI筛选结果中每个月的记录数。"""
    _require_columns(df, ("added_month",), "月度动态图")
    if df.empty:
        return pd.DataFrame(columns=["added_month", "record_count"])

    return (
        df.groupby("added_month", as_index=False, sort=False)
        .size()
        .rename(columns={"size": "record_count"})
        .sort_values("added_month", ascending=True, kind="mergesort")
        .reset_index(drop=True)
    )


def summarize_filtered_vendors(df: pd.DataFrame) -> pd.DataFrame:
    """统计当前GUI筛选结果中各厂商对应的不同CVE数量。"""
    _require_columns(df, ("vendor_clean", "cveID"), "厂商动态图")
    if df.empty:
        return pd.DataFrame(columns=["vendor_clean", "record_count"])

    return (
        df.groupby("vendor_clean", as_index=False, sort=False)["cveID"]
        .nunique()
        .rename(columns={"cveID": "record_count"})
        .sort_values(
            ["record_count", "vendor_clean"],
            ascending=[False, True],
            kind="mergesort",
        )
        .reset_index(drop=True)
    )


def summarize_filtered_cwe(df: pd.DataFrame) -> pd.DataFrame:
    """统计当前GUI筛选子集中的CWE数量，不套用全量快照固定分母。"""
    long_table = build_cwe_long_table(df)
    if long_table.empty:
        return pd.DataFrame(columns=["cwe", "distinct_cve_count"])

    return (
        long_table.groupby("cwe", as_index=False, sort=False)["cveID"]
        .nunique()
        .rename(columns={"cveID": "distinct_cve_count"})
        .sort_values(
            ["distinct_cve_count", "cwe"],
            ascending=[False, True],
            kind="mergesort",
        )
        .reset_index(drop=True)
    )


def make_filtered_monthly_figure(monthly_counts: pd.DataFrame) -> Any:
    """绘制GUI筛选结果的月度记录数折线图。"""
    required = ("added_month", "record_count")
    missing = [column for column in required if column not in monthly_counts.columns]
    if missing:
        raise ValueError(f"monthly_counts缺少字段: {missing}")

    fig, ax = plt.subplots(figsize=(11, 4.8))
    if monthly_counts.empty:
        ax.text(
            0.5,
            0.5,
            "当前筛选无记录",
            ha="center",
            va="center",
            transform=ax.transAxes,
        )
        ax.set_axis_off()
    else:
        ax.plot(
            monthly_counts["added_month"],
            monthly_counts["record_count"],
            marker="o",
            markersize=3,
        )
        ax.set_title("筛选结果：按月加入KEV的记录数")
        ax.set_xlabel("月份")
        ax.set_ylabel("记录数")
        ax.tick_params(axis="x", rotation=60)
        ax.grid(alpha=0.25)
    fig.tight_layout()
    return fig


def make_filtered_vendor_figure(
    vendor_summary: pd.DataFrame,
    *,
    top_n: int = 10,
) -> Any:
    """绘制GUI筛选结果的厂商Top-N水平柱状图。"""
    required = ("vendor_clean", "record_count")
    missing = [column for column in required if column not in vendor_summary.columns]
    if missing:
        raise ValueError(f"vendor_summary缺少字段: {missing}")
    if top_n <= 0:
        raise ValueError("top_n必须为正整数")

    plot_data = vendor_summary.head(top_n).iloc[::-1]
    fig, ax = plt.subplots(figsize=(10, max(5, len(plot_data) * 0.42)))
    if plot_data.empty:
        ax.text(
            0.5,
            0.5,
            "当前筛选无记录",
            ha="center",
            va="center",
            transform=ax.transAxes,
        )
        ax.set_axis_off()
    else:
        ax.barh(plot_data["vendor_clean"], plot_data["record_count"])
        ax.set_title(f"筛选结果：厂商Top {min(top_n, len(plot_data))}")
        ax.set_xlabel("不同CVE数量")
        ax.set_ylabel("厂商")
        ax.grid(axis="x", alpha=0.25)
    fig.tight_layout()
    return fig
