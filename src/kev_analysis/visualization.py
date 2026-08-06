from __future__ import annotations

from typing import Any

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.ticker import PercentFormatter


def make_monthly_added_figure(monthly_counts: pd.DataFrame) -> Any:
    raise NotImplementedError


def make_deadline_distribution_figure(deadline_frequency: pd.DataFrame) -> Any:
    raise NotImplementedError


def make_ransomware_by_year_figure(by_year: pd.DataFrame) -> Any:
    raise NotImplementedError


def make_vendor_top_figure(vendor_summary: pd.DataFrame, *, top_n: int = 15) -> Any:
    raise NotImplementedError


def make_vendor_cumulative_figure(vendor_summary: pd.DataFrame) -> Any:
    raise NotImplementedError


def _require_columns(df: pd.DataFrame, required: tuple[str, ...], name: str) -> None:
    missing = [column for column in required if column not in df.columns]
    if missing:
        raise ValueError(f"{name}缺少字段: {missing}")


def make_cwe_top_figure(cwe_summary: pd.DataFrame, *, top_n: int = 20) -> Any:
    """绘制总体Top-N CWE对应的不同CVE数量水平柱状图。"""
    _require_columns(cwe_summary, ("cwe", "distinct_cve_count"), "cwe_summary")
    if top_n <= 0:
        raise ValueError("top_n必须为正整数")

    plot_data = cwe_summary.head(top_n).iloc[::-1]
    fig, ax = plt.subplots(figsize=(10, max(5, len(plot_data) * 0.32)))
    if plot_data.empty:
        ax.text(0.5, 0.5, "无可用CWE数据", ha="center", va="center", transform=ax.transAxes)
        ax.set_axis_off()
    else:
        ax.barh(plot_data["cwe"], plot_data["distinct_cve_count"])
        ax.set_xlabel("不同CVE数量")
        ax.set_ylabel("CWE")
        ax.set_title(f"CWE Top {min(top_n, len(plot_data))}（按不同CVE数量）")
        ax.grid(axis="x", alpha=0.25)
    fig.tight_layout()
    return fig


def make_cwe_known_unknown_figure(
    known_summary: pd.DataFrame,
    unknown_summary: pd.DataFrame,
    *,
    top_n: int = 15,
) -> Any:
    """按各自冻结分母比较Known与Unknown子集中的主要CWE占比。"""
    _require_columns(
        known_summary,
        ("cwe", "denominator", "known_share"),
        "known_summary",
    )
    _require_columns(
        unknown_summary,
        ("cwe", "denominator", "unknown_share"),
        "unknown_summary",
    )
    if top_n <= 0:
        raise ValueError("top_n必须为正整数")

    known_denominator = (
        int(known_summary["denominator"].iloc[0]) if not known_summary.empty else 0
    )
    unknown_denominator = (
        int(unknown_summary["denominator"].iloc[0]) if not unknown_summary.empty else 0
    )

    merged = known_summary[["cwe", "known_share"]].merge(
        unknown_summary[["cwe", "unknown_share"]],
        on="cwe",
        how="outer",
    )
    merged[["known_share", "unknown_share"]] = merged[
        ["known_share", "unknown_share"]
    ].fillna(0.0)
    merged["max_share"] = merged[["known_share", "unknown_share"]].max(axis=1)

    plot_data = (
        merged.sort_values(
            ["max_share", "cwe"],
            ascending=[False, True],
            kind="mergesort",
        )
        .head(top_n)
        .sort_values(["max_share", "cwe"], ascending=[True, False], kind="mergesort")
    )

    fig, ax = plt.subplots(figsize=(11, max(5, len(plot_data) * 0.38)))
    if plot_data.empty:
        ax.text(0.5, 0.5, "无可用CWE数据", ha="center", va="center", transform=ax.transAxes)
        ax.set_axis_off()
    else:
        positions = list(range(len(plot_data)))
        height = 0.38
        ax.barh(
            [position - height / 2 for position in positions],
            plot_data["known_share"],
            height=height,
            label=f"Known（分母={known_denominator}）",
        )
        ax.barh(
            [position + height / 2 for position in positions],
            plot_data["unknown_share"],
            height=height,
            label=f"Unknown（分母={unknown_denominator}）",
        )
        ax.set_yticks(positions, labels=plot_data["cwe"])
        ax.set_xlabel("该子集中包含相应CWE的CVE占比")
        ax.set_ylabel("CWE")
        ax.set_title("主要CWE在Known与Unknown子集中的占比对比")
        ax.xaxis.set_major_formatter(PercentFormatter(1.0))
        ax.legend()
        ax.grid(axis="x", alpha=0.25)
    fig.tight_layout()
    return fig
