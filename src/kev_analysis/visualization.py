from __future__ import annotations

from typing import Any

import matplotlib.pyplot as plt
import pandas as pd


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
    """以总体候选集合对比Known和Unknown子集中的不同CVE数量。"""
    _require_columns(known_summary, ("cwe", "distinct_cve_count"), "known_summary")
    _require_columns(unknown_summary, ("cwe", "distinct_cve_count"), "unknown_summary")
    if top_n <= 0:
        raise ValueError("top_n必须为正整数")

    merged = known_summary[["cwe", "distinct_cve_count"]].rename(
        columns={"distinct_cve_count": "known_count"}
    ).merge(
        unknown_summary[["cwe", "distinct_cve_count"]].rename(
            columns={"distinct_cve_count": "unknown_count"}
        ),
        on="cwe",
        how="outer",
    )
    merged[["known_count", "unknown_count"]] = merged[
        ["known_count", "unknown_count"]
    ].fillna(0)
    merged["total_count"] = merged["known_count"] + merged["unknown_count"]
    plot_data = (
        merged.sort_values(
            ["total_count", "cwe"],
            ascending=[False, True],
            kind="mergesort",
        )
        .head(top_n)
        .sort_values(["total_count", "cwe"], ascending=[True, False], kind="mergesort")
    )

    fig, ax = plt.subplots(figsize=(11, max(5, len(plot_data) * 0.36)))
    if plot_data.empty:
        ax.text(0.5, 0.5, "无可用CWE数据", ha="center", va="center", transform=ax.transAxes)
        ax.set_axis_off()
    else:
        positions = list(range(len(plot_data)))
        height = 0.38
        ax.barh([position - height / 2 for position in positions], plot_data["known_count"], height=height, label="Known")
        ax.barh([position + height / 2 for position in positions], plot_data["unknown_count"], height=height, label="Unknown")
        ax.set_yticks(positions, labels=plot_data["cwe"])
        ax.set_xlabel("不同CVE数量")
        ax.set_ylabel("CWE")
        ax.set_title("主要CWE在Known与Unknown子集中的数量对比")
        ax.legend()
        ax.grid(axis="x", alpha=0.25)
    fig.tight_layout()
    return fig
