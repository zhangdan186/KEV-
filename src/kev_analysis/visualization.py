from __future__ import annotations

from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib import font_manager
from matplotlib.ticker import PercentFormatter


def configure_chart_style() -> str:
    """Select an installed CJK font so exported Chinese labels stay readable."""
    available = {font.name for font in font_manager.fontManager.ttflist}
    candidates = (
        "Microsoft YaHei",
        "SimHei",
        "DengXian",
        "Noto Sans CJK SC",
        "Source Han Sans SC",
    )
    selected = next((name for name in candidates if name in available), "DejaVu Sans")
    matplotlib.rcParams["font.sans-serif"] = [selected, "DejaVu Sans"]
    matplotlib.rcParams["axes.unicode_minus"] = False
    return selected


configure_chart_style()


def _require_columns(df: pd.DataFrame, required: tuple[str, ...], name: str) -> None:
    missing = [column for column in required if column not in df.columns]
    if missing:
        raise ValueError(f"{name}缺少字段: {missing}")


def _empty_figure(message: str, *, figsize: tuple[float, float]) -> Any:
    fig, ax = plt.subplots(figsize=figsize)
    ax.text(0.5, 0.5, message, ha="center", va="center", transform=ax.transAxes)
    ax.set_axis_off()
    fig.tight_layout()
    return fig


def make_monthly_added_figure(monthly_counts: pd.DataFrame) -> Any:
    """Plot the continuous monthly KEV record sequence."""
    _require_columns(monthly_counts, ("added_month", "record_count"), "monthly_counts")
    if monthly_counts.empty:
        return _empty_figure("无可用月度数据", figsize=(11, 4.8))

    plot_data = monthly_counts.sort_values("added_month", kind="mergesort")
    dates = pd.to_datetime(plot_data["added_month"] + "-01", errors="raise")
    fig, ax = plt.subplots(figsize=(11, 4.8))
    ax.plot(dates, plot_data["record_count"], color="#2563eb", linewidth=2)
    ax.fill_between(dates, plot_data["record_count"], alpha=0.14, color="#2563eb")
    ax.set_title("按月加入 KEV 目录的记录数")
    ax.set_xlabel("月份（2021-11 至 2026-07）")
    ax.set_ylabel("记录数")
    ax.grid(axis="y", alpha=0.25)
    fig.autofmt_xdate(rotation=30)
    fig.tight_layout()
    return fig


def make_deadline_distribution_figure(deadline_frequency: pd.DataFrame) -> Any:
    """Plot the exact frequency distribution of CISA action-window days."""
    _require_columns(
        deadline_frequency,
        ("deadline_days", "record_count"),
        "deadline_frequency",
    )
    if deadline_frequency.empty:
        return _empty_figure("无可用期限数据", figsize=(10, 5))

    plot_data = deadline_frequency.sort_values("deadline_days", kind="mergesort")
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(plot_data["deadline_days"], plot_data["record_count"], color="#0f766e")
    ax.set_title("CISA 目录行动窗口频数")
    ax.set_xlabel("期限天数")
    ax.set_ylabel("记录数")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    return fig


def make_ransomware_by_year_figure(by_year: pd.DataFrame) -> Any:
    """Plot yearly Known/Unknown counts without treating Unknown as negative evidence."""
    _require_columns(
        by_year,
        ("added_year", "known_count", "unknown_count"),
        "ransomware_by_year",
    )
    if by_year.empty:
        return _empty_figure("无可用勒索软件状态数据", figsize=(10, 5))

    plot_data = by_year.sort_values("added_year", kind="mergesort")
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(plot_data["added_year"], plot_data["known_count"], label="Known（已确认）")
    ax.bar(
        plot_data["added_year"],
        plot_data["unknown_count"],
        bottom=plot_data["known_count"],
        label="Unknown（尚未确认）",
    )
    ax.set_title("按加入年份统计 Known 与 Unknown")
    ax.set_xlabel("加入年份")
    ax.set_ylabel("记录数")
    ax.legend()
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    return fig


def make_vendor_top_figure(vendor_summary: pd.DataFrame, *, top_n: int = 15) -> Any:
    """Plot the stably sorted Top-N vendor labels."""
    _require_columns(vendor_summary, ("vendor_clean", "record_count"), "vendor_summary")
    if top_n <= 0:
        raise ValueError("top_n必须为正整数")
    if vendor_summary.empty:
        return _empty_figure("无可用厂商数据", figsize=(10, 5))

    plot_data = vendor_summary.head(top_n).iloc[::-1]
    fig, ax = plt.subplots(figsize=(10, max(5, len(plot_data) * 0.38)))
    ax.barh(plot_data["vendor_clean"], plot_data["record_count"], color="#7c3aed")
    ax.set_title(f"厂商标签 Top {min(top_n, len(plot_data))}")
    ax.set_xlabel("KEV 记录数")
    ax.set_ylabel("厂商标签")
    ax.grid(axis="x", alpha=0.25)
    fig.tight_layout()
    return fig


def make_vendor_cumulative_figure(vendor_summary: pd.DataFrame) -> Any:
    """Plot cumulative KEV record share across stably sorted vendor labels."""
    _require_columns(
        vendor_summary,
        ("vendor_clean", "cumulative_share"),
        "vendor_summary",
    )
    if vendor_summary.empty:
        return _empty_figure("无可用厂商累计占比数据", figsize=(10, 5))

    plot_data = vendor_summary.reset_index(drop=True)
    ranks = pd.RangeIndex(1, len(plot_data) + 1)
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(ranks, plot_data["cumulative_share"], color="#dc2626", linewidth=2)
    ax.axhline(0.8, color="#6b7280", linestyle="--", linewidth=1)
    ax.set_title("厂商标签累计占比")
    ax.set_xlabel("厂商标签排名")
    ax.set_ylabel("累计占比")
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_ylim(0, 1.02)
    ax.grid(alpha=0.25)
    fig.tight_layout()
    return fig


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
        ax.barh(plot_data["cwe"], plot_data["distinct_cve_count"], color="#2563eb")
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

    known_denominator = int(known_summary["denominator"].iloc[0]) if not known_summary.empty else 0
    unknown_denominator = (
        int(unknown_summary["denominator"].iloc[0]) if not unknown_summary.empty else 0
    )

    merged = known_summary[["cwe", "known_share"]].merge(
        unknown_summary[["cwe", "unknown_share"]],
        on="cwe",
        how="outer",
    )
    merged[["known_share", "unknown_share"]] = merged[["known_share", "unknown_share"]].fillna(0.0)
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
