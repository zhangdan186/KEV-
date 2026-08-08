from __future__ import annotations

import pandas as pd

from .cwe_analysis import build_cwe_long_table
from .errors import MissingPreparedColumnError
from .visualization import make_monthly_added_figure, make_vendor_top_figure


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
        .agg(record_count=("added_month", "size"))
        .sort_values("added_month", ascending=True, kind="mergesort")
        .reset_index(drop=True)
    )


def summarize_filtered_vendors(df: pd.DataFrame) -> pd.DataFrame:
    """统计当前GUI筛选结果中各厂商对应的不同CVE数量。"""
    _require_columns(df, ("vendor_clean", "cveID"), "厂商动态图")
    if df.empty:
        return pd.DataFrame(columns=["vendor_clean", "record_count"])

    return (
        df.groupby("vendor_clean", as_index=False, sort=False)
        .agg(record_count=("cveID", "nunique"))
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
        long_table.groupby("cwe", as_index=False, sort=False)
        .agg(distinct_cve_count=("cveID", "nunique"))
        .sort_values(
            ["distinct_cve_count", "cwe"],
            ascending=[False, True],
            kind="mergesort",
        )
        .reset_index(drop=True)
    )


def make_filtered_monthly_figure(monthly_counts: pd.DataFrame) -> object:
    """绘制GUI筛选结果的月度记录数折线图。"""
    return make_monthly_added_figure(monthly_counts)


def make_filtered_vendor_figure(
    vendor_summary: pd.DataFrame,
    *,
    top_n: int = 10,
) -> object:
    """绘制GUI筛选结果的厂商Top-N水平柱状图。"""
    return make_vendor_top_figure(vendor_summary, top_n=top_n)
