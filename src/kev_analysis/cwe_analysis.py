from __future__ import annotations

import re
from typing import Any

import pandas as pd

from .constants import CWE_DENOMINATORS, CWE_PATTERN, RANSOMWARE_VALUES
from .errors import KevRecordSchemaError, MissingPreparedColumnError
from .models import CweAnalysisResult
from .visualization import make_cwe_known_unknown_figure, make_cwe_top_figure

_LONG_COLUMNS: tuple[str, ...] = (
    "cveID",
    "cwe",
    "knownRansomwareCampaignUse",
    "dateAdded",
    "vendor_clean",
    "product_clean",
)
_REQUIRED_COLUMNS: tuple[str, ...] = (
    "cveID",
    "cwes",
    "knownRansomwareCampaignUse",
    "dateAdded",
    "vendor_clean",
    "product_clean",
)


def _require_columns(df: pd.DataFrame) -> None:
    missing = [column for column in _REQUIRED_COLUMNS if column not in df.columns]
    if missing:
        raise MissingPreparedColumnError(
            "CWE分析输入缺少清洗后字段",
            context={"missing": missing},
        )


def _validate_cwe_lists(df: pd.DataFrame) -> None:
    invalid_type = ~df["cwes"].map(lambda values: isinstance(values, list))
    if invalid_type.any():
        raise KevRecordSchemaError(
            "CWE分析要求cwes列中的每个值均为列表",
            context={"row_indices": df.index[invalid_type].tolist()},
        )

    invalid_rows: list[Any] = []
    for index, values in df["cwes"].items():
        if any(
            not isinstance(value, str) or re.fullmatch(CWE_PATTERN, value) is None
            for value in values
        ):
            invalid_rows.append(index)
    if invalid_rows:
        raise KevRecordSchemaError(
            "CWE分析输入包含非法CWE成员",
            context={"row_indices": invalid_rows},
        )


def build_cwe_long_table(df: pd.DataFrame) -> pd.DataFrame:
    """构造去重后的CVE-CWE长表，并保证不修改输入DataFrame。"""
    _require_columns(df)
    _validate_cwe_lists(df)

    source = df.loc[:, _REQUIRED_COLUMNS].copy(deep=True)
    source = source.loc[source["cwes"].map(bool)]
    if source.empty:
        return pd.DataFrame(columns=_LONG_COLUMNS)

    long_table = source.explode("cwes").rename(columns={"cwes": "cwe"})
    long_table = long_table.drop_duplicates(subset=["cveID", "cwe"], keep="first")
    return (
        long_table.loc[:, _LONG_COLUMNS]
        .sort_values(["cveID", "cwe"], ascending=[True, True], kind="mergesort")
        .reset_index(drop=True)
    )


def _summarize_subset(
    long_table: pd.DataFrame,
    *,
    denominator: int,
    share_column: str,
) -> pd.DataFrame:
    columns = ["cwe", "distinct_cve_count", "denominator", share_column]
    if long_table.empty:
        return pd.DataFrame(columns=columns)

    summary = (
        long_table.groupby("cwe", as_index=False, sort=False)["cveID"]
        .nunique()
        .rename(columns={"cveID": "distinct_cve_count"})
    )
    summary["distinct_cve_count"] = summary["distinct_cve_count"].astype(int)
    summary["denominator"] = int(denominator)
    summary[share_column] = summary["distinct_cve_count"] / float(denominator)
    return (
        summary.loc[:, columns]
        .sort_values(
            ["distinct_cve_count", "cwe"],
            ascending=[False, True],
            kind="mergesort",
        )
        .reset_index(drop=True)
    )


def analyze_cwe(df: pd.DataFrame) -> CweAnalysisResult:
    """按冻结分母统计总体、Known和Unknown子集中的CWE分布。"""
    long_table = build_cwe_long_table(df)
    invalid_status = ~long_table["knownRansomwareCampaignUse"].isin(RANSOMWARE_VALUES)
    if invalid_status.any():
        raise KevRecordSchemaError(
            "CWE分析输入包含非法勒索软件确认状态",
            context={"row_indices": long_table.index[invalid_status].tolist()},
        )

    overall = _summarize_subset(
        long_table,
        denominator=CWE_DENOMINATORS["overall"],
        share_column="share",
    )
    known = _summarize_subset(
        long_table.loc[long_table["knownRansomwareCampaignUse"].eq("Known")],
        denominator=CWE_DENOMINATORS["Known"],
        share_column="known_share",
    )
    unknown = _summarize_subset(
        long_table.loc[long_table["knownRansomwareCampaignUse"].eq("Unknown")],
        denominator=CWE_DENOMINATORS["Unknown"],
        share_column="unknown_share",
    )

    figures = {
        "cwe_top20": make_cwe_top_figure(overall, top_n=20),
        "cwe_known_unknown": make_cwe_known_unknown_figure(known, unknown, top_n=15),
    }
    return CweAnalysisResult(
        long_table=long_table,
        overall=overall,
        known=known,
        unknown=unknown,
        figures=figures,
    )
