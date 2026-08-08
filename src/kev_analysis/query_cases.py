from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TypedDict

import pandas as pd

from .constants import PREPARED_FIELDS
from .cwe_analysis import build_cwe_long_table
from .errors import KevRecordSchemaError, MissingPreparedColumnError
from .exporters import export_dataframe
from .models import OutputSpec, PathLike
from .query import filter_kev


class QueryCase(TypedDict):
    case_id: int
    start_date: str | None
    end_date: str | None
    vendor: str | None
    ransomware: str | None
    cwe: str | None


QUERY_CASE_SUMMARY_COLUMNS: tuple[str, ...] = (
    "case_id",
    "start_date",
    "end_date",
    "vendor",
    "ransomware",
    "cwe",
    "record_count",
    "vendor_count",
    "max_date",
    "known_count",
    "output_file",
)


def _require_prepared_columns(df: pd.DataFrame) -> None:
    missing = [column for column in PREPARED_FIELDS if column not in df.columns]
    if missing:
        raise MissingPreparedColumnError(
            "固定查询案例输入缺少清洗后字段",
            context={"missing": missing},
        )


def _year_bounds(year: int) -> tuple[str, str]:
    return f"{year:04d}-01-01", f"{year:04d}-12-31"


def build_default_query_cases(df: pd.DataFrame) -> tuple[QueryCase, QueryCase, QueryCase]:
    """基于冻结数据快照确定三组可复现、非空且覆盖不同条件的查询。"""
    _require_prepared_columns(df)
    if df.empty:
        raise KevRecordSchemaError("无法从空DataFrame生成固定查询案例")

    known = df.loc[df["knownRansomwareCampaignUse"].eq("Known")]
    if known.empty:
        raise KevRecordSchemaError("数据中没有Known记录，无法生成查询案例1")

    case1_candidates = (
        known.groupby(["added_year", "vendor_clean"], as_index=False, sort=False)
        .agg(record_count=("cveID", "nunique"))
        .sort_values(
            ["record_count", "added_year", "vendor_clean"],
            ascending=[False, True, True],
            kind="mergesort",
        )
        .reset_index(drop=True)
    )
    case1_row = case1_candidates.iloc[0]
    case1_year = int(case1_row["added_year"])
    case1_start, case1_end = _year_bounds(case1_year)

    long_table = build_cwe_long_table(df)
    if long_table.empty:
        raise KevRecordSchemaError("数据中没有CWE关系，无法生成查询案例2和3")

    case2_candidates = (
        long_table.groupby(["vendor_clean", "cwe"], as_index=False, sort=False)
        .agg(record_count=("cveID", "nunique"))
        .sort_values(
            ["record_count", "vendor_clean", "cwe"],
            ascending=[False, True, True],
            kind="mergesort",
        )
        .reset_index(drop=True)
    )
    case2_row = case2_candidates.iloc[0]

    unknown_long = long_table.loc[long_table["knownRansomwareCampaignUse"].eq("Unknown")].copy(
        deep=True
    )
    if unknown_long.empty:
        raise KevRecordSchemaError("数据中没有Unknown且含CWE的记录，无法生成查询案例3")
    unknown_long["added_year"] = pd.to_datetime(unknown_long["dateAdded"], errors="raise").dt.year
    case3_candidates = (
        unknown_long.groupby(["added_year", "cwe"], as_index=False, sort=False)
        .agg(record_count=("cveID", "nunique"))
        .sort_values(
            ["record_count", "added_year", "cwe"],
            ascending=[False, True, True],
            kind="mergesort",
        )
        .reset_index(drop=True)
    )
    case3_row = case3_candidates.iloc[0]
    case3_year = int(case3_row["added_year"])
    case3_start, case3_end = _year_bounds(case3_year)

    return (
        QueryCase(
            case_id=1,
            start_date=case1_start,
            end_date=case1_end,
            vendor=str(case1_row["vendor_clean"]),
            ransomware="Known",
            cwe=None,
        ),
        QueryCase(
            case_id=2,
            start_date=None,
            end_date=None,
            vendor=str(case2_row["vendor_clean"]),
            ransomware=None,
            cwe=str(case2_row["cwe"]),
        ),
        QueryCase(
            case_id=3,
            start_date=case3_start,
            end_date=case3_end,
            vendor=None,
            ransomware="Unknown",
            cwe=str(case3_row["cwe"]),
        ),
    )


def _normalize_case(case: Mapping[str, Any]) -> QueryCase:
    required = {
        "case_id",
        "start_date",
        "end_date",
        "vendor",
        "ransomware",
        "cwe",
    }
    missing = sorted(required - set(case))
    if missing:
        raise ValueError(f"查询案例缺少字段: {missing}")

    case_id = int(case["case_id"])
    if case_id <= 0:
        raise ValueError("case_id必须为正整数")

    return QueryCase(
        case_id=case_id,
        start_date=None if case["start_date"] is None else str(case["start_date"]),
        end_date=None if case["end_date"] is None else str(case["end_date"]),
        vendor=None if case["vendor"] is None else str(case["vendor"]),
        ransomware=None if case["ransomware"] is None else str(case["ransomware"]),
        cwe=None if case["cwe"] is None else str(case["cwe"]),
    )


def execute_query_cases(
    df: pd.DataFrame,
    cases: Sequence[Mapping[str, Any]] | None = None,
) -> tuple[pd.DataFrame, dict[int, pd.DataFrame]]:
    """执行至少三组查询，返回冻结列结构的摘要和实际记录。"""
    _require_prepared_columns(df)
    normalized_cases = tuple(
        _normalize_case(case)
        for case in (cases if cases is not None else build_default_query_cases(df))
    )
    if len(normalized_cases) < 3:
        raise ValueError("题目要求至少三组查询案例")

    case_ids = [case["case_id"] for case in normalized_cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("查询案例case_id不得重复")

    summary_rows: list[dict[str, Any]] = []
    results: dict[int, pd.DataFrame] = {}
    for case in normalized_cases:
        result, summary = filter_kev(
            df,
            start_date=case["start_date"],
            end_date=case["end_date"],
            vendor=case["vendor"],
            ransomware=case["ransomware"],
            cwe=case["cwe"],
        )
        case_id = case["case_id"]
        results[case_id] = result
        summary_rows.append(
            {
                **case,
                "record_count": summary.record_count,
                "vendor_count": summary.vendor_count,
                "max_date": (
                    None if summary.max_date is None else summary.max_date.strftime("%Y-%m-%d")
                ),
                "known_count": summary.known_count,
                "output_file": f"query_case_{case_id}.csv",
            }
        )

    summary_frame = (
        pd.DataFrame(summary_rows, columns=QUERY_CASE_SUMMARY_COLUMNS)
        .sort_values("case_id", ascending=True, kind="mergesort")
        .reset_index(drop=True)
    )
    return summary_frame, results


def export_query_cases(
    df: pd.DataFrame,
    output_root: PathLike,
    cases: Sequence[Mapping[str, Any]] | None = None,
) -> tuple[pd.DataFrame, dict[int, pd.DataFrame], tuple[Path, ...]]:
    """按冻结输出标准导出查询摘要和每组查询的实际记录。"""
    summary, results = execute_query_cases(df, cases)
    root = Path(output_root)
    written: list[Path] = []

    written.append(
        export_dataframe(
            summary,
            OutputSpec(
                "query_cases_summary",
                "queries/query_cases_summary.csv",
                "csv",
                QUERY_CASE_SUMMARY_COLUMNS,
            ),
            root,
        )
    )

    for case_id, result in sorted(results.items()):
        written.append(
            export_dataframe(
                result,
                OutputSpec(
                    f"query_case_{case_id}",
                    f"queries/query_case_{case_id}.csv",
                    "csv",
                    PREPARED_FIELDS,
                ),
                root,
            )
        )

    return summary, results, tuple(written)
