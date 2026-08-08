from __future__ import annotations

import re
from typing import Any

import pandas as pd

from .constants import CWE_PATTERN, PREPARED_FIELDS, RANSOMWARE_VALUES
from .errors import (
    InvalidCweError,
    InvalidDateRangeError,
    InvalidRansomwareStatusError,
    MissingPreparedColumnError,
)
from .models import DateLike, ExtendedKevFilter, QuerySummary


def _require_prepared_columns(df: pd.DataFrame) -> None:
    missing = [column for column in PREPARED_FIELDS if column not in df.columns]
    if missing:
        raise MissingPreparedColumnError(
            "查询输入缺少清洗后字段",
            context={"missing": missing},
        )


def _normalize_date(value: DateLike | None, parameter: str) -> pd.Timestamp | None:
    if value is None:
        return None
    try:
        timestamp = pd.Timestamp(value)
    except (TypeError, ValueError) as exc:
        raise InvalidDateRangeError(
            f"{parameter}不是合法日期",
            context={parameter: str(value)},
        ) from exc
    if pd.isna(timestamp):
        raise InvalidDateRangeError(
            f"{parameter}不是合法日期",
            context={parameter: str(value)},
        )
    if timestamp.tzinfo is not None:
        timestamp = timestamp.tz_localize(None)
    return timestamp.normalize()


def _make_summary(result: pd.DataFrame) -> QuerySummary:
    max_date: pd.Timestamp | None
    if result.empty:
        max_date = None
    else:
        value: Any = result["dateAdded"].max()
        max_date = None if pd.isna(value) else pd.Timestamp(value)
    return QuerySummary(
        record_count=int(len(result)),
        vendor_count=int(result["vendor_clean"].nunique(dropna=True)),
        max_date=max_date,
        known_count=int(result["knownRansomwareCampaignUse"].eq("Known").sum()),
    )


def filter_kev(
    df: pd.DataFrame,
    start_date: DateLike | None = None,
    end_date: DateLike | None = None,
    vendor: str | None = None,
    ransomware: str | None = None,
    cwe: str | None = None,
) -> tuple[pd.DataFrame, QuerySummary]:
    """按题目冻结契约执行日期、厂商、勒索状态和CWE组合查询。"""
    _require_prepared_columns(df)
    result = df.copy(deep=True)

    start = _normalize_date(start_date, "start_date")
    end = _normalize_date(end_date, "end_date")
    if start is not None and end is not None and start > end:
        raise InvalidDateRangeError(
            "start_date不得晚于end_date",
            context={"start_date": str(start.date()), "end_date": str(end.date())},
        )

    mask = pd.Series(True, index=result.index, dtype=bool)
    if start is not None:
        mask &= result["dateAdded"].ge(start)
    if end is not None:
        mask &= result["dateAdded"].le(end)

    vendor_value = vendor.strip() if isinstance(vendor, str) else None
    if vendor_value:
        mask &= result["vendor_clean"].str.contains(
            vendor_value,
            case=False,
            regex=False,
            na=False,
        )

    if ransomware is not None and ransomware not in RANSOMWARE_VALUES:
        raise InvalidRansomwareStatusError(
            "ransomware只能为Known、Unknown或None",
            context={"ransomware": ransomware},
        )
    if ransomware is not None:
        mask &= result["knownRansomwareCampaignUse"].eq(ransomware)

    cwe_value = cwe.strip().upper() if isinstance(cwe, str) else None
    if cwe_value:
        if re.fullmatch(CWE_PATTERN, cwe_value) is None:
            raise InvalidCweError(
                "CWE编号格式非法",
                context={"cwe": cwe},
            )
        invalid_lists = ~result["cwes"].map(lambda values: isinstance(values, list))
        if invalid_lists.any():
            raise MissingPreparedColumnError(
                "查询要求cwes列中的每个值均为列表",
                context={"row_indices": result.index[invalid_lists].tolist()},
            )
        mask &= result["cwes"].map(lambda values: cwe_value in values)

    filtered = (
        result.loc[mask]
        .sort_values(
            ["dateAdded", "cveID"],
            ascending=[False, True],
            kind="mergesort",
        )
        .reset_index(drop=True)
    )
    return filtered, _make_summary(filtered)


def filter_kev_extended(
    df: pd.DataFrame,
    filters: ExtendedKevFilter,
) -> tuple[pd.DataFrame, QuerySummary]:
    """复用核心查询，并增加GUI所需的产品字面子串筛选。"""
    result, _ = filter_kev(
        df,
        start_date=filters.start_date,
        end_date=filters.end_date,
        vendor=filters.vendor,
        ransomware=filters.ransomware,
        cwe=filters.cwe,
    )
    product_value = filters.product.strip() if isinstance(filters.product, str) else None
    if product_value:
        result = result.loc[
            result["product_clean"].str.contains(
                product_value,
                case=False,
                regex=False,
                na=False,
            )
        ].reset_index(drop=True)
    return result, _make_summary(result)
