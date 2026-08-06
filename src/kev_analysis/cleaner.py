from __future__ import annotations

import pandas as pd

from .constants import PREPARED_FIELDS, RAW_FIELDS
from .errors import KevRecordSchemaError


def prepare_kev_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Return a new prepared DataFrame with the seven frozen derived fields."""
    missing = [field for field in RAW_FIELDS if field not in df.columns]
    if missing:
        raise KevRecordSchemaError("清洗输入缺少原始字段", context={"missing": missing})

    prepared = df.loc[:, RAW_FIELDS].copy(deep=True)
    prepared["cwes"] = prepared["cwes"].map(
        lambda values: list(values) if isinstance(values, list) else values
    )
    invalid_cwes = ~prepared["cwes"].map(lambda values: isinstance(values, list))
    if invalid_cwes.any():
        raise KevRecordSchemaError(
            "清洗输入的cwes必须全部是列表",
            context={"row_indices": prepared.index[invalid_cwes].tolist()},
        )

    for field in ("vendorProject", "product"):
        invalid = ~prepared[field].map(lambda value: isinstance(value, str))
        if invalid.any():
            raise KevRecordSchemaError(
                f"清洗输入的{field}必须全部是字符串",
                context={"row_indices": prepared.index[invalid].tolist()},
            )

    for field in ("dateAdded", "dueDate"):
        parsed = pd.to_datetime(prepared[field], format="%Y-%m-%d", errors="coerce")
        if parsed.isna().any():
            raise KevRecordSchemaError(
                f"清洗输入的{field}包含非法日期",
                context={"row_indices": prepared.index[parsed.isna()].tolist()},
            )
        prepared[field] = parsed.dt.normalize()

    prepared["vendor_clean"] = prepared["vendorProject"].str.strip()
    prepared["product_clean"] = prepared["product"].str.strip()
    prepared["added_year"] = prepared["dateAdded"].dt.year.astype("Int64")
    prepared["added_month"] = prepared["dateAdded"].dt.strftime("%Y-%m")
    prepared["deadline_days"] = (prepared["dueDate"] - prepared["dateAdded"]).dt.days.astype(
        "Int64"
    )
    if prepared["deadline_days"].lt(0).any():
        raise KevRecordSchemaError(
            "清洗输入包含dueDate早于dateAdded的记录",
            context={"row_indices": prepared.index[prepared["deadline_days"].lt(0)].tolist()},
        )
    prepared["has_cwe"] = prepared["cwes"].map(bool).astype(bool)
    prepared["cwe_count"] = prepared["cwes"].map(len).astype("Int64")
    return prepared.loc[:, PREPARED_FIELDS]
