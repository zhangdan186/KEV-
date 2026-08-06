from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pandas as pd

from .constants import RAW_FIELDS, TOP_LEVEL_FIELDS
from .errors import (
    KevEncodingError,
    KevFileNotFoundError,
    KevJsonDecodeError,
    KevRecordSchemaError,
    KevTopLevelSchemaError,
)
from .models import KevMetadata, PathLike


def load_kev_json(file_path: PathLike) -> tuple[KevMetadata, pd.DataFrame]:
    """Read the raw course JSON without applying business cleaning.

    Implementation owner: member 1.
    See docs/interface-contract.md for frozen behavior and exceptions.
    """
    path = Path(file_path)
    if not path.is_file():
        raise KevFileNotFoundError("输入文件不存在", context={"path": str(path)})

    try:
        with path.open("r", encoding="utf-8") as stream:
            payload = json.load(stream)
    except UnicodeDecodeError as exc:
        raise KevEncodingError("输入文件不是有效的UTF-8文本", context={"path": str(path)}) from exc
    except json.JSONDecodeError as exc:
        raise KevJsonDecodeError(
            "输入文件不是有效的JSON",
            context={"path": str(path), "line": exc.lineno, "column": exc.colno},
        ) from exc
    except OSError as exc:
        raise KevFileNotFoundError("输入文件无法读取", context={"path": str(path)}) from exc

    if not isinstance(payload, Mapping):
        raise KevTopLevelSchemaError("JSON顶层必须是对象")
    missing_top = [field for field in TOP_LEVEL_FIELDS if field not in payload]
    if missing_top:
        raise KevTopLevelSchemaError("JSON缺少顶层字段", context={"missing": missing_top})
    if not isinstance(payload["title"], str) or not isinstance(payload["catalogVersion"], str):
        raise KevTopLevelSchemaError("title和catalogVersion必须是字符串")
    if not isinstance(payload["dateReleased"], str):
        raise KevTopLevelSchemaError("dateReleased必须是字符串")
    if isinstance(payload["count"], bool) or not isinstance(payload["count"], int):
        raise KevTopLevelSchemaError("count必须是整数")
    if not isinstance(payload["vulnerabilities"], list):
        raise KevTopLevelSchemaError("vulnerabilities必须是数组")

    records = payload["vulnerabilities"]
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise KevRecordSchemaError("漏洞记录必须是对象", context={"row_index": index})
        missing = [field for field in RAW_FIELDS if field not in record]
        extra = [field for field in record if field not in RAW_FIELDS]
        if missing or extra:
            raise KevRecordSchemaError(
                "漏洞记录字段与冻结的11个原始字段不一致",
                context={"row_index": index, "missing": missing, "extra": extra},
            )

    metadata = KevMetadata(
        title=payload["title"],
        catalog_version=payload["catalogVersion"],
        date_released=payload["dateReleased"],
        count=payload["count"],
    )
    # Supplying columns explicitly keeps the empty-array case and field order stable.
    frame = pd.DataFrame(records, columns=list(RAW_FIELDS)).copy(deep=True)
    frame["cwes"] = frame["cwes"].map(
        lambda values: list(values) if isinstance(values, list) else values
    )
    return metadata, frame
