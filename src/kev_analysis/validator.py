from __future__ import annotations

import json
import re
from typing import Any

import pandas as pd

from .constants import (
    CVE_PATTERN,
    CWE_PATTERN,
    EXPECTED_EMPTY_CWE_COUNT,
    EXPECTED_KNOWN_WITH_CWE_COUNT,
    EXPECTED_PRODUCT_WHITESPACE_COUNT,
    EXPECTED_RAW_FIELD_COUNT,
    EXPECTED_RECORD_COUNT,
    EXPECTED_UNKNOWN_WITH_CWE_COUNT,
    EXPECTED_VENDOR_WHITESPACE_COUNT,
    EXPECTED_WITH_CWE_COUNT,
    RANSOMWARE_VALUES,
    RAW_FIELDS,
)
from .models import KevMetadata, ValidationIssue, ValidationReport

SUMMARY_COLUMNS = (
    "check_id",
    "check_name",
    "severity",
    "passed",
    "actual",
    "expected",
    "message",
)
DETAIL_COLUMNS = (
    "issue_code",
    "severity",
    "row_index",
    "cveID",
    "field",
    "observed_value",
    "message",
)
PROFILE_COLUMNS = (
    "field",
    "dtype",
    "row_count",
    "non_null_count",
    "null_count",
    "empty_string_count",
    "unique_count",
)
KEY_TEXT_FIELDS = (
    "vendorProject",
    "product",
    "vulnerabilityName",
    "shortDescription",
    "requiredAction",
)


def _is_blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    missing = pd.isna(value)
    return bool(missing) if not hasattr(missing, "__len__") else False


def _display(value: Any) -> Any:
    if isinstance(value, list):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return value


def _field_profile(df: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for field in df.columns:
        series = df[field]
        normalized = series.map(_display)
        rows.append(
            {
                "field": field,
                "dtype": str(series.dtype),
                "row_count": len(series),
                "non_null_count": int(series.notna().sum()),
                "null_count": int(series.isna().sum()),
                "empty_string_count": int(
                    series.map(lambda value: isinstance(value, str) and not value.strip()).sum()
                ),
                "unique_count": int(normalized.nunique(dropna=True)),
            }
        )
    return (
        pd.DataFrame(rows, columns=PROFILE_COLUMNS)
        .sort_values("field", kind="mergesort")
        .reset_index(drop=True)
    )


def validate_raw_kev(metadata: KevMetadata, df: pd.DataFrame) -> ValidationReport:
    """Collect structural, field, logical and snapshot validation issues."""
    issues: list[ValidationIssue] = []
    checks: list[dict[str, Any]] = []

    def add_issue(
        code: str,
        severity: str,
        message: str,
        *,
        field: str | None = None,
        row_index: int | None = None,
        observed_value: Any = None,
    ) -> None:
        cve_id: str | None = None
        if row_index is not None and "cveID" in df.columns and row_index in df.index:
            value = df.at[row_index, "cveID"]
            cve_id = value if isinstance(value, str) else None
        issues.append(
            ValidationIssue(
                code=code,
                severity=severity,
                message=message,
                field=field,
                row_index=int(row_index) if isinstance(row_index, int) else row_index,
                cve_id=cve_id,
                observed_value=_display(observed_value),
            )
        )

    def add_check(
        check_id: str,
        name: str,
        severity: str,
        passed: bool,
        actual: Any,
        expected: Any,
        message: str,
    ) -> None:
        checks.append(
            {
                "check_id": check_id,
                "check_name": name,
                "severity": severity,
                "passed": bool(passed),
                "actual": _display(actual),
                "expected": _display(expected),
                "message": message,
            }
        )

    actual_fields = tuple(df.columns)
    fields_valid = actual_fields == RAW_FIELDS
    add_check(
        "KEV-SCHEMA-002",
        "原始字段结构",
        "FATAL",
        fields_valid,
        len(actual_fields),
        EXPECTED_RAW_FIELD_COUNT,
        "原始字段名称、数量和顺序必须与冻结契约一致",
    )
    if not fields_valid:
        add_issue(
            "KEV-SCHEMA-002",
            "FATAL",
            "原始字段名称、数量或顺序不符合冻结契约",
            observed_value=list(actual_fields),
        )

    count_valid = metadata.count == len(df)
    add_check(
        "KEV-VAL-001",
        "顶层计数一致性",
        "FATAL",
        count_valid,
        {"metadata_count": metadata.count, "dataframe_rows": len(df)},
        "metadata.count == len(df)",
        "顶层count必须等于DataFrame行数",
    )
    if not count_valid:
        add_issue("KEV-VAL-001", "FATAL", "顶层count与DataFrame行数不一致", observed_value=len(df))

    record_count_valid = len(df) == EXPECTED_RECORD_COUNT
    add_check(
        "KEV-VAL-002",
        "冻结快照记录数",
        "FATAL",
        record_count_valid,
        len(df),
        EXPECTED_RECORD_COUNT,
        "课程指定快照应包含1656条记录",
    )
    if not record_count_valid:
        add_issue(
            "KEV-VAL-002", "FATAL", "输入不是课程指定的1656条冻结快照", observed_value=len(df)
        )

    if not fields_valid:
        details = pd.DataFrame(
            [
                {
                    "issue_code": issue.code,
                    "severity": issue.severity,
                    "row_index": issue.row_index,
                    "cveID": issue.cve_id,
                    "field": issue.field,
                    "observed_value": issue.observed_value,
                    "message": issue.message,
                }
                for issue in issues
            ],
            columns=DETAIL_COLUMNS,
        )
        summary = pd.DataFrame(checks, columns=SUMMARY_COLUMNS).sort_values(
            "check_id", kind="mergesort"
        )
        return ValidationReport(
            False, tuple(issues), summary.reset_index(drop=True), details, _field_profile(df)
        )

    cve_blank = df["cveID"].map(_is_blank)
    cve_duplicates = df["cveID"].notna() & df["cveID"].duplicated(keep=False)
    cve_key_valid = not bool((cve_blank | cve_duplicates).any())
    add_check(
        "KEV-VAL-003",
        "CVE非空且唯一",
        "ERROR",
        cve_key_valid,
        int((cve_blank | cve_duplicates).sum()),
        0,
        "cveID不得为空或重复",
    )
    for index in df.index[cve_blank | cve_duplicates]:
        add_issue(
            "KEV-VAL-003",
            "ERROR",
            "cveID为空或重复",
            field="cveID",
            row_index=index,
            observed_value=df.at[index, "cveID"],
        )

    cve_format = df["cveID"].map(
        lambda value: isinstance(value, str) and re.fullmatch(CVE_PATTERN, value) is not None
    )
    add_check(
        "KEV-VAL-004",
        "CVE格式",
        "ERROR",
        bool(cve_format.all()),
        int((~cve_format).sum()),
        0,
        "cveID必须匹配冻结正则",
    )
    for index in df.index[~cve_format]:
        add_issue(
            "KEV-VAL-004",
            "ERROR",
            "cveID格式非法",
            field="cveID",
            row_index=index,
            observed_value=df.at[index, "cveID"],
        )

    parsed_dates: dict[str, pd.Series] = {}
    date_invalid = pd.Series(False, index=df.index)
    for field in ("dateAdded", "dueDate"):
        format_valid = df[field].map(
            lambda value: (
                isinstance(value, str)
                and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is not None
            )
        )
        parsed = pd.to_datetime(df[field].where(format_valid), format="%Y-%m-%d", errors="coerce")
        parsed_dates[field] = parsed
        invalid = ~format_valid | parsed.isna()
        date_invalid |= invalid
        for index in df.index[invalid]:
            add_issue(
                "KEV-VAL-005",
                "ERROR",
                "日期无法按YYYY-MM-DD解析",
                field=field,
                row_index=index,
                observed_value=df.at[index, field],
            )
    add_check(
        "KEV-VAL-005",
        "日期格式与可解析性",
        "ERROR",
        not bool(date_invalid.any()),
        int(date_invalid.sum()),
        0,
        "dateAdded和dueDate必须是有效的YYYY-MM-DD日期",
    )

    reversed_dates = (
        parsed_dates["dateAdded"].notna()
        & parsed_dates["dueDate"].notna()
        & (parsed_dates["dueDate"] < parsed_dates["dateAdded"])
    )
    add_check(
        "KEV-VAL-006",
        "日期逻辑",
        "ERROR",
        not bool(reversed_dates.any()),
        int(reversed_dates.sum()),
        0,
        "dueDate不得早于dateAdded",
    )
    for index in df.index[reversed_dates]:
        add_issue(
            "KEV-VAL-006",
            "ERROR",
            "dueDate早于dateAdded",
            field="dueDate",
            row_index=index,
            observed_value=df.at[index, "dueDate"],
        )

    ransomware_valid = df["knownRansomwareCampaignUse"].isin(RANSOMWARE_VALUES)
    add_check(
        "KEV-VAL-007",
        "勒索软件确认状态",
        "ERROR",
        bool(ransomware_valid.all()),
        int((~ransomware_valid).sum()),
        sorted(RANSOMWARE_VALUES),
        "状态只能为Known或Unknown",
    )
    for index in df.index[~ransomware_valid]:
        add_issue(
            "KEV-VAL-007",
            "ERROR",
            "勒索软件确认状态非法",
            field="knownRansomwareCampaignUse",
            row_index=index,
            observed_value=df.at[index, "knownRansomwareCampaignUse"],
        )

    cwes_are_lists = df["cwes"].map(lambda value: isinstance(value, list))
    add_check(
        "KEV-VAL-008",
        "CWE列表类型",
        "ERROR",
        bool(cwes_are_lists.all()),
        int((~cwes_are_lists).sum()),
        0,
        "每条记录的cwes必须为列表",
    )
    for index in df.index[~cwes_are_lists]:
        add_issue(
            "KEV-VAL-008",
            "ERROR",
            "cwes不是列表",
            field="cwes",
            row_index=index,
            observed_value=df.at[index, "cwes"],
        )

    invalid_cwe_rows = 0
    for index in df.index[cwes_are_lists]:
        cwe_values = df.at[index, "cwes"]
        if not isinstance(cwe_values, list):
            continue
        invalid_values = [
            value
            for value in cwe_values
            if not isinstance(value, str) or re.fullmatch(CWE_PATTERN, value) is None
        ]
        if invalid_values:
            invalid_cwe_rows += 1
            add_issue(
                "KEV-VAL-009",
                "ERROR",
                "CWE成员格式非法",
                field="cwes",
                row_index=index,
                observed_value=invalid_values,
            )
    add_check(
        "KEV-VAL-009",
        "CWE成员格式",
        "ERROR",
        invalid_cwe_rows == 0,
        invalid_cwe_rows,
        0,
        "非空CWE成员必须匹配冻结正则",
    )

    blank_text_count = 0
    for field in KEY_TEXT_FIELDS:
        invalid = df[field].map(_is_blank)
        blank_text_count += int(invalid.sum())
        for index in df.index[invalid]:
            add_issue(
                "KEV-VAL-010",
                "ERROR",
                "关键文本字段为空",
                field=field,
                row_index=index,
                observed_value=df.at[index, field],
            )
    add_check(
        "KEV-VAL-010",
        "关键文本完整性",
        "ERROR",
        blank_text_count == 0,
        blank_text_count,
        0,
        "厂商、产品、漏洞名称、描述和处置行动不得为空",
    )

    list_lengths = (
        df["cwes"]
        .map(lambda value: len(value) if isinstance(value, list) else pd.NA)
        .astype("Int64")
    )
    has_cwe = list_lengths.fillna(0).gt(0)
    known = df["knownRansomwareCampaignUse"].eq("Known")
    whitespace_vendor = df["vendorProject"].map(
        lambda value: isinstance(value, str) and value != value.strip()
    )
    whitespace_product = df["product"].map(
        lambda value: isinstance(value, str) and value != value.strip()
    )
    snapshot_counts = {
        "empty_cwe": int((list_lengths == 0).sum()),
        "with_cwe": int(has_cwe.sum()),
        "known_with_cwe": int((known & has_cwe).sum()),
        "unknown_with_cwe": int((~known & has_cwe & ransomware_valid).sum()),
        "vendor_whitespace": int(whitespace_vendor.sum()),
        "product_whitespace": int(whitespace_product.sum()),
    }
    expected_snapshot = {
        "empty_cwe": EXPECTED_EMPTY_CWE_COUNT,
        "with_cwe": EXPECTED_WITH_CWE_COUNT,
        "known_with_cwe": EXPECTED_KNOWN_WITH_CWE_COUNT,
        "unknown_with_cwe": EXPECTED_UNKNOWN_WITH_CWE_COUNT,
        "vendor_whitespace": EXPECTED_VENDOR_WHITESPACE_COUNT,
        "product_whitespace": EXPECTED_PRODUCT_WHITESPACE_COUNT,
    }
    snapshot_valid = snapshot_counts == expected_snapshot
    add_check(
        "KEV-VAL-011",
        "冻结快照黄金计数",
        "FATAL",
        snapshot_valid,
        snapshot_counts,
        expected_snapshot,
        "CWE和首尾空白黄金计数必须与课程快照一致",
    )
    if not snapshot_valid:
        add_issue("KEV-VAL-011", "FATAL", "冻结快照黄金计数不一致", observed_value=snapshot_counts)

    details = pd.DataFrame(
        [
            {
                "issue_code": issue.code,
                "severity": issue.severity,
                "row_index": issue.row_index,
                "cveID": issue.cve_id,
                "field": issue.field,
                "observed_value": issue.observed_value,
                "message": issue.message,
            }
            for issue in issues
        ],
        columns=DETAIL_COLUMNS,
    )
    if not details.empty:
        severity_order = pd.Categorical(
            details["severity"], ["FATAL", "ERROR", "WARNING", "INFO"], ordered=True
        )
        details = (
            details.assign(_severity=severity_order)
            .sort_values(
                ["_severity", "issue_code", "row_index"], kind="mergesort", na_position="last"
            )
            .drop(columns="_severity")
            .reset_index(drop=True)
        )
    summary = (
        pd.DataFrame(checks, columns=SUMMARY_COLUMNS)
        .sort_values("check_id", kind="mergesort")
        .reset_index(drop=True)
    )
    is_valid = not any(issue.severity in {"ERROR", "FATAL"} for issue in issues)
    return ValidationReport(is_valid, tuple(issues), summary, details, _field_profile(df))
