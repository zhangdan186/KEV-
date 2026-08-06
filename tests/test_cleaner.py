from __future__ import annotations

from pathlib import Path

import pandas as pd

from kev_analysis.cleaner import prepare_kev_dataframe
from kev_analysis.constants import PREPARED_FIELDS, RAW_FIELDS
from kev_analysis.loader import load_kev_json

ROOT = Path(__file__).resolve().parents[1]
COURSE_JSON = ROOT / "data" / "CISA_KEV_2026-07-29.json"


def test_prepare_course_snapshot_adds_frozen_fields_and_preserves_input() -> None:
    _, raw = load_kev_json(COURSE_JSON)
    before = raw.copy(deep=True)

    prepared = prepare_kev_dataframe(raw)

    assert tuple(prepared.columns) == PREPARED_FIELDS
    assert tuple(raw.columns) == RAW_FIELDS
    assert raw.equals(before)
    assert pd.api.types.is_datetime64_ns_dtype(prepared["dateAdded"])
    assert pd.api.types.is_datetime64_ns_dtype(prepared["dueDate"])
    assert str(prepared["added_year"].dtype) == "Int64"
    assert str(prepared["deadline_days"].dtype) == "Int64"
    assert str(prepared["cwe_count"].dtype) == "Int64"
    assert prepared["deadline_days"].ge(0).all()
    assert prepared["has_cwe"].sum() == 1485
    assert prepared["cwe_count"].eq(0).sum() == 171


def test_cleaning_only_strips_derived_vendor_and_product_fields() -> None:
    _, raw = load_kev_json(COURSE_JSON)
    prepared = prepare_kev_dataframe(raw)

    assert (prepared["vendorProject"] != prepared["vendorProject"].str.strip()).sum() == 6
    assert (prepared["product"] != prepared["product"].str.strip()).sum() == 10
    assert prepared["vendor_clean"].equals(prepared["vendorProject"].str.strip())
    assert prepared["product_clean"].equals(prepared["product"].str.strip())
