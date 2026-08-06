from __future__ import annotations

import json
from pathlib import Path

import pytest

from kev_analysis.constants import RAW_FIELDS
from kev_analysis.errors import (
    KevFileNotFoundError,
    KevJsonDecodeError,
    KevRecordSchemaError,
    KevTopLevelSchemaError,
)
from kev_analysis.loader import load_kev_json

ROOT = Path(__file__).resolve().parents[1]
COURSE_JSON = ROOT / "data" / "CISA_KEV_2026-07-29.json"


def test_load_course_snapshot_preserves_raw_contract() -> None:
    metadata, frame = load_kev_json(COURSE_JSON)

    assert metadata.catalog_version == "2026.07.29"
    assert metadata.count == len(frame) == 1656
    assert tuple(frame.columns) == RAW_FIELDS
    assert frame["cwes"].map(lambda value: isinstance(value, list)).all()


def test_missing_file_has_stable_error_code(tmp_path: Path) -> None:
    with pytest.raises(KevFileNotFoundError, match=r"KEV-IO-001"):
        load_kev_json(tmp_path / "missing.json")


def test_invalid_json_has_stable_error_code(tmp_path: Path) -> None:
    source = tmp_path / "broken.json"
    source.write_text("{broken", encoding="utf-8")

    with pytest.raises(KevJsonDecodeError, match=r"KEV-IO-002"):
        load_kev_json(source)


def test_missing_top_level_field_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "missing-top.json"
    source.write_text(json.dumps({"title": "x"}), encoding="utf-8")

    with pytest.raises(KevTopLevelSchemaError, match=r"KEV-SCHEMA-001"):
        load_kev_json(source)


def test_record_field_mismatch_is_rejected(tmp_path: Path) -> None:
    record = {field: "value" for field in RAW_FIELDS}
    record.pop("product")
    payload = {
        "title": "x",
        "catalogVersion": "1",
        "dateReleased": "2026-01-01T00:00:00Z",
        "count": 1,
        "vulnerabilities": [record],
    }
    source = tmp_path / "bad-record.json"
    source.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(KevRecordSchemaError, match=r"KEV-SCHEMA-002"):
        load_kev_json(source)
