from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from kev_analysis.pipeline import run_data_core

ROOT = Path(__file__).resolve().parents[1]
COURSE_JSON = ROOT / "data" / "CISA_KEV_2026-07-29.json"


def test_data_core_pipeline_writes_required_member_one_outputs(tmp_path: Path) -> None:
    result = run_data_core(COURSE_JSON, tmp_path)

    assert result.status == "data_core_complete"
    assert result.validation.is_valid
    assert result.prepared is not None
    assert len(result.artifacts) == 5
    assert (tmp_path / "validation" / "metadata.json").is_file()
    assert (tmp_path / "validation" / "validation_summary.csv").is_file()
    assert (tmp_path / "validation" / "validation_details.csv").is_file()
    assert (tmp_path / "validation" / "field_profile.csv").is_file()
    prepared_path = tmp_path / "prepared" / "kev_prepared.csv"
    assert prepared_path.is_file()
    assert len(pd.read_csv(prepared_path, encoding="utf-8-sig")) == 1656
    metadata = json.loads((tmp_path / "validation" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["count"] == metadata["actualRecordCount"] == 1656
