from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from kev_analysis.errors import OutputContractError
from kev_analysis.exporters import export_dataframe, export_json
from kev_analysis.models import OutputSpec


def test_dataframe_export_uses_bom_dates_and_compact_cwe_json(tmp_path: Path) -> None:
    frame = pd.DataFrame(
        {
            "dateAdded": [pd.Timestamp("2026-07-29")],
            "cwes": [["CWE-79", "CWE-89"]],
            "share": [0.125],
        }
    )
    spec = OutputSpec("sample", "tables/sample.csv", "csv", tuple(frame.columns))

    path = export_dataframe(frame, spec, tmp_path)

    assert path.read_bytes().startswith(b"\xef\xbb\xbf")
    loaded = pd.read_csv(path, encoding="utf-8-sig")
    assert loaded.loc[0, "dateAdded"] == "2026-07-29"
    assert loaded.loc[0, "cwes"] == '["CWE-79","CWE-89"]'
    assert loaded.loc[0, "share"] == pytest.approx(0.125)
    assert isinstance(frame.loc[0, "cwes"], list)


def test_export_rejects_missing_registered_columns(tmp_path: Path) -> None:
    with pytest.raises(OutputContractError, match=r"KEV-OUT-001"):
        export_dataframe(
            pd.DataFrame({"a": [1]}),
            OutputSpec("sample", "tables/sample.csv", "csv", ("a", "b")),
            tmp_path,
        )


def test_json_export_is_utf8_and_preserves_non_ascii(tmp_path: Path) -> None:
    path = export_json(
        {"title": "漏洞目录"},
        OutputSpec("metadata", "validation/metadata.json", "json"),
        tmp_path,
    )

    assert json.loads(path.read_text(encoding="utf-8"))["title"] == "漏洞目录"
