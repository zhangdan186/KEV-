from __future__ import annotations

from pathlib import Path

from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]


def test_streamlit_app_starts_at_upload_state() -> None:
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=20).run()

    assert not app.exception
    assert app.title[0].value == "CISA KEV 目录查询与可视化工具"
    assert any("上传" in item.value for item in app.info)
