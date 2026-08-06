from __future__ import annotations

"""Streamlit GUI skeleton.

The final GUI must load the raw JSON, call shared loader/validator/cleaner/query
services, show at least two dynamic charts, record details and CSV/PNG export.
"""

try:
    import streamlit as st
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Install dependencies with: pip install -r requirements.txt") from exc

st.set_page_config(page_title="CISA KEV 分析工具", layout="wide")
st.title("CISA KEV 目录查询与可视化工具")
st.info("开发冻结骨架已加载。成员三应在不改变公共接口的前提下实现GUI。")
