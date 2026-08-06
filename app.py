from __future__ import annotations

import json
import sys
import tempfile
from io import BytesIO
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    import streamlit as st
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Install dependencies with: pip install -r requirements.txt") from exc

from kev_analysis.cleaner import prepare_kev_dataframe
from kev_analysis.cwe_analysis import analyze_cwe
from kev_analysis.errors import KevError
from kev_analysis.loader import load_kev_json
from kev_analysis.models import ExtendedKevFilter
from kev_analysis.query import filter_kev_extended
from kev_analysis.validator import validate_raw_kev


def _figure_to_png(fig: Any) -> bytes:
    buffer = BytesIO()
    fig.savefig(buffer, format="png", dpi=200, bbox_inches="tight")
    buffer.seek(0)
    return buffer.getvalue()


def _result_to_csv(df: pd.DataFrame) -> bytes:
    exported = df.copy(deep=True)
    if "cwes" in exported.columns:
        exported["cwes"] = exported["cwes"].map(
            lambda values: json.dumps(values, ensure_ascii=False, separators=(",", ":"))
        )
    return exported.to_csv(index=False, encoding="utf-8-sig", date_format="%Y-%m-%d").encode(
        "utf-8-sig"
    )


def _monthly_figure(df: pd.DataFrame) -> Any:
    monthly = (
        df.groupby("added_month", as_index=False)
        .size()
        .rename(columns={"size": "record_count"})
        .sort_values("added_month", kind="mergesort")
    )
    fig, ax = plt.subplots(figsize=(11, 4.8))
    if monthly.empty:
        ax.text(0.5, 0.5, "当前筛选无记录", ha="center", va="center", transform=ax.transAxes)
        ax.set_axis_off()
    else:
        ax.plot(monthly["added_month"], monthly["record_count"], marker="o", markersize=3)
        ax.set_title("筛选结果：按月加入KEV的记录数")
        ax.set_xlabel("月份")
        ax.set_ylabel("记录数")
        ax.tick_params(axis="x", rotation=60)
        ax.grid(alpha=0.25)
    fig.tight_layout()
    return fig


def _vendor_figure(df: pd.DataFrame, top_n: int = 10) -> Any:
    vendor = (
        df.groupby("vendor_clean", as_index=False)["cveID"]
        .nunique()
        .rename(columns={"cveID": "record_count"})
        .sort_values(["record_count", "vendor_clean"], ascending=[False, True], kind="mergesort")
        .head(top_n)
        .iloc[::-1]
    )
    fig, ax = plt.subplots(figsize=(10, 5.2))
    if vendor.empty:
        ax.text(0.5, 0.5, "当前筛选无记录", ha="center", va="center", transform=ax.transAxes)
        ax.set_axis_off()
    else:
        ax.barh(vendor["vendor_clean"], vendor["record_count"])
        ax.set_title(f"筛选结果：厂商Top {min(top_n, len(vendor))}")
        ax.set_xlabel("不同CVE数量")
        ax.set_ylabel("厂商")
        ax.grid(axis="x", alpha=0.25)
    fig.tight_layout()
    return fig


st.set_page_config(page_title="CISA KEV 分析工具", page_icon="🛡️", layout="wide")
st.title("CISA KEV 目录查询与可视化工具")
st.caption("直接读取课程JSON；日期、厂商、产品、Known/Unknown和CWE条件使用AND组合。")

uploaded_file = st.sidebar.file_uploader("选择CISA KEV JSON", type=["json"])

if uploaded_file is None:
    st.info("请在左侧上传 CISA_KEV_2026-07-29.json。")
    st.stop()

try:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_file:
        temp_file.write(uploaded_file.getbuffer())
        temp_path = Path(temp_file.name)
    metadata, raw_df = load_kev_json(temp_path)
    validation = validate_raw_kev(metadata, raw_df)
    if not validation.is_valid:
        st.error("数据校验未通过，不能继续正式分析。")
        st.dataframe(validation.summary, use_container_width=True)
        with st.expander("查看校验问题明细"):
            st.dataframe(validation.details, use_container_width=True)
        st.stop()
    prepared_df = prepare_kev_dataframe(raw_df)
except (KevError, OSError, ValueError) as exc:
    st.error(f"文件加载失败：{exc}")
    st.stop()
finally:
    try:
        temp_path.unlink(missing_ok=True)
    except NameError:
        pass

st.success("原始JSON读取、校验和清洗完成。")
meta_cols = st.columns(4)
meta_cols[0].metric("目录版本", metadata.catalog_version)
meta_cols[1].metric("发布日期", metadata.date_released)
meta_cols[2].metric("原始记录数", metadata.count)
meta_cols[3].metric("含CWE记录数", int(prepared_df["has_cwe"].sum()))

minimum_date = prepared_df["dateAdded"].min().date()
maximum_date = prepared_df["dateAdded"].max().date()

st.sidebar.subheader("组合筛选")
use_date = st.sidebar.checkbox("启用日期范围", value=False)
if use_date:
    date_range = st.sidebar.date_input(
        "dateAdded闭区间",
        value=(minimum_date, maximum_date),
        min_value=minimum_date,
        max_value=maximum_date,
    )
    if isinstance(date_range, tuple) and len(date_range) == 2:
        start_date, end_date = date_range
    else:
        start_date = end_date = None
else:
    start_date = end_date = None

vendor = st.sidebar.text_input("厂商/项目关键词")
product = st.sidebar.text_input("产品关键词")
ransomware_label = st.sidebar.selectbox("勒索软件确认状态", ["全部", "Known", "Unknown"])
cwe = st.sidebar.text_input("CWE编号（如 CWE-79）")

filters = ExtendedKevFilter(
    start_date=str(start_date) if start_date is not None else None,
    end_date=str(end_date) if end_date is not None else None,
    vendor=vendor or None,
    product=product or None,
    ransomware=None if ransomware_label == "全部" else ransomware_label,
    cwe=cwe or None,
)

try:
    result, summary = filter_kev_extended(prepared_df, filters)
except KevError as exc:
    st.error(str(exc))
    st.stop()

summary_cols = st.columns(4)
summary_cols[0].metric("筛选记录数", summary.record_count)
summary_cols[1].metric("厂商数", summary.vendor_count)
summary_cols[2].metric("Known数量", summary.known_count)
summary_cols[3].metric(
    "最新加入日期",
    summary.max_date.strftime("%Y-%m-%d") if summary.max_date is not None else "—",
)

chart_tab, table_tab, detail_tab, validation_tab = st.tabs(
    ["动态可视化", "查询结果", "CVE详情", "数据校验"]
)

with chart_tab:
    chart_name = st.radio("选择图表", ["月度新增", "厂商Top 10", "CWE Top 20"], horizontal=True)
    if chart_name == "月度新增":
        chart = _monthly_figure(result)
    elif chart_name == "厂商Top 10":
        chart = _vendor_figure(result)
    else:
        chart = analyze_cwe(result).figures["cwe_top20"]
    st.pyplot(chart, use_container_width=True)
    st.download_button(
        "下载当前图表PNG",
        data=_figure_to_png(chart),
        file_name="kev_current_chart.png",
        mime="image/png",
    )
    plt.close(chart)

with table_tab:
    display_columns = [
        "cveID",
        "vendor_clean",
        "product_clean",
        "vulnerabilityName",
        "dateAdded",
        "dueDate",
        "knownRansomwareCampaignUse",
        "cwes",
    ]
    st.dataframe(result.loc[:, display_columns], use_container_width=True, hide_index=True)
    st.download_button(
        "导出当前筛选结果CSV",
        data=_result_to_csv(result),
        file_name="kev_filtered_results.csv",
        mime="text/csv",
        disabled=result.empty,
    )

with detail_tab:
    if result.empty:
        st.info("当前筛选无记录。")
    else:
        selected_cve = st.selectbox("选择CVE", result["cveID"].tolist())
        record = result.loc[result["cveID"].eq(selected_cve)].iloc[0]
        st.subheader(f"{record['cveID']} · {record['vulnerabilityName']}")
        col_a, col_b = st.columns(2)
        col_a.write(f"**厂商：** {record['vendor_clean']}")
        col_a.write(f"**产品：** {record['product_clean']}")
        col_a.write(f"**加入日期：** {record['dateAdded']:%Y-%m-%d}")
        col_b.write(f"**处置截止：** {record['dueDate']:%Y-%m-%d}")
        col_b.write(f"**勒索软件状态：** {record['knownRansomwareCampaignUse']}")
        col_b.write(f"**CWE：** {', '.join(record['cwes']) if record['cwes'] else '未提供'}")
        st.markdown("#### 漏洞简述")
        st.write(record["shortDescription"])
        st.markdown("#### 要求采取的行动")
        st.write(record["requiredAction"])
        st.markdown("#### 备注")
        st.write(record["notes"] or "无")

with validation_tab:
    st.dataframe(validation.summary, use_container_width=True, hide_index=True)
    with st.expander("字段画像"):
        st.dataframe(validation.field_profile, use_container_width=True, hide_index=True)
