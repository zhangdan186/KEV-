from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd

from .cleaner import prepare_kev_dataframe
from .constants import CONTRACT_VERSION
from .cwe_analysis import analyze_cwe
from .deadline_analysis import analyze_deadlines
from .errors import OutputContractError
from .exporters import (
    clear_registered_artifacts,
    describe_artifact,
    export_dataframe,
    export_figure,
    export_html,
    export_json,
    find_missing_required_artifacts,
    load_output_specs,
    query_case_output_spec,
    sha256_file,
    write_pipeline_manifest,
)
from .loader import load_kev_json
from .ml_analysis import analyze_text_clusters
from .models import (
    ArtifactRecord,
    DataCoreResult,
    KevMetadata,
    OutputSpec,
    PipelineConfig,
    RunManifest,
    ValidationReport,
)
from .query_cases import execute_query_cases
from .ransomware_analysis import analyze_ransomware_status
from .time_analysis import analyze_added_time
from .validator import DETAIL_COLUMNS, PROFILE_COLUMNS, SUMMARY_COLUMNS, validate_raw_kev
from .vendor_analysis import analyze_vendors


def _metadata_payload(metadata: KevMetadata, raw: pd.DataFrame) -> dict[str, Any]:
    return {
        "title": metadata.title,
        "catalogVersion": metadata.catalog_version,
        "dateReleased": metadata.date_released,
        "count": metadata.count,
        "actualRecordCount": len(raw),
        "originalFields": list(raw.columns),
    }


def _add_record(
    records: list[ArtifactRecord],
    name: str,
    path: Path,
    root: Path,
) -> None:
    records.append(describe_artifact(name, path, root=root))


def _export_validation(
    metadata: KevMetadata,
    raw: pd.DataFrame,
    validation: ValidationReport,
    root: Path,
    specs: dict[str, OutputSpec],
) -> list[ArtifactRecord]:
    records: list[ArtifactRecord] = []
    metadata_path = export_json(_metadata_payload(metadata, raw), specs["metadata"], root)
    _add_record(records, "metadata", metadata_path, root)

    validation_outputs = (
        ("validation_summary", validation.summary, SUMMARY_COLUMNS),
        ("validation_details", validation.details, DETAIL_COLUMNS),
        ("field_profile", validation.field_profile, PROFILE_COLUMNS),
    )
    for name, frame, columns in validation_outputs:
        spec = specs[name]
        if tuple(columns) != spec.columns:
            raise OutputContractError(
                "验证输出列与注册表不一致",
                context={"artifact": name},
            )
        path = export_dataframe(frame, spec, root)
        _add_record(records, name, path, root)
    return records


def run_data_core(raw_json: Path, output_root: Path) -> DataCoreResult:
    """Run member 1's load, validate, prepare and core-export stages."""
    metadata, raw = load_kev_json(raw_json)
    validation = validate_raw_kev(metadata, raw)
    root = Path(output_root)
    specs = load_output_specs()
    records = _export_validation(metadata, raw, validation, root, specs)

    if not validation.is_valid:
        return DataCoreResult(metadata, validation, None, tuple(records), "validation_failed")

    prepared = prepare_kev_dataframe(raw)
    prepared_path = export_dataframe(
        prepared.sort_values(["dateAdded", "cveID"], kind="mergesort"),
        specs["kev_prepared"],
        root,
    )
    _add_record(records, "kev_prepared", prepared_path, root)
    return DataCoreResult(metadata, validation, prepared, tuple(records), "data_core_complete")


def run_pipeline(config: PipelineConfig) -> RunManifest:
    """Run the frozen eight-stage pipeline and export every registered artifact."""
    raw_path = Path(config.raw_json).resolve()
    root = Path(config.output_root).resolve()
    specs = load_output_specs()
    input_digest = sha256_file(raw_path)

    metadata, raw = load_kev_json(raw_path)
    validation = validate_raw_kev(metadata, raw)
    clear_registered_artifacts(root)
    records = _export_validation(metadata, raw, validation, root, specs)

    if not validation.is_valid:
        failed_manifest = RunManifest(
            contract_version=CONTRACT_VERSION,
            input_path=str(raw_path),
            input_sha256=input_digest,
            artifacts=tuple(records),
            status="validation_failed",
        )
        write_pipeline_manifest(failed_manifest, root)
        return failed_manifest

    prepared = prepare_kev_dataframe(raw)
    prepared_path = export_dataframe(
        prepared.sort_values(["dateAdded", "cveID"], kind="mergesort"),
        specs["kev_prepared"],
        root,
    )
    _add_record(records, "kev_prepared", prepared_path, root)

    time_result = analyze_added_time(prepared)
    deadline_result = analyze_deadlines(prepared)
    ransomware_result = analyze_ransomware_status(prepared)
    vendor_result = analyze_vendors(prepared)
    cwe_result = analyze_cwe(prepared)
    query_summary, query_results = execute_query_cases(prepared)
    ml_result = (
        analyze_text_clusters(prepared, random_state=config.random_seed)
        if config.ml_enabled
        else None
    )

    table_outputs: dict[str, pd.DataFrame] = {
        "monthly_added_counts": time_result.monthly_counts,
        "annual_added_summary": time_result.annual_summary,
        "same_period_comparison": time_result.same_period_comparison,
        "deadline_descriptive": deadline_result.descriptive,
        "deadline_frequency": deadline_result.frequency,
        "deadline_by_year": deadline_result.by_year,
        "ransomware_summary": ransomware_result.overall,
        "ransomware_by_year": ransomware_result.by_year,
        "vendor_summary": vendor_result.vendor_summary,
        "vendor_product_summary": vendor_result.vendor_product_summary,
        "vendor_product_top30": vendor_result.vendor_product_top30,
        "concentration_metrics": vendor_result.concentration_metrics,
        "cve_cwe_long": cwe_result.long_table,
        "cwe_overall_summary": cwe_result.overall,
        "cwe_known_summary": cwe_result.known,
        "cwe_unknown_summary": cwe_result.unknown,
        "query_cases_summary": query_summary,
    }
    if ml_result is not None:
        table_outputs.update(
            {
                "ml_cluster_results": ml_result.cluster_results,
                "ml_cluster_selection": ml_result.cluster_selection,
                "ml_cluster_summary": ml_result.cluster_summary,
                "ml_cluster_keywords": ml_result.cluster_keywords,
            }
        )

    for name, frame in table_outputs.items():
        path = export_dataframe(frame, specs[name], root)
        _add_record(records, name, path, root)

    for case_id, frame in sorted(query_results.items()):
        name = f"query_case_{case_id}"
        path = export_dataframe(frame, query_case_output_spec(case_id), root)
        _add_record(records, name, path, root)

    figure_outputs: dict[str, Any] = {
        "monthly_added_trend_figure": time_result.figures["monthly_added_trend"],
        "deadline_distribution_figure": deadline_result.figures["deadline_distribution"],
        "ransomware_by_year_figure": ransomware_result.figures["ransomware_by_year"],
        "vendor_top15_figure": vendor_result.figures["vendor_top15"],
        "vendor_cumulative_share_figure": vendor_result.figures["vendor_cumulative_share"],
        "cwe_top20_figure": cwe_result.figures["cwe_top20"],
        "cwe_known_unknown_figure": cwe_result.figures["cwe_known_unknown"],
    }
    if ml_result is not None:
        figure_outputs["ml_clusters_figure"] = ml_result.figures["ml_clusters"]

    for name, figure in figure_outputs.items():
        path = export_figure(figure, specs[name], root)
        _add_record(records, name, path, root)
        plt.close(figure)

    treemap_path = export_html(
        vendor_result.html["vendor_product_treemap"],
        specs["vendor_product_treemap"],
        root,
    )
    _add_record(records, "vendor_product_treemap", treemap_path, root)

    manifest = RunManifest(
        contract_version=CONTRACT_VERSION,
        input_path=str(raw_path),
        input_sha256=input_digest,
        artifacts=tuple(records),
        status="complete",
    )
    write_pipeline_manifest(manifest, root)
    missing = find_missing_required_artifacts(root, ml_enabled=config.ml_enabled)
    if missing:
        raise OutputContractError(
            "流水线未生成全部必需产物",
            context={"missing": list(missing)},
        )
    return manifest
