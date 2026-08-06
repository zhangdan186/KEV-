from __future__ import annotations

from pathlib import Path

from .cleaner import prepare_kev_dataframe
from .constants import PREPARED_FIELDS
from .exporters import describe_artifact, export_dataframe, export_json
from .loader import load_kev_json
from .models import DataCoreResult, OutputSpec, PipelineConfig, RunManifest
from .validator import DETAIL_COLUMNS, PROFILE_COLUMNS, SUMMARY_COLUMNS, validate_raw_kev


def run_data_core(raw_json: Path, output_root: Path) -> DataCoreResult:
    """Run member 1's load, validate, prepare and core-export stages."""
    metadata, raw = load_kev_json(raw_json)
    validation = validate_raw_kev(metadata, raw)
    root = Path(output_root)
    records = []

    metadata_path = export_json(
        {
            "title": metadata.title,
            "catalogVersion": metadata.catalog_version,
            "dateReleased": metadata.date_released,
            "count": metadata.count,
            "actualRecordCount": len(raw),
            "originalFields": list(raw.columns),
        },
        OutputSpec("metadata", "validation/metadata.json", "json"),
        root,
    )
    records.append(describe_artifact("metadata", metadata_path, root=root))

    validation_specs = (
        (
            "validation_summary",
            "validation/validation_summary.csv",
            validation.summary,
            SUMMARY_COLUMNS,
        ),
        (
            "validation_details",
            "validation/validation_details.csv",
            validation.details,
            DETAIL_COLUMNS,
        ),
        (
            "field_profile",
            "validation/field_profile.csv",
            validation.field_profile,
            PROFILE_COLUMNS,
        ),
    )
    for name, path, frame, columns in validation_specs:
        artifact_path = export_dataframe(
            frame,
            OutputSpec(name, path, "csv", tuple(columns)),
            root,
        )
        records.append(describe_artifact(name, artifact_path, root=root))

    if not validation.is_valid:
        return DataCoreResult(metadata, validation, None, tuple(records), "validation_failed")

    prepared = prepare_kev_dataframe(raw)
    prepared_path = export_dataframe(
        prepared.sort_values(["dateAdded", "cveID"], kind="mergesort"),
        OutputSpec(
            "kev_prepared",
            "prepared/kev_prepared.csv",
            "csv",
            PREPARED_FIELDS,
        ),
        root,
    )
    records.append(describe_artifact("kev_prepared", prepared_path, root=root))
    return DataCoreResult(metadata, validation, prepared, tuple(records), "data_core_complete")


def run_pipeline(config: PipelineConfig) -> RunManifest:
    """Run the frozen eight-stage pipeline."""
    raise NotImplementedError("Implement according to frozen pipeline contract")
