from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

PathLike = str | Path
DateLike = str | pd.Timestamp


@dataclass(frozen=True)
class KevMetadata:
    title: str
    catalog_version: str
    date_released: str
    count: int


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    severity: str
    message: str
    field: str | None = None
    row_index: int | None = None
    cve_id: str | None = None
    observed_value: Any = None


@dataclass(frozen=True)
class ValidationReport:
    is_valid: bool
    issues: tuple[ValidationIssue, ...]
    summary: pd.DataFrame
    details: pd.DataFrame
    field_profile: pd.DataFrame


@dataclass(frozen=True)
class QuerySummary:
    record_count: int
    vendor_count: int
    max_date: pd.Timestamp | None
    known_count: int


@dataclass(frozen=True)
class ExtendedKevFilter:
    start_date: DateLike | None = None
    end_date: DateLike | None = None
    vendor: str | None = None
    product: str | None = None
    ransomware: str | None = None
    cwe: str | None = None


@dataclass(frozen=True)
class TimeAnalysisResult:
    monthly_counts: pd.DataFrame
    annual_summary: pd.DataFrame
    same_period_comparison: pd.DataFrame
    figures: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DeadlineAnalysisResult:
    descriptive: pd.DataFrame
    frequency: pd.DataFrame
    by_year: pd.DataFrame
    figures: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RansomwareAnalysisResult:
    overall: pd.DataFrame
    by_year: pd.DataFrame
    figures: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VendorAnalysisResult:
    vendor_summary: pd.DataFrame
    vendor_product_summary: pd.DataFrame
    vendor_product_top30: pd.DataFrame
    concentration_metrics: pd.DataFrame
    figures: Mapping[str, Any] = field(default_factory=dict)
    html: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CweAnalysisResult:
    long_table: pd.DataFrame
    overall: pd.DataFrame
    known: pd.DataFrame
    unknown: pd.DataFrame
    figures: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MlAnalysisResult:
    cluster_results: pd.DataFrame
    cluster_selection: pd.DataFrame
    cluster_summary: pd.DataFrame
    cluster_keywords: pd.DataFrame
    figures: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OutputSpec:
    name: str
    path: str
    format: str
    columns: tuple[str, ...] = ()


@dataclass(frozen=True)
class ArtifactRecord:
    name: str
    path: str
    sha256: str
    bytes: int
    row_count: int | None = None
    columns: tuple[str, ...] = ()


@dataclass(frozen=True)
class PipelineConfig:
    raw_json: Path
    output_root: Path
    random_seed: int
    ml_enabled: bool = True


@dataclass(frozen=True)
class RunManifest:
    contract_version: str
    input_path: str
    input_sha256: str
    artifacts: tuple[ArtifactRecord, ...]
    status: str


@dataclass(frozen=True)
class DataCoreResult:
    metadata: KevMetadata
    validation: ValidationReport
    prepared: pd.DataFrame | None
    artifacts: tuple[ArtifactRecord, ...]
    status: str
