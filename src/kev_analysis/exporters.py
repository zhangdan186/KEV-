from __future__ import annotations

import hashlib
import json
import os
import platform
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict
from datetime import UTC, datetime
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from .constants import CONTRACT_VERSION, PREPARED_FIELDS
from .errors import ArtifactWriteError, OutputContractError
from .models import ArtifactRecord, OutputSpec, PathLike, RunManifest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY_PATH = PROJECT_ROOT / "contracts" / "output_registry.yaml"


def load_output_registry(registry_path: PathLike | None = None) -> dict[str, Any]:
    """Load and minimally validate the frozen machine-readable output registry."""
    path = Path(registry_path) if registry_path is not None else DEFAULT_REGISTRY_PATH
    try:
        registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise OutputContractError(
            "输出注册表无法读取",
            context={"path": str(path)},
        ) from exc
    if not isinstance(registry, dict) or not isinstance(registry.get("artifacts"), dict):
        raise OutputContractError("输出注册表缺少artifacts映射")
    if registry.get("contract_version") != CONTRACT_VERSION:
        raise OutputContractError(
            "输出注册表版本与代码契约不一致",
            context={
                "registry_version": registry.get("contract_version"),
                "contract_version": CONTRACT_VERSION,
            },
        )
    return registry


def load_output_specs(registry_path: PathLike | None = None) -> dict[str, OutputSpec]:
    """Return fixed-path OutputSpec objects from the frozen registry."""
    registry = load_output_registry(registry_path)
    specs: dict[str, OutputSpec] = {}
    for name, entry in registry["artifacts"].items():
        if not isinstance(entry, dict) or "path" not in entry:
            continue
        specs[name] = OutputSpec(
            name=name,
            path=str(entry["path"]),
            format=str(entry["format"]),
            columns=tuple(entry.get("columns", ())),
        )
    return specs


def query_case_output_spec(case_id: int) -> OutputSpec:
    if case_id <= 0:
        raise OutputContractError("query case id必须为正整数")
    return OutputSpec(
        name=f"query_case_{case_id}",
        path=f"queries/query_case_{case_id}.csv",
        format="csv",
        columns=PREPARED_FIELDS,
    )


def _output_path(root: PathLike, spec: OutputSpec) -> Path:
    root_path = Path(root).resolve()
    target = (root_path / spec.path).resolve()
    try:
        target.relative_to(root_path)
    except ValueError as exc:
        raise OutputContractError(
            "输出路径不能越出输出根目录", context={"path": spec.path}
        ) from exc
    if target.suffix.lower().lstrip(".") != spec.format.lower():
        raise OutputContractError(
            "输出扩展名与格式不一致",
            context={"path": spec.path, "format": spec.format},
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def _atomic_replace(target: Path, writer: Callable[[Path], Any]) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            delete=False, dir=target.parent, suffix=target.suffix
        ) as stream:
            temporary = Path(stream.name)
        writer(temporary)
        os.replace(temporary, target)
    except OSError as exc:
        raise ArtifactWriteError("产物写入失败", context={"path": str(target)}) from exc
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def export_dataframe(df: pd.DataFrame, spec: OutputSpec, root: PathLike) -> Path:
    """Validate columns/order and export a CSV using the frozen serialization rules."""
    if spec.format.lower() != "csv":
        raise OutputContractError("DataFrame只能导出为CSV", context={"format": spec.format})
    missing = [column for column in spec.columns if column not in df.columns]
    if missing:
        raise OutputContractError("DataFrame缺少注册列", context={"missing": missing})
    exported = df.loc[:, spec.columns].copy(deep=True) if spec.columns else df.copy(deep=True)
    if "cwes" in exported.columns:
        invalid = ~exported["cwes"].map(lambda value: isinstance(value, list))
        if invalid.any():
            raise OutputContractError("cwes导出前必须保持列表类型")
        exported["cwes"] = exported["cwes"].map(
            lambda value: json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        )
    target = _output_path(root, spec)
    _atomic_replace(
        target,
        lambda path: exported.to_csv(
            path,
            index=False,
            encoding="utf-8-sig",
            float_format="%.8f",
            date_format="%Y-%m-%d",
        ),
    )
    return target


def export_json(data: Mapping[str, Any], spec: OutputSpec, root: PathLike) -> Path:
    if spec.format.lower() != "json":
        raise OutputContractError("映射数据只能导出为JSON", context={"format": spec.format})
    target = _output_path(root, spec)
    _atomic_replace(
        target,
        lambda path: path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n",
            encoding="utf-8",
        ),
    )
    return target


def export_figure(fig: Any, spec: OutputSpec, root: PathLike) -> Path:
    if spec.format.lower() != "png":
        raise OutputContractError("Figure只能导出为PNG", context={"format": spec.format})
    if not hasattr(fig, "savefig"):
        raise OutputContractError("图表对象不支持savefig")
    target = _output_path(root, spec)
    _atomic_replace(target, lambda path: fig.savefig(path, dpi=300, bbox_inches="tight"))
    return target


def export_html(content: str, spec: OutputSpec, root: PathLike) -> Path:
    if spec.format.lower() != "html":
        raise OutputContractError("HTML内容只能导出为HTML", context={"format": spec.format})
    target = _output_path(root, spec)
    _atomic_replace(target, lambda path: path.write_text(content, encoding="utf-8"))
    return target


def write_run_manifest(records: Sequence[ArtifactRecord], root: PathLike) -> Path:
    """Write the frozen artifact-only manifest interface for compatibility."""
    target = Path(root).resolve() / "manifests" / "run_manifest.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "contract_version": CONTRACT_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "artifacts": [asdict(record) for record in records],
    }
    _atomic_replace(
        target,
        lambda path: path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        ),
    )
    return target


def write_pipeline_manifest(manifest: RunManifest, root: PathLike) -> Path:
    """Write the complete reproducibility manifest used by the full pipeline."""
    target = Path(root).resolve() / "manifests" / "run_manifest.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    packages: dict[str, str] = {}
    for package in ("pandas", "numpy", "matplotlib", "plotly", "scikit-learn"):
        try:
            packages[package] = importlib_metadata.version(package)
        except importlib_metadata.PackageNotFoundError:
            packages[package] = "not-installed"
    payload = {
        "contract_version": manifest.contract_version,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": manifest.status,
        "input_path": manifest.input_path,
        "input_sha256": manifest.input_sha256,
        "environment": {"python": platform.python_version(), "packages": packages},
        "artifacts": [asdict(record) for record in manifest.artifacts],
    }
    _atomic_replace(
        target,
        lambda path: path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        ),
    )
    return target


def sha256_file(path: PathLike) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def describe_artifact(name: str, path: Path, *, root: PathLike) -> ArtifactRecord:
    """Build manifest metadata for a written artifact."""
    row_count: int | None = None
    columns: tuple[str, ...] = ()
    if path.suffix.lower() == ".csv":
        frame = pd.read_csv(path, encoding="utf-8-sig")
        row_count = len(frame)
        columns = tuple(frame.columns)
    return ArtifactRecord(
        name=name,
        path=path.resolve().relative_to(Path(root).resolve()).as_posix(),
        sha256=sha256_file(path),
        bytes=path.stat().st_size,
        row_count=row_count,
        columns=columns,
    )


def find_missing_required_artifacts(root: PathLike, *, ml_enabled: bool) -> tuple[str, ...]:
    """Return required registry paths absent from an output directory."""
    registry = load_output_registry()
    root_path = Path(root)
    missing: list[str] = []
    for _name, entry in registry["artifacts"].items():
        if not isinstance(entry, dict):
            continue
        required = bool(entry.get("required")) or (
            entry.get("required_when") == "ml.enabled" and ml_enabled
        )
        if required and "path" in entry and not (root_path / str(entry["path"])).is_file():
            missing.append(str(entry["path"]))
        if "path_pattern" in entry:
            minimum = int(entry.get("required_count_min", 0))
            matches = tuple(root_path.glob(str(entry["path_pattern"]).replace("{case_id}", "*")))
            if len(matches) < minimum:
                missing.append(f"{entry['path_pattern']} (至少{minimum}个，实际{len(matches)}个)")
    return tuple(sorted(missing))


def clear_registered_artifacts(root: PathLike) -> None:
    """Remove only files declared by the output registry, preserving unrelated files."""
    registry = load_output_registry()
    root_path = Path(root).resolve()
    for entry in registry["artifacts"].values():
        if not isinstance(entry, dict):
            continue
        if "path" in entry:
            target = (root_path / str(entry["path"])).resolve()
            try:
                target.relative_to(root_path)
            except ValueError as exc:
                raise OutputContractError(
                    "注册产物路径越出输出根目录",
                    context={"path": str(entry["path"])},
                ) from exc
            target.unlink(missing_ok=True)
        if "path_pattern" in entry:
            pattern = str(entry["path_pattern"]).replace("{case_id}", "*")
            for target in root_path.glob(pattern):
                if target.is_file():
                    target.unlink()
