from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from .constants import CONTRACT_VERSION
from .errors import ArtifactWriteError, OutputContractError
from .models import ArtifactRecord, OutputSpec, PathLike


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


def _atomic_replace(target: Path, writer: Any) -> None:
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
    """Validate columns/order and export according to output registry."""
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


def write_run_manifest(records: Sequence[ArtifactRecord], root: PathLike) -> Path:
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


def describe_artifact(name: str, path: Path, *, root: PathLike) -> ArtifactRecord:
    """Build manifest metadata for a written artifact."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    row_count: int | None = None
    columns: tuple[str, ...] = ()
    if path.suffix.lower() == ".csv":
        frame = pd.read_csv(path, encoding="utf-8-sig")
        row_count = len(frame)
        columns = tuple(frame.columns)
    return ArtifactRecord(
        name=name,
        path=path.resolve().relative_to(Path(root).resolve()).as_posix(),
        sha256=digest,
        bytes=path.stat().st_size,
        row_count=row_count,
        columns=columns,
    )
