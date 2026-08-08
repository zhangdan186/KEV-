from __future__ import annotations

import json
from pathlib import Path

from kev_analysis.constants import CONTRACT_VERSION, DEFAULT_RANDOM_SEED
from kev_analysis.exporters import find_missing_required_artifacts, sha256_file
from kev_analysis.models import PipelineConfig
from kev_analysis.pipeline import run_pipeline

ROOT = Path(__file__).resolve().parents[1]
COURSE_JSON = ROOT / "data" / "CISA_KEV_2026-07-29.json"


def test_full_pipeline_without_ml_writes_every_required_artifact(tmp_path: Path) -> None:
    input_hash = sha256_file(COURSE_JSON)
    result = run_pipeline(
        PipelineConfig(
            raw_json=COURSE_JSON,
            output_root=tmp_path,
            random_seed=DEFAULT_RANDOM_SEED,
            ml_enabled=False,
        )
    )

    assert result.status == "complete"
    assert result.contract_version == CONTRACT_VERSION
    assert result.input_sha256 == input_hash == sha256_file(COURSE_JSON)
    assert len(result.artifacts) == 33
    assert find_missing_required_artifacts(tmp_path, ml_enabled=False) == ()
    assert len(tuple((tmp_path / "queries").glob("query_case_*.csv"))) == 3

    manifest_path = tmp_path / "manifests" / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "complete"
    assert manifest["input_sha256"] == input_hash
    assert manifest["environment"]["python"]
    assert len(manifest["artifacts"]) == 33


def test_pipeline_stops_after_fatal_validation_and_records_failure(tmp_path: Path) -> None:
    payload = json.loads(COURSE_JSON.read_text(encoding="utf-8"))
    payload["count"] = 1
    invalid_json = tmp_path / "invalid-count.json"
    invalid_json.write_text(json.dumps(payload), encoding="utf-8")
    output_root = tmp_path / "outputs"
    stale_prepared = output_root / "prepared" / "kev_prepared.csv"
    stale_prepared.parent.mkdir(parents=True)
    stale_prepared.write_text("stale", encoding="utf-8")

    result = run_pipeline(
        PipelineConfig(
            raw_json=invalid_json,
            output_root=output_root,
            random_seed=DEFAULT_RANDOM_SEED,
            ml_enabled=False,
        )
    )

    assert result.status == "validation_failed"
    assert not stale_prepared.exists()
    assert (output_root / "validation" / "validation_summary.csv").is_file()
    manifest = json.loads(
        (output_root / "manifests" / "run_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["status"] == "validation_failed"
    assert len(manifest["artifacts"]) == 4
