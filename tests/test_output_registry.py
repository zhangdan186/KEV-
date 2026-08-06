from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_output_registry_is_parseable_and_unique() -> None:
    registry = yaml.safe_load((ROOT / "contracts/output_registry.yaml").read_text(encoding="utf-8"))
    assert registry["contract_version"] == "1.0.0"
    artifacts = registry["artifacts"]
    paths = [v["path"] for v in artifacts.values() if "path" in v]
    assert len(paths) == len(set(paths))


def test_required_core_outputs_exist_in_registry() -> None:
    registry = yaml.safe_load((ROOT / "contracts/output_registry.yaml").read_text(encoding="utf-8"))
    artifacts = registry["artifacts"]
    required = {
        "kev_prepared",
        "monthly_added_counts",
        "annual_added_summary",
        "deadline_descriptive",
        "ransomware_by_year",
        "vendor_summary",
        "concentration_metrics",
        "cve_cwe_long",
        "cwe_overall_summary",
        "query_cases_summary",
        "run_manifest",
    }
    assert required <= set(artifacts)
