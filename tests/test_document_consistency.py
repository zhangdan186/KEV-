from pathlib import Path

from kev_analysis.constants import CONTRACT_VERSION

ROOT = Path(__file__).resolve().parents[1]


def test_contract_version_occurs_in_machine_contracts() -> None:
    assert CONTRACT_VERSION in (ROOT / "config/default.yaml").read_text(encoding="utf-8")
    assert CONTRACT_VERSION in (ROOT / "contracts/output_registry.yaml").read_text(encoding="utf-8")


def test_required_docs_exist() -> None:
    for rel in [
        "docs/data-contract.md",
        "docs/interface-contract.md",
        "docs/output-contract.md",
        "docs/error-contract.md",
        "docs/testing-and-quality-gates.md",
        "docs/requirements-traceability.md",
    ]:
        assert (ROOT / rel).is_file(), rel
