from __future__ import annotations

import argparse
import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from kev_analysis import CONTRACT_VERSION  # noqa: E402
from kev_analysis.pipeline import run_data_core  # noqa: E402
from kev_analysis.query import filter_kev  # noqa: E402


def check_contracts() -> int:
    expected = ["df", "start_date", "end_date", "vendor", "ransomware", "cwe"]
    actual = list(inspect.signature(filter_kev).parameters)
    if actual != expected:
        print(f"Contract mismatch: filter_kev parameters={actual}, expected={expected}")
        return 1
    print(f"KEV freeze contract {CONTRACT_VERSION}: interface check passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-contracts", action="store_true")
    parser.add_argument(
        "--data-core",
        action="store_true",
        help="run member 1 data loading, validation, cleaning and export stages",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=ROOT / "data" / "CISA_KEV_2026-07-29.json",
    )
    parser.add_argument("--output", type=Path, default=ROOT / "outputs")
    args = parser.parse_args()
    if args.check_contracts:
        return check_contracts()
    if args.data_core:
        result = run_data_core(args.input, args.output)
        print(
            f"Data core status={result.status}; records={result.metadata.count}; "
            f"validation_issues={len(result.validation.issues)}; artifacts={len(result.artifacts)}"
        )
        return 0 if result.status == "data_core_complete" else 2
    print(
        "This is the development-freeze skeleton. "
        "Implement run_pipeline() before using main.py for final analysis."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
