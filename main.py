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
from kev_analysis.constants import DEFAULT_RANDOM_SEED  # noqa: E402
from kev_analysis.errors import KevError  # noqa: E402
from kev_analysis.models import PipelineConfig  # noqa: E402
from kev_analysis.pipeline import run_data_core, run_pipeline  # noqa: E402
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
    parser.add_argument("--skip-ml", action="store_true")
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
    try:
        manifest = run_pipeline(
            PipelineConfig(
                raw_json=args.input,
                output_root=args.output,
                random_seed=DEFAULT_RANDOM_SEED,
                ml_enabled=not args.skip_ml,
            )
        )
    except (KevError, OSError, ValueError) as exc:
        print(f"Pipeline failed: {exc}", file=sys.stderr)
        return 2
    print(
        f"Pipeline status={manifest.status}; artifacts={len(manifest.artifacts)}; "
        f"manifest={args.output / 'manifests' / 'run_manifest.json'}"
    )
    return 0 if manifest.status == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
