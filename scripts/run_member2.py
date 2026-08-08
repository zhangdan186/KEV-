from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from kev_analysis.cleaner import prepare_kev_dataframe  # noqa: E402
from kev_analysis.deadline_analysis import analyze_deadlines  # noqa: E402
from kev_analysis.exporters import export_dataframe, export_figure  # noqa: E402
from kev_analysis.loader import load_kev_json  # noqa: E402
from kev_analysis.ml_analysis import analyze_text_clusters  # noqa: E402
from kev_analysis.models import OutputSpec  # noqa: E402
from kev_analysis.ransomware_analysis import analyze_ransomware_status  # noqa: E402
from kev_analysis.time_analysis import analyze_added_time  # noqa: E402
from kev_analysis.validator import validate_raw_kev  # noqa: E402
from kev_analysis.vendor_analysis import analyze_vendors  # noqa: E402


def _load_output_specs() -> dict[str, OutputSpec]:
    registry_path = ROOT / "contracts" / "output_registry.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    specs: dict[str, OutputSpec] = {}
    for name, entry in registry["artifacts"].items():
        if "path" not in entry:
            continue
        specs[name] = OutputSpec(
            name=name,
            path=entry["path"],
            format=entry["format"],
            columns=tuple(entry.get("columns", ())),
        )
    return specs


def run_member2(
    input_path: Path,
    output_root: Path,
    *,
    run_ml: bool,
    candidate_k: tuple[int, ...],
) -> list[Path]:
    metadata, raw = load_kev_json(input_path)
    validation = validate_raw_kev(metadata, raw)
    if not validation.is_valid:
        issue_codes = sorted({issue.code for issue in validation.issues})
        raise ValueError(f"input failed validation; issue codes: {issue_codes}")
    prepared = prepare_kev_dataframe(raw)

    time_result = analyze_added_time(prepared)
    deadline_result = analyze_deadlines(prepared)
    ransomware_result = analyze_ransomware_status(prepared)
    vendor_result = analyze_vendors(prepared)
    ml_result = analyze_text_clusters(prepared, candidate_k=candidate_k) if run_ml else None

    specs = _load_output_specs()
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

    written = [
        export_dataframe(frame, specs[name], output_root) for name, frame in table_outputs.items()
    ]

    figure_outputs = {
        "monthly_added_trend_figure": time_result.figures["monthly_added_trend"],
        "deadline_distribution_figure": deadline_result.figures["deadline_distribution"],
        "ransomware_by_year_figure": ransomware_result.figures["ransomware_by_year"],
        "vendor_top15_figure": vendor_result.figures["vendor_top15"],
        "vendor_cumulative_share_figure": vendor_result.figures["vendor_cumulative_share"],
    }
    if ml_result is not None:
        figure_outputs["ml_clusters_figure"] = ml_result.figures["ml_clusters"]
    for name, figure in figure_outputs.items():
        written.append(export_figure(figure, specs[name], output_root))
        plt.close(figure)

    html_spec = specs["vendor_product_treemap"]
    html_path = output_root.resolve() / html_spec.path
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(vendor_result.html["vendor_product_treemap"], encoding="utf-8")
    written.append(html_path)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run member 2 statistical and exploratory text-clustering analyses."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=ROOT / "data" / "CISA_KEV_2026-07-29.json",
    )
    parser.add_argument("--output", type=Path, default=ROOT / "outputs")
    parser.add_argument("--skip-ml", action="store_true")
    parser.add_argument("--candidate-k", nargs="+", type=int, default=[4, 5, 6, 7, 8])
    args = parser.parse_args()

    written = run_member2(
        args.input,
        args.output,
        run_ml=not args.skip_ml,
        candidate_k=tuple(args.candidate_k),
    )
    print(f"Member 2 analysis complete: {len(written)} artifacts written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
