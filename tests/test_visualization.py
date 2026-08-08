from __future__ import annotations

import matplotlib.pyplot as plt
import pandas as pd
import pytest

from kev_analysis.visualization import (
    configure_chart_style,
    make_deadline_distribution_figure,
    make_monthly_added_figure,
    make_ransomware_by_year_figure,
    make_vendor_cumulative_figure,
    make_vendor_top_figure,
)


def test_chart_style_selects_an_installed_font() -> None:
    assert configure_chart_style()


@pytest.mark.parametrize(
    ("factory", "frame"),
    [
        (
            make_monthly_added_figure,
            pd.DataFrame({"added_month": ["2026-01"], "record_count": [3]}),
        ),
        (
            make_deadline_distribution_figure,
            pd.DataFrame({"deadline_days": [21], "record_count": [3]}),
        ),
        (
            make_ransomware_by_year_figure,
            pd.DataFrame({"added_year": [2026], "known_count": [1], "unknown_count": [2]}),
        ),
        (
            make_vendor_top_figure,
            pd.DataFrame({"vendor_clean": ["Vendor"], "record_count": [3]}),
        ),
        (
            make_vendor_cumulative_figure,
            pd.DataFrame({"vendor_clean": ["Vendor"], "cumulative_share": [1.0]}),
        ),
    ],
)
def test_public_visualization_functions_return_renderable_figures(
    factory: object,
    frame: pd.DataFrame,
) -> None:
    figure = factory(frame)  # type: ignore[operator]
    assert figure.axes
    figure.canvas.draw()
    plt.close(figure)
