from __future__ import annotations

from typing import Any

import pandas as pd


def make_monthly_added_figure(monthly_counts: pd.DataFrame) -> Any:
    raise NotImplementedError


def make_deadline_distribution_figure(deadline_frequency: pd.DataFrame) -> Any:
    raise NotImplementedError


def make_ransomware_by_year_figure(by_year: pd.DataFrame) -> Any:
    raise NotImplementedError


def make_vendor_top_figure(vendor_summary: pd.DataFrame, *, top_n: int = 15) -> Any:
    raise NotImplementedError


def make_vendor_cumulative_figure(vendor_summary: pd.DataFrame) -> Any:
    raise NotImplementedError


def make_cwe_top_figure(cwe_summary: pd.DataFrame, *, top_n: int = 20) -> Any:
    raise NotImplementedError
