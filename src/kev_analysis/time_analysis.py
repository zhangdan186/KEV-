from __future__ import annotations

import pandas as pd

from .models import TimeAnalysisResult


def analyze_added_time(df: pd.DataFrame) -> TimeAnalysisResult:
    """Analyze continuous monthly sequence, annual coverage and comparable periods."""
    raise NotImplementedError("Implement according to frozen time-analysis contract")
