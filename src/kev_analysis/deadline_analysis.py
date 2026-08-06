from __future__ import annotations

import pandas as pd

from .models import DeadlineAnalysisResult


def analyze_deadlines(df: pd.DataFrame) -> DeadlineAnalysisResult:
    """Analyze the CISA action-window term structure."""
    raise NotImplementedError("Implement according to frozen deadline-analysis contract")
