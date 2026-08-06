from __future__ import annotations

import pandas as pd

from .models import CweAnalysisResult


def build_cwe_long_table(df: pd.DataFrame) -> pd.DataFrame:
    """Build a de-duplicated CVE-CWE long table."""
    raise NotImplementedError("Implement according to frozen CWE long-table contract")


def analyze_cwe(df: pd.DataFrame) -> CweAnalysisResult:
    """Analyze overall, Known and Unknown CWE occurrence using frozen denominators."""
    raise NotImplementedError("Implement according to frozen CWE-analysis contract")
