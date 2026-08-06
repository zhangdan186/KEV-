from __future__ import annotations

import pandas as pd

from .models import VendorAnalysisResult


def analyze_vendors(df: pd.DataFrame) -> VendorAnalysisResult:
    """Analyze vendor/product labels and CR5, CR10 and unscaled HHI."""
    raise NotImplementedError("Implement according to frozen vendor-analysis contract")
