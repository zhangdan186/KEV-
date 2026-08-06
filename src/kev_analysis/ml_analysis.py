from __future__ import annotations

import pandas as pd

from .models import MlAnalysisResult


def analyze_text_clusters(
    df: pd.DataFrame,
    *,
    candidate_k: tuple[int, ...] = (4, 5, 6, 7, 8),
    random_state: int = 20260806,
) -> MlAnalysisResult:
    """Run reproducible TF-IDF + KMeans exploratory text clustering."""
    raise NotImplementedError("Implement according to frozen ML contract")
