from __future__ import annotations

import pandas as pd

from .models import DateLike, ExtendedKevFilter, QuerySummary


def filter_kev(
    df: pd.DataFrame,
    start_date: DateLike | None = None,
    end_date: DateLike | None = None,
    vendor: str | None = None,
    ransomware: str | None = None,
    cwe: str | None = None,
) -> tuple[pd.DataFrame, QuerySummary]:
    """Frozen assignment-specified multi-condition query interface."""
    raise NotImplementedError("Implement according to frozen query contract")


def filter_kev_extended(
    df: pd.DataFrame,
    filters: ExtendedKevFilter,
) -> tuple[pd.DataFrame, QuerySummary]:
    """GUI wrapper adding product literal substring filtering.

    It must call filter_kev first and must not duplicate core query logic.
    """
    raise NotImplementedError("Implement according to frozen GUI extension contract")
