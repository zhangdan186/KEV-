from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class KevError(Exception):
    code = "KEV-UNKNOWN-000"

    def __init__(self, message: str, *, context: Mapping[str, Any] | None = None) -> None:
        self.message = message
        self.context = dict(context or {})
        super().__init__(f"[{self.code}] {message}")


class KevFileNotFoundError(KevError):
    code = "KEV-IO-001"


class KevJsonDecodeError(KevError):
    code = "KEV-IO-002"


class KevEncodingError(KevError):
    code = "KEV-IO-003"


class KevTopLevelSchemaError(KevError):
    code = "KEV-SCHEMA-001"


class KevRecordSchemaError(KevError):
    code = "KEV-SCHEMA-002"


class InvalidDateRangeError(KevError):
    code = "KEV-QRY-001"


class InvalidRansomwareStatusError(KevError):
    code = "KEV-QRY-002"


class InvalidCweError(KevError):
    code = "KEV-QRY-003"


class MissingPreparedColumnError(KevError):
    code = "KEV-QRY-004"


class OutputContractError(KevError):
    code = "KEV-OUT-001"


class ArtifactWriteError(KevError):
    code = "KEV-OUT-002"


class MlConfigurationError(KevError):
    code = "KEV-ML-001"


class MlInsufficientDataError(KevError):
    code = "KEV-ML-002"
