from __future__ import annotations

CONTRACT_VERSION = "1.0.0"

RAW_FIELDS: tuple[str, ...] = (
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "notes",
    "cwes",
)

DERIVED_FIELDS: tuple[str, ...] = (
    "vendor_clean",
    "product_clean",
    "added_year",
    "added_month",
    "deadline_days",
    "has_cwe",
    "cwe_count",
)

PREPARED_FIELDS: tuple[str, ...] = RAW_FIELDS + DERIVED_FIELDS
TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "title",
    "catalogVersion",
    "dateReleased",
    "count",
    "vulnerabilities",
)

CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,19}$"
CWE_PATTERN = r"^CWE-[0-9]+$"
RANSOMWARE_VALUES = frozenset({"Known", "Unknown"})

EXPECTED_RECORD_COUNT = 1656
EXPECTED_RAW_FIELD_COUNT = 11
EXPECTED_EMPTY_CWE_COUNT = 171
EXPECTED_WITH_CWE_COUNT = 1485
EXPECTED_KNOWN_WITH_CWE_COUNT = 294
EXPECTED_UNKNOWN_WITH_CWE_COUNT = 1191
EXPECTED_VENDOR_WHITESPACE_COUNT = 6
EXPECTED_PRODUCT_WHITESPACE_COUNT = 10

MONTHLY_START = "2021-11"
MONTHLY_END = "2026-07"
INCOMPLETE_YEARS = frozenset({2021, 2026})

CWE_DENOMINATORS = {
    "overall": EXPECTED_WITH_CWE_COUNT,
    "Known": EXPECTED_KNOWN_WITH_CWE_COUNT,
    "Unknown": EXPECTED_UNKNOWN_WITH_CWE_COUNT,
}

DEFAULT_RANDOM_SEED = 20260806
