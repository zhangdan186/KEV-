from kev_analysis.constants import (
    CWE_DENOMINATORS,
    DERIVED_FIELDS,
    EXPECTED_EMPTY_CWE_COUNT,
    EXPECTED_KNOWN_WITH_CWE_COUNT,
    EXPECTED_PRODUCT_WHITESPACE_COUNT,
    EXPECTED_RAW_FIELD_COUNT,
    EXPECTED_RECORD_COUNT,
    EXPECTED_UNKNOWN_WITH_CWE_COUNT,
    EXPECTED_VENDOR_WHITESPACE_COUNT,
    EXPECTED_WITH_CWE_COUNT,
    PREPARED_FIELDS,
    RAW_FIELDS,
)


def test_raw_fields_are_exactly_frozen() -> None:
    assert len(RAW_FIELDS) == EXPECTED_RAW_FIELD_COUNT == 11
    assert RAW_FIELDS[0] == "cveID"
    assert RAW_FIELDS[-1] == "cwes"


def test_prepared_fields_are_raw_plus_seven_derived() -> None:
    assert PREPARED_FIELDS == RAW_FIELDS + DERIVED_FIELDS
    assert len(DERIVED_FIELDS) == 7


def test_snapshot_golden_counts_are_consistent() -> None:
    assert EXPECTED_RECORD_COUNT == 1656
    assert EXPECTED_EMPTY_CWE_COUNT + EXPECTED_WITH_CWE_COUNT == EXPECTED_RECORD_COUNT
    assert (
        EXPECTED_KNOWN_WITH_CWE_COUNT + EXPECTED_UNKNOWN_WITH_CWE_COUNT == EXPECTED_WITH_CWE_COUNT
    )
    assert CWE_DENOMINATORS == {"overall": 1485, "Known": 294, "Unknown": 1191}
    assert EXPECTED_VENDOR_WHITESPACE_COUNT == 6
    assert EXPECTED_PRODUCT_WHITESPACE_COUNT == 10
