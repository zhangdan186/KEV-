import inspect

from kev_analysis.cleaner import prepare_kev_dataframe
from kev_analysis.cwe_analysis import analyze_cwe, build_cwe_long_table
from kev_analysis.loader import load_kev_json
from kev_analysis.query import filter_kev, filter_kev_extended
from kev_analysis.validator import validate_raw_kev


def params(func: object) -> list[str]:
    return list(inspect.signature(func).parameters)


def test_core_interface_names() -> None:
    assert params(load_kev_json) == ["file_path"]
    assert params(validate_raw_kev) == ["metadata", "df"]
    assert params(prepare_kev_dataframe) == ["df"]
    assert params(build_cwe_long_table) == ["df"]
    assert params(analyze_cwe) == ["df"]


def test_assignment_filter_signature_is_frozen() -> None:
    assert params(filter_kev) == [
        "df",
        "start_date",
        "end_date",
        "vendor",
        "ransomware",
        "cwe",
    ]


def test_gui_extension_is_separate() -> None:
    assert params(filter_kev_extended) == ["df", "filters"]
