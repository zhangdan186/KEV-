from pathlib import Path

from kev_analysis.cleaner import prepare_kev_dataframe
from kev_analysis.loader import load_kev_json
from kev_analysis.validator import validate_raw_kev

data_path = Path("data/CISA_KEV_2026-07-29.json")

metadata, raw_df = load_kev_json(data_path)
report = validate_raw_kev(metadata, raw_df)

assert report.is_valid

prepared_df = prepare_kev_dataframe(raw_df)

print(prepared_df.shape)
print(prepared_df.columns.tolist())
print(type(prepared_df.loc[0, "cwes"]))
print(prepared_df[["cveID", "vendor_clean", "cwes"]].head())