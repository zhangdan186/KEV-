$ErrorActionPreference = "Stop"
python scripts/verify_freeze.py
python -m pytest tests -q
python main.py --check-contracts
python -m compileall src main.py app.py
