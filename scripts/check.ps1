$ErrorActionPreference = "Stop"
python scripts/verify_freeze.py
python -m pytest tests -q
python -m ruff check src tests main.py app.py scripts
python -m mypy src
python main.py --check-contracts
python -m compileall src main.py app.py
