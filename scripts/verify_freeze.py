from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "FREEZE_LOCK.json"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    data = json.loads(LOCK.read_text(encoding="utf-8"))
    errors: list[str] = []
    for rel, expected in data["files"].items():
        path = ROOT / rel
        if not path.exists():
            errors.append(f"missing: {rel}")
            continue
        actual = sha256(path)
        if actual != expected:
            errors.append(f"modified: {rel}\n  expected={expected}\n  actual  ={actual}")
    if errors:
        print("Freeze verification failed:")
        print("\n".join(errors))
        return 1
    print(
        "Freeze verification passed: "
        f"{len(data['files'])} contract files, version {data['version']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
