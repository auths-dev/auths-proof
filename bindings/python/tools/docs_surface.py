from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    module: str | None = None
    symbols: list[dict[str, str]] = []
    for line in (ROOT / "api" / "public-api.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("[") and line.endswith("]"):
            module = line[1:-1]
        elif line:
            if module is None:
                raise SystemExit("public API symbol has no module")
            symbols.append({"module": module, "name": line})
    symbols.sort(key=lambda symbol: (symbol["module"], symbol["name"]))
    print(json.dumps({"schema": "auths.docs.python-surface/1", "package": "auths", "symbols": symbols}, indent=2))


if __name__ == "__main__":
    main()
