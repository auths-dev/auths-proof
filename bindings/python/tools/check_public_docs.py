from __future__ import annotations

import ast
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCT = ROOT / "python" / "auths" / "_product.py"
REQUIRED = {"Auths": {"execute", "resume", "recover", "delegate"}}


def main() -> None:
    module = ast.parse(PRODUCT.read_text(encoding="utf-8"))
    missing: list[str] = []
    for node in module.body:
        if isinstance(node, ast.ClassDef) and node.name in REQUIRED:
            if not ast.get_docstring(node):
                missing.append(node.name)
            methods = {
                child.name: child
                for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            for name in REQUIRED[node.name]:
                method = methods.get(name)
                if method is None or not ast.get_docstring(method):
                    missing.append(f"{node.name}.{name}")
    if missing:
        raise SystemExit(f"Python P0 documentation missing: {', '.join(missing)}")
    print(json.dumps({"schema": "auths.public-docs.python/1", "p0": 5, "missing": []}))


if __name__ == "__main__":
    main()
