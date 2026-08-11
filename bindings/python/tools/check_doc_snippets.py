from __future__ import annotations

import ast
from pathlib import Path


def snippets(document: Path) -> tuple[str, ...]:
    blocks: list[str] = []
    active: list[str] | None = None
    for line in document.read_text().splitlines():
        if line == "```python":
            if active is not None:
                raise SystemExit(f"nested Python fence in {document}")
            active = []
        elif line == "```" and active is not None:
            blocks.append("\n".join(active))
            active = None
        elif active is not None:
            active.append(line)
    if active is not None:
        raise SystemExit(f"unterminated Python fence in {document}")
    return tuple(blocks)


def main() -> None:
    root = Path(__file__).parents[1]
    documents = (root / "README.md", root / "docs" / "INTEGRATION_RECIPES.md")
    count = 0
    for document in documents:
        for index, source in enumerate(snippets(document), start=1):
            try:
                compile(
                    source,
                    f"{document}:{index}",
                    "exec",
                    flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT,
                )
            except SyntaxError as error:
                raise SystemExit(str(error)) from error
            count += 1
    print(f"Python documentation snippets passed: {count}")


if __name__ == "__main__":
    main()
