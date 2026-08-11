from __future__ import annotations

import sys
import zipfile
from pathlib import Path, PurePosixPath


REQUIRED_PACKAGE_FILES = {
    "auths/__init__.py",
    "auths/_native.pyi",
    "auths/_plan.py",
    "auths/approvals.py",
    "auths/authority.py",
    "auths/custody.py",
    "auths/diagnostics.py",
    "auths/errors.py",
    "auths/identity.py",
    "auths/inspection.py",
    "auths/integrations.py",
    "auths/lifecycle.py",
    "auths/observability.py",
    "auths/profile_kit.py",
    "auths/profiles/__init__.py",
    "auths/profiles/http.py",
    "auths/profiles/mcp.py",
    "auths/py.typed",
    "auths/runtime.py",
    "auths/testkit.py",
    "auths/trust.py",
    "auths/verify.py",
    "auths/workflow.py",
}
FORBIDDEN_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "fixtures",
    "target",
    "tests",
    "typecheck",
}
FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".rs", ".seed", ".key", ".pem"}


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_wheel.py <wheel>")
    wheel = Path(sys.argv[1]).resolve()
    if wheel.suffix != ".whl" or not wheel.is_file():
        raise SystemExit("expected one built wheel")
    with zipfile.ZipFile(wheel) as archive:
        files = {name for name in archive.namelist() if not name.endswith("/")}
        for name in files:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                raise SystemExit("wheel contains an unsafe path")
            lowered = {part.lower() for part in path.parts}
            if lowered & FORBIDDEN_PARTS or path.suffix.lower() in FORBIDDEN_SUFFIXES:
                raise SystemExit(f"wheel contains a forbidden entry: {name}")
            if any(
                marker in name.lower()
                for marker in ("private-key", "secret", "seed.bin")
            ):
                raise SystemExit(
                    f"wheel contains sensitive development material: {name}"
                )
        missing = REQUIRED_PACKAGE_FILES - files
        if missing:
            raise SystemExit(
                "wheel omitted required package files: " + ", ".join(sorted(missing))
            )
        extensions = {
            name
            for name in files
            if name.startswith("auths/_native.")
            and PurePosixPath(name).suffix.lower() in {".so", ".pyd"}
        }
        if len(extensions) != 1:
            raise SystemExit("wheel must contain exactly one native extension")
        unexpected = {
            name
            for name in files
            if not name.startswith("auths/") and ".dist-info/" not in name
        }
        if unexpected:
            raise SystemExit(
                "wheel contains unexpected package roots: "
                + ", ".join(sorted(unexpected))
            )
        metadata_names = [
            name for name in files if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            raise SystemExit("wheel must contain one METADATA record")
        metadata = archive.read(metadata_names[0]).decode("utf-8")
        required = (
            "Name: auths\n",
            "Version: 1.0.0rc1\n",
            "Requires-Python: >=3.9\n",
            "Classifier: Operating System :: Microsoft :: Windows\n",
            "Classifier: Operating System :: MacOS\n",
            "Classifier: Operating System :: POSIX :: Linux\n",
            "Classifier: Programming Language :: Python :: 3.9\n",
            "Classifier: Programming Language :: Python :: 3.14\n",
            "Classifier: Typing :: Typed\n",
        )
        if any(field not in metadata for field in required):
            raise SystemExit("wheel metadata does not match the public Python contract")
    print(f"Python wheel contents passed: {len(files)} files")


if __name__ == "__main__":
    main()
