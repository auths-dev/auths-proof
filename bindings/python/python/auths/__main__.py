from __future__ import annotations

import sys

from ._doctor import doctor, render_doctor


def main() -> int:
    if sys.argv[1:] != ["doctor"]:
        print("usage: python -m auths doctor", file=sys.stderr)
        return 2
    try:
        print(render_doctor(doctor()))
    except Exception:
        print("Auths doctor could not initialize the packaged runtime", file=sys.stderr)
        return 1
    return 0


raise SystemExit(main())
