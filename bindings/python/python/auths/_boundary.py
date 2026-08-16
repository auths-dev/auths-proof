"""The pyo3 boundary: failures cross as `AuthsError`, never as bare strings.

`NativeAuthsError` already carries Rust's classification of the failure. A
public entry point that let it escape untranslated, or that raised a bare
`ValueError`, would hand the caller an exception with no code identity, no
effect state, no retry class, and no recommended action -- exactly the loss
contract 5.2 forbids.

`TypeError` is deliberately NOT translated: a wrong argument type is a
contract violation by the caller, and relabelling it as an authorization
outcome is forbidden by contract 5.7.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar, cast

from ._native import NativeAuthsError
from ._product_errors import AuthsError

# Anything this build's registry cannot place is malformed input that never
# reached an effect. It is only used for a Python-side parse failure; a native
# failure always carries Rust's own code.
_PARSE_CODE = "core.malformed-input"

CallableT = TypeVar("CallableT", bound=Callable[..., Any])


def boundary(summary: str) -> Callable[[CallableT], CallableT]:
    """Translates every failure of a public entry point into `AuthsError`."""

    def decorate(function: CallableT) -> CallableT:
        @wraps(function)
        def wrapper(*arguments: Any, **keywords: Any) -> Any:
            try:
                return function(*arguments, **keywords)
            except AuthsError:
                raise
            except NativeAuthsError as error:
                raise _from_native(error, summary) from None
            except ValueError:
                raise AuthsError.from_code(_PARSE_CODE, summary) from None

        return cast(CallableT, wrapper)

    return decorate


def _from_native(error: NativeAuthsError, summary: str) -> AuthsError:
    code = getattr(error, "code", None)
    if not isinstance(code, str) or not code:
        return AuthsError.from_code(_PARSE_CODE, summary)
    return AuthsError.from_native_code(code, summary)


__all__ = ["boundary"]
