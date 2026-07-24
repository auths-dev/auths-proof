# ADR 0001: Proof-Carrying Authorization

**Status:** Accepted

## Decision

The repository implements one primitive:

> Every action carries proof that it was authorized.

The protocol binds an action to a signed, attenuating grant chain rooted in
local trust. It is not an identity directory, login protocol, or key manager.

## Consequence

Authentication proves principal control. Auths proves delegated authority over
an exact action. Applications still make and enforce the operational decision.
