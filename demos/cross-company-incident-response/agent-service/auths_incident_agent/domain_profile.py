from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal, Optional, cast

from auths import _native as native
from auths._application_profile import (
    ApplicationProfile,
    CanonicalProfileAction,
    ProfileBudget,
    ProfileDefinition,
    ProfilePermission,
    define_profile,
)
from auths._workflow import ReviewField


@dataclass(frozen=True)
class DomainProfileOptions:
    audience: str
    resource_namespace: Optional[str] = None


@dataclass(frozen=True)
class EdgeActionInput:
    fleet: str
    device: str
    command: Literal["activate-firmware", "apply-config", "execute", "restart"]
    sequence: int
    state_digest: Optional[str] = None


EdgeProfile = ApplicationProfile[EdgeActionInput, EdgeActionInput]


class DomainProfiles:
    def edge(self, options: DomainProfileOptions) -> EdgeProfile:
        if type(options) is not DomainProfileOptions:
            raise TypeError("edge profile options are required")
        audience = _bounded(options.audience, "audience")
        namespace = (
            None
            if options.resource_namespace is None
            else _bounded(options.resource_namespace, "resource namespace")
        )

        def canonicalize(value: EdgeActionInput) -> CanonicalProfileAction:
            if type(value) is not EdgeActionInput:
                raise TypeError("edge action input is required")
            projection = native.canonicalize_edge_action_v1(
                value.fleet,
                value.device,
                value.command,
                value.sequence,
                value.state_digest,
            )
            return _canonical(projection, audience, namespace)

        def decode_verified(value: CanonicalProfileAction) -> EdgeActionInput:
            projection = native.parse_canonical_edge_action_v1(value.body)
            decoded = json.loads(bytes(projection.body))
            if type(decoded) is not dict:
                raise ValueError("native edge action omitted its object")
            return EdgeActionInput(
                fleet=_text(decoded, "fleet"),
                device=_text(decoded, "device"),
                command=cast(
                    Literal["activate-firmware", "apply-config", "execute", "restart"],
                    _text(decoded, "command"),
                ),
                sequence=_integer(decoded, "sequence"),
                state_digest=(
                    None
                    if decoded.get("state_digest") is None
                    else _text(decoded, "state_digest")
                ),
            )

        return define_profile(
            ProfileDefinition("auths.edge", 1, canonicalize, decode_verified)
        )


def load_domain_profiles() -> DomainProfiles:
    return DomainProfiles()


def _canonical(
    projection: native.DomainActionProjection,
    audience: str,
    namespace: Optional[str],
) -> CanonicalProfileAction:
    budget = projection.budget
    return CanonicalProfileAction(
        projection.media_type,
        bytes(projection.body),
        ProfilePermission(projection.capability, projection.resource),
        projection.resource if namespace is None else namespace,
        audience,
        (
            ReviewField("Action", projection.review_title),
            *(ReviewField(label, value) for label, value in projection.review_fields),
        ),
        None if budget is None else ProfileBudget(*budget),
    )


def _bounded(value: str, label: str) -> str:
    if type(value) is not str or not value or len(value.encode()) > 2048:
        raise ValueError(label + " is outside bounds")
    return value


def _text(value: dict[object, object], key: str) -> str:
    field = value.get(key)
    if type(field) is not str:
        raise ValueError("native edge action omitted " + key)
    return field


def _integer(value: dict[object, object], key: str) -> int:
    field = value.get(key)
    if type(field) is not int or field < 0:
        raise ValueError("native edge action omitted " + key)
    return field
