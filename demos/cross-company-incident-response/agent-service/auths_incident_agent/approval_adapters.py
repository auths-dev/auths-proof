from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from auths import ApprovalRequest, ApprovalResponse
from auths import _native as native
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


class GrantBootstrapApproval:
    def __init__(self, plan_provider: object) -> None:
        self._plan_provider = plan_provider

    async def approve(self, request: ApprovalRequest) -> ApprovalResponse:
        if request.object_kind == "grant":
            return _response(request, "approved")
        approve = getattr(self._plan_provider, "approve", None)
        if not callable(approve):
            return _response(request, "rejected")
        return await approve(request)


class NorthstarOidcApproval:
    def __init__(self, base_url: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._client_id = "auths-incident-agent"
        self._redirect_uri = "http://auths.local/oidc/callback"

    async def approve(self, request: ApprovalRequest) -> ApprovalResponse:
        verifier = secrets.token_urlsafe(48)
        challenge = _b64(hashlib.sha256(verifier.encode()).digest())
        state = secrets.token_urlsafe(24)
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": self._client_id,
                "redirect_uri": self._redirect_uri,
                "scope": "openid profile",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": state,
            }
        )
        redirect = _redirect(f"{self._base_url}/authorize?{query}")
        parameters = urllib.parse.parse_qs(urllib.parse.urlparse(redirect).query)
        if parameters.get("state") != [state] or len(parameters.get("code", ())) != 1:
            return _response(request, "rejected")
        token = _form(
            f"{self._base_url}/token",
            {
                "grant_type": "authorization_code",
                "client_id": self._client_id,
                "redirect_uri": self._redirect_uri,
                "code": parameters["code"][0],
                "code_verifier": verifier,
            },
        )
        access_token = str(token.get("access_token", ""))
        _verify_oidc_token(
            access_token,
            _get(f"{self._base_url}/jwks.json"),
            issuer=self._base_url,
            audience=self._client_id,
            subject="northstar-commander",
        )
        result = _post(
            f"{self._base_url}/api/approve",
            _approval_payload(request),
            {"authorization": f"Bearer {access_token}"},
        )
        return _remote_response(request, result)


class EdgeShieldSignedApproval:
    def __init__(self, base_url: str, certificate_fingerprint: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {"x-auths-client-cert-sha256": certificate_fingerprint}

    async def approve(self, request: ApprovalRequest) -> ApprovalResponse:
        result = _post(
            f"{self._base_url}/api/approve",
            _approval_payload(request),
            self._headers,
        )
        if (
            result.get("requestId") != request.request_id
            or result.get("transactionDigest") != request.transaction_digest.hex()
            or result.get("decision") != "approved"
        ):
            return _response(request, "rejected")
        try:
            public_key = bytes.fromhex(str(result.get("publicKey", "")))
            signature = bytes.fromhex(str(result.get("signature", "")))
            native.verify_ed25519_preimage_v1(
                public_key, request.transaction_digest, signature
            )
        except (TypeError, ValueError, RuntimeError):
            return _response(request, "rejected")
        return _response(request, "approved")


def _approval_payload(request: ApprovalRequest) -> dict[str, Any]:
    plan_commitment = next(
        (field.value for field in request.display if field.label == "Plan commitment"),
        "",
    )
    return {
        "requestId": request.request_id,
        "objectKind": request.object_kind,
        "transactionDigest": request.transaction_digest.hex(),
        "planCommitment": plan_commitment,
        "expiresAt": request.expires_at,
        "policy": {
            "id": request.policy.policy_id,
            "version": request.policy.evaluator_version,
            "configuration": bytes(request.policy.configuration_digest).hex(),
        },
    }


def _remote_response(
    request: ApprovalRequest, result: dict[str, Any]
) -> ApprovalResponse:
    decision = "approved" if result.get("decision") == "approved" else "rejected"
    if (
        result.get("requestId") != request.request_id
        or result.get("transactionDigest") != request.transaction_digest.hex()
    ):
        decision = "rejected"
    return _response(request, decision)


def _response(request: ApprovalRequest, decision: str) -> ApprovalResponse:
    return ApprovalResponse(
        request.request_id,
        request.transaction_digest,
        request.policy,
        "approved" if decision == "approved" else "rejected",
    )


def _verify_oidc_token(
    token: str,
    jwks: dict[str, Any],
    *,
    issuer: str,
    audience: str,
    subject: str,
) -> None:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid OIDC token")
    header = json.loads(_unb64(parts[0]))
    claims = json.loads(_unb64(parts[1]))
    if (
        header.get("alg") != "ES256"
        or claims.get("iss") != issuer
        or claims.get("aud") != audience
        or claims.get("sub") != subject
        or type(claims.get("exp")) is not int
        or claims["exp"] < int(time.time())
    ):
        raise ValueError("OIDC claim mismatch")
    keys = jwks.get("keys")
    key = (
        next(
            (
                value
                for value in keys
                if type(value) is dict and value.get("kid") == header.get("kid")
            ),
            None,
        )
        if type(keys) is list
        else None
    )
    if key is None or key.get("kty") != "EC" or key.get("crv") != "P-256":
        raise ValueError("OIDC key mismatch")
    public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(_unb64(str(key["x"]))),
        int.from_bytes(_unb64(str(key["y"]))),
        ec.SECP256R1(),
    ).public_key()
    signature = _unb64(parts[2])
    if len(signature) != 64:
        raise ValueError("OIDC signature mismatch")
    public.verify(
        encode_dss_signature(
            int.from_bytes(signature[:32]), int.from_bytes(signature[32:])
        ),
        f"{parts[0]}.{parts[1]}".encode(),
        ec.ECDSA(hashes.SHA256()),
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: object,
        file: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> None:
        return None


def _redirect(url: str) -> str:
    try:
        urllib.request.build_opener(_NoRedirect).open(url, timeout=10)
    except urllib.error.HTTPError as error:
        if error.code == 302:
            location = error.headers.get("location")
            if location:
                return location
        raise
    raise ValueError("OIDC provider omitted authorization redirect")


def _form(url: str, values: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(values).encode(),
        method="POST",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    return _read(request)


def _post(url: str, values: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(values, separators=(",", ":"), sort_keys=True).encode(),
        method="POST",
        headers={"content-type": "application/json", **headers},
    )
    return _read(request)


def _get(url: str) -> dict[str, Any]:
    return _read(urllib.request.Request(url))


def _read(request: urllib.request.Request) -> dict[str, Any]:
    with urllib.request.urlopen(request, timeout=15) as response:
        value = json.loads(response.read())
    if type(value) is not dict:
        raise ValueError("remote provider returned a non-object")
    return value


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
