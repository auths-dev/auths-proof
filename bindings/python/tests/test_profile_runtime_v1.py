from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, fields
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, NoReturn

import pytest

import auths._native as native
from auths import ClientOptions, DeniedError, OperationMetadata, OperationOptions, ReceiptIntegrityError, RecoveryRequired as RecoveryRequiredError
from auths._cbor import decode, encode
from auths._session import (
    Client, Operations as SessionOperations, RecoveryHandle, _AdmissionGate,
    _PostWriteRequestError, _is_reserved_sdk_request, _status_from_outcome,
    _status_from_pending,
)
from auths.profile_runtime import (
    PROFILE_CLIENT_RUNTIME,
    BoundProfile,
    Completed,
    Conflict,
    NotApplied,
    ProfileFile,
    ReceiptIntegrityFailed,
    RecoveryRequired,
    _encode_profile_input,
    _issue,
    _outcome,
    bind_profile,
)


@dataclass(frozen=True)
class Input:
    value: int


@dataclass(frozen=True)
class Result:
    doubled: int
    auths: OperationMetadata


@dataclass(frozen=True)
class FileInput:
    payload: object


PROFILE_API = {
    "schema": "auths.profile-api/1",
    "types": {
        "Input": {
            "kind": "record",
            "fields": [{
                "name": "value",
                "value": {"kind": "uint", "minimum": "0", "maximum": "100"},
                "sensitive": False,
            }],
        },
        "Result": {
            "kind": "record",
            "fields": [{
                "name": "doubled",
                "value": {"kind": "uint", "minimum": "0", "maximum": "200"},
                "sensitive": False,
            }],
        },
    },
}

FILE_PROFILE_API = {
    "schema": "auths.profile-api/1",
    "types": {
        "FileInput": {
            "kind": "record",
            "fields": [{
                "name": "payload",
                "value": {
                    "kind": "bytes",
                    "minimumBytes": 1,
                    "maximumBytes": 3,
                    "sourceConvenience": "file",
                },
                "sensitive": True,
            }],
        },
    },
}


_OPERATION = "op_" + "A" * 22


def _recovery_bytes(operation_id: str = _OPERATION) -> bytes:
    return encode({
        1: 1, 2: operation_id, 3: "auths.example.double", 4: 1,
        5: b"a" * 32, 6: 1, 7: None, 8: b"b" * 32,
        9: "Ed25519", 10: "profile-runtime-test", 11: b"s" * 64,
    })


@pytest.fixture(autouse=True)
def _native_portable_decision_for_fake_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fake transport returns one opaque stand-in for a Rust-minted receipt."""
    original = native.decode_portable_receipt_v1

    def decode_portable(value: bytes) -> object:
        if value == b"decision":
            return SimpleNamespace(
                portable_receipt_id="rcpt_" + "A" * 43,
                kind="decision",
                decision_receipt_id=b"d" * 32,
                execution_receipt_id=None,
                attested_decision=b"attested-decision",
                attested_execution=None,
            )
        return original(value)

    monkeypatch.setattr(native, "decode_portable_receipt_v1", decode_portable)


class FakeLocalClient:
    def __init__(self, digest: bytes, *, fail_execute: bool = False, fail_recover: bool = False, fail_evidence_response: bool = False, malformed_evidence_response: bool = False, malformed_prepare_response: bool = False, timeout_prepare_response: bool = False, cancel_evidence_response: bool = False, cancel_prepare_response: bool = False, recover_not_applied: bool = False, integrity_outcome: dict[int, Any] | None = None, evidence_outcome: dict[int, Any] | None = None) -> None:
        self.digest = digest
        self.fail_execute = fail_execute
        self.fail_recover = fail_recover
        self.fail_evidence_response = fail_evidence_response
        self.malformed_evidence_response = malformed_evidence_response
        self.malformed_prepare_response = malformed_prepare_response
        self.timeout_prepare_response = timeout_prepare_response
        self.cancel_evidence_response = cancel_evidence_response
        self.cancel_prepare_response = cancel_prepare_response
        self.recover_not_applied = recover_not_applied
        self.integrity_outcome = integrity_outcome
        self.evidence_outcome = evidence_outcome
        self.request_id: bytes | None = None
        self.requests: list[tuple[str, str, dict[int, Any]]] = []
        self.timeouts: list[object] = []

    def _profile_capability(self, profile_id: str, version: int) -> object:
        assert (profile_id, version) == ("auths.example.double", 1)
        return SimpleNamespace(
            runtime_digest=self.digest,
            error_digest=self.digest,
            operation_protocol="auths.profile-operation/1",
            qualification=("qlf_" + "A" * 43, "linux-x86_64", b"q" * 32),
        )

    def _qualification_socket_for(self, profile_id: str, version: int) -> None:
        assert (profile_id, version) == ("auths.example.double", 1)
        return None

    async def _request(self, method: str, path: str, body: bytes, timeout: object) -> bytes:
        self.timeouts.append(timeout)
        wire = decode(body) if body else {}
        assert isinstance(wire, dict)
        self.requests.append((method, path, wire))
        operation = _OPERATION
        if path.endswith("/preparation-evidence"):
            self.request_id = wire[2]
            if self.cancel_evidence_response:
                self.cancel_evidence_response = False
                raise _PostWriteRequestError(asyncio.CancelledError())
            if self.fail_evidence_response:
                self.fail_evidence_response = False
                raise _PostWriteRequestError(OSError("lease response was lost"))
            if self.malformed_evidence_response:
                self.malformed_evidence_response = False
                return encode({})
            if self.evidence_outcome is not None:
                return encode({
                    1: 1,
                    2: wire[2],
                    3: "outcome",
                    4: encode({**self.evidence_outcome, 3: wire[2]}),
                })
            return encode({
                1: 1,
                2: wire[2],
                3: "lease",
                4: b"h" * 32,
                5: b"e" * 32,
                6: 4_000_000_000,
            })
        if path.endswith("/operations"):
            assert wire[6] == "primary"
            if wire.get(7) is not None:
                assert wire[7] == b"h" * 32
            if self.cancel_prepare_response:
                self.cancel_prepare_response = False
                raise _PostWriteRequestError(asyncio.CancelledError())
            if self.timeout_prepare_response:
                self.timeout_prepare_response = False
                raise _PostWriteRequestError(asyncio.TimeoutError())
            if self.malformed_prepare_response:
                self.malformed_prepare_response = False
                return encode({})
            if self.integrity_outcome is not None:
                return encode({**self.integrity_outcome, 3: wire[2]})
            return encode({
                1: 1, 2: "ready", 3: wire[2], 4: operation,
                5: b"c" * 32, 6: b"decision", 7: _recovery_bytes(), 8: "primary",
            })
        if method == "GET":
            assert path.endswith(operation)
            assert self.request_id is not None
            return encode({
                1: 1,
                2: "completed",
                3: self.request_id,
                4: operation,
                5: encode({"doubled": 14}),
                6: [],
                7: "fresh",
                8: "primary",
            })
        if path.endswith("/execute") and self.fail_execute:
            self.fail_execute = False
            raise _PostWriteRequestError(OSError("ambiguous local transport failure"))
        if path.endswith("/recover"):
            assert wire[3] == _recovery_bytes()
            if self.fail_recover:
                raise asyncio.TimeoutError("bounded recovery wait elapsed")
            if self.recover_not_applied:
                return encode(_not_applied_wire(wire[2]))
        else:
            assert path.endswith(f"/{operation}/execute")
        return encode({
            1: 1,
            2: "completed",
            3: wire[2],
            4: operation,
            5: encode({"doubled": 14}),
            6: [],
            7: "fresh",
            8: "primary",
        })


def _not_applied_wire(request_id: bytes) -> dict[int, Any]:
    operation = _OPERATION
    issue = {
        "schema": "auths.error/1",
        "family": "runtime",
        "code": "operation.timed-out",
        "operation": "execute",
        "stage": "pre-provider",
        "summary": "the operation timed out before provider entry",
        "correlationId": operation,
        "retry": "safe",
        "effect": "not-applied",
        "entered": {
            "approval": True,
            "signer": True,
            "state": True,
            "credential": False,
            "provider": False,
        },
        "recommendedAction": "retry-execution",
        "executionReference": operation,
        "decisionReference": None,
        "receiptReference": None,
        "causes": ["timeout"],
    }
    return {
        1: 1, 2: "not-applied", 3: request_id, 4: operation,
        5: encode(issue), 6: [], 7: "fresh", 8: "primary",
    }


def test_local_agent_client_options_have_no_token_or_remote_endpoint() -> None:
    assert [field.name for field in fields(ClientOptions)] == [
        "agent_socket", "connect_timeout",
    ]


def test_profile_outcomes_are_sealed_and_discriminated() -> None:
    assert PROFILE_CLIENT_RUNTIME == "auths.profile-client-runtime/1"
    with pytest.raises(TypeError, match="sealed"):
        Completed(object(), "completed", object())


def test_profile_file_is_sealed_redacted_and_reads_only_maximum_plus_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "sensitive.tfplan"
    path.write_bytes(b"abc")
    selected = ProfileFile(path)
    assert str(path) not in repr(selected)
    with pytest.raises(TypeError, match="sealed"):
        type("ForgedProfileFile", (ProfileFile,), {})

    requested: list[int] = []
    real_read = os.read
    real_open = os.open
    opened_with: list[int] = []

    def tracked_read(descriptor: int, maximum: int) -> bytes:
        requested.append(maximum)
        return real_read(descriptor, maximum)

    def tracked_open(selected_path: str, flags: int) -> int:
        opened_with.append(flags)
        return real_open(selected_path, flags)

    monkeypatch.setattr("auths.profile_runtime.os.read", tracked_read)
    monkeypatch.setattr("auths.profile_runtime.os.open", tracked_open)
    encoded = _encode_profile_input(
        FILE_PROFILE_API, "FileInput", FileInput(selected), FileInput,
    )
    assert decode(encoded) == {"payload": b"abc"}
    assert requested == [4]
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        assert opened_with[0] & nofollow


def test_profile_file_rejects_oversize_symlink_and_non_file(
    tmp_path: Path,
) -> None:
    oversize = tmp_path / "oversize.tfplan"
    oversize.write_bytes(b"abcd")
    with pytest.raises(ValueError, match="generated bound"):
        _encode_profile_input(
            FILE_PROFILE_API, "FileInput", FileInput(ProfileFile(oversize)), FileInput,
        )

    target = tmp_path / "target.tfplan"
    target.write_bytes(b"abc")
    link = tmp_path / "linked.tfplan"
    link.symlink_to(target)
    with pytest.raises(TypeError, match="regular non-symlink"):
        _encode_profile_input(
            FILE_PROFILE_API, "FileInput", FileInput(ProfileFile(link)), FileInput,
        )
    with pytest.raises(TypeError, match="regular non-symlink"):
        _encode_profile_input(
            FILE_PROFILE_API, "FileInput", FileInput(ProfileFile(tmp_path)), FileInput,
        )


def test_profile_file_rejects_path_swap_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "selected.tfplan"
    replacement = tmp_path / "replacement.tfplan"
    path.write_bytes(b"abc")
    replacement.write_bytes(b"xyz")
    real_open = os.open

    def swapping_open(selected: str, flags: int) -> int:
        os.replace(replacement, path)
        return real_open(selected, flags)

    monkeypatch.setattr("auths.profile_runtime.os.open", swapping_open)
    with pytest.raises(ValueError, match="changed during bounded read"):
        _encode_profile_input(
            FILE_PROFILE_API, "FileInput", FileInput(ProfileFile(path)), FileInput,
        )


def test_operation_errors_are_not_caller_constructible() -> None:
    with pytest.raises(TypeError, match="SDK-constructible"):
        DeniedError(object(), "op_AAAAAAAAAAAAAAAAAAAAAA", ())  # type: ignore[call-arg,arg-type]


def test_outcomes_and_error_envelopes_are_closed() -> None:
    request = b"r" * 16
    with pytest.raises(ValueError, match="unknown, missing, or mismatched"):
        _outcome(encode({
            1: 1, 2: "ready", 3: request, 4: "op_AAAAAAAAAAAAAAAAAAAAAA",
            5: b"c" * 32, 6: b"decision", 7: b"recover", 8: None,
            9: "injected",
        }), request)
    envelope = {
        "schema": "auths.error/1", "family": "forged", "code": "client.profile-contract-mismatch",
        "operation": "connect", "stage": "negotiation", "summary": "mismatch",
        "correlationId": "test", "retry": "never", "effect": "not-applied",
        "entered": {"approval": False, "signer": False, "state": False, "credential": False, "provider": False},
        "recommendedAction": "install-compatible-runtime", "executionReference": None,
        "decisionReference": None, "receiptReference": None, "causes": [],
    }
    with pytest.raises(ValueError, match="contradictory"):
        _issue(encode(envelope))


def test_generated_descriptor_runtime_timeout_and_receipt_limits_are_enforced() -> None:
    digest = b"l" * 32
    client = FakeLocalClient(digest)
    arguments = dict(
        profile_id="auths.example.double",
        version=1,
        collection_route="/v1/profiles/example/double/1/operations",
        profile_client_runtime=PROFILE_CLIENT_RUNTIME,
        runtime_contract_digest=digest.hex(),
        error_projection_digest=digest.hex(),
        request_bytes=4096,
        response_bytes=4096,
        execution_milliseconds=10,
        receipt_count=1,
        receipt_bytes=1024,
        profile_api=PROFILE_API,
        input_type="Input",
        success_type="Result",
        input_class=Input,
        success_class=Result,
        connection="primary",
    )
    with pytest.raises(ValueError, match="runtime mismatch"):
        bind_profile(
            client,  # type: ignore[arg-type]
            **{**arguments, "profile_client_runtime": "auths.profile-client-runtime/0"},
        )

    profile = bind_profile(client, **arguments)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="execution bound"):
        asyncio.run(profile.invoke(
            Input(7),
            OperationOptions(
                timeout=timedelta(milliseconds=11),
                recovery_wait=timedelta(milliseconds=1),
            ),
        ))

    receipt_limited = bind_profile(
        client,  # type: ignore[arg-type]
        **{**arguments, "execution_milliseconds": 30_000, "receipt_bytes": 4},
    )
    with pytest.raises(ValueError, match="portable receipt"):
        asyncio.run(receipt_limited.invoke(Input(7)))


def test_generated_profile_shape_uses_alias_and_returns_typed_success() -> None:
    async def scenario() -> None:
        digest = b"d" * 32
        client = FakeLocalClient(digest)
        profile: BoundProfile[Result, NoReturn, NoReturn] = bind_profile(
            client,  # type: ignore[arg-type]
            profile_id="auths.example.double",
            version=1,
            collection_route="/v1/profiles/example/double/1/operations",
            profile_client_runtime=PROFILE_CLIENT_RUNTIME,
            runtime_contract_digest=digest.hex(),
            error_projection_digest=digest.hex(),
            request_bytes=4096,
            response_bytes=4096,
            execution_milliseconds=30_000,
            receipt_count=4,
            receipt_bytes=1024,
            profile_api=PROFILE_API,
            input_type="Input",
            success_type="Result",
            input_class=Input,
            success_class=Result,
            connection="primary",
        )
        result = await profile.invoke(Input(7))
        assert result.doubled == 14
        assert result.auths.connection == "primary"
        assert [path for _, path, _ in client.requests] == [
            "/v1/profiles/example/double/1/operations",
            "/v1/profiles/example/double/1/operations/op_AAAAAAAAAAAAAAAAAAAAAA/execute",
        ]

    asyncio.run(scenario())


def test_declared_preparation_evidence_is_retried_exactly_and_hidden_from_api() -> None:
    async def scenario() -> None:
        digest = b"p" * 32
        client = FakeLocalClient(digest, fail_evidence_response=True)
        profile: BoundProfile[Result, NoReturn, NoReturn] = bind_profile(
            client,  # type: ignore[arg-type]
            profile_id="auths.example.double",
            version=1,
            collection_route="/v1/profiles/example/double/1/operations",
            profile_client_runtime=PROFILE_CLIENT_RUNTIME,
            runtime_contract_digest=digest.hex(),
            error_projection_digest=digest.hex(),
            preparation_evidence="protected-lease",
            request_bytes=4096,
            response_bytes=4096,
            execution_milliseconds=30_000,
            receipt_count=4,
            receipt_bytes=1024,
            profile_api=PROFILE_API,
            input_type="Input",
            success_type="Result",
            input_class=Input,
            success_class=Result,
            connection="primary",
        )
        result = await profile.invoke(Input(7), OperationOptions(idempotency_key="same"))
        assert result.doubled == 14
        evidence = [item for item in client.requests if item[1].endswith("/preparation-evidence")]
        assert len(evidence) == 2
        assert evidence[0][2] == evidence[1][2]
        prepare = next(item for item in client.requests if item[1].endswith("/operations"))
        assert prepare[2][7] == b"h" * 32

    asyncio.run(scenario())


def test_ambiguous_execute_uses_issued_recovery_handle_without_reentry() -> None:
    async def scenario() -> None:
        digest = b"r" * 32
        client = FakeLocalClient(digest, fail_execute=True)
        profile: BoundProfile[Result, NoReturn, NoReturn] = bind_profile(
            client,  # type: ignore[arg-type]
            profile_id="auths.example.double",
            version=1,
            collection_route="/v1/profiles/example/double/1/operations",
            profile_client_runtime=PROFILE_CLIENT_RUNTIME,
            runtime_contract_digest=digest.hex(),
            error_projection_digest=digest.hex(),
            request_bytes=4096,
            response_bytes=4096,
            execution_milliseconds=30_000,
            receipt_count=4,
            receipt_bytes=1024,
            profile_api=PROFILE_API,
            input_type="Input",
            success_type="Result",
            input_class=Input,
            success_class=Result,
            connection="primary",
        )
        result = await profile.invoke(Input(7))
        assert result.doubled == 14
        assert [path.rsplit("/", 1)[-1] for _, path, _ in client.requests] == [
            "operations", "execute", "recover",
        ]

    asyncio.run(scenario())


def test_recovery_timeout_preserves_possible_effect() -> None:
    async def scenario() -> None:
        digest = b"u" * 32
        client = FakeLocalClient(digest, fail_execute=True, fail_recover=True)
        profile: BoundProfile[Result, NoReturn, NoReturn] = bind_profile(
            client,  # type: ignore[arg-type]
            profile_id="auths.example.double",
            version=1,
            collection_route="/v1/profiles/example/double/1/operations",
            profile_client_runtime=PROFILE_CLIENT_RUNTIME,
            runtime_contract_digest=digest.hex(),
            error_projection_digest=digest.hex(),
            request_bytes=4096,
            response_bytes=4096,
            execution_milliseconds=30_000,
            receipt_count=4,
            receipt_bytes=1024,
            profile_api=PROFILE_API,
            input_type="Input",
            success_type="Result",
            input_class=Input,
            success_class=Result,
            connection="primary",
        )
        outcome = await profile.invoke_outcome(Input(7))
        assert isinstance(outcome, RecoveryRequired)
        assert outcome.issue.effect.value == "possible"
        assert outcome.issue.code == "operation.outcome-unknown"
        client.fail_execute = True
        client.fail_recover = True
        with pytest.raises(RecoveryRequiredError):
            await profile.invoke(Input(7))

    asyncio.run(scenario())


def _integrity_wire(
    state: str,
    effect: str,
    terminal: bool,
    *,
    correlation: str = "op_AAAAAAAAAAAAAAAAAAAAAA",
) -> dict[int, Any]:
    operation = "op_AAAAAAAAAAAAAAAAAAAAAA"
    provider = effect in ("possible", "applied")
    issue = {
        "schema": "auths.error/1",
        "family": "internal",
        "code": "core.terminal-receipt-integrity-failed",
        "operation": "resume",
        "stage": "receipt",
        "summary": "the retained receipt failed integrity verification",
        "correlationId": correlation,
        "retry": "never",
        "effect": effect,
        "entered": {
            "approval": True,
            "signer": True,
            "state": True,
            "credential": provider,
            "provider": provider,
        },
        "recommendedAction": "contact-support",
        "executionReference": operation,
        "decisionReference": None,
        "receiptReference": None,
        "causes": ["corrupt-state"],
    }
    return {
        1: 1,
        2: "receipt-integrity-failed",
        3: b"replaced-by-client-request",
        4: operation,
        5: encode(issue),
        6: state,
        7: effect,
        8: terminal,
        9: "primary",
    }


def _integrity_profile(client: FakeLocalClient) -> BoundProfile[Result, NoReturn, NoReturn]:
    digest = client.digest
    return bind_profile(
        client,  # type: ignore[arg-type]
        profile_id="auths.example.double",
        version=1,
        collection_route="/v1/profiles/example/double/1/operations",
        profile_client_runtime=PROFILE_CLIENT_RUNTIME,
        runtime_contract_digest=digest.hex(),
        error_projection_digest=digest.hex(),
        request_bytes=4096,
        response_bytes=4096,
        execution_milliseconds=30_000,
        receipt_count=4,
        receipt_bytes=1024,
        profile_api=PROFILE_API,
        input_type="Input",
        success_type="Result",
        input_class=Input,
        success_class=Result,
        connection="primary",
    )


def _companion_profile(client: FakeLocalClient) -> BoundProfile[Result, NoReturn, NoReturn]:
    digest = client.digest
    return bind_profile(
        client,  # type: ignore[arg-type]
        profile_id="auths.example.double",
        version=1,
        collection_route="/v1/profiles/example/double/1/operations",
        profile_client_runtime=PROFILE_CLIENT_RUNTIME,
        runtime_contract_digest=digest.hex(),
        error_projection_digest=digest.hex(),
        preparation_evidence="protected-lease",
        request_bytes=4096,
        response_bytes=4096,
        execution_milliseconds=30_000,
        receipt_count=4,
        receipt_bytes=1024,
        profile_api=PROFILE_API,
        input_type="Input",
        success_type="Result",
        input_class=Input,
        success_class=Result,
        connection="primary",
    )


def _companion_conflict_wire() -> dict[int, Any]:
    operation = _OPERATION
    issue = {
        "schema": "auths.error/1",
        "family": "state",
        "code": "operation.idempotency-conflict",
        "operation": "execute",
        "stage": "reservation",
        "summary": "the idempotency key names a different operation",
        "correlationId": operation,
        "retry": "unknown",
        "effect": "possible",
        "entered": {
            "approval": True,
            "signer": True,
            "state": True,
            "credential": True,
            "provider": True,
        },
        "recommendedAction": "resume-and-reconcile",
        "executionReference": operation,
        "decisionReference": None,
        "receiptReference": None,
        "causes": ["conflict"],
    }
    return {
        1: 1,
        2: "conflict",
        3: b"replaced-by-client-request",
        4: operation,
        5: encode(issue),
        6: _recovery_bytes(),
        7: [],
        8: "primary",
    }


def test_companion_outcomes_resume_the_normal_state_machine() -> None:
    async def scenario() -> None:
        operation = _OPERATION
        ready = {
            1: 1, 2: "ready", 3: b"replaced-by-client-request", 4: operation,
            5: b"c" * 32, 6: b"decision", 7: _recovery_bytes(), 8: "primary",
        }
        in_progress_not_applied = {
            1: 1, 2: "in-progress", 3: b"replaced-by-client-request",
            4: operation, 5: "executing", 6: "not-applied", 7: [],
            8: _recovery_bytes(), 9: "primary",
        }
        in_progress_possible = {
            **in_progress_not_applied,
            6: "possible",
        }
        completed = {
            1: 1, 2: "completed", 3: b"replaced-by-client-request",
            4: operation, 5: encode({"doubled": 14}), 6: [],
            7: "replayed", 8: "primary",
        }
        cases = (
            (ready, ("preparation-evidence", "execute"), Completed),
            (in_progress_not_applied, ("preparation-evidence", operation), Completed),
            (in_progress_possible, ("preparation-evidence", "recover"), Completed),
            (completed, ("preparation-evidence",), Completed),
            (_companion_conflict_wire(), ("preparation-evidence",), Conflict),
            (_integrity_wire("completed", "applied", True), ("preparation-evidence",), ReceiptIntegrityFailed),
        )
        for outcome_wire, expected_tail, expected_type in cases:
            client = FakeLocalClient(b"q" * 32, evidence_outcome=outcome_wire)
            outcome = await _companion_profile(client).invoke_outcome(Input(7))
            assert isinstance(outcome, expected_type)
            assert tuple(path.rsplit("/", 1)[-1] for _, path, _ in client.requests) == expected_tail

    asyncio.run(scenario())


def test_null_qualification_advertisement_remains_usable_for_testkit() -> None:
    async def scenario() -> None:
        client = FakeLocalClient(b"q" * 32)
        client._profile_capability = lambda profile_id, version: SimpleNamespace(  # type: ignore[method-assign]
            runtime_digest=client.digest,
            error_digest=client.digest,
            operation_protocol="auths.profile-operation/1",
            qualification=None,
        )
        outcome = await _companion_profile(client).invoke_outcome(Input(7))
        assert isinstance(outcome, Completed)

    asyncio.run(scenario())


def test_recovery_only_blocks_new_effects_and_preserves_conservative_recovery() -> None:
    async def scenario() -> None:
        digest = b"d" * 32
        request_id = b"r" * 16
        client = Client()
        client.digest = digest  # type: ignore[attr-defined]
        client._state = "open"
        client._socket = "/unused"
        client._install_session({
            1: 1, 2: request_id, 3: "ses_AQEBAQEBAQEBAQEBAQEBAQ", 4: "raw:test-principal",
            5: b"x" * 32,
            6: [{
                1: "auths.example.double", 2: 1, 3: digest,
                4: "auths.profile-operation/1", 5: digest, 6: None, 7: None,
            }],
            7: 16, 8: "recovery-only",
        }, request_id, b"c" * 32)
        profile = _companion_profile(client)  # type: ignore[arg-type]
        with pytest.raises(Exception) as blocked:
            await profile.invoke_outcome(Input(7))
        assert getattr(blocked.value, "code", None) == "client.profile-unavailable"

        operation = "op_" + "A" * 22
        recovery = RecoveryHandle.from_bytes(encode({
            1: 1, 2: operation, 3: "auths.example.double", 4: 1,
            5: b"a" * 32, 6: 1, 7: None, 8: b"b" * 32,
            9: "Ed25519", 10: "recovery-test", 11: b"s" * 64,
        }))

        async def completed_recovery(method: str, path: str, body: bytes, timeout: object) -> bytes:
            wire = decode(body)
            return encode({
                1: 1, 2: "completed", 3: wire[2], 4: operation,
                5: encode({"doubled": 14}), 6: [], 7: "replayed", 8: "primary",
            })

        client._request = completed_recovery  # type: ignore[method-assign]
        completed = await profile.recover_outcome(recovery)
        assert isinstance(completed, Completed)
        assert completed.value.doubled == 14

        foreign = "op_" + "B" * 22

        async def foreign_recovery(method: str, path: str, body: bytes, timeout: object) -> bytes:
            wire = decode(body)
            return encode({
                1: 1, 2: "completed", 3: wire[2], 4: foreign,
                5: encode({"doubled": 14}), 6: [], 7: "replayed", 8: "primary",
            })

        client._request = foreign_recovery  # type: ignore[method-assign]
        foreign_outcome = await profile.recover_outcome(recovery)
        assert isinstance(foreign_outcome, RecoveryRequired)
        assert foreign_outcome.operation_id == operation
        assert foreign_outcome.recovery is recovery

        foreign_handle = encode({
            1: 1, 2: foreign, 3: "auths.example.double", 4: 1,
            5: b"a" * 32, 6: 1, 7: None, 8: b"b" * 32,
            9: "Ed25519", 10: "recovery-test", 11: b"s" * 64,
        })

        async def foreign_handle_recovery(method: str, path: str, body: bytes, timeout: object) -> bytes:
            wire = decode(body)
            return encode({
                1: 1, 2: "in-progress", 3: wire[2], 4: operation,
                5: "executing", 6: "possible", 7: [], 8: foreign_handle, 9: "primary",
            })

        client._request = foreign_handle_recovery  # type: ignore[method-assign]
        foreign_handle_outcome = await profile.recover_outcome(recovery)
        assert isinstance(foreign_handle_outcome, RecoveryRequired)
        assert foreign_handle_outcome.operation_id == operation
        assert foreign_handle_outcome.recovery is recovery

        client._profiles[("auths.example.double", 1)] = SimpleNamespace(
            runtime_digest=b"z" * 32,
            error_digest=b"z" * 32,
            operation_protocol="auths.profile-operation/1",
            qualification=None,
        )
        mismatched = await profile.recover_outcome(recovery)
        assert isinstance(mismatched, RecoveryRequired)
        assert mismatched.issue.code == "operation.recovery-unavailable"
        assert mismatched.recovery is recovery
        client._profiles[("auths.example.double", 1)] = SimpleNamespace(
            runtime_digest=digest,
            error_digest=digest,
            operation_protocol="auths.profile-operation/1",
            qualification=None,
        )

        async def unknown_recovery(method: str, path: str, body: bytes, timeout: object) -> bytes:
            wire = decode(body)
            return encode({1: 1, 2: "future-terminal", 3: wire[2], 4: operation})

        client._request = unknown_recovery  # type: ignore[method-assign]
        generated = await profile.recover_outcome(recovery)
        assert isinstance(generated, RecoveryRequired)
        assert generated.issue.code == "operation.recovery-unavailable"
        assert generated.operation_id == operation
        assert generated.recovery is recovery
        with pytest.raises(RecoveryRequiredError) as unavailable:
            await client.operations.recover(recovery)
        assert unavailable.value.code == "operation.recovery-unavailable"
        assert unavailable.value.operation_id == operation
        assert unavailable.value.recovery is recovery
        assert unavailable.value.info.entered_boundaries == unavailable.value.info.entered_boundaries.__class__(
            False, False, False, False, True,
        )

    asyncio.run(scenario())


def test_session_negotiation_rejects_malformed_binding_and_profile_rows() -> None:
    request_id = b"n" * 16
    digest = b"d" * 32

    def response() -> dict[int, Any]:
        return {
            1: 1, 2: request_id, 3: "ses_AQEBAQEBAQEBAQEBAQEBAQ",
            4: "raw:test-principal", 5: digest,
            6: [{
                1: "auths.example.double", 2: 1, 3: digest,
                4: "auths.profile-operation/1", 5: digest,
                6: {1: "example", 2: "auths.example.connection/1", 3: "auths.example.connection-descriptor/1"},
                7: None,
            }],
            7: 16, 8: "full",
        }

    mutations = []
    for key, value in ((3, "test-session"), (3, "ses_" + "A" * 22), (4, "DID:key:bad"), (7, True)):
        wire = response(); wire[key] = value; mutations.append(wire)
    for key, value in ((1, "auths.Bad.profile"), (2, True)):
        wire = response(); wire[6][0][key] = value; mutations.append(wire)
    for key, value in ((1, "Example"), (2, "invalid semantic id")):
        wire = response(); wire[6][0][6][key] = value; mutations.append(wire)
    for wire in mutations:
        with pytest.raises(ValueError):
            Client()._install_session(wire, request_id, digest)


def test_sdk_admission_is_bounded_fifo_cancellable_and_reserves_control() -> None:
    async def scenario() -> None:
        gate = _AdmissionGate(32)
        blocked = asyncio.Event()
        started: list[int] = []

        async def call(index: int) -> None:
            await gate.acquire()
            try:
                started.append(index)
                await blocked.wait()
            finally:
                gate.release()

        tasks = [asyncio.create_task(call(index)) for index in range(32)]
        cancelled = asyncio.create_task(call(32))
        tasks.extend(asyncio.create_task(call(index)) for index in range(33, 288))
        for _ in range(3):
            await asyncio.sleep(0)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        tasks.append(asyncio.create_task(call(288)))
        await asyncio.sleep(0)
        with pytest.raises(Exception) as exhausted:
            await gate.acquire()
        assert getattr(exhausted.value, "code", None) == "operation.admission-exhausted"
        assert getattr(exhausted.value, "effect", None) == "not-applied"
        blocked.set()
        await asyncio.gather(*tasks)
        assert started == list(range(32)) + list(range(33, 289))
        assert _is_reserved_sdk_request("GET", "/v1/operations/pending")
        assert _is_reserved_sdk_request("POST", "/v1/operations/recover")
        assert _is_reserved_sdk_request(
            "POST", "/v1/profiles/example/double/1/operations/op_" + "A" * 22 + "/recover",
        )
        assert not _is_reserved_sdk_request("POST", "/v1/profiles/example/double/1/operations")
        assert not _is_reserved_sdk_request(
            "POST", "/v1/profiles/example/double/1/operations/op_A/recover",
        )

    asyncio.run(scenario())


def test_closing_admission_rejects_queued_work_without_starting_it() -> None:
    async def scenario() -> None:
        gate = _AdmissionGate(1)
        await gate.acquire()
        queued = asyncio.create_task(gate.acquire())
        await asyncio.sleep(0)
        gate.close()
        with pytest.raises(Exception, match="auths client is closed"):
            await queued
        gate.release()
        with pytest.raises(Exception, match="auths client is closed"):
            await gate.acquire()

    asyncio.run(scenario())


def test_profile_invocation_coordination_is_bounded_fresh_and_promotable() -> None:
    async def scenario() -> None:
        client = Client()
        client._state = "open"
        client._session_id = "ses_AQEBAQEBAQEBAQEBAQEBAQ"
        scope = "auths.example.double/1:coordinated"
        request_a = b"a" * 16
        request_b = b"b" * 16
        leader = client._begin_profile_invocation(scope, b"f" * 32, request_a)
        conflict = client._begin_profile_invocation(scope, b"g" * 32, request_b)
        assert leader.role == "leader"
        assert conflict.role == "conflict-probe"
        assert conflict.request_id == request_b
        client._finish_profile_invocation(conflict)

        followers = [
            client._begin_profile_invocation(scope, b"f" * 32, b"c" * 16)
            for _ in range(256)
        ]
        observer = client._begin_profile_invocation(scope, b"f" * 32, b"d" * 16)
        assert all(ticket.role == "follower" for ticket in followers)
        assert observer.role == "observer"

        status_reads = 0
        release_status = asyncio.Event()
        async def request(method: str, path: str, body: bytes, timeout: timedelta) -> bytes:
            nonlocal status_reads
            assert method == "GET" and not body
            status_reads += 1
            await release_status.wait()
            return b"status"
        client._request = request  # type: ignore[method-assign]
        statuses = [
            asyncio.create_task(client._profile_invocation_status(ticket, "/status", timedelta(seconds=1)))
            for ticket in (*followers, observer)
        ]
        for _ in range(3):
            await asyncio.sleep(0)
        assert status_reads == 1
        release_status.set()
        assert await asyncio.gather(*statuses) == [b"status"] * 257

        operation_id = "op_" + "A" * 22
        client._publish_profile_invocation(leader, operation_id)
        identities = await asyncio.gather(*(ticket.entry.identity for ticket in (*followers, observer)))
        assert all(identity == (request_a, operation_id, b"") for identity in identities)
        client._finish_profile_invocation(leader)
        for ticket in followers:
            client._finish_profile_invocation(ticket)
        client._finish_profile_invocation(observer)

        failed = client._begin_profile_invocation(scope + ":promotion", b"f" * 32, request_a)
        first = client._begin_profile_invocation(scope + ":promotion", b"f" * 32, request_b)
        second = client._begin_profile_invocation(scope + ":promotion", b"f" * 32, b"e" * 16)
        client._finish_profile_invocation(failed)
        assert await first.entry.identity is None
        assert await second.entry.identity is None
        promoted = client._begin_profile_invocation(scope + ":promotion", b"f" * 32, request_b)
        attached = client._begin_profile_invocation(scope + ":promotion", b"f" * 32, request_a)
        assert promoted.role == "leader"
        assert attached.role == "follower"
        client._finish_profile_invocation(first)
        client._finish_profile_invocation(second)
        client._finish_profile_invocation(promoted)
        client._finish_profile_invocation(attached)

        bounded_leader = client._begin_profile_invocation(
            scope + ":conflicts", b"l" * 32, request_a,
        )
        probes = [
            client._begin_profile_invocation(
                scope + ":conflicts", index.to_bytes(32, "big"), request_b,
            )
            for index in range(256)
        ]
        assert all(ticket.role == "conflict-probe" for ticket in probes)
        with pytest.raises(Exception) as captured:
            client._begin_profile_invocation(
                scope + ":conflicts", b"z" * 32, request_b,
            )
        assert getattr(captured.value, "issue").code == "operation.admission-exhausted"
        for ticket in probes:
            client._finish_profile_invocation(ticket)
        client._finish_profile_invocation(bounded_leader)
        client._state = "closed"

    asyncio.run(scenario())


def test_generated_profile_coalesces_exact_keys_and_preserves_cancelled_follower_truth() -> None:
    async def scenario() -> None:
        digest = b"z" * 32
        client = Client()
        client._state = "open"
        client._session_id = "ses_AQEBAQEBAQEBAQEBAQEBAQ"
        client._profiles[("auths.example.double", 1)] = SimpleNamespace(
            runtime_digest=digest,
            error_digest=digest,
            operation_protocol="auths.profile-operation/1",
            qualification=None,
        )
        profile = bind_profile(
            client,
            profile_id="auths.example.double", version=1,
            collection_route="/v1/profiles/example/double/1/operations",
            profile_client_runtime=PROFILE_CLIENT_RUNTIME,
            runtime_contract_digest=digest.hex(), error_projection_digest=digest.hex(),
            preparation_evidence="protected-lease", request_bytes=4096,
            response_bytes=4096, execution_milliseconds=30_000,
            receipt_count=4, receipt_bytes=1024, profile_api=PROFILE_API,
            input_type="Input", success_type="Result", input_class=Input,
            success_class=Result, connection="primary",
        )
        requests: list[tuple[str, str, dict[int, Any]]] = []
        prepare_ids: list[bytes] = []
        first_prepare = asyncio.Event()
        release_prepare = asyncio.Event()

        async def request(
            method: str, path: str, body: bytes, timeout: timedelta,
            coordination: object = None,
        ) -> bytes:
            wire = decode(body) if body else {}
            assert isinstance(wire, dict)
            requests.append((method, path, wire))
            if path.endswith("/preparation-evidence"):
                return encode({1: 1, 2: wire[2], 3: "lease", 4: b"h" * 32, 5: b"e" * 32, 6: 4_000_000_000})
            if path.endswith("/operations") and method == "POST":
                prepare_ids.append(wire[2])
                if len(prepare_ids) == 1:
                    first_prepare.set()
                    await release_prepare.wait()
                    return encode({1: 1, 2: "completed", 3: wire[2], 4: _OPERATION, 5: encode({"doubled": 14}), 6: [], 7: "fresh", 8: "primary"})
                conflict = _companion_conflict_wire()
                return encode({**conflict, 3: wire[2]})
            raise AssertionError(f"unexpected coordinated request: {method} {path}")

        client._request = request  # type: ignore[method-assign]
        options = OperationOptions(idempotency_key="same-key")
        leader = asyncio.create_task(profile.invoke_outcome(Input(7), options))
        await first_prepare.wait()
        follower = asyncio.create_task(profile.invoke_outcome(Input(7), options))
        while next(iter(client._profile_invocations.values())).waiters < 1:
            await asyncio.sleep(0)
        follower.cancel()
        changed = asyncio.create_task(profile.invoke_outcome(Input(8), options))
        release_prepare.set()
        first, second, mismatch = await asyncio.gather(leader, follower, changed)
        assert isinstance(first, Completed)
        assert isinstance(second, Completed)
        assert isinstance(mismatch, Conflict)
        assert first.value.auths.completion == "fresh"
        assert second.value.auths.completion == "replayed"
        assert len([path for _, path, _ in requests if path.endswith("/preparation-evidence")]) == 2
        assert len(prepare_ids) == 2
        assert prepare_ids[0] != prepare_ids[1]
        assert not any(path.endswith("/execute") for _, path, _ in requests)
        client._state = "closed"

    asyncio.run(scenario())


def test_pending_rows_are_exact_identity_bound_and_strictly_ordered() -> None:
    def recovery_bytes(operation_id: str) -> bytes:
        return encode({
            1: 1, 2: operation_id, 3: "auths.example.double", 4: 1,
            5: b"a" * 32, 6: 1, 7: None, 8: b"b" * 32,
            9: "Ed25519", 10: "pending-test", 11: b"s" * 64,
        })

    def row(operation_id: str, updated_at: int) -> dict[int, Any]:
        return {
            1: operation_id, 2: "auths.example.double", 3: 1, 4: "ready",
            5: "not-applied", 6: False, 7: updated_at, 8: [],
            9: recovery_bytes(operation_id), 10: "primary",
        }

    first = "op_" + "A" * 22
    second = "op_" + "B" * 22
    assert _status_from_pending(row(first, 10)).operation_id == first
    hostile = []
    extra = row(first, 10); extra[11] = None; hostile.append(extra)
    wrong_truth = row(first, 10); wrong_truth[5] = "possible"; hostile.append(wrong_truth)
    wrong_handle = row(second, 10); wrong_handle[9] = recovery_bytes(first); hostile.append(wrong_handle)
    for item in hostile:
        with pytest.raises((TypeError, ValueError)):
            _status_from_pending(item)

    class PendingClient:
        async def _request(self, method: str, path: str, body: bytes, timeout: object) -> bytes:
            return encode({1: 1, 2: self.rows})

    async def scenario() -> None:
        client = PendingClient()
        client.rows = [row(first, 10), row(second, 10)]
        pending = await SessionOperations(client).pending()  # type: ignore[arg-type]
        assert [item.operation_id for item in pending] == [first, second]
        client.rows.reverse()
        with pytest.raises(ValueError, match="strictly ordered"):
            await SessionOperations(client).pending()  # type: ignore[arg-type]

    asyncio.run(scenario())

    request_id = b"u" * 16
    unavailable = _status_from_outcome({
        1: 1, 2: "unavailable", 3: request_id, 4: first,
        5: _not_applied_wire(request_id)[5], 6: [], 7: "primary",
    }, (first, "auths.example.double", 1), request_id)
    assert unavailable.state == "unavailable"
    assert unavailable.effect == "not-applied"
    assert unavailable.terminal is True


def test_root_recovery_status_rejects_ignored_field_and_identity_mutations() -> None:
    request_id = b"s" * 16
    identity = (_OPERATION, "auths.example.double", 1)
    foreign = "op_" + "B" * 22
    in_progress = {
        1: 1, 2: "in-progress", 3: request_id, 4: _OPERATION,
        5: "executing", 6: "possible", 7: [], 8: _recovery_bytes(), 9: "primary",
    }
    completed = {
        1: 1, 2: "completed", 3: request_id, 4: _OPERATION,
        5: encode({"doubled": 14}), 6: [], 7: "fresh", 8: "primary",
    }
    ready = {
        1: 1, 2: "ready", 3: request_id, 4: _OPERATION,
        5: b"c" * 31, 6: b"decision", 7: _recovery_bytes(), 8: "primary",
    }
    hostile = [
        {**in_progress, 5: "future"},
        {**in_progress, 8: _recovery_bytes(foreign)},
        {**completed, 7: "future"},
        ready,
        {
            1: 1, 2: "unavailable", 3: request_id, 4: _OPERATION,
            5: _companion_conflict_wire()[5], 6: [], 7: "primary",
        },
    ]
    for wire in hostile:
        with pytest.raises((TypeError, ValueError)):
            _status_from_outcome(wire, identity, request_id)

    conflict = _companion_conflict_wire()
    conflict[3] = request_id
    status = _status_from_outcome(conflict, identity, request_id)
    assert status.state == "recovery-required"
    assert status.effect == "possible"
    assert status.recovery is not None


def test_root_recovery_preserves_original_handle_after_post_write_loss() -> None:
    recovery = RecoveryHandle.from_bytes(_recovery_bytes())

    class LostResponseClient:
        def __init__(self, mode: str) -> None:
            self._mode = mode

        async def _request(
            self, method: str, path: str, body: bytes, timeout: object,
        ) -> bytes:
            raise _PostWriteRequestError(OSError("recovery response was lost"))

    async def scenario() -> None:
        for mode in ("full", "recovery-only"):
            with pytest.raises(RecoveryRequiredError) as captured:
                await SessionOperations(LostResponseClient(mode)).recover(  # type: ignore[arg-type]
                    recovery,
                )
            assert captured.value.code == "operation.recovery-unavailable"
            assert captured.value.operation_id == _OPERATION
            assert captured.value.recovery is recovery

    asyncio.run(scenario())


def test_post_write_cancellation_never_advances_a_not_applied_operation() -> None:
    async def scenario() -> None:
        companion = FakeLocalClient(b"x" * 32, cancel_evidence_response=True)
        with pytest.raises(asyncio.CancelledError):
            await _companion_profile(companion).invoke_outcome(Input(7))
        assert [path.rsplit("/", 1)[-1] for _, path, _ in companion.requests] == [
            "preparation-evidence", "preparation-evidence",
        ]

        prepared = FakeLocalClient(
            b"y" * 32,
            cancel_prepare_response=True,
            recover_not_applied=True,
        )
        with pytest.raises(asyncio.CancelledError):
            await _integrity_profile(prepared).invoke_outcome(Input(7))
        tails = [path.rsplit("/", 1)[-1] for _, path, _ in prepared.requests]
        assert tails == ["operations", "operations", "recover"]
        assert "execute" not in tails

    asyncio.run(scenario())


def test_post_write_cancellation_preserves_coalesced_applied_or_possible_truth() -> None:
    async def scenario() -> None:
        completed = {
            1: 1, 2: "completed", 3: b"replaced-by-client-request",
            4: "op_AAAAAAAAAAAAAAAAAAAAAA",
            5: encode({"doubled": 14}), 6: [], 7: "replayed", 8: "primary",
        }
        applied = FakeLocalClient(
            b"a" * 32,
            cancel_prepare_response=True,
            integrity_outcome=completed,
        )
        assert isinstance(
            await _integrity_profile(applied).invoke_outcome(Input(7)),
            Completed,
        )
        assert all(not path.endswith("/execute") for _, path, _ in applied.requests)

        possible = FakeLocalClient(
            b"b" * 32,
            cancel_prepare_response=True,
            fail_recover=True,
        )
        outcome = await _integrity_profile(possible).invoke_outcome(Input(7))
        assert isinstance(outcome, RecoveryRequired)
        assert all(not path.endswith("/execute") for _, path, _ in possible.requests)

    asyncio.run(scenario())


def test_malformed_responses_are_exactly_replayed_inside_the_retry_boundary() -> None:
    async def scenario() -> None:
        companion = FakeLocalClient(b"c" * 32, malformed_evidence_response=True)
        assert isinstance(
            await _companion_profile(companion).invoke_outcome(Input(7)),
            Completed,
        )
        assert sum(path.endswith("/preparation-evidence") for _, path, _ in companion.requests) == 2

        prepared = FakeLocalClient(b"d" * 32, malformed_prepare_response=True)
        assert isinstance(
            await _integrity_profile(prepared).invoke_outcome(Input(7)),
            Completed,
        )
        assert sum(path.endswith("/operations") for _, path, _ in prepared.requests) == 2

    asyncio.run(scenario())


def test_post_write_timeout_uses_reserved_cleanup_budget_and_never_executes() -> None:
    async def scenario() -> None:
        client = FakeLocalClient(
            b"t" * 32,
            timeout_prepare_response=True,
            recover_not_applied=True,
        )
        outcome = await _integrity_profile(client).invoke_outcome(
            Input(7),
            OperationOptions(
                timeout=timedelta(milliseconds=100),
                recovery_wait=timedelta(milliseconds=50),
            ),
        )
        assert isinstance(outcome, NotApplied)
        tails = [path.rsplit("/", 1)[-1] for _, path, _ in client.requests]
        assert tails == ["operations", "operations", "recover"]
        assert "execute" not in tails
        assert client.timeouts[1] > client.timeouts[0]

    asyncio.run(scenario())


def test_receipt_integrity_outcome_preserves_truth_and_is_sdk_sealed() -> None:
    async def scenario() -> None:
        for state, effect, terminal in (
            ("ready", "not-applied", False),
            ("recovery-required", "possible", False),
            ("completed", "applied", True),
            ("not-applied", "not-applied", True),
        ):
            client = FakeLocalClient(
                b"i" * 32,
                integrity_outcome=_integrity_wire(state, effect, terminal),
            )
            profile = _integrity_profile(client)
            outcome = await profile.invoke_outcome(Input(7))
            assert isinstance(outcome, ReceiptIntegrityFailed)
            assert outcome.state == state
            assert outcome.effect.value == effect
            assert outcome.terminal is terminal
            assert outcome.receipt_ids == ()
            with pytest.raises(ReceiptIntegrityError) as captured:
                await profile.invoke(Input(7))
            assert captured.value.state == state
            assert captured.value.effect.value == effect
            assert captured.value.terminal is terminal
            assert captured.value.receipt_ids == ()

    asyncio.run(scenario())


def test_receipt_integrity_outcome_rejects_identity_and_truth_mismatch() -> None:
    async def scenario() -> None:
        malformed = (
            _integrity_wire("ready", "not-applied", True),
            _integrity_wire("completed", "applied", True, correlation="op_BBBBBBBBBBBBBBBBBBBBBB"),
            _integrity_wire("recovery-required", "possible", False),
        )
        malformed[2][5] = encode({
            **decode(malformed[2][5]),
            "entered": {
                **decode(malformed[2][5])["entered"],
                "provider": False,
            },
        })
        for wire in malformed:
            client = FakeLocalClient(b"m" * 32, integrity_outcome=wire)
            with pytest.raises(ValueError):
                await _integrity_profile(client).invoke_outcome(Input(7))

    asyncio.run(scenario())
