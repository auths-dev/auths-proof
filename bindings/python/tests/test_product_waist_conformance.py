from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Callable

import pytest

from auths.testkit import ProductWaistExpected, product_waist_conformance

MANIFEST = json.loads(
    (
        Path(__file__).parents[3]
        / "product/conformance/v1/simplified-product-waist.json"
    ).read_text()
)


def test_product_waist_runner_executes_every_rust_owned_case() -> None:
    observed: list[str] = []
    cases: dict[str, Callable[[ProductWaistExpected], None]] = {}
    for candidate in MANIFEST["cases"]:
        identifier = candidate["id"]

        def run(
            expected: ProductWaistExpected,
            *,
            item: dict[str, object] = candidate,
            case_id: str = identifier,
        ) -> None:
            assert expected == ProductWaistExpected(
                item["boundary"],
                item["expected"],
            )
            observed.append(case_id)

        cases[identifier] = run
    report = asyncio.run(product_waist_conformance(MANIFEST, cases))
    expected_ids = tuple(candidate["id"] for candidate in MANIFEST["cases"])
    assert tuple(observed) == expected_ids
    assert report.passed == expected_ids
    assert report.manifest_schema == MANIFEST["schema"]


def test_product_waist_runner_rejects_case_set_drift() -> None:
    cases = {
        candidate["id"]: lambda _expected: None for candidate in MANIFEST["cases"]
    }
    cases.pop("command/forged-construction")
    with pytest.raises(TypeError, match="missing=command/forged-construction"):
        asyncio.run(product_waist_conformance(MANIFEST, cases))
