"""Browser E2E for a deployed bounded Stripe collection application.

Set AUTHS_STRIPE_PAYMENT_COLLECT_E2E_URL to a real HTTP(S) deployment. The
application must use its native backend and real Stripe test mode; this test
does not mock browser or API responses.
"""

import os
from urllib.parse import urljoin, urlparse

from playwright.sync_api import expect, sync_playwright


base_url = os.environ.get("AUTHS_STRIPE_PAYMENT_COLLECT_E2E_URL", "").rstrip("/")
if not base_url:
    raise SystemExit("AUTHS_STRIPE_PAYMENT_COLLECT_E2E_URL is required")
parsed = urlparse(base_url)
if parsed.scheme not in {"http", "https"} or not parsed.netloc:
    raise SystemExit("E2E URL must be an absolute HTTP(S) origin")


def fresh(page):
    page.goto(base_url, wait_until="networkidle")
    expect(page.locator("#execute")).to_be_enabled(timeout=30_000)
    expect(page.locator("#test-mode")).to_have_text("YES")
    expect(page.locator("#configuration")).to_have_text("required = executed")
    expect(page.locator("#experiments")).to_be_visible()
    expect(page.locator("#outcome")).to_have_text("READY")


def run(page, experiment, expected):
    page.locator(f'[data-experiment="{experiment}"]').click()
    page.locator("#execute").click()
    expect(page.locator("#outcome")).to_have_text(expected, timeout=30_000)


with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page()

    fresh(page)
    run(page, "denial", "REJECTED")
    expect(page.locator("#credential-requests")).to_have_text("0")
    expect(page.locator("#provider-calls")).to_have_text("0")

    fresh(page)
    run(page, "changed-action", "REJECTED")
    expect(page.locator("#credential-requests")).to_have_text("0")
    expect(page.locator("#provider-calls")).to_have_text("0")

    fresh(page)
    run(page, "changed-configuration", "REJECTED")
    expect(page.locator("#durable-state")).to_have_text("no state written")
    expect(page.locator("#credential-requests")).to_have_text("0")

    fresh(page)
    run(page, "success", "COLLECTED")
    expect(page.locator("#durable-state")).to_have_text("committed")
    expect(page.locator("#receipt-json")).to_contain_text(
        "auths.stripe.payment-collect"
    )
    run(page, "replay", "REPLAY")
    expect(page.locator("#credential-requests")).to_have_text("0")
    expect(page.locator("#provider-calls")).to_have_text("0")

    receipt_href = page.locator("#receipt-link").get_attribute("href")
    assert receipt_href
    receipt = browser.new_page()
    receipt.goto(urljoin(base_url, receipt_href), wait_until="networkidle")
    expect(receipt.locator("#receipt-id")).not_to_have_text("—")
    expect(receipt.locator("#profile")).to_contain_text("exact-payment-collect")
    expect(receipt.locator("#receipt-json")).to_contain_text(
        "merchant-collection"
    )

    fresh(page)
    run(page, "ambiguous", "OUTCOME-UNKNOWN")
    expect(page.locator("#durable-state")).to_have_text("outcome-unknown")
    expect(page.locator("#reconcile")).to_be_visible()
    page.locator("#reconcile").click()
    expect(page.locator("#outcome")).to_have_text("RECONCILED", timeout=30_000)
    expect(page.locator("#durable-state")).to_have_text(
        "reconciled-committed"
    )

    invalid = browser.new_page()
    invalid.goto(f"{base_url}/receipts/not-a-digest", wait_until="networkidle")
    expect(invalid.locator("body")).not_to_contain_text("provider accepted")
    browser.close()
