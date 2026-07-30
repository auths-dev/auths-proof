"""Browser E2E for a deployed bounded Stripe cancel application.

Set AUTHS_STRIPE_PAYMENT_CANCEL_E2E_URL to a real HTTP(S) deployment. The
application must use its native backend and real Stripe test mode; this test
does not mock browser or API responses.
"""

import os
from urllib.parse import urljoin, urlparse

from playwright.sync_api import expect, sync_playwright


base_url = os.environ.get("AUTHS_STRIPE_PAYMENT_CANCEL_E2E_URL", "").rstrip("/")
if not base_url:
    raise SystemExit("AUTHS_STRIPE_PAYMENT_CANCEL_E2E_URL is required")
parsed = urlparse(base_url)
if parsed.scheme not in {"http", "https"} or not parsed.netloc:
    raise SystemExit("E2E URL must be an absolute HTTP(S) origin")


def fresh(page):
    # Stripe test-mode fixture creation performs several dependent writes and
    # shared test infrastructure can fail transiently. Each reload creates a
    # new random, idempotent fixture; retry only session setup, never cancel.
    for attempt in range(3):
        page.goto(base_url, wait_until="networkidle")
        page.wait_for_function(
            """() => {
                const execute = document.querySelector("#execute");
                return !execute.disabled || execute.textContent.includes("unavailable");
            }""",
            timeout=60_000,
        )
        if page.locator("#execute").is_enabled():
            break
        if attempt == 2:
            raise AssertionError("Stripe test setup remained unavailable after 3 attempts")
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
    run(page, "success", "CANCELED")
    expect(page.locator("#durable-state")).to_have_text("cancel-committed")
    expect(page.locator("#capturable-amount")).to_have_text("$0.00")
    expect(page.locator("#budget-held")).to_have_text("$0.00")
    expect(page.locator("#cancel-reason")).to_have_text("requested_by_customer")
    expect(page.locator("#receipt-json")).to_contain_text(
        "auths.stripe.payment-cancel"
    )
    run(page, "replay", "REPLAY")
    expect(page.locator("#credential-requests")).to_have_text("0")
    expect(page.locator("#provider-calls")).to_have_text("0")

    receipt_href = page.locator("#receipt-link").get_attribute("href")
    assert receipt_href
    receipt = browser.new_page()
    receipt.goto(urljoin(base_url, receipt_href), wait_until="networkidle")
    expect(receipt.locator("#receipt-id")).not_to_have_text("—")
    expect(receipt.locator("#profile")).to_contain_text("exact-payment-cancel")
    expect(receipt.locator("#receipt-json")).to_contain_text(
        "merchant-cancel"
    )

    fresh(page)
    run(page, "ambiguous", "OUTCOME-UNKNOWN")
    expect(page.locator("#durable-state")).to_have_text("outcome-unknown")
    expect(page.locator("#reconcile")).to_be_visible()
    page.locator("#reconcile").click()
    expect(page.locator("#outcome")).to_have_text("RECONCILED", timeout=30_000)
    expect(page.locator("#durable-state")).to_have_text(
        "reconciled-cancel-committed"
    )

    invalid = browser.new_page()
    invalid.goto(f"{base_url}/receipts/not-a-digest", wait_until="networkidle")
    expect(invalid.locator("body")).not_to_contain_text("provider accepted")
    browser.close()
