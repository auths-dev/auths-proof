"""Browser E2E for the deployed or locally served bounded Stripe demo.

Set AUTHS_STRIPE_E2E_URL to the frontend origin. The frontend must route its
normal /api/v1 paths to a native test-mode backend; this test does not mock API
responses.
"""

import os
from urllib.parse import urlparse

from playwright.sync_api import expect, sync_playwright


base_url = os.environ.get("AUTHS_STRIPE_E2E_URL", "").rstrip("/")
if not base_url:
    raise SystemExit("AUTHS_STRIPE_E2E_URL is required for live browser E2E")
parsed = urlparse(base_url)
if parsed.scheme not in {"http", "https"} or not parsed.netloc:
    raise SystemExit("AUTHS_STRIPE_E2E_URL must be an absolute HTTP(S) origin")


with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page()
    page.goto(base_url, wait_until="networkidle")

    expect(page.locator("#workbench-grid")).to_be_visible(timeout=30_000)
    expect(page.locator("#policy-provenance")).to_have_text("executor-local config")
    expect(page.locator("#policy-limit")).to_contain_text("50%")
    expect(page.locator("#budget-available")).to_contain_text("$25.00")
    expect(page.locator("#stripe-contacted")).to_have_text("NOT YET")

    page.locator('[data-variant="amount-changed"]').click()
    expect(page.locator("#verdict")).to_have_text("DENIED")
    page.locator("#execute").click()
    expect(page.locator("#stripe-contacted")).to_have_text("NO", timeout=15_000)
    expect(page.locator("#receipt-json")).to_contain_text(
        "bounded-relative-limit-exceeded"
    )

    page.locator('[data-variant="exact"]').click()
    expect(page.locator("#verdict")).to_have_text("AUTHORIZED")
    page.locator("#execute").click()
    expect(page.locator("#stripe-contacted")).to_have_text("YES", timeout=30_000)
    expect(page.locator("#decision-code")).to_have_text("bounded-authorized")
    expect(page.locator("#budget-spent")).to_contain_text("$10.00")
    expect(page.locator("#receipt-json")).to_contain_text(
        "executor-local-trusted-configuration"
    )
    expect(page.locator("#receipt-json")).to_contain_text('"state": "committed"')

    page.locator("#execute").click()
    expect(page.locator("#decision-code")).to_have_text(
        "bounded-replay", timeout=15_000
    )
    expect(page.locator("#stripe-contacted")).to_have_text("NO")

    receipt_url = page.locator("#receipt-link").get_attribute("href")
    assert receipt_url
    receipt = browser.new_page()
    receipt.goto(f"{base_url}{receipt_url}", wait_until="networkidle")
    expect(receipt.locator("#policy-digest")).not_to_have_text("—")
    expect(receipt.locator("#policy-provenance")).to_have_text(
        "executor-local-trusted-configuration"
    )
    expect(receipt.locator("#reservation-state")).to_have_text("committed")
    expect(receipt.locator("#receipt-json")).to_contain_text(
        "auths.stripe.bounded-refund-policy"
    )
    browser.close()
