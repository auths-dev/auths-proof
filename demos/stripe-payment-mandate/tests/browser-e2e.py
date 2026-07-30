"""Browser E2E for the real bounded Stripe payment-mandate deployment."""

import os
from urllib.parse import urljoin, urlparse

from playwright.sync_api import expect, sync_playwright


base_url = os.environ.get("AUTHS_STRIPE_PAYMENT_MANDATE_E2E_URL", "").rstrip("/")
if not base_url:
    raise SystemExit("AUTHS_STRIPE_PAYMENT_MANDATE_E2E_URL is required")
parsed = urlparse(base_url)
if parsed.scheme not in {"http", "https"} or not parsed.netloc:
    raise SystemExit("E2E URL must be an absolute HTTP(S) origin")


def fresh(page):
    page.goto(base_url, wait_until="networkidle")
    expect(page.locator("#outcome")).to_have_text("CONSENT REQUIRED", timeout=30_000)
    expect(page.locator("#execute")).to_be_disabled()
    expect(page.locator("body")).to_contain_text("does not charge money")
    page.locator("#accept").check()
    page.locator("#consent").click()
    expect(page.locator("#outcome")).to_have_text("READY", timeout=30_000)


def run(page, experiment, expected):
    page.locator(f'[data-experiment="{experiment}"]').click()
    page.locator("#execute").click()
    expect(page.locator("#outcome")).to_have_text(expected, timeout=30_000)


with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page()

    fresh(page)
    run(page, "denial", "REJECTED")
    expect(page.locator("#credential")).to_have_text("0")
    expect(page.locator("#provider")).to_have_text("0")

    fresh(page)
    run(page, "changed-configuration", "REJECTED")
    expect(page.locator("#capability")).to_have_text("none")
    expect(page.locator("#credential")).to_have_text("0")

    fresh(page)
    run(page, "success", "MANDATE-ESTABLISHED")
    expect(page.locator("#capability")).to_have_text("committed")
    expect(page.locator("#receipt-json")).to_contain_text("payment-mandate")
    run(page, "replay", "REPLAY")
    expect(page.locator("#credential")).to_have_text("0")
    expect(page.locator("#provider")).to_have_text("0")

    receipt_href = page.locator("#receipt-link").get_attribute("href")
    assert receipt_href
    receipt = browser.new_page()
    receipt.goto(urljoin(base_url, receipt_href), wait_until="networkidle")
    expect(receipt.locator("#receipt-json")).to_contain_text("payment-mandate")
    expect(receipt.locator("body")).to_contain_text("No charge occurred")

    fresh(page)
    run(page, "ambiguous", "OUTCOME-UNKNOWN")
    expect(page.locator("#capability")).to_have_text("outcome-unknown")
    page.locator("#reconcile").click()
    expect(page.locator("#outcome")).to_have_text("MANDATE-ESTABLISHED", timeout=30_000)
    expect(page.locator("#capability")).to_have_text("committed")

    browser.close()
