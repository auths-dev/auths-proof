"""Browser E2E for the bounded Stripe subscription-create deployment."""

import os
from urllib.parse import urljoin, urlparse

from playwright.sync_api import expect, sync_playwright

base_url = os.environ.get("AUTHS_STRIPE_SUBSCRIPTION_CREATE_E2E_URL", "").rstrip("/")
if not base_url:
    raise SystemExit("AUTHS_STRIPE_SUBSCRIPTION_CREATE_E2E_URL is required")
parsed = urlparse(base_url)
if parsed.scheme not in {"http", "https"} or not parsed.netloc:
    raise SystemExit("E2E URL must be an absolute HTTP(S) origin")

with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page()
    page.goto(base_url, wait_until="networkidle")
    expect(page.locator("body")).to_contain_text("Recurring authority")
    page.locator("#begin").click()
    expect(page.locator("#workspace")).to_be_visible(timeout=30_000)
    expect(page.locator("#term")).to_have_text("$15.00 USD")

    page.locator("#experiment").select_option("denial")
    page.locator("#execute").click()
    expect(page.locator("#outcome")).to_have_text("denied")
    expect(page.locator("#credentials")).to_have_text("0")
    expect(page.locator("#calls")).to_have_text("0")

    page.locator("#experiment").select_option("success")
    page.locator("#execute").click()
    expect(page.locator("#outcome")).to_have_text("active", timeout=30_000)
    expect(page.locator("#receipt")).to_contain_text("subscription-create")

    page.locator("#experiment").select_option("replay")
    page.locator("#execute").click()
    expect(page.locator("#outcome")).to_have_text("replay")
    expect(page.locator("#credentials")).to_have_text("0")
    expect(page.locator("#calls")).to_have_text("0")

    receipt_href = page.locator("#receipt-link").get_attribute("href")
    receipt = browser.new_page()
    receipt.goto(urljoin(base_url, receipt_href), wait_until="networkidle")
    expect(receipt.locator("#receipt")).to_contain_text("subscription-create")
    browser.close()
