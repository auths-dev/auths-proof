#!/usr/bin/env python3
import os
from playwright.sync_api import sync_playwright

base = os.environ.get("AUTHS_PURCHASE_DEMO_URL", "http://127.0.0.1:8080")
with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    page.goto(base, wait_until="networkidle")
    page.get_by_role("button", name="Create procurement intent").click()
    page.get_by_role("button", name="Run decision").wait_for(state="visible")
    page.get_by_role("button", name="Run decision").click()
    page.get_by_text("AUTHORIZED", exact=True).wait_for()
    assert "purchase-authorized" in page.locator("#result").inner_text()
    assert "credential_requests" in page.locator("#receipt").inner_text()
    browser.close()
