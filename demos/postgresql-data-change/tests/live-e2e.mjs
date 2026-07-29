import { chromium } from "playwright";
import assert from "node:assert/strict";
import test from "node:test";

const baseUrl = (process.env.AUTHS_POSTGRESQL_E2E_URL ?? "http://localhost:4175").replace(/\/$/, "");
const browser = await chromium.launch({ headless: true });

try {
  const page = await browser.newPage();
  await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  await page
    .locator("#service-state")
    .filter({ hasText: /ready · tls-postgresql/ })
    .waitFor({ timeout: 120_000 });
  assert.match(await page.locator("#service-state").innerText(), /ready · tls-postgresql/);

  await page.locator("#execute").click();
  await page.locator("#verdict").filter({ hasText: /COMMITTED|RECONCILED/ }).waitFor({
    timeout: 120_000,
  });
  assert.equal(await page.locator("#credential-called").innerText(), "YES");
  assert.equal(await page.locator("#transaction-called").innerText(), "YES");
  await page.waitForFunction(
    () => document.querySelector("#receipt-json")?.textContent?.includes('"transaction_receipt"'),
    undefined,
    { timeout: 30_000 },
  );
  assert.match(await page.locator("#receipt-json").textContent(), /"transaction_receipt"/);

  const designedReceiptPath = await page.locator("#receipt-link").getAttribute("href");
  assert.match(designedReceiptPath ?? "", /^\/receipts\/[0-9a-f]{32}$/);
  const receiptPage = await browser.newPage();
  await receiptPage.goto(new URL(designedReceiptPath, baseUrl).href);
  await receiptPage.locator("#receipt-content").waitFor({ state: "visible" });
  assert.match(await receiptPage.locator("#receipt-title").innerText(), /committed/i);
  assert.match(await receiptPage.locator("#receipt-json").textContent(), /"transaction"/);
  await receiptPage.close();

  await page.locator("#execute").click();
  await page.locator("#decision-code").filter({ hasText: "already-claimed" }).waitFor();
  assert.equal(await page.locator("#transaction-called").innerText(), "NO");

  await page.locator('[data-variant="configuration-changed"]').click();
  await page.locator("#execute").click();
  await page
    .locator("#decision-code")
    .filter({ hasText: "verifier-configuration-mismatch" })
    .waitFor();
  assert.equal(await page.locator("#credential-called").innerText(), "NO");
  assert.equal(await page.locator("#transaction-called").innerText(), "NO");

  const invalid = await browser.newPage();
  await invalid.goto(`${baseUrl}/receipts/00000000000000000000000000000000`);
  await invalid.locator("#receipt-error").waitFor({ state: "visible" });
  assert.match(await invalid.locator("#receipt-error h2").innerText(), /Receipt unavailable/i);
  await invalid.close();

  console.log(`PostgreSQL browser E2E passed: ${baseUrl}`);
} finally {
  await browser.close();
}

test("live_browser_database_and_receipt_contract", () => assert.ok(true));
