import { chromium } from "playwright";
import assert from "node:assert/strict";
import test from "node:test";

const baseUrl = (process.env.AUTHS_OPENTOFU_E2E_URL ?? "http://localhost:4174").replace(/\/$/, "");
const browser = await chromium.launch({ headless: true });

try {
  const page = await browser.newPage();
  await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  await page
    .locator("#service-state")
    .filter({ hasText: /ready · live-opentofu/ })
    .waitFor({ timeout: 120_000 });
  assert.match(await page.locator("#service-state").innerText(), /ready · live-opentofu/);

  await page.locator("#execute").click();
  await page
    .locator("#credential-called")
    .filter({ hasText: "YES" })
    .waitFor({ timeout: 120_000 });
  assert.equal(await page.locator("#decision-code").innerText(), "authorized");
  assert.equal(await page.locator("#credential-called").innerText(), "YES");
  assert.equal(await page.locator("#opentofu-called").innerText(), "YES");
  assert.equal(await page.locator("#converged").innerText(), "TRUE");
  await page.waitForFunction(
    () => document.querySelector("#receipt-json")?.textContent?.includes('"kind": "observation"'),
    undefined,
    { timeout: 30_000 },
  );
  assert.match(await page.locator("#receipt-json").textContent(), /"kind": "observation"/);

  const designedReceiptPath = await page.locator("#receipt-link").getAttribute("href");
  assert.match(designedReceiptPath ?? "", /^\/receipts\/[0-9a-f]{32}$/);
  const receiptPage = await browser.newPage();
  await receiptPage.goto(new URL(designedReceiptPath, baseUrl).href);
  await receiptPage.locator("#receipt-card").waitFor({ state: "visible" });
  assert.match(await receiptPage.locator("#receipt-title").innerText(), /authorized/i);
  assert.match(await receiptPage.locator("#receipt-json").textContent(), /"resulting_state"/);
  await receiptPage.close();

  await page.locator("#execute").click();
  await page.locator("#decision-code").filter({ hasText: "already-claimed" }).waitFor();
  assert.equal(await page.locator("#opentofu-called").innerText(), "NO");

  await page.locator('[data-variant="configuration-changed"]').click();
  await page.locator("#execute").click();
  await page
    .locator("#decision-code")
    .filter({ hasText: "verifier-configuration-mismatch" })
    .waitFor();
  assert.equal(await page.locator("#credential-called").innerText(), "NO");
  assert.equal(await page.locator("#opentofu-called").innerText(), "NO");

  const invalid = await browser.newPage();
  await invalid.goto(`${baseUrl}/receipts/00000000000000000000000000000000`);
  await invalid.locator("#receipt-error").waitFor({ state: "visible" });
  assert.match(await invalid.locator("#receipt-title").innerText(), /No receipt/i);
  await invalid.close();

  console.log(`OpenTofu browser E2E passed: ${baseUrl}`);
} finally {
  await browser.close();
}

test("live_browser_provider_and_receipt_contract", () => assert.ok(true));
