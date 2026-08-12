import assert from "node:assert/strict";
import { chromium } from "../../../bindings/typescript/node_modules/playwright/index.mjs";

const base = process.env.AUTHS_INCIDENT_CONTROL_ROOM ?? "http://localhost:7100";
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  await page.goto(base, { waitUntil: "load" });
  await page.locator("#sdk-evidence.ok").waitFor();
  assert.match(await page.locator("#sdk-evidence").innerText(), /Python .* TypeScript/);
  assert.equal(await page.locator(".actor").count(), 6);

  await page.getByRole("button", { name: "Reset deterministic incident" }).click();
  await page.getByRole("button", { name: /Review & execute plan/ }).click();
  await page.locator("#run-status").filter({ hasText: "AUTHORIZED" }).waitFor({ timeout: 30_000 });
  assert.equal(await page.locator(".receipt").count(), 2);
  assert.match(await page.locator("#approval-state").innerText(), /approved · exact plan/);
  assert.match(await page.locator("#receipt-access-status").innerText(), /Unauthenticated viewer/);
  assert.doesNotMatch(await page.locator("#receipts").innerText(), /apply-config/);

  await selectReceiptRole(page, "Operator summary");
  await page.locator("#receipt-access-status").filter({ hasText: "Northstar operator" }).waitFor();
  assert.match(await page.locator("#receipts").innerText(), /apply-config/);
  assert.equal(await page.locator("#receipts details").count(), 0);

  await selectReceiptRole(page, "Auditor evidence");
  await page.locator("#receipt-access-status").filter({ hasText: "security auditor" }).waitFor();
  assert.equal(await page.locator("#receipts details").count(), 2);

  await page.getByRole("button", { name: "Public commitments" }).click();
  await page.locator("#receipt-access-status").filter({ hasText: "Unauthenticated viewer" }).waitFor();
  assert.doesNotMatch(await page.locator("#receipts").innerText(), /apply-config/);

  for (const label of [
    "Expand eu-west-2 → all regions",
    "Change firewall byte after approval",
    "Replay executed command",
    "Use expired grant",
    "Compromise approver",
    "Rotate EdgeShield Ed25519 key",
    "Deliver unauthorized bytes over Iroh",
    "Remote failure before execution",
    "Remote failure after execution",
    "Remote outcome unknown",
    "Withdraw approval mid-plan",
  ]) {
    await page.getByRole("button", { name: label }).click();
    await page.locator("#attack-output .blocked").waitFor({ timeout: 15_000 });
    assert.match(await page.locator("#attack-output").innerText(), /BLOCKED/);
  }
} finally {
  await browser.close();
}

async function selectReceiptRole(page, name) {
  await Promise.all([
    page.waitForNavigation({ waitUntil: "load", timeout: 30_000 }),
    page.getByRole("button", { name }).click(),
  ]);
}
