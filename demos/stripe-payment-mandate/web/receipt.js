const configuredApi = document.querySelector('meta[name="auths-api-base"]')?.content ?? "";
const queryApi = new URLSearchParams(location.search).get("api") ?? "";
const API = (queryApi || window.AUTHS_PAYMENT_MANDATE_API_BASE || configuredApi).replace(/\/$/, "");
const receiptId = location.pathname.split("/").filter(Boolean).at(-1);
const status = document.querySelector("#status");
const summary = document.querySelector("#summary");
const output = document.querySelector("#receipt-json");

fetch(`${API}/api/v1/receipts/${encodeURIComponent(receiptId)}`, {
  cache: "no-store", credentials: "include",
})
  .then(async (response) => {
    const body = await response.json();
    if (!response.ok) throw new Error(body.error?.message ?? `HTTP ${response.status}`);
    return body;
  })
  .then((body) => {
    status.textContent = body.receipt.kind;
    summary.textContent = "This canonical, digest-addressed receipt separates consent, bounded decision, capability state, and provider observation.";
    output.textContent = JSON.stringify(body.receipt, null, 2);
  })
  .catch((error) => {
    status.textContent = "unavailable";
    summary.textContent = error.message;
    output.textContent = "The receipt could not be loaded.";
  });
