const match = /^\/receipts\/([0-9a-f]{32})\/?$/.exec(window.location.pathname);
const query = new URLSearchParams(window.location.search);
const API = (query.get("api") ?? "").replace(/\/$/, "");
const loading = document.querySelector("#receipt-loading");
const content = document.querySelector("#receipt-content");
const failure = document.querySelector("#receipt-error");

async function load() {
  if (!match) return fail();
  try {
    const response = await fetch(`${API}/api/v1/receipts/${match[1]}`, { cache: "no-store" });
    if (!response.ok) return fail();
    const receipt = await response.json();
    const result = receipt.last_result;
    if (!result || !Array.isArray(receipt.receipts)) return fail();
    document.querySelector("#receipt-verdict").textContent = result.state.toUpperCase();
    document.querySelector("#receipt-badge").dataset.kind = result.state;
    document.querySelector("#receipt-code").textContent = result.stable_code;
    document.querySelector("#receipt-stage").textContent = result.stage;
    document.querySelector("#receipt-credential").textContent = result.credential_acquired ? "native executor" : "not acquired";
    document.querySelector("#receipt-effect").textContent = result.database_effect;
    document.querySelector("#receipt-json").textContent = JSON.stringify(receipt, null, 2);
    loading.hidden = true;
    content.hidden = false;
  } catch {
    fail();
  }
}
function fail() {
  loading.hidden = true;
  content.hidden = true;
  failure.hidden = false;
}
load();
