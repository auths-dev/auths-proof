let sessionId = null;
const apiBase = (window.AUTHS_PURCHASE_AUTHORIZATION_API_BASE || "").replace(/\/$/, "");
const api = path => `${apiBase}${path}`;
const create = document.querySelector("#create");
const run = document.querySelector("#run");
const result = document.querySelector("#result");
const receipt = document.querySelector("#receipt");
const incoming = document.querySelector("#incoming");
const designed = document.querySelector("#designed");

create.addEventListener("click", async () => {
  create.disabled = true;
  try {
    const response = await fetch(api("/api/v1/procurement-intents"), { method: "POST" });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || "request failed");
    sessionId = body.session_id;
    incoming.innerHTML = `<dl><dt>Merchant</dt><dd>${body.exact_action.merchant_id}</dd><dt>Category</dt><dd>${body.exact_action.merchant_category}</dd><dt>Country</dt><dd>${body.exact_action.merchant_country}</dd><dt>Amount</dt><dd>${body.exact_action.amount_minor} ${body.exact_action.currency} minor</dd></dl>`;
    receipt.textContent = JSON.stringify(body.procurement_intent, null, 2);
    run.disabled = false;
  } catch (error) {
    result.innerHTML = `<strong>ERROR</strong><span>${error.message}</span>`;
  } finally {
    create.disabled = false;
  }
});

run.addEventListener("click", async () => {
  if (!sessionId) return;
  run.disabled = true;
  const experiment = document.querySelector("#experiment").value;
  try {
    const response = await fetch(api(`/api/v1/sessions/${sessionId}/authorize`), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ experiment })
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || "request failed");
    result.innerHTML = `<strong>${body.outcome.toUpperCase()}</strong><span>${body.code || "durable replay"} · credentials ${body.boundary.credential_requests} · provider calls ${body.boundary.provider_calls}</span>`;
    receipt.textContent = JSON.stringify(body.receipt || body, null, 2);
    if (body.receipt_url) {
      designed.href = body.receipt_url;
      designed.hidden = false;
    }
  } catch (error) {
    result.innerHTML = `<strong>ERROR</strong><span>${error.message}</span>`;
  } finally {
    run.disabled = false;
  }
});
