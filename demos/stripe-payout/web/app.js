let workflowId = null;
const run = document.querySelector("#run");
const replay = document.querySelector("#replay");
const result = document.querySelector("#result");
const receipt = document.querySelector("#receipt");

async function execute(experiment) {
  const response = await fetch("/api/v1/payouts", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ workflow_id: workflowId, experiment })
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "request failed");
  result.innerHTML = `<strong>${body.outcome.toUpperCase()}</strong><span>${body.code} · approvals ${body.approvals} · credentials ${body.credential_requests} · provider calls ${body.provider_calls} · capacity held ${body.capacity_held}</span>`;
  receipt.textContent = JSON.stringify(body, null, 2);
  replay.disabled = false;
}

run.addEventListener("click", async () => {
  workflowId = `workflow-${Date.now()}`;
  run.disabled = true;
  try { await execute(document.querySelector("#experiment").value); }
  catch (error) { result.innerHTML = `<strong>ERROR</strong><span>${error.message}</span>`; }
  finally { run.disabled = false; }
});

replay.addEventListener("click", async () => {
  replay.disabled = true;
  try { await execute("pending"); }
  catch (error) { result.innerHTML = `<strong>ERROR</strong><span>${error.message}</span>`; }
  finally { replay.disabled = false; }
});
