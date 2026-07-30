const raw = sessionStorage.getItem("auths-subscription-cancel-receipt");
if (raw) {
  const receipt = JSON.parse(raw);
  document.querySelector("#outcome").textContent = receipt.outcome;
  document.querySelector("#mode").textContent = receipt.mode;
  document.querySelector("#before").textContent = receipt.remaining_liability_minor;
  document.querySelector("#released").textContent = receipt.released_liability_minor;
  document.querySelector("#retained").textContent = receipt.retained_liability_minor;
  document.querySelector("#canonical").textContent = JSON.stringify(receipt, null, 2);
}
