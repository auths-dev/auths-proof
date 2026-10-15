'use strict';
const element = id => document.getElementById(id);
const descriptions = {
  'observed-by-provider': 'A fresh provider read matched the verified value and this action’s echo. The link assumes no other writer copied the echo.',
  observed: 'The gateway read the declared field. Value equality alone does not link that value to this action or establish its effect.',
  'response-recorded': 'The gateway recorded an HTTP response. This alone does not establish an effect.',
  unknown: 'The outcome remains unknown. The provider may have received the write; its response or matching fresh value and echo is unavailable. Authority remains consumed; no automatic retry is allowed.',
  'not-entered': 'The gateway refused before write transport. A provider-read guard may already have acquired a credential and read evidence.',
  denied: 'Native proof verification refused this exact action.',
  indeterminate: 'Native verification could not establish authority.',
  'transport-unconfirmed': 'The app lost its gateway exchange. Entry may have occurred. Inspect through the operator; do not retry a write automatically.',
  'signed-observation': 'The gateway returned signed stored-outcome bytes. This is an observation, not a new provider write.',
  'not-submitted': 'Native approval collection stopped before the gateway. Simulator state alone cannot authorize an action.',
};
let token;
function display(record) {
  const outcomes = record.records.map(item => item.result.outcome);
  element('outcome').textContent = record.records.map(item => item.result.outcome === 'observed'
    ? (item.result.matched === false ? 'FIELD READ · VALUE MISMATCH' : 'FIELD READ · UNLINKED')
    : item.result.outcome.toUpperCase()).join(' / ');
  element('explanation').textContent = outcomes.map(value => descriptions[value] || 'Inspect the exact gateway result below.').join(' ');
  element('result-json').textContent = JSON.stringify(record, null, 2);
}
async function initialize() {
  const response = await fetch('/api/status');
  if (!response.ok) throw new Error('Demo unavailable');
  const status = await response.json();
  token = status.submission_token;
  element('mode').textContent = status.mode === 'live' ? 'LIVE DISPOSABLE AIRTABLE TABLE · DEVELOPMENT CUSTODY' : 'SIMULATION · COUNTING AIRTABLE DOUBLE';
  element('connection').textContent = 'Connected to the gateway application client. Production qualification is not claimed.';
  if (!element('submit')) {
    const audit = await fetch('/api/audit');
    if (!audit.ok) throw new Error('Evidence unavailable');
    element('result-json').textContent = JSON.stringify(await audit.json(), null, 2);
    return;
  }
  element('base').textContent = status.base;
  element('credential-model').textContent = status.provider_credential_model;
  element('table').textContent = status.table;
  element('approval').textContent = `${status.approval.required} of ${status.approval.approvers.length} native signed responses`;
  element('expiry').textContent = new Date(status.expires_at * 1000).toLocaleString();
  element('recipe').textContent = status.recipe_digest;
  // Fault injection is operator/test controlled. Live traffic is never routed
  // through a double, and a chosen label cannot manufacture a lost response.
  if (status.mode === 'live') {
    for (const value of ['lost-response', 'competing-writer', 'rate-limit', 'provider-error', 'malformed-response', 'oversized-response']) {
      element('experiment').querySelector(`[value="${value}"]`).disabled = true;
    }
  }
  element('submit').disabled = Date.now() >= status.expires_at * 1000;
  if (status.records.length) display(status.records.at(-1));
  function proposal() {
    const value = element('experiment').value;
    const original = value === 'recover-loss' ? 'lost-response' : value === 'recover-competing' ? 'competing-writer' : 'exact';
    const action = status.proposals[value] || status.proposals[original];
    element('proposal').textContent = `${action.record_id} → ${action.replacement} · operation ${action.operation_id}`;
    const review = status.approval.reviews[value] || status.approval.reviews[original];
    element('approval-review').textContent = `${review.title} · ${review.fields.map(([label, field]) => `${label}: ${field}`).join(' · ')} · expires ${new Date(review.valid_until * 1000).toLocaleTimeString()}`;
    const link = element('provider-link');
    link.hidden = status.mode !== 'live' || !/^rec[A-Za-z0-9]{14}$/.test(action.record_id);
    if (!link.hidden) {
      link.href = `https://airtable.com/${status.base}/${status.table}/` + (status.view ? `${status.view}/${action.record_id}` : '');
      link.textContent = status.view ? 'Open this record on Airtable ↗' : 'Open this table on Airtable ↗';
    }
  }
  element('experiment').addEventListener('change', proposal);
  proposal();
  element('submit').addEventListener('click', async () => {
    element('submit').disabled = true;
    try {
      const result = await fetch('/api/experiment', {
        method: 'POST', headers: {'Content-Type': 'application/json', 'X-Demo-Token': token},
        body: JSON.stringify({experiment: element('experiment').value}),
      });
      const record = await result.json();
      if (!result.ok) throw new Error(record.code || 'Request refused');
      display(record);
    } catch (error) {
      element('outcome').textContent = 'UNCONFIRMED';
      element('explanation').textContent = `${error.message}. Inspect the gateway state before any further write.`;
    } finally {
      element('submit').disabled = Date.now() >= status.expires_at * 1000;
    }
  });
}
initialize().catch(() => { element('connection').textContent = 'Demo unavailable. Ask the operator to check the gateway and installation.'; });
