'use strict';
const element = id => document.getElementById(id);
const descriptions = {
  'observed-by-provider': 'A fresh provider read matched the verified value and this action’s echo. The link assumes no other writer copied the echo.',
  observed: 'The gateway read the declared field. Value equality alone does not link that value to this action or establish its effect.',
  'recovery-report': 'A separately authorized read completed. Inspect the original write stage, read facts and evidence disposition below; a state match alone is not causation.',
  refused: 'The gateway refused this request. Retained history is unchanged; this is no permission to retry an uncertain operation.',
  acknowledged: 'The gateway retained the exact recipient acknowledgement. It is a disclosure fact, separate from a provider response or a write observation.',
  'entry-granted': 'A durable acquisition grant exists. Provider entry may have occurred, but no response is recorded yet; no new read is authorized by this history.',
  reserved: 'The operation is reserved. Another process may still be working; this is not permission to repeat delivery.',
  'response-recorded': 'The gateway recorded an HTTP response. An acquisition response retains private content; it does not establish recipient delivery. A write response alone does not establish its effect.',
  unknown: 'The outcome remains unknown. The provider may have received the write; its response or matching fresh value and echo is unavailable. Authority remains consumed; no automatic retry is allowed.',
  'not-entered': 'The gateway refused before write transport. A provider-read guard may already have acquired a credential and read evidence.',
  denied: 'Native proof verification refused this exact action.',
  indeterminate: 'Native verification could not establish authority.',
  'transport-unconfirmed': 'The app lost its gateway exchange. Entry may have occurred. Inspect through the operator; do not retry a write automatically.',
  'signed-observation': 'The gateway returned signed stored-outcome bytes. This is an observation, not a new provider write.',
  'not-submitted': 'The requested review or approval stopped before native submission. Earlier operation history is unchanged.',
};
let token;
function display(record) {
  element('outcome').textContent = record.records.map(item => {
    if (item.result.native?.outcome === 'history') {
      return `${item.result.native.history.kind.toUpperCase()} · ${item.result.outcome.toUpperCase()}`;
    }
    return item.result.outcome === 'observed'
      ? (item.result.matched === false ? 'FIELD READ · VALUE MISMATCH' : 'FIELD READ · UNLINKED')
      : item.result.outcome.toUpperCase();
  }).join(' / ');
  element('explanation').textContent = record.records.map(item => {
    const kind = item.result.native?.history?.kind;
    if (kind === 'disclosure' && item.result.outcome === 'unknown') {
      return 'Disclosure is unknown: bytes may have reached the recipient, but the exact ACK is not retained. Allocations remain charged; no automatic redelivery is allowed.';
    }
    if (kind === 'acquisition' && item.result.outcome === 'unknown') {
      return 'Acquisition is unknown: provider entry may have happened without a retained response. This does not authorize a new read or any recipient release.';
    }
    return descriptions[item.result.outcome] || 'Inspect the exact native facts below.';
  }).join(' ');
  element('result-json').textContent = JSON.stringify(record, null, 2);
  const reviewed = record.records.find(item => item.result.literal_review);
  if (reviewed) element('approval-review').textContent = reviewed.result.literal_review;
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
  for (const option of element('experiment').options) {
    if (option.value.startsWith('managed-')) option.disabled = !status.managed_content;
  }
  element('submit').disabled = Date.now() >= status.expires_at * 1000;
  if (status.records.length) display(status.records.at(-1));
  function proposal() {
    const value = element('experiment').value;
    const original = value === 'recover-loss' ? 'lost-response' : value === 'recover-competing' ? 'competing-writer' : 'exact';
    const action = status.proposals[value] || status.proposals[original];
    const managed = value.startsWith('managed-');
    element('proposal').textContent = managed
      ? `Native bounded acquisition or separate disclosure of record ${action.record_id}. History actions perform no provider or recipient I/O.`
      : `${action.record_id} → ${action.replacement} · operation ${action.operation_id}`;
    const source = value.startsWith('recover-') ? value.slice(8) : value;
    const review = status.effect_review.reviews[source] || (['replay', 'typescript', 'observe'].includes(value) ? status.effect_review.reviews.exact : null);
    element('approval-review').textContent = managed ? 'Each new acquisition or disclosure requires its own complete native review and authenticated owner consent. The browser displays facts only; content stays in the authorized recipient’s private files.' : value.startsWith('recover-') ? 'A separate native read review and operator consent are required. The exact read review is retained with its result.' : review || 'Native review refused this hostile input. This experiment substitutes another effect’s approval and must be rejected.';
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
