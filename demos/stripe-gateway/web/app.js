'use strict';
const element = id => document.getElementById(id);
const descriptions = {
  'observed-by-provider': 'A fresh provider read matched the verified value and this action’s echo. The link assumes no other writer copied the echo.',
  'response-recorded': 'The gateway recorded an HTTP response. This alone does not establish an effect.',
  unknown: 'The outcome remains unknown. The provider may have received the write; its response or locator is unavailable. Authority remains consumed; no automatic retry is allowed.',
  'not-entered': 'The gateway refused before write transport. A provider-read guard may already have acquired a credential and read evidence.',
  denied: 'Native proof verification refused this exact action.',
  indeterminate: 'Native verification could not establish authority.',
  'transport-unconfirmed': 'The app lost its gateway exchange. Entry may have occurred. Inspect through the operator; do not retry a write automatically.',
  'signed-observation': 'The gateway returned signed stored-outcome bytes. This is an observation, not a new provider write.',
};
let token;
function display(record) {
  const outcomes = record.records.map(item => item.result.outcome);
  element('outcome').textContent = outcomes.join(' / ').toUpperCase();
  element('explanation').textContent = outcomes.map(value => descriptions[value] || 'Inspect the exact gateway result below.').join(' ');
  element('result-json').textContent = JSON.stringify(record, null, 2);
}
async function initialize() {
  const response = await fetch('/api/status');
  if (!response.ok) throw new Error('Demo unavailable');
  const status = await response.json();
  token = status.submission_token;
  element('mode').textContent = status.mode === 'live' ? 'LIVE STRIPE TEST MODE · DEVELOPMENT CUSTODY' : 'SIMULATION · COUNTING PROVIDER DOUBLE';
  element('connection').textContent = 'Connected to the gateway application client. Production qualification is not claimed.';
  if (!element('submit')) {
    const audit = await fetch('/api/audit');
    if (!audit.ok) throw new Error('Evidence unavailable');
    element('result-json').textContent = JSON.stringify(await audit.json(), null, 2);
    return;
  }
  element('platform').textContent = status.platform;
  element('expiry').textContent = new Date(status.expires_at * 1000).toLocaleString();
  element('recipe').textContent = status.recipe_digest;
  // Fault injection is operator/test controlled. Live traffic is never routed
  // through a double, and a chosen label cannot manufacture a lost response.
  if (status.mode === 'live') element('experiment').querySelector('[value="lost-response"]').disabled = true;
  element('submit').disabled = Date.now() >= status.expires_at * 1000;
  if (status.records.length) display(status.records.at(-1));
  function proposal() {
    const value = element('experiment').value;
    const action = status.proposals[value] || status.proposals.exact;
    element('proposal').textContent = `${action.payment_intent} · ${action.amount / 100} ${action.currency.toUpperCase()} · operation ${action.operation_id}`;
    const link = element('provider-link');
    link.hidden = status.mode !== 'live' || !/^pi_[A-Za-z0-9]+$/.test(action.payment_intent);
    if (!link.hidden) link.href = `https://dashboard.stripe.com/test/payments/${action.payment_intent}`;
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
