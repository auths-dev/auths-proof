'use strict';
const element = id => document.getElementById(id);
const renderer = 'auths.literal-complete-review/1';
let bearer, csrf, pending, busy = false;
const headers = () => bearer ? {'Authorization': 'Bearer ' + bearer} : {};
async function post(path, value) {
  const response = await fetch(path, {method: 'POST', headers: {
    'Content-Type': 'application/json', ...headers(), ...(csrf ? {'X-Owner-CSRF': csrf} : {})
  }, body: JSON.stringify(value)});
  if (!response.ok) throw new Error('The owner channel refused this request. Sign in again or inspect the current review.');
  return response.json();
}
function clear() {
  pending = null;
  element('approve').disabled = true;
  element('decline').disabled = true;
  element('review').hidden = true;
  element('literal').textContent = '';
  element('signing').textContent = '';
}
async function refresh() {
  if (!csrf || busy) return;
  try {
    const response = await fetch('/api/review', {cache: 'no-store', headers: headers()});
    if (!response.ok) throw new Error('Owner session expired. Sign in again.');
    const value = await response.json();
    if (!value) { clear(); element('status').textContent = 'Signed in. Waiting for an exact native review.'; return; }
    if (value.native.schema !== 'auths.private-effect-signing/2' || value.native.renderer !== renderer
        || typeof value.native.literal_review !== 'string' || !value.native.literal_review) {
      throw new Error('Unsupported native review. Approval is unavailable.');
    }
    element('literal').textContent = value.native.literal_review;
    element('signing').textContent = JSON.stringify(value.native.approval_request, null, 2)
      + '\nNative signing message:\n' + value.native.signing_message_hex;
    pending = value.review_id;
    element('review').hidden = false;
    element('approve').disabled = false;
    element('decline').disabled = false;
    element('status').textContent = 'Review the full native value before deciding.';
  } catch (error) { clear(); bearer = csrf = null; element('login').hidden = false; element('status').textContent = error.message; }
}
element('login').addEventListener('submit', async event => {
  event.preventDefault();
  const credential = element('credential').value;
  element('credential').value = '';
  try {
    const session = await post('/api/login', {credential});
    if (session.renderer !== renderer) throw new Error('Unsupported review renderer.');
    csrf = session.csrf;
    bearer = session.bearer;
    element('login').hidden = true;
    await refresh();
  } catch (error) { element('status').textContent = error.message; }
});
for (const decision of ['approve', 'decline']) element(decision).addEventListener('click', async () => {
  if (!pending || busy) return;
  const review_id = pending;
  busy = true;
  element('approve').disabled = true;
  element('decline').disabled = true;
  try {
    await post('/api/decision', {review_id, decision, renderer});
    clear();
    element('status').textContent = decision === 'approve'
      ? 'Consent recorded for that exact native request. Inspect the gateway outcome separately.'
      : 'Declined. No exact approval was issued.';
  } catch (error) { clear(); element('status').textContent = error.message; }
  finally { busy = false; }
});
setInterval(refresh, 1000);
