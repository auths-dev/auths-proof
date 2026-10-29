"""Installed native owner-consent journey with a real browser and local provider.

The browser actions simulate the owner; no human-attention/live-provider claim.
"""
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.request
from playwright.sync_api import expect, sync_playwright

CONTAINER = 'airtable-owner-workbench'
APP = 'http://localhost:8181'
OWNER = 'http://localhost:8182'


def private_file(path):
    return subprocess.check_output(['docker', 'exec', CONTAINER, 'cat', path])


def witness():
    value = subprocess.check_output(['docker', 'exec', CONTAINER,
        '/opt/demo/bin/auths-gateway-simulation', 'execution-witness', '--state-dir', '/run/demo/gateway0'])
    return json.loads(value)['execution_witness']


def native_review(name):
    return json.loads(private_file('/run/demo/private/' + name + '/literal-review.json'))


def test_installed_authenticated_owner_review_and_native_recovery():
    # Read through the trusted operator account, never an application endpoint.
    credential = private_file('/run/demo/private/owner-login').decode()
    denied = subprocess.run(['docker', 'exec', '--user', '62004:62005', CONTAINER,
        'cat', '/run/demo/private/owner-login'], capture_output=True)
    assert denied.returncode != 0 and not denied.stdout
    plan = json.loads(private_file('/run/demo/app/application.json'))
    assert plan['effect_approvals'] == {}, 'the agent received a preapproved effect'
    try:
        urllib.request.urlopen(OWNER + '/api/review')
        raise AssertionError('anonymous private review disclosure')
    except urllib.error.HTTPError as error:
        assert error.code == 401
    before = witness()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context()
        owner, agent = context.new_page(), context.new_page()
        owner.goto(OWNER)
        owner.locator('#credential').fill(credential)
        owner.locator('#login button').click()
        expect(owner.locator('#login')).to_be_hidden()
        assert owner.evaluate('document.cookie === "" && localStorage.length === 0 && sessionStorage.length === 0')
        # Both pages share browser state. Cookie auth would leak across these
        # localhost ports; explicit owner-origin memory/headers must not.
        app_headers = []
        agent.on('request', lambda request: app_headers.append(request.all_headers())
                 if request.url.startswith(APP) else None)
        agent.goto(APP)
        expect(agent.locator('#submit')).to_be_enabled()
        assert all('authorization' not in h and 'cookie' not in h for h in app_headers)
        assert agent.evaluate('typeof bearer === "undefined"')

        agent.locator('#experiment').select_option('pending')
        agent.locator('#submit').click()
        expect(owner.locator('#review')).to_be_visible(timeout=45000)
        expect(owner.locator('#literal')).to_contain_text('"replacement": "Pending"')
        assert witness() == before, 'review entered custody or provider transport'
        owner.locator('#decline').click()
        expect(agent.locator('#outcome')).to_have_text('NOT-SUBMITTED', timeout=45000)
        assert witness() == before, 'declined effect entered the native runtime'

        agent.locator('#experiment').select_option('exact')
        agent.locator('#submit').click()
        expect(owner.locator('#review')).to_be_visible(timeout=45000)
        expect(owner.locator('#literal')).to_contain_text('"replacement": "Approved"')
        native = native_review('owner-mutation-exact')
        assert owner.locator('#literal').text_content() == native['literal_review'], 'review changed or truncated'
        effect_id = json.loads(native['literal_review'])['effect_id_hex']
        assert witness() == before
        status = owner.evaluate('''async () => (await fetch('/api/decision', {
            method:'POST',headers:{'Content-Type':'application/json',
            'Authorization':'Bearer '+bearer,'X-Owner-CSRF':csrf},
            body:JSON.stringify({review_id:'substituted',decision:'approve',renderer})})).status''')
        assert status == 409 and witness() == before
        Path('/evidence').mkdir(exist_ok=True)
        owner.screenshot(path='/evidence/owner-review.png', full_page=True)
        owner.locator('#approve').click()
        expect(agent.locator('#outcome')).to_have_text('RESPONSE-RECORDED', timeout=45000)
        after_write = witness()
        assert after_write['scope'] == before['scope']
        assert after_write['write_transport_entries'] == before['write_transport_entries'] + 1

        agent.locator('#experiment').select_option('recover-exact')
        agent.locator('#submit').click()
        expect(owner.locator('#review')).to_be_visible(timeout=45000)
        expect(owner.locator('#literal')).to_contain_text('auths_gateway_recovery_read_v1')
        native_read = native_review('read-exact-1')
        assert owner.locator('#literal').text_content() == native_read['literal_review']
        assert json.loads(native_read['literal_review'])['native']['recovery']['source_effect'] == effect_id
        assert witness() == after_write
        owner.locator('#approve').click()
        expect(agent.locator('#outcome')).to_have_text('RECOVERY-REPORT', timeout=45000)
        after_read = witness()
        assert after_read['write_transport_entries'] == after_write['write_transport_entries']
        assert after_read['read_transport_entries'] == after_write['read_transport_entries'] + 1
        agent.locator('#experiment').select_option('replay')
        agent.locator('#submit').click()
        expect(agent.locator('#outcome')).to_have_text('OBSERVED-BY-PROVIDER', timeout=45000)
        assert witness() == after_read
        fresh = subprocess.check_output(['docker', 'exec', '--user', '62004:62005', CONTAINER,
            '/opt/consumer/bin/python', '/opt/demo/app.py', 'submit', '--experiment', 'replay'])
        assert json.loads(fresh)['records'][0]['result']['outcome'] == 'observed-by-provider'
        assert witness() == after_read, 'fresh client replay recreated execution'
        agent.screenshot(path='/evidence/owner-journey.png', full_page=True)
        assert all('authorization' not in h and 'cookie' not in h for h in app_headers)
        browser.close()
    manifest = json.loads(private_file('/opt/demo/manifest.json'))
    Path('/evidence/owner-journey.json').write_text(json.dumps({
        'schema': 'auths.authenticated-owner-review-journey/1', 'source_commit': manifest['source_commit'],
        'production_qualification': False, 'native_renderer_unchanged': True,
        'withheld_approvals_before_consent': True, 'decline_no_native_entry': True,
        'substituted_review_refused': True, 'application_cannot_read_owner_credential': True,
        'owner_auth_not_sent_to_application': True, 'one_exact_write': True,
        'independent_exact_read': True, 'replay_no_extra_execution': True,
        'fresh_process_replay_no_new_consent_or_execution': True,
        'scope': 'installed packages and native runtime; browser-simulated authenticated owner; local provider',
        'excluded': ['content acquisition/disclosure journey', 'human attention', 'production custody',
                     'live provider qualification', 'hostile operating system']}, indent=2))


if __name__ == '__main__':
    test_installed_authenticated_owner_review_and_native_recovery()
