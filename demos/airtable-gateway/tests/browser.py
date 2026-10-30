"""Actual browser against packaged app, two native gateways and counting provider."""
import json
import urllib.request
import urllib.error
from playwright.sync_api import expect, sync_playwright


def test_packaged_workbench_and_unsigned_evidence():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto('http://localhost:8081')
        expect(page.locator('#mode')).to_contain_text('SIMULATION')
        expect(page.locator('#submit')).to_be_enabled()
        expect(page.locator('#approval')).to_contain_text('2 of 3')
        expect(page.locator('#approval-review')).to_contain_text('set_demo_status_v1')
        for case, outcome in [('approval-insufficient', 'DENIED'),
                              ('approval-duplicate', 'NOT-SUBMITTED'),
                              ('unsupported-value', 'NOT-ENTERED'), ('rate-limit', 'RESPONSE-RECORDED'), ('exact', 'RESPONSE-RECORDED'), ('recover-exact', 'RECOVERY-REPORT'),
                              ('replay', 'OBSERVED-BY-PROVIDER'), ('lost-response', 'UNKNOWN')]:
            page.locator('#experiment').select_option(case)
            page.locator('#submit').click()
            expect(page.locator('#outcome')).to_have_text(outcome, timeout=45000)
            expect(page.locator('#submit')).to_be_enabled()
        expect(page.locator('#explanation')).to_contain_text('no automatic retry')
        page.locator('#receipt-link').click()
        expect(page.locator('#result-json')).to_contain_text('auths.gateway-audit-bundle/2')
        expect(page.locator('#result-json')).to_contain_text('outcome_b64')
        page.screenshot(path='/evidence/workbench-evidence.png', full_page=True)
        page.goto('http://localhost:8081')
        page.screenshot(path='/evidence/workbench.png', full_page=True)
        page.set_viewport_size({'width': 390, 'height': 844})
        page.screenshot(path='/evidence/workbench-mobile.png', full_page=True)
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        assert page.evaluate('document.querySelectorAll("button").length') == 1
        browser.close()


def test_http_origin_and_closed_experiment_refusals():
    request = urllib.request.Request('http://localhost:8081/api/experiment',
        data=b'{"experiment":"exact"}', headers={'Content-Type': 'application/json'}, method='POST')
    try:
        urllib.request.urlopen(request)
        raise AssertionError('missing origin/session was accepted')
    except urllib.error.HTTPError as error:
        assert error.code == 403
    with urllib.request.urlopen('http://localhost:8081/api/status') as response:
        token = json.load(response)['submission_token']
    for body in [b'{"experiment":"unlisted"}', b'{"experiment":"exact","provider_url":"https://other.example"}']:
        request = urllib.request.Request('http://localhost:8081/api/experiment', data=body,
            headers={'Content-Type': 'application/json', 'Origin': 'http://localhost:8081',
                     'X-Demo-Token': token}, method='POST')
        try:
            urllib.request.urlopen(request)
            raise AssertionError('unlisted experiment or provider argument was accepted')
        except urllib.error.HTTPError as error:
            assert error.code == 400


if __name__ == '__main__':
    test_http_origin_and_closed_experiment_refusals()
    test_packaged_workbench_and_unsigned_evidence()
