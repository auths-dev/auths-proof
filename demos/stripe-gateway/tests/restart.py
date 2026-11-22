"""Verify retained Unknown and app access after a packaged simulation restart."""
import json
import subprocess
import sys
import time


def docker(*args):
    return subprocess.run(['docker', *args], check=True, capture_output=True,
                          text=True, timeout=10).stdout


def check_restart(container):
    def provider_requests():
        return int(docker('exec', container, 'wc', '-l', '/run/demo/provider.jsonl').split()[0])

    marker = 'demo.gateway-restarted:gateway0'
    previous = docker('logs', container).splitlines().count(marker)
    before = provider_requests()
    docker('kill', '--signal=HUP', container)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if docker('logs', container).splitlines().count(marker) == previous + 1:
            break
        time.sleep(0.2)
    else:
        raise AssertionError('operator did not report gateway0 ready after restart')

    # The prior workbench test submitted this same operation and observed Unknown.
    # Its exact retained history is available to the restricted app after restart.
    result = json.loads(docker('exec', '--user', '62004:62005', container,
                              '/opt/consumer/bin/python', '/opt/demo/app.py',
                              'submit', '--experiment', 'lost-response'))
    assert [entry['result']['outcome'] for entry in result['records']] == ['unknown']
    assert provider_requests() == before, 'restart or retained-result lookup entered provider'
    print('Gateway restart retained Unknown with no additional provider request')


if __name__ == '__main__':
    check_restart(sys.argv[1])
