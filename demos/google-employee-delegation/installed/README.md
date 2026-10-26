# AP-071 installed Google task bundle

`build_bundle.py` packages a reviewed gateway, Google custody executable,
native Auths wheel, broker wheel, separate agent wheel, offline dependencies
and the four read/write/create/populate recipe pairs. It copies no Google grant,
OAuth client, task key, private producer report or document content.

Build from the repository with a fresh output directory:

```sh
python3 demos/google-employee-delegation/installed/build_bundle.py \
  --output /private/tmp/ap071-google-bundle \
  --gateway-bin /absolute/path/to/auths-gateway \
  --custody-bin /absolute/path/to/auths-google-employee-custody \
  --auths-wheel /absolute/path/to/auths.whl \
  --broker-wheel /absolute/path/to/broker.whl \
  --agent-wheel /absolute/path/to/agent.whl \
  --dependency-wheelhouse /absolute/path/to/offline-wheels
```

Keep the printed `manifest_sha256` outside the bundle. On the target host,
use a Python 3.12 interpreter with `venv` and bundled `ensurepip` support:

```sh
python3.12 /private/tmp/ap071-google-bundle/prepare.py \
  --manifest-sha256 PIN_FROM_BUILD_OUTPUT \
  --root /private/tmp/ap071-google-install
```

Preparation checks every bundle byte against the independent manifest pin,
installs wheels with `--no-index`, imports the three packages from the new
virtual environment outside the checkout, and checks the gateway command.
The output gives the installed Python, gateway and custody paths. Configure
the owner-private Google source references, task journal, signed Jules task
and demo_co reports separately; this preparation creates no provider effect
and does not qualify the live run by itself. The
[v2 producer runbook](../../../docs/program-log/2026-10-26-ap071-provider-final-v2-consumer.md)
records the report sequence and owner activity manifest.
