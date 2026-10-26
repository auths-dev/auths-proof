# AP-071 source-free Google artifact preparation, 26 October 2026

This prepares the revised Google read/create/populate task path without a
Google request, Jules signature or provider effect. The
[bundle builder](../../demos/google-employee-delegation/installed/build_bundle.py)
copies only reviewed executables, wheels and four recipe/profile-lock pairs;
it copies no grant, OAuth client, task key, private producer report or content.

| Component | SHA-256 |
| --- | --- |
| Gateway executable | `707c4ec66188b0ccdb388c298e8262270bae7ae8116e5875a2c364c69ea74c40` |
| Google custody executable | `d4c455bd8f86d4aeae28819a7860f079a709eb2c94b5f6d42b53ef11b8f9902a` |
| Native Auths wheel | `433e9d5f6c1627084ab7fea8d5c951ec92931021ac86a3d9d167fa23435367c2` |
| Broker wheel with provider v2 owner view | `60f2a7da04f69eb1213eac1338ab1ec3f9bdd62466753566ca27faef1f373856` |
| Separate agent wheel | `5080d42bbb0e240a79bc7205dbaf7bd4b2bd28915ae41a0d0cda25993fac0e5a` |

The final local bundle is
`/private/tmp/ap071-google-source-free-bundle-final-20261026` with
`manifest.json` SHA-256
`cc3113dc6b9b0a8d08c1bfc27f2ca815044f069f6fa01322ff741e1f77434c94`.
It contains 33 wheels including the three primary wheels. The
[preparation command](../../demos/google-employee-delegation/installed/prepare.py)
verified the independent manifest pin, installed with pip `--no-index`, and
imported the native, broker-owner and agent modules from a new isolated
virtual environment under
`/private/tmp/ap071-google-source-free-install-final-20261026`. It ran
outside the checkout with Homebrew Python 3.12. The gateway command help
completed, and `pip check` reported no broken requirements. A deliberately
wrong manifest digest was refused before creating
an installation root. A synthetic inventory check refused an added, unpinned
nested `manifest.json` file. This host's uv-managed Python 3.12 could not
seed pip in a standard `venv`; the successful run used the Homebrew interpreter.
The installed native wheel also passed `bindings/python/tools/check_contract.py`
against the checked-in ABI manifest.

The installed bundle is ready to be configured with the owner-private Google
grant source and the next fresh demo_co v2 reports. It has not activated a
human-to-agent task or exercised the live Google effect, and it does not
qualify production custody or container isolation. The
[producer v2 runbook](2026-10-26-ap071-provider-final-v2-consumer.md)
records the remaining report sequence and owner-view evidence manifest.
