# Installed native delegation process evidence

The orchestrator uses public native authoring APIs and real CLI/daemon processes.
Five installed-language processes generate their own fresh keys: resource owner,
initiating machine, agents A/B and an independent **scripted** reviewer. The
orchestrator receives public keys and signatures; seeds never cross that pipe.
The reviewer is a test signing role, not a human-presence assertion or production
custody adapter. Python uses the installed SDK's native ephemeral identity key;
npm transport uses the installed public gateway subpath and Node's Ed25519 crypto.
The native CLI supplies recipient disclosure; no alternate verifier is embedded
in either role script.

The native flow provisions a connection privately, prepares root pins against it,
reviews/activates the scoped policy, bootstraps the root, enrolls A then B with
separate control/acceptance/resource evidence, and independently approves exact
read, disclosure and mutation effects. A receives plaintext only through the
authenticated native disclosure protocol. B receives acquisition metadata. The
double checks a fresh private credential and exact request, while uncredentialed
direct calls fail. The shared ancestor limit refuses A's second write after B's
first. Restart replay causes no new write. Withdrawal of A leaves B's original
enrollment receipt historical and refuses a new B approval review. Original
control history is exported and replayed with separate trusted inputs.

For the required local canonical artifact construction (not a general test gate):

```sh
python3 product/runtime/auths-gateway/tests/content_journey/delegation_process/build_local.py \
  --output /tmp/ap073-installed-consumer-unique
```

The output directory must be new. The constructor builds the gateway/test
executable, wheel and full npm/WASM payloads, installs the packages into that
directory, and explicitly runs the ignored installed-process constructor. Logs
are retained separately for independent build failures. It does not use sibling
source imports, live credentials or a live provider. The canonical artifact
excludes random keys, host IDs, clock samples, paths and private content.

The Airtable package workflow additionally copies the compiled orchestrator into
the existing handoff. The receiving job has no repository checkout: it verifies
payload checksums, installs wheel/npm payloads and invokes the embedded native
test from the container. Linux mode uses five distinct numeric UIDs, cleared
supplementary groups/capabilities and no-new-privileges; only the app socket group
is shared. State is operator-private. Agents probe private state and other
signers' process memory. Local same-UID runs do not establish DAC or hostile
process-memory containment. No mode promises protection from a hostile host/root,
erasure of all JavaScript/Python memory copies, or control after authorized
plaintext disclosure. Arbitrary post-disclosure network egress is not restricted.

The artifact does not establish live provider qualification, human presence,
every crash/ACK-loss schedule, PostgreSQL or full AP073 acceptance. Those remain
separate required evidence; this workflow is not a substitute for them.
