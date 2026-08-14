# Prompt: Build an International Shipment Chain of Custody

You are working in the `auths-dev/auths-proof` repository without prior project knowledge. Build a realistic demonstration in which a pharmaceutical manufacturer, a logistics company, and a customs authority transfer custody of a temperature-sensitive shipment across organizational, cryptographic, network, and offline boundaries.

Begin by reading `AGENTS.md` and its referenced instructions, the target-state architecture documents, both elite SDK specifications, the Rust semantic core, public SDKs, fixtures, and current demos. Work autonomously and make documented decisions where the repository leaves application policy open.

All Auths meaning must remain native-owned. Application code may adapt sensors, identity providers, transport, storage, and customs APIs, but it must not invent parallel verification or capability rules.

## Organizations and actors

- **Helix Pharma** uses client-certificate employee authentication, P-256 staff identities, and Ed25519 container-sensor identities.
- **Wayline Logistics** uses OAuth/OIDC for employees and Ed25519 workload identities for routing agents.
- **Port Meridian Customs** uses WebAuthn-style employee authentication and P-256 Auths identities.
- Each physical container, warehouse scanner, routing agent, compliance agent, and human custodian has a distinct identity and lifecycle.

Do not collapse authentication method, signing suite, Auths identity, organization, or physical asset identity into one type.

## Required workflow

1. Create one batch, container, manifest, route, temperature range, and delivery deadline.
2. Helix authorizes shipment of exactly that batch in exactly that container.
3. A container sensor signs bounded temperature readings while online and offline.
4. Custody moves from manufacturer to carrier, carrier to port, and port to warehouse through attenuated delegations.
5. Iroh transports readings and custody artifacts during disconnected segments; HTTPS transports them when infrastructure returns.
6. A compliance agent reviews the journey without receiving release authority.
7. Customs approves release of the exact container and manifest.
8. The receiving warehouse verifies identity, authority, status, approval, journey evidence, and receipts without querying a shared central account database.
9. Python and TypeScript independently verify selected portable artifacts and agree on the outcome.
10. Rotate at least one sensor or employee key without pretending it is a new organization or asset.

## Attack and disruption lab

Build visible, repeatable cases for:

- Replacing the container ID in an approved manifest.
- Applying authority for one shipment to another shipment.
- Replaying a sensor reading or custody-transfer command.
- Creating a child delegation with a longer deadline or broader route.
- Using a sensor after compromise.
- Using custody authority after handoff or expiry.
- Delivering an unauthorized artifact successfully over Iroh.
- Receiving conflicting online and offline status observations.
- Breaking the temperature policy midway through the route.
- Failing the warehouse API after a release command may have executed.

The system must fail closed where required and distinguish rejection, retryable failure, and outcome unknown.

## Experience

Build a polished shipment operations application with:

- A map or route timeline.
- Separate organization consoles.
- Live custody, identity, key-suite, and lifecycle state.
- A temperature and evidence timeline.
- An authority/delegation graph.
- Customs review and approval.
- Transport state showing offline Iroh and online HTTPS delivery.
- Final receipt and cross-SDK verification views.
- An attack-lab drawer that explains the exact failed invariant.

## Engineering constraints

- Use separate services and stores for all three organizations.
- Keep sensor, IdP, key, transport, storage, and application-policy adapters replaceable.
- Use bounded deterministic data rather than simulated success flags.
- Keep review, approval, custody transfer, and physical release distinct.
- Preserve opaque verified objects at SDK boundaries.
- Prefer parse-don't-validate construction, strong types, separation of concerns, DRY code, and minimal comments.
- Do not add compatibility or deprecation machinery to this prelaunch repository.

## Deliverables and completion

Place the demo under `demos/international-shipment-custody/`. Include a one-command launcher, deterministic scenario controls, README, architecture diagram, threat model, feature-to-proof matrix, fixtures, and comprehensive unit, integration, browser, transport, lifecycle, parity, and adversarial tests.

The demo is complete when a new developer can run a full shipment, disconnect and reconnect transport, transfer custody, rotate a key, approve customs release, attack every boundary, and independently verify the final chain from both SDKs.
