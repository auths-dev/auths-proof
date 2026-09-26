# Provider connection lifecycle runbook

Provider connections are deployment-owned account bindings. Applications see
only a non-secret alias. Credentials cross the privileged local admin socket,
are stored by the agent, and are never returned through the application SDK.

## Start and validate the agent

Use owner-controlled absolute paths. The current runnable deployment is
qualified only for Unix-domain sockets.

```bash
auths-node agent validate-config /etc/auths/agent.toml
auths-node agent serve \
  --config /etc/auths/agent.toml \
  --state-directory /var/lib/auths
```

The state directory must be owner controlled. The agent binds separate
application and admin sockets, creates its recovery key without overwriting,
and refuses malformed authority, profile configuration, or persistent stores
before publishing either socket.

The admin socket keeps its own connection budget, so an application that
holds or refills its socket cannot keep `connections disable` or `revoke` from
connecting. Application connections are limited agent-wide and per peer UID,
and a connection that sends nothing, stops inside its headers, or stops inside
its body is closed after 10 seconds. The agent sizes the application limit
from its soft descriptor limit and refuses to start
(`process descriptor limit is too low for the local-agent sockets`) when that
limit cannot also reserve the admin socket's share. A soft limit of at least
16,400 (for example systemd `LimitNOFILE=16400`) admits the full 8,192
application connections; a lower limit admits half of what remains after the
admin share. A failed accept is logged and retried; it does not stop the
agent.

## Add and inspect an account

Prepare a canonical non-secret provider descriptor and an owner-only secret
file (or pipe the secret on non-terminal stdin):

```bash
auths-node --admin-socket /var/lib/auths/admin.sock connections add stripe \
  --alias billing \
  --descriptor /etc/auths/stripe-billing.json \
  --allow-workload refund-worker \
  --allow-profile auths.stripe.refund/1 \
  --secret-file /run/secrets/stripe-billing

auths-node --admin-socket /var/lib/auths/admin.sock connections inspect stripe/billing
auths-node --admin-socket /var/lib/auths/admin.sock connections list
```

Onboarding must contact or query the provider sufficiently to prove that the
credential belongs to the descriptor's immutable account. Unknown or widened
scopes fail before publication.

## Default selection

Defaults and allowed aliases belong to workload mapping configuration, not
application credentials. Changing the account selected by an existing alias is
not an in-place edit: onboard the successor account under a new record, update
the workload mapping deliberately, and preserve unresolved recovery against the
original connection generation.

## Rotate, disable, enable, revoke

```bash
auths-node --admin-socket /var/lib/auths/admin.sock connections rotate stripe/billing \
  --secret-file /run/secrets/stripe-billing-next
auths-node --admin-socket /var/lib/auths/admin.sock connections disable stripe/billing
auths-node --admin-socket /var/lib/auths/admin.sock connections enable stripe/billing
auths-node --admin-socket /var/lib/auths/admin.sock connections revoke stripe/billing
```

- **Rotate** creates a successor generation with the new secret, and new
  operations use it. The agent keeps the previous secret while an unresolved
  operation still names its generation. It deletes it once none does,
  checking at each rotation and whenever an execute or recover call finishes
  an operation. A rotation that fails after storing the new secret deletes it
  again, and the connection keeps its current secret.
- **Disable** blocks new operations and every provider entry, including an
  operation that stopped before entering the provider. Reconciliation of an
  operation that may already have entered the provider continues. Disable
  stores no secret, so it works when the credential store is full.
- **Enable** reopens a non-revoked record after operator review. Operations
  prepared before the disable still cannot enter the provider, because their
  generation is superseded.
- **Revoke** is permanent. The record refuses every credential lease,
  reconciliation included, and the agent deletes every stored generation of
  the connection's secret; revoke also works when the credential store is
  full. An operation that had not entered the provider ends `unavailable`. One
  that may have entered stays `recovery-required` with effect `possible`; it
  is never rewritten as `not-applied`. Close it with provider evidence as the
  [recovery runbook](PROFILE_RECOVERY_RUNBOOK.md) describes. If revoke reports
  a failure after the record is revoked, run it again: a repeated revoke
  finishes deleting the stored secrets. To stop the credential from working
  anywhere, also revoke it at the provider.

Every mutation is admin-peer authenticated and appended to the redacted audit
log. Never put credentials, recovery handles, raw descriptors containing
secrets, or provider responses in logs.

## Backup and restore

Back up the complete owner-only state directory as one consistency unit while
the agent is stopped: connection registry, credential store, operation journal,
recovery key, profile state, and admin audit log. Preserve ownership and modes.
Restoring only some files can make exact recovery impossible and must fail
closed. After restore, run config validation and inspect sanitized records
before starting application traffic.

For possible effects and crash recovery, follow
[Profile recovery](PROFILE_RECOVERY_RUNBOOK.md).
