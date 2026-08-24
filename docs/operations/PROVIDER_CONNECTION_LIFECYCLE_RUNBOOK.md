# Provider connection lifecycle runbook

Provider connections are deployment-owned account bindings. Applications see
only a non-secret alias. Credentials cross the privileged local admin socket,
are stored by the agent, and are never returned through the application SDK.

## Start and validate the agent

Use owner-controlled absolute paths. The current runnable deployment is
qualified only for Unix-domain sockets.

```bash
auths agent validate-config /etc/auths/agent.toml
auths agent serve \
  --config /etc/auths/agent.toml \
  --state-directory /var/lib/auths
```

The state directory must be owner controlled. The agent binds separate
application and admin sockets, creates its recovery key without overwriting,
and refuses malformed authority, profile configuration, or persistent stores
before publishing either socket.

## Add and inspect an account

Prepare a canonical non-secret provider descriptor and an owner-only secret
file (or pipe the secret on non-terminal stdin):

```bash
auths --admin-socket /var/lib/auths/admin.sock connections add stripe \
  --alias billing \
  --descriptor /etc/auths/stripe-billing.json \
  --allow-workload refund-worker \
  --allow-profile auths.stripe.refund/1 \
  --secret-file /run/secrets/stripe-billing

auths --admin-socket /var/lib/auths/admin.sock connections inspect stripe/billing
auths --admin-socket /var/lib/auths/admin.sock connections list
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
auths --admin-socket /var/lib/auths/admin.sock connections rotate stripe/billing \
  --secret-file /run/secrets/stripe-billing-next
auths --admin-socket /var/lib/auths/admin.sock connections disable stripe/billing
auths --admin-socket /var/lib/auths/admin.sock connections enable stripe/billing
auths --admin-socket /var/lib/auths/admin.sock connections revoke stripe/billing
```

- **Rotate** creates a successor generation. New operations use it; unresolved
  operations retain the exact prior generation needed for recovery.
- **Disable** blocks new operations but preserves recovery material.
- **Enable** reopens a non-revoked record after operator review.
- **Revoke** is permanent. New effects stop immediately; retained unresolved
  recovery state must not be rewritten as `not-applied` merely because the
  current credential is unavailable.

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
