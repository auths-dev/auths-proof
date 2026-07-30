# Bounded Issuing purchase demo

This demo turns one protected Stripe Issuing authorization event into an exact
full-amount approve/decline response. Auths proof verification, webhook
evidence, procurement intent matching, deny-precedence policy evaluation,
atomic capacity reservation, and receipt persistence are visible. The agent
never receives Stripe credentials or card secrets.

The repository browser scenario is deterministic. A genuine Stripe
`issuing_authorization.request` enters only through the signature-authenticated
webhook route and unmatched events fail closed.
