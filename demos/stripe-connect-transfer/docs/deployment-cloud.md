# Cloud deployment

The supplied `fly.toml` runs the Rust API as a non-root process with a persistent
volume. Deploy from this demo directory only after choosing an unused Fly app
name and explicitly provisioning the volume.

The static `web/` directory can be deployed to Vercel. For a split deployment,
configure the frontend to call the Fly origin and set
`AUTHS_STRIPE_ALLOWED_ORIGIN` to the exact Vercel HTTPS origin.

Stripe keys are server-only secrets. Public deployment and secret upload are
separate release approvals; neither is implied by local CLI login.
