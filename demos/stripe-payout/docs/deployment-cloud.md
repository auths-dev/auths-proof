# Cloud deployment

The Fly configuration runs the API as a non-root process with persistent
storage. The static `web/` directory is suitable for Vercel after configuring
the exact API and CORS origins.

Provisioning a Fly volume, selecting public names, deploying, and uploading a
server-only restricted Stripe test secret are explicit release operations.
Existing CLI login does not authorize them.
