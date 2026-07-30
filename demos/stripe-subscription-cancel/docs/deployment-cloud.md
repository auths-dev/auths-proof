# Cloud deployment

The checked-in Fly and Vercel manifests bind the intended origins. Add secrets only through the platform secret stores and only with explicit operator authorization. Never place a Stripe key in Vercel browser variables.
