"""Minimal application call through Auths and a generated domain client."""

import asyncio

import auths
from auths_profiles.stripe import Stripe


async def main() -> None:
    async with auths.connect() as session:
        stripe = Stripe(session, connection="billing")
        refund = await stripe.refunds.create(
            payment_intent="pi_123",
            amount=2_000,
            currency="usd",
        )
        print(refund.id, refund.auths.operation_id)


if __name__ == "__main__":
    asyncio.run(main())
