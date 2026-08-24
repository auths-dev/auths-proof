/** Minimal application call through Auths and a generated domain client. */

import { connect } from "@auths-dev/sdk";
import { Stripe } from "@auths-dev/profile-stripe";

const session = await connect();
try {
  const stripe = new Stripe(session, { connection: "billing" });
  const refund = await stripe.refunds.create({
    paymentIntent: "pi_123",
    amount: 2_000,
    currency: "usd",
  });
  console.log(refund.id, refund.auths.operationId);
} finally {
  await session.close();
}
