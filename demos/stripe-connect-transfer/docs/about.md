# Bounded Connect transfer demo

This demo makes one exact Stripe Connect Transfer understandable: USD 5.00
moves from one platform Charge to one permitted connected account. The signed
action commits the destination, `source_transaction`, PaymentIntent, transfer
group, currency, description, fixed metadata, policy, evaluator,
configuration, audience, expiry, and nonce.

It deliberately cannot create payouts, refunds, reversals, destination charges,
multi-destination transfers, or transfers without a source Charge.
