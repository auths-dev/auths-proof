# Bounded subscription-create demo

This native demo proves one exact Auths action can create one repository-owned
Stripe test subscription without granting general Billing authority to the
agent. The action consumes a typed payment-mandate receipt and fixes the
Customer, PaymentMethod, Product, Price, quantity, weekly interval, first
invoice, three-cycle liability, test clock, and terminal `cancel_at`.

The page shows policy, action, calculated liability, provider boundary, and
canonical receipts together. It never returns Stripe credentials or a
PaymentIntent/SetupIntent client secret.
