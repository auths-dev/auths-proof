# Authenticate an identity

Learn one security concept: **Identity**. This recipe exchanges bounded public
identity data and proves control over exact message bytes. It creates no
authority, approval, or effect workflow.

```ts
import { identity } from "@auths-dev/sdk/identity";

const received = identity.decode(packet);
const authenticated = await identity.authenticate(received, { message, signature, registry });
console.log(authenticated.id);
```

```python
from auths.identity import decode_identity

received = decode_identity(packet)
authenticated = await received.authenticate(message, signature, registry)
print(authenticated.identity_id)
```

Outcome: authenticated identity data, or a typed rejection. Authentication
never creates permission.
