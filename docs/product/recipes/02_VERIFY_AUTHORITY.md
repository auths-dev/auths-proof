# Verify authority without executing

Learn **Authority** and **Action**. Verification checks whether existing proof
authorizes one exact action and remains effect-free.

```ts
import { verify } from "@auths-dev/sdk/verify";

const result = await verify({ proof, action, trust });
console.log(result.kind, result.code);
```

```python
from auths.verify import verify

result = verify(proof, action, trust)
print(result.kind, result.code)
```

Outcome: `authorized`, `denied`, or `indeterminate`. An authorized verification
result is still inert evidence.
