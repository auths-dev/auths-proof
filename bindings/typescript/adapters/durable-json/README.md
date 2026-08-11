# Auths durable JSON runtime store

This separately versioned reference adapter proves that `ExecutionStatePort`
can survive a Node.js process restart without becoming part of
`@auths-dev/sdk`.

It uses atomic file replacement and serializes calls within one process. It is
appropriate for examples, development, and single-process services. It does
not claim multi-host coordination; production deployments should implement the
same compare-and-set contract over their transactional database.

```js
import { DurableJsonExecutionStateStore } from "@auths-dev/runtime-json-store";

const state = new DurableJsonExecutionStateStore("./var/auths-runtime.json");
```
