# Auths SQLite runtime store

`auths-sqlite` is the maintained durable reference implementation of the
Auths Python challenge, budget, command, and receipt store ports. It uses only
the Python standard library and imports all lifecycle and capacity meaning
from `auths.runtime`.

```python
from auths_sqlite import SQLiteRuntimeStore

store = SQLiteRuntimeStore("auths-runtime.sqlite3", budget_ceilings={
    "numeric-ceiling-v1": 100,
})
```

The adapter demonstrates atomic compare-and-swap, replay claims, budget
reservations, and receipt idempotency. Applications remain responsible for
database backup, encryption, filesystem permissions, availability, and
operational recovery.
