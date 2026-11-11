# Gateway serving and restart ownership

One gateway process owns an installation from startup through admitted-session
drain and socket cleanup. A second `serve` attempt fails with
`gateway.serve.busy` while that owner is active, including during shutdown.
Administrative commands use a separate state lock and remain available.

Application and administration sockets must have existing canonical parent
directories owned by the gateway UID and closed to group/other writes. The
administration parent retains its stricter private-directory requirements.
Each endpoint parent is exclusively claimed by one daemon. Separate daemon
installations must use separate endpoint parent directories, even when their
socket filenames differ. This restriction also covers filename aliases on
case-insensitive filesystems. Keep the retained serving lockfiles in place;
deleting an active lockfile defeats coordination between processes.

Normal shutdown stops new admission, drains admitted sessions, removes only the
socket identities created by that serving generation, then releases ownership.
If the existing 25-second drain deadline expires, the process reports
`gateway.serve.shutdown-incomplete` and exits with failure while its claims are
still held. This is an incomplete shutdown, not confirmation that every external
effect finished. A subsequent process acquires the OS-released claims and uses
the existing dead-socket and durable recovery checks.

These claims protect process and endpoint ownership. Native operation fences,
receipt truth, provider reconciliation and administrative authorization retain
their existing authorities. See [AP-SPEC-078](../specs/0078-residual-state-ownership.md)
for the transition and interruption contract.
