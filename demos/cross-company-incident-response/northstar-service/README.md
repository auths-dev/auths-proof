# Northstar demo state ownership

Run exactly one mutating Node process for each `NORTHSTAR_STATE_PATH`. The JSON
file is local demo state; sharing it between processes or machines is unsupported.
A deployment needing shared state must use a cross-process transaction.

Each request finishes bounded body acquisition before loading state. The single
Node event loop then owns current-state guard checks, mutation, persistence and
response without an intervening await. Code redemption, approval counters,
firewall application and reset all use that boundary. A body admitted before
reset re-evaluates the reset successor when its body finishes.

Build with `npm run build`, then run `npm test`. The held-body tests start isolated
server processes and use HTTP admission acknowledgements to order competing
requests without scheduler sleeps. They cover code consumption, provider calls,
approval counters, timelines and reset. They establish same-process ordering;
they do not claim crash-safe JSON replacement or physical power-loss durability.
