# Bounded comparison: current observations

This experiment tests mechanisms on a local refund operation. It is not a named
competitor benchmark, independent production review or customer-value study.

## Contracts and common observations

Auths uses the source-free main package, installed clients, exact portable
approval quorum, private compiled-effect approval, native journal/fence and the
counting platform Stripe double. The baseline uses scoped locally issued HS256
JWTs with pinned issuer/audience/algorithm/expiry, two distinct server-side
manager approval records for the exact JSON action, a closed local HTTP ingress,
transactional SQLite admission and a provider idempotency key.

Both actually send HTTP to the same provider-double implementation. The selected
refund contract has an exact payment/amount/currency, a gross-payment relative
ceiling, a shared 1000-unit capacity and conservative retention after a lost
response. Applied provider effects and persisted accounting are observed; neither
gateway's success string alone is the effect oracle.

The baseline has one actor and no transferable delegation. Its scope check and
budget are conventional application policy, not another Auths implementation.
It is a lab identity stub, not an OAuth authorization server. Its implementation
is intentionally allowed ordinary transactions, approval records and idempotency;
the experiment does not remove those mechanisms to create an artificial failure.

## Results already observed

| Scenario | Auths evidence | Baseline observation |
| --- | --- | --- |
| Exact approved request | New provider-reaching positive control plus installed reference | One applied effect; retained accounting. |
| Change approved amount | Changed action and other exact approval refused without provider entry | Changed action has no matching approvals; denied, no effect. |
| Duplicate approver | Existing installed/native quorum cases in the completed census | One manager recorded twice does not satisfy quorum; denied. |
| Final shared capacity | Sixteen contenders across two gateway processes; one write, total 1000 | Sixteen HTTP contenders; one effect, total 1000. |
| Response lost after apply, then retry | Unknown retained across restart/inspection; no extra provider I/O | Unknown and charge retained; replay makes no extra provider I/O. |
| Withdrawal before entry | New connection-disable-before-entry case and native fence histories | Trusted operator disables under the same transaction owner; request denied. |

The matching rows are scenario families, not identical protocol byte streams or
an exhaustive equivalence proof. The baseline's fault row does not yet establish
its process-restart, power-loss or multi-host behavior. Differences are recorded
rather than quietly attributed to a commercial product.

## What this changes

These observations do **not** show that Auths uniquely supplies exact approval,
basic transactional limits or conservative replay. A small application-owned
adapter can implement those properties for one operation with conventional
mechanisms. Any product claim to the contrary would be unsupported.

Potential incremental value remains in reusable native contracts, actual
delegation/capacity-origin handling, separately authorized recovery/information
flow and portable public-key evidence. The baseline does not implement those;
their absence is an explicit coverage/cost gap, not a demonstrated exploit.
The installed AP073 corpus and source/composition analysis assess Auths's side,
but do not establish a buyer wants or needs the additional machinery.

## Cost and limitations

The custom baseline and HTTP adapter are in
`qualification/security_assessment/baseline.py`; the scenario controller is
`compare.py`. Count them separately from the shared provider double and generated
evidence. They are a small research adapter without Auths's supported principal
methods, language surfaces, durable administrative lifecycle, shared-store
deployment, independent recovery grants or public-proof audit contract. Comparing
its line count with the whole monorepo would be misleading.

Both experiments use development custody and synthetic provider state. Command
timings are machine observations, not human onboarding effort. Setup steps,
custom security decisions and recovery burden must be interpreted alongside the
different feature contracts. Demand, operational acceptability and commercial
differentiation remain unvalidated.

The measured handwritten source counts, including comments/blank lines, are
206 lines for `baseline.py` and 102 for `compare.py`. The independent Auths
campaign driver is 411 lines and the shared provider double is 112. These are
lab-adapter costs, not production implementation-size comparisons. The baseline
has six explicit decision groups (scoped identity, exact action, distinct manager
quorum, enabled state, shared count/sum, retained attempt) and one SQLite state
owner. It still trusts its operator, identity/approval provisioner and database;
HS256 records are not transferable independent authorization evidence.

The recorded six baseline case intervals sum to about 0.077 seconds on this
machine; the Auths recovery drill records four scripted steps over about 2.222
seconds. Those clocks cover different work and are **not** a comparative latency
benchmark. Image acquisition/build/fixture preparation and human effort are
outside those intervals. Auths's reproduction requires pinned package acquisition,
lab image construction and container execution; the baseline reuses that lab
image and provider double, so treating it as zero-setup would be unfair.
