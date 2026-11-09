# Customer-validation handoff

Status: hypotheses and interview protocol only. No customer was contacted, no
human trial was performed and no willingness to adopt is established.

## Concrete candidate action to validate

**Unvalidated hypothesis:** a support organization currently lets its assistant
propose a refund but withholds the Stripe credential because the assistant could
refund a different payment, exceed shared limits or repeat an uncertain refund.
The candidate permitted action is one platform-account refund for the exact
named payment, currency and amount approved by two distinct authorized managers,
within the installed per-action and shared count/sum ceilings. The agent receives
no provider credential. This describes the existing supported demonstration;
it is not evidence that an organization actually has this problem.

Ask the prospective risk owner to decide whether that bounded workflow changes
their present prohibition. Acceptance requires the unfamiliar operator to
configure the supported deployment, execute the authorized test-mode action,
observe changed-action/limit/replay refusals, export independently verifiable
authorization evidence and safely handle a deliberately lost response. Record
every undocumented intervention, approval step and unresolved escalation.

Falsify the value hypothesis if their ordinary identity/approval/transactional
gateway can already permit the action with acceptable effort, if the extra
provisioning/recovery burden outweighs the benefit, or if the required trusted
parties differ from Auths's supported threat model. The bounded baseline gives
a concrete reason to ask these questions. Do not recruit a fictional customer
or change the security acceptance criteria to obtain a positive answer.

## Interview and acceptance questions

Use the existing refund workflow to explain the boundary, but do not presume that
two people approving every small refund is the actual customer requirement. Ask
an actual prospective operator for one consequential action they currently refuse
to delegate. Record their words and context with permission; do not synthesize
answers with an agent persona.

For that action establish:

1. What useful work is blocked today, how frequently it arises and who owns the
   risk decision. Distinguish an existing manual process from a hypothetical need.
2. Whether the concern is a compromised agent, excessive delegation, credential
   exposure, accidental duplicate effects, a dishonest operator or another party.
   The trust model determines which Auths guarantees would matter.
3. The smallest guarantee that changes the decision: exact approval, bounded
   upfront authority, shared limits, independent evidence, recovery or another
   concrete property. Do not lead the participant toward every Auths feature.
4. What their current identity/policy/provider-idempotency stack already handles,
   and what custom code or operational work would close the remaining gap.
5. The provisioning, approval latency, unresolved-outcome escalation and recovery
   burden they would accept, and who could actually operate those procedures.
6. A falsifiable acceptance exercise they are willing to try with disposable data,
   plus reasons they would reject the product even if its security tests pass.

Only after those answers should a new provider or feature be considered. A
successful lab comparison cannot establish buying intent, human understanding or
safe production operation. Keep the security assessment and customer conclusions
separate in the final release recommendation.
