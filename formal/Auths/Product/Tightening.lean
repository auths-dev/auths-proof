import Auths.Product.Eligibility

namespace Auths.Product

universe u

/--
A domain supplies its own policy type, fixed-context evaluator, and semantic
tightening relation. The shared contract does not invent a universal policy
language.
-/
structure ClosedEvaluator where
  Policy : Type u
  Context : Type u
  evaluate : Policy → Context → Eligibility
  tightens : Policy → Policy → Prop
  resultRefines : OutputCommitments → OutputCommitments → Prop
  tightensRefl : ∀ policy, tightens policy policy
  tightensTrans :
    ∀ {child middle parent},
      tightens child middle →
      tightens middle parent →
      tightens child parent
  eligibleMonotone :
    ∀ {child parent context childOutputs},
      tightens child parent →
      evaluate child context = .eligible childOutputs →
      ∃ parentOutputs,
        evaluate parent context = .eligible parentOutputs ∧
        resultRefines childOutputs parentOutputs

theorem fixed_context_tightening
    (evaluator : ClosedEvaluator)
    {child parent : evaluator.Policy}
    {context : evaluator.Context}
    {childOutputs : OutputCommitments}
    (tightens : evaluator.tightens child parent)
    (eligible :
      evaluator.evaluate child context = .eligible childOutputs) :
    ∃ parentOutputs,
      evaluator.evaluate parent context = .eligible parentOutputs ∧
      evaluator.resultRefines childOutputs parentOutputs :=
  evaluator.eligibleMonotone tightens eligible

end Auths.Product
