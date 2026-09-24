import Auths.Product.Tightening
import Auths.ExtensionLaw

/-!
# The gateway's argument-ceiling window-count evaluator

One registered bounded-policy evaluator: a ceiling on one named verified
argument, and a maximum number of authorized actions per principal in each
fixed window. A grant carries its policy in a `bounded-policy-commitment-v1`
extension; the kernel checks only that a delegated commitment links its
parent's, and the gateway runs this evaluator's tightening decider on every
linked pair before eligibility.

The model states the fixed-context tightening law (a smaller ceiling or count
never authorizes more), proves the decider sound (it accepts a child only when
the child admits a subset of the parent's contexts), and packages the law the
gateway enforces as a lawful narrowing law. That discharges, in the product
layer, the narrowing premise of the bounded-policy extension.
-/

namespace Auths.Product.CeilingCount

structure Policy where
  argument : String
  ceiling : Nat
  window : Nat
  maxCount : Nat

/-- One fixed evaluation context: the verified unsigned arguments of the
action, and, per window length, how many actions the actor already has
authorized in the current window. -/
structure Context where
  argument : String → Option Nat
  count : Nat → Nat

/-- The stable decision the translated kernel leaf computes. -/
inductive Code where
  | eligible
  | aboveCeiling
  | windowExhausted
  deriving DecidableEq, Repr

/-- Mirrors `ceiling_count_code`: the ceiling is checked first. -/
def codeOf (value ceiling count maxCount : Nat) : Code :=
  if value > ceiling then .aboveCeiling
  else if count ≥ maxCount then .windowExhausted
  else .eligible

/-- Mirrors `ceiling_count_tightens`. -/
def numericTightens
    (childCeiling childMax childWindow parentCeiling parentMax parentWindow : Nat) :
    Bool :=
  if childWindow ≠ parentWindow then false
  else if childCeiling > parentCeiling then false
  else decide (childMax ≤ parentMax)

/-- The contexts a policy admits. -/
def admits (policy : Policy) (context : Context) : Prop :=
  ∃ value, context.argument policy.argument = some value ∧
    codeOf value policy.ceiling (context.count policy.window) policy.maxCount = .eligible

/-- Semantic tightening: the same argument and window, and a ceiling and
count no larger. -/
def tightens (child parent : Policy) : Prop :=
  child.argument = parent.argument ∧ child.window = parent.window ∧
    child.ceiling ≤ parent.ceiling ∧ child.maxCount ≤ parent.maxCount

/-- The registered decider: argument equality and the numeric leaf. -/
def decider (child parent : Policy) : Bool :=
  decide (child.argument = parent.argument) &&
    numericTightens child.ceiling child.maxCount child.window
      parent.ceiling parent.maxCount parent.window

theorem code_eligible_iff (value ceiling count maxCount : Nat) :
    codeOf value ceiling count maxCount = .eligible ↔
      value ≤ ceiling ∧ count < maxCount := by
  unfold codeOf
  split_ifs <;> simp_all <;> omega

theorem decider_iff_tightens (child parent : Policy) :
    decider child parent = true ↔ tightens child parent := by
  unfold decider numericTightens tightens
  split_ifs <;> simp_all <;> omega

/-- Fixed-context tightening: a tighter policy never admits a context its
parent refuses. -/
theorem tightening_never_admits_more {child parent : Policy} {context : Context}
    (tighter : tightens child parent) (admitted : admits child context) :
    admits parent context := by
  obtain ⟨sameArgument, sameWindow, ceilingOrder, countOrder⟩ := tighter
  obtain ⟨value, found, eligible⟩ := admitted
  rw [code_eligible_iff] at eligible
  refine ⟨value, sameArgument ▸ found, ?_⟩
  rw [code_eligible_iff, ← sameWindow]
  omega

/-- The decider is sound: a child it accepts admits only contexts its parent
admits. -/
theorem decider_sound {child parent : Policy}
    (accepted : decider child parent = true) (context : Context)
    (admitted : admits child context) : admits parent context :=
  tightening_never_admits_more ((decider_iff_tightens child parent).mp accepted) admitted

theorem smaller_ceiling_never_authorizes_more (policy : Policy) {ceiling : Nat}
    (smaller : ceiling ≤ policy.ceiling) {context : Context}
    (admitted : admits { policy with ceiling := ceiling } context) :
    admits policy context :=
  tightening_never_admits_more (child := { policy with ceiling := ceiling })
    (parent := policy) ⟨rfl, rfl, smaller, le_refl _⟩ admitted

theorem smaller_count_never_authorizes_more (policy : Policy) {maxCount : Nat}
    (smaller : maxCount ≤ policy.maxCount) {context : Context}
    (admitted : admits { policy with maxCount := maxCount } context) :
    admits policy context :=
  tightening_never_admits_more (child := { policy with maxCount := maxCount })
    (parent := policy) ⟨rfl, rfl, le_refl _, smaller⟩ admitted

theorem tightens_refl (policy : Policy) : tightens policy policy :=
  ⟨rfl, rfl, le_refl _, le_refl _⟩

theorem tightens_trans {child middle parent : Policy}
    (childMiddle : tightens child middle) (middleParent : tightens middle parent) :
    tightens child parent :=
  ⟨childMiddle.1.trans middleParent.1, childMiddle.2.1.trans middleParent.2.1,
    childMiddle.2.2.1.trans middleParent.2.2.1, childMiddle.2.2.2.trans middleParent.2.2.2⟩

/-- The bounded-policy extension law as the gateway enforces it: a child
keeps the extension only with a policy the decider accepts, adding the
extension to an unbounded parent is accepted, and dropping it is refused.
The kernel's own share is the parent link; tightening is the product
layer's. -/
def boundedPolicyLaw : NarrowingLaw Policy Context where
  attenuates child parent :=
    match child, parent with
    | some child, some parent => decider child parent = true
    | some _, none => True
    | none, _ => False
  admits := admits

/-- The bounded-policy law is a preorder that narrows. -/
theorem bounded_policy_law_lawful : boundedPolicyLaw.Lawful where
  refl policy := (decider_iff_tightens policy policy).mpr (tightens_refl policy)
  trans child middle parent childMiddle middleParent := by
    cases parent with
    | none => trivial
    | some parent =>
        exact (decider_iff_tightens child parent).mpr
          (tightens_trans ((decider_iff_tightens child middle).mp childMiddle)
            ((decider_iff_tightens middle parent).mp middleParent))
  narrows child parent accepted context admitted :=
    decider_sound accepted context admitted

/-- Adding a bound to an unbounded grant is accepted. -/
theorem bounded_policy_law_accepts_addition (policy : Policy) :
    boundedPolicyLaw.attenuates (some policy) none :=
  trivial

private def unitDigest : Digest := ⟨List.replicate 32 0, by simp⟩

private def unitOutputs : OutputCommitments where
  reservationIntents := unitDigest
  obligations := unitDigest
  reservationCount := 1
  obligationCount := 0
  reservationBounded := by decide
  obligationBounded := by decide
  canonicalBytes := 0
  bytesBounded := by decide

private def refusal : SemanticId := ⟨[0x62], by simp⟩

instance (policy : Policy) (context : Context) : Decidable (admits policy context) := by
  unfold admits
  cases found : context.argument policy.argument with
  | none => exact isFalse (by simp)
  | some value =>
      exact decidable_of_iff
        (codeOf value policy.ceiling (context.count policy.window) policy.maxCount = .eligible)
        (by simp)

/-- The evaluator in the shared closed-evaluator contract: an admitted
context is eligible with one window-count reservation. -/
def evaluator : ClosedEvaluator where
  Policy := Policy
  Context := Context
  evaluate policy context :=
    if admits policy context then .eligible unitOutputs else .denied refusal refusal
  tightens := tightens
  resultRefines := Eq
  tightensRefl := tightens_refl
  tightensTrans := tightens_trans
  eligibleMonotone := by
    intro child parent context childOutputs tighter eligible
    by_cases admitted : admits child context
    · simp only [admitted, if_true, Eligibility.eligible.injEq] at eligible
      refine ⟨childOutputs, ?_, rfl⟩
      simp [tightening_never_admits_more tighter admitted, eligible]
    · simp [admitted] at eligible

theorem ceiling_count_fixed_context_tightening
    {child parent : Policy} {context : Context} {childOutputs : OutputCommitments}
    (tighter : tightens child parent)
    (eligible : evaluator.evaluate child context = .eligible childOutputs) :
    ∃ parentOutputs,
      evaluator.evaluate parent context = .eligible parentOutputs ∧
        childOutputs = parentOutputs :=
  fixed_context_tightening evaluator tighter eligible

end Auths.Product.CeilingCount
