import Auths.Product.Tightening
import Auths.ExtensionLaw

/-!
# The gateway's argument-ceiling window-count evaluator

One registered bounded-policy evaluator: a ceiling on one named verified
argument, a maximum number of admitted actions per counter in each fixed,
epoch-aligned window, and, optionally, a sum limit on the bounded argument
per listed partition value and a scope that lists the values one verified
argument may take. A grant carries its policy in a
`bounded-policy-commitment-v1` extension; the kernel checks only that a
delegated commitment links its parent's, and the gateway runs this
evaluator's tightening decider on every linked pair before eligibility.

Every bounded grant of the authorized branch contributes one link: its
subject and its policy. A link's count counter is keyed by its subject, not
by the acting principal, so every admitted action of the subject and of each
delegate below it charges the same counter, and a link's sum counter is
keyed by its subject and the action's partition value. The model fixes one
window: every arrival is evaluated inside one window index, which the
counter keys therefore omit.

The model states the fixed-context tightening law (a tighter policy never
admits more), proves the decider sound, packages the law the gateway
enforces as a lawful narrowing law, and proves that reserving a chain's
counters is all or none and that, for every arrival order in one window, a
link's count bounds the admitted actions of its subject and delegates, its
ceiling times its count bounds their argument sum, and its sum limit bounds
that sum per listed partition value directly.
-/

namespace Auths.Product.CeilingCount

/-- An argument name, a subject identifier, or a listed value: its bytes. -/
abbrev Name := List Nat

/-- The values a policy lists for one named verified argument. -/
structure Values where
  argument : Name
  values : List Name
  deriving DecidableEq

/-- A sum limit on the bounded argument, optionally per partition value. -/
structure SumBound where
  limit : Nat
  partition : Option Values
  deriving DecidableEq

structure Policy where
  argument : Name
  ceiling : Nat
  window : Nat
  maxCount : Nat
  sum : Option SumBound
  scope : Option Values
  deriving DecidableEq

/-- A counter of one fixed window: a link subject's count per window length,
or its running sum per window length and partition value. -/
inductive CounterKey where
  | count (subject : Name) (window : Nat)
  | sum (subject : Name) (window : Nat) (partition : Name)
  deriving DecidableEq

/-- One fixed evaluation context: the link subject whose counters the policy
is evaluated at, the verified unsigned and text arguments of the action, and
each counter's value in the current window. -/
structure Context where
  subject : Name
  argument : Name → Option Nat
  text : Name → Option Name
  count : CounterKey → Nat

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

/-! ## Admission -/

/-- The verified text argument a list names is one of its values. -/
def listed (text : Name → Option Name) (list : Values) : Bool :=
  match text list.argument with
  | some value => decide (value ∈ list.values)
  | none => false

/-- The partition value that selects a sum counter: the verified value of the
partition argument, or empty for an unpartitioned sum. A listed value is
never empty. -/
def partitionValue (text : Name → Option Name) : Option Values → Name
  | none => []
  | some list => (text list.argument).getD []

def scopeAdmits (text : Name → Option Name) : Option Values → Bool
  | none => true
  | some list => listed text list

def partitionAdmits (text : Name → Option Name) : Option Values → Bool
  | none => true
  | some list => listed text list

/-- The sum condition: the partition value is listed, and the running sum
plus the argument stays within the limit. -/
def sumAdmits (context : Context) (window value : Nat) : Option SumBound → Bool
  | none => true
  | some bound =>
      partitionAdmits context.text bound.partition &&
        decide (context.count (.sum context.subject window
          (partitionValue context.text bound.partition)) + value ≤ bound.limit)

/-- Every condition of one policy at one argument value. -/
def admitsValue (policy : Policy) (context : Context) (value : Nat) : Bool :=
  decide (codeOf value policy.ceiling (context.count (.count context.subject policy.window))
      policy.maxCount = .eligible) &&
    scopeAdmits context.text policy.scope &&
    sumAdmits context policy.window value policy.sum

/-- The contexts a policy admits. -/
def admits (policy : Policy) (context : Context) : Prop :=
  ∃ value, context.argument policy.argument = some value ∧
    admitsValue policy context value = true

/-! ## Tightening -/

/-- The same argument, and a subset of the parent's values. -/
def valuesNarrow (child parent : Values) : Prop :=
  child.argument = parent.argument ∧ ∀ value ∈ child.values, value ∈ parent.values

def partitionNarrows : Option Values → Option Values → Prop
  | none, none => True
  | some child, some parent => valuesNarrow child parent
  | _, _ => False

def sumNarrows : Option SumBound → Option SumBound → Prop
  | _, none => True
  | none, some _ => False
  | some child, some parent =>
      child.limit ≤ parent.limit ∧ partitionNarrows child.partition parent.partition

def scopeNarrows : Option Values → Option Values → Prop
  | _, none => True
  | none, some _ => False
  | some child, some parent => valuesNarrow child parent

/-- Semantic tightening: the same argument and window, a ceiling and count no
larger, a sum no larger with the parent's partition argument and a subset of
its values whenever the parent has a sum, and a scope on the same argument
with a subset of its values whenever the parent has one. -/
def tightens (child parent : Policy) : Prop :=
  child.argument = parent.argument ∧ child.window = parent.window ∧
    child.ceiling ≤ parent.ceiling ∧ child.maxCount ≤ parent.maxCount ∧
    sumNarrows child.sum parent.sum ∧ scopeNarrows child.scope parent.scope

/-- Mirrors `values_narrow`. -/
def valuesNarrowB (child parent : Values) : Bool :=
  decide (child.argument = parent.argument) &&
    child.values.all fun value => decide (value ∈ parent.values)

/-- Mirrors `partition_narrows`. -/
def partitionTightens : Option Values → Option Values → Bool
  | none, none => true
  | some child, some parent => valuesNarrowB child parent
  | _, _ => false

/-- Mirrors `sum_tightens`. -/
def sumTightens : Option SumBound → Option SumBound → Bool
  | _, none => true
  | none, some _ => false
  | some child, some parent =>
      decide (child.limit ≤ parent.limit) && partitionTightens child.partition parent.partition

/-- Mirrors `scope_tightens`. -/
def scopeTightens : Option Values → Option Values → Bool
  | _, none => true
  | none, some _ => false
  | some child, some parent => valuesNarrowB child parent

/-- The registered decider, mirrored by `argument_policy_tightens`: argument
equality, the unchanged numeric leaf, and the sum, partition, and scope
rules. -/
def decider (child parent : Policy) : Bool :=
  decide (child.argument = parent.argument) &&
    numericTightens child.ceiling child.maxCount child.window
      parent.ceiling parent.maxCount parent.window &&
    sumTightens child.sum parent.sum && scopeTightens child.scope parent.scope

theorem code_eligible_iff (value ceiling count maxCount : Nat) :
    codeOf value ceiling count maxCount = .eligible ↔
      value ≤ ceiling ∧ count < maxCount := by
  unfold codeOf
  split_ifs <;> simp_all <;> omega

theorem valuesNarrowB_iff (child parent : Values) :
    valuesNarrowB child parent = true ↔ valuesNarrow child parent := by
  simp [valuesNarrowB, valuesNarrow]

theorem partitionTightens_iff (child parent : Option Values) :
    partitionTightens child parent = true ↔ partitionNarrows child parent := by
  cases child <;> cases parent <;>
    simp [partitionTightens, partitionNarrows, valuesNarrowB_iff]

theorem sumTightens_iff (child parent : Option SumBound) :
    sumTightens child parent = true ↔ sumNarrows child parent := by
  cases child <;> cases parent <;>
    simp [sumTightens, sumNarrows, partitionTightens_iff]

theorem scopeTightens_iff (child parent : Option Values) :
    scopeTightens child parent = true ↔ scopeNarrows child parent := by
  cases child <;> cases parent <;>
    simp [scopeTightens, scopeNarrows, valuesNarrowB_iff]

theorem numericTightens_iff
    (childCeiling childMax childWindow parentCeiling parentMax parentWindow : Nat) :
    numericTightens childCeiling childMax childWindow parentCeiling parentMax parentWindow =
        true ↔
      childWindow = parentWindow ∧ childCeiling ≤ parentCeiling ∧ childMax ≤ parentMax := by
  unfold numericTightens
  split_ifs <;> simp_all

theorem decider_iff_tightens (child parent : Policy) :
    decider child parent = true ↔ tightens child parent := by
  simp only [decider, tightens, Bool.and_eq_true, decide_eq_true_eq, numericTightens_iff,
    sumTightens_iff, scopeTightens_iff]
  tauto

theorem listed_narrows {text : Name → Option Name} {child parent : Values}
    (narrow : valuesNarrow child parent) (holds : listed text child = true) :
    listed text parent = true := by
  obtain ⟨sameArgument, subset⟩ := narrow
  unfold listed at holds ⊢
  rw [← sameArgument]
  cases found : text child.argument with
  | none => simp [found] at holds
  | some value =>
      simp only [found, decide_eq_true_eq] at holds ⊢
      exact subset value holds

theorem partitionValue_narrows {text : Name → Option Name} {child parent : Option Values}
    (narrow : partitionNarrows child parent) :
    partitionValue text child = partitionValue text parent := by
  cases child <;> cases parent <;> simp_all [partitionNarrows, partitionValue, valuesNarrow]

theorem partitionAdmits_narrows {text : Name → Option Name} {child parent : Option Values}
    (narrow : partitionNarrows child parent) (holds : partitionAdmits text child = true) :
    partitionAdmits text parent = true := by
  cases child <;> cases parent <;> simp_all [partitionNarrows, partitionAdmits]
  exact listed_narrows narrow holds

theorem scopeAdmits_narrows {text : Name → Option Name} {child parent : Option Values}
    (narrow : scopeNarrows child parent) (holds : scopeAdmits text child = true) :
    scopeAdmits text parent = true := by
  cases child <;> cases parent <;> simp_all [scopeNarrows, scopeAdmits]
  exact listed_narrows narrow holds

theorem sumAdmits_narrows {context : Context} {window value : Nat}
    {child parent : Option SumBound}
    (narrow : sumNarrows child parent) (holds : sumAdmits context window value child = true) :
    sumAdmits context window value parent = true := by
  cases parent with
  | none => rfl
  | some parentBound =>
      cases child with
      | none => exact absurd narrow id
      | some childBound =>
          obtain ⟨limitOrder, partitionOrder⟩ := narrow
          simp only [sumAdmits, Bool.and_eq_true, decide_eq_true_eq] at holds ⊢
          refine ⟨partitionAdmits_narrows partitionOrder holds.1, ?_⟩
          rw [← partitionValue_narrows partitionOrder]
          omega

/-- Fixed-context tightening: a tighter policy never admits a context its
parent refuses. -/
theorem tightening_never_admits_more {child parent : Policy} {context : Context}
    (tighter : tightens child parent) (admitted : admits child context) :
    admits parent context := by
  obtain ⟨sameArgument, sameWindow, ceilingOrder, countOrder, sumOrder, scopeOrder⟩ := tighter
  obtain ⟨value, found, eligible⟩ := admitted
  simp only [admitsValue, Bool.and_eq_true, decide_eq_true_eq] at eligible
  obtain ⟨⟨code, scope⟩, sum⟩ := eligible
  rw [code_eligible_iff] at code
  refine ⟨value, sameArgument ▸ found, ?_⟩
  simp only [admitsValue, Bool.and_eq_true, decide_eq_true_eq]
  refine ⟨⟨?_, scopeAdmits_narrows scopeOrder scope⟩, ?_⟩
  · rw [code_eligible_iff, ← sameWindow]
    omega
  · rw [← sameWindow]
    exact sumAdmits_narrows sumOrder sum

/-- The decider is sound: a child it accepts admits only contexts its parent
admits. -/
theorem decider_sound {child parent : Policy}
    (accepted : decider child parent = true) (context : Context)
    (admitted : admits child context) : admits parent context :=
  tightening_never_admits_more ((decider_iff_tightens child parent).mp accepted) admitted

theorem partitionNarrows_refl (partition : Option Values) :
    partitionNarrows partition partition := by
  cases partition <;> simp [partitionNarrows, valuesNarrow]

theorem tightens_refl (policy : Policy) : tightens policy policy := by
  refine ⟨rfl, rfl, le_refl _, le_refl _, ?_, ?_⟩
  · cases h : policy.sum <;> simp [sumNarrows, partitionNarrows_refl]
  · cases h : policy.scope <;> simp [scopeNarrows, valuesNarrow]

theorem valuesNarrow_trans {child middle parent : Values}
    (childMiddle : valuesNarrow child middle) (middleParent : valuesNarrow middle parent) :
    valuesNarrow child parent :=
  ⟨childMiddle.1.trans middleParent.1,
    fun value member => middleParent.2 value (childMiddle.2 value member)⟩

theorem partitionNarrows_trans {child middle parent : Option Values}
    (childMiddle : partitionNarrows child middle) (middleParent : partitionNarrows middle parent) :
    partitionNarrows child parent := by
  cases child <;> cases middle <;> cases parent <;>
    simp_all [partitionNarrows]
  exact valuesNarrow_trans childMiddle middleParent

theorem sumNarrows_trans {child middle parent : Option SumBound}
    (childMiddle : sumNarrows child middle) (middleParent : sumNarrows middle parent) :
    sumNarrows child parent := by
  cases parent with
  | none => trivial
  | some parentBound =>
      cases middle with
      | none => exact absurd middleParent id
      | some middleBound =>
          cases child with
          | none => exact absurd childMiddle id
          | some childBound =>
              exact ⟨childMiddle.1.trans middleParent.1,
                partitionNarrows_trans childMiddle.2 middleParent.2⟩

theorem scopeNarrows_trans {child middle parent : Option Values}
    (childMiddle : scopeNarrows child middle) (middleParent : scopeNarrows middle parent) :
    scopeNarrows child parent := by
  cases parent with
  | none => trivial
  | some parentScope =>
      cases middle with
      | none => exact absurd middleParent id
      | some middleScope =>
          cases child with
          | none => exact absurd childMiddle id
          | some childScope => exact valuesNarrow_trans childMiddle middleParent

theorem tightens_trans {child middle parent : Policy}
    (childMiddle : tightens child middle) (middleParent : tightens middle parent) :
    tightens child parent :=
  ⟨childMiddle.1.trans middleParent.1, childMiddle.2.1.trans middleParent.2.1,
    childMiddle.2.2.1.trans middleParent.2.2.1, childMiddle.2.2.2.1.trans middleParent.2.2.2.1,
    sumNarrows_trans childMiddle.2.2.2.2.1 middleParent.2.2.2.2.1,
    scopeNarrows_trans childMiddle.2.2.2.2.2 middleParent.2.2.2.2.2⟩

theorem smaller_ceiling_never_authorizes_more (policy : Policy) {ceiling : Nat}
    (smaller : ceiling ≤ policy.ceiling) {context : Context}
    (admitted : admits { policy with ceiling := ceiling } context) :
    admits policy context := by
  obtain ⟨_, _, _, _, sum, scope⟩ := tightens_refl policy
  exact tightening_never_admits_more (child := { policy with ceiling := ceiling })
    (parent := policy) ⟨rfl, rfl, smaller, le_refl _, sum, scope⟩ admitted

theorem smaller_count_never_authorizes_more (policy : Policy) {maxCount : Nat}
    (smaller : maxCount ≤ policy.maxCount) {context : Context}
    (admitted : admits { policy with maxCount := maxCount } context) :
    admits policy context := by
  obtain ⟨_, _, _, _, sum, scope⟩ := tightens_refl policy
  exact tightening_never_admits_more (child := { policy with maxCount := maxCount })
    (parent := policy) ⟨rfl, rfl, le_refl _, smaller, sum, scope⟩ admitted

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
      exact decidable_of_iff (admitsValue policy context value = true) (by simp)

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

/-! ## Chains and reservation -/

/-- One bounded grant of the authorized branch: its subject and its policy. -/
abbrev Link := Name × Policy

/-- The verified arguments of one action. -/
structure Facts where
  argument : Name → Option Nat
  text : Name → Option Name

/-- The context of a link subject under the current counters. -/
def Facts.at (facts : Facts) (counts : CounterKey → Nat) (subject : Name) : Context where
  subject := subject
  argument := facts.argument
  text := facts.text
  count := counts

/-- Today's admission at the link's counter, plus the scope, partition, and
sum conditions, at the verified argument value. -/
def linkAdmits (facts : Facts) (value : Nat) (counts : CounterKey → Nat) (link : Link) : Bool :=
  decide (facts.argument link.2.argument = some value) &&
    admitsValue link.2 (facts.at counts link.1) value

/-- Every link admits. A counter several links share must have room under
each of them, so it takes the smallest of their capacities. -/
def chainAdmits (facts : Facts) (value : Nat) (links : List Link)
    (counts : CounterKey → Nat) : Bool :=
  links.all (linkAdmits facts value counts)

def countKey (link : Link) : CounterKey := .count link.1 link.2.window

/-- A link's sum counter for the action's partition value, with its limit. -/
def sumEntry (text : Name → Option Name) (link : Link) : Option (CounterKey × Nat) :=
  link.2.sum.map fun bound =>
    (.sum link.1 link.2.window (partitionValue text bound.partition), bound.limit)

def countKeys (links : List Link) : List CounterKey := links.map countKey

def sumEntries (text : Name → Option Name) (links : List Link) : List (CounterKey × Nat) :=
  links.filterMap (sumEntry text)

def sumKeys (text : Name → Option Name) (links : List Link) : List CounterKey :=
  (sumEntries text links).map Prod.fst

/-- Every distinct count counter of the chain rises by one, and every
distinct sum counter by the argument. -/
def raise (text : Name → Option Name) (links : List Link) (value : Nat)
    (counts : CounterKey → Nat) : CounterKey → Nat := fun key =>
  counts key + (if key ∈ countKeys links then 1 else 0) +
    (if key ∈ sumKeys text links then value else 0)

/-- Reserves a chain's counters for one action with argument `value`, all or
none. `reserve facts` has the type `List Link → Nat → (CounterKey → Nat) →
Option (CounterKey → Nat)`. -/
def reserve (facts : Facts) (links : List Link) (value : Nat)
    (counts : CounterKey → Nat) : Option (CounterKey → Nat) :=
  if chainAdmits facts value links counts then some (raise facts.text links value counts)
  else none

theorem count_key_not_sum_key {text : Name → Option Name} {links : List Link}
    {key : CounterKey} (member : key ∈ countKeys links) : key ∉ sumKeys text links := by
  intro sumMember
  simp only [countKeys, List.mem_map] at member
  simp only [sumKeys, sumEntries, sumEntry, List.mem_map, List.mem_filterMap,
    Option.map_eq_some_iff] at sumMember
  obtain ⟨link, _, rfl⟩ := member
  obtain ⟨⟨key', limit⟩, ⟨_, _, bound, _, equal⟩, keyEq⟩ := sumMember
  simp only [Prod.mk.injEq] at equal
  subst keyEq
  simp [countKey] at equal

theorem raise_ge (text : Name → Option Name) (links : List Link) (value : Nat)
    (counts : CounterKey → Nat) (key : CounterKey) :
    counts key ≤ raise text links value counts key := by
  unfold raise
  omega

theorem raise_count {text : Name → Option Name} {links : List Link} {value : Nat}
    {counts : CounterKey → Nat} {key : CounterKey} (member : key ∈ countKeys links) :
    raise text links value counts key = counts key + 1 := by
  simp [raise, member, count_key_not_sum_key member]

theorem raise_sum {text : Name → Option Name} {links : List Link} {value : Nat}
    {counts : CounterKey → Nat} {key : CounterKey} (member : key ∈ sumKeys text links) :
    raise text links value counts key = counts key + value := by
  have notCount : key ∉ countKeys links := fun count => count_key_not_sum_key count member
  simp [raise, member, notCount]

theorem raise_other {text : Name → Option Name} {links : List Link} {value : Nat}
    {counts : CounterKey → Nat} {key : CounterKey}
    (notCount : key ∉ countKeys links) (notSum : key ∉ sumKeys text links) :
    raise text links value counts key = counts key := by
  simp [raise, notCount, notSum]

/-- Reservation is all or none: either nothing changes, or each distinct
count counter of the chain rises by exactly one, each distinct sum counter
by exactly the argument, and every other counter is unchanged. -/
theorem reserve_all_or_none (facts : Facts) (links : List Link) (value : Nat)
    (counts : CounterKey → Nat) :
    reserve facts links value counts = none ∨
      ∃ raised, reserve facts links value counts = some raised ∧
        (∀ key ∈ countKeys links, raised key = counts key + 1) ∧
        (∀ key ∈ sumKeys facts.text links, raised key = counts key + value) ∧
        (∀ key, key ∉ countKeys links → key ∉ sumKeys facts.text links →
          raised key = counts key) := by
  unfold reserve
  split
  · exact Or.inr ⟨_, rfl, fun _ member => raise_count member,
      fun _ member => raise_sum member, fun _ notCount notSum => raise_other notCount notSum⟩
  · exact Or.inl rfl

theorem reserve_some_iff (facts : Facts) (links : List Link) (value : Nat)
    (counts : CounterKey → Nat) :
    (reserve facts links value counts).isSome = chainAdmits facts value links counts := by
  unfold reserve
  split <;> simp_all

/-- An admitted chain's scope and partition values are in every list its
links carry. -/
theorem scope_admits_only_listed {facts : Facts} {value : Nat} {links : List Link}
    {counts : CounterKey → Nat} (admitted : chainAdmits facts value links counts = true)
    {link : Link} (member : link ∈ links) :
    (∀ scope, link.2.scope = some scope →
        ∃ listedValue, facts.text scope.argument = some listedValue ∧
          listedValue ∈ scope.values) ∧
      (∀ bound partition, link.2.sum = some bound → bound.partition = some partition →
        ∃ listedValue, facts.text partition.argument = some listedValue ∧
          listedValue ∈ partition.values) := by
  have holds := List.all_eq_true.mp admitted link member
  simp only [linkAdmits, admitsValue, Bool.and_eq_true] at holds
  obtain ⟨_, ⟨_, scope⟩, sum⟩ := holds
  have fromListed : ∀ list : Values, listed facts.text list = true →
      ∃ listedValue, facts.text list.argument = some listedValue ∧
        listedValue ∈ list.values := by
    intro list holds
    unfold listed at holds
    cases found : facts.text list.argument with
    | none => simp [found] at holds
    | some listedValue =>
        simp only [found, decide_eq_true_eq] at holds
        exact ⟨listedValue, rfl, holds⟩
  constructor
  · intro list carries
    rw [carries] at scope
    exact fromListed list scope
  · intro bound list carries partitioned
    rw [carries] at sum
    simp only [sumAdmits, partitionValue, Bool.and_eq_true] at sum
    rw [partitioned] at sum
    exact fromListed list sum.1

/-! ## The leaves' share of chain admission -/

/-- The model of `chain_counts_admit`: every counter below its capacity, with
slices of equal length. -/
def countsAdmit (counts capacities : List Nat) : Bool :=
  counts.length == capacities.length &&
    (counts.zip capacities).all fun entry => decide (entry.1 < entry.2)

/-- The model of `chain_sums_admit`: every running sum plus the argument
within its capacity, with slices of equal length. -/
def sumsAdmit (sums : List Nat) (value : Nat) (capacities : List Nat) : Bool :=
  sums.length == capacities.length &&
    (sums.zip capacities).all fun entry => decide (entry.1 + value ≤ entry.2)

/-- The smallest element; zero for an empty list. -/
def smallest : List Nat → Nat
  | [] => 0
  | first :: rest => rest.foldl min first

theorem le_foldl_min_iff (bound first : Nat) (rest : List Nat) :
    bound ≤ rest.foldl min first ↔ bound ≤ first ∧ ∀ element ∈ rest, bound ≤ element := by
  induction rest generalizing first with
  | nil => simp
  | cons next rest induction =>
      simp only [List.foldl_cons, induction, le_min_iff, List.mem_cons, forall_eq_or_imp]
      tauto

theorem le_smallest_iff {bound : Nat} {elements : List Nat} (nonempty : elements ≠ []) :
    bound ≤ smallest elements ↔ ∀ element ∈ elements, bound ≤ element := by
  cases elements with
  | nil => exact absurd rfl nonempty
  | cons first rest => simp [smallest, le_foldl_min_iff]

/-- The capacity of a count counter: the smallest maximum count of the links
that share it. -/
def countCapacity (links : List Link) (key : CounterKey) : Nat :=
  smallest ((links.filter fun link => countKey link = key).map fun link => link.2.maxCount)

/-- The capacity of a sum counter: the smallest limit of the links that share
it. -/
def sumCapacity (text : Name → Option Name) (links : List Link) (key : CounterKey) : Nat :=
  smallest (((sumEntries text links).filter fun entry => entry.1 = key).map Prod.snd)

theorem countsAdmit_map {α : Type} (keys : List α) (first second : α → Nat) :
    countsAdmit (keys.map first) (keys.map second) =
      keys.all fun key => decide (first key < second key) := by
  unfold countsAdmit
  simp only [List.length_map, beq_self_eq_true, Bool.true_and]
  induction keys with
  | nil => rfl
  | cons key rest induction => simp [induction]

theorem sumsAdmit_map {α : Type} (keys : List α) (first second : α → Nat) (value : Nat) :
    sumsAdmit (keys.map first) value (keys.map second) =
      keys.all fun key => decide (first key + value ≤ second key) := by
  unfold sumsAdmit
  simp only [List.length_map, beq_self_eq_true, Bool.true_and]
  induction keys with
  | nil => rfl
  | cons key rest induction => simp [induction]

/-- The count leaf decides exactly the count part of `chainAdmits`, over the
chain's distinct count counters with each counter's smallest capacity. -/
theorem chain_counts_part (links : List Link) (counts : CounterKey → Nat) :
    countsAdmit ((countKeys links).dedup.map counts)
        ((countKeys links).dedup.map (countCapacity links)) = true ↔
      ∀ link ∈ links, counts (countKey link) < link.2.maxCount := by
  simp only [countsAdmit_map, List.all_eq_true, decide_eq_true_eq, List.mem_dedup]
  constructor
  · intro holds link member
    have key := holds (countKey link) (List.mem_map_of_mem member)
    have nonempty : ((links.filter fun other => countKey other = countKey link).map
        fun other => other.2.maxCount) ≠ [] := by
      simp only [ne_eq, List.map_eq_nil_iff, List.filter_eq_nil_iff, not_forall,
        decide_eq_true_eq]
      exact ⟨link, member, fun absurd => absurd rfl⟩
    have := (le_smallest_iff (bound := counts (countKey link) + 1) nonempty).mp key
    exact this link.2.maxCount (List.mem_map.mpr ⟨link, List.mem_filter.mpr ⟨member, by simp⟩, rfl⟩)
  · intro holds key member
    simp only [countKeys, List.mem_map] at member
    obtain ⟨link, linkMember, rfl⟩ := member
    have nonempty : ((links.filter fun other => countKey other = countKey link).map
        fun other => other.2.maxCount) ≠ [] := by
      simp only [ne_eq, List.map_eq_nil_iff, List.filter_eq_nil_iff, not_forall,
        decide_eq_true_eq]
      exact ⟨link, linkMember, fun absurd => absurd rfl⟩
    show counts (countKey link) + 1 ≤ countCapacity links (countKey link)
    unfold countCapacity
    rw [le_smallest_iff nonempty]
    intro capacity capacityMember
    simp only [List.mem_map, List.mem_filter, decide_eq_true_eq] at capacityMember
    obtain ⟨other, ⟨otherMember, sameKey⟩, rfl⟩ := capacityMember
    have := holds other otherMember
    rw [sameKey] at this
    omega

/-- The sum leaf decides exactly the sum part of `chainAdmits`, over the
chain's distinct sum counters with each counter's smallest limit. -/
theorem chain_sums_part (text : Name → Option Name) (links : List Link) (value : Nat)
    (counts : CounterKey → Nat) :
    sumsAdmit ((sumKeys text links).dedup.map counts) value
        ((sumKeys text links).dedup.map (sumCapacity text links)) = true ↔
      ∀ entry ∈ sumEntries text links, counts entry.1 + value ≤ entry.2 := by
  simp only [sumsAdmit_map, List.all_eq_true, decide_eq_true_eq, List.mem_dedup]
  constructor
  · intro holds entry member
    have key := holds entry.1 (List.mem_map_of_mem member)
    have nonempty : (((sumEntries text links).filter fun other => other.1 = entry.1).map
        Prod.snd) ≠ [] := by
      simp only [ne_eq, List.map_eq_nil_iff, List.filter_eq_nil_iff, not_forall,
        decide_eq_true_eq]
      exact ⟨entry, member, fun absurd => absurd rfl⟩
    exact (le_smallest_iff nonempty).mp key entry.2
      (List.mem_map.mpr ⟨entry, List.mem_filter.mpr ⟨member, by simp⟩, rfl⟩)
  · intro holds key member
    simp only [sumKeys, List.mem_map] at member
    obtain ⟨entry, entryMember, rfl⟩ := member
    have nonempty : (((sumEntries text links).filter fun other => other.1 = entry.1).map
        Prod.snd) ≠ [] := by
      simp only [ne_eq, List.map_eq_nil_iff, List.filter_eq_nil_iff, not_forall,
        decide_eq_true_eq]
      exact ⟨entry, entryMember, fun absurd => absurd rfl⟩
    unfold sumCapacity
    rw [le_smallest_iff nonempty]
    intro capacity capacityMember
    simp only [List.mem_map, List.mem_filter, decide_eq_true_eq] at capacityMember
    obtain ⟨other, ⟨otherMember, sameKey⟩, rfl⟩ := capacityMember
    have := holds other otherMember
    rw [sameKey] at this
    exact this

/-- `chainAdmits` is exactly the per-link argument, ceiling, scope, and
partition checks, the count part the count leaf decides, and the sum part
the sum leaf decides. -/
theorem chain_admits_parts (facts : Facts) (value : Nat) (links : List Link)
    (counts : CounterKey → Nat) :
    chainAdmits facts value links counts = true ↔
      (∀ link ∈ links, facts.argument link.2.argument = some value ∧
        value ≤ link.2.ceiling ∧ scopeAdmits facts.text link.2.scope = true ∧
        (∀ bound ∈ link.2.sum, partitionAdmits facts.text bound.partition = true)) ∧
      (∀ link ∈ links, counts (countKey link) < link.2.maxCount) ∧
      (∀ entry ∈ sumEntries facts.text links, counts entry.1 + value ≤ entry.2) := by
  simp only [chainAdmits, List.all_eq_true, linkAdmits, admitsValue, Bool.and_eq_true,
    decide_eq_true_eq, code_eligible_iff, Facts.at, countKey, sumEntries, List.mem_filterMap,
    sumEntry, Option.map_eq_some_iff]
  constructor
  · intro holds
    refine ⟨fun link member => ?_, fun link member => (holds link member).2.1.1.2, ?_⟩
    · obtain ⟨found, ⟨⟨ceiling, _⟩, scope⟩, sum⟩ := holds link member
      refine ⟨found, ceiling, scope, fun bound carries => ?_⟩
      rw [Option.mem_def] at carries
      rw [carries] at sum
      simp only [sumAdmits, Bool.and_eq_true] at sum
      exact sum.1
    · rintro entry ⟨link, member, bound, carries, rfl⟩
      have sum := (holds link member).2.2
      rw [carries] at sum
      simp only [sumAdmits, Bool.and_eq_true, decide_eq_true_eq] at sum
      exact sum.2
  · rintro ⟨perLink, countPart, sumPart⟩ link member
    obtain ⟨found, ceiling, scope, partition⟩ := perLink link member
    refine ⟨found, ⟨⟨ceiling, countPart link member⟩, scope⟩, ?_⟩
    cases carries : link.2.sum with
    | none => rfl
    | some bound =>
        simp only [sumAdmits, Bool.and_eq_true, decide_eq_true_eq]
        exact ⟨partition bound carries, sumPart _ ⟨link, member, bound, carries, rfl⟩⟩

/-! ## Arrivals in one window -/

/-- One submission: its verified arguments, its chain, and the verified value
of the bounded argument. -/
structure Arrival where
  facts : Facts
  links : List Link
  value : Nat

/-- Admits one arrival when its reservation succeeds. -/
def admitStep (state : (CounterKey → Nat) × List Arrival) (arrival : Arrival) :
    (CounterKey → Nat) × List Arrival :=
  match reserve arrival.facts arrival.links arrival.value state.1 with
  | some raised => (raised, state.2 ++ [arrival])
  | none => state

/-- Runs arrivals in order from the given counters: the final counters and
the admitted arrivals, in order. -/
def admitAll (counts : CounterKey → Nat) (arrivals : List Arrival) :
    (CounterKey → Nat) × List Arrival :=
  arrivals.foldl admitStep (counts, [])

/-- The arrivals whose chain contains `link`. -/
def containing (link : Link) (arrivals : List Arrival) : List Arrival :=
  arrivals.filter fun arrival => decide (link ∈ arrival.links)

/-- The arrivals whose chain contains `link` and whose partition value for
`bound` is `partition`. -/
def containingIn (link : Link) (bound : SumBound) (partition : Name)
    (arrivals : List Arrival) : List Arrival :=
  arrivals.filter fun arrival =>
    decide (link ∈ arrival.links) &&
      decide (partitionValue arrival.facts.text bound.partition = partition)

theorem admitStep_admits {state : (CounterKey → Nat) × List Arrival} {arrival : Arrival} :
    (admitStep state arrival = state) ∨
      (chainAdmits arrival.facts arrival.value arrival.links state.1 = true ∧
        admitStep state arrival =
          (raise arrival.facts.text arrival.links arrival.value state.1,
            state.2 ++ [arrival])) := by
  unfold admitStep reserve
  split <;> rename_i result equal
  · split at equal
    · simp_all
    · simp at equal
  · left; rfl

theorem foldl_invariant (invariant : (CounterKey → Nat) × List Arrival → Prop)
    (preserved : ∀ state arrival, invariant state → invariant (admitStep state arrival))
    (arrivals : List Arrival) (state : (CounterKey → Nat) × List Arrival)
    (initial : invariant state) : invariant (arrivals.foldl admitStep state) := by
  induction arrivals generalizing state with
  | nil => exact initial
  | cons arrival rest induction => exact induction _ (preserved state arrival initial)

theorem link_admits_of_chain {facts : Facts} {value : Nat} {links : List Link}
    {counts : CounterKey → Nat} (admitted : chainAdmits facts value links counts = true)
    {link : Link} (member : link ∈ links) :
    value ≤ link.2.ceiling ∧ counts (countKey link) < link.2.maxCount := by
  have holds := List.all_eq_true.mp admitted link member
  simp only [linkAdmits, admitsValue, Bool.and_eq_true, decide_eq_true_eq,
    code_eligible_iff] at holds
  exact holds.2.1.1

/-- The count invariant: the admitted arrivals containing a link number at
most its counter's value and at most its count, and their argument sum is at
most their number times its ceiling. -/
def countInvariant (link : Link) (state : (CounterKey → Nat) × List Arrival) : Prop :=
  (containing link state.2).length ≤ state.1 (countKey link) ∧
    (containing link state.2).length ≤ link.2.maxCount ∧
    ((containing link state.2).map Arrival.value).sum ≤
      (containing link state.2).length * link.2.ceiling

theorem countInvariant_preserved (link : Link) (state : (CounterKey → Nat) × List Arrival)
    (arrival : Arrival) (holds : countInvariant link state) :
    countInvariant link (admitStep state arrival) := by
  rcases admitStep_admits (state := state) (arrival := arrival) with same | ⟨admitted, step⟩
  · rw [same]; exact holds
  · rw [step]
    obtain ⟨belowCounter, belowCount, spend⟩ := holds
    unfold countInvariant containing
    simp only [List.filter_append, List.length_append, List.map_append, List.sum_append]
    by_cases member : link ∈ arrival.links
    · have linkHolds := link_admits_of_chain admitted member
      have raised : raise arrival.facts.text arrival.links arrival.value state.1 (countKey link) =
          state.1 (countKey link) + 1 := raise_count (List.mem_map_of_mem member)
      simp only [containing] at belowCounter belowCount spend
      simp only [member, decide_true, List.filter_cons_of_pos, List.filter_nil,
        List.length_singleton, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
        raised]
      refine ⟨by omega, by omega, ?_⟩
      rw [Nat.add_mul, Nat.one_mul]
      omega
    · have raised := raise_ge arrival.facts.text arrival.links arrival.value state.1 (countKey link)
      simp only [containing] at belowCounter belowCount spend
      simp only [member, decide_false, Bool.false_eq_true, not_false_eq_true,
        List.filter_cons_of_neg, List.filter_nil, List.length_nil, List.map_nil, List.sum_nil]
      refine ⟨by omega, by omega, by simpa using spend⟩

/-- For every arrival order in one window, the admitted chains containing a
link number at most its count: a link's count bounds its subject and every
delegate together. -/
theorem aggregate_count_bound (counts : CounterKey → Nat) (arrivals : List Arrival)
    (link : Link) :
    (containing link (admitAll counts arrivals).2).length ≤ link.2.maxCount :=
  (foldl_invariant (countInvariant link) (countInvariant_preserved link) arrivals (counts, [])
    ⟨by simp [containing], by simp [containing], by simp [containing]⟩).2.1

/-- For every arrival order in one window, the argument sum of the admitted
chains containing a link is at most the link's ceiling times its count. -/
theorem aggregate_spend_bound (counts : CounterKey → Nat) (arrivals : List Arrival)
    (link : Link) :
    ((containing link (admitAll counts arrivals).2).map Arrival.value).sum ≤
      link.2.ceiling * link.2.maxCount := by
  obtain ⟨_, belowCount, spend⟩ :=
    foldl_invariant (countInvariant link) (countInvariant_preserved link) arrivals (counts, [])
      ⟨by simp [containing], by simp [containing], by simp [containing]⟩
  calc ((containing link (admitAll counts arrivals).2).map Arrival.value).sum
      ≤ (containing link (admitAll counts arrivals).2).length * link.2.ceiling := spend
    _ ≤ link.2.maxCount * link.2.ceiling := Nat.mul_le_mul_right _ belowCount
    _ = link.2.ceiling * link.2.maxCount := Nat.mul_comm _ _

/-- The sum counter of `link` for partition value `partition`. -/
def sumCounter (link : Link) (partition : Name) : CounterKey :=
  .sum link.1 link.2.window partition

/-- The sum invariant: the argument sum of the admitted arrivals containing a
link, for one partition value, is at most that counter's value and at most
the link's sum limit. -/
def sumInvariant (link : Link) (bound : SumBound) (partition : Name)
    (state : (CounterKey → Nat) × List Arrival) : Prop :=
  ((containingIn link bound partition state.2).map Arrival.value).sum ≤
      state.1 (sumCounter link partition) ∧
    ((containingIn link bound partition state.2).map Arrival.value).sum ≤ bound.limit

theorem sumInvariant_preserved (link : Link) {bound : SumBound}
    (carries : link.2.sum = some bound) (partition : Name)
    (state : (CounterKey → Nat) × List Arrival) (arrival : Arrival)
    (holds : sumInvariant link bound partition state) :
    sumInvariant link bound partition (admitStep state arrival) := by
  rcases admitStep_admits (state := state) (arrival := arrival) with same | ⟨admitted, step⟩
  · rw [same]; exact holds
  · rw [step]
    obtain ⟨belowCounter, belowLimit⟩ := holds
    unfold sumInvariant containingIn
    simp only [List.filter_append, List.map_append, List.sum_append]
    simp only [containingIn] at belowCounter belowLimit
    by_cases selected : link ∈ arrival.links ∧
        partitionValue arrival.facts.text bound.partition = partition
    · obtain ⟨member, samePartition⟩ := selected
      have linkHolds := List.all_eq_true.mp admitted link member
      simp only [linkAdmits, admitsValue, Bool.and_eq_true, Facts.at] at linkHolds
      have sum := linkHolds.2.2
      rw [carries] at sum
      simp only [sumAdmits, Bool.and_eq_true, decide_eq_true_eq, samePartition] at sum
      have entry : (sumCounter link partition, bound.limit) ∈
          sumEntries arrival.facts.text arrival.links := by
        simp only [sumEntries, List.mem_filterMap, sumEntry, Option.map_eq_some_iff]
        exact ⟨link, member, bound, carries, by rw [samePartition]; rfl⟩
      have raised : raise arrival.facts.text arrival.links arrival.value state.1
          (sumCounter link partition) = state.1 (sumCounter link partition) + arrival.value :=
        raise_sum (List.mem_map_of_mem entry)
      simp only [member, samePartition, decide_true, Bool.and_self, List.filter_cons_of_pos,
        List.filter_nil, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, raised]
      refine ⟨by omega, ?_⟩
      have : state.1 (sumCounter link partition) + arrival.value ≤ bound.limit := sum.2
      omega
    · have raised := raise_ge arrival.facts.text arrival.links arrival.value state.1
        (sumCounter link partition)
      have excluded : (decide (link ∈ arrival.links) &&
          decide (partitionValue arrival.facts.text bound.partition = partition)) = false := by
        simpa [Bool.and_eq_true] using selected
      simp only [List.filter_cons, excluded, Bool.false_eq_true, if_false, List.filter_nil,
        List.map_nil, List.sum_nil, Nat.add_zero]
      exact ⟨by omega, belowLimit⟩

/-- For every arrival order in one window, the argument sum of the admitted
chains containing a link with a sum limit, for one partition value, is at
most that limit: a link's sum limit bounds its subject and every delegate
together, per partition value. -/
theorem aggregate_sum_bound (counts : CounterKey → Nat) (arrivals : List Arrival)
    (link : Link) {bound : SumBound} (carries : link.2.sum = some bound) (partition : Name) :
    ((containingIn link bound partition (admitAll counts arrivals).2).map Arrival.value).sum ≤
      bound.limit :=
  (foldl_invariant (sumInvariant link bound partition)
    (sumInvariant_preserved link carries partition) arrivals (counts, [])
    ⟨by simp [containingIn], by simp [containingIn]⟩).2

theorem admitted_sublist (counts : CounterKey → Nat) (arrivals : List Arrival) :
    ∀ arrival ∈ (admitAll counts arrivals).2, arrival ∈ arrivals := by
  have general : ∀ (rest : List Arrival) (state : (CounterKey → Nat) × List Arrival),
      (∀ arrival ∈ (rest.foldl admitStep state).2, arrival ∈ state.2 ∨ arrival ∈ rest) := by
    intro rest
    induction rest with
    | nil => intro state arrival member; exact Or.inl member
    | cons next rest induction =>
        intro state arrival member
        rcases induction (admitStep state next) arrival member with earlier | later
        · rcases admitStep_admits (state := state) (arrival := next) with same | ⟨_, step⟩
          · rw [same] at earlier; exact Or.inl earlier
          · rw [step] at earlier
            simp only [List.mem_append, List.mem_singleton] at earlier
            rcases earlier with old | rfl
            · exact Or.inl old
            · exact Or.inr List.mem_cons_self
        · exact Or.inr (List.mem_cons_of_mem _ later)
  intro arrival member
  rcases general arrivals (counts, []) arrival member with none | found
  · simp at none
  · exact found

/-- Delegation never multiplies a count: when every arrival's chain carries
the root link, the admitted arrivals of the whole tree number at most the
root's count, and their argument sum is at most its ceiling times its
count. -/
theorem delegation_never_multiplies (counts : CounterKey → Nat) (arrivals : List Arrival)
    (root : Link) (tree : ∀ arrival ∈ arrivals, root ∈ arrival.links) :
    (admitAll counts arrivals).2.length ≤ root.2.maxCount ∧
      ((admitAll counts arrivals).2.map Arrival.value).sum ≤
        root.2.ceiling * root.2.maxCount := by
  have whole : containing root (admitAll counts arrivals).2 = (admitAll counts arrivals).2 := by
    unfold containing
    rw [List.filter_eq_self]
    intro arrival member
    simpa using tree arrival (admitted_sublist counts arrivals arrival member)
  have count := aggregate_count_bound counts arrivals root
  have spend := aggregate_spend_bound counts arrivals root
  rw [whole] at count spend
  exact ⟨count, spend⟩

/-- Delegation never multiplies a sum: when every arrival's chain carries the
root link, the argument sum of the whole tree's admitted arrivals, for one
partition value, is at most the root's sum limit. -/
theorem sum_delegation_never_multiplies (counts : CounterKey → Nat) (arrivals : List Arrival)
    (root : Link) (tree : ∀ arrival ∈ arrivals, root ∈ arrival.links) {bound : SumBound}
    (carries : root.2.sum = some bound) (partition : Name) :
    (((admitAll counts arrivals).2.filter fun arrival =>
        decide (partitionValue arrival.facts.text bound.partition = partition)).map
          Arrival.value).sum ≤ bound.limit := by
  have whole : containingIn root bound partition (admitAll counts arrivals).2 =
      (admitAll counts arrivals).2.filter fun arrival =>
        decide (partitionValue arrival.facts.text bound.partition = partition) := by
    unfold containingIn
    apply List.filter_congr
    intro arrival member
    simp [tree arrival (admitted_sublist counts arrivals arrival member)]
  have sum := aggregate_sum_bound counts arrivals root carries partition
  rw [whole] at sum
  exact sum

end Auths.Product.CeilingCount
