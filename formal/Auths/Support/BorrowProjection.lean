import Auths.Support.SourceClosureRegions

/-!
Typed pure-data views for the nominal records/sums expanded by the native
borrow-projection constructor. A partial view retains the active sum branch;
restoration cannot switch that branch or overwrite an unselected field.

Atoms are the original uninterpreted *values*, indexed by their full source
type tree. No operation, callback result, reference permission or heap behavior
is assumed for them. Borrow nodes describe the regionful shape of pure values;
they are not Rust addresses/loans. The LLBC/symbolic-to-view, native lifetime,
alias/layout/drop and backward-continuation refinements remain required.
All new proof scripts await the final elaboration and axiom audit.
-/
namespace Auths.Support.BorrowProjection

open SourceClosureRegions
universe u

inductive Label where
  | nominal (originalType : Expr)
  | variant (identity : Nat)
  | field (index : Nat) (name : Option (List Nat))
  | boxed
  deriving DecidableEq, Repr

inductive Shape where
  | atom (originalType : Expr)
  | empty
  | unit
  | product (left right : Shape)
  | sum (left right : Shape)
  | named (identity : Label) (body : Shape)
  | borrow (mutable : Bool) (region : Region) (body : Shape)
  deriving DecidableEq, Repr

inductive Data (Atom : Expr → Type u) : Shape → Type u where
  | atom {sort} (value : Atom sort) : Data Atom (.atom sort)
  | unit : Data Atom .unit
  | product {left right} (first : Data Atom left) (second : Data Atom right) :
      Data Atom (.product left right)
  | left {left right} (value : Data Atom left) : Data Atom (.sum left right)
  | right {left right} (value : Data Atom right) : Data Atom (.sum left right)
  | named {identity body} (value : Data Atom body) : Data Atom (.named identity body)
  | borrow {mutable region body} (value : Data Atom body) : Data Atom (.borrow mutable region body)

abbrev Datum (Atom : Expr → Type u) := Σ shape : Shape, Data Atom shape

/-- Inspect a record's complete field spine. The check preserves source field
indices and refuses any gap, reordering or unexplained tail. Values remain
heterogeneous, indexed by their actual complete source shapes. -/
def recordFields {Atom : Expr → Type u} (index : Nat) :
    {shape : Shape} → Data Atom shape → Option (List (Datum Atom))
  | .unit, .unit => some []
  | .product (.named (.field actual _) body) _, .product (.named value) rest =>
      if actual = index then
        (recordFields (index + 1) rest).map (⟨body, value⟩ :: ·)
      else none
  | _, _ => none

def capturedFields {Atom : Expr → Type u} :
    {shape : Shape} → Data Atom shape → Option (List (Datum Atom))
  | .named (.nominal _) _, .named value => recordFields 0 value
  | _, _ => none

inductive Plan : Shape → Type where
  | keep {shape} : Plan shape
  | skip {shape} : Plan shape
  | empty : Plan .empty
  | product {left right} (first : Plan left) (second : Plan right) : Plan (.product left right)
  | sum {left right} (first : Plan left) (second : Plan right) : Plan (.sum left right)
  | named {identity body} (contents : Plan body) : Plan (.named identity body)
  | borrow {mutable region body} (contents : Plan body) : Plan (.borrow mutable region body)
  deriving DecidableEq

/-- A view's nominal identity and field sorts remain in its dependent index.
Partial sums retain a branch even when that branch has no selected payload. -/
def View (Atom : Expr → Type u) : {shape : Shape} → Plan shape → Type u
  | _, .keep => Data Atom _
  | _, .skip => PUnit
  | _, .empty => PEmpty
  | _, .product first second => View Atom first × View Atom second
  | _, .sum first second => Sum (View Atom first) (View Atom second)
  | _, .named contents => View Atom contents
  | _, .borrow contents => View Atom contents

def get {Atom : Expr → Type u} : {shape : Shape} →
    (plan : Plan shape) → Data Atom shape → View Atom plan
  | _, .keep, value => value
  | _, .skip, _ => PUnit.unit
  | _, .empty, value => nomatch value
  | _, .product first second, .product left right => (get first left, get second right)
  | _, .sum first _, .left value => .inl (get first value)
  | _, .sum _ second, .right value => .inr (get second value)
  | _, .named contents, .named value => get contents value
  | _, .borrow contents, .borrow value => get contents value

/-- Restore a partial view into its original carrier. The original enum branch
is required for a partial sum; a `keep` of an entire owned sum can replace it.
Skipped fields always come from the original carrier. -/
def put {Atom : Expr → Type u} : {shape : Shape} →
    (plan : Plan shape) → Data Atom shape → View Atom plan → Option (Data Atom shape)
  | _, .keep, _, update => some update
  | _, .skip, original, _ => some original
  | _, .empty, original, _ => nomatch original
  | _, .product first second, .product left right, (updateLeft, updateRight) => do
      let left ← put first left updateLeft
      let right ← put second right updateRight
      pure (.product left right)
  | _, .sum first _, .left original, .inl update => (put first original update).map Data.left
  | _, .sum _ second, .right original, .inr update => (put second original update).map Data.right
  | _, .sum _ _, .left _, .inr _ => none
  | _, .sum _ _, .right _, .inl _ => none
  | _, .named contents, .named original, update => (put contents original update).map Data.named
  | _, .borrow contents, .borrow original, update => (put contents original update).map Data.borrow

/-- Region selection is structural. A selected mutable borrow owns its whole
pure pointee view; shared nodes have no mutable view in this algebra. Unselected
outer mutable references are traversed to find selected nested references.
This is not a claim about Rust interior mutability or evidence that a native
loan may be ended. -/
def select (regions : List Region) : (shape : Shape) → Plan shape
  | .atom _ => .skip
  | .empty => .empty
  | .unit => .skip
  | .product left right => .product (select regions left) (select regions right)
  | .sum left right => .sum (select regions left) (select regions right)
  | .named _ body => .named (select regions body)
  | .borrow false _ _ => .skip
  | .borrow true region body =>
      if region ∈ regions then .borrow .keep else .borrow (select regions body)

theorem get_then_put {Atom : Expr → Type u} {shape : Shape} (plan : Plan shape)
    (original : Data Atom shape) : put plan original (get plan original) = some original := by
  induction plan generalizing original with
  | keep => rfl
  | skip => rfl
  | empty => cases original
  | product first second firstIH secondIH =>
      cases original with
      | product left right => simp [get, put, firstIH, secondIH]
  | sum first second firstIH secondIH =>
      cases original with
      | left value => simp [get, put, firstIH]
      | right value => simp [get, put, secondIH]
  | named contents ih =>
      cases original with
      | named value => simp [get, put, ih]
  | borrow contents ih =>
      cases original with
      | borrow value => simp [get, put, ih]

theorem put_then_get {Atom : Expr → Type u} {shape : Shape} (plan : Plan shape)
    (original after : Data Atom shape) (update : View Atom plan)
    (accepted : put plan original update = some after) : get plan after = update := by
  induction plan generalizing original after update with
  | keep =>
      have same : update = after := Option.some.inj accepted
      subst after
      rfl
  | skip => cases update; rfl
  | empty => cases original
  | product first second firstIH secondIH =>
      cases original with
      | product left right =>
          rcases update with ⟨updateLeft, updateRight⟩
          cases leftResult : put first left updateLeft with
          | none => simp [put, leftResult] at accepted
          | some newLeft =>
              cases rightResult : put second right updateRight with
              | none => simp [put, leftResult, rightResult] at accepted
              | some newRight =>
                  have same : Data.product newLeft newRight = after := by
                    simpa [put, leftResult, rightResult] using accepted
                  subst after
                  exact Prod.ext (firstIH left newLeft updateLeft leftResult)
                    (secondIH right newRight updateRight rightResult)
  | sum first second firstIH secondIH =>
      cases original with
      | left value =>
          cases update with
          | inl patch =>
              cases result : put first value patch with
              | none => simp [put, result] at accepted
              | some next =>
                  have same : Data.left next = after := by simpa [put, result] using accepted
                  subst after
                  exact congrArg Sum.inl (firstIH value next patch result)
          | inr patch => simp [put] at accepted
      | right value =>
          cases update with
          | inl patch => simp [put] at accepted
          | inr patch =>
              cases result : put second value patch with
              | none => simp [put, result] at accepted
              | some next =>
                  have same : Data.right next = after := by simpa [put, result] using accepted
                  subst after
                  exact congrArg Sum.inr (secondIH value next patch result)
  | named contents ih =>
      cases original with
      | named value =>
          cases result : put contents value update with
          | none => simp [put, result] at accepted
          | some next =>
              have same : Data.named next = after := by simpa [put, result] using accepted
              subst after
              exact ih value next update result
  | borrow contents ih =>
      cases original with
      | borrow value =>
          cases result : put contents value update with
          | none => simp [put, result] at accepted
          | some next =>
              have same : Data.borrow next = after := by simpa [put, result] using accepted
              subst after
              exact ih value next update result

theorem skipped_field_is_preserved {Atom : Expr → Type u} {shape : Shape}
    (original : Data Atom shape) (update : View Atom (.skip : Plan shape)) :
    put .skip original update = some original := rfl

theorem partial_sum_cannot_switch_left_to_right {Atom : Expr → Type u}
    {left right : Shape} (first : Plan left) (second : Plan right)
    (original : Data Atom left) (update : View Atom second) :
    put (.sum first second) (.left original) (.inr update) = none := rfl

theorem partial_sum_cannot_switch_right_to_left {Atom : Expr → Type u}
    {left right : Shape} (first : Plan left) (second : Plan right)
    (original : Data Atom right) (update : View Atom first) :
    put (.sum first second) (.right original) (.inl update) = none := rfl

theorem selected_views_round_trip {Atom : Expr → Type u} (regions : List Region)
    (shape : Shape) (original : Data Atom shape) :
    put (select regions shape) original (get (select regions shape) original) = some original :=
  get_then_put _ _

theorem shared_reference_has_no_mutable_view (regions : List Region) (region : Region) (body : Shape) :
    select regions (.borrow false region body) = .skip := rfl

theorem nonexistent_enum_tail_has_no_view (Atom : Expr → Type u) (regions : List Region) :
    IsEmpty (View Atom (select regions .empty)) := inferInstance

theorem unselected_product_sibling_is_preserved {Atom : Expr → Type u}
    {left right : Shape} (rightPlan : Plan right) (beforeLeft : Data Atom left)
    (beforeRight : Data Atom right) (patch : View Atom rightPlan)
    (after : Data Atom (.product left right))
    (accepted : put (.product .skip rightPlan) (.product beforeLeft beforeRight)
      (PUnit.unit, patch) = some after) :
    ∃ afterRight, after = .product beforeLeft afterRight := by
  cases result : put rightPlan beforeRight patch with
  | none => simp [put, result] at accepted
  | some afterRight =>
      refine ⟨afterRight, ?_⟩
      have same : Data.product beforeLeft afterRight = after := by
        simpa [put, result] using accepted
      exact same.symm

end Auths.Support.BorrowProjection
