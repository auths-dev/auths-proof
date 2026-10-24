import Auths.Support.NativeBorrowDefaults

/-!
Materialize full pure field data only when an indexed witness accounts for
every field. A skipped atom has no constructor. Empty enum tails are empty
views; unit fields can be reconstructed without supplying an atom. This
creates no reference address, native loan permission or ordinary result.
All new scripts await final elaboration.
-/
namespace Auths.Support.BorrowViewMaterialize
open SourceClosureRegions BorrowProjection BorrowTransport NativeBorrowDefaults
universe u

inductive Rebuilder : {shape : Shape} → Plan shape → Type where
  | keep {shape} : Rebuilder (Plan.keep : Plan shape)
  | empty : Rebuilder .empty
  | unit : Rebuilder (Plan.skip : Plan .unit)
  | product {left right} {first : Plan left} {second : Plan right}
      (one : Rebuilder first) (two : Rebuilder second) : Rebuilder (.product first second)
  | sum {left right} {first : Plan left} {second : Plan right}
      (one : Rebuilder first) (two : Rebuilder second) : Rebuilder (.sum first second)
  | named {identity body} {plan : Plan body} (contents : Rebuilder plan) :
      Rebuilder (Plan.named (identity := identity) plan)
  | borrow {mutable region body} {plan : Plan body} (contents : Rebuilder plan) :
      Rebuilder (Plan.borrow (mutable := mutable) (region := region) plan)

def rebuild {Atom : Expr → Type u} : {shape : Shape} → {plan : Plan shape} →
    Rebuilder plan → View Atom plan → Data Atom shape
  | _, _, .keep, value => value
  | _, _, .empty, value => nomatch value
  | _, _, .unit, _ => .unit
  | _, _, .product first second, value => .product (rebuild first value.1) (rebuild second value.2)
  | _, _, .sum first _, .inl value => .left (rebuild first value)
  | _, _, .sum _ second, .inr value => .right (rebuild second value)
  | _, _, .named contents, value => .named (rebuild contents value)
  | _, _, .borrow contents, value => .borrow (rebuild contents value)

theorem rebuilt_view_is_exact {Atom : Expr → Type u} {shape : Shape} {plan : Plan shape}
    (builder : Rebuilder plan) (value : View Atom plan) : get plan (rebuild builder value) = value := by
  induction builder generalizing value with
  | keep => rfl
  | empty => cases value
  | unit => cases value; rfl
  | product first second firstIH secondIH =>
      rcases value with ⟨one, two⟩
      exact Prod.ext (firstIH one) (secondIH two)
  | sum first second firstIH secondIH =>
      cases value with
      | inl one => exact congrArg Sum.inl (firstIH one)
      | inr two => exact congrArg Sum.inr (secondIH two)
  | named contents ih => exact ih value
  | borrow contents ih => exact ih value

theorem extraction_rebuilds_original {Atom : Expr → Type u} {shape : Shape} {plan : Plan shape}
    (builder : Rebuilder plan) (value : Data Atom shape) : rebuild builder (get plan value) = value := by
  induction builder generalizing value with
  | keep => rfl
  | empty => cases value
  | unit => cases value; rfl
  | product first second firstIH secondIH =>
      cases value with
      | product one two => simp [get, rebuild, firstIH, secondIH]
  | sum first second firstIH secondIH =>
      cases value with
      | left one => simp [get, rebuild, firstIH]
      | right two => simp [get, rebuild, secondIH]
  | named contents ih => cases value with | named one => simp [get, rebuild, ih]
  | borrow contents ih => cases value with | borrow one => simp [get, rebuild, ih]

def readNativeCurrent {Atom : Expr → Type u} (current : Current Atom) (key : Key)
    {candidate native : Shape} {available : Plan candidate}
    (builder : Rebuilder available) (change : Change candidate native) : Option (Data Atom native) :=
  (readCurrent current key candidate available).map fun value => forward change (rebuild builder value)

theorem absent_current_is_not_materialized {Atom : Expr → Type u} (current : Current Atom) (key : Key)
    {candidate native : Shape} {available : Plan candidate}
    (builder : Rebuilder available) (change : Change candidate native) (missing : current key = none) :
    readNativeCurrent current key builder change = none := by
  simp [readNativeCurrent, readCurrent, missing]

theorem current_view_materializes_exact_native_fields {Atom : Expr → Type u}
    (current : Current Atom) (key : Key) {candidate native : Shape} {available : Plan candidate}
    (builder : Rebuilder available) (change : Change candidate native) (value : View Atom available)
    (present : current key = some ⟨candidate, available, value⟩) :
    readNativeCurrent current key builder change = some (forward change (rebuild builder value)) := by
  simp [readNativeCurrent, readCurrent, present, castEntry]

end Auths.Support.BorrowViewMaterialize
