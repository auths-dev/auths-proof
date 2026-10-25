import Auths.Support.BorrowProjection

/-! A view may be restricted only through an explicit structural witness.
No missing field, inactive enum tag or ordinary value is supplied. -/
namespace Auths.Support.BorrowViewRestriction
open BorrowProjection
universe u

inductive Restriction : {shape : Shape} → Plan shape → Plan shape → Type where
  | whole {shape} (target : Plan shape) : Restriction .keep target
  | discard {shape} (source : Plan shape) : Restriction source .skip
  | empty : Restriction .empty .empty
  | product {left right} {sl tl : Plan left} {sr tr : Plan right}
      (first : Restriction sl tl) (second : Restriction sr tr) :
      Restriction (.product sl sr) (.product tl tr)
  | sum {left right} {sl tl : Plan left} {sr tr : Plan right}
      (first : Restriction sl tl) (second : Restriction sr tr) :
      Restriction (.sum sl sr) (.sum tl tr)
  | named {identity body} {source target : Plan body} (contents : Restriction source target) :
      Restriction (Plan.named (identity := identity) source) (.named target)
  | borrow {mutable region body} {source target : Plan body} (contents : Restriction source target) :
      Restriction (Plan.borrow (mutable := mutable) (region := region) source) (.borrow target)

def restrict {Atom : SourceClosureRegions.Expr → Type u} :
    {shape : Shape} → {source target : Plan shape} →
    Restriction source target → View Atom source → View Atom target
  | _, _, _, .whole plan, value => get plan value
  | _, _, _, .discard _, _ => PUnit.unit
  | _, _, _, .empty, value => nomatch value
  | _, _, _, .product first second, value => (restrict first value.1, restrict second value.2)
  | _, _, _, .sum first _, .inl value => .inl (restrict first value)
  | _, _, _, .sum _ second, .inr value => .inr (restrict second value)
  | _, _, _, .named contents, value => restrict contents value
  | _, _, _, .borrow contents, value => restrict contents value

theorem restriction_matches_extraction {Atom : SourceClosureRegions.Expr → Type u}
    {shape : Shape} {source target : Plan shape} (restriction : Restriction source target)
    (value : Data Atom shape) : restrict restriction (get source value) = get target value := by
  induction restriction generalizing value with
  | whole => rfl
  | discard => rfl
  | empty => cases value
  | product first second firstIH secondIH =>
      cases value with
      | product left right => exact Prod.ext (firstIH left) (secondIH right)
  | sum first second firstIH secondIH =>
      cases value with
      | left inner => exact congrArg Sum.inl (firstIH inner)
      | right inner => exact congrArg Sum.inr (secondIH inner)
  | named contents ih => cases value with | named inner => exact ih inner
  | borrow contents ih => cases value with | borrow inner => exact ih inner

/-- Structural composition carries no data and cannot supply a missing field.
It describes nested access; it does not follow a runtime default chain. -/
def compose : {shape : Shape} → {source middle target : Plan shape} →
    Restriction source middle → Restriction middle target → Restriction source target
  | _, _, _, target, .whole _, _ => .whole target
  | _, source, _, _, _, .discard _ => .discard source
  | _, _, _, _, .empty, .empty => .empty
  | _, _, _, _, .product first second, .product nextFirst nextSecond =>
      .product (compose first nextFirst) (compose second nextSecond)
  | _, _, _, _, .sum first second, .sum nextFirst nextSecond =>
      .sum (compose first nextFirst) (compose second nextSecond)
  | _, _, _, _, .named contents, .named next => .named (compose contents next)
  | _, _, _, _, .borrow contents, .borrow next => .borrow (compose contents next)

theorem restrict_composition {Atom : SourceClosureRegions.Expr → Type u}
    {shape : Shape} {source middle target : Plan shape}
    (first : Restriction source middle) (second : Restriction middle target)
    (value : View Atom source) :
    restrict (compose first second) value = restrict second (restrict first value) := by
  induction first generalizing target value with
  | whole plan =>
      simpa [compose, restrict] using (restriction_matches_extraction second value).symm
  | discard plan => cases second <;> rfl
  | empty => cases value
  | product left right leftIH rightIH =>
      cases second with
      | discard => rfl
      | product nextLeft nextRight =>
          exact Prod.ext (leftIH nextLeft value.1) (rightIH nextRight value.2)
  | sum left right leftIH rightIH =>
      cases second with
      | discard => rfl
      | sum nextLeft nextRight =>
          cases value with
          | inl inner => exact congrArg Sum.inl (leftIH nextLeft inner)
          | inr inner => exact congrArg Sum.inr (rightIH nextRight inner)
  | named contents ih =>
      cases second with
      | discard => rfl
      | named next => exact ih next value
  | borrow contents ih =>
      cases second with
      | discard => rfl
      | borrow next => exact ih next value

theorem nested_restriction_matches_current_extraction {Atom : SourceClosureRegions.Expr → Type u}
    {shape : Shape} {source middle target : Plan shape}
    (first : Restriction source middle) (second : Restriction middle target)
    (current : Data Atom shape) :
    restrict second (restrict first (get source current)) = get target current := by
  rw [← restrict_composition first second]
  exact restriction_matches_extraction (compose first second) current

end Auths.Support.BorrowViewRestriction
