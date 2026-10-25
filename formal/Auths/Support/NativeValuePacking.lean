import Auths.Support.NativePureExpressions

/-!
Source-derived witnesses for the complete native field layouts supported by the
closed expression interpreter. Packing is computed from the actual value and
all constructor/variant/ordered-field nodes. No callback, chosen alternative,
ordinary result or successful packing result is supplied. The witness gives an
explicit fuel bound; exhausted or unsupported layouts remain refused by the
original interpreter. Scripts await final elaboration.
-/
namespace Auths.Support.NativeValuePacking
open NativePurePayload NativePureExpressions
universe u

mutual
  inductive Root : Layout → Ty → Type where
    | atom (type : Ty) : Root (.atom type) type
    | nominal (type : Ty) {layout} (body : Body layout) : Root (.named (.nominal type) layout) type
  inductive Fields : Nat → Layout → Type where
    | unit (index : Nat) : Fields index .unit
    | cons (index : Nat) (name : Option (List Nat)) {layout type rest}
        (first : Root layout type) (tail : Fields (index + 1) rest) :
        Fields index (.product (.named (.field index name) layout) rest)
  inductive Body : Layout → Type where
    | empty : Body .empty
    | fields {layout} (fields : Fields 0 layout) : Body layout
    | sum {left right} (first : Variant left) (rest : Body right) : Body (.sum left right)
  inductive Variant : Layout → Type where
    | variant (identity : Nat) {layout} (fields : Fields 0 layout) :
        Variant (.named (.variant identity) layout)
end

mutual
  def rootFuel : Root layout type → Nat
    | .atom _ => 1
    | .nominal _ body => (bodyFuel body).succ
  def fieldsFuel : Fields index layout → Nat
    | .unit _ => 1
    | .cons _ _ first rest => (max (rootFuel first) (fieldsFuel rest)).succ
  def bodyFuel : Body layout → Nat
    | .empty => 1
    | .fields fields => (fieldsFuel fields).succ
    | .sum first rest => (max (variantFuel first) (bodyFuel rest)).succ
  def variantFuel : Variant layout → Nat
    | .variant _ fields => (fieldsFuel fields).succ
end

mutual
  def rootValue {Atom : Ty → Type u} : (witness : Root layout type) → Value Atom layout → Dynamic Atom
    | .atom type, .atom value => .atom type value
    | .nominal type body, .named value =>
        let packed := bodyValue body value
        .constructor type packed.1 packed.2
  def fieldValues {Atom : Ty → Type u} : (witness : Fields index layout) → Value Atom layout → List (Dynamic Atom)
    | .unit _, .unit => []
    | .cons _ _ first rest, .product (.named value) tail => rootValue first value :: fieldValues rest tail
  def bodyValue {Atom : Ty → Type u} : (witness : Body layout) → Value Atom layout → Option Nat × List (Dynamic Atom)
    | .empty, value => nomatch value
    | .fields fields, value => (none, fieldValues fields value)
    | .sum first _, .left value => variantValue first value
    | .sum _ rest, .right value => bodyValue rest value
  def variantValue {Atom : Ty → Type u} : (witness : Variant layout) → Value Atom layout → Option Nat × List (Dynamic Atom)
    | .variant identity fields, .named value => (some identity, fieldValues fields value)
end

theorem root_value_has_exact_type {Atom : Ty → Type u} (witness : Root layout type) (value : Value Atom layout) :
    (rootValue witness value).type = type := by
  match witness, value with
  | .atom _, .atom _ => rfl
  | .nominal _ _, .named _ => rfl

mutual
  theorem pack_root {Atom : Ty → Type u} (fuel : Nat) (witness : Root layout type)
      (value : Value Atom layout) (enough : rootFuel witness ≤ fuel) :
      pack fuel value = some (rootValue witness value) := by
    cases fuel with
    | zero => cases witness <;> simp [rootFuel] at enough
    | succ fuel =>
        match witness, value, enough with
        | .atom _, .atom _, _ => rfl
        | .nominal _ body, .named value, enough =>
            have next : bodyFuel body ≤ fuel := Nat.le_of_succ_le_succ enough
            simp only [pack, rootValue]
            rw [pack_body fuel body value next]
            rfl

  theorem pack_fields {Atom : Ty → Type u} (fuel : Nat) (witness : Fields index layout)
      (value : Value Atom layout) (enough : fieldsFuel witness ≤ fuel) :
      packFields fuel index value = some (fieldValues witness value) := by
    cases fuel with
    | zero => cases witness <;> simp [fieldsFuel] at enough
    | succ fuel =>
        match witness, value, enough with
        | .unit _, .unit, _ => rfl
        | .cons _ _ first rest, .product (.named firstValue) tail, enough =>
            have bound : max (rootFuel first) (fieldsFuel rest) ≤ fuel := Nat.le_of_succ_le_succ enough
            have one : rootFuel first ≤ fuel := Nat.le_trans (Nat.le_max_left _ _) bound
            have two : fieldsFuel rest ≤ fuel := Nat.le_trans (Nat.le_max_right _ _) bound
            simp [packFields, fieldValues, pack_root fuel first firstValue one, pack_fields fuel rest tail two]

  theorem pack_body {Atom : Ty → Type u} (fuel : Nat) (witness : Body layout)
      (value : Value Atom layout) (enough : bodyFuel witness ≤ fuel) :
      packBody fuel value = some (bodyValue witness value) := by
    cases fuel with
    | zero => cases witness <;> simp [bodyFuel] at enough
    | succ fuel =>
        match witness, value, enough with
        | .empty, value, _ => nomatch value
        | .fields fields, value, enough =>
            have next : fieldsFuel fields ≤ fuel := Nat.le_of_succ_le_succ enough
            have found := pack_fields fuel fields value next
            cases fields <;>
              simpa only [packBody, bodyValue] using
                congrArg (Option.map fun values => (none, values)) found
        | .sum first _, .left value, enough =>
            have bound : max (variantFuel first) _ ≤ fuel := Nat.le_of_succ_le_succ enough
            exact pack_variant fuel first value (Nat.le_trans (Nat.le_max_left _ _) bound)
        | .sum _ rest, .right value, enough =>
            have bound : max _ (bodyFuel rest) ≤ fuel := Nat.le_of_succ_le_succ enough
            exact pack_body fuel rest value (Nat.le_trans (Nat.le_max_right _ _) bound)

  theorem pack_variant {Atom : Ty → Type u} (fuel : Nat) (witness : Variant layout)
      (value : Value Atom layout) (enough : variantFuel witness ≤ fuel) :
      packVariant fuel value = some (variantValue witness value) := by
    cases fuel with
    | zero => cases witness <;> simp [variantFuel] at enough
    | succ fuel =>
        match witness, value, enough with
        | .variant identity fields, .named value, enough =>
            have next : fieldsFuel fields ≤ fuel := Nat.le_of_succ_le_succ enough
            simpa only [packVariant, variantValue] using
              congrArg (Option.map fun values => (some identity, values)) (pack_fields fuel fields value next)
end

/-- Construct the represented success from the actual typed output. -/
def success {Atom : Ty → Type u} (builtins : Builtins) (witness : Root layout type)
    (value : Value Atom layout) : Dynamic Atom :=
  .constructor (.result type) (some builtins.resultOk) [rootValue witness value]

theorem expected_some_is_success {Atom : Ty → Type u} (builtins : Builtins) (fuel : Nat)
    (witness : Root layout type) (value : Value Atom layout) (enough : rootFuel witness ≤ fuel) :
    expected builtins fuel type (some value) = some (success builtins witness value) := by
  simp [expected, success, pack_root fuel witness value enough]

/-- All aggregate fields come from supplied typed outputs; there is no chosen
provider or Rust result. One output keeps the original scalar convention. -/
def successMany {Atom : Ty → Type u} (builtins : Builtins) (values : List (Dynamic Atom)) : Dynamic Atom :=
  let value := match values with
    | [value] => value
    | values => .constructor (.tuple (values.map Dynamic.type)) none values
  .constructor (.result value.type) (some builtins.resultOk) [value]

end Auths.Support.NativeValuePacking
