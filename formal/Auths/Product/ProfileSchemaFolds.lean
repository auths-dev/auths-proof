import Auths.Product.ProfileSchemaCorrectness

namespace Auths.Product.ProfileSchema
open RequestConstruction ScalarProjection FieldProjection
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def enumFold (prefix : List Bytes) : List Value → Option Schema
  | [] => if EnumSchema prefix then some (.enumeration prefix) else none
  | .text bytes :: rest => if EnumVariant bytes then enumFold (prefix ++ [bytes]) rest else none
  | _ :: _ => none

def enumResult (values : List Value) : Option Schema := do
  let variants ← texts values
  if EnumSchema variants then some (.enumeration variants) else none

private theorem invalid_enum_member (prefix suffix : List Bytes) (bytes : Bytes) (invalid : ¬EnumVariant bytes) :
    ¬EnumSchema (prefix ++ bytes :: suffix) := by
  intro valid
  exact invalid (valid.2.2.2 bytes (by simp))

theorem enum_fold_exact (prefix : List Bytes) (values : List Value) :
    enumFold prefix values = do
      let suffix ← texts values
      if EnumSchema (prefix ++ suffix) then some (.enumeration (prefix ++ suffix)) else none := by
  induction values generalizing prefix with
  | nil => simp [enumFold, texts]
  | cons value rest ih =>
    cases value with
    | text bytes =>
      by_cases allowed : EnumVariant bytes
      · simp [enumFold, texts, allowed, ih, List.append_assoc, Option.bind_assoc]
      · cases tail : texts rest with
        | none => simp [enumFold, texts, allowed, tail]
        | some suffix =>
          have rejected := invalid_enum_member prefix suffix bytes allowed
          simp [enumFold, texts, allowed, tail, rejected]
    | _ => simp [enumFold, texts]

theorem enum_fold_start (values : List Value) : enumFold [] values = enumResult values := by
  simpa [enumResult] using enum_fold_exact [] values

theorem enum_result_count_refusal (values : List Value) (excluded : values = [] ∨ 32 < values.length) :
    enumResult values = none := by
  cases source : texts values with
  | none => simp [enumResult, source]
  | some variants =>
    have paired := (texts_exact values variants).mp source
    have sizes := paired.length_eq
    have invalid : ¬EnumSchema variants := by
      intro valid
      rcases excluded with empty | large
      · simp [empty] at sizes
        have := valid.1
        omega
      · have := valid.2.1
        omega
    simp [enumResult, source, invalid]

def fieldsFold (prefix : List Field) : List (Bytes × Value) → Option (List Field)
  | [] => if LayoutValid prefix then some prefix else none
  | (name, value) :: rest =>
    if OperationIdentity.validToken name 64 then do
      let schema ← parseScalar value
      fieldsFold (prefix ++ [⟨name, schema⟩]) rest
    else none

theorem collected_fields_names (members : List (Bytes × Value)) (fields : List Field)
    (parsed : collectFields members = some fields) : names fields = members.map Prod.fst := by
  have paired := collected_fields_sound members fields parsed
  induction paired with
  | nil => rfl
  | cons first rest ih => simp [names, first.1, ih]

theorem fields_fold_exact (prefix : List Field) (members : List (Bytes × Value)) :
    fieldsFold prefix members = do
      let suffix ← collectFields members
      if LayoutValid (prefix ++ suffix) then some (prefix ++ suffix) else none := by
  induction members generalizing prefix with
  | nil => simp [fieldsFold, collectFields]
  | cons first rest ih =>
    rcases first with ⟨name, value⟩
    by_cases lexical : OperationIdentity.validToken name 64 = true
    · cases schemaAt : parseScalar value with
      | none => simp [fieldsFold, collectFields, lexical, schemaAt]
      | some schema => simp [fieldsFold, collectFields, lexical, schemaAt, ih, List.append_assoc, Option.bind_assoc]
    · cases schemaAt : parseScalar value with
      | none => simp [fieldsFold, collectFields, lexical, schemaAt]
      | some schema =>
        cases tailAt : collectFields rest with
        | none => simp [fieldsFold, collectFields, lexical, schemaAt, tailAt]
        | some tail =>
          have invalid : ¬LayoutValid (prefix ++ ⟨name, schema⟩ :: tail) := by
            intro layout
            exact lexical (layout.2.2 ⟨name, schema⟩ (by simp))
          simp [fieldsFold, collectFields, lexical, schemaAt, tailAt, invalid]

theorem fields_fold_start (members : List (Bytes × Value))
    (admitted : members ≠ [] ∧ members.length ≤ 32) : fieldsFold [] members = parseFields members := by
  simp [fields_fold_exact, parseFields, admitted.1, Nat.not_lt.mpr admitted.2]

/-- Operational order of the actual source parser, related below to the
independent unordered-key parser. Closed key sets prevent overlapping kinds. -/
def scalarSourceOrder (members : List (Bytes × Value)) : Option Schema :=
  if member typeKey members = some (.text enumTag) then
    if ExactKeys members [typeKey, variantsKey] then
      match member variantsKey members with
      | some (.array values) => enumResult values
      | _ => none
    else none
  else if member kindKey members = some (.text booleanTag) then
    if ExactKeys members [kindKey] then some .boolean else none
  else if ExactKeys members [kindKey, minimumKey, maximumKey] then
    if member kindKey members = some (.text stringTag) then do
      let minimum ← stringBound (member minimumKey members)
      let maximum ← stringBound (member maximumKey members)
      if StringSchema minimum maximum then some (.text minimum maximum) else none
    else if member kindKey members = some (.text integerTag) then do
      let minimum ← signedBound (member minimumKey members)
      let maximum ← signedBound (member maximumKey members)
      if IntegerSchema minimum maximum then some (.integer minimum maximum) else none
    else none
  else none

theorem scalar_source_order_exact (members : List (Bytes × Value)) :
    scalarSourceOrder members = parseScalar (.object members) := by
  by_cases enumKeys : ExactKeys members [typeKey, variantsKey]
  · have noKind := exact_keys_lookup_absent members _ kindKey enumKeys (by decide)
    have notBounded : ¬ExactKeys members [kindKey, minimumKey, maximumKey] := by
      intro bounded
      have left := exact_keys_size members _ enumKeys
      have right := exact_keys_size members _ bounded
      simp at left right
      omega
    have notBool : ¬ExactKeys members [kindKey] := by
      intro single
      have left := exact_keys_size members _ enumKeys
      have right := exact_keys_size members _ single
      simp at left right
      omega
    cases kindAt : member typeKey members with
    | none => simp [scalarSourceOrder, parseScalar, enumKeys, noKind, notBounded, notBool, kindAt]
    | some kind =>
      cases kind <;> simp [scalarSourceOrder, parseScalar, enumKeys, noKind, notBounded, notBool, kindAt]
      case text bytes =>
        by_cases tag : bytes = enumTag <;>
          cases valuesAt : member variantsKey members <;>
          simp [scalarSourceOrder, parseScalar, enumKeys, noKind, notBounded, notBool, kindAt, tag, valuesAt, enumResult]
        all_goals cases ‹Value› <;> simp_all [enumResult]
  · by_cases boolKeys : ExactKeys members [kindKey]
    · have noType := exact_keys_lookup_absent members _ typeKey boolKeys (by decide)
      have notBounded : ¬ExactKeys members [kindKey, minimumKey, maximumKey] := by
        intro bounded
        have left := exact_keys_size members _ boolKeys
        have right := exact_keys_size members _ bounded
        simp at left right
        omega
      simp [scalarSourceOrder, parseScalar, enumKeys, boolKeys, noType, notBounded]
    · by_cases boundedKeys : ExactKeys members [kindKey, minimumKey, maximumKey]
      · have noType := exact_keys_lookup_absent members _ typeKey boundedKeys (by decide)
        by_cases booleanKind : member kindKey members = some (.text booleanTag)
        · simp [scalarSourceOrder, parseScalar, enumKeys, boolKeys, boundedKeys, noType,
            booleanKind, booleanTag, stringTag, integerTag]
        · simp [scalarSourceOrder, parseScalar, enumKeys, boolKeys, boundedKeys, noType, booleanKind]
      · simp [scalarSourceOrder, parseScalar, enumKeys, boolKeys, boundedKeys]

end Auths.Product.ProfileSchema
