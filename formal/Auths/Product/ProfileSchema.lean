import Auths.Product.FieldProjection
import Mathlib.Data.List.Perm.Subperm

namespace Auths.Product.ProfileSchema
open RequestConstruction ScalarProjection FieldProjection

/-- This decoded boundary retains all names and every array/object child.
Unsupported atoms cannot acquire schema meaning through coercion. -/
inductive Value where
  | text (bytes : Bytes)
  | signed (value : Int)
  | unsigned (value : Nat)
  | array (values : List Value)
  | object (members : List (Bytes × Value))
  | unsupported
  deriving DecidableEq

def kindKey : Bytes := [107,105,110,100]
def fieldsKey : Bytes := [102,105,101,108,100,115]
def typeKey : Bytes := [116,121,112,101]
def variantsKey : Bytes := [118,97,114,105,97,110,116,115]
def minimumKey : Bytes := [109,105,110,105,109,117,109]
def maximumKey : Bytes := [109,97,120,105,109,117,109]
def objectTag : Bytes := [111,98,106,101,99,116]
def booleanTag : Bytes := [98,111,111,108,101,97,110]
def stringTag : Bytes := [115,116,114,105,110,103]
def integerTag : Bytes := [105,110,116,101,103,101,114]
def enumTag : Bytes := [101,110,117,109]
def namespaceName : Bytes := [111,112,101,114,97,116,111,114,95,110,97,109,101,115,112,97,99,101]
def operationName : Bytes := [111,112,101,114,97,116,105,111,110,95,105,100]
def digestName : Bytes := [114,101,99,105,112,101,95,100,105,103,101,115,116]

def member (wanted : Bytes) : List (Bytes × Value) → Option Value
  | [] => none
  | (name, value) :: rest => if name = wanted then some value else member wanted rest

/-- Independent unordered exact key-set semantics. The permutation includes
multiplicity, so a repeated key cannot stand in for another required key. -/
def ExactKeys (members : List (Bytes × Value)) (expected : List Bytes) : Prop :=
  (members.map Prod.fst).Perm expected

instance (members : List (Bytes × Value)) (expected : List Bytes) : Decidable (ExactKeys members expected) := by
  unfold ExactKeys
  infer_instance

def Numeric : Value → Int → Prop
  | .signed actual, expected => actual = expected
  | .unsigned actual, expected => (actual : Int) = expected
  | _, _ => False

def numeric : Value → Option Int
  | .signed value => some value
  | .unsigned value => some (value : Int)
  | _ => none

def stringBound : Option Value → Option Nat
  | some value => do
    let number ← numeric value
    if 0 ≤ number ∧ number ≤ 4096 then some number.toNat else none
  | none => none

def signedBound : Option Value → Option Int
  | some (.signed value) => some value
  | some (.unsigned value) => if value ≤ 9223372036854775807 then some (value : Int) else none
  | _ => none

def texts : List Value → Option (List Bytes)
  | [] => some []
  | .text bytes :: rest => (texts rest).map (bytes :: ·)
  | _ :: _ => none

def SchemaValid : Schema → Prop
  | .text minimum maximum => StringSchema minimum maximum
  | .enumeration variants => EnumSchema variants
  | .integer minimum maximum => IntegerSchema minimum maximum
  | .boolean => True

instance (schema : Schema) : Decidable (SchemaValid schema) := by
  cases schema <;> unfold SchemaValid <;> infer_instance

/-- Meaning is stated over the original raw members, their exact key set,
numeric values and original enum children. It contains no parser success,
validity bit, field index or desired output buffer. -/
inductive ScalarMeaning : Value → Schema → Prop where
  | string (members : List (Bytes × Value)) (minimum maximum : Nat) (low high : Value)
      (keys : ExactKeys members [kindKey, minimumKey, maximumKey])
      (kind : member kindKey members = some (.text stringTag))
      (lowAt : member minimumKey members = some low) (highAt : member maximumKey members = some high)
      (lowValue : Numeric low (minimum : Int)) (highValue : Numeric high (maximum : Int))
      (bounds : StringSchema minimum maximum) :
      ScalarMeaning (.object members) (.text minimum maximum)
  | integer (members : List (Bytes × Value)) (minimum maximum : Int) (low high : Value)
      (keys : ExactKeys members [kindKey, minimumKey, maximumKey])
      (kind : member kindKey members = some (.text integerTag))
      (lowAt : member minimumKey members = some low) (highAt : member maximumKey members = some high)
      (lowValue : Numeric low minimum) (highValue : Numeric high maximum)
      (bounds : IntegerSchema minimum maximum) :
      ScalarMeaning (.object members) (.integer minimum maximum)
  | enumeration (members : List (Bytes × Value)) (values : List Value) (variants : List Bytes)
      (keys : ExactKeys members [typeKey, variantsKey])
      (kind : member typeKey members = some (.text enumTag))
      (valuesAt : member variantsKey members = some (.array values))
      (paired : List.Forall₂ (fun value bytes => value = .text bytes) values variants)
      (valid : EnumSchema variants) :
      ScalarMeaning (.object members) (.enumeration variants)
  | boolean (members : List (Bytes × Value)) (keys : ExactKeys members [kindKey])
      (kind : member kindKey members = some (.text booleanTag)) :
      ScalarMeaning (.object members) .boolean

def parseScalar : Value → Option Schema
  | .object members =>
    if ExactKeys members [typeKey, variantsKey] then do
      let .text kind ← member typeKey members | none
      if kind ≠ enumTag then none else do
        let .array values ← member variantsKey members | none
        let variants ← texts values
        if EnumSchema variants then some (.enumeration variants) else none
    else if ExactKeys members [kindKey] then
      if member kindKey members = some (.text booleanTag) then some .boolean else none
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
  | _ => none

def collectFields : List (Bytes × Value) → Option (List Field)
  | [] => some []
  | (name, value) :: rest => do
    let schema ← parseScalar value
    let fields ← collectFields rest
    some (⟨name, schema⟩ :: fields)

def parseFields (members : List (Bytes × Value)) : Option (List Field) := do
  if members = [] ∨ 32 < members.length then none else do
    let fields ← collectFields members
    if LayoutValid fields then some fields else none

def parseRoot : Value → Option (List Field)
  | .object members =>
    if ExactKeys members [kindKey, fieldsKey] ∧ member kindKey members = some (.text objectTag) then do
      let .object fields ← member fieldsKey members | none
      parseFields fields
    else none
  | _ => none

def FieldMeaning (member : Bytes × Value) (field : Field) : Prop :=
  field.name = member.1 ∧ ScalarMeaning member.2 field.schema

def FieldsMeaning (members : List (Bytes × Value)) (fields : List Field) : Prop :=
  0 < fields.length ∧ LayoutValid fields ∧ List.Forall₂ FieldMeaning members fields

def RootMeaning (source : Value) (fields : List Field) : Prop :=
  ∃ root members, source = .object root ∧ ExactKeys root [kindKey, fieldsKey] ∧
    member kindKey root = some (.text objectTag) ∧ member fieldsKey root = some (.object members) ∧
    FieldsMeaning members fields

def BindingFields (fields : List Field) (namespaceBytes : Bytes) : Prop :=
  schemaFor namespaceName fields = some (.enumeration [namespaceBytes]) ∧
    (∃ minimum maximum, schemaFor operationName fields = some (.text minimum maximum) ∧
      1 ≤ minimum ∧ maximum ≤ 128) ∧
    schemaFor digestName fields = some (.text 64 64)

def bindingFieldsMatch (fields : List Field) (namespaceBytes : Bytes) : Bool :=
  match schemaFor namespaceName fields with
  | some (.enumeration [name]) =>
    if name ≠ namespaceBytes then false else
    match schemaFor operationName fields with
    | some (.text minimum maximum) =>
      if minimum < 1 ∨ 128 < maximum then false else
      match schemaFor digestName fields with
      | some (.text 64 64) => true
      | _ => false
    | _ => false
  | _ => false

theorem member_some_is_original (members : List (Bytes × Value)) (name : Bytes) (value : Value)
    (found : member name members = some value) : (name, value) ∈ members := by
  induction members with
  | nil => simp [member] at found
  | cons first rest ih =>
    rcases first with ⟨key, original⟩
    simp only [member] at found
    by_cases same : key = name
    · simp [same] at found
      simp [same, found]
    · simp [same] at found
      exact List.mem_cons_of_mem _ (ih found)

theorem member_none_iff_absent (members : List (Bytes × Value)) (name : Bytes) :
    member name members = none ↔ name ∉ members.map Prod.fst := by
  induction members with
  | nil => simp [member]
  | cons first rest ih => rcases first with ⟨key, value⟩; by_cases same : key = name <;> simp [member, same, ih, eq_comm]

theorem exact_keys_size (members : List (Bytes × Value)) (expected : List Bytes)
    (exact : ExactKeys members expected) : members.length = expected.length := by
  simpa [ExactKeys] using List.Perm.length_eq exact

theorem exact_keys_lookup_absent (members : List (Bytes × Value)) (expected : List Bytes) (name : Bytes)
    (exact : ExactKeys members expected) (absent : name ∉ expected) : member name members = none := by
  apply (member_none_iff_absent members name).mpr
  intro present
  exact absent (exact.mem_iff.mp present)

theorem exact_keys_unique (members : List (Bytes × Value)) (expected : List Bytes)
    (exact : ExactKeys members expected) (unique : expected.Nodup) : (members.map Prod.fst).Nodup :=
  exact.nodup_iff.mpr unique

theorem numeric_iff (source : Value) (number : Int) : numeric source = some number ↔ Numeric source number := by
  cases source <;> simp [numeric, Numeric]

theorem texts_exact (values : List Value) (bytes : List Bytes) :
    texts values = some bytes ↔ List.Forall₂ (fun value text => value = .text text) values bytes := by
  induction values generalizing bytes with
  | nil => cases bytes <;> simp [texts, List.Forall₂]
  | cons value rest ih =>
    cases value <;> cases bytes <;> simp [texts, List.Forall₂, Option.map_eq_some_iff, ih]

theorem scalar_meaning_valid (source : Value) (schema : Schema) (meaning : ScalarMeaning source schema) :
    SchemaValid schema := by
  cases meaning <;> first | assumption | trivial

theorem fields_meaning_keeps_original_names (members : List (Bytes × Value)) (fields : List Field)
    (meaning : FieldsMeaning members fields) : names fields = members.map Prod.fst := by
  have paired := meaning.2.2
  induction paired with
  | nil => rfl
  | cons first rest ih => simp [names, first.1, ih]

theorem root_meaning_earns_complete_valid_layout (source : Value) (fields : List Field)
    (meaning : RootMeaning source fields) :
    0 < fields.length ∧ LayoutValid fields ∧ ∀ field ∈ fields, SchemaValid field.schema := by
  obtain ⟨_, _, _, _, _, _, nonempty, layout, paired⟩ := meaning
  refine ⟨nonempty, layout, ?_⟩
  induction paired with
  | nil => simp
  | cons first rest ih =>
    intro field present
    rcases List.mem_cons.mp present with same | later
    · subst field
      exact scalar_meaning_valid _ _ first.2
    · exact ih field later

theorem bound_namespace_exact (fields : List Field) (namespaceBytes : Bytes)
    (binding : BindingFields fields namespaceBytes) :
    schemaFor namespaceName fields = some (.enumeration [namespaceBytes]) := binding.1

theorem binding_boolean_exact (fields : List Field) (namespaceBytes : Bytes) :
    bindingFieldsMatch fields namespaceBytes = true ↔ BindingFields fields namespaceBytes := by
  unfold bindingFieldsMatch BindingFields
  split <;> rename_i namespaceAt
  · split_ifs <;>
      split <;>
      try { simp_all }
    all_goals split_ifs <;> split <;> simp_all
  · simp_all

end Auths.Product.ProfileSchema
