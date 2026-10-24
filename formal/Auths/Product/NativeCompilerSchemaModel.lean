import Auths.Product.NativeCompilerValues
import Auths.Product.ProfileSchemaFolds

open Aeneas Aeneas.Std

namespace Auths.Product.NativeCompiler

abbrev NativeConstructError := AuthsNativeRecipe.auths_gateway_kernel.construct.ConstructError
abbrev NativeScalarSchema := AuthsNativeRecipe.auths_gateway_kernel.scalars.ScalarSchema
abbrev NativeFieldSpec := AuthsNativeRecipe.auths_gateway_kernel.field_projection.FieldSpec

def schemaSliceBytes (input : Slice Std.U8) : List Nat := input.val.map (·.val)

/-- Exact optional representation, including absence. This relation cannot
make a missing or differently typed native value satisfy an independent lookup. -/
def MaybeSchemaMeaning (input : Option SchemaNode) (meaning : Option ProfileSchema.Value) : Prop :=
  match input, meaning with
  | none, none => True
  | some value, some original => SchemaMeaning value original
  | _, _ => False

def NativeSchemaMemberMeaning (input : SchemaMember) (meaning : List Nat × ProfileSchema.Value) : Prop :=
  bytes input.name = meaning.1 ∧ SchemaMeaning input.value meaning.2

def nativeScalarMeaning : NativeScalarSchema → ScalarProjection.Schema
  | .String minimum maximum => .text minimum.val maximum.val
  | .Integer minimum maximum => .integer minimum.val maximum.val
  | .Enum variants => .enumeration (variants.val.map bytes)
  | .Boolean => .boolean

def nativeFieldMeaning (input : NativeFieldSpec) : FieldProjection.Field :=
  ⟨bytes input.name, nativeScalarMeaning input.schema⟩

def nativeFieldsMeaning (input : NativeVec NativeFieldSpec) : List FieldProjection.Field :=
  input.val.map nativeFieldMeaning

def sourceFieldParse (original : List Nat × ProfileSchema.Value) : Option FieldProjection.Field :=
  if OperationIdentity.validToken original.1 64 then
    (ProfileSchema.parseScalar original.2).map (fun schema => ⟨original.1, schema⟩)
  else none

theorem refused_field_stops_fold (prefix : List FieldProjection.Field)
    (original : List Nat × ProfileSchema.Value) (rest : List (List Nat × ProfileSchema.Value))
    (refused : sourceFieldParse original = none) : ProfileSchema.fieldsFold prefix (original :: rest) = none := by
  rcases original with ⟨name, value⟩
  unfold sourceFieldParse at refused
  by_cases lexical : OperationIdentity.validToken name 64 = true
  · cases scalar : ProfileSchema.parseScalar value with
    | none => simp [ProfileSchema.fieldsFold, lexical, scalar]
    | some schema => simp [lexical, scalar] at refused
  · simp [ProfileSchema.fieldsFold, lexical]

theorem accepted_field_advances_fold (prefix : List FieldProjection.Field)
    (original : List Nat × ProfileSchema.Value) (rest : List (List Nat × ProfileSchema.Value))
    (field : FieldProjection.Field) (parsed : sourceFieldParse original = some field) :
    ProfileSchema.fieldsFold prefix (original :: rest) = ProfileSchema.fieldsFold (prefix ++ [field]) rest := by
  rcases original with ⟨name, value⟩
  unfold sourceFieldParse at parsed
  by_cases lexical : OperationIdentity.validToken name 64 = true
  · cases scalar : ProfileSchema.parseScalar value with
    | none => simp [lexical, scalar] at parsed
    | some schema =>
        have same : field = ⟨name, schema⟩ := by simpa only [lexical, ↓reduceIte, scalar, Option.map_some, Option.some.injEq] using parsed.symm
        simp [ProfileSchema.fieldsFold, lexical, scalar, same]
  · simp [lexical] at parsed

theorem schema_members_as_pairs {inputs : List SchemaMember}
    {meanings : List (List Nat × ProfileSchema.Value)}
    (paired : SchemaMemberMeanings inputs meanings) :
    List.Forall₂ NativeSchemaMemberMeaning inputs meanings := by
  induction paired with
  | nil => exact .nil
  | cons head tail ih => exact .cons ⟨rfl, head⟩ ih

theorem schema_members_count {inputs : List SchemaMember}
    {meanings : List (List Nat × ProfileSchema.Value)}
    (paired : SchemaMemberMeanings inputs meanings) : inputs.length = meanings.length :=
  (schema_members_as_pairs paired).length_eq

theorem schema_values_count {inputs : List SchemaNode} {meanings : List ProfileSchema.Value}
    (paired : SchemaMeanings inputs meanings) : inputs.length = meanings.length := by
  induction paired with
  | nil => rfl
  | cons _ _ ih => simp only [List.length_cons, ih]

theorem maybe_schema_absence {input : Option SchemaNode} {meaning : Option ProfileSchema.Value}
    (same : MaybeSchemaMeaning input meaning) : input = none ↔ meaning = none := by
  cases input <;> cases meaning <;> simp_all [MaybeSchemaMeaning]

theorem maybe_schema_presence {input : Option SchemaNode} {meaning : Option ProfileSchema.Value}
    (same : MaybeSchemaMeaning input meaning) : input.isSome = meaning.isSome := by
  cases input <;> cases meaning <;> simp_all [MaybeSchemaMeaning]

theorem native_byte_list_injective : Function.Injective (fun values : List Std.U8 => values.map (·.val)) := by
  intro left right same
  induction left generalizing right with
  | nil => cases right <;> simp_all
  | cons first rest ih =>
      cases right with
      | nil => simp at same
      | cons other tail =>
          simp only [List.map_cons, List.cons.injEq] at same
          have heads : first = other := UScalar.eq_of_val_eq same.1
          simp only [heads, ih same.2]

theorem native_slice_bytes_equal (left right : Slice Std.U8) :
    schemaSliceBytes left = schemaSliceBytes right ↔ left.val = right.val :=
  ⟨native_byte_list_injective, congrArg (List.map (·.val))⟩

end Auths.Product.NativeCompiler
