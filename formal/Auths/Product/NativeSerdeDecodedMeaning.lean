import Auths.Product.NativeSerdeCarriers
import Auths.Product.NativeFullJsonMeaning

/-!
Full original decoded-value meaning, relating the independent input tree to
EVERY field of the actual native recipe/lock carrier. This is the required
postcondition for a future actual serde-derive refinement, not an assumed
decoder implementation. No translated derive correctness is claimed here.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar SerdeFieldLayout NativeCompiler
open Aeneas Aeneas.Std

abbrev RawJson := FullJsonValue.Value

def methodName : AuthsNativeRecipe.recipe.WriteMethod → String
  | .Post => "POST"
  | .Put => "PUT"
  | .Patch => "PATCH"
  | .Delete => "DELETE"

mutual
  inductive Decode : Mode → (kind : Kind) → RawJson → NativeKind kind → Prop where
    | text (mode : Mode) (value : String) (fits : TextFits value) : Decode mode .text (.text value) value
    | boolean (mode : Mode) (value : Bool) : Decode mode .boolean (.boolean value) value
    | signed (mode : Mode) (number : FullJsonValue.Number) (value : Std.I64)
        (decoded : signedValue number = some value.val) : Decode mode .signed64 (.number number) value
    | unsigned8 (mode : Mode) (number : FullJsonValue.Number) (value : Std.U8)
        (decoded : unsignedValue 255 number = some value.val) : Decode mode .unsigned8 (.number number) value
    | unsigned16 (mode : Mode) (number : FullJsonValue.Number) (value : Std.U16)
        (decoded : unsignedValue 65535 number = some value.val) : Decode mode .unsigned16 (.number number) value
    | unsigned (mode : Mode) (number : FullJsonValue.Number) (value : Std.U64)
        (decoded : unsignedValue 18446744073709551615 number = some value.val) : Decode mode .unsigned64 (.number number) value
    | word (mode : Mode) (number : FullJsonValue.Number) (value : Std.Usize)
        (decoded : unsignedValue Usize.max number = some value.val) : Decode mode .word (.number number) value
    | json (mode : Mode) (input : RawJson) (value : NativeCompiler.Json)
        (original : FullJsonMeaning value input) (bounds : JsonBounds value) : Decode mode .json input value
    | absent (mode : Mode) (kind : Kind) : Decode mode (.option kind) .null none
    | present {mode : Mode} {kind : Kind} {input : RawJson} {value : NativeKind kind}
        (notNull : input ≠ .null) (child : Decode mode kind input value) : Decode mode (.option kind) input (some value)
    | vector {mode : Mode} {kind : Kind} {input : List RawJson} {value : NativeVec (NativeKind kind)}
        (children : ValuesDecode mode kind input value.val) : Decode mode (.vector kind) (.array input) value
    | map {mode : Mode} {kind : Kind} {input : List (String × RawJson)}
        {value : SourceMap (NativeKind kind)} (sourceOrder : List (String × NativeKind kind))
        (children : MembersDecode mode kind input sourceOrder)
        (ordered : value.entries.val.Pairwise (fun left right => left.1 < right.1))
        (retained : sourceOrder.Perm value.entries.val) : Decode mode (.map kind) (.object input) value
    | record {mode : Mode} {name : Record} {input : RawJson} (value : NativeRecord name) (fields : List RawJson)
        (bound : normalize (recordFields name) input = .ok fields)
        (children : FieldsDecode mode (recordFields name) fields (recordSlots name value)) :
        Decode mode (.record name) input value
    | internal {mode : Mode} {name : Enum} {input content : RawJson} (value : NativeEnum name)
        (selected : SerdeFieldLayout.internal mode ((variants name).map Variant.name) input =
          .ok ((nativeVariant name value).name, content))
        (child : VariantDecode name value content) : Decode mode (.internal name) input value
    | writeMethod (mode : Mode) (input : RawJson) (value : AuthsNativeRecipe.recipe.WriteMethod)
        (selected : externalUnit mode writeMethods input = .ok (methodName value)) : Decode mode .writeMethod input value

  inductive ValuesDecode : Mode → (kind : Kind) → List RawJson → List (NativeKind kind) → Prop where
    | nil (mode : Mode) (kind : Kind) : ValuesDecode mode kind [] []
    | cons {mode : Mode} {kind : Kind} {input : RawJson} {value : NativeKind kind}
        {rest : List RawJson} {values : List (NativeKind kind)}
        (head : Decode mode kind input value) (tail : ValuesDecode mode kind rest values) :
        ValuesDecode mode kind (input :: rest) (value :: values)

  inductive MembersDecode : Mode → (kind : Kind) → List (String × RawJson) → List (String × NativeKind kind) → Prop where
    | nil (mode : Mode) (kind : Kind) : MembersDecode mode kind [] []
    | cons {mode : Mode} {kind : Kind} {name : String} {input : RawJson} {value : NativeKind kind}
        {rest : List (String × RawJson)} {values : List (String × NativeKind kind)} (fits : TextFits name)
        (head : Decode mode kind input value) (tail : MembersDecode mode kind rest values) :
        MembersDecode mode kind ((name, input) :: rest) ((name, value) :: values)

  inductive FieldsDecode : Mode → Fields → List RawJson → List Slot → Prop where
    | nil (mode : Mode) : FieldsDecode mode [] [] []
    | cons {mode : Mode} {field : Field Kind} {rest : Fields} {input : RawJson}
        {inputs : List RawJson} {value : NativeKind field.kind} {values : List Slot}
        (head : Decode mode field.kind input value) (tail : FieldsDecode mode rest inputs values) :
        FieldsDecode mode (field :: rest) (input :: inputs) (⟨field.kind, value⟩ :: values)

  inductive VariantDecode : (name : Enum) → NativeEnum name → RawJson → Prop where
    | unit (name : Enum) (value : NativeEnum name) (content : RawJson)
        (noFields : (nativeVariant name value).fields = none) (accepted : unitContent content = true) :
        VariantDecode name value content
    | fields (name : Enum) (value : NativeEnum name) (fields : Fields) (content : RawJson) (inputs : List RawJson)
        (declared : (nativeVariant name value).fields = some fields)
        (bound : normalize fields content = .ok inputs)
        (children : FieldsDecode .buffered fields inputs (variantSlots name value)) :
        VariantDecode name value content
end

mutual
  theorem native_decode_earns_typed_shape {mode : Mode} {kind : Kind} {input : RawJson} {value : NativeKind kind}
      (decoded : Decode mode kind input value) : Accepts Usize.max mode kind input := by
    cases decoded with
    | text mode value _ => exact .text mode value
    | boolean mode value => exact .boolean mode value
    | signed mode number value original => exact .signed mode number value.val original
    | unsigned8 mode number value original => exact .unsigned8 mode number value.val original
    | unsigned16 mode number value original => exact .unsigned16 mode number value.val original
    | unsigned mode number value original => exact .unsigned mode number value.val original
    | word mode number value original => exact .word mode number value.val original
    | json mode input value _ _ => exact .json mode input
    | absent mode kind => exact .absent mode kind
    | present notNull child => exact .present notNull (native_decode_earns_typed_shape child)
    | vector children => exact .vector (native_values_earn_typed_shape children)
    | map sourceOrder children _ _ => exact .map (native_members_earn_typed_shape children)
    | record value fields bound children => exact .record bound (native_fields_earn_typed_shape children)
    | internal value selected child =>
        exact .internal _ (native_variant_is_declared _ value) selected (native_variant_earns_typed_shape child)
    | writeMethod mode input value selected => exact .writeMethod (methodName value) selected
  termination_by structural decoded

  theorem native_values_earn_typed_shape {mode : Mode} {kind : Kind} {inputs : List RawJson}
      {values : List (NativeKind kind)} (decoded : ValuesDecode mode kind inputs values) :
      ValuesAccept Usize.max mode kind inputs := by
    cases decoded with
    | nil mode kind => exact .nil mode kind
    | cons head tail => exact .cons (native_decode_earns_typed_shape head) (native_values_earn_typed_shape tail)
  termination_by structural decoded

  theorem native_members_earn_typed_shape {mode : Mode} {kind : Kind} {inputs : List (String × RawJson)}
      {values : List (String × NativeKind kind)} (decoded : MembersDecode mode kind inputs values) :
      MembersAccept Usize.max mode kind inputs := by
    cases decoded with
    | nil mode kind => exact .nil mode kind
    | cons fits head tail => exact .cons (native_decode_earns_typed_shape head) (native_members_earn_typed_shape tail)
  termination_by structural decoded

  theorem native_fields_earn_typed_shape {mode : Mode} {fields : Fields} {inputs : List RawJson}
      {values : List Slot} (decoded : FieldsDecode mode fields inputs values) :
      FieldsAccept Usize.max mode fields inputs := by
    cases decoded with
    | nil mode => exact .nil mode
    | cons head tail => exact .cons (native_decode_earns_typed_shape head) (native_fields_earn_typed_shape tail)
  termination_by structural decoded

  theorem native_variant_earns_typed_shape {name : Enum} {value : NativeEnum name} {input : RawJson}
      (decoded : VariantDecode name value input) : VariantAccept Usize.max (nativeVariant name value) input := by
    cases decoded with
    | unit name value content noFields accepted =>
        change VariantAccept Usize.max ⟨(nativeVariant name value).name, (nativeVariant name value).fields⟩ content
        rw [noFields]
        exact .unit _ content accepted
    | fields name value fields content inputs declared bound children =>
        change VariantAccept Usize.max ⟨(nativeVariant name value).name, (nativeVariant name value).fields⟩ content
        rw [declared]
        exact .fields _ fields content inputs bound (native_fields_earn_typed_shape children)
  termination_by structural decoded
end

theorem native_values_keep_full_count {mode : Mode} {kind : Kind} {inputs : List RawJson}
    {values : List (NativeKind kind)} (decoded : ValuesDecode mode kind inputs values) : values.length = inputs.length := by
  induction decoded with
  | nil => rfl
  | cons _ _ ih => simp only [List.length_cons, ih]

theorem native_members_keep_full_names {mode : Mode} {kind : Kind} {inputs : List (String × RawJson)}
    {values : List (String × NativeKind kind)} (decoded : MembersDecode mode kind inputs values) :
    values.map Prod.fst = inputs.map Prod.fst := by
  induction decoded with
  | nil => rfl
  | cons _ _ _ ih => simp only [List.map_cons, ih]

theorem native_fields_keep_full_kinds {mode : Mode} {fields : Fields} {inputs : List RawJson}
    {values : List Slot} (decoded : FieldsDecode mode fields inputs values) :
    values.map Slot.kind = fields.map Field.kind := by
  induction decoded with
  | nil => rfl
  | cons _ _ ih => simp only [List.map_cons, ih]

/-- Typed BTreeMap decoding may reorder the original object, but cannot drop,
replace or collapse an occurrence in this strict-preflight decoded relation.
The ordered native sequence and the full original names/count are earned
together. Actual parser/BTreeMap construction must establish the relation. -/
theorem native_map_retains_complete_names {mode : Mode} {kind : Kind} {input : List (String × RawJson)}
    {value : SourceMap (NativeKind kind)} (decoded : Decode mode (.map kind) (.object input) value) :
    (value.entries.val.map Prod.fst).Perm (input.map Prod.fst) ∧
      value.entries.val.length = input.length ∧
      value.entries.val.Pairwise (fun left right => left.1 < right.1) := by
  cases decoded with
  | map sourceOrder children ordered retained =>
      have originalNames := native_members_keep_full_names children
      have names := (List.Perm.map Prod.fst retained).symm
      rw [originalNames] at names
      exact ⟨names, by simpa only [List.length_map] using names.length_eq, ordered⟩

def SourceMeaning (input : RawJson) (value : NativeRecord .recipe) : Prop :=
  FullJsonValue.checkMembers input = .ok () ∧ Decode .direct (.record .recipe) input value

def LockMeaning (input : RawJson) (value : NativeRecord .lock) : Prop :=
  FullJsonValue.checkMembers input = .ok () ∧ Decode .direct (.record .lock) input value

theorem native_source_meaning_earns_shape (input : RawJson) (value : NativeRecord .recipe)
    (original : SourceMeaning input value) : SourceShape Usize.max input :=
  ⟨original.1, native_decode_earns_typed_shape original.2⟩

theorem native_lock_meaning_earns_shape (input : RawJson) (value : NativeRecord .lock)
    (original : LockMeaning input value) : LockShape Usize.max input :=
  ⟨original.1, native_decode_earns_typed_shape original.2⟩

end Auths.Product.NativeSerde
