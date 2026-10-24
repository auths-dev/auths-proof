import Auths.Product.NativeSerdeDecodedMeaning

/-!
Representation properties earned by full decoded-value meaning. These bounds
do not admit a recipe, assume a parser result, limit semantic depth, or assert
aggregate allocation/time costs. The actual serde refinement must establish
Decode first. Native word/vector capacity is already part of the carrier.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar SerdeFieldLayout NativeCompiler
open Aeneas Aeneas.Std

mutual
  inductive CarrierBounds : (kind : Kind) → NativeKind kind → Prop where
    | text (value : String) (fits : TextFits value) : CarrierBounds .text value
    | boolean (value : Bool) : CarrierBounds .boolean value
    | signed (value : Std.I64) : CarrierBounds .signed64 value
    | unsigned8 (value : Std.U8) : CarrierBounds .unsigned8 value
    | unsigned16 (value : Std.U16) : CarrierBounds .unsigned16 value
    | unsigned (value : Std.U64) : CarrierBounds .unsigned64 value
    | word (value : Std.Usize) : CarrierBounds .word value
    | json (value : NativeCompiler.Json) (bounds : JsonBounds value) : CarrierBounds .json value
    | absent (kind : Kind) : CarrierBounds (.option kind) none
    | present {kind : Kind} {value : NativeKind kind} (child : CarrierBounds kind value) :
        CarrierBounds (.option kind) (some value)
    | vector {kind : Kind} (value : NativeVec (NativeKind kind))
        (children : ElementsBounded kind value.val) : CarrierBounds (.vector kind) value
    | map {kind : Kind} (value : SourceMap (NativeKind kind))
        (children : MembersBounded kind value.entries.val)
        (ordered : value.entries.val.Pairwise (fun left right => left.1 < right.1)) : CarrierBounds (.map kind) value
    | record (name : Record) (value : NativeRecord name) (children : SlotsBounded (recordSlots name value)) :
        CarrierBounds (.record name) value
    | internal (name : Enum) (value : NativeEnum name) (children : SlotsBounded (variantSlots name value)) :
        CarrierBounds (.internal name) value
    | writeMethod (value : AuthsNativeRecipe.recipe.WriteMethod) : CarrierBounds .writeMethod value

  inductive ElementsBounded : (kind : Kind) → List (NativeKind kind) → Prop where
    | nil (kind : Kind) : ElementsBounded kind []
    | cons {kind : Kind} {value : NativeKind kind} {rest : List (NativeKind kind)}
        (head : CarrierBounds kind value) (tail : ElementsBounded kind rest) : ElementsBounded kind (value :: rest)

  inductive MembersBounded : (kind : Kind) → List (String × NativeKind kind) → Prop where
    | nil (kind : Kind) : MembersBounded kind []
    | cons {kind : Kind} {name : String} {value : NativeKind kind} {rest : List (String × NativeKind kind)}
        (fits : TextFits name) (head : CarrierBounds kind value) (tail : MembersBounded kind rest) :
        MembersBounded kind ((name, value) :: rest)

  inductive SlotsBounded : List Slot → Prop where
    | nil : SlotsBounded []
    | cons {slot : Slot} {rest : List Slot} (head : CarrierBounds slot.kind slot.value)
        (tail : SlotsBounded rest) : SlotsBounded (slot :: rest)
end

theorem bounded_members_each {kind : Kind} {members : List (String × NativeKind kind)}
    (bounded : MembersBounded kind members) :
    ∀ pair ∈ members, TextFits pair.1 ∧ CarrierBounds kind pair.2 := by
  induction bounded with
  | nil => simp
  | cons fits head tail ih =>
      intro pair member
      rcases List.mem_cons.mp member with rfl | later
      · exact ⟨fits, head⟩
      · exact ih pair later

private theorem members_bounded_from_each (kind : Kind) (members : List (String × NativeKind kind))
    (bounded : ∀ pair ∈ members, TextFits pair.1 ∧ CarrierBounds kind pair.2) : MembersBounded kind members := by
  revert bounded
  induction members with
  | nil => intro _; exact .nil kind
  | cons pair rest ih =>
      intro bounded
      have head := bounded pair (by simp)
      have tail := ih (fun pair member => bounded pair (List.mem_cons_of_mem _ member))
      cases pair
      exact .cons head.1 head.2 tail

theorem bounded_members_permutation {kind : Kind} {first second : List (String × NativeKind kind)}
    (bounded : MembersBounded kind first) (retained : first.Perm second) : MembersBounded kind second := by
  apply members_bounded_from_each
  intro pair member
  exact bounded_members_each bounded pair (retained.mem_iff.mpr member)

theorem bounded_elements_each {kind : Kind} {values : List (NativeKind kind)}
    (bounded : ElementsBounded kind values) : ∀ value ∈ values, CarrierBounds kind value := by
  induction bounded with
  | nil => simp
  | cons head tail ih =>
      intro value member
      rcases List.mem_cons.mp member with rfl | later
      · exact head
      · exact ih value later

theorem bounded_slots_each {values : List Slot} (bounded : SlotsBounded values) :
    ∀ slot ∈ values, CarrierBounds slot.kind slot.value := by
  induction bounded with
  | nil => simp
  | cons head tail ih =>
      intro slot member
      rcases List.mem_cons.mp member with rfl | later
      · exact head
      · exact ih slot later

theorem native_unit_variant_slots_empty (name : Enum) (value : NativeEnum name)
    (unit : (nativeVariant name value).fields = none) : variantSlots name value = [] := by
  cases name <;> cases value <;>
    simp_all [nativeVariant, variantIndex, variants, variantSlots]

mutual
  theorem native_decode_earns_carrier_bounds {mode : Mode} {kind : Kind} {input : RawJson} {value : NativeKind kind}
      (decoded : Decode mode kind input value) : CarrierBounds kind value := by
    cases decoded with
    | text mode value fits => exact .text value fits
    | boolean mode value => exact .boolean value
    | signed mode number value _ => exact .signed value
    | unsigned8 mode number value _ => exact .unsigned8 value
    | unsigned16 mode number value _ => exact .unsigned16 value
    | unsigned mode number value _ => exact .unsigned value
    | word mode number value _ => exact .word value
    | json mode input value _ bounds => exact .json value bounds
    | absent mode kind => exact .absent kind
    | present _ child => exact .present (native_decode_earns_carrier_bounds child)
    | vector children => exact .vector _ (native_values_earn_carrier_bounds children)
    | map sourceOrder children ordered retained =>
        exact .map _ (bounded_members_permutation (native_members_earn_carrier_bounds children) retained) ordered
    | record value fields bound children => exact .record _ value (native_fields_earn_carrier_bounds children)
    | internal value selected child => exact .internal _ value (native_variant_earns_carrier_bounds child)
    | writeMethod mode input value _ => exact .writeMethod value
  termination_by structural decoded

  theorem native_values_earn_carrier_bounds {mode : Mode} {kind : Kind} {inputs : List RawJson}
      {values : List (NativeKind kind)} (decoded : ValuesDecode mode kind inputs values) : ElementsBounded kind values := by
    cases decoded with
    | nil mode kind => exact .nil kind
    | cons head tail => exact .cons (native_decode_earns_carrier_bounds head) (native_values_earn_carrier_bounds tail)
  termination_by structural decoded

  theorem native_members_earn_carrier_bounds {mode : Mode} {kind : Kind} {inputs : List (String × RawJson)}
      {values : List (String × NativeKind kind)} (decoded : MembersDecode mode kind inputs values) : MembersBounded kind values := by
    cases decoded with
    | nil mode kind => exact .nil kind
    | cons fits head tail => exact .cons fits (native_decode_earns_carrier_bounds head) (native_members_earn_carrier_bounds tail)
  termination_by structural decoded

  theorem native_fields_earn_carrier_bounds {mode : Mode} {fields : Fields} {inputs : List RawJson}
      {values : List Slot} (decoded : FieldsDecode mode fields inputs values) : SlotsBounded values := by
    cases decoded with
    | nil mode => exact .nil
    | cons head tail => exact .cons (native_decode_earns_carrier_bounds head) (native_fields_earn_carrier_bounds tail)
  termination_by structural decoded

  theorem native_variant_earns_carrier_bounds {name : Enum} {value : NativeEnum name} {input : RawJson}
      (decoded : VariantDecode name value input) : SlotsBounded (variantSlots name value) := by
    cases decoded with
    | unit name value content unit _ =>
        rw [native_unit_variant_slots_empty name value unit]
        exact .nil
    | fields name value fields content inputs _ _ children => exact native_fields_earn_carrier_bounds children
  termination_by structural decoded
end

theorem bounded_text_fits {value : String} (bounded : CarrierBounds .text value) : TextFits value := by
  cases bounded with
  | text _ fits => exact fits

theorem bounded_json_fits {value : NativeCompiler.Json} (bounded : CarrierBounds .json value) : JsonBounds value := by
  cases bounded with
  | json _ bounds => exact bounds

theorem bounded_record_field {name : Record} {value : NativeRecord name}
    (bounded : CarrierBounds (.record name) value) (kind : Kind) (field : NativeKind kind)
    (member : ⟨kind, field⟩ ∈ recordSlots name value) : CarrierBounds kind field := by
  cases bounded with
  | record name value children => exact bounded_slots_each children _ member

theorem bounded_variant_field {name : Enum} {value : NativeEnum name}
    (bounded : CarrierBounds (.internal name) value) (kind : Kind) (field : NativeKind kind)
    (member : ⟨kind, field⟩ ∈ variantSlots name value) : CarrierBounds kind field := by
  cases bounded with
  | internal name value children => exact bounded_slots_each children _ member

theorem bounded_option_present {kind : Kind} {input : Option (NativeKind kind)}
    (bounded : CarrierBounds (.option kind) input) (value : NativeKind kind)
    (present : input = some value) : CarrierBounds kind value := by
  rw [present] at bounded
  cases bounded with
  | present child => exact child

theorem bounded_vector_elements {kind : Kind} {values : NativeVec (NativeKind kind)}
    (bounded : CarrierBounds (.vector kind) values) : ∀ value ∈ values.val, CarrierBounds kind value := by
  cases bounded with
  | vector value children => exact bounded_elements_each children

theorem bounded_map_members {kind : Kind} {values : SourceMap (NativeKind kind)}
    (bounded : CarrierBounds (.map kind) values) :
    ∀ pair ∈ values.entries.val, TextFits pair.1 ∧ CarrierBounds kind pair.2 := by
  cases bounded with
  | map value children ordered => exact bounded_members_each children

end Auths.Product.NativeSerde
