import Auths.Product.SerdeFieldUniqueness
import Auths.Product.NativeSerdeBounds

/-!
Full decoded meaning plus the original strict preflight earns recursive
native map uniqueness, including generic JSON literals. This is separate from
word/string representation bounds and admission. Actual serde implementation
adequacy is still required to establish Decode from original input bytes.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar SerdeFieldLayout NativeCompiler
open Aeneas Aeneas.Std

def JsonUnique (value : NativeCompiler.Json) : Prop :=
  ∃ original, FullJsonMeaning value original ∧ FullJsonValue.Unique original

theorem json_unique_earns_original_uniqueness (value : NativeCompiler.Json)
    (unique : JsonUnique value) (original : FullJsonValue.Value)
    (meaning : FullJsonMeaning value original) : FullJsonValue.Unique original := by
  obtain ⟨witness, witnessMeaning, witnessUnique⟩ := unique
  rw [← full_json_meaning_unique witnessMeaning meaning]
  exact witnessUnique

mutual
  inductive CarrierUnique : (kind : Kind) → NativeKind kind → Prop where
    | text (value : String) : CarrierUnique .text value
    | boolean (value : Bool) : CarrierUnique .boolean value
    | signed (value : Std.I64) : CarrierUnique .signed64 value
    | unsigned8 (value : Std.U8) : CarrierUnique .unsigned8 value
    | unsigned16 (value : Std.U16) : CarrierUnique .unsigned16 value
    | unsigned (value : Std.U64) : CarrierUnique .unsigned64 value
    | word (value : Std.Usize) : CarrierUnique .word value
    | json (value : NativeCompiler.Json) (original : JsonUnique value) : CarrierUnique .json value
    | absent (kind : Kind) : CarrierUnique (.option kind) none
    | present {kind : Kind} {value : NativeKind kind} (child : CarrierUnique kind value) :
        CarrierUnique (.option kind) (some value)
    | vector {kind : Kind} (value : NativeVec (NativeKind kind)) (children : ElementsUnique kind value.val) :
        CarrierUnique (.vector kind) value
    | map {kind : Kind} (value : SourceMap (NativeKind kind))
        (names : (value.entries.val.map Prod.fst).Nodup) (children : MembersUnique kind value.entries.val) :
        CarrierUnique (.map kind) value
    | record (name : Record) (value : NativeRecord name) (children : SlotsUnique (recordSlots name value)) :
        CarrierUnique (.record name) value
    | internal (name : Enum) (value : NativeEnum name) (children : SlotsUnique (variantSlots name value)) :
        CarrierUnique (.internal name) value
    | writeMethod (value : AuthsNativeRecipe.recipe.WriteMethod) : CarrierUnique .writeMethod value

  inductive ElementsUnique : (kind : Kind) → List (NativeKind kind) → Prop where
    | nil (kind : Kind) : ElementsUnique kind []
    | cons {kind : Kind} {value : NativeKind kind} {rest : List (NativeKind kind)}
        (head : CarrierUnique kind value) (tail : ElementsUnique kind rest) : ElementsUnique kind (value :: rest)

  inductive MembersUnique : (kind : Kind) → List (String × NativeKind kind) → Prop where
    | nil (kind : Kind) : MembersUnique kind []
    | cons {kind : Kind} {name : String} {value : NativeKind kind} {rest : List (String × NativeKind kind)}
        (head : CarrierUnique kind value) (tail : MembersUnique kind rest) :
        MembersUnique kind ((name, value) :: rest)

  inductive SlotsUnique : List Slot → Prop where
    | nil : SlotsUnique []
    | cons {slot : Slot} {rest : List Slot} (head : CarrierUnique slot.kind slot.value)
        (tail : SlotsUnique rest) : SlotsUnique (slot :: rest)
end

theorem unique_members_each {kind : Kind} {members : List (String × NativeKind kind)}
    (unique : MembersUnique kind members) : ∀ pair ∈ members, CarrierUnique kind pair.2 := by
  induction unique with
  | nil => simp
  | cons head tail ih =>
      intro pair member
      rcases List.mem_cons.mp member with rfl | later
      · exact head
      · exact ih pair later

private theorem members_unique_from_each (kind : Kind) (members : List (String × NativeKind kind))
    (each : ∀ pair ∈ members, CarrierUnique kind pair.2) : MembersUnique kind members := by
  revert each
  induction members with
  | nil => intro _; exact .nil kind
  | cons first rest ih =>
      intro each
      have head := each first (by simp)
      have tail := ih (fun pair member => each pair (List.mem_cons_of_mem _ member))
      cases first
      exact .cons head tail

theorem unique_members_permutation {kind : Kind} {first second : List (String × NativeKind kind)}
    (unique : MembersUnique kind first) (retained : first.Perm second) : MembersUnique kind second := by
  apply members_unique_from_each
  intro pair member
  exact unique_members_each unique pair (retained.mem_iff.mpr member)

theorem unique_elements_each {kind : Kind} {values : List (NativeKind kind)}
    (unique : ElementsUnique kind values) : ∀ value ∈ values, CarrierUnique kind value := by
  induction unique with
  | nil => simp
  | cons head tail ih =>
      intro value member
      rcases List.mem_cons.mp member with rfl | later
      · exact head
      · exact ih value later

theorem unique_slots_each {values : List Slot} (unique : SlotsUnique values) :
    ∀ slot ∈ values, CarrierUnique slot.kind slot.value := by
  induction unique with
  | nil => simp
  | cons head tail ih =>
      intro slot member
      rcases List.mem_cons.mp member with rfl | later
      · exact head
      · exact ih slot later

mutual
  theorem native_decode_earns_carrier_uniqueness {mode : Mode} {kind : Kind} {input : RawJson}
      {value : NativeKind kind} (decoded : Decode mode kind input value)
      (original : FullJsonValue.Unique input) : CarrierUnique kind value := by
    cases decoded with
    | text mode value fits => exact .text value
    | boolean mode value => exact .boolean value
    | signed mode number value decoded => exact .signed value
    | unsigned8 mode number value decoded => exact .unsigned8 value
    | unsigned16 mode number value decoded => exact .unsigned16 value
    | unsigned mode number value decoded => exact .unsigned value
    | word mode number value decoded => exact .word value
    | json mode input value meaning bounds => exact .json value ⟨input, meaning, original⟩
    | absent mode kind => exact .absent kind
    | present notNull child => exact .present (native_decode_earns_carrier_uniqueness child original)
    | vector children =>
        exact .vector _ (native_values_earn_carrier_uniqueness children
          ((FullJsonValue.array_unique_iff _).mp original))
    | map sourceOrder children ordered retained =>
        obtain ⟨originalNames, each⟩ := (FullJsonValue.object_unique_iff _).mp original
        have sourceNames : (sourceOrder.map Prod.fst).Nodup := by
          rw [native_members_keep_full_names children]
          exact originalNames
        exact .map _ ((retained.map Prod.fst).nodup sourceNames)
          (unique_members_permutation (native_members_earn_carrier_uniqueness children each) retained)
    | record value fields bound children =>
        exact .record _ value (native_fields_earn_carrier_uniqueness children
          (normalization_keeps_unique_values _ _ _ original bound))
    | internal value selected child =>
        exact .internal _ value (native_variant_earns_carrier_uniqueness child
          (internal_keeps_unique_content _ _ _ _ _ original selected))
    | writeMethod mode input value selected => exact .writeMethod value
  termination_by structural decoded

  theorem native_values_earn_carrier_uniqueness {mode : Mode} {kind : Kind} {inputs : List RawJson}
      {values : List (NativeKind kind)} (decoded : ValuesDecode mode kind inputs values)
      (original : ∀ input ∈ inputs, FullJsonValue.Unique input) : ElementsUnique kind values := by
    cases decoded with
    | nil mode kind => exact .nil kind
    | cons head tail =>
        exact .cons (native_decode_earns_carrier_uniqueness head (original _ (by simp)))
          (native_values_earn_carrier_uniqueness tail
            (fun input member => original input (List.mem_cons_of_mem _ member)))
  termination_by structural decoded

  theorem native_members_earn_carrier_uniqueness {mode : Mode} {kind : Kind}
      {inputs : List (String × RawJson)} {values : List (String × NativeKind kind)}
      (decoded : MembersDecode mode kind inputs values)
      (original : ∀ input ∈ inputs, FullJsonValue.Unique input.2) : MembersUnique kind values := by
    cases decoded with
    | nil mode kind => exact .nil kind
    | cons fits head tail =>
        exact .cons (native_decode_earns_carrier_uniqueness head (original _ (by simp)))
          (native_members_earn_carrier_uniqueness tail
            (fun input member => original input (List.mem_cons_of_mem _ member)))
  termination_by structural decoded

  theorem native_fields_earn_carrier_uniqueness {mode : Mode} {fields : Fields} {inputs : List RawJson}
      {values : List Slot} (decoded : FieldsDecode mode fields inputs values)
      (original : ∀ input ∈ inputs, FullJsonValue.Unique input) : SlotsUnique values := by
    cases decoded with
    | nil mode => exact .nil
    | cons head tail =>
        exact .cons (native_decode_earns_carrier_uniqueness head (original _ (by simp)))
          (native_fields_earn_carrier_uniqueness tail
            (fun input member => original input (List.mem_cons_of_mem _ member)))
  termination_by structural decoded

  theorem native_variant_earns_carrier_uniqueness {name : Enum} {value : NativeEnum name} {input : RawJson}
      (decoded : VariantDecode name value input) (original : FullJsonValue.Unique input) :
      SlotsUnique (variantSlots name value) := by
    cases decoded with
    | unit name value content unit accepted =>
        rw [native_unit_variant_slots_empty name value unit]
        exact .nil
    | fields name value fields content inputs declared bound children =>
        exact native_fields_earn_carrier_uniqueness children
          (normalization_keeps_unique_values _ _ _ original bound)
  termination_by structural decoded
end

theorem unique_record_field {name : Record} {value : NativeRecord name}
    (unique : CarrierUnique (.record name) value) (kind : Kind) (field : NativeKind kind)
    (member : ⟨kind, field⟩ ∈ recordSlots name value) : CarrierUnique kind field := by
  cases unique with
  | record name value children => exact unique_slots_each children _ member

theorem unique_variant_field {name : Enum} {value : NativeEnum name}
    (unique : CarrierUnique (.internal name) value) (kind : Kind) (field : NativeKind kind)
    (member : ⟨kind, field⟩ ∈ variantSlots name value) : CarrierUnique kind field := by
  cases unique with
  | internal name value children => exact unique_slots_each children _ member

theorem unique_option_present {kind : Kind} {input : Option (NativeKind kind)}
    (unique : CarrierUnique (.option kind) input) (value : NativeKind kind)
    (present : input = some value) : CarrierUnique kind value := by
  rw [present] at unique
  cases unique with
  | present child => exact child

theorem unique_json_original {value : NativeCompiler.Json} (unique : CarrierUnique .json value) : JsonUnique value := by
  cases unique with
  | json value original => exact original

theorem decoded_source_earns_carrier_uniqueness (raw : RawJson) (input : NativeRecord .recipe)
    (original : SourceMeaning raw input) : CarrierUnique (.record .recipe) input :=
  native_decode_earns_carrier_uniqueness original.2
    (FullJsonValue.check_earns_full_uniqueness raw original.1)

theorem decoded_lock_earns_carrier_uniqueness (raw : RawJson) (input : NativeRecord .lock)
    (original : LockMeaning raw input) : CarrierUnique (.record .lock) input :=
  native_decode_earns_carrier_uniqueness original.2
    (FullJsonValue.check_earns_full_uniqueness raw original.1)

end Auths.Product.NativeSerde
