import Auths.Product.ScalarProjection
import Auths.Product.ArgumentBindingRefinement

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.SchemaIndex.Refinement

namespace Auths.Product.ScalarProjection.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

@[step] theorem string_schema_exact (minimum maximum : Std.Usize) :
    scalars.string_schema_valid minimum maximum ⦃ actual =>
      actual = decide (StringSchema minimum.val maximum.val) ⦄ := by
  simp [scalars.string_schema_valid, scalars.MAX_TEXT_BYTES, StringSchema,
    UScalar.le_equiv, spec_ok, Bool.and_eq_true, decide_and]

@[step] theorem string_scan_exact (text : Slice Std.U8) :
    scalars.string_value_valid_loop text 0#usize ⦃ actual =>
      actual = decide (0 ∉ sliceBytes text) ⦄ := by
  unfold scalars.string_value_valid_loop
  apply loop.spec_decr_nat
    (measure := fun index => text.val.length - index.val)
    (inv := fun index => index.val ≤ text.val.length ∧
      ∀ byte ∈ text.val.take index.val, byte.val ≠ 0)
  · intro index invariant
    unfold scalars.string_value_valid_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < text.val.length := by simpa using within
      step as ⟨byte, byteAt⟩
      by_cases zero : byte = 0#u8
      · have member : byte ∈ text.val := List.mem_iff_getElem?.mpr
          ⟨index.val, by simpa [byteAt] using List.getElem?_eq_getElem inside⟩
        have zeroMember : 0 ∈ sliceBytes text := by
          exact List.mem_map.mpr ⟨byte, member, by simp [zero]⟩
        simp [zero, zeroMember]
      · simp only [zero, ↓reduceIte]
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        rw [nextValue, List.take_succ_eq_append_getElem inside]
        intro current member
        simp only [List.mem_append, List.mem_singleton] at member
        rcases member with earlier | current
        · exact invariant.2 _ earlier
        · have same : current = byte := by simpa [byteAt] using current
          subst current
          intro numericZero
          exact zero (UScalar.eq_of_val_eq (by simpa using numericZero))
    · simp only [spec_ok]
      have atEnd : text.val.length ≤ index.val := by simpa using within
      have absent : 0 ∉ sliceBytes text := by
        intro member
        obtain ⟨byte, member, zero⟩ := List.mem_map.mp member
        exact invariant.2 byte (by simpa [List.take_of_length_le atEnd] using member) zero
      simp [absent]
  · exact ⟨by simp, by simp⟩

@[step] theorem string_valid_exact (minimum maximum : Std.Usize) (text : Slice Std.U8) :
    scalars.string_value_valid minimum maximum text ⦃ actual =>
      actual = decide (StringValue minimum.val maximum.val (sliceBytes text)) ⦄ := by
  unfold scalars.string_value_valid
  step with string_schema_exact as ⟨schema, schemaMeaning⟩
  cases schema
  · have invalid : ¬StringSchema minimum.val maximum.val := by simpa using schemaMeaning.symm
    simp [invalid, StringValue]
  · have valid : StringSchema minimum.val maximum.val := by simpa using schemaMeaning.symm
    by_cases short : text.val.length < minimum.val
    · have nativeShort : text.len < minimum := by scalar_tac
      simp [nativeShort, StringValue, sliceBytes, byteList, valid, short, Nat.not_le.mpr short]
    · have nativeLongEnough : ¬text.len < minimum := by scalar_tac
      by_cases long : maximum.val < text.val.length
      · have nativeLong : text.len > maximum := by scalar_tac
        simp [nativeLongEnough, nativeLong, StringValue, sliceBytes, byteList, valid, long, Nat.not_le.mpr long]
      · have nativeBound : ¬text.len > maximum := by scalar_tac
        simp only [nativeLongEnough, nativeBound, Bool.false_or, ↓reduceIte]
        step with string_scan_exact as ⟨actual, meaning⟩
        simpa [StringValue, valid, sliceBytes, byteList, Nat.le_of_not_gt short, Nat.le_of_not_gt long] using meaning

@[step] theorem enum_byte_exact (byte : Std.U8) :
    scalars.enum_byte_valid byte ⦃ actual => actual = decide (EnumByte byte.val) ⦄ := by
  unfold scalars.enum_byte_valid
  step with is_alphanumeric_spec as ⟨alphanumeric, meaning⟩
  simp [meaning, EnumByte, RequestConstruction.alphanumeric,
    UScalar.eq_equiv, UScalar.le_equiv, Bool.or_eq_true, Bool.and_eq_true]

@[step] theorem enum_scan_exact (text : Slice Std.U8) :
    scalars.enum_variant_valid_loop text 0#usize ⦃ actual =>
      actual = decide (∀ byte ∈ sliceBytes text, EnumByte byte) ⦄ := by
  unfold scalars.enum_variant_valid_loop
  apply loop.spec_decr_nat
    (measure := fun index => text.val.length - index.val)
    (inv := fun index => index.val ≤ text.val.length ∧
      ∀ byte ∈ text.val.take index.val, EnumByte byte.val)
  · intro index invariant
    unfold scalars.enum_variant_valid_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < text.val.length := by simpa using within
      step as ⟨byte, byteAt⟩
      step with enum_byte_exact as ⟨allowed, allowedMeaning⟩
      cases allowed
      · have invalid : ¬EnumByte byte.val := by simpa using allowedMeaning.symm
        have member : byte.val ∈ sliceBytes text := List.mem_map.mpr
          ⟨byte, List.mem_iff_getElem?.mpr ⟨index.val, by simpa [byteAt] using List.getElem?_eq_getElem inside⟩, rfl⟩
        have refused : ¬∀ current ∈ sliceBytes text, EnumByte current := fun all => invalid (all _ member)
        simp [refused]
      · have valid : EnumByte byte.val := by simpa using allowedMeaning.symm
        simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        rw [nextValue, List.take_succ_eq_append_getElem inside]
        intro current member
        simp only [List.mem_append, List.mem_singleton] at member
        rcases member with earlier | current
        · exact invariant.2 _ earlier
        · simpa [current, byteAt] using valid
    · simp only [spec_ok]
      have atEnd : text.val.length ≤ index.val := by simpa using within
      have valid : ∀ byte ∈ sliceBytes text, EnumByte byte := by
        intro byte member
        obtain ⟨current, member, same⟩ := List.mem_map.mp member
        simpa [same] using invariant.2 current (by simpa [List.take_of_length_le atEnd] using member)
      simp [valid]
  · exact ⟨by simp, by simp⟩

@[step] theorem enum_variant_exact (text : Slice Std.U8) :
    scalars.enum_variant_valid text ⦃ actual => actual = decide (EnumVariant (sliceBytes text)) ⦄ := by
  unfold scalars.enum_variant_valid scalars.MAX_ENUM_BYTES
  dsimp only
  by_cases empty : text.val = []
  · simp [empty, core.slice.Slice.is_empty, EnumVariant, sliceBytes, byteList]
  · have nonempty : 0 < text.val.length := List.length_pos.mpr empty
    by_cases long : 64 < text.val.length
    · have nativeLong : text.len > 64#usize := by scalar_tac
      simp [nativeLong, EnumVariant, sliceBytes, byteList, Nat.not_le.mpr long]
    · have nativeBound : ¬text.len > 64#usize := by scalar_tac
      simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false, Bool.false_or, nativeBound, ↓reduceIte]
      step with enum_scan_exact as ⟨actual, meaning⟩
      simpa [EnumVariant, sliceBytes, byteList, nonempty, Nat.le_of_not_gt long] using meaning

@[step] theorem enum_schema_scan_exact (variants : Slice (alloc.vec.Vec Std.U8)) :
    scalars.enum_schema_valid_loop variants 0#usize ⦃ actual =>
      actual = decide (∀ text ∈ namesView variants, EnumVariant text) ⦄ := by
  unfold scalars.enum_schema_valid_loop
  apply loop.spec_decr_nat
    (measure := fun index => variants.val.length - index.val)
    (inv := fun index => index.val ≤ variants.val.length ∧
      ∀ text ∈ variants.val.take index.val, EnumVariant (vecBytes text))
  · intro index invariant
    unfold scalars.enum_schema_valid_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < variants.val.length := by simpa using within
      step as ⟨variant, variantAt⟩
      step with enum_variant_exact as ⟨allowed, meaning⟩
      cases allowed
      · have invalid : ¬EnumVariant (vecBytes variant) := by simpa [alloc.vec.Vec.deref, sliceBytes] using meaning.symm
        have member : vecBytes variant ∈ namesView variants := List.mem_map.mpr
          ⟨variant, List.mem_iff_getElem?.mpr ⟨index.val, by simpa [variantAt] using List.getElem?_eq_getElem inside⟩, rfl⟩
        have refused : ¬∀ text ∈ namesView variants, EnumVariant text := fun all => invalid (all _ member)
        simp [refused]
      · have valid : EnumVariant (vecBytes variant) := by simpa [alloc.vec.Vec.deref, sliceBytes] using meaning.symm
        simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        rw [nextValue, List.take_succ_eq_append_getElem inside]
        intro text member
        simp only [List.mem_append, List.mem_singleton] at member
        rcases member with earlier | current
        · exact invariant.2 _ earlier
        · simpa [current, variantAt] using valid
    · simp only [spec_ok]
      have atEnd : variants.val.length ≤ index.val := by simpa using within
      have valid : ∀ text ∈ namesView variants, EnumVariant text := by
        intro text member
        obtain ⟨variant, member, same⟩ := List.mem_map.mp member
        simpa [same] using invariant.2 variant (by simpa [List.take_of_length_le atEnd] using member)
      simp [valid]
  · exact ⟨by simp, by simp⟩

@[step] theorem enum_schema_exact (variants : Slice (alloc.vec.Vec Std.U8)) :
    scalars.enum_schema_valid variants ⦃ actual =>
      actual = decide (EnumSchema (namesView variants)) ⦄ := by
  unfold scalars.enum_schema_valid scalars.MAX_ENUM_VARIANTS
  dsimp only
  by_cases empty : variants.val = []
  · simp [empty, core.slice.Slice.is_empty, EnumSchema, namesView]
  · have nonempty : 0 < variants.val.length := List.length_pos.mpr empty
    by_cases long : 32 < variants.val.length
    · have nativeLong : variants.len > 32#usize := by scalar_tac
      simp [nativeLong, EnumSchema, namesView, Nat.not_le.mpr long]
    · have nativeBound : ¬variants.len > 32#usize := by scalar_tac
      simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false, Bool.false_or, nativeBound, ↓reduceIte]
      step with ArgumentBinding.Refinement.unique_fields_exact as ⟨unique, uniqueMeaning⟩
      cases unique
      · have repeated : ¬(namesView variants).Nodup := by simpa using uniqueMeaning.symm
        simp [EnumSchema, repeated]
      · have unique : (namesView variants).Nodup := by simpa using uniqueMeaning.symm
        step with enum_schema_scan_exact as ⟨actual, meaning⟩
        simpa [EnumSchema, namesView, nonempty, Nat.le_of_not_gt long, unique] using meaning

@[step] theorem enum_valid_exact (variants : Slice (alloc.vec.Vec Std.U8)) (text : Slice Std.U8) :
    scalars.enum_value_valid variants text ⦃ actual =>
      actual = decide (EnumValue (namesView variants) (sliceBytes text)) ⦄ := by
  unfold scalars.enum_value_valid
  step with enum_schema_exact as ⟨schema, meaning⟩
  cases schema
  · have invalid : ¬EnumSchema (namesView variants) := by simpa using meaning.symm
    simp [EnumValue, invalid]
  · have valid : EnumSchema (namesView variants) := by simpa using meaning.symm
    step with field_index_spec as ⟨index, indexMeaning⟩
    cases index with
    | none =>
      have absent : sliceBytes text ∉ namesView variants := (SchemaIndex.absent_iff _ _).mp indexMeaning.symm
      simp [core.option.Option.is_some, EnumValue, valid, absent]
    | some position =>
      have indexed := SchemaIndex.position_points_to_name _ _ _ indexMeaning.symm
      have present : sliceBytes text ∈ namesView variants := List.mem_iff_getElem?.mpr ⟨position.val, indexed⟩
      simp [core.option.Option.is_some, EnumValue, valid, present]

@[step] theorem integer_schema_exact (minimum maximum : Std.I64) :
    scalars.integer_schema_valid minimum maximum ⦃ actual =>
      actual = decide (IntegerSchema minimum.val maximum.val) ⦄ := by
  simp [scalars.integer_schema_valid, scalars.MAX_JSON_INTEGER, IntegerSchema,
    IScalar.le_equiv, spec_ok, Bool.and_eq_true, decide_and]

@[step] theorem integer_valid_exact (minimum maximum value : Std.I64) :
    scalars.integer_value_valid minimum maximum value ⦃ actual =>
      actual = decide (IntegerValue minimum.val maximum.val value.val) ⦄ := by
  unfold scalars.integer_value_valid
  step with integer_schema_exact as ⟨schema, meaning⟩
  simp [meaning, IntegerValue, IScalar.le_equiv, Bool.and_eq_true, decide_and]

@[step] theorem string_projection_exact (minimum maximum : Std.Usize) (text : Slice Std.U8) :
    scalars.string_value minimum maximum text ⦃ actual =>
      actual.map argOf = if StringValue minimum.val maximum.val (sliceBytes text)
        then some (.text (sliceBytes text)) else none ⦄ := by
  unfold scalars.string_value
  step with string_valid_exact as ⟨valid, meaning⟩
  cases valid
  · have invalid : ¬StringValue minimum.val maximum.val (sliceBytes text) := by simpa using meaning.symm
    simp [invalid]
  · have valid : StringValue minimum.val maximum.val (sliceBytes text) := by simpa using meaning.symm
    have bound := accepted_string_bound _ _ _ valid
    have fits : text.val.length < 4294967295 := by simp [sliceBytes, byteList] at bound; omega
    step with copy_bytes_spec as ⟨copied, same⟩
    simp [valid, argOf, vecBytes, sliceBytes, same]

@[step] theorem enum_projection_exact (variants : Slice (alloc.vec.Vec Std.U8)) (text : Slice Std.U8) :
    scalars.enum_value variants text ⦃ actual =>
      actual.map argOf = if EnumValue (namesView variants) (sliceBytes text)
        then some (.text (sliceBytes text)) else none ⦄ := by
  unfold scalars.enum_value
  step with enum_valid_exact as ⟨valid, meaning⟩
  cases valid
  · have invalid : ¬EnumValue (namesView variants) (sliceBytes text) := by simpa using meaning.symm
    simp [invalid]
  · have valid : EnumValue (namesView variants) (sliceBytes text) := by simpa using meaning.symm
    have bound := accepted_enum_bound _ _ valid
    have fits : text.val.length < 4294967295 := by simp [sliceBytes, byteList] at bound; omega
    step with copy_bytes_spec as ⟨copied, same⟩
    simp [valid, argOf, vecBytes, sliceBytes, same]

end Auths.Product.ScalarProjection.Refinement
