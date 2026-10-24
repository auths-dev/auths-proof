import Auths.Product.NativeCompilerArrayIndex
import Auths.Product.NativeCompilerBodyFields
import Auths.Support.NativeRecipeStringRanges

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def pointerTokenEnd (bytes : List Nat) (start : Nat) : Nat :=
  start + ((bytes.drop start).takeWhile (· != 47)).length

def pointerToken (bytes : List Nat) (start : Nat) : List Nat :=
  (bytes.drop start).takeWhile (· != 47)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.StdModel

theorem take_while_length_bound {A : Type} (test : A → Bool) (values : List A) :
    (values.takeWhile test).length ≤ values.length := by
  induction values with
  | nil => simp
  | cons first rest ih =>
      by_cases admitted : test first
      · simpa [List.takeWhile_cons_of_pos admitted] using Nat.succ_le_succ ih
      · simp [List.takeWhile_cons_of_neg admitted]

theorem take_while_is_take {A : Type} (test : A → Bool) (values : List A) :
    values.takeWhile test = values.take (values.takeWhile test).length := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
      by_cases admitted : test first
      · simp only [List.takeWhile_cons_of_pos admitted, List.length_cons, List.take_succ_cons]
        exact congrArg (List.cons first) ih
      · simp [List.takeWhile_cons_of_neg admitted]

theorem utf8_first_byte_has_native_boundary (byte : UInt8) (valid : byte.IsUTF8FirstByte) :
    byte.toNat < 128 ∨ 192 ≤ byte.toNat := by
  have finite : ∀ index : Fin 256, (UInt8.ofNat index.val).IsUTF8FirstByte →
      index.val < 128 ∨ 192 ≤ index.val := by decide
  exact finite ⟨byte.toNat, UInt8.toNat_lt byte⟩ (by simpa using valid)

/-- A valid character position in the original Lean String earns the native
foreign str-range boundary check. The converse is not asserted: the raw native
byte predicate by itself is not a UTF-8 validity certificate. -/
theorem original_string_boundary (text : String) (fits : TextFits text) (position : Nat)
    (valid : (String.Pos.Raw.mk position).IsValid text) :
    AuthsNativeRecipe.NativeModel.charBoundary (nativeTextView text fits) position = true := by
  rcases String.Pos.Raw.isValid_iff_isUTF8FirstByte.mp valid with ended | ⟨inside, first⟩
  · have endValue : position = text.toByteArray.size := by
      simpa using congrArg String.Pos.Raw.byteIdx ended
    simp [AuthsNativeRecipe.NativeModel.charBoundary, nativeTextView, native_text_length, endValue]
  · have insideValue : position < text.toByteArray.size := by simpa [String.Pos.Raw.lt_iff] using inside
    have byteRange := utf8_first_byte_has_native_boundary (text.getUTF8Byte ⟨position⟩ inside) first
    simp [AuthsNativeRecipe.NativeModel.charBoundary, nativeTextView,
      AuthsNativeRecipe.NativeModel.textBytes, List.getElem?_eq_getElem,
      insideValue, String.getUTF8Byte, byteRange]

theorem original_slash_boundary (text : String) (position : Nat)
    (inside : position < (textBytes text).length) (slash : (textBytes text)[position] = 47) :
    (String.Pos.Raw.mk position).IsValid text := by
  apply String.Pos.Raw.isValid_iff_isUTF8FirstByte.mpr
  have bound : (String.Pos.Raw.mk position) < text.rawEndPos := by
    simpa [String.Pos.Raw.lt_iff, textBytes] using inside
  refine Or.inr ⟨bound, ?_⟩
  have byte : text.getUTF8Byte ⟨position⟩ bound = 47 := by
    apply UInt8.toNat_inj.mp
    simpa [String.getUTF8Byte, textBytes] using slash
  rw [byte]
  decide

/-- ASCII slash is a one-byte scalar. Advancing its real valid String
position earns the boundary after the delimiter, including the end position.
No assumption that an arbitrary byte offset is a character index is used. -/
theorem original_after_slash_boundary (text : String) (position : Nat)
    (inside : position < (textBytes text).length) (slash : (textBytes text)[position] = 47) :
    (String.Pos.Raw.mk (position + 1)).IsValid text := by
  let cursor : text.Pos := ⟨⟨position⟩, original_slash_boundary text position inside slash⟩
  have notEnd : cursor ≠ text.endPos := by
    intro equal
    have same := congrArg (fun p => p.offset.byteIdx) equal
    simp [cursor, textBytes] at inside same
    omega
  have byte : cursor.byte notEnd = 47 := by
    apply UInt8.toNat_inj.mp
    simpa [cursor, String.Pos.byte, String.getUTF8Byte, textBytes] using slash
  have width : (cursor.get notEnd).utf8Size = 1 := by
    rw [← String.Pos.utf8ByteSize_byte]
    simp [byte, UInt8.utf8ByteSize]
  have nextPosition : (cursor.next notEnd).offset = String.Pos.Raw.mk (position + 1) := by
    apply String.Pos.Raw.ext
    simpa [cursor, width] using String.Pos.byteIdx_offset_next cursor notEnd
  simpa only [nextPosition] using (cursor.next notEnd).isValid

theorem pointer_token_end_bounds (bytes : List Nat) (start : Nat) (within : start ≤ bytes.length) :
    start ≤ pointerTokenEnd bytes start ∧ pointerTokenEnd bytes start ≤ bytes.length := by
  have prefixBound := take_while_length_bound (· != 47) (bytes.drop start)
  simp only [List.length_drop] at prefixBound
  simp only [pointerTokenEnd]
  omega

theorem pointer_token_end_delimiter (bytes : List Nat) (start : Nat) (within : start ≤ bytes.length) :
    pointerTokenEnd bytes start = bytes.length ∨
      ∃ inside : pointerTokenEnd bytes start < bytes.length, bytes[pointerTokenEnd bytes start] = 47 := by
  generalize suffixAt : bytes.drop start = suffix
  induction suffix generalizing start with
  | nil =>
      have ended : bytes.length ≤ start := List.drop_eq_nil_iff.mp suffixAt
      exact Or.inl (by simp [pointerTokenEnd, suffixAt]; omega)
  | cons first rest ih =>
      by_cases slash : first = 47
      · have inside : start < bytes.length := by
          by_contra ended
          simp [List.drop_eq_nil_of_le (by omega)] at suffixAt
        have same : bytes[start] = first := by
          simpa using congrArg List.head? suffixAt
        refine Or.inr ⟨by simp [pointerTokenEnd, suffixAt, slash]; omega, ?_⟩
        simpa [pointerTokenEnd, suffixAt, slash] using same.trans slash
      · have inside : start < bytes.length := by
          by_contra ended
          simp [List.drop_eq_nil_of_le (by omega)] at suffixAt
        have tail : bytes.drop (start + 1) = rest := by
          simpa [List.drop_drop] using congrArg (List.drop 1) suffixAt
        have continued := ih (start + 1) (by omega) tail
        simpa [pointerTokenEnd, suffixAt, tail, slash, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using continued

theorem pointer_token_is_span (bytes : List Nat) (start : Nat) :
    pointerToken bytes start = (bytes.drop start).take (pointerTokenEnd bytes start - start) := by
  simpa [pointerToken, pointerTokenEnd] using take_while_is_take (· != 47) (bytes.drop start)

theorem original_token_end_boundary (text : String) (fits : TextFits text) (start : Nat)
    (within : start ≤ (textBytes text).length) :
    AuthsNativeRecipe.NativeModel.charBoundary (nativeTextView text fits)
      (pointerTokenEnd (textBytes text) start) = true := by
  rcases pointer_token_end_delimiter (textBytes text) start within with ended | ⟨inside, slash⟩
  · have nativeEnd : pointerTokenEnd (textBytes text) start = (nativeTextView text fits).val.length := by
      simpa [nativeTextView, native_text_length, textBytes] using ended
    simp [AuthsNativeRecipe.NativeModel.charBoundary, nativeEnd]
  · exact original_string_boundary text fits _ (original_slash_boundary text _ inside slash)

end Auths.Product.NativeCompiler.StdModel

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

@[step] theorem native_pointer_token_end_exact (pointer : Slice Std.U8) (start : Std.Usize)
    (within : start.val ≤ pointer.val.length) :
    AuthsNativeRecipe.recipe.validate.template_at_token_loop pointer start ⦃ actual =>
      actual.val = pointerTokenEnd (schemaSliceBytes pointer) start.val ⦄ := by
  generalize remaining : pointer.val.length - start.val = count
  induction count using Nat.strong_induction_on generalizing start with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.template_at_token_loop
      by_cases inside : start.val < pointer.val.length
      · have nativeInside : start < pointer.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec pointer start inside as ⟨byte, byteAt⟩
        have suffix : (schemaSliceBytes pointer).drop start.val =
            byte.val :: (schemaSliceBytes pointer).drop (start.val + 1) := by
          simpa [schemaSliceBytes, List.drop_map, byteAt] using
            congrArg (List.map (·.val)) (List.drop_eq_getElem_cons inside)
        by_cases slash : byte.val = 47
        · have nativeSlash : byte = 47#u8 := by scalar_tac
          simp [nativeSlash, pointerTokenEnd, suffix, slash]
        · have nativeOther : byte ≠ 47#u8 := by scalar_tac
          simp only [nativeOther, bne_iff_ne, ↓reduceIte]
          step as ⟨next, nextValue⟩
          apply spec_mono (ih _ (by omega) next (by omega) rfl)
          intro actual meaning
          simpa [pointerTokenEnd, suffix, slash, nextValue, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using meaning
      · have nativeEnded : ¬start < pointer.len := by scalar_tac
        have ended : pointer.val.length ≤ start.val := by omega
        simp [nativeEnded, pointerTokenEnd, schemaSliceBytes, List.drop_map, List.drop_eq_nil_of_le ended]

@[step] theorem native_original_pointer_span (text : String) (fits : TextFits text) (start end1 : Std.Usize)
    (within : start.val ≤ (textBytes text).length)
    (boundary : (String.Pos.Raw.mk start.val).IsValid text)
    (endValue : end1.val = pointerTokenEnd (textBytes text) start.val) :
    AuthsNativeRecipe.core.str.Str.get AuthsNativeRecipe.core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexStrStr
      (nativeTextView text fits) ⟨start, end1⟩ ⦃ actual =>
        ∃ token, actual = some token ∧ schemaSliceBytes token = pointerToken (textBytes text) start.val ⦄ := by
  have bounds := pointer_token_end_bounds (textBytes text) start.val within
  have startBoundary := original_string_boundary text fits start.val boundary
  have endBoundary := original_token_end_boundary text fits start.val within
  unfold AuthsNativeRecipe.core.str.Str.get
    AuthsNativeRecipe.core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexStrStr.get
    AuthsNativeRecipe.NativeModel.strRange
  have valid : start.val ≤ end1.val ∧ end1.val ≤ (nativeTextView text fits).val.length ∧
      AuthsNativeRecipe.NativeModel.charBoundary (nativeTextView text fits) start.val = true ∧
      AuthsNativeRecipe.NativeModel.charBoundary (nativeTextView text fits) end1.val = true := by
    simpa [endValue, nativeTextView, native_text_length, textBytes] using
      And.intro bounds.1 (And.intro bounds.2 (And.intro startBoundary endBoundary))
  simp only [dif_pos valid, spec_ok]
  refine ⟨_, rfl, ?_⟩
  simpa [schemaSliceBytes, List.map_take, List.map_drop, native_text_view_bytes,
    endValue] using (pointer_token_is_span (textBytes text) start.val).symm

end Auths.Product.NativeCompiler.Refinement
