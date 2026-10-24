import Auths.Product.NativeCompilerRuleNames
import Auths.Product.NativeCompilerContainers

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def nativeTextView (text : String) (fits : TextFits text) : Str :=
  ⟨AuthsNativeRecipe.NativeModel.textBytes text, by
    simpa [StdModel.native_text_length] using fits⟩

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.StdModel

@[step] theorem native_text_empty_exact (text : String) :
    AuthsNativeRecipe.alloc.string.String.is_empty text ⦃ actual =>
      actual = decide (textBytes text = []) ⦄ := by
  simp [AuthsNativeRecipe.alloc.string.String.is_empty, textBytes, ByteArray.isEmpty,
    List.map_eq_nil_iff, spec_ok]

@[step] theorem native_text_size_exact (text : String) (fits : TextFits text) :
    AuthsNativeRecipe.alloc.string.String.len text ⦃ actual =>
      actual.val = (textBytes text).length ⦄ := by
  simp [AuthsNativeRecipe.alloc.string.String.len, fits, TextFits, textBytes, spec_ok]

/-- Exact native String borrowing, with a usize domain rather than the codec's
separate U32 wire-length bound. No contents or UTF-8 prefix is discarded. -/
@[step] theorem native_deref_text_exact (text : String) (fits : TextFits text) :
    AuthsNativeRecipe.alloc.string.String.Insts.CoreOpsDerefDerefStr.deref text ⦃ actual =>
      actual.val = AuthsNativeRecipe.NativeModel.textBytes text ∧
      schemaSliceBytes actual = textBytes text ⦄ := by
  unfold AuthsNativeRecipe.alloc.string.String.Insts.CoreOpsDerefDerefStr.deref
    AuthsNativeRecipe.alloc.string.String.as_bytes
  have bound : (AuthsNativeRecipe.NativeModel.textBytes text).length ≤ Usize.max := by
    simpa [native_text_length] using fits
  simp [dif_pos bound, schemaSliceBytes, native_text_bytes, spec_ok]

@[step] theorem native_deref_view_exact (text : String) (fits : TextFits text) :
    AuthsNativeRecipe.alloc.string.String.Insts.CoreOpsDerefDerefStr.deref text ⦃ actual =>
      actual = nativeTextView text fits ⦄ := by
  apply spec_mono (native_deref_text_exact text fits)
  rintro actual ⟨original, meaning⟩
  exact Subtype.ext original

theorem native_str_decode_exact (input : Str) :
    Rules.decodeName (schemaSliceBytes input) = String.fromUTF8? (Auths.Codec.StdModel.bytes input) := by
  have range : Rules.ByteRange (schemaSliceBytes input) := by
    intro byte member
    obtain ⟨original, _, rfl⟩ := List.mem_map.mp member
    scalar_tac
  have same : Rules.nameBytes (schemaSliceBytes input) = Auths.Codec.StdModel.bytes input := by
    simp only [Rules.nameBytes, schemaSliceBytes, Auths.Codec.StdModel.bytes, List.map_map]
    rfl
  simp only [Rules.decodeName, if_pos range, same]

/-- Accepted lexical bytes earn UTF-8 reconstruction; conversion success is
not a premise. The input token may still be refused by a separate policy. -/
@[step] theorem native_token_owned_exact (input : Str) (maximum : Nat)
    (token : OperationIdentity.validToken (schemaSliceBytes input) maximum = true) :
    AuthsNativeRecipe.Str.Insts.AllocBorrowToOwnedString.to_owned input ⦃ owned =>
      textBytes owned = schemaSliceBytes input ⦄ := by
  obtain ⟨name, decoded, original⟩ := Rules.ascii_has_lossless_name (schemaSliceBytes input)
    (Rules.token_bytes_are_ascii (schemaSliceBytes input) maximum token)
  have libraryDecode : String.fromUTF8? (Auths.Codec.StdModel.bytes input) = some name := by
    rw [← native_str_decode_exact]
    exact decoded
  simp [AuthsNativeRecipe.Str.Insts.AllocBorrowToOwnedString.to_owned,
    libraryDecode, spec_ok, original]

/-- The complete native UTF-8 conversion is lossless whenever it returns.
This observation grants no lexical, source, host or namespace admission. -/
theorem native_owned_success_keeps_bytes (input : Str) (owned : String)
    (completed : AuthsNativeRecipe.Str.Insts.AllocBorrowToOwnedString.to_owned input = ok owned) :
    textBytes owned = schemaSliceBytes input := by
  unfold AuthsNativeRecipe.Str.Insts.AllocBorrowToOwnedString.to_owned at completed
  cases decoded : String.fromUTF8? (Auths.Codec.StdModel.bytes input) with
  | none => simp [decoded] at completed
  | some text =>
      have same : text = owned := by simpa [decoded] using completed
      subst owned
      apply Rules.decoded_name_has_original_bytes (schemaSliceBytes input) text
      rw [native_str_decode_exact]
      exact decoded

/-- URL str projections carry UTF-8 validity, not host admission. Owning such
a projection preserves all bytes and earns the native String size domain. -/
@[step] theorem native_utf8_owned_exact (input : AuthsNativeRecipe.NativeModel.Utf8Str) :
    AuthsNativeRecipe.Str.Insts.AllocBorrowToOwnedString.to_owned input.val ⦃ owned =>
      textBytes owned = schemaSliceBytes input.val ∧ TextFits owned ⦄ := by
  have valid : (String.fromUTF8? (Auths.Codec.StdModel.bytes input.val)).isSome = true := by
    simpa only [AuthsNativeRecipe.NativeModel.rawByteArray, Auths.Codec.StdModel.bytes] using input.property
  cases decoded : String.fromUTF8? (Auths.Codec.StdModel.bytes input.val) with
  | none => simp [decoded] at valid
  | some owned =>
      have copied : AuthsNativeRecipe.Str.Insts.AllocBorrowToOwnedString.to_owned input.val = ok owned := by
        simp [AuthsNativeRecipe.Str.Insts.AllocBorrowToOwnedString.to_owned, decoded]
      have original := native_owned_success_keeps_bytes input.val owned copied
      have size : owned.toByteArray.size = input.val.val.length := by
        simpa [textBytes, schemaSliceBytes] using congrArg List.length original
      have fits : TextFits owned := by
        unfold TextFits
        rw [size]
        exact input.val.property
      simp [copied, spec_ok, original, fits]

end Auths.Product.NativeCompiler.StdModel
