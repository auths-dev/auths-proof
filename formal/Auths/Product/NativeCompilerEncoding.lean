import Auths.Product.NativeCompilerConstruction
import Auths.Product.BodyCompilerBounds

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RequestConstruction
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

@[step] theorem native_form_literal_exact (byte : Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.is_form_literal byte ⦃ actual =>
      actual = formLiteral byte.val ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.is_form_literal
  step with native_schema_alphanumeric_exact byte as ⟨alpha, meaning⟩
  repeat' split
  all_goals simp_all [formLiteral, alphanumeric, OperationIdentity.Alphanumeric,
    UScalar.eq_equiv, Bool.eq_iff_iff]

@[step] theorem native_hex_upper_exact (nibble : Std.U8) (small : nibble.val < 16) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.hex_upper nibble ⦃ actual =>
      actual.val = hexUpper nibble.val ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.hex_upper hexUpper
  by_cases low : nibble.val < 10
  · have nativeLow : nibble < 10#u8 := by scalar_tac
    simp only [nativeLow, low, ↓reduceIte]
    step as ⟨actual, exact⟩
    omega
  · have nativeHigh : ¬nibble < 10#u8 := by scalar_tac
    simp only [nativeHigh, low, ↓reduceIte]
    step as ⟨shifted, shiftedMeaning⟩
    step as ⟨actual, exact⟩
    omega

@[step] theorem native_hex_lower_exact (nibble : Std.U8) (small : nibble.val < 16) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.hex_lower nibble ⦃ actual =>
      actual.val = hexLower nibble.val ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.hex_lower hexLower
  by_cases low : nibble.val < 10
  · have nativeLow : nibble < 10#u8 := by scalar_tac
    simp only [nativeLow, low, ↓reduceIte]
    step as ⟨actual, exact⟩
    omega
  · have nativeHigh : ¬nibble < 10#u8 := by scalar_tac
    simp only [nativeHigh, low, ↓reduceIte]
    step as ⟨shifted, shiftedMeaning⟩
    step as ⟨actual, exact⟩
    omega

private theorem native_pair_push (output : NativeVec Std.U8) (first second : Std.U8)
    (room : output.val.length + 2 ≤ Usize.max) :
    (do
      let prefix ← AuthsNativeRecipe.alloc.vec.Vec.push output first
      AuthsNativeRecipe.alloc.vec.Vec.push prefix second) ⦃ actual =>
        bytes actual = bytes output ++ [first.val, second.val] ⦄ := by
  step with native_push_exact output first (by omega) as ⟨prefix, prefixMeaning⟩
  have capacity : prefix.val.length < Usize.max := by
    simp only [prefixMeaning, List.length_append, List.length_singleton]
    omega
  step with native_push_exact prefix second capacity as ⟨actual, exact⟩
  simp [bytes, exact, prefixMeaning, List.map_append, List.append_assoc]

@[step] theorem native_percent_exact (output : NativeVec Std.U8) (byte : Std.U8)
    (room : output.val.length + 3 ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.append_percent output byte ⦃ actual =>
      bytes actual = bytes output ++ percent byte.val ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.append_percent
  step with native_push_exact output 37#u8 (by omega) as ⟨prefix, prefixMeaning⟩
  step as ⟨high, highMeaning⟩
  step with native_hex_upper_exact high (by have := byte.property; scalar_tac) as ⟨highDigit, highDigitMeaning⟩
  have highRoom : prefix.val.length < Usize.max := by
    simp only [prefixMeaning, List.length_append, List.length_singleton]
    omega
  step with native_push_exact prefix highDigit highRoom as ⟨middle, middleMeaning⟩
  step as ⟨low, lowMeaning⟩
  step with native_hex_upper_exact low (by have := byte.property; scalar_tac) as ⟨lowDigit, lowDigitMeaning⟩
  have lowRoom : middle.val.length < Usize.max := by
    simp only [middleMeaning, prefixMeaning, List.length_append, List.length_singleton]
    omega
  step with native_push_exact middle lowDigit lowRoom as ⟨actual, exact⟩
  simp [bytes, exact, middleMeaning, prefixMeaning, List.map_append, List.append_assoc,
    percent, highDigitMeaning, lowDigitMeaning, highMeaning, lowMeaning]

@[step] theorem native_form_byte_exact (output : NativeVec Std.U8) (byte : Std.U8)
    (room : output.val.length + (formByte byte.val).length ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.append_form_byte output byte ⦃ actual =>
      bytes actual = bytes output ++ formByte byte.val ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.append_form_byte
  by_cases space : byte.val = 32
  · have nativeSpace : byte = 32#u8 := by scalar_tac
    have capacity : output.val.length < Usize.max := by simp [formByte, space] at room; omega
    simp only [nativeSpace, ↓reduceIte]
    step with native_push_exact output 43#u8 capacity as ⟨actual, exact⟩
    simp [bytes, exact, formByte, space, List.map_append]
  · have nativeNotSpace : byte ≠ 32#u8 := by scalar_tac
    simp only [nativeNotSpace, ↓reduceIte]
    step with native_form_literal_exact byte as ⟨literal, literalMeaning⟩
    cases literal with
    | true =>
        have capacity : output.val.length < Usize.max := by
          simp [formByte, space, ← literalMeaning] at room
          omega
        simp only [Bool.true_eq_true, ↓reduceIte]
        step with native_push_exact output byte capacity as ⟨actual, exact⟩
        simp [bytes, exact, formByte, space, ← literalMeaning, List.map_append]
    | false =>
        have capacity : output.val.length + 3 ≤ Usize.max := by
          simpa [formByte, space, ← literalMeaning, percent] using room
        simp only [Bool.false_eq_true, ↓reduceIte]
        apply spec_mono (native_percent_exact output byte capacity)
        intro actual exact
        simpa [formByte, space, ← literalMeaning] using exact

@[step] theorem native_json_byte_exact (output : NativeVec Std.U8) (byte : Std.U8)
    (room : output.val.length + (jsonByte byte.val).length ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.append_json_byte output byte ⦃ actual =>
      bytes actual = bytes output ++ jsonByte byte.val ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.append_json_byte
  by_cases quote : byte.val = 34
  · have nativeQuote : byte = 34#u8 := by scalar_tac
    simp only [nativeQuote, ↓reduceIte]
    apply spec_mono (native_pair_push output 92#u8 byte (by simp [jsonByte, quote] at room; omega))
    intro actual exact
    simpa [jsonByte, quote] using exact
  have nativeNotQuote : byte ≠ 34#u8 := by scalar_tac
  simp only [nativeNotQuote, ↓reduceIte]
  by_cases slash : byte.val = 92
  · have nativeSlash : byte = 92#u8 := by scalar_tac
    simp only [nativeSlash, ↓reduceIte]
    apply spec_mono (native_pair_push output 92#u8 byte (by simp [jsonByte, slash] at room; omega))
    intro actual exact
    simpa [jsonByte, slash] using exact
  have nativeNotSlash : byte ≠ 92#u8 := by scalar_tac
  simp only [nativeNotSlash, ↓reduceIte]
  by_cases backspace : byte.val = 8
  · have nativeBackspace : byte = 8#u8 := by scalar_tac
    simp only [nativeBackspace, ↓reduceIte]
    apply spec_mono (native_pair_push output 92#u8 98#u8 (by simp [jsonByte, backspace] at room; omega))
    intro actual exact
    simpa [jsonByte, backspace] using exact
  have nativeNotBackspace : byte ≠ 8#u8 := by scalar_tac
  simp only [nativeNotBackspace, ↓reduceIte]
  by_cases tab : byte.val = 9
  · have nativeTab : byte = 9#u8 := by scalar_tac
    simp only [nativeTab, ↓reduceIte]
    apply spec_mono (native_pair_push output 92#u8 116#u8 (by simp [jsonByte, tab] at room; omega))
    intro actual exact
    simpa [jsonByte, tab] using exact
  have nativeNotTab : byte ≠ 9#u8 := by scalar_tac
  simp only [nativeNotTab, ↓reduceIte]
  by_cases newline : byte.val = 10
  · have nativeNewline : byte = 10#u8 := by scalar_tac
    simp only [nativeNewline, ↓reduceIte]
    apply spec_mono (native_pair_push output 92#u8 110#u8 (by simp [jsonByte, newline] at room; omega))
    intro actual exact
    simpa [jsonByte, newline] using exact
  have nativeNotNewline : byte ≠ 10#u8 := by scalar_tac
  simp only [nativeNotNewline, ↓reduceIte]
  by_cases formfeed : byte.val = 12
  · have nativeFormfeed : byte = 12#u8 := by scalar_tac
    simp only [nativeFormfeed, ↓reduceIte]
    apply spec_mono (native_pair_push output 92#u8 102#u8 (by simp [jsonByte, formfeed] at room; omega))
    intro actual exact
    simpa [jsonByte, formfeed] using exact
  have nativeNotFormfeed : byte ≠ 12#u8 := by scalar_tac
  simp only [nativeNotFormfeed, ↓reduceIte]
  by_cases carriage : byte.val = 13
  · have nativeCarriage : byte = 13#u8 := by scalar_tac
    simp only [nativeCarriage, ↓reduceIte]
    apply spec_mono (native_pair_push output 92#u8 114#u8 (by simp [jsonByte, carriage] at room; omega))
    intro actual exact
    simpa [jsonByte, carriage] using exact
  have nativeNotCarriage : byte ≠ 13#u8 := by scalar_tac
  simp only [nativeNotCarriage, ↓reduceIte]
  by_cases control : byte.val < 32
  · have nativeControl : byte < 32#u8 := by scalar_tac
    have capacity : output.val.length + 6 ≤ Usize.max := by
      simpa [jsonByte, quote, slash, backspace, tab, newline, formfeed, carriage, control] using room
    simp only [nativeControl, ↓reduceIte]
    step with native_push_exact output 92#u8 (by omega) as ⟨one, oneMeaning⟩
    step with native_push_exact one 117#u8 (by simp only [oneMeaning, List.length_append, List.length_singleton]; omega)
      as ⟨two, twoMeaning⟩
    step with native_push_exact two 48#u8 (by simp only [twoMeaning, oneMeaning, List.length_append, List.length_singleton]; omega)
      as ⟨three, threeMeaning⟩
    step with native_push_exact three 48#u8
      (by simp only [threeMeaning, twoMeaning, oneMeaning, List.length_append, List.length_singleton]; omega)
      as ⟨four, fourMeaning⟩
    step as ⟨high, highMeaning⟩
    step with native_hex_lower_exact high (by scalar_tac) as ⟨highDigit, highDigitMeaning⟩
    step with native_push_exact four highDigit
      (by simp only [fourMeaning, threeMeaning, twoMeaning, oneMeaning, List.length_append, List.length_singleton]; omega)
      as ⟨five, fiveMeaning⟩
    step as ⟨low, lowMeaning⟩
    step with native_hex_lower_exact low (by scalar_tac) as ⟨lowDigit, lowDigitMeaning⟩
    step with native_push_exact five lowDigit
      (by simp only [fiveMeaning, fourMeaning, threeMeaning, twoMeaning, oneMeaning, List.length_append, List.length_singleton]; omega)
      as ⟨actual, exact⟩
    simp [bytes, exact, fiveMeaning, fourMeaning, threeMeaning, twoMeaning, oneMeaning,
      jsonByte, quote, slash, backspace, tab, newline, formfeed, carriage, control,
      highMeaning, lowMeaning, highDigitMeaning, lowDigitMeaning, List.map_append, List.append_assoc]
  · have nativeNotControl : ¬byte < 32#u8 := by scalar_tac
    have capacity : output.val.length < Usize.max := by
      simp [jsonByte, quote, slash, backspace, tab, newline, formfeed, carriage, control] at room
      omega
    simp only [nativeNotControl, ↓reduceIte]
    step with native_push_exact output byte capacity as ⟨actual, exact⟩
    simp [bytes, exact, jsonByte, quote, slash, backspace, tab, newline, formfeed, carriage, control, List.map_append]

end Auths.Product.NativeCompiler.Refinement
