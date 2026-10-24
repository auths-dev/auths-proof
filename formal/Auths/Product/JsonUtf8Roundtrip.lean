import Auths.Product.JsonStringScalars

/-!
The concrete scalar reader inverts every complete Unicode UTF-8 scalar before
an arbitrary suffix. No valid-tail, parser-success, ASCII-only or desired
cursor premise is supplied. This is independent reader/encoder correspondence,
not actual Rust str/serde implementation adequacy.
-/
namespace Auths.Product.JsonStringScalars

set_option maxHeartbeats 6000000

@[simp] theorem checked_character_inverse (character : Char) (valid : character.toNat.isValidChar) :
    Char.ofNatAux character.toNat valid = character := by
  apply Char.toNat_inj.mp
  rfl

theorem utf8_encoded_scalar_roundtrip (character : Char) (tail : Bytes) :
    scalarResult (utf8 (NativeUtf8KeyOrder.scalar character.toNat ++ tail)) = .ok (character, tail) := by
  have bounded := NativeUtf8KeyOrder.character_scalar_bounded character
  change character.toNat ≤ 1114111 at bounded
  have nativeValid : character.toNat.isValidChar := character.valid
  by_cases ascii : character.toNat ≤ 127
  · have first : character.toNat < 128 := by omega
    simp [NativeUtf8KeyOrder.scalar, ascii, utf8, scalarResult, first]
  · by_cases two : character.toNat ≤ 2047
    · have first : ¬ 192 + character.toNat / 64 < 128 := by omega
      have leading : 194 ≤ 192 + character.toNat / 64 ∧ 192 + character.toNat / 64 < 224 := by omega
      have next : continuation (128 + character.toNat % 64) := by unfold continuation; omega
      have recovered : ((192 + character.toNat / 64) - 192) * 64 +
          ((128 + character.toNat % 64) - 128) = character.toNat := by omega
      simp [NativeUtf8KeyOrder.scalar, ascii, two, utf8, scalarResult, first, leading, next, recovered]
    · by_cases three : character.toNat ≤ 65535
      · have first : ¬ 224 + character.toNat / 4096 < 128 := by omega
        have notTwo : ¬ (194 ≤ 224 + character.toNat / 4096 ∧ 224 + character.toNat / 4096 < 224) := by omega
        have leading : 224 ≤ 224 + character.toNat / 4096 ∧ 224 + character.toNat / 4096 < 240 := by omega
        have next : continuation (128 + (character.toNat / 64) % 64) ∧
            continuation (128 + character.toNat % 64) := by unfold continuation; omega
        have recovered : ((224 + character.toNat / 4096) - 224) * 4096 +
            ((128 + (character.toNat / 64) % 64) - 128) * 64 +
            ((128 + character.toNat % 64) - 128) = character.toNat := by omega
        have minimum : 2048 ≤ character.toNat := by omega
        simp [NativeUtf8KeyOrder.scalar, ascii, two, three, utf8, scalarResult, first, notTwo,
          leading, next, recovered, minimum, nativeValid]
      · have first : ¬ 240 + character.toNat / 262144 < 128 := by omega
        have notTwo : ¬ (194 ≤ 240 + character.toNat / 262144 ∧ 240 + character.toNat / 262144 < 224) := by omega
        have notThree : ¬ (224 ≤ 240 + character.toNat / 262144 ∧ 240 + character.toNat / 262144 < 240) := by omega
        have leading : 240 ≤ 240 + character.toNat / 262144 ∧ 240 + character.toNat / 262144 < 245 := by omega
        have next : continuation (128 + (character.toNat / 4096) % 64) ∧
            continuation (128 + (character.toNat / 64) % 64) ∧ continuation (128 + character.toNat % 64) := by
          unfold continuation
          omega
        have recovered : ((240 + character.toNat / 262144) - 240) * 262144 +
            ((128 + (character.toNat / 4096) % 64) - 128) * 4096 +
            ((128 + (character.toNat / 64) % 64) - 128) * 64 +
            ((128 + character.toNat % 64) - 128) = character.toNat := by omega
        have minimum : 65536 ≤ character.toNat := by omega
        simp [NativeUtf8KeyOrder.scalar, ascii, two, three, utf8, scalarResult, first, notTwo,
          notThree, leading, next, recovered, minimum, nativeValid]

theorem unescaped_utf8_lead_is_not_syntax (character : Char) (ordinary : 32 ≤ character.toNat)
    (notQuote : character.toNat ≠ 34) (notSlash : character.toNat ≠ 92) :
    ∃ first rest, NativeUtf8KeyOrder.scalar character.toNat = first :: rest ∧
      first ≠ 92 ∧ 32 ≤ first ∧ first ≠ 34 := by
  unfold NativeUtf8KeyOrder.scalar
  repeat' split
  all_goals
    refine ⟨_, _, rfl, ?_, ?_, ?_⟩ <;> omega

theorem raw_string_scalar_roundtrip (character : Char) (tail : Bytes) (ordinary : 32 ≤ character.toNat)
    (notQuote : character.toNat ≠ 34) (notSlash : character.toNat ≠ 92) :
    scalarResult (stringScalar (NativeUtf8KeyOrder.scalar character.toNat ++ tail)) = .ok (character, tail) := by
  obtain ⟨first, rest, original, firstNotSlash, firstOrdinary, firstNotQuote⟩ :=
    unescaped_utf8_lead_is_not_syntax character ordinary notQuote notSlash
  have notSyntax : ¬ (first < 32 ∨ first = 34) := by omega
  have parser : stringScalar (NativeUtf8KeyOrder.scalar character.toNat ++ tail) =
      utf8 (NativeUtf8KeyOrder.scalar character.toNat ++ tail) := by
    rw [original]
    simp [stringScalar, firstNotSlash, notSyntax]
  rw [parser]
  exact utf8_encoded_scalar_roundtrip character tail

end Auths.Product.JsonStringScalars
