import Auths.Product.JsonUtf8Roundtrip
import Auths.Product.JsonStringDocument
import Auths.Product.JcsStringEncoding

/-!
Complete reference string-writer/key-reader roundtrip. Canonical quoting
retains every original character, including controls and supplementary text,
and earns its own parse result with arbitrary following bytes. This is not
native serde/String/formatter adequacy or whole-number/canonical injectivity.
-/
namespace Auths.Product.JcsStringRoundtrip
open JsonStringScalars

set_option maxHeartbeats 6000000

private theorem character_from_nat_equality (character : Char) (value : Nat)
    (same : character.toNat = value) : character = Char.ofNat value := by
  simpa only [same] using (Char.ofNat_toNat character).symm

private theorem control_scalar_roundtrip (character : Char) (tail : Bytes) (small : character.toNat < 32) :
    scalarResult (stringScalar (JcsStringEncoding.scalar character.toNat ++ tail)) = .ok (character, tail) := by
  have options : character.toNat = 0 ∨ character.toNat = 1 ∨ character.toNat = 2 ∨ character.toNat = 3 ∨ character.toNat = 4 ∨ character.toNat = 5 ∨ character.toNat = 6 ∨ character.toNat = 7 ∨ character.toNat = 8 ∨ character.toNat = 9 ∨ character.toNat = 10 ∨ character.toNat = 11 ∨ character.toNat = 12 ∨ character.toNat = 13 ∨ character.toNat = 14 ∨ character.toNat = 15 ∨ character.toNat = 16 ∨ character.toNat = 17 ∨ character.toNat = 18 ∨ character.toNat = 19 ∨ character.toNat = 20 ∨ character.toNat = 21 ∨ character.toNat = 22 ∨ character.toNat = 23 ∨ character.toNat = 24 ∨ character.toNat = 25 ∨ character.toNat = 26 ∨ character.toNat = 27 ∨ character.toNat = 28 ∨ character.toNat = 29 ∨ character.toNat = 30 ∨ character.toNat = 31 := by omega
  rcases options with atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue | atValue
  all_goals
    have same := character_from_nat_equality character _ atValue
    rw [same]
    simp [JcsStringEncoding.scalar, JcsStringEncoding.hex, stringScalar, scalarResult,
      escape, unicodeEscape, hex4, hexDigit, Consumed.prepend, Consumed.chain, Consumed.map, Char.ofNat]

theorem scalar_encoded_roundtrip (character : Char) (tail : Bytes) :
    scalarResult (stringScalar (JcsStringEncoding.scalar character.toNat ++ tail)) = .ok (character, tail) := by
  by_cases quote : character.toNat = 34
  · have same : character = '"' := Char.toNat_inj.mp (by simpa using quote)
    subst character
    simp [JcsStringEncoding.scalar, stringScalar, scalarResult, escape, Consumed.prepend]
  · by_cases slash : character.toNat = 92
    · have same : character = '\\' := Char.toNat_inj.mp (by simpa using slash)
      subst character
      simp [JcsStringEncoding.scalar, stringScalar, scalarResult, escape, Consumed.prepend]
    · by_cases small : character.toNat < 32
      · exact control_scalar_roundtrip character tail small
      · have ordinary : 32 ≤ character.toNat := by omega
        have notEight : character.toNat ≠ 8 := by omega
        have notNine : character.toNat ≠ 9 := by omega
        have notTen : character.toNat ≠ 10 := by omega
        have notTwelve : character.toNat ≠ 12 := by omega
        have notThirteen : character.toNat ≠ 13 := by omega
        simpa only [JcsStringEncoding.scalar, if_neg quote, if_neg slash, if_neg notEight, if_neg notNine,
          if_neg notTen, if_neg notTwelve, if_neg notThirteen, if_neg small] using
          raw_string_scalar_roundtrip character tail ordinary quote slash

theorem encoded_scalar_lead_is_not_quote (character : Char) :
    ∃ first rest, JcsStringEncoding.scalar character.toNat = first :: rest ∧ first ≠ 34 := by
  unfold JcsStringEncoding.scalar NativeUtf8KeyOrder.scalar
  repeat' split
  all_goals
    refine ⟨_, _, rfl, ?_⟩
    omega

def contentResult (input : Bytes) : Except Unit (List Char × Bytes) :=
  (JsonStringDocument.contents input).map (fun parsed => (parsed.value, parsed.rest))

def quotedResult (input : Bytes) : Except Unit (List Char × Bytes) :=
  (JsonStringDocument.quoted input).map (fun parsed => (parsed.value, parsed.rest))

theorem content_result_step (first : Nat) (rest : Bytes) (notQuote : first ≠ 34) :
    contentResult (first :: rest) = do
      let (character, remaining) ← scalarResult (stringScalar (first :: rest))
      let (characters, suffix) ← contentResult remaining
      pure (character :: characters, suffix) := by
  cases scalarAt : stringScalar (first :: rest) with
  | error error => simp [contentResult, JsonStringDocument.contents, notQuote, scalarResult, scalarAt]
  | ok parsed =>
      cases tailAt : JsonStringDocument.contents parsed.rest <;>
        simp [contentResult, JsonStringDocument.contents, notQuote, scalarResult, scalarAt, tailAt, Consumed.chain, Consumed.map]

theorem encoded_contents_roundtrip (characters : List Char) (tail : Bytes) :
    contentResult (JcsStringEncoding.characters characters ++ 34 :: tail) = .ok (characters, tail) := by
  induction characters with
  | nil => simp [contentResult, JcsStringEncoding.characters, JsonStringDocument.contents]
  | cons character rest ih =>
      let suffix := JcsStringEncoding.characters rest ++ 34 :: tail
      obtain ⟨first, bytes, encoded, notQuote⟩ := encoded_scalar_lead_is_not_quote character
      have shape : JcsStringEncoding.characters (character :: rest) ++ 34 :: tail =
          first :: (bytes ++ suffix) := by
        simp [JcsStringEncoding.characters, encoded, suffix, List.append_assoc]
      have scalarAt := scalar_encoded_roundtrip character suffix
      rw [encoded, List.cons_append] at scalarAt
      rw [shape, content_result_step first (bytes ++ suffix) notQuote]
      simpa [scalarAt, suffix, ih]

theorem quoted_result_eq_contents (rest : Bytes) : quotedResult (34 :: rest) = contentResult rest := by
  cases parsedAt : JsonStringDocument.contents rest <;>
    simp [quotedResult, contentResult, JsonStringDocument.quoted, parsedAt, Consumed.prepend]

theorem quoted_bytes_roundtrip (input : String) (tail : Bytes) :
    quotedResult (JcsStringEncoding.quoted input ++ tail) = .ok (input.toList, tail) := by
  simp only [JcsStringEncoding.quoted, List.cons_append, List.append_assoc, List.singleton_append, quoted_result_eq_contents]
  exact encoded_contents_roundtrip input.toList tail

theorem document_quote_roundtrip (input : String) :
    JsonStringDocument.document (JcsStringEncoding.quoted input) = .ok input := by
  have view := quoted_bytes_roundtrip input []
  simp only [List.append_nil] at view
  have noLeading : JsonDocumentEnd.skip (JcsStringEncoding.quoted input) = 0 := by
    simp [JcsStringEncoding.quoted, JsonDocumentEnd.skip, JsonDocumentEnd.whitespace]
  cases parsedAt : JsonStringDocument.quoted (JcsStringEncoding.quoted input) with
  | error error => simp [quotedResult, parsedAt] at view
  | ok parsed =>
      have data : parsed.value = input.toList ∧ parsed.rest = [] := by
        simpa [quotedResult, parsedAt] using view
      simp [JsonStringDocument.document, noLeading, parsedAt, data.1, data.2,
        JsonDocumentEnd.skip, String.ofList_toList]

theorem property_quote_roundtrip (name : String) (value : Bytes) :
    JsonStringDocument.property (JcsStringEncoding.quoted name) value =
      .ok (JcsObjectBuffer.originalProperty name value) := by
  simp [JsonStringDocument.property, document_quote_roundtrip, JcsObjectBuffer.originalProperty]

/-- String quoting is injective. This does not claim that arbitrary numbers,
whole JSON values or typed sources have injective canonical numeric bytes. -/
theorem quoted_string_encoding_injective {left right : String}
    (same : JcsStringEncoding.quoted left = JcsStringEncoding.quoted right) : left = right := by
  have decoded := congrArg JsonStringDocument.document same
  rw [document_quote_roundtrip, document_quote_roundtrip] at decoded
  exact Except.ok.inj decoded

end Auths.Product.JcsStringRoundtrip

