import Auths.Product.RecipeAdmissionAtoms

namespace Auths.Product.RecipeAdmissionAtoms

def readIndexFrom (initial : Nat) (bytes : Bytes) : Nat :=
  bytes.foldl (fun value byte => 10 * value + (byte - 48)) initial

def indexDigit (maximum value byte : Nat) : Nat × Bool :=
  if 48 ≤ byte ∧ byte ≤ 57 ∧ 10 * value ≤ maximum ∧ 10 * value + (byte - 48) ≤ maximum then
    (10 * value + (byte - 48), true)
  else (value, false)

/-- Retain the last represented prefix on invalid digits or either checked
word overflow. This models refusal state, separately from IndexSyntax. -/
def indexScan (maximum : Nat) : Bytes → Nat → Bool → Nat × Bool
  | [], value, valid => (value, valid)
  | byte :: rest, value, valid =>
      if valid then
        let next := indexDigit maximum value byte
        indexScan maximum rest next.1 next.2
      else (value, false)

theorem read_index_from_monotone (initial : Nat) (bytes : Bytes) : initial ≤ readIndexFrom initial bytes := by
  induction bytes generalizing initial with
  | nil => rfl
  | cons byte rest ih =>
      have next := ih (10 * initial + (byte - 48))
      change initial ≤ readIndexFrom (10 * initial + (byte - 48)) rest
      omega

theorem index_scan_stopped (maximum : Nat) (bytes : Bytes) (value : Nat) :
    indexScan maximum bytes value false = (value, false) := by
  cases bytes <;> rfl

theorem index_scan_validity (maximum : Nat) (bytes : Bytes) (value : Nat) (within : value ≤ maximum) :
    (indexScan maximum bytes value true).2 =
      decide ((∀ byte ∈ bytes, 48 ≤ byte ∧ byte ≤ 57) ∧ readIndexFrom value bytes ≤ maximum) ∧
    ((indexScan maximum bytes value true).2 = true →
      (indexScan maximum bytes value true).1 = readIndexFrom value bytes) := by
  induction bytes generalizing value with
  | nil => simp [indexScan, readIndexFrom, within]
  | cons byte rest ih =>
      by_cases digit : 48 ≤ byte ∧ byte ≤ 57
      · by_cases room : 10 * value + (byte - 48) ≤ maximum
        · have productRoom : 10 * value ≤ maximum := by omega
          simpa [indexScan, indexDigit, digit, room, productRoom,
            readIndexFrom, List.foldl_cons, and_assoc] using ih _ room
        · have finalLarge : ¬readIndexFrom value (byte :: rest) ≤ maximum := by
            have grows := read_index_from_monotone (10 * value + (byte - 48)) rest
            change ¬readIndexFrom (10 * value + (byte - 48)) rest ≤ maximum
            omega
          simp [indexScan, indexDigit, room, index_scan_stopped, finalLarge]
      · simp [indexScan, indexDigit, digit, index_scan_stopped]

theorem index_scan_word_bounded (maximum : Nat) (bytes : Bytes) (value : Nat) (valid : Bool)
    (within : value ≤ maximum) : (indexScan maximum bytes value valid).1 ≤ maximum := by
  induction bytes generalizing value valid with
  | nil => exact within
  | cons byte rest ih =>
      cases valid with
      | false => exact within
      | true =>
          unfold indexScan indexDigit
          split
          · rename_i room
            exact ih _ true room.2.2.2
          · simpa [index_scan_stopped] using within

theorem array_index_from_scan (maximum : Nat) (bytes : Bytes) :
    arrayIndex maximum bytes =
      if bytes = [] ∨ (1 < bytes.length ∧ bytes.head? = some 48) then none
      else let scanned := indexScan maximum bytes 0 true
        if scanned.2 then some scanned.1 else none := by
  have meaning := index_scan_validity maximum bytes 0 (by omega)
  by_cases empty : bytes = []
  · simp [empty, arrayIndex, IndexSyntax]
  · by_cases leading : 1 < bytes.length ∧ bytes.head? = some 48
    · simp [leading, arrayIndex, IndexSyntax]; omega
    · have lengthPositive := List.length_pos.mpr empty
      have syntaxPrefix : bytes.length = 1 ∨ bytes.head? ≠ some 48 := by
        by_cases one : bytes.length = 1
        · exact Or.inl one
        · exact Or.inr (fun zero => leading ⟨by omega, zero⟩)
      cases admitted : (indexScan maximum bytes 0 true).2 with
      | false =>
          have invalid : ¬((∀ byte ∈ bytes, 48 ≤ byte ∧ byte ≤ 57) ∧ readIndexFrom 0 bytes ≤ maximum) := by
            simpa [admitted] using meaning.1.symm
          simp [arrayIndex, IndexSyntax, empty, leading, syntaxPrefix, readIndex, ← readIndexFrom, admitted, invalid]
      | true =>
          have exactValue := meaning.2 admitted
          have admittedModel : (∀ byte ∈ bytes, 48 ≤ byte ∧ byte ≤ 57) ∧ readIndexFrom 0 bytes ≤ maximum := by
            simpa [admitted] using meaning.1.symm
          simp [arrayIndex, IndexSyntax, empty, leading, syntaxPrefix, readIndex,
            ← readIndexFrom, admittedModel, admitted, exactValue]

end Auths.Product.RecipeAdmissionAtoms
