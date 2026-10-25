import Init.Data.Char.Lemmas
import Init.Data.String.Basic
import Mathlib.Data.List.Nodup
import Lean.Elab.Tactic.Omega

/-!
Complete UTF-16 sorting keys for the recipe canonical JSON boundary. Numbers
are full code units, without a narrowing conversion. The decoder is an
independent inverse: it refuses out-of-range units, isolated surrogates and
incorrect pairs. It is used to earn key injectivity, not as a shipping parser.
Native String::encode_utf16 and JsonProperty::new adequacy remain explicit
ordinary-library obligations; neither is replaced by an opaque Auths body.
-/
namespace Auths.Product.JcsUtf16Keys

def ValidScalar (value : Nat) : Prop :=
  value < 55296 ∨ (57343 < value ∧ value < 1114112)

def scalar (value : Nat) : List Nat :=
  if value < 65536 then [value]
  else [55296 + (value - 65536) / 1024, 56320 + (value - 65536) % 1024]

def decode : List Nat → Option (List Nat)
  | [] => some []
  | first :: rest =>
      if first < 55296 then (first :: ·) <$> decode rest
      else if first < 56320 then
        match rest with
        | [] => none
        | second :: tail =>
            if 56320 ≤ second ∧ second < 57344 then
              ((65536 + (first - 55296) * 1024 + (second - 56320)) :: ·) <$> decode tail
            else none
      else if first < 57344 then none
      else if first < 65536 then (first :: ·) <$> decode rest
      else none

def characters (input : List Char) : List Nat := input.flatMap (fun value => scalar value.toNat)

def key (input : String) : List Nat := characters input.toList

theorem character_is_valid (value : Char) : ValidScalar value.toNat := by
  have valid := value.valid
  unfold UInt32.isValidChar Nat.isValidChar at valid
  change ValidScalar value.val.toNat
  unfold ValidScalar
  omega

theorem scalar_units_bounded (value : Nat) (valid : ValidScalar value) :
    ∀ unit ∈ scalar value, unit < 65536 := by
  unfold scalar ValidScalar at *
  split
  all_goals
    intro unit member
    simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    omega

/-- A scalar prefix decodes to that exact scalar before the arbitrary tail
is considered. No tail validity or presumed successful decoding is supplied. -/
theorem scalar_prefix_roundtrip (value : Nat) (valid : ValidScalar value) (tail : List Nat) :
    decode (scalar value ++ tail) = (value :: ·) <$> decode tail := by
  by_cases bmp : value < 65536
  · rcases valid with before | after
    · simp [scalar, bmp, decode, before]
    · have notBefore : ¬ value < 55296 := by omega
      have notHigh : ¬ value < 56320 := by omega
      have notLow : ¬ value < 57344 := by omega
      simp [scalar, bmp, decode, notBefore, notHigh, notLow]
  · have bounded : value < 1114112 := by rcases valid with before | after <;> omega
    have highNotBefore : ¬ 55296 + (value - 65536) / 1024 < 55296 := by omega
    have highIsHigh : 55296 + (value - 65536) / 1024 < 56320 := by omega
    have lowBounds : 56320 ≤ 56320 + (value - 65536) % 1024 ∧
        56320 + (value - 65536) % 1024 < 57344 := by omega
    have original : 65536 + ((55296 + (value - 65536) / 1024) - 55296) * 1024 +
        ((56320 + (value - 65536) % 1024) - 56320) = value := by omega
    simp [scalar, bmp, decode, highNotBefore, highIsHigh, lowBounds, original]

theorem characters_roundtrip (input : List Char) :
    decode (characters input) = some (input.map Char.toNat) := by
  induction input with
  | nil => rfl
  | cons first rest ih =>
      change decode (scalar first.toNat ++ characters rest) = some ((first :: rest).map Char.toNat)
      rw [scalar_prefix_roundtrip _ (character_is_valid first) _, ih]
      rfl

theorem characters_injective {left right : List Char}
    (same : characters left = characters right) : left = right := by
  have decoded := congrArg decode same
  rw [characters_roundtrip, characters_roundtrip] at decoded
  exact List.map_injective (fun _ _ equal => Char.toNat_inj.mp equal) (Option.some.inj decoded)

theorem key_injective {left right : String} (same : key left = key right) : left = right := by
  exact String.toList_injective (characters_injective same)

theorem key_equality_exact (left right : String) : key left = key right ↔ left = right :=
  ⟨key_injective, fun same => congrArg key same⟩

theorem key_units_bounded (input : String) : ∀ unit ∈ key input, unit < 65536 := by
  intro unit member
  obtain ⟨character, _, inScalar⟩ := List.mem_flatMap.mp member
  exact scalar_units_bounded character.toNat (character_is_valid character) unit inScalar

theorem key_append (left right : String) : key (left ++ right) = key left ++ key right := by
  simp only [key, characters, String.toList_append, List.flatMap_append]

theorem distinct_names_have_distinct_keys (names : List String) :
    (names.map key).Nodup ↔ names.Nodup :=
  List.nodup_map_iff (fun _ _ same => key_injective same)

/-- This proves only that the sorting-key projection cannot introduce a new
collision. The original member list still has to earn its own uniqueness. -/
theorem distinct_members_have_distinct_keys {T : Type} (members : List (String × T))
    (distinct : (members.map Prod.fst).Nodup) :
    (members.map (fun member => key member.1)).Nodup := by
  simpa only [List.map_map] using (distinct_names_have_distinct_keys (members.map Prod.fst)).mpr distinct

/-- Payloads and complete member count are retained in this key projection;
the key is additional sorting data, not a replacement for the original name. -/
def properties {T : Type} (members : List (String × T)) : List (List Nat × (String × T)) :=
  members.map (fun member => (key member.1, member))

theorem properties_keep_original_members {T : Type} (members : List (String × T)) :
    (properties members).map Prod.snd = members := by
  simp [properties, List.map_map]

theorem properties_keep_count {T : Type} (members : List (String × T)) :
    (properties members).length = members.length := by simp [properties]

end Auths.Product.JcsUtf16Keys
