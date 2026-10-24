import Auths.Product.DecimalProjectionRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.SchemaIndex.Refinement
open Auths.Product.DecimalProjection

namespace Auths.Product.ScalarProjection.Refinement

private theorem safe_witness (value : Int) (power : Nat) (bytes : Bytes)
    (safe : -9007199254740991 ≤ value ∧ value ≤ 9007199254740991)
    (largest : 10 ^ power ≤ max 1 value.natAbs) (upper : value.natAbs < 10 ^ (power + 1))
    (same : bytes = (if value < 0 then [45] else []) ++ DecimalProjection.emit value.natAbs (10 ^ power)) :
    SignedDecimal bytes value ∧ bytes.length ≤ 17 := by
  have canonical := emit_canonical value.natAbs power upper largest
  have absoluteBound : value.natAbs ≤ 9007199254740991 := by
    have interval : |value| ≤ (9007199254740991 : Int) := abs_le.mpr safe
    rw [← Int.natCast_natAbs] at interval
    exact_mod_cast interval
  have digitsBound := json_digits_bounded value.natAbs power absoluteBound largest
  constructor
  · by_cases negative : value < 0
    · simp only [SignedDecimal, negative, ↓reduceIte]
      exact ⟨_, by simpa [negative] using same, canonical⟩
    · simpa [SignedDecimal, negative, same] using canonical
  · rw [same, List.length_append]
    split_ifs <;> simp at * <;> omega

/-- Integer projection returns no value for every invalid schema/range. An
accepted scalar earns independent exact decimal meaning and its byte bound. -/
@[step] theorem integer_projection_exact (minimum maximum value : Std.I64) :
    scalars.integer_value minimum maximum value ⦃ actual =>
      (actual = none ↔ ¬IntegerValue minimum.val maximum.val value.val) ∧
      ∀ output, actual = some output →
        Projects (.integer minimum.val maximum.val) (.integer value.val) (argOf output) ∧
          PayloadLength (argOf output) ≤ 17 ⦄ := by
  unfold scalars.integer_value
  step with integer_valid_exact as ⟨allowed, meaning⟩
  cases allowed
  · have invalid : ¬IntegerValue minimum.val maximum.val value.val := by simpa using meaning.symm
    simp [invalid]
  · have valid : IntegerValue minimum.val maximum.val value.val := by simpa using meaning.symm
    step with DecimalProjection.Refinement.integer_bytes_exact as ⟨bytes, power, largest, upper, same⟩
    have safe := accepted_integer_bound _ _ _ valid
    have represented := safe_witness value.val power (vecBytes bytes) safe largest upper same
    simp only [spec_ok]
    refine ⟨by simp [valid], ?_⟩
    intro output sameOutput
    have sameValue : output = .Integer bytes := by simpa using sameOutput.symm
    subst output
    exact ⟨⟨valid, represented.1⟩, represented.2⟩

theorem string_projection_sound (minimum maximum : Std.Usize) (text : Slice Std.U8) :
    scalars.string_value minimum maximum text ⦃ actual =>
      (actual = none ↔ ¬StringValue minimum.val maximum.val (sliceBytes text)) ∧
      ∀ output, actual = some output →
        Projects (.text minimum.val maximum.val) (.text (sliceBytes text)) (argOf output) ∧
          PayloadLength (argOf output) ≤ 4096 ⦄ := by
  apply spec_mono (string_projection_exact minimum maximum text)
  intro actual meaning
  by_cases valid : StringValue minimum.val maximum.val (sliceBytes text)
  · simp only [valid, ↓reduceIte] at meaning
    constructor
    · constructor
      · intro absent
        simp [absent] at meaning
      · exact False.elim ∘ (· valid)
    · intro output same
      rw [same] at meaning
      have value : argOf output = .text (sliceBytes text) := Option.some.inj meaning
      rw [value]
      exact ⟨⟨valid, rfl⟩, accepted_string_bound _ _ _ valid⟩
  · simp only [valid, ↓reduceIte] at meaning
    have none : actual = none := Option.map_eq_none_iff.mp meaning
    simp [none, valid]

theorem enum_projection_sound (variants : Slice (alloc.vec.Vec Std.U8)) (text : Slice Std.U8) :
    scalars.enum_value variants text ⦃ actual =>
      (actual = none ↔ ¬EnumValue (namesView variants) (sliceBytes text)) ∧
      ∀ output, actual = some output →
        Projects (.enumeration (namesView variants)) (.text (sliceBytes text)) (argOf output) ∧
          PayloadLength (argOf output) ≤ 64 ⦄ := by
  apply spec_mono (enum_projection_exact variants text)
  intro actual meaning
  by_cases valid : EnumValue (namesView variants) (sliceBytes text)
  · simp only [valid, ↓reduceIte] at meaning
    constructor
    · constructor
      · intro absent
        simp [absent] at meaning
      · exact False.elim ∘ (· valid)
    · intro output same
      rw [same] at meaning
      have value : argOf output = .text (sliceBytes text) := Option.some.inj meaning
      rw [value]
      exact ⟨⟨valid, rfl⟩, accepted_enum_bound _ _ valid⟩
  · simp only [valid, ↓reduceIte] at meaning
    have none : actual = none := Option.map_eq_none_iff.mp meaning
    simp [none, valid]

@[step] theorem boolean_projection_exact (value : Bool) :
    scalars.boolean_value value ⦃ actual =>
      Projects .boolean (.boolean value) (argOf actual) ∧ PayloadLength (argOf actual) = 0 ⦄ := by
  simp [scalars.boolean_value, Projects, argOf, PayloadLength]

/-- Independent typed projection records carry the source-earned bounds. The
named binder's allocation domain follows for every such complete environment;
deriving that environment from the actual serde object is a caller obligation. -/
theorem bounded_named_environment_fits (values : Slice arguments.NamedArgument)
    (bounded : ∀ entry ∈ values.val, PayloadLength (argOf entry.value) ≤ 4096) :
    ArgumentBinding.Refinement.PayloadsFit values := by
  intro entry member
  have bound := bounded entry member
  cases value : entry.value <;>
    simp [argOf, vecBytes, byteList, PayloadLength, ArgumentBinding.Refinement.payloadLength, value] at bound ⊢ <;> omega

end Auths.Product.ScalarProjection.Refinement
