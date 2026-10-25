import Auths.Product.JcsIntegerDecimal
import Auths.Product.RecipeSerdeSourceNumericSafety

/-!
Expected exact numeric bytes for the COMPLETE admitted recipe/schema domain.
The closed encoder refuses unsupported float kinds and unsafe integers; this
is a reference for values whose admission is earned, not a model claiming
that the native JCS formatter itself refuses unsafe numbers. Native JCS can
round those numbers before recipe admission, as the separate alias cases show.
-/
namespace Auths.Product.AdmittedIntegerBytes
open FullJsonValue FullJsonNumericSafety

def integerValue : Number → Option Int
  | .unsigned value => some (Int.ofNat value)
  | .signed value => some value
  | .floating _ => none

def encode : Number → Option (List Nat)
  | .unsigned value => if value ≤ 9007199254740991 then some (JcsIntegerDecimal.unsigned value) else none
  | .signed value => if -9007199254740991 ≤ value ∧ value ≤ 9007199254740991 then
      some (JcsIntegerDecimal.signed value) else none
  | .floating _ => none

def ExactDecimal (number : Number) : Prop :=
  ∃ value bytes, integerValue number = some value ∧ encode number = some bytes ∧
    DecimalProjection.SignedDecimal bytes value ∧ JcsIntegerDecimal.readSigned bytes = some value ∧
    bytes.length ≤ 17 ∧ ∀ byte ∈ bytes, byte < 256

theorem safe_number_earns_exact_decimal (number : Number) (safe : SafeNumbers (.number number)) : ExactDecimal number := by
  cases safe with
  | unsigned value bounded =>
      refine ⟨Int.ofNat value, JcsIntegerDecimal.unsigned value, rfl, by simp [encode, bounded], ?_, ?_, ?_,
        JcsIntegerDecimal.unsigned_bytes_are_bounded value⟩
      · rw [← JcsIntegerDecimal.nonnegative_signed_bytes]
        exact JcsIntegerDecimal.signed_realizes_original_decimal _
      · rw [← JcsIntegerDecimal.nonnegative_signed_bytes]
        exact JcsIntegerDecimal.signed_roundtrip _
      · have length := JcsIntegerDecimal.admitted_unsigned_length value bounded
        omega
  | signed value bounded =>
      exact ⟨value, JcsIntegerDecimal.signed value, rfl, by simp [encode, bounded],
        JcsIntegerDecimal.signed_realizes_original_decimal value, JcsIntegerDecimal.signed_roundtrip value,
        JcsIntegerDecimal.admitted_signed_length value bounded, JcsIntegerDecimal.signed_bytes_are_bounded value⟩

theorem original_number_occurrence_is_safe (source : Value) (safe : SafeNumbers source) (number : Number)
    (inside : NumberIn number source) : SafeNumbers (.number number) := by
  revert safe
  induction inside with
  | here => exact id
  | array present inside ih =>
      intro safe
      cases safe with | array values each => exact ih (each _ present)
  | object present inside ih =>
      intro safe
      cases safe with | object members each => exact ih (each _ present)

theorem every_original_number_has_exact_decimal (source : Value) (safe : SafeNumbers source) :
    ∀ number, NumberIn number source → ExactDecimal number := by
  intro number inside
  exact safe_number_earns_exact_decimal number (original_number_occurrence_is_safe source safe number inside)

/-- Signed/unsigned carrier tags may differ while denoting the same integer.
Equality is claimed for that original integer meaning, never for raw tags or
float bits that the canonicalizer does not preserve. -/
theorem encoded_numbers_do_not_alias_integer_meaning (first second : Number) (bytes : List Nat)
    (firstExact : ExactDecimal first) (secondExact : ExactDecimal second)
    (left : encode first = some bytes) (right : encode second = some bytes) : integerValue first = integerValue second := by
  obtain ⟨firstValue, firstBytes, firstMeaning, firstAt, firstDecimal, firstRead, firstLength, firstBounds⟩ := firstExact
  obtain ⟨secondValue, secondBytes, secondMeaning, secondAt, secondDecimal, secondRead, secondLength, secondBounds⟩ := secondExact
  have leftBytes : firstBytes = bytes := Option.some.inj (firstAt.symm.trans left)
  have rightBytes : secondBytes = bytes := Option.some.inj (secondAt.symm.trans right)
  rw [leftBytes] at firstRead
  rw [rightBytes] at secondRead
  have same : firstValue = secondValue := Option.some.inj (firstRead.symm.trans secondRead)
  rw [firstMeaning, secondMeaning, same]

theorem admitted_source_every_number_has_exact_decimal (fields : RecipeRuleAdmission.Fields)
    (input : RecipeSerde.Source) (body : TemplateAst.Body) (original : NativeCompiler.BodySourceMeaning input.write.body body)
    (admitted : (RecipeRuleAdmission.validate fields (NativeCompiler.ruleSource input body)).1 = .ok ())
    (serialized : RecipeSerde.Json) (encoded : RecipeSerde.SourceEncoding input serialized) :
    ∀ number, NumberIn number serialized → ExactDecimal number :=
  every_original_number_has_exact_decimal serialized
    (RecipeSerde.admitted_source_serialization_has_safe_numbers fields input body original admitted serialized encoded)

theorem admitted_schema_every_number_has_exact_decimal (schema : Value) (fields : List FieldProjection.Field)
    (admitted : ProfileSchema.parseRoot (schemaView schema) = some fields) :
    ∀ number, NumberIn number schema → ExactDecimal number :=
  every_original_number_has_exact_decimal schema (parsed_full_schema_has_safe_numbers schema fields admitted)

end Auths.Product.AdmittedIntegerBytes
