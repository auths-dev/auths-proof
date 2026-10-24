import Auths.Product.NativeSerdeCompilation
import Auths.Product.RecipeSerdeSourceNumericSafety

/-!
Construct the complete same-source serialization from original decoded
provenance, then earn numeric safety from complete recipe-rule admission.
Schema evidence remains the complete original command-schema value, never a
lossy schema view substituted for a canonical preimage. No serialization,
safe-number record, body view or rounding result is supplied by the caller.
This composes existing model/data relations; actual native byte decoding,
Serialize, numeric conversion/ryu and JCS adequacy are still outer gates.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar NativeCompiler

/-- Original decoded provenance constructs the full body meaning before any
admission claim. If the complete rules accept that same body/source, complete
unique serialization exists and every original numeric occurrence is exact
under the integral binary64 rounding model. -/
theorem decoded_source_earns_admitted_numeric_serialization (raw : RawJson) (input : NativeRecord .recipe)
    (original : SourceMeaning raw input) :
    ∃ body, BodySourceMeaning input.write.body body ∧
      ∀ fields, (RecipeRuleAdmission.validate fields (ruleSource input body)).1 = .ok () →
      ∃ serialized, RecipeSerde.SourceEncoding input serialized ∧ FullJsonValue.Unique serialized ∧
        FullJsonNumericSafety.SafeNumbers serialized ∧
        ∀ number, FullJsonNumericSafety.NumberIn number serialized → FullJsonNumericSafety.RoundingExact number := by
  have bounded := native_decode_earns_carrier_bounds original.2
  have bodyBounds := source_body_bounds_from_carrier input bounded
  obtain ⟨copied, body, copiedAt, bodyOriginal, kernelOriginal⟩ :=
    NativeCompiler.Refinement.native_body_earns_original_meaning input.write.body bodyBounds
  refine ⟨body, bodyOriginal, ?_⟩
  intro fields admitted
  obtain ⟨serialized, encoded, unique⟩ := decoded_source_earns_unique_full_serialization raw input original
  have safe := RecipeSerde.admitted_source_serialization_has_safe_numbers fields input body bodyOriginal admitted serialized encoded
  exact ⟨serialized, encoded, unique, safe, FullJsonNumericSafety.every_original_number_rounds_exactly serialized safe⟩

/-- The same original command schema is constructed before the closed-schema
parser's admission premise. Its numbers are proved safe only when that parser
accepts; ignored/unsupported schema members cannot be hidden by projection. -/
theorem decoded_lock_earns_admitted_numeric_schema (raw : RawJson) (input : NativeRecord .lock)
    (original : LockMeaning raw input) :
    ∃ schema, FullJsonMeaning input.command_schema schema ∧ FullJsonValue.Unique schema ∧
      ∀ fields, ProfileSchema.parseRoot (FullJsonValue.schemaView schema) = some fields →
        FullJsonNumericSafety.SafeNumbers schema ∧
        ∀ number, FullJsonNumericSafety.NumberIn number schema → FullJsonNumericSafety.RoundingExact number := by
  obtain ⟨schema, meaning, unique⟩ := decoded_lock_earns_unique_full_schema raw input original
  refine ⟨schema, meaning, unique, ?_⟩
  intro fields admitted
  have safe := FullJsonNumericSafety.parsed_full_schema_has_safe_numbers schema fields admitted
  exact ⟨safe, FullJsonNumericSafety.every_original_number_rounds_exactly schema safe⟩

end Auths.Product.NativeSerde
