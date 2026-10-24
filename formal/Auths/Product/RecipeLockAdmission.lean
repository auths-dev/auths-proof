import Auths.Product.RecipeBinding

/-!
Independent lock/canonical-source outcomes. The hash function is a separately
named crypto parameter; it is applied to the complete original bytes. This
model neither supplies canonicalization success nor assumes a lock digest
matches. The native caller must earn both outcomes from the original decoded
source/lock under the foreign serialization contract.
-/
namespace Auths.Product.RecipeLockAdmission
open RequestConstruction RecipeBinding

structure Errors (Error : Type) where
  invalidSource : Error
  invalidProfileLock : Error

abbrev CanonicalOutcome := Except Unit Bytes

/-- Metadata refusal precedes canonicalization-failure consumption and digest
comparison, retaining the actual compiler's stable error boundary. -/
def validateLock {Error : Type} (errors : Errors Error) (hash : Bytes → Bytes)
    (metadata : Metadata) (canonicalSchema : CanonicalOutcome) : Except Error Unit :=
  if MetadataValid metadata then
    match canonicalSchema with
    | .error () => .error errors.invalidProfileLock
    | .ok bytes =>
        if SchemaDigestMatches metadata.binding.schemaDigest (hash bytes) then .ok ()
        else .error errors.invalidProfileLock
  else .error errors.invalidProfileLock

/-- Failure is consumed only after source admission. The successful branch
hashes the exact domain and original source bytes, including the terminal NUL. -/
def recipeDigest {Error : Type} (errors : Errors Error) (hash : Bytes → Bytes)
    (canonicalSource : CanonicalOutcome) : Except Error Bytes :=
  match canonicalSource with
  | .error () => .error errors.invalidSource
  | .ok bytes => .ok (hash (digestPreimage bytes))

theorem lock_success_earns_original_digest {Error : Type} (errors : Errors Error)
    (hash : Bytes → Bytes) (metadata : Metadata) (canonicalSchema : CanonicalOutcome) :
    validateLock errors hash metadata canonicalSchema = .ok () ↔
      MetadataValid metadata ∧ ∃ bytes, canonicalSchema = .ok bytes ∧
        SchemaDigestMatches metadata.binding.schemaDigest (hash bytes) := by
  by_cases valid : MetadataValid metadata
  · cases canonicalSchema with
    | error reason => cases reason; simp [validateLock, valid]
    | ok bytes => simp [validateLock, valid]
  · simp [validateLock, valid]

theorem lock_metadata_refusal_first {Error : Type} (errors : Errors Error)
    (hash : Bytes → Bytes) (metadata : Metadata) (canonicalSchema : CanonicalOutcome)
    (invalid : ¬MetadataValid metadata) :
    validateLock errors hash metadata canonicalSchema = .error errors.invalidProfileLock := by
  simp [validateLock, invalid]

theorem failed_schema_canonicalization_refused {Error : Type} (errors : Errors Error)
    (hash : Bytes → Bytes) (metadata : Metadata) :
    validateLock errors hash metadata (.error ()) = .error errors.invalidProfileLock := by
  by_cases valid : MetadataValid metadata <;> simp [validateLock, valid]

theorem recipe_digest_keeps_complete_preimage {Error : Type} (errors : Errors Error)
    (hash : Bytes → Bytes) (original : Bytes) :
    recipeDigest errors hash (.ok original) = .ok (hash (compiledRecipeDomain ++ original)) := rfl

theorem failed_source_canonicalization_refused {Error : Type} (errors : Errors Error)
    (hash : Bytes → Bytes) :
    recipeDigest errors hash (.error ()) = .error errors.invalidSource := rfl

/-- This is a statement about the hash argument. It asserts no injectivity or
collision resistance for the hash result. -/
theorem recipe_preimage_retains_original_source (left right : Bytes)
    (sameArgument : digestPreimage left = digestPreimage right) : left = right :=
  recipe_preimage_injective left right sameArgument

end Auths.Product.RecipeLockAdmission
