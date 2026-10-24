import Auths.Product.DerivedTokens

namespace Auths.Product.RecipeBinding
open RequestConstruction DerivedTokens

/-- Literal tags are part of the contract, including the terminal NUL in the
compiled-recipe hash domain. These are bytes, without Unicode normalization. -/
def sourceSchema : Bytes := [97,117,116,104,115,46,103,97,116,101,119,97,121,45,114,101,99,105,112,101,45,115,111,117,114,99,101,47,50]
def lockSchema : Bytes := [97,117,116,104,115,46,115,101,108,102,45,104,111,115,116,101,100,45,112,114,111,102,105,108,101,45,108,111,99,107,47,49]
def compiledRecipeDomain : Bytes := [97,117,116,104,115,46,103,97,116,101,119,97,121,45,99,111,109,112,105,108,101,100,45,114,101,99,105,112,101,47,50,0]

structure Binding where
  service : Bytes
  tool : Bytes
  schemaDigest : Bytes
  deriving DecidableEq

structure Metadata where
  schema : Bytes
  generatorFormat : Nat
  version : Nat
  profile : Bytes
  binding : Binding
  deriving DecidableEq

def LowerHexDigest (bytes : Bytes) : Prop :=
  bytes.length = 64 ∧ ∀ byte ∈ bytes, HexDigit byte

instance (bytes : Bytes) : Decidable (LowerHexDigest bytes) := by
  unfold LowerHexDigest
  infer_instance

def MetadataValid (lock : Metadata) : Prop :=
  lock.schema = lockSchema ∧ lock.generatorFormat = 2 ∧ lock.version ≠ 0 ∧
    lock.profile ≠ [] ∧ lock.binding.service ≠ [] ∧ lock.binding.tool ≠ [] ∧
    LowerHexDigest lock.binding.schemaDigest

instance (lock : Metadata) : Decidable (MetadataValid lock) := by
  unfold MetadataValid
  infer_instance

def SourceMatches (source lock : Binding) : Prop :=
  source.service = lock.service ∧ source.tool = lock.tool ∧ source.schemaDigest = lock.schemaDigest

instance (source lock : Binding) : Decidable (SourceMatches source lock) := by
  unfold SourceMatches
  infer_instance

def SchemaDigestMatches (declared digest : Bytes) : Prop := declared = hexDigest digest

instance (declared digest : Bytes) : Decidable (SchemaDigestMatches declared digest) := by
  unfold SchemaDigestMatches
  infer_instance

structure DigestInput where
  domain : Bytes
  canonicalSource : Bytes
  deriving DecidableEq

def recipeInput (canonicalSource : Bytes) : DigestInput :=
  ⟨compiledRecipeDomain, canonicalSource⟩

def digestPreimage (canonicalSource : Bytes) : Bytes := compiledRecipeDomain ++ canonicalSource

theorem source_matches_iff_equal (source lock : Binding) : SourceMatches source lock ↔ source = lock := by
  cases source
  cases lock
  simp [SourceMatches, Binding.mk.injEq]

theorem admitted_metadata_components (lock : Metadata) (admitted : MetadataValid lock) :
    lock.schema = lockSchema ∧ lock.generatorFormat = 2 ∧ lock.version ≠ 0 ∧
      lock.profile ≠ [] ∧ lock.binding.service ≠ [] ∧ lock.binding.tool ≠ [] ∧
      lock.binding.schemaDigest.length = 64 ∧ ∀ byte ∈ lock.binding.schemaDigest, HexDigit byte := by
  simpa [MetadataValid, LowerHexDigest] using admitted

theorem bound_source_retains_lock_components (source : Binding) (lock : Metadata)
    (admitted : MetadataValid lock) (matches : SourceMatches source lock.binding) :
    source.service ≠ [] ∧ source.tool ≠ [] ∧ LowerHexDigest source.schemaDigest := by
  have same := (source_matches_iff_equal source lock.binding).mp matches
  rw [same]
  exact ⟨admitted.2.2.2.2.1, admitted.2.2.2.2.2.1, admitted.2.2.2.2.2.2⟩

theorem actual_digest_spelling_is_admitted (declared digest : Bytes)
    (size : digest.length = 32) (bounded : ∀ byte ∈ digest, byte < 256)
    (matches : SchemaDigestMatches declared digest) : LowerHexDigest declared := by
  rw [SchemaDigestMatches] at matches
  rw [matches]
  exact ⟨by rw [hex_digest_length, size], hex_digest_digits digest bounded⟩

/-- This conclusion concerns the actual input digest, not injectivity of SHA-256. -/
theorem declared_digest_determines_actual_digest (declared left right : Bytes)
    (leftBound : ∀ byte ∈ left, byte < 256) (rightBound : ∀ byte ∈ right, byte < 256)
    (first : SchemaDigestMatches declared left) (second : SchemaDigestMatches declared right) :
    left = right := by
  exact hex_digest_injective left right leftBound rightBound (first.symm.trans second)

theorem recipe_input_preserves_original (canonicalSource : Bytes) :
    (recipeInput canonicalSource).domain = compiledRecipeDomain ∧
      (recipeInput canonicalSource).canonicalSource = canonicalSource := by
  exact ⟨rfl, rfl⟩

theorem recipe_input_has_exact_preimage (canonicalSource : Bytes) :
    (recipeInput canonicalSource).domain ++ (recipeInput canonicalSource).canonicalSource =
      digestPreimage canonicalSource := rfl

theorem recipe_preimage_injective (left right : Bytes)
    (same : digestPreimage left = digestPreimage right) : left = right := by
  exact List.append_left_cancel same

theorem recipe_preimage_size (canonicalSource : Bytes) :
    (digestPreimage canonicalSource).length = 32 + canonicalSource.length := by
  simp [digestPreimage, compiledRecipeDomain]

end Auths.Product.RecipeBinding
