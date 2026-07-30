namespace Auths.Product

/--
An opaque byte-exact semantic identity. The production refinement supplies
validated ASCII bytes and their V1 length proof.
-/
structure SemanticId where
  bytes : List UInt8
  nonempty : bytes ≠ []
  deriving DecidableEq

/-- Exact 32-byte commitment used by the product contract. -/
structure Digest where
  bytes : List UInt8
  exactWidth : bytes.length = 32
  deriving DecidableEq

structure PolicyCommitment where
  policyType : SemanticId
  policyVersion : Nat
  versionPositive : 0 < policyVersion
  canonicalization : SemanticId
  policyDigest : Digest
  evaluatorSemantics : SemanticId

structure ConfigurationCommitment where
  semantics : SemanticId
  canonicalization : SemanticId
  digest : Digest
  implementation : Option SemanticId

inductive ConfigurationMatch where
  | matches
  | semanticMismatch
  | canonicalizationMismatch
  | digestMismatch
  | implementationMismatch
  deriving DecidableEq, Repr

def projectedConfigurationMatch
    (semanticEqual canonicalizationEqual digestEqual
      implementationEqualOrUnpinned : Bool) : ConfigurationMatch :=
  if !semanticEqual then
    .semanticMismatch
  else if !canonicalizationEqual then
    .canonicalizationMismatch
  else if !digestEqual then
    .digestMismatch
  else if !implementationEqualOrUnpinned then
    .implementationMismatch
  else
    .matches

/--
Required configuration may omit an implementation pin. If it supplies one,
the executed implementation must be the same byte-exact identity.
-/
def configurationMatch
    (required executed : ConfigurationCommitment) : ConfigurationMatch :=
  if required.semantics ≠ executed.semantics then
    .semanticMismatch
  else if required.canonicalization ≠ executed.canonicalization then
    .canonicalizationMismatch
  else if required.digest ≠ executed.digest then
    .digestMismatch
  else
    match required.implementation with
    | none => .matches
    | some requiredImplementation =>
        if executed.implementation = some requiredImplementation then
          .matches
        else
          .implementationMismatch

theorem configuration_match_refl (configuration : ConfigurationCommitment) :
    configurationMatch configuration configuration = .matches := by
  rcases configuration with ⟨semantics, canonicalization, digest, implementation⟩
  cases implementation <;> simp [configurationMatch]

theorem configuration_match_deterministic
    (required executed : ConfigurationCommitment) :
    ∃ result, configurationMatch required executed = result := by
  exact ⟨configurationMatch required executed, rfl⟩

end Auths.Product
