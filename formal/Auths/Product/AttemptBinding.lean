import Auths.Product.RecipeBinding
import Auths.Product.Recovery

namespace Auths.Product.AttemptBinding
open RequestConstruction DerivedTokens

structure Stored where
  namespaceBytes : Bytes
  operation : Bytes
  recipeHex : Bytes
  actionHex : Bytes
  evaluatedAt : Nat
  deriving DecidableEq

structure Request where
  namespaceBytes : Bytes
  operation : Bytes
  recipeDigest : Bytes
  actionCommitment : Bytes
  evaluatedAt : Nat
  deriving DecidableEq

def InstallationMatches (namespaceBytes digest installedNamespace installedDigest : Bytes) : Prop :=
  namespaceBytes = installedNamespace ∧ digest = installedDigest

instance (namespaceBytes digest installedNamespace installedDigest : Bytes) :
    Decidable (InstallationMatches namespaceBytes digest installedNamespace installedDigest) := by
  unfold InstallationMatches
  infer_instance

/-- Exact immutable record identity; matching does not establish that the
record was acknowledged by the backend or that its caller is authorized. -/
def ClaimMatches (stage : Recovery.Stage) (stored : Stored) (request : Request) : Prop :=
  stage = .attempting ∧ stored.evaluatedAt = request.evaluatedAt ∧
    stored.namespaceBytes = request.namespaceBytes ∧ stored.operation = request.operation ∧
    stored.recipeHex = hexDigest request.recipeDigest ∧ stored.actionHex = hexDigest request.actionCommitment

instance (stage : Recovery.Stage) (stored : Stored) (request : Request) : Decidable (ClaimMatches stage stored request) := by
  unfold ClaimMatches
  infer_instance

def DigestBytesValid (request : Request) : Prop :=
  (∀ byte ∈ request.recipeDigest, byte < 256) ∧ (∀ byte ∈ request.actionCommitment, byte < 256)

def storedFor (request : Request) : Stored :=
  ⟨request.namespaceBytes, request.operation, hexDigest request.recipeDigest,
    hexDigest request.actionCommitment, request.evaluatedAt⟩

theorem matching_claim_retains_every_identity_column (stage : Recovery.Stage) (stored : Stored) (request : Request)
    (matches : ClaimMatches stage stored request) :
    stage = .attempting ∧ stored.namespaceBytes = request.namespaceBytes ∧ stored.operation = request.operation ∧
      stored.recipeHex = hexDigest request.recipeDigest ∧ stored.actionHex = hexDigest request.actionCommitment ∧
      stored.evaluatedAt = request.evaluatedAt := by
  exact ⟨matches.1, matches.2.2.1, matches.2.2.2.1, matches.2.2.2.2.1, matches.2.2.2.2.2, matches.2.1⟩

theorem other_stages_refuse (stage : Recovery.Stage) (stored : Stored) (request : Request)
    (other : stage ≠ .attempting) : ¬ClaimMatches stage stored request := fun matches => other matches.1

theorem original_identity_has_useful_match (request : Request) : ClaimMatches .attempting (storedFor request) request := by
  simp [ClaimMatches, storedFor]

/-- Hexadecimal spelling is injective on bytes. This theorem identifies only
the request identity columns, without assuming SHA-256 collision freedom. -/
theorem one_record_has_one_request_identity (stage : Recovery.Stage) (stored : Stored) (first second : Request)
    (firstBytes : DigestBytesValid first) (secondBytes : DigestBytesValid second)
    (left : ClaimMatches stage stored first) (right : ClaimMatches stage stored second) : first = second := by
  have names : first.namespaceBytes = second.namespaceBytes := left.2.2.1.symm.trans right.2.2.1
  have operations : first.operation = second.operation := left.2.2.2.1.symm.trans right.2.2.2.1
  have recipes := hex_digest_injective first.recipeDigest second.recipeDigest firstBytes.1 secondBytes.1
    (left.2.2.2.2.1.symm.trans right.2.2.2.2.1)
  have actions := hex_digest_injective first.actionCommitment second.actionCommitment firstBytes.2 secondBytes.2
    (left.2.2.2.2.2.symm.trans right.2.2.2.2.2)
  have times : first.evaluatedAt = second.evaluatedAt := left.2.1.symm.trans right.2.1
  cases first
  cases second
  simp_all

theorem distinct_identity_refuses (stage : Recovery.Stage) (stored : Stored) (first second : Request)
    (firstBytes : DigestBytesValid first) (secondBytes : DigestBytesValid second)
    (left : ClaimMatches stage stored first) (different : first ≠ second) : ¬ClaimMatches stage stored second := by
  intro right
  exact different (one_record_has_one_request_identity stage stored first second firstBytes secondBytes left right)

theorem installed_names_and_mapping_are_exact (namespaceBytes digest installedNamespace installedDigest : Bytes)
    (matches : InstallationMatches namespaceBytes digest installedNamespace installedDigest) :
    namespaceBytes = installedNamespace ∧ digest = installedDigest := matches

end Auths.Product.AttemptBinding
