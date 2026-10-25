import Auths.Crypto.BorrowedKeys

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.BundleNormalization
open Auths.Codec

/- Projection after stable sorting retains the complete record. This is a
mathematical key/record association fact, with no successful source sort,
expected encoder bytes or hash injectivity premise. -/
theorem entries_project {Record Id : Type} (idKey : Id → List Nat)
    (identifier : Record → Id) (recordKey : Record → List Nat)
    (sameKey : ∀ record, idKey (identifier record) = recordKey record) (records : List Record) :
    (StableNormalization.sort (fun entry : Id × Record => idKey entry.1)
      (records.map (fun record => (identifier record, record)))).map Prod.snd =
        StableNormalization.sort recordKey records := by
  have keyAgreement : ∀ entry ∈ records.map (fun record => (identifier record, record)),
      idKey entry.1 = recordKey entry.2 := by
    intro entry member
    obtain ⟨record, _, same⟩ := List.mem_map.mp member
    subst entry
    exact sameKey record
  rw [StableNormalization.sort_congr_on (fun entry : Id × Record => idKey entry.1)
    (fun entry => recordKey entry.2) _ keyAgreement]
  rw [StableNormalization.map_sort Prod.snd recordKey]
  simp only [List.map_map, Function.comp_def, List.map_id]

variable [primitive : Sha256Primitives]

@[step] theorem grant_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (bundle : auths_model.ProofBundle)
    (domains : ∀ record ∈ bundle.grants.val, BorrowedKeys.GrantDomain record)
    (capacity : BorrowedKeys.ReferenceCapacity bundle.grants.val.length) :
    encode.sorted_grants bundle ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = BundleObjects.grants sha256 bundle ⦄ := by
  unfold encode.sorted_grants
  simp only [auths_model.ProofBundle.impl.grants, core.ops.deref.DerefVec, bind_tc_ok]
  step with BorrowedKeys.grant_derive_exact sha256 contract (alloc.vec.Vec.deref bundle.grants)
    (by simpa only [alloc.vec.deref_exact] using domains) (by simpa only [alloc.vec.deref_exact] using capacity) as ⟨derived, derivedMeaning⟩
  cases derived with
  | Err reason => exact False.elim derivedMeaning
  | Ok keyed =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    rw [BundleSorting.grant_keys_exact, bind_tc_ok]
    step with OwnedRecords.unkey_exact (SnapshotOrdering.sortedByKey RecordNormalization.grantKey keyed)
      as ⟨output, projected⟩
    have exactRecords : output.val = BundleObjects.grants sha256 bundle := by
      rw [projected, SnapshotOrdering.sorted_by_key_contents, derivedMeaning]
      simpa only [BorrowedKeys.grantEntries, RecordNormalization.grantKey, BundleObjects.grants, alloc.vec.deref_exact] using
        entries_project ProtocolOrdering.grantIdKey (BorrowedKeys.grantIdentifier sha256)
          (BundleObjects.grantKey sha256) (BorrowedKeys.grant_key_meaning sha256) bundle.grants.val
    simpa only [spec_ok] using exactRecords

@[step] theorem principal_status_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (records : Slice auths_model.SignedPrincipalStatus)
    (domains : ∀ record ∈ records.val, BorrowedKeys.PrincipalStatusDomain record)
    (capacity : BorrowedKeys.ReferenceCapacity records.val.length) :
    encode.sorted_principal_status records ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = StableNormalization.sort (BundleObjects.principalStatusKey sha256) records.val ⦄ := by
  unfold encode.sorted_principal_status
  step with BorrowedKeys.principal_status_derive_exact sha256 contract records
    domains capacity as ⟨derived, derivedMeaning⟩
  cases derived with
  | Err reason => exact False.elim derivedMeaning
  | Ok keyed =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    rw [BundleSorting.principal_status_keys_exact, bind_tc_ok]
    step with OwnedRecords.unkey_exact (SnapshotOrdering.sortedByKey RecordNormalization.principalStatusKey keyed)
      as ⟨output, projected⟩
    have exactRecords : output.val = StableNormalization.sort (BundleObjects.principalStatusKey sha256) records.val := by
      rw [projected, SnapshotOrdering.sorted_by_key_contents, derivedMeaning]
      simpa only [BorrowedKeys.principal_statusEntries, RecordNormalization.principalStatusKey] using
        entries_project ProtocolOrdering.principalStatusIdKey (BorrowedKeys.principal_statusIdentifier sha256)
          (BundleObjects.principalStatusKey sha256) (BorrowedKeys.principal_status_key_meaning sha256) records.val
    simpa only [spec_ok] using exactRecords

@[step] theorem grant_status_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (records : Slice auths_model.SignedGrantStatus)
    (domains : ∀ record ∈ records.val, BorrowedKeys.GrantStatusDomain record)
    (capacity : BorrowedKeys.ReferenceCapacity records.val.length) :
    encode.sorted_grant_status records ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = StableNormalization.sort (BundleObjects.grantStatusKey sha256) records.val ⦄ := by
  unfold encode.sorted_grant_status
  step with BorrowedKeys.grant_status_derive_exact sha256 contract records
    domains capacity as ⟨derived, derivedMeaning⟩
  cases derived with
  | Err reason => exact False.elim derivedMeaning
  | Ok keyed =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    rw [BundleSorting.grant_status_keys_exact, bind_tc_ok]
    step with OwnedRecords.unkey_exact (SnapshotOrdering.sortedByKey RecordNormalization.grantStatusKey keyed)
      as ⟨output, projected⟩
    have exactRecords : output.val = StableNormalization.sort (BundleObjects.grantStatusKey sha256) records.val := by
      rw [projected, SnapshotOrdering.sorted_by_key_contents, derivedMeaning]
      simpa only [BorrowedKeys.grant_statusEntries, RecordNormalization.grantStatusKey] using
        entries_project ProtocolOrdering.grantStatusIdKey (BorrowedKeys.grant_statusIdentifier sha256)
          (BundleObjects.grantStatusKey sha256) (BorrowedKeys.grant_status_key_meaning sha256) records.val
    simpa only [spec_ok] using exactRecords

end Auths.Crypto.BundleNormalization
