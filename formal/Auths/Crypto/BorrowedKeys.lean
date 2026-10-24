import Auths.Crypto.BundleSorting
import Auths.Crypto.IdentifierCallers

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.BorrowedKeys
open Auths.Codec Auths.Codec.Refinement

/- Independent input domains for the concrete source key loops. A 128-byte
per-record envelope conservatively dominates the compile-time asserted keyed
reference/pointer layouts and growth/scratch room; it is not a physical OOM
or measured peak-memory claim. The unsigned-statement envelope additionally
retains signed native byte/growth room before source ID framing. -/
def ReferenceCapacity (count : Nat) : Prop :=
  count ≤ Usize.max ∧ (128 * count : Int) ≤ Isize.max

theorem reference_capacity_mono {small large : Nat} (within : small ≤ large)
    (bounded : ReferenceCapacity large) : ReferenceCapacity small := by
  rcases bounded with ⟨words, bytes⟩
  constructor <;> omega

variable [primitive : Sha256Primitives]

def GrantDomain (record : auths_model.SignedGrant) : Prop :=
  ProtocolValidity.Grant record.statement ∧
    StatementWriters.grantCost record.statement ≤ Usize.max ∧
    (2 * StatementWriters.grantCost record.statement : Int) ≤ Isize.max ∧
    FramedHash.IdentifierAdmissible (UnsignedObjects.grant record.statement)

def grantIdentifier (sha256 : List Nat → auths_model.Digest) (record : auths_model.SignedGrant) :
    auths_model.GrantId :=
  sha256 (CommitmentFrames.identifier ⟨1, UnsignedObjects.grant record.statement⟩)

def grantEntries (sha256 : List Nat → auths_model.Digest) (records : List auths_model.SignedGrant) :=
  records.map (fun record => (grantIdentifier sha256 record, record))

theorem grant_key_meaning (sha256 : List Nat → auths_model.Digest) (record : auths_model.SignedGrant) :
    ProtocolOrdering.grantIdKey (grantIdentifier sha256 record) = BundleObjects.grantKey sha256 record := by rfl

@[step] theorem grant_push_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256)
    (current : alloc.vec.Vec (auths_model.GrantId × auths_model.SignedGrant))
    (record : auths_model.SignedGrant) (domain : GrantDomain record)
    (capacity : ReferenceCapacity (current.val.length + 1)) :
    encode.push_keyed_grants current record ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = current.val ++ [(grantIdentifier sha256 record, record)] ⦄ := by
  have room : current.val.length < Usize.max := by have := capacity.1; omega
  have identifier : hash.grant_id record.statement = ok (.Ok (grantIdentifier sha256 record)) := by
    simpa only [grantIdentifier, IdentifierCallers.grantFrame] using
      IdentifierCallers.grant_exact sha256 contract record.statement domain.1 domain.2.1 domain.2.2.2
  unfold encode.push_keyed_grants
  simp only [auths_model.SignedGrant.impl.statement, bind_tc_ok, identifier,
    core.result.Result.Insts.CoreOpsTry.branch]
  step with alloc.vec.push_spec current (grantIdentifier sha256 record, record) room
    as ⟨output, appended⟩
  simpa only [spec_ok] using appended

private theorem grant_suffix (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (records : Slice auths_model.SignedGrant)
    (position : Std.Usize) (current : alloc.vec.Vec (auths_model.GrantId × auths_model.SignedGrant))
    (rest : List auths_model.SignedGrant) (remaining : records.val.drop position.val = rest)
    (domains : ∀ record ∈ rest, GrantDomain record)
    (capacity : ReferenceCapacity (current.val.length + rest.length)) :
    encode.derive_grant_ref_keys_loop records (.Ok current) position ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = current.val ++ grantEntries sha256 rest ⦄ := by
  induction rest generalizing position current with
  | nil =>
    have finished : ¬ position < records.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.derive_grant_ref_keys_loop.eq_def]
    simp [finished, spec_ok, grantEntries]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head records position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next records position first tail remaining
    have firstDomain := domains first (by simp)
    have tailDomains : ∀ record ∈ tail, GrantDomain record :=
      fun record member => domains record (by simp [member])
    have firstCapacity : ReferenceCapacity (current.val.length + 1) :=
      reference_capacity_mono (small := current.val.length + 1)
        (large := current.val.length + (first :: tail).length) (by simp; omega) capacity
    rw [encode.derive_grant_ref_keys_loop.eq_def]
    simp only [guard, ↓reduceIte, core.result.Result.is_ok, atFirst, bind_tc_ok]
    step with grant_push_exact sha256 contract current first firstDomain firstCapacity
      as ⟨pushed, meaning⟩
    cases pushed with
    | Err reason => exact False.elim meaning
    | Ok after =>
      have sameCount : after.val.length + tail.length = current.val.length + (first :: tail).length := by
        simp only [meaning, List.length_append, List.length_singleton, List.length_cons]
        omega
      have nextCapacity : ReferenceCapacity (after.val.length + tail.length) := by
        rw [sameCount]
        exact capacity
      simp only [bind_tc_ok, increment]
      apply spec_mono (ih next after nextRemaining tailDomains nextCapacity)
      intro result resultMeaning
      cases result with
      | Err reason => exact False.elim resultMeaning
      | Ok output =>
        simp only at resultMeaning ⊢
        rw [resultMeaning, meaning]
        simp [grantEntries, List.append_assoc]

@[step] theorem grant_derive_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (records : Slice auths_model.SignedGrant)
    (domains : ∀ record ∈ records.val, GrantDomain record)
    (capacity : ReferenceCapacity records.val.length) :
    encode.derive_grant_ref_keys records ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = grantEntries sha256 records.val ⦄ := by
  unfold encode.derive_grant_ref_keys
  simp only [lift, bind_tc_ok]
  apply spec_mono (grant_suffix sha256 contract records 0#usize
    (alloc.vec.Vec.with_capacity (auths_model.GrantId × auths_model.SignedGrant) (Slice.len records))
    records.val (by simp) domains (by
      simpa only [alloc.vec.with_capacity_contents, List.length_nil, Nat.zero_add] using capacity))
  intro result meaning
  cases result with
  | Err reason => exact False.elim meaning
  | Ok output => simpa only [alloc.vec.with_capacity_contents, List.nil_append] using meaning

def PrincipalStatusDomain (record : auths_model.SignedPrincipalStatus) : Prop :=
  ProtocolValidity.PrincipalStatus record.statement ∧
    StatementWriters.principal_statusCost record.statement ≤ Usize.max ∧
    (2 * StatementWriters.principal_statusCost record.statement : Int) ≤ Isize.max ∧
    FramedHash.IdentifierAdmissible (UnsignedObjects.principalStatus record.statement)

def principal_statusIdentifier (sha256 : List Nat → auths_model.Digest) (record : auths_model.SignedPrincipalStatus) :
    auths_model.PrincipalStatusId :=
  sha256 (CommitmentFrames.identifier ⟨5, UnsignedObjects.principalStatus record.statement⟩)

def principal_statusEntries (sha256 : List Nat → auths_model.Digest) (records : List auths_model.SignedPrincipalStatus) :=
  records.map (fun record => (principal_statusIdentifier sha256 record, record))

theorem principal_status_key_meaning (sha256 : List Nat → auths_model.Digest) (record : auths_model.SignedPrincipalStatus) :
    ProtocolOrdering.principalStatusIdKey (principal_statusIdentifier sha256 record) = BundleObjects.principalStatusKey sha256 record := by rfl

@[step] theorem principal_status_push_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256)
    (current : alloc.vec.Vec (auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus))
    (record : auths_model.SignedPrincipalStatus) (domain : PrincipalStatusDomain record)
    (capacity : ReferenceCapacity (current.val.length + 1)) :
    encode.push_keyed_principal_status current record ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = current.val ++ [(principal_statusIdentifier sha256 record, record)] ⦄ := by
  have room : current.val.length < Usize.max := by have := capacity.1; omega
  have identifier : hash.principal_status_id record.statement = ok (.Ok (principal_statusIdentifier sha256 record)) := by
    simpa only [principal_statusIdentifier, IdentifierCallers.principal_statusFrame] using
      IdentifierCallers.principal_status_exact sha256 contract record.statement domain.1 domain.2.1 domain.2.2.2
  unfold encode.push_keyed_principal_status
  simp only [auths_model.SignedPrincipalStatus.impl.statement, bind_tc_ok, identifier,
    core.result.Result.Insts.CoreOpsTry.branch]
  step with alloc.vec.push_spec current (principal_statusIdentifier sha256 record, record) room
    as ⟨output, appended⟩
  simpa only [spec_ok] using appended

private theorem principal_status_suffix (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (records : Slice auths_model.SignedPrincipalStatus)
    (position : Std.Usize) (current : alloc.vec.Vec (auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus))
    (rest : List auths_model.SignedPrincipalStatus) (remaining : records.val.drop position.val = rest)
    (domains : ∀ record ∈ rest, PrincipalStatusDomain record)
    (capacity : ReferenceCapacity (current.val.length + rest.length)) :
    encode.derive_principal_status_ref_keys_loop records (.Ok current) position ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = current.val ++ principal_statusEntries sha256 rest ⦄ := by
  induction rest generalizing position current with
  | nil =>
    have finished : ¬ position < records.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.derive_principal_status_ref_keys_loop.eq_def]
    simp [finished, spec_ok, principal_statusEntries]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head records position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next records position first tail remaining
    have firstDomain := domains first (by simp)
    have tailDomains : ∀ record ∈ tail, PrincipalStatusDomain record :=
      fun record member => domains record (by simp [member])
    have firstCapacity : ReferenceCapacity (current.val.length + 1) :=
      reference_capacity_mono (small := current.val.length + 1)
        (large := current.val.length + (first :: tail).length) (by simp; omega) capacity
    rw [encode.derive_principal_status_ref_keys_loop.eq_def]
    simp only [guard, ↓reduceIte, core.result.Result.is_ok, atFirst, bind_tc_ok]
    step with principal_status_push_exact sha256 contract current first firstDomain firstCapacity
      as ⟨pushed, meaning⟩
    cases pushed with
    | Err reason => exact False.elim meaning
    | Ok after =>
      have sameCount : after.val.length + tail.length = current.val.length + (first :: tail).length := by
        simp only [meaning, List.length_append, List.length_singleton, List.length_cons]
        omega
      have nextCapacity : ReferenceCapacity (after.val.length + tail.length) := by
        rw [sameCount]
        exact capacity
      simp only [bind_tc_ok, increment]
      apply spec_mono (ih next after nextRemaining tailDomains nextCapacity)
      intro result resultMeaning
      cases result with
      | Err reason => exact False.elim resultMeaning
      | Ok output =>
        simp only at resultMeaning ⊢
        rw [resultMeaning, meaning]
        simp [principal_statusEntries, List.append_assoc]

@[step] theorem principal_status_derive_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (records : Slice auths_model.SignedPrincipalStatus)
    (domains : ∀ record ∈ records.val, PrincipalStatusDomain record)
    (capacity : ReferenceCapacity records.val.length) :
    encode.derive_principal_status_ref_keys records ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = principal_statusEntries sha256 records.val ⦄ := by
  unfold encode.derive_principal_status_ref_keys
  simp only [lift, bind_tc_ok]
  apply spec_mono (principal_status_suffix sha256 contract records 0#usize
    (alloc.vec.Vec.with_capacity (auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus) (Slice.len records))
    records.val (by simp) domains (by
      simpa only [alloc.vec.with_capacity_contents, List.length_nil, Nat.zero_add] using capacity))
  intro result meaning
  cases result with
  | Err reason => exact False.elim meaning
  | Ok output => simpa only [alloc.vec.with_capacity_contents, List.nil_append] using meaning

def GrantStatusDomain (record : auths_model.SignedGrantStatus) : Prop :=
  ProtocolValidity.GrantStatus record.statement ∧
    StatementWriters.grant_statusCost record.statement ≤ Usize.max ∧
    (2 * StatementWriters.grant_statusCost record.statement : Int) ≤ Isize.max ∧
    FramedHash.IdentifierAdmissible (UnsignedObjects.grantStatus record.statement)

def grant_statusIdentifier (sha256 : List Nat → auths_model.Digest) (record : auths_model.SignedGrantStatus) :
    auths_model.GrantStatusId :=
  sha256 (CommitmentFrames.identifier ⟨6, UnsignedObjects.grantStatus record.statement⟩)

def grant_statusEntries (sha256 : List Nat → auths_model.Digest) (records : List auths_model.SignedGrantStatus) :=
  records.map (fun record => (grant_statusIdentifier sha256 record, record))

theorem grant_status_key_meaning (sha256 : List Nat → auths_model.Digest) (record : auths_model.SignedGrantStatus) :
    ProtocolOrdering.grantStatusIdKey (grant_statusIdentifier sha256 record) = BundleObjects.grantStatusKey sha256 record := by rfl

@[step] theorem grant_status_push_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256)
    (current : alloc.vec.Vec (auths_model.GrantStatusId × auths_model.SignedGrantStatus))
    (record : auths_model.SignedGrantStatus) (domain : GrantStatusDomain record)
    (capacity : ReferenceCapacity (current.val.length + 1)) :
    encode.push_keyed_grant_status current record ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = current.val ++ [(grant_statusIdentifier sha256 record, record)] ⦄ := by
  have room : current.val.length < Usize.max := by have := capacity.1; omega
  have identifier : hash.grant_status_id record.statement = ok (.Ok (grant_statusIdentifier sha256 record)) := by
    simpa only [grant_statusIdentifier, IdentifierCallers.grant_statusFrame] using
      IdentifierCallers.grant_status_exact sha256 contract record.statement domain.1 domain.2.1 domain.2.2.2
  unfold encode.push_keyed_grant_status
  simp only [auths_model.SignedGrantStatus.impl.statement, bind_tc_ok, identifier,
    core.result.Result.Insts.CoreOpsTry.branch]
  step with alloc.vec.push_spec current (grant_statusIdentifier sha256 record, record) room
    as ⟨output, appended⟩
  simpa only [spec_ok] using appended

private theorem grant_status_suffix (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (records : Slice auths_model.SignedGrantStatus)
    (position : Std.Usize) (current : alloc.vec.Vec (auths_model.GrantStatusId × auths_model.SignedGrantStatus))
    (rest : List auths_model.SignedGrantStatus) (remaining : records.val.drop position.val = rest)
    (domains : ∀ record ∈ rest, GrantStatusDomain record)
    (capacity : ReferenceCapacity (current.val.length + rest.length)) :
    encode.derive_grant_status_ref_keys_loop records (.Ok current) position ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = current.val ++ grant_statusEntries sha256 rest ⦄ := by
  induction rest generalizing position current with
  | nil =>
    have finished : ¬ position < records.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [encode.derive_grant_status_ref_keys_loop.eq_def]
    simp [finished, spec_ok, grant_statusEntries]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head records position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next records position first tail remaining
    have firstDomain := domains first (by simp)
    have tailDomains : ∀ record ∈ tail, GrantStatusDomain record :=
      fun record member => domains record (by simp [member])
    have firstCapacity : ReferenceCapacity (current.val.length + 1) :=
      reference_capacity_mono (small := current.val.length + 1)
        (large := current.val.length + (first :: tail).length) (by simp; omega) capacity
    rw [encode.derive_grant_status_ref_keys_loop.eq_def]
    simp only [guard, ↓reduceIte, core.result.Result.is_ok, atFirst, bind_tc_ok]
    step with grant_status_push_exact sha256 contract current first firstDomain firstCapacity
      as ⟨pushed, meaning⟩
    cases pushed with
    | Err reason => exact False.elim meaning
    | Ok after =>
      have sameCount : after.val.length + tail.length = current.val.length + (first :: tail).length := by
        simp only [meaning, List.length_append, List.length_singleton, List.length_cons]
        omega
      have nextCapacity : ReferenceCapacity (after.val.length + tail.length) := by
        rw [sameCount]
        exact capacity
      simp only [bind_tc_ok, increment]
      apply spec_mono (ih next after nextRemaining tailDomains nextCapacity)
      intro result resultMeaning
      cases result with
      | Err reason => exact False.elim resultMeaning
      | Ok output =>
        simp only at resultMeaning ⊢
        rw [resultMeaning, meaning]
        simp [grant_statusEntries, List.append_assoc]

@[step] theorem grant_status_derive_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (records : Slice auths_model.SignedGrantStatus)
    (domains : ∀ record ∈ records.val, GrantStatusDomain record)
    (capacity : ReferenceCapacity records.val.length) :
    encode.derive_grant_status_ref_keys records ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = grant_statusEntries sha256 records.val ⦄ := by
  unfold encode.derive_grant_status_ref_keys
  simp only [lift, bind_tc_ok]
  apply spec_mono (grant_status_suffix sha256 contract records 0#usize
    (alloc.vec.Vec.with_capacity (auths_model.GrantStatusId × auths_model.SignedGrantStatus) (Slice.len records))
    records.val (by simp) domains (by
      simpa only [alloc.vec.with_capacity_contents, List.length_nil, Nat.zero_add] using capacity))
  intro result meaning
  cases result with
  | Err reason => exact False.elim meaning
  | Ok output => simpa only [alloc.vec.with_capacity_contents, List.nil_append] using meaning

end Auths.Crypto.BorrowedKeys
