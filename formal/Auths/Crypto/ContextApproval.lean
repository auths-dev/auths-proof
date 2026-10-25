import Auths.Crypto.ContextObjects
import Auths.Crypto.RequirementIdentifiers
import Auths.Crypto.BundleWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ContextApproval
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters Auths.Crypto.BorrowedKeys

/- Context requirements use their own 64-member bound. Actual identifier
derivation, stable sorting and reference projection precede the concrete full
record loop. No owned payload clone, hash injectivity, successful normalizer or
desired intermediate bytes is a premise of these writer specifications. -/
variable [primitive : Sha256Primitives]

def Domain (record : auths_model.approval.ApprovalRequirement) : Prop :=
  ProtocolValidity.ApprovalRequirement record

def identifier (sha256 : List Nat → auths_model.Digest)
    (record : auths_model.approval.ApprovalRequirement) : auths_model.ApprovalRequirementId :=
  sha256 (CommitmentFrames.identifier ⟨12, UnsignedObjects.approvalRequirement record⟩)

def entries (sha256 : List Nat → auths_model.Digest)
    (records : List auths_model.approval.ApprovalRequirement) :=
  records.map (fun record => (identifier sha256 record, record))

def entryKey (entry : auths_model.ApprovalRequirementId × auths_model.approval.ApprovalRequirement) : List Nat :=
  ProtocolOrdering.approvalRequirementIdKey entry.1

theorem key_meaning (sha256 : List Nat → auths_model.Digest)
    (record : auths_model.approval.ApprovalRequirement) :
    ProtocolOrdering.approvalRequirementIdKey (identifier sha256 record) = ContextObjects.approvalKey sha256 record := by rfl

theorem source_selector (entry : auths_model.ApprovalRequirementId × auths_model.approval.ApprovalRequirement) :
    approval.requirement_ref_sort_key entry = ok entry.1 := by rfl

theorem sort_keys_exact (values : alloc.vec.Vec (auths_model.ApprovalRequirementId × auths_model.approval.ApprovalRequirement)) :
    approval.sort_requirement_ref_keys values = ok (SnapshotOrdering.sortedByKey entryKey values) := by
  auths_record_key_sort approval.sort_requirement_ref_keys,
    approval.requirement_ref_sort_key, source_selector,
    ProtocolOrdering.approvalRequirementIdKey, ProtocolOrdering.approval_requirement_id_compare, entryKey

@[step] theorem push_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256)
    (current : alloc.vec.Vec (auths_model.ApprovalRequirementId × auths_model.approval.ApprovalRequirement))
    (record : auths_model.approval.ApprovalRequirement) (domain : Domain record)
    (capacity : ReferenceCapacity (current.val.length + 1)) :
    approval.push_keyed_requirement current record ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = current.val ++ [(identifier sha256 record, record)] ⦄ := by
  have room : current.val.length < Usize.max := by have := capacity.1; omega
  have idRun : hash.approval_requirement_id record = ok (.Ok (identifier sha256 record)) := by
    simpa only [identifier, RequirementIdentifiers.approvalFrame] using
      RequirementIdentifiers.approval_valid_exact sha256 contract record domain
  unfold approval.push_keyed_requirement
  simp only [idRun, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with alloc.vec.push_spec current (identifier sha256 record, record) room
    as ⟨output, appended⟩
  simpa only [spec_ok] using appended

private theorem derive_suffix (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (records : Slice auths_model.approval.ApprovalRequirement)
    (position : Std.Usize) (current : alloc.vec.Vec (auths_model.ApprovalRequirementId × auths_model.approval.ApprovalRequirement))
    (rest : List auths_model.approval.ApprovalRequirement) (remaining : records.val.drop position.val = rest)
    (domains : ∀ record ∈ rest, Domain record)
    (capacity : ReferenceCapacity (current.val.length + rest.length)) :
    approval.derive_requirement_ref_keys_loop records (.Ok current) position ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = current.val ++ entries sha256 rest ⦄ := by
  induction rest generalizing position current with
  | nil =>
    have finished : ¬ position < records.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [approval.derive_requirement_ref_keys_loop.eq_def]
    simp [finished, spec_ok, entries]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head records position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next records position first tail remaining
    have firstDomain := domains first (by simp)
    have tailDomains : ∀ record ∈ tail, Domain record :=
      fun record member => domains record (by simp [member])
    have firstCapacity : ReferenceCapacity (current.val.length + 1) :=
      reference_capacity_mono (small := current.val.length + 1)
        (large := current.val.length + (first :: tail).length) (by simp; omega) capacity
    rw [approval.derive_requirement_ref_keys_loop.eq_def]
    simp only [guard, ↓reduceIte, core.result.Result.is_ok, atFirst, bind_tc_ok]
    step with push_exact sha256 contract current first firstDomain firstCapacity
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
        simp [entries, List.append_assoc]

@[step] theorem derive_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (records : Slice auths_model.approval.ApprovalRequirement)
    (domains : ∀ record ∈ records.val, Domain record)
    (capacity : ReferenceCapacity records.val.length) :
    approval.derive_requirement_ref_keys records ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = entries sha256 records.val ⦄ := by
  unfold approval.derive_requirement_ref_keys
  simp only [lift, bind_tc_ok]
  apply spec_mono (derive_suffix sha256 contract records 0#usize
    (alloc.vec.Vec.with_capacity (auths_model.ApprovalRequirementId × auths_model.approval.ApprovalRequirement) (Slice.len records))
    records.val (by simp) domains (by
      simpa only [alloc.vec.with_capacity_contents, List.length_nil, Nat.zero_add] using capacity))
  intro result meaning
  cases result with
  | Err reason => exact False.elim meaning
  | Ok output => simpa only [alloc.vec.with_capacity_contents, List.nil_append] using meaning

@[step] theorem normalize_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (records : Slice auths_model.approval.ApprovalRequirement)
    (domains : ∀ record ∈ records.val, Domain record)
    (capacity : ReferenceCapacity records.val.length) :
    approval.sorted_requirement_refs records ⦃ result =>
      match result with
      | .Err _ => False
      | .Ok output => output.val = StableNormalization.sort (ContextObjects.approvalKey sha256) records.val ⦄ := by
  unfold approval.sorted_requirement_refs approval.sorted_approval_requirements
  step with derive_exact sha256 contract records domains capacity as ⟨derived, derivedMeaning⟩
  cases derived with
  | Err reason => exact False.elim derivedMeaning
  | Ok keyed =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    rw [sort_keys_exact, bind_tc_ok]
    step with OwnedRecords.unkey_exact (SnapshotOrdering.sortedByKey entryKey keyed)
      as ⟨output, projected⟩
    have exactRecords : output.val = StableNormalization.sort (ContextObjects.approvalKey sha256) records.val := by
      rw [projected, SnapshotOrdering.sorted_by_key_contents, derivedMeaning]
      simpa only [entries, entryKey] using BundleNormalization.entries_project
        ProtocolOrdering.approvalRequirementIdKey (identifier sha256)
        (ContextObjects.approvalKey sha256) (key_meaning sha256) records.val
    simpa only [spec_ok] using exactRecords

private theorem records_stopped (self : cbor.Encoder) (values : Slice auths_model.approval.ApprovalRequirement)
    (position : Std.Usize) (failure : error.CodecError) :
    approval.encode_requirement_refs_loop self values position (some failure) = ok (self.output, some failure) := by
  rw [approval.encode_requirement_refs_loop.eq_def]
  by_cases guard : position < values.len <;>
    simp [guard, core.option.Option.is_none]

private theorem records_suffix (values : Slice auths_model.approval.ApprovalRequirement) (position : Std.Usize)
    (self : cbor.Encoder) (rest : List auths_model.approval.ApprovalRequirement)
    (remaining : values.val.drop position.val = rest)
    (fields : ∀ value ∈ rest, RequirementWriters.ApprovalStrings value)
    (space : self.output.val.length + allocation RequirementWriters.approvalCost rest ≤ Usize.max) :
    approval.encode_requirement_refs_loop self values position none ⦃ actual => actual.2 = none ∧
      byteList actual.1.val = byteList self.output.val ++ contents UnsignedObjects.approvalRequirement rest ⦄ := by
  induction rest generalizing position self with
  | nil =>
    have finished : ¬ position < values.len := by
      have length := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at length
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [approval.encode_requirement_refs_loop.eq_def]
    simp [finished, spec_ok, contents]
  | cons first tail ih =>
    obtain ⟨guard, atFirst⟩ := Auths.StatusSelection.indexed_head values position first tail remaining
    obtain ⟨next, increment, nextValue, nextRemaining⟩ :=
      Auths.StatusSelection.indexed_next values position first tail remaining
    have firstValid := fields first (by simp)
    have tailValid : ∀ value ∈ tail, RequirementWriters.ApprovalStrings value :=
      fun value member => fields value (by simp [member])
    have firstSpace : self.output.val.length + RequirementWriters.approvalCost first ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    rw [approval.encode_requirement_refs_loop.eq_def]
    simp only [guard, ↓reduceIte, core.option.Option.is_none, atFirst, bind_tc_ok]
    step with RequirementWriters.approval_exact self first firstValid firstSpace
      as ⟨verdict, after, success, written⟩
    simp only [success, bind_tc_ok, increment]
    have actualLength := output_length written
    have itemBound := RequirementWriters.approval_length first
    have tailSpace : after.output.val.length + allocation RequirementWriters.approvalCost tail ≤ Usize.max := by
      simp only [allocation, List.map_cons, List.sum_cons] at space
      omega
    apply spec_mono (ih next after nextRemaining tailValid tailSpace)
    rintro ⟨output, failure⟩ ⟨noFailure, encoded⟩
    refine ⟨noFailure, ?_⟩
    rw [encoded, written]
    simp [contents, List.append_assoc]

@[step] theorem records_exact (self : cbor.Encoder) (values : alloc.vec.Vec auths_model.approval.ApprovalRequirement)
    (fields : ∀ value ∈ values.val, RequirementWriters.ApprovalStrings value)
    (space : self.output.val.length + 9 + allocation RequirementWriters.approvalCost values.val ≤ Usize.max) :
    approval.encode_requirement_refs self values ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++
        UnsignedWire.array (values.val.map UnsignedObjects.approvalRequirement) ⦄ := by
  unfold approval.encode_requirement_refs
  simp only [alloc.vec.Vec.as_slice, bind_tc_ok]
  step with ProtocolWriter.array_exact self (Slice.len (alloc.vec.Vec.deref values)) (by omega)
    as ⟨verdict, afterHeader, success, headerBytes⟩
  have headerLength := output_length headerBytes
  have headerBound := Auths.Codec.encodeHead_length_le_nine ⟨4, values.val.length⟩
  have loopSpace : afterHeader.output.val.length + allocation RequirementWriters.approvalCost values.val ≤ Usize.max := by
    simp only [Slice.len_val, Slice.length, alloc.vec.deref_exact] at headerLength
    omega
  simp only [success, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with records_suffix (alloc.vec.Vec.deref values) 0#usize afterHeader values.val
    (by simp [alloc.vec.deref_exact]) fields loopSpace
    as ⟨output, failure, noFailure, encoded⟩
  simp [noFailure, encoded, headerBytes, UnsignedWire.array, contents_flatten,
    Slice.len_val, Slice.length, alloc.vec.deref_exact, List.append_assoc]

@[step] theorem context_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (self : cbor.Encoder)
    (records : Slice auths_model.approval.ApprovalRequirement)
    (domains : ∀ record ∈ records.val, Domain record)
    (count : records.val.length ≤ 64)
    (space : self.output.val.length + 9 + allocation RequirementWriters.approvalCost records.val ≤ Usize.max) :
    approval.encode_context_requirements self records ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ ContextObjects.approvalRequirements sha256 records.val ⦄ := by
  have capacity : ReferenceCapacity records.val.length := by
    constructor <;> scalar_tac
  have guard : ¬ 64#usize < records.len := by
    simpa only [UScalar.lt_equiv, Slice.len_val, Slice.length] using Nat.not_lt.mpr count
  unfold approval.encode_context_requirements
  simp only [guard, ↓reduceIte, bind_tc_ok]
  step with normalize_exact sha256 contract records domains capacity as ⟨ordered, ordering⟩
  cases ordered with
  | Err reason => exact False.elim ordering
  | Ok values =>
    have fields : ∀ record ∈ values.val, RequirementWriters.ApprovalStrings record := by
      rw [ordering]
      exact BundleWriters.fields_sorted (ContextObjects.approvalKey sha256)
        RequirementWriters.ApprovalStrings records.val
        (fun record member => RequirementWriters.approval_strings_valid record (domains record member))
    have allocation : allocation RequirementWriters.approvalCost values.val =
        allocation RequirementWriters.approvalCost records.val := by
      rw [ordering]
      exact BundleObjects.allocation_normalized (ContextObjects.approvalKey sha256)
        RequirementWriters.approvalCost records.val
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    apply spec_mono (records_exact self values fields (by rw [allocation]; exact space))
    rintro actual ⟨success, written⟩
    exact ⟨success, by simpa only [ordering, ContextObjects.approvalRequirements] using written⟩

@[step] theorem context_refuses (self : cbor.Encoder)
    (records : Slice auths_model.approval.ApprovalRequirement) (count : 64 < records.val.length) :
    approval.encode_context_requirements self records ⦃ actual =>
      actual.1 = .Err .LimitExceeded ∧ actual.2 = self ⦄ := by
  have guard : 64#usize < records.len := by
    simpa only [UScalar.lt_equiv, Slice.len_val, Slice.length] using count
  unfold approval.encode_context_requirements
  simp [guard, spec_ok]

end Auths.Crypto.ContextApproval
