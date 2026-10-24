import Auths.Crypto.SnapshotArrays
import Auths.Crypto.BundleWriters

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.SnapshotWriters
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolWriter
open Auths.Codec.ProtocolArrayWriters Auths.Crypto.SigningObjectWriters

/- Complete wire snapshots. Source derived-ID normalization is earned before
writing every signed record; constructor primary order, full-value uniqueness,
time coverage and status authority remain separate obligations. These byte
statements contain no successful encoder/normalizer or desired bytes premise. -/

variable [primitive : Sha256Primitives]

structure PrincipalFields (value : auths_model.PrincipalStatusSnapshot) : Prop where
  statements : ∀ record ∈ value.statements.val, SignedObjectWriters.PrincipalStatusStrings record
  trust : ∀ rule ∈ value.trust.val, SnapshotLeaves.TrustStrings rule

theorem principal_length (sha256 : List Nat → auths_model.Digest) (value : auths_model.PrincipalStatusSnapshot) :
    (SnapshotObjects.principalSnapshot sha256 value).length ≤ SnapshotObjects.principalCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.digest value.id),
    (1, UnsignedWire.uint value.observed_at.val), (2, UnsignedWire.uint value.valid_until.val),
    (3, UnsignedWire.array ((SnapshotObjects.principalStatements sha256 value).map UnsignedObjects.signedPrincipalStatus)),
    (4, UnsignedWire.array (value.checkpoints.val.map UnsignedObjects.digest)),
    (5, SnapshotObjects.trust value.trust.val)]
  have id := UnsignedLeaves.digest_length value.id
  have observed := UnsignedWire.uint_length value.observed_at.val
  have until := UnsignedWire.uint_length value.valid_until.val
  have statements := array_model_length UnsignedObjects.signedPrincipalStatus SignedObjectWriters.principal_statusCost
    SignedObjectWriters.principal_status_length (SnapshotObjects.principalStatements sha256 value)
  have checkpoints := BundleLeaves.evidence_ids_length value.checkpoints.val
  have trust := SnapshotLeaves.trust_length value.trust.val
  simp only [SnapshotObjects.principalStatements, BundleObjects.allocation_normalized] at statements
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [SnapshotObjects.principalCost, SnapshotObjects.trustCost] at *
  omega

@[step] theorem principal_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (self : cbor.Encoder) (value : auths_model.PrincipalStatusSnapshot)
    (fields : PrincipalFields value)
    (domains : ∀ record ∈ value.statements.val, BorrowedKeys.PrincipalStatusDomain record)
    (capacity : BorrowedKeys.ReferenceCapacity value.statements.val.length)
    (space : self.output.val.length + SnapshotObjects.principalCost value ≤ Usize.max)
    (native : (2 * (self.output.val.length + SnapshotObjects.principalCost value) : Int) ≤ Isize.max) :
    encode.encode_principal_snapshot self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ SnapshotObjects.principalSnapshot sha256 value ⦄ := by
  obtain ⟨statements, statementRun, statementOrder⟩ := BundleWriters.records_success
    (BundleNormalization.principal_status_exact sha256 contract (alloc.vec.Vec.deref value.statements)
      (by simpa only [alloc.vec.deref_exact] using domains)
      (by simpa only [alloc.vec.deref_exact] using capacity))
  have statementModel : statements.val = SnapshotObjects.principalStatements sha256 value := by
    simpa only [SnapshotObjects.principalStatements, alloc.vec.deref_exact] using statementOrder
  have statementFields : ∀ record ∈ statements.val, SignedObjectWriters.PrincipalStatusStrings record := by
    rw [statementModel]
    exact BundleWriters.fields_sorted (BundleObjects.principalStatusKey sha256)
      SignedObjectWriters.PrincipalStatusStrings value.statements.val fields.statements
  have statementAllocation : allocation SignedObjectWriters.principal_statusCost statements.val =
      allocation SignedObjectWriters.principal_statusCost value.statements.val := by
    rw [statementModel]
    exact BundleObjects.allocation_normalized (BundleObjects.principalStatusKey sha256)
      SignedObjectWriters.principal_statusCost value.statements.val
  unfold encode.encode_principal_snapshot
  simp only [SnapshotObjects.principalCost] at space
  step with ProtocolWriter.map_exact self 6#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 6⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusSnapshot.impl.id, auths_model.StatusSnapshotId.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e1 value.id (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := UnsignedLeaves.digest_length value.id
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusSnapshot.impl.observed_at, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e3 value.observed_at (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := encodeHead_length_le_nine ⟨0, (value.observed_at).val⟩
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusSnapshot.impl.valid_until, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e5 value.valid_until (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := encodeHead_length_le_nine ⟨0, (value.valid_until).val⟩
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusSnapshot.impl.statements, core.ops.deref.DerefVec, statementRun,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with BundleArrays.principal_status_exact e7 statements statementFields (by rw [statementAllocation]; omega) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := array_model_length UnsignedObjects.signedPrincipalStatus SignedObjectWriters.principal_statusCost SignedObjectWriters.principal_status_length statements.val
  rw [statementAllocation] at bound8
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusSnapshot.impl.checkpoints, core.ops.deref.DerefVec, bind_tc_ok]
  step with BundleLeaves.evidence_ids_exact e9 (alloc.vec.Vec.deref value.checkpoints) (by simpa only [alloc.vec.deref_exact, BundleLeaves.id_allocation] using (show e9.output.val.length + 9 + 41 * value.checkpoints.val.length ≤ Usize.max by omega)) as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := BundleLeaves.evidence_ids_length value.checkpoints.val
  simp only [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega) as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.PrincipalStatusSnapshot.impl.trust, core.ops.deref.DerefVec, bind_tc_ok]
  step with SnapshotArrays.trust_exact e11 (alloc.vec.Vec.deref value.trust) fields.trust (by simpa only [alloc.vec.deref_exact] using (show e11.output.val.length + 9 + allocation SnapshotObjects.trustRuleCost value.trust.val ≤ Usize.max by omega)) as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := SnapshotLeaves.trust_length value.trust.val
  simp [ok12, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, SnapshotObjects.principalSnapshot, SnapshotObjects.trust, statementModel,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem principal_encoder (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.PrincipalStatusSnapshot)
    (fields : PrincipalFields value)
    (domains : ∀ record ∈ value.statements.val, BorrowedKeys.PrincipalStatusDomain record)
    (capacity : BorrowedKeys.ReferenceCapacity value.statements.val.length)
    (space : SnapshotObjects.principalCost value ≤ Usize.max)
    (native : (2 * SnapshotObjects.principalCost value : Int) ≤ Isize.max) :
    encode.encode_principal_status_snapshot_value value ⦃ result =>
      Encodes (SnapshotObjects.principalSnapshot sha256 value) result ⦄ := by
  unfold encode.encode_principal_status_snapshot_value
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with principal_exact sha256 contract (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value fields domains capacity
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using native)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem principal_canonical_encoder (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (carrier : canonical_value.Canonical auths_model.PrincipalStatusSnapshot)
    (value : auths_model.PrincipalStatusSnapshot) (projection : canonical_value.Canonical.as_value carrier = ok value)
    (fields : PrincipalFields value)
    (domains : ∀ record ∈ value.statements.val, BorrowedKeys.PrincipalStatusDomain record)
    (capacity : BorrowedKeys.ReferenceCapacity value.statements.val.length)
    (space : SnapshotObjects.principalCost value ≤ Usize.max)
    (native : (2 * SnapshotObjects.principalCost value : Int) ≤ Isize.max) :
    encode.encode_principal_status_snapshot carrier ⦃ result =>
      Encodes (SnapshotObjects.principalSnapshot sha256 value) result ⦄ := by
  unfold encode.encode_principal_status_snapshot
  rw [projection]
  simpa only [bind_tc_ok] using principal_encoder sha256 contract value fields domains capacity space native

theorem principal_canonical_projection (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (carrier : canonical_value.Canonical auths_model.PrincipalStatusSnapshot) :
    ∃ value, canonical_value.Canonical.as_value carrier = ok value ∧
      ∀ (fields : PrincipalFields value)
        (domains : ∀ record ∈ value.statements.val, BorrowedKeys.PrincipalStatusDomain record)
        (capacity : BorrowedKeys.ReferenceCapacity value.statements.val.length)
        (space : SnapshotObjects.principalCost value ≤ Usize.max)
        (native : (2 * SnapshotObjects.principalCost value : Int) ≤ Isize.max),
        encode.encode_principal_status_snapshot carrier ⦃ result =>
          Encodes (SnapshotObjects.principalSnapshot sha256 value) result ⦄ := by
  obtain ⟨value, projection, _⟩ := CanonicalValues.projections_total carrier
  exact ⟨value, projection, fun fields domains capacity space native =>
    principal_canonical_encoder sha256 contract carrier value projection fields domains capacity space native⟩

structure GrantFields (value : auths_model.GrantStatusSnapshot) : Prop where
  statements : ∀ record ∈ value.statements.val, SignedObjectWriters.GrantStatusStrings record
  trust : ∀ rule ∈ value.trust.val, SnapshotLeaves.TrustStrings rule

theorem grant_length (sha256 : List Nat → auths_model.Digest) (value : auths_model.GrantStatusSnapshot) :
    (SnapshotObjects.grantSnapshot sha256 value).length ≤ SnapshotObjects.grantCost value := by
  have outer := UnsignedWire.map_length [(0, UnsignedObjects.digest value.id),
    (1, UnsignedWire.uint value.observed_at.val), (2, UnsignedWire.uint value.valid_until.val),
    (3, UnsignedWire.array ((SnapshotObjects.grantStatements sha256 value).map UnsignedObjects.signedGrantStatus)),
    (4, UnsignedWire.array (value.checkpoints.val.map UnsignedObjects.digest)),
    (5, SnapshotObjects.trust value.trust.val)]
  have id := UnsignedLeaves.digest_length value.id
  have observed := UnsignedWire.uint_length value.observed_at.val
  have until := UnsignedWire.uint_length value.valid_until.val
  have statements := array_model_length UnsignedObjects.signedGrantStatus SignedObjectWriters.grant_statusCost
    SignedObjectWriters.grant_status_length (SnapshotObjects.grantStatements sha256 value)
  have checkpoints := BundleLeaves.evidence_ids_length value.checkpoints.val
  have trust := SnapshotLeaves.trust_length value.trust.val
  simp only [SnapshotObjects.grantStatements, BundleObjects.allocation_normalized] at statements
  simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at outer
  change (UnsignedWire.map _).length ≤ _
  simp only [SnapshotObjects.grantCost, SnapshotObjects.trustCost] at *
  omega

@[step] theorem grant_exact (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (self : cbor.Encoder) (value : auths_model.GrantStatusSnapshot)
    (fields : GrantFields value)
    (domains : ∀ record ∈ value.statements.val, BorrowedKeys.GrantStatusDomain record)
    (capacity : BorrowedKeys.ReferenceCapacity value.statements.val.length)
    (space : self.output.val.length + SnapshotObjects.grantCost value ≤ Usize.max)
    (native : (2 * (self.output.val.length + SnapshotObjects.grantCost value) : Int) ≤ Isize.max) :
    encode.encode_grant_snapshot self value ⦃ actual => actual.1 = .Ok () ∧
      byteList actual.2.output.val = byteList self.output.val ++ SnapshotObjects.grantSnapshot sha256 value ⦄ := by
  obtain ⟨statements, statementRun, statementOrder⟩ := BundleWriters.records_success
    (BundleNormalization.grant_status_exact sha256 contract (alloc.vec.Vec.deref value.statements)
      (by simpa only [alloc.vec.deref_exact] using domains)
      (by simpa only [alloc.vec.deref_exact] using capacity))
  have statementModel : statements.val = SnapshotObjects.grantStatements sha256 value := by
    simpa only [SnapshotObjects.grantStatements, alloc.vec.deref_exact] using statementOrder
  have statementFields : ∀ record ∈ statements.val, SignedObjectWriters.GrantStatusStrings record := by
    rw [statementModel]
    exact BundleWriters.fields_sorted (BundleObjects.grantStatusKey sha256)
      SignedObjectWriters.GrantStatusStrings value.statements.val fields.statements
  have statementAllocation : allocation SignedObjectWriters.grant_statusCost statements.val =
      allocation SignedObjectWriters.grant_statusCost value.statements.val := by
    rw [statementModel]
    exact BundleObjects.allocation_normalized (BundleObjects.grantStatusKey sha256)
      SignedObjectWriters.grant_statusCost value.statements.val
  unfold encode.encode_grant_snapshot
  simp only [SnapshotObjects.grantCost] at space
  step with ProtocolWriter.map_exact self 6#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 6⟩
  simp only [ok0, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [ok1, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusSnapshot.impl.id, auths_model.StatusSnapshotId.as_bytes, lift, bind_tc_ok]
  step with UnsignedLeaves.digest_exact e1 value.id (by omega) as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := UnsignedLeaves.digest_length value.id
  simp only [ok2, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [ok3, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusSnapshot.impl.observed_at, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e3 value.observed_at (by omega) as ⟨r4, e4, ok4, bytes4⟩
  have len4 := output_length bytes4
  have bound4 := encodeHead_length_le_nine ⟨0, (value.observed_at).val⟩
  simp only [ok4, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e4 2#u8 (by omega) as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [ok5, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusSnapshot.impl.valid_until, auths_model.Timestamp.get, bind_tc_ok]
  step with ProtocolEncoderState.u64_exact e5 value.valid_until (by omega) as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := encodeHead_length_le_nine ⟨0, (value.valid_until).val⟩
  simp only [ok6, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e6 3#u8 (by omega) as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [ok7, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusSnapshot.impl.statements, core.ops.deref.DerefVec, statementRun,
    core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with BundleArrays.grant_status_exact e7 statements statementFields (by rw [statementAllocation]; omega) as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := array_model_length UnsignedObjects.signedGrantStatus SignedObjectWriters.grant_statusCost SignedObjectWriters.grant_status_length statements.val
  rw [statementAllocation] at bound8
  simp only [ok8, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e8 4#u8 (by omega) as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [ok9, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusSnapshot.impl.checkpoints, core.ops.deref.DerefVec, bind_tc_ok]
  step with BundleLeaves.evidence_ids_exact e9 (alloc.vec.Vec.deref value.checkpoints) (by simpa only [alloc.vec.deref_exact, BundleLeaves.id_allocation] using (show e9.output.val.length + 9 + 41 * value.checkpoints.val.length ≤ Usize.max by omega)) as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := BundleLeaves.evidence_ids_length value.checkpoints.val
  simp only [ok10, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolWriter.key_exact e10 5#u8 (by omega) as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [ok11, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.GrantStatusSnapshot.impl.trust, core.ops.deref.DerefVec, bind_tc_ok]
  step with SnapshotArrays.trust_exact e11 (alloc.vec.Vec.deref value.trust) fields.trust (by simpa only [alloc.vec.deref_exact] using (show e11.output.val.length + 9 + allocation SnapshotObjects.trustRuleCost value.trust.val ≤ Usize.max by omega)) as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := SnapshotLeaves.trust_length value.trust.val
  simp [ok12, core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
    bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0, SnapshotObjects.grantSnapshot, SnapshotObjects.trust, statementModel,
    UnsignedObjects.identifier, UnsignedObjects.utf8, UnsignedWire.map, UnsignedWire.entries,
    UnsignedWire.uint, UnsignedWire.text, UnsignedWire.array, stringBytes, payloadEncoding,
    alloc.vec.deref_exact, byteList, List.append_assoc]

@[step] theorem grant_encoder (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (value : auths_model.GrantStatusSnapshot)
    (fields : GrantFields value)
    (domains : ∀ record ∈ value.statements.val, BorrowedKeys.GrantStatusDomain record)
    (capacity : BorrowedKeys.ReferenceCapacity value.statements.val.length)
    (space : SnapshotObjects.grantCost value ≤ Usize.max)
    (native : (2 * SnapshotObjects.grantCost value : Int) ≤ Isize.max) :
    encode.encode_grant_status_snapshot_value value ⦃ result =>
      Encodes (SnapshotObjects.grantSnapshot sha256 value) result ⦄ := by
  unfold encode.encode_grant_status_snapshot_value
  simp only [cbor.Encoder.new, bind_tc_ok]
  step with grant_exact sha256 contract (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) value fields domains capacity
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using space)
    (by simpa only [alloc.vec.new_contents, List.length_nil, Nat.zero_add] using native)
    as ⟨verdict, encoder, success, written⟩
  simp [success, core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
    Encodes, written, alloc.vec.new_contents, byteList]

@[step] theorem grant_canonical_encoder (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (carrier : canonical_value.Canonical auths_model.GrantStatusSnapshot)
    (value : auths_model.GrantStatusSnapshot) (projection : canonical_value.Canonical.as_value carrier = ok value)
    (fields : GrantFields value)
    (domains : ∀ record ∈ value.statements.val, BorrowedKeys.GrantStatusDomain record)
    (capacity : BorrowedKeys.ReferenceCapacity value.statements.val.length)
    (space : SnapshotObjects.grantCost value ≤ Usize.max)
    (native : (2 * SnapshotObjects.grantCost value : Int) ≤ Isize.max) :
    encode.encode_grant_status_snapshot carrier ⦃ result =>
      Encodes (SnapshotObjects.grantSnapshot sha256 value) result ⦄ := by
  unfold encode.encode_grant_status_snapshot
  rw [projection]
  simpa only [bind_tc_ok] using grant_encoder sha256 contract value fields domains capacity space native

theorem grant_canonical_projection (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (carrier : canonical_value.Canonical auths_model.GrantStatusSnapshot) :
    ∃ value, canonical_value.Canonical.as_value carrier = ok value ∧
      ∀ (fields : GrantFields value)
        (domains : ∀ record ∈ value.statements.val, BorrowedKeys.GrantStatusDomain record)
        (capacity : BorrowedKeys.ReferenceCapacity value.statements.val.length)
        (space : SnapshotObjects.grantCost value ≤ Usize.max)
        (native : (2 * SnapshotObjects.grantCost value : Int) ≤ Isize.max),
        encode.encode_grant_status_snapshot carrier ⦃ result =>
          Encodes (SnapshotObjects.grantSnapshot sha256 value) result ⦄ := by
  obtain ⟨value, projection, _⟩ := CanonicalValues.projections_total carrier
  exact ⟨value, projection, fun fields domains capacity space native =>
    grant_canonical_encoder sha256 contract carrier value projection fields domains capacity space native⟩

end Auths.Crypto.SnapshotWriters
