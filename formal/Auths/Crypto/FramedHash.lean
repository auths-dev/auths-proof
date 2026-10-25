import Auths.Crypto.ProtocolFramingTotality
import Auths.Codec.ProtocolHash

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.FramedHash
open Auths.Codec Auths.Codec.Refinement

/- Independent resource domains and complete typed-result specifications.
They use byte lengths and the explicit native unsigned/signed limits, never
successful source execution, expected encoder output or a trusted flag.
Hash specifications are explicit functions; functional correctness does not
imply collision resistance, injectivity or signature authenticity. -/

def IdentifierAdmissible (payload : List Nat) : Prop :=
  payload.length ≤ U64.max ∧ 20 + payload.length ≤ Usize.max ∧
    (20 + payload.length : Int) ≤ Isize.max

def ApplicationAdmissible (domain payload : List Nat) : Prop :=
  0 < domain.length ∧ domain.length ≤ 128 ∧ payload.length ≤ U64.max ∧
    28 + domain.length + payload.length ≤ Usize.max ∧
    (28 + domain.length + payload.length : Int) ≤ Isize.max

def SigningAdmissible (frame : Framing.Frame) : Prop :=
  frame.profile.length ≤ U16.max ∧ frame.statement.length ≤ U64.max ∧
    21 + frame.profile.length + frame.statement.length ≤ Usize.max ∧
    (21 + frame.profile.length + frame.statement.length : Int) ≤ Isize.max

def PreimageResult (admitted : Prop) (bytes : List Nat)
    (result : core.result.Result (alloc.vec.Vec Std.U8) error.CodecError) : Prop :=
  match result with
  | .Ok output => admitted ∧ byteList output.val = bytes
  | .Err reason => reason = .LimitExceeded ∧ ¬ admitted

def HashResult (admitted : Prop) (expected : auths_model.Digest)
    (result : core.result.Result auths_model.Digest error.CodecError) : Prop :=
  match result with
  | .Ok output => admitted ∧ output = expected
  | .Err reason => reason = .LimitExceeded ∧ ¬ admitted

theorem preimage_accepted {admitted : Prop} {bytes : List Nat}
    {result : core.result.Result (alloc.vec.Vec Std.U8) error.CodecError}
    (classified : PreimageResult admitted bytes result) (fits : admitted) :
    ∃ output, result = .Ok output ∧ byteList output.val = bytes := by
  cases result with
  | Err reason => exact False.elim (classified.2 fits)
  | Ok output => exact ⟨output, rfl, classified.2⟩

theorem preimage_refused {admitted : Prop} {bytes : List Nat}
    {result : core.result.Result (alloc.vec.Vec Std.U8) error.CodecError}
    (classified : PreimageResult admitted bytes result) (outside : ¬ admitted) :
    result = .Err .LimitExceeded := by
  cases result with
  | Err reason => exact congrArg core.result.Result.Err classified.1
  | Ok output => exact False.elim (outside classified.1)

theorem hash_accepted {admitted : Prop} {expected : auths_model.Digest}
    {result : core.result.Result auths_model.Digest error.CodecError}
    (classified : HashResult admitted expected result) (fits : admitted) :
    result = .Ok expected := by
  cases result with
  | Err reason => exact False.elim (classified.2 fits)
  | Ok output => exact congrArg core.result.Result.Ok classified.2

theorem hash_refused {admitted : Prop} {expected : auths_model.Digest}
    {result : core.result.Result auths_model.Digest error.CodecError}
    (classified : HashResult admitted expected result) (outside : ¬ admitted) :
    result = .Err .LimitExceeded := by
  cases result with
  | Err reason => exact congrArg core.result.Result.Err classified.1
  | Ok output => exact False.elim (outside classified.1)

theorem identifier_domain (kind : hash.IdentifierType) (payload : Slice Std.U8) :
    IdentifierAdmissible (ProtocolFraming.identifierFrame kind payload).payload ↔
      ProtocolFramingTotality.IdentifierAdmissible payload := by
  simp [IdentifierAdmissible, ProtocolFramingTotality.IdentifierAdmissible,
    ProtocolFraming.identifierFrame]

theorem application_domain (domain : Str) (payload : Slice Std.U8) :
    ApplicationAdmissible (ProtocolFraming.applicationFrame domain payload).domain
      (ProtocolFraming.applicationFrame domain payload).payload ↔
        ProtocolFramingTotality.ApplicationAdmissible domain payload := by
  simp [ApplicationAdmissible, ProtocolFramingTotality.ApplicationAdmissible,
    ProtocolFraming.applicationFrame]

theorem signing_domain (kind : hash.ObjectType) (profile : Str) (version : Std.U16)
    (payload : Slice Std.U8) :
    SigningAdmissible (ProtocolFraming.inputFrame kind profile version payload) ↔
      ProtocolFramingTotality.SigningAdmissible profile payload := by
  simp [SigningAdmissible, ProtocolFramingTotality.SigningAdmissible,
    ProtocolFraming.inputFrame]

@[step] theorem identifier_preimage_total (kind : hash.IdentifierType) (payload : Slice Std.U8) :
    hash.identifier_preimage kind payload ⦃ result =>
      PreimageResult (IdentifierAdmissible (ProtocolFraming.identifierFrame kind payload).payload)
        (CommitmentFrames.identifier (ProtocolFraming.identifierFrame kind payload)) result ⦄ := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (ProtocolFramingTotality.identifier_total kind payload)
  rw [runs]
  simp only [spec_ok]
  cases result with
  | Err reason =>
    exact ⟨classified.1, fun admitted => classified.2 ((identifier_domain kind payload).mp admitted)⟩
  | Ok output =>
    exact ⟨(identifier_domain kind payload).mpr classified,
      ProtocolFraming.identifier_preimage_exact kind payload output runs⟩

@[step] theorem application_preimage_total (domain : Str) (payload : Slice Std.U8) :
    hash.commitment_preimage domain payload ⦃ result =>
      PreimageResult (ApplicationAdmissible (ProtocolFraming.applicationFrame domain payload).domain
        (ProtocolFraming.applicationFrame domain payload).payload)
        (CommitmentFrames.application (ProtocolFraming.applicationFrame domain payload)) result ⦄ := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (ProtocolFramingTotality.application_total domain payload)
  rw [runs]
  simp only [spec_ok]
  cases result with
  | Err reason =>
    exact ⟨classified.1, fun admitted => classified.2 ((application_domain domain payload).mp admitted)⟩
  | Ok output =>
    exact ⟨(application_domain domain payload).mpr classified,
      ProtocolFraming.application_preimage_exact domain payload output runs⟩

@[step] theorem signing_preimage_total (kind : hash.ObjectType) (profile : Str)
    (version : Std.U16) (payload : Slice Std.U8) :
    hash.signing_preimage kind profile version payload ⦃ result =>
      PreimageResult (SigningAdmissible (ProtocolFraming.inputFrame kind profile version payload))
        (Framing.encode (ProtocolFraming.inputFrame kind profile version payload)) result ⦄ := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (ProtocolFramingTotality.signing_total kind profile version payload)
  rw [runs]
  simp only [spec_ok]
  cases result with
  | Err reason =>
    exact ⟨classified.1, fun admitted => classified.2 ((signing_domain kind profile version payload).mp admitted)⟩
  | Ok output =>
    exact ⟨(signing_domain kind profile version payload).mpr classified,
      ProtocolFraming.signing_preimage_exact kind profile version payload output runs⟩

variable [primitive : Sha256Primitives]

/-- Functional primitive/output-representation premise with an independent
natural-byte specification. No default instance or cryptographic axiom exists. -/
abbrev Contract (sha256 : List Nat → auths_model.Digest) : Prop :=
  Sha256Native.Contract (fun bytes => sha256 (bytes.map UScalar.val))

theorem raw_hash_exact (sha256 : List Nat → auths_model.Digest) (contract : Contract sha256)
    (bytes : Slice Std.U8) : hash.raw_sha256 bytes = ok (sha256 (byteList bytes.val)) :=
  AuthsProtocolCodec.raw_sha256_refines _ contract bytes

@[step] theorem identifier_hash_total (sha256 : List Nat → auths_model.Digest)
    (contract : Contract sha256) (kind : hash.IdentifierType) (payload : Slice Std.U8) :
    hash.domain_hash kind payload ⦃ result =>
      HashResult (IdentifierAdmissible (ProtocolFraming.identifierFrame kind payload).payload)
        (sha256 (CommitmentFrames.identifier (ProtocolFraming.identifierFrame kind payload))) result ⦄ := by
  unfold hash.domain_hash
  obtain ⟨framed, runs, classified⟩ := spec_imp_exists (identifier_preimage_total kind payload)
  rw [runs]
  cases framed with
  | Err reason =>
    simpa [HashResult, core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from] using classified
  | Ok preimage =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, core.ops.deref.DerefVec, bind_tc_ok]
    rw [raw_hash_exact sha256 contract]
    simp only [bind_tc_ok, spec_ok, HashResult]
    refine ⟨classified.1, ?_⟩
    simpa only [alloc.vec.deref_exact, classified.2]

@[step] theorem application_hash_total (sha256 : List Nat → auths_model.Digest)
    (contract : Contract sha256) (domain : Str) (payload : Slice Std.U8) :
    hash.domain_commitment domain payload ⦃ result =>
      HashResult (ApplicationAdmissible (ProtocolFraming.applicationFrame domain payload).domain
        (ProtocolFraming.applicationFrame domain payload).payload)
        (sha256 (CommitmentFrames.application (ProtocolFraming.applicationFrame domain payload))) result ⦄ := by
  unfold hash.domain_commitment
  obtain ⟨framed, runs, classified⟩ := spec_imp_exists (application_preimage_total domain payload)
  rw [runs]
  cases framed with
  | Err reason =>
    simpa [HashResult, core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from] using classified
  | Ok preimage =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, core.ops.deref.DerefVec, bind_tc_ok]
    rw [raw_hash_exact sha256 contract]
    simp only [bind_tc_ok, spec_ok, HashResult]
    refine ⟨classified.1, ?_⟩
    simpa only [alloc.vec.deref_exact, classified.2]

theorem identifier_hash_exact (sha256 : List Nat → auths_model.Digest)
    (contract : Contract sha256) (kind : hash.IdentifierType) (payload : Slice Std.U8)
    (fits : IdentifierAdmissible (ProtocolFraming.identifierFrame kind payload).payload) :
    hash.domain_hash kind payload =
      ok (.Ok (sha256 (CommitmentFrames.identifier (ProtocolFraming.identifierFrame kind payload)))) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (identifier_hash_total sha256 contract kind payload)
  simpa only [hash_accepted classified fits] using runs

theorem identifier_hash_refuses (sha256 : List Nat → auths_model.Digest)
    (contract : Contract sha256) (kind : hash.IdentifierType) (payload : Slice Std.U8)
    (outside : ¬ IdentifierAdmissible (ProtocolFraming.identifierFrame kind payload).payload) :
    hash.domain_hash kind payload = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (identifier_hash_total sha256 contract kind payload)
  simpa only [hash_refused classified outside] using runs

theorem application_hash_exact (sha256 : List Nat → auths_model.Digest)
    (contract : Contract sha256) (domain : Str) (payload : Slice Std.U8)
    (fits : ApplicationAdmissible (ProtocolFraming.applicationFrame domain payload).domain
      (ProtocolFraming.applicationFrame domain payload).payload) :
    hash.domain_commitment domain payload =
      ok (.Ok (sha256 (CommitmentFrames.application (ProtocolFraming.applicationFrame domain payload)))) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (application_hash_total sha256 contract domain payload)
  simpa only [hash_accepted classified fits] using runs

theorem application_hash_refuses (sha256 : List Nat → auths_model.Digest)
    (contract : Contract sha256) (domain : Str) (payload : Slice Std.U8)
    (outside : ¬ ApplicationAdmissible (ProtocolFraming.applicationFrame domain payload).domain
      (ProtocolFraming.applicationFrame domain payload).payload) :
    hash.domain_commitment domain payload = ok (.Err .LimitExceeded) := by
  obtain ⟨result, runs, classified⟩ := spec_imp_exists
    (application_hash_total sha256 contract domain payload)
  simpa only [hash_refused classified outside] using runs

end Auths.Crypto.FramedHash
