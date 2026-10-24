import Auths.Crypto.ProtocolFraming

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Crypto.SigningCallers

/- These source traces bind the actual statement and descriptor arguments,
registered object domain, and actual profile/version to the framing operation.
The unsigned-object writer still needs its independent schema refinement:
an existential successful source encoding is not substituted for that proof. -/

macro "auths_signing_effect" effect:ident : tactic => `(tactic|
  simp only [Bind.bind, Aeneas.Std.bind, bind_tc_ok, bind_tc_fail, bind_tc_div,
    core.result.Result.Insts.CoreOpsTry.branch,
    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
    core.convert.FromSame, core.convert.FromSame.from,
    Result.ok.injEq, core.result.Result.Ok.injEq, reduceCtorEq] at $effect)

syntax "auths_profile_signing_trace " term "," term
  " at " ident "," ident : tactic

macro_rules
| `(tactic| auths_profile_signing_trace $profileValue, $encodeCall
    at $output:ident, $accepted:ident) =>
  `(tactic|
    (cases borrowed : auths_model.ProfileId.as_str $profileValue with
     | fail error =>
       simp only [borrowed] at $accepted
       auths_signing_effect $accepted
     | div =>
       simp only [borrowed] at $accepted
       auths_signing_effect $accepted
     | ok profile =>
       simp only [borrowed] at $accepted
       auths_signing_effect $accepted
       cases encoded : $encodeCall with
       | fail error =>
         simp only [encoded] at $accepted
         auths_signing_effect $accepted
       | div =>
         simp only [encoded] at $accepted
         auths_signing_effect $accepted
       | ok result =>
         cases result with
         | Err error =>
           simp only [encoded] at $accepted
           auths_signing_effect $accepted
         | Ok payload =>
           simp only [encoded] at $accepted
           auths_signing_effect $accepted
           refine ⟨profile, payload, borrowed, encoded, $accepted, ?_⟩
           simpa only [ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
             alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref] using
             ProtocolFraming.signing_preimage_exact _ _ _ _ $output $accepted))

syntax "auths_unprofiled_signing_trace " term " at " ident "," ident : tactic

macro_rules
| `(tactic| auths_unprofiled_signing_trace $encodeCall at $output:ident, $accepted:ident) =>
  `(tactic|
    (cases encoded : $encodeCall with
     | fail error =>
       simp only [encoded] at $accepted
       auths_signing_effect $accepted
     | div =>
       simp only [encoded] at $accepted
       auths_signing_effect $accepted
     | ok result =>
       cases result with
       | Err error =>
         simp only [encoded] at $accepted
         auths_signing_effect $accepted
       | Ok payload =>
         simp only [encoded] at $accepted
         auths_signing_effect $accepted
         refine ⟨payload, encoded, $accepted, ?_⟩
         simpa only [ProtocolFraming.inputFrame, ProtocolFraming.tagValue,
           alloc.vec.Vec.deref, auths_composition.alloc.vec.Vec.deref,
           List.map_nil, UScalar.ofNat_val_eq] using
           ProtocolFraming.signing_preimage_exact _ _ _ _ $output $accepted))

theorem grant_trace (statement : auths_model.GrantStatement)
    (descriptor : auths_model.SignatureDescriptor) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.grant_signing_preimage statement descriptor = ok (.Ok output)) :
    ∃ (profile : Str) (payload : alloc.vec.Vec Std.U8),
      auths_model.ProfileId.as_str statement.profile.id = ok profile ∧
      encode.encode_grant_signing_input statement descriptor = ok (.Ok payload) ∧
      hash.signing_preimage .Grant profile statement.profile.version (alloc.vec.Vec.deref payload) =
        ok (.Ok output) ∧
      output.val.map UScalar.val = Framing.encode
        ⟨1, profile.val.map UScalar.val, statement.profile.version.val, payload.val.map UScalar.val⟩ := by
  unfold hash.grant_signing_preimage at accepted
  simp only [auths_model.GrantStatement.impl.profile, auths_model.ProfileRef.impl.id,
    auths_model.ProfileRef.impl.version, bind_tc_ok] at accepted
  auths_profile_signing_trace statement.profile.id, encode.encode_grant_signing_input statement descriptor
    at output, accepted

theorem action_trace (statement : auths_model.ActionEnvelope)
    (descriptor : auths_model.SignatureDescriptor) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.action_signing_preimage statement descriptor = ok (.Ok output)) :
    ∃ (profile : Str) (payload : alloc.vec.Vec Std.U8),
      auths_model.ProfileId.as_str statement.profile.id = ok profile ∧
      encode.encode_action_signing_input statement descriptor = ok (.Ok payload) ∧
      hash.signing_preimage .Action profile statement.profile.version (alloc.vec.Vec.deref payload) =
        ok (.Ok output) ∧
      output.val.map UScalar.val = Framing.encode
        ⟨2, profile.val.map UScalar.val, statement.profile.version.val, payload.val.map UScalar.val⟩ := by
  unfold hash.action_signing_preimage at accepted
  simp only [auths_model.ActionEnvelope.impl.profile, auths_model.ProfileRef.impl.id,
    auths_model.ProfileRef.impl.version, bind_tc_ok] at accepted
  auths_profile_signing_trace statement.profile.id, encode.encode_action_signing_input statement descriptor
    at output, accepted

theorem approval_trace (statement : auths_model.approval.ApprovalStatement)
    (descriptor : auths_model.SignatureDescriptor) (profileValue : auths_model.ProfileRef)
    (output : alloc.vec.Vec Std.U8)
    (accepted : hash.approval_signing_preimage statement descriptor profileValue = ok (.Ok output)) :
    ∃ (profile : Str) (payload : alloc.vec.Vec Std.U8),
      auths_model.ProfileId.as_str profileValue.id = ok profile ∧
      approval.encode_approval_signing_input statement descriptor = ok (.Ok payload) ∧
      hash.signing_preimage .Approval profile profileValue.version (alloc.vec.Vec.deref payload) =
        ok (.Ok output) ∧
      output.val.map UScalar.val = Framing.encode
        ⟨10, profile.val.map UScalar.val, profileValue.version.val, payload.val.map UScalar.val⟩ := by
  unfold hash.approval_signing_preimage at accepted
  simp only [auths_model.ProfileRef.impl.id, auths_model.ProfileRef.impl.version, bind_tc_ok] at accepted
  auths_profile_signing_trace profileValue.id, approval.encode_approval_signing_input statement descriptor
    at output, accepted

theorem principal_status_trace (statement : auths_model.PrincipalStatusStatement)
    (descriptor : auths_model.SignatureDescriptor) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.principal_status_signing_preimage statement descriptor = ok (.Ok output)) :
    ∃ payload : alloc.vec.Vec Std.U8,
      encode.encode_principal_status_signing_input statement descriptor = ok (.Ok payload) ∧
      hash.signing_preimage .PrincipalStatus ⟨[], by scalar_tac⟩ 0#u16 (alloc.vec.Vec.deref payload) =
        ok (.Ok output) ∧
      output.val.map UScalar.val = Framing.encode ⟨3, [], 0, payload.val.map UScalar.val⟩ := by
  unfold hash.principal_status_signing_preimage at accepted
  auths_unprofiled_signing_trace encode.encode_principal_status_signing_input statement descriptor
    at output, accepted

theorem grant_status_trace (statement : auths_model.GrantStatusStatement)
    (descriptor : auths_model.SignatureDescriptor) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.grant_status_signing_preimage statement descriptor = ok (.Ok output)) :
    ∃ payload : alloc.vec.Vec Std.U8,
      encode.encode_grant_status_signing_input statement descriptor = ok (.Ok payload) ∧
      hash.signing_preimage .GrantStatus ⟨[], by scalar_tac⟩ 0#u16 (alloc.vec.Vec.deref payload) =
        ok (.Ok output) ∧
      output.val.map UScalar.val = Framing.encode ⟨4, [], 0, payload.val.map UScalar.val⟩ := by
  unfold hash.grant_status_signing_preimage at accepted
  auths_unprofiled_signing_trace encode.encode_grant_status_signing_input statement descriptor
    at output, accepted

theorem observation_trace (statement : auths_model.observation.ObservationStatement)
    (descriptor : auths_model.SignatureDescriptor) (output : alloc.vec.Vec Std.U8)
    (accepted : hash.observation_signing_preimage statement descriptor = ok (.Ok output)) :
    ∃ payload : alloc.vec.Vec Std.U8,
      observation.encode_observation_signing_input statement descriptor = ok (.Ok payload) ∧
      hash.signing_preimage .Observation ⟨[], by scalar_tac⟩ 0#u16 (alloc.vec.Vec.deref payload) =
        ok (.Ok output) ∧
      output.val.map UScalar.val = Framing.encode ⟨9, [], 0, payload.val.map UScalar.val⟩ := by
  unfold hash.observation_signing_preimage at accepted
  auths_unprofiled_signing_trace observation.encode_observation_signing_input statement descriptor
    at output, accepted

end Auths.Crypto.SigningCallers
