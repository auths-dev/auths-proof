import qualification.aeneas.generated.temporal_witness.Funs

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsTemporalWitness

namespace Auths.Verifier.SealedProjection

/-- Exact contents of the authority earned by preceding verifier stages.
This relation states field preservation independently of the source function's
return value. It does not assume, or establish, that the authority was earned. -/
def Preserves (source : sealed.VerifiedAuthority) (output : sealed.VerifiedAction) : Prop :=
  output.canonical_action = source.canonical_action ∧
  output.proof_digest = source.proof_digest ∧
  output.context_digest = source.context_digest ∧
  output.plan_id = source.plan_id ∧
  output.action_ids = source.action_ids ∧
  output.authorized_branches = source.authorized_branches ∧
  output.assurance = source.assurance ∧
  output.assurance_satisfactions = source.assurance_satisfactions ∧
  output.observation_satisfactions = source.observation_satisfactions ∧
  output.approval_satisfactions = source.approval_satisfactions ∧
  output.authority_not_after = source.authority_not_after ∧
  output.work_units = source.work_units

/-- The actual shipping sealer moves every authority field intact. In
particular it cannot lengthen the evidence horizon, reset charged work, select
different authorized branches or replace canonical action bytes. The caller
must separately establish the complete rich authorization relation. -/
@[step] theorem source_exact (source : sealed.VerifiedAuthority) :
    sealed.bind_verified_action source ⦃ output => Preserves source output ⦄ := by
  simp [sealed.bind_verified_action, Preserves]

end Auths.Verifier.SealedProjection
