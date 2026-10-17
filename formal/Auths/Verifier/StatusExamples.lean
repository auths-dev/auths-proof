import Auths.Verifier.StatusGrant
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace Auths.StatusSelection.Examples
open Auths.StatusSelection

def zeroDigest : AuthsStatusSelection.auths_model.Digest :=
  ⟨List.replicate 32 0#u8, by decide⟩

def signature : AuthsStatusSelection.auths_model.SignatureEnvelope :=
  ⟨⟨"raw-key-v1", "raw:issuer#key-1", "ed25519-v1"⟩, ⟨List.replicate 64 1#u8, by scalar_tac⟩⟩

def principalStatement (state : AuthsStatusSelection.auths_model.PrincipalState)
    (sequence observed : Std.U64) : AuthsStatusSelection.auths_model.SignedPrincipalStatus :=
  ⟨⟨1#u16, "auths-principal-status-v1", "raw:actor", state, sequence, observed, 100#u64, "raw:issuer", ⟨[], by scalar_tac⟩⟩, signature⟩

def rule : AuthsStatusSelection.auths_model.StatusTrustRule :=
  ⟨"auths-principal-status-v1", "raw:issuer", 1#u64, .AnyAnchor⟩

def snapshot (rows : List AuthsStatusSelection.auths_model.SignedPrincipalStatus)
    (bounded : rows.length ≤ Usize.max) : AuthsStatusSelection.auths_model.PrincipalStatusSnapshot :=
  ⟨zeroDigest, 40#u64, 100#u64, ⟨rows, bounded⟩, ⟨[], by scalar_tac⟩, ⟨[rule], by scalar_tac⟩⟩

def required : AuthsStatusSelection.auths_model.StatusPolicy := .SnapshotRequired "auths-principal-status-v1" 20#u64

def implementation : AuthsStatusSelection.ExactStatusMethod := ⟨"auths-principal-status-v1"⟩

-- These shape-valid signature bytes are synthetic. The actual pure selector
-- consumes evidence authenticated by its caller; these component witnesses
-- assert selection and deadline behavior, not cryptographic authenticity.
-- Native parity tests separately construct the same carriers through Rust APIs.
def unknownIssuer : AuthsStatusSelection.auths_model.SignedPrincipalStatus :=
  let signed := principalStatement .Active 2#u64 40#u64
  {signed with statement := {signed.statement with issuer := "raw:unknown"}}

theorem active_selected_horizon :
    AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
      implementation required (snapshot [principalStatement .Active 2#u64 40#u64] (by scalar_tac)) "raw:actor" .Approver 50#u64
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation = ⟨.active, 60⟩ ⦄ := by
  have result := principal_method_approver_refines implementation required (snapshot [principalStatement .Active 2#u64 40#u64] (by scalar_tac)) "raw:actor" 50#u64
  simpa [implementation, required, snapshot, principalStatement, unknownIssuer, rule, ruleView, scopeView,
    policyView, principalView, principalActive, Model.evaluateScan, Model.scan, Model.record,
    Model.visible, Model.scopeCovers, Model.sequenceFloor, Model.initial, Model.contribute,
    Model.fresh, Model.deadline, Model.wordMaximum, Model.finish] using result

theorem revoked_selected_horizon :
    AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
      implementation required (snapshot [principalStatement .Revoked 2#u64 40#u64] (by scalar_tac)) "raw:actor" .Approver 50#u64
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation = ⟨.revoked, 60⟩ ⦄ := by
  have result := principal_method_approver_refines implementation required (snapshot [principalStatement .Revoked 2#u64 40#u64] (by scalar_tac)) "raw:actor" 50#u64
  simpa [implementation, required, snapshot, principalStatement, unknownIssuer, rule, ruleView, scopeView,
    policyView, principalView, principalActive, Model.evaluateScan, Model.scan, Model.record,
    Model.visible, Model.scopeCovers, Model.sequenceFloor, Model.initial, Model.contribute,
    Model.fresh, Model.deadline, Model.wordMaximum, Model.finish] using result

theorem stale_selected_refused :
    AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
      implementation required (snapshot [principalStatement .Active 2#u64 0#u64] (by scalar_tac)) "raw:actor" .Approver 50#u64
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation = ⟨.stale, 50⟩ ⦄ := by
  have result := principal_method_approver_refines implementation required (snapshot [principalStatement .Active 2#u64 0#u64] (by scalar_tac)) "raw:actor" 50#u64
  simpa [implementation, required, snapshot, principalStatement, unknownIssuer, rule, ruleView, scopeView,
    policyView, principalView, principalActive, Model.evaluateScan, Model.scan, Model.record,
    Model.visible, Model.scopeCovers, Model.sequenceFloor, Model.initial, Model.contribute,
    Model.fresh, Model.deadline, Model.wordMaximum, Model.finish] using result

theorem rollback_despite_newer :
    AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
      implementation required (snapshot [principalStatement .Active 0#u64 40#u64, principalStatement .Active 3#u64 40#u64] (by scalar_tac)) "raw:actor" .Approver 50#u64
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation = ⟨.rollback, 50⟩ ⦄ := by
  have result := principal_method_approver_refines implementation required (snapshot [principalStatement .Active 0#u64 40#u64, principalStatement .Active 3#u64 40#u64] (by scalar_tac)) "raw:actor" 50#u64
  simpa [implementation, required, snapshot, principalStatement, unknownIssuer, rule, ruleView, scopeView,
    policyView, principalView, principalActive, Model.evaluateScan, Model.scan, Model.record,
    Model.visible, Model.scopeCovers, Model.sequenceFloor, Model.initial, Model.contribute,
    Model.fresh, Model.deadline, Model.wordMaximum, Model.finish] using result

theorem newer_discards_old_stale_revocation :
    AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
      implementation required (snapshot [principalStatement .Revoked 1#u64 0#u64, principalStatement .Active 2#u64 40#u64] (by scalar_tac)) "raw:actor" .Approver 50#u64
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation = ⟨.active, 60⟩ ⦄ := by
  have result := principal_method_approver_refines implementation required (snapshot [principalStatement .Revoked 1#u64 0#u64, principalStatement .Active 2#u64 40#u64] (by scalar_tac)) "raw:actor" 50#u64
  simpa [implementation, required, snapshot, principalStatement, unknownIssuer, rule, ruleView, scopeView,
    policyView, principalView, principalActive, Model.evaluateScan, Model.scan, Model.record,
    Model.visible, Model.scopeCovers, Model.sequenceFloor, Model.initial, Model.contribute,
    Model.fresh, Model.deadline, Model.wordMaximum, Model.finish] using result

theorem latest_ties_conservatively_revoke :
    AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
      implementation required (snapshot [principalStatement .Active 2#u64 40#u64, principalStatement .Superseded 2#u64 40#u64] (by scalar_tac)) "raw:actor" .Approver 50#u64
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation = ⟨.revoked, 60⟩ ⦄ := by
  have result := principal_method_approver_refines implementation required (snapshot [principalStatement .Active 2#u64 40#u64, principalStatement .Superseded 2#u64 40#u64] (by scalar_tac)) "raw:actor" 50#u64
  simpa [implementation, required, snapshot, principalStatement, unknownIssuer, rule, ruleView, scopeView,
    policyView, principalView, principalActive, Model.evaluateScan, Model.scan, Model.record,
    Model.visible, Model.scopeCovers, Model.sequenceFloor, Model.initial, Model.contribute,
    Model.fresh, Model.deadline, Model.wordMaximum, Model.finish] using result

theorem wrong_method_refused :
    AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
      implementation (.SnapshotRequired "other-status-v1" 20#u64) (snapshot [principalStatement .Active 2#u64 40#u64] (by scalar_tac)) "raw:actor" .Approver 50#u64
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation = ⟨.wrongMethod, 50⟩ ⦄ := by
  have result := principal_method_approver_refines implementation (.SnapshotRequired "other-status-v1" 20#u64) (snapshot [principalStatement .Active 2#u64 40#u64] (by scalar_tac)) "raw:actor" 50#u64
  simpa [implementation, required, snapshot, principalStatement, unknownIssuer, rule, ruleView, scopeView,
    policyView, principalView, principalActive, Model.evaluateScan, Model.scan, Model.record,
    Model.visible, Model.scopeCovers, Model.sequenceFloor, Model.initial, Model.contribute,
    Model.fresh, Model.deadline, Model.wordMaximum, Model.finish] using result

theorem missing_uses_snapshot_window :
    AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
      implementation required (snapshot [] (by scalar_tac)) "raw:actor" .Approver 50#u64
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation = ⟨.missing, 100⟩ ⦄ := by
  have result := principal_method_approver_refines implementation required (snapshot [] (by scalar_tac)) "raw:actor" 50#u64
  simpa [implementation, required, snapshot, principalStatement, unknownIssuer, rule, ruleView, scopeView,
    policyView, principalView, principalActive, Model.evaluateScan, Model.scan, Model.record,
    Model.visible, Model.scopeCovers, Model.sequenceFloor, Model.initial, Model.contribute,
    Model.fresh, Model.deadline, Model.wordMaximum, Model.finish] using result

theorem unknown_issuer_refused :
    AuthsStatusSelection.ExactStatusMethod.Insts.Auths_portsStatusMethod.principal
      implementation required (snapshot [unknownIssuer] (by scalar_tac)) "raw:actor" .Approver 50#u64
      ⦃ actual => ∃ evaluation, actual = .Ok evaluation ∧ evaluationView evaluation = ⟨.untrusted, 50⟩ ⦄ := by
  have result := principal_method_approver_refines implementation required (snapshot [unknownIssuer] (by scalar_tac)) "raw:actor" 50#u64
  simpa [implementation, required, snapshot, principalStatement, unknownIssuer, rule, ruleView, scopeView,
    policyView, principalView, principalActive, Model.evaluateScan, Model.scan, Model.record,
    Model.visible, Model.scopeCovers, Model.sequenceFloor, Model.initial, Model.contribute,
    Model.fresh, Model.deadline, Model.wordMaximum, Model.finish] using result

end Auths.StatusSelection.Examples
