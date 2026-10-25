import Auths.Support.FullBorrowABI
import Auths.Support.BorrowViewMaterialize
import qualification.aeneas.cases.NativeBorrowExecution
/- Full native field-value adapters; unelaborated/unqualified.
   Actual current-state, native pure-type ABI and Rust heap/loan/layout adequacy remain required. -/
namespace Auths.Qualification.NativeBorrowFullABI
open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.BorrowTransport Auths.Support.FullBorrowABI
open Auths.Qualification.NativeBorrowExecution
open Auths.Support.BorrowViewMaterialize Auths.Support.NativeBorrowDefaults
universe u
def branch0Channel0 : Channel := { candidateShape := branch0Operation0Access.candidateShape, selected := branch0Operation0Access.selected,
  incomingShape := branch0Operation0Access.nativeShape, outgoingShape := branch0Operation1Access.nativeShape,
  incomingChange := branch0Operation0Access.transport, outgoingChange := branch0Operation1Access.transport }
def branch0Channel0CurrentBuilder : Rebuilder Auths.Qualification.NativeBorrowDefaults.branch0Symbol7Available := .keep
def branch0Channel0ReadCurrent (Atom : Expr → Type u) (current : Current Atom) : Option (Data Atom branch0Channel0.outgoingShape) :=
  readNativeCurrent current (.borrow 0) branch0Channel0CurrentBuilder branch0Channel0.outgoingChange
theorem branch0Channel0_missing_current_is_not_materialized (Atom : Expr → Type u) (current : Current Atom)
    (missing : current (.borrow 0) = none) : branch0Channel0ReadCurrent Atom current = none :=
  absent_current_is_not_materialized _ _ _ _ missing
theorem branch0Channel0_owns_whole_pointee : branch0Channel0.selected = .keep := by rfl
theorem branch0Channel0_needs_no_current_default (Atom : Expr → Type u) (current : Data Atom branch0Channel0.outgoingShape)
    (incoming : Data Atom branch0Channel0.incomingShape) : adapt branch0Channel0 current incoming = some (wholeValue branch0Channel0 incoming) :=
  whole_ownership_needs_no_current_default branch0Channel0 branch0Channel0_owns_whole_pointee current incoming
theorem branch0Channel0_matching_full_input_is_accepted (Atom : Expr → Type u) (current : Data Atom branch0Channel0.outgoingShape) :
    adapt branch0Channel0 current (matchingIncoming branch0Channel0 current) = some current := matching_incoming_is_accepted _ _
theorem branch0Channel0_keeps_current_unselected_fields (Atom : Expr → Type u)
    (current after : Data Atom branch0Channel0.outgoingShape) (incoming : Data Atom branch0Channel0.incomingShape)
    (accepted : adapt branch0Channel0 current incoming = some after) :
    get (Auths.Support.CurrentBorrowCarrier.complement branch0Channel0.outgoingPlan) after =
      get (Auths.Support.CurrentBorrowCarrier.complement branch0Channel0.outgoingPlan) current := accepted_update_preserves_current_frame _ _ _ _ accepted
theorem branch0Channel0_ignores_unselected_incoming_fields (Atom : Expr → Type u)
    (current : Data Atom branch0Channel0.outgoingShape) (first second : Data Atom branch0Channel0.incomingShape)
    (same : get branch0Channel0.incomingPlan first = get branch0Channel0.incomingPlan second) :
    adapt branch0Channel0 current first = adapt branch0Channel0 current second := unselected_incoming_data_has_no_effect _ _ _ _ same
def branch0Full (Atom : Expr → Type u)  (incoming0 : Data Atom branch0Channel0.incomingShape) : Option (Data Atom branch0Channel0.outgoingShape) := do
  let output0 := wholeValue branch0Channel0 incoming0
  pure output0
def branch0FullExecute (Atom : Expr → Type u)
    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)
    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)
     (incoming0 : Data Atom branch0Channel0.incomingShape) : Option (Data Atom branch0Channel0.outgoingShape) := do
  let views ← branch0Execute Atom (initialCurrent Atom counter writer) (get branch0Channel0.incomingPlan incoming0)
  let output0 := views
  pure output0
theorem branch0_full_value_adapter_matches_all_endings (Atom : Expr → Type u)
    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)
    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)
     (incoming0 : Data Atom branch0Channel0.incomingShape) :
    branch0FullExecute Atom counter writer  incoming0 = branch0Full Atom  incoming0 := by
  simp [branch0FullExecute, branch0_execution_normalizes_all_actual_endings, branch0Full,
    branch0Backward, adapt, route, wholeValue, Channel.incomingPlan, Channel.outgoingPlan, branch0Channel0]
def branch0FullFromEndingState (Atom : Expr → Type u)
    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)
    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)
    (incoming0 : Data Atom branch0Channel0.incomingShape) : Option (Data Atom branch0Channel0.outgoingShape) := do
  let state ← Auths.Support.NativeBorrowExecution.run branch0 (initialCurrent Atom counter writer) (branch0Incoming Atom (get branch0Channel0.incomingPlan incoming0))
  let view0 ← (state.outputs[0]?).bind (castEntry branch0Channel0.outgoingShape branch0Channel0.outgoingPlan)
  let output0 := view0
  pure output0
def branch1Channel0 : Channel := { candidateShape := branch1Operation2Access.candidateShape, selected := branch1Operation2Access.selected,
  incomingShape := branch1Operation2Access.nativeShape, outgoingShape := branch1Operation3Access.nativeShape,
  incomingChange := branch1Operation2Access.transport, outgoingChange := branch1Operation3Access.transport }
def branch1Channel0CurrentBuilder : Rebuilder Auths.Qualification.NativeBorrowDefaults.branch1Symbol9Available := .keep
def branch1Channel0ReadCurrent (Atom : Expr → Type u) (current : Current Atom) : Option (Data Atom branch1Channel0.outgoingShape) :=
  readNativeCurrent current (.borrow 1) branch1Channel0CurrentBuilder branch1Channel0.outgoingChange
theorem branch1Channel0_missing_current_is_not_materialized (Atom : Expr → Type u) (current : Current Atom)
    (missing : current (.borrow 1) = none) : branch1Channel0ReadCurrent Atom current = none :=
  absent_current_is_not_materialized _ _ _ _ missing
theorem branch1Channel0_owns_whole_pointee : branch1Channel0.selected = .keep := by rfl
theorem branch1Channel0_needs_no_current_default (Atom : Expr → Type u) (current : Data Atom branch1Channel0.outgoingShape)
    (incoming : Data Atom branch1Channel0.incomingShape) : adapt branch1Channel0 current incoming = some (wholeValue branch1Channel0 incoming) :=
  whole_ownership_needs_no_current_default branch1Channel0 branch1Channel0_owns_whole_pointee current incoming
theorem branch1Channel0_matching_full_input_is_accepted (Atom : Expr → Type u) (current : Data Atom branch1Channel0.outgoingShape) :
    adapt branch1Channel0 current (matchingIncoming branch1Channel0 current) = some current := matching_incoming_is_accepted _ _
theorem branch1Channel0_keeps_current_unselected_fields (Atom : Expr → Type u)
    (current after : Data Atom branch1Channel0.outgoingShape) (incoming : Data Atom branch1Channel0.incomingShape)
    (accepted : adapt branch1Channel0 current incoming = some after) :
    get (Auths.Support.CurrentBorrowCarrier.complement branch1Channel0.outgoingPlan) after =
      get (Auths.Support.CurrentBorrowCarrier.complement branch1Channel0.outgoingPlan) current := accepted_update_preserves_current_frame _ _ _ _ accepted
theorem branch1Channel0_ignores_unselected_incoming_fields (Atom : Expr → Type u)
    (current : Data Atom branch1Channel0.outgoingShape) (first second : Data Atom branch1Channel0.incomingShape)
    (same : get branch1Channel0.incomingPlan first = get branch1Channel0.incomingPlan second) :
    adapt branch1Channel0 current first = adapt branch1Channel0 current second := unselected_incoming_data_has_no_effect _ _ _ _ same
def branch1Full (Atom : Expr → Type u)  (incoming0 : Data Atom branch1Channel0.incomingShape) : Option (Data Atom branch1Channel0.outgoingShape) := do
  let output0 := wholeValue branch1Channel0 incoming0
  pure output0
def branch1FullExecute (Atom : Expr → Type u)
    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)
    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)
     (incoming0 : Data Atom branch1Channel0.incomingShape) : Option (Data Atom branch1Channel0.outgoingShape) := do
  let views ← branch1Execute Atom (initialCurrent Atom counter writer) (get branch1Channel0.incomingPlan incoming0)
  let output0 := views
  pure output0
theorem branch1_full_value_adapter_matches_all_endings (Atom : Expr → Type u)
    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)
    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)
     (incoming0 : Data Atom branch1Channel0.incomingShape) :
    branch1FullExecute Atom counter writer  incoming0 = branch1Full Atom  incoming0 := by
  simp [branch1FullExecute, branch1_execution_normalizes_all_actual_endings, branch1Full,
    branch1Backward, adapt, route, wholeValue, Channel.incomingPlan, Channel.outgoingPlan, branch1Channel0]
def branch1FullFromEndingState (Atom : Expr → Type u)
    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)
    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)
    (incoming0 : Data Atom branch1Channel0.incomingShape) : Option (Data Atom branch1Channel0.outgoingShape) := do
  let state ← Auths.Support.NativeBorrowExecution.run branch1 (initialCurrent Atom counter writer) (branch1Incoming Atom (get branch1Channel0.incomingPlan incoming0))
  let view0 ← (state.outputs[0]?).bind (castEntry branch1Channel0.outgoingShape branch1Channel0.outgoingPlan)
  let output0 := view0
  pure output0
def branch2Channel0 : Channel := { candidateShape := branch2Operation2Access.candidateShape, selected := branch2Operation2Access.selected,
  incomingShape := branch2Operation2Access.nativeShape, outgoingShape := branch2Operation3Access.nativeShape,
  incomingChange := branch2Operation2Access.transport, outgoingChange := branch2Operation3Access.transport }
def branch2Channel0CurrentBuilder : Rebuilder Auths.Qualification.NativeBorrowDefaults.branch2Symbol11Available := .keep
def branch2Channel0ReadCurrent (Atom : Expr → Type u) (current : Current Atom) : Option (Data Atom branch2Channel0.outgoingShape) :=
  readNativeCurrent current (.symbolic 6) branch2Channel0CurrentBuilder branch2Channel0.outgoingChange
theorem branch2Channel0_missing_current_is_not_materialized (Atom : Expr → Type u) (current : Current Atom)
    (missing : current (.symbolic 6) = none) : branch2Channel0ReadCurrent Atom current = none :=
  absent_current_is_not_materialized _ _ _ _ missing
theorem branch2Channel0_matching_full_input_is_accepted (Atom : Expr → Type u) (current : Data Atom branch2Channel0.outgoingShape) :
    adapt branch2Channel0 current (matchingIncoming branch2Channel0 current) = some current := matching_incoming_is_accepted _ _
theorem branch2Channel0_keeps_current_unselected_fields (Atom : Expr → Type u)
    (current after : Data Atom branch2Channel0.outgoingShape) (incoming : Data Atom branch2Channel0.incomingShape)
    (accepted : adapt branch2Channel0 current incoming = some after) :
    get (Auths.Support.CurrentBorrowCarrier.complement branch2Channel0.outgoingPlan) after =
      get (Auths.Support.CurrentBorrowCarrier.complement branch2Channel0.outgoingPlan) current := accepted_update_preserves_current_frame _ _ _ _ accepted
theorem branch2Channel0_ignores_unselected_incoming_fields (Atom : Expr → Type u)
    (current : Data Atom branch2Channel0.outgoingShape) (first second : Data Atom branch2Channel0.incomingShape)
    (same : get branch2Channel0.incomingPlan first = get branch2Channel0.incomingPlan second) :
    adapt branch2Channel0 current first = adapt branch2Channel0 current second := unselected_incoming_data_has_no_effect _ _ _ _ same
def branch2Full (Atom : Expr → Type u) (current0 : Data Atom branch2Channel0.outgoingShape) (incoming0 : Data Atom branch2Channel0.incomingShape) : Option (Data Atom branch2Channel0.outgoingShape) := do
  let output0 ← adapt branch2Channel0 current0 incoming0
  pure output0
def branch2FullExecute (Atom : Expr → Type u)
    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)
    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)
    (current0 : Data Atom branch2Channel0.outgoingShape) (incoming0 : Data Atom branch2Channel0.incomingShape) : Option (Data Atom branch2Channel0.outgoingShape) := do
  let views ← branch2Execute Atom (initialCurrent Atom counter writer) (get branch2Channel0.incomingPlan incoming0)
  let output0 ← put branch2Channel0.outgoingPlan current0 views
  pure output0
theorem branch2_full_value_adapter_matches_all_endings (Atom : Expr → Type u)
    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)
    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)
    (current0 : Data Atom branch2Channel0.outgoingShape) (incoming0 : Data Atom branch2Channel0.incomingShape) :
    branch2FullExecute Atom counter writer current0 incoming0 = branch2Full Atom current0 incoming0 := by
  simp [branch2FullExecute, branch2_execution_normalizes_all_actual_endings, branch2Full,
    branch2Backward, adapt, route, wholeValue, Channel.incomingPlan, Channel.outgoingPlan, branch2Channel0]
def branch2FullFromEndingState (Atom : Expr → Type u)
    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)
    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)
    (incoming0 : Data Atom branch2Channel0.incomingShape) : Option (Data Atom branch2Channel0.outgoingShape) := do
  let state ← Auths.Support.NativeBorrowExecution.run branch2 (initialCurrent Atom counter writer) (branch2Incoming Atom (get branch2Channel0.incomingPlan incoming0))
  let view0 ← (state.outputs[0]?).bind (castEntry branch2Channel0.outgoingShape branch2Channel0.outgoingPlan)
  let current0 ← branch2Channel0ReadCurrent Atom state.current
  let output0 ← put branch2Channel0.outgoingPlan current0 view0
  pure output0
def branch3Channel0 : Channel := { candidateShape := branch3Operation4Access.candidateShape, selected := branch3Operation4Access.selected,
  incomingShape := branch3Operation4Access.nativeShape, outgoingShape := branch3Operation5Access.nativeShape,
  incomingChange := branch3Operation4Access.transport, outgoingChange := branch3Operation5Access.transport }
def branch3Channel0CurrentBuilder : Rebuilder Auths.Qualification.NativeBorrowDefaults.branch3Symbol14Available := .named (.sum (.named (.product (.named (.borrow (.keep))) (.unit))) (.sum (.named (.product (.named (.borrow (.keep))) (.unit))) (.empty)))
def branch3Channel0ReadCurrent (Atom : Expr → Type u) (current : Current Atom) : Option (Data Atom branch3Channel0.outgoingShape) :=
  readNativeCurrent current (.symbolic 13) branch3Channel0CurrentBuilder branch3Channel0.outgoingChange
theorem branch3Channel0_missing_current_is_not_materialized (Atom : Expr → Type u) (current : Current Atom)
    (missing : current (.symbolic 13) = none) : branch3Channel0ReadCurrent Atom current = none :=
  absent_current_is_not_materialized _ _ _ _ missing
theorem branch3Channel0_matching_full_input_is_accepted (Atom : Expr → Type u) (current : Data Atom branch3Channel0.outgoingShape) :
    adapt branch3Channel0 current (matchingIncoming branch3Channel0 current) = some current := matching_incoming_is_accepted _ _
theorem branch3Channel0_keeps_current_unselected_fields (Atom : Expr → Type u)
    (current after : Data Atom branch3Channel0.outgoingShape) (incoming : Data Atom branch3Channel0.incomingShape)
    (accepted : adapt branch3Channel0 current incoming = some after) :
    get (Auths.Support.CurrentBorrowCarrier.complement branch3Channel0.outgoingPlan) after =
      get (Auths.Support.CurrentBorrowCarrier.complement branch3Channel0.outgoingPlan) current := accepted_update_preserves_current_frame _ _ _ _ accepted
theorem branch3Channel0_ignores_unselected_incoming_fields (Atom : Expr → Type u)
    (current : Data Atom branch3Channel0.outgoingShape) (first second : Data Atom branch3Channel0.incomingShape)
    (same : get branch3Channel0.incomingPlan first = get branch3Channel0.incomingPlan second) :
    adapt branch3Channel0 current first = adapt branch3Channel0 current second := unselected_incoming_data_has_no_effect _ _ _ _ same
def branch3Channel1 : Channel := { candidateShape := branch3Operation6Access.candidateShape, selected := branch3Operation6Access.selected,
  incomingShape := branch3Operation6Access.nativeShape, outgoingShape := branch3Operation7Access.nativeShape,
  incomingChange := branch3Operation6Access.transport, outgoingChange := branch3Operation7Access.transport }
def branch3Channel1CurrentBuilder : Rebuilder Auths.Qualification.NativeBorrowDefaults.branch3Symbol15Available := .keep
def branch3Channel1ReadCurrent (Atom : Expr → Type u) (current : Current Atom) : Option (Data Atom branch3Channel1.outgoingShape) :=
  readNativeCurrent current (.symbolic 6) branch3Channel1CurrentBuilder branch3Channel1.outgoingChange
theorem branch3Channel1_missing_current_is_not_materialized (Atom : Expr → Type u) (current : Current Atom)
    (missing : current (.symbolic 6) = none) : branch3Channel1ReadCurrent Atom current = none :=
  absent_current_is_not_materialized _ _ _ _ missing
theorem branch3Channel1_matching_full_input_is_accepted (Atom : Expr → Type u) (current : Data Atom branch3Channel1.outgoingShape) :
    adapt branch3Channel1 current (matchingIncoming branch3Channel1 current) = some current := matching_incoming_is_accepted _ _
theorem branch3Channel1_keeps_current_unselected_fields (Atom : Expr → Type u)
    (current after : Data Atom branch3Channel1.outgoingShape) (incoming : Data Atom branch3Channel1.incomingShape)
    (accepted : adapt branch3Channel1 current incoming = some after) :
    get (Auths.Support.CurrentBorrowCarrier.complement branch3Channel1.outgoingPlan) after =
      get (Auths.Support.CurrentBorrowCarrier.complement branch3Channel1.outgoingPlan) current := accepted_update_preserves_current_frame _ _ _ _ accepted
theorem branch3Channel1_ignores_unselected_incoming_fields (Atom : Expr → Type u)
    (current : Data Atom branch3Channel1.outgoingShape) (first second : Data Atom branch3Channel1.incomingShape)
    (same : get branch3Channel1.incomingPlan first = get branch3Channel1.incomingPlan second) :
    adapt branch3Channel1 current first = adapt branch3Channel1 current second := unselected_incoming_data_has_no_effect _ _ _ _ same
def branch3Full (Atom : Expr → Type u) (current0 : Data Atom branch3Channel0.outgoingShape) (current1 : Data Atom branch3Channel1.outgoingShape) (incoming0 : Data Atom branch3Channel0.incomingShape) (incoming1 : Data Atom branch3Channel1.incomingShape) : Option ((Data Atom branch3Channel0.outgoingShape × Data Atom branch3Channel1.outgoingShape)) := do
  let output0 ← adapt branch3Channel0 current0 incoming0
  let output1 ← adapt branch3Channel1 current1 incoming1
  pure (output0, output1)
def branch3FullExecute (Atom : Expr → Type u)
    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)
    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)
    (current0 : Data Atom branch3Channel0.outgoingShape) (current1 : Data Atom branch3Channel1.outgoingShape) (incoming0 : Data Atom branch3Channel0.incomingShape) (incoming1 : Data Atom branch3Channel1.incomingShape) : Option ((Data Atom branch3Channel0.outgoingShape × Data Atom branch3Channel1.outgoingShape)) := do
  let views ← branch3Execute Atom (initialCurrent Atom counter writer) (get branch3Channel0.incomingPlan incoming0) (get branch3Channel1.incomingPlan incoming1)
  let output0 ← put branch3Channel0.outgoingPlan current0 views.1
  let output1 ← put branch3Channel1.outgoingPlan current1 views.2
  pure (output0, output1)
theorem branch3_full_value_adapter_matches_all_endings (Atom : Expr → Type u)
    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)
    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)
    (current0 : Data Atom branch3Channel0.outgoingShape) (current1 : Data Atom branch3Channel1.outgoingShape) (incoming0 : Data Atom branch3Channel0.incomingShape) (incoming1 : Data Atom branch3Channel1.incomingShape) :
    branch3FullExecute Atom counter writer current0 current1 incoming0 incoming1 = branch3Full Atom current0 current1 incoming0 incoming1 := by
  simp [branch3FullExecute, branch3_execution_normalizes_all_actual_endings, branch3Full,
    branch3Backward, adapt, route, wholeValue, Channel.incomingPlan, Channel.outgoingPlan, branch3Channel0, branch3Channel1]
def branch3FullFromEndingState (Atom : Expr → Type u)
    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)
    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)
    (incoming0 : Data Atom branch3Channel0.incomingShape) (incoming1 : Data Atom branch3Channel1.incomingShape) : Option ((Data Atom branch3Channel0.outgoingShape × Data Atom branch3Channel1.outgoingShape)) := do
  let state ← Auths.Support.NativeBorrowExecution.run branch3 (initialCurrent Atom counter writer) (branch3Incoming Atom (get branch3Channel0.incomingPlan incoming0) (get branch3Channel1.incomingPlan incoming1))
  let view0 ← (state.outputs[0]?).bind (castEntry branch3Channel0.outgoingShape branch3Channel0.outgoingPlan)
  let current0 ← branch3Channel0ReadCurrent Atom state.current
  let output0 ← put branch3Channel0.outgoingPlan current0 view0
  let view1 ← (state.outputs[1]?).bind (castEntry branch3Channel1.outgoingShape branch3Channel1.outgoingPlan)
  let current1 ← branch3Channel1ReadCurrent Atom state.current
  let output1 ← put branch3Channel1.outgoingPlan current1 view1
  pure (output0, output1)
end Auths.Qualification.NativeBorrowFullABI
