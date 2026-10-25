import Auths.Support.CurrentBorrowCarrier
import qualification.aeneas.cases.NativeBorrowTransport
/- Actual current-carrier restoration, unelaborated/unqualified.
   Native parent/default continuations, full ABI and heap/loan adequacy remain required. -/
namespace Auths.Qualification.CurrentBorrowCarrier
open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.CurrentBorrowCarrier
open Auths.Qualification.NativeBorrowTransport
open Auths.Qualification.BorrowProjection.Candidate3400
universe u
def input0Focus : Focus outputShape input0Shape := .named (.second (.first (.named (.here))))
def recoverInput0 (Atom : Expr → Type u) (current : Data Atom outputShape) : Data Atom input0Shape :=
  read input0Focus current
def input1Focus : Focus outputShape input1Shape := .named (.first (.named (.here)))
def recoverInput1 (Atom : Expr → Type u) (current : Data Atom outputShape) : Data Atom input1Shape :=
  read input1Focus current
theorem recover_source_input_0 (Atom : Expr → Type u) (input0 : Data Atom input0Shape) (input1 : Data Atom input1Shape) :
    recoverInput0 Atom (construct Atom input0 input1) = input0 := by rfl
theorem recover_source_input_1 (Atom : Expr → Type u) (input0 : Data Atom input0Shape) (input1 : Data Atom input1Shape) :
    recoverInput1 Atom (construct Atom input0 input1) = input1 := by rfl
theorem reassemble_current_source_inputs (Atom : Expr → Type u) (current : Data Atom outputShape) :
    construct Atom (recoverInput0 Atom current) (recoverInput1 Atom current) = current := by
  cases current with
  | named fields =>
      cases fields with
      | product field0 tail0 =>
          cases field0 with
          | named input0 =>
              cases tail0 with
              | product field1 tail1 =>
                  cases field1 with
                  | named input1 =>
                      cases tail1
                      rfl
def branch0Port0Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch0Schema0.shape := .named (.second (.first (.named (.borrow (.here)))))
def branch0Port0Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch0Port0NativePlan :=
  branch0Port0ToNative Atom (extract branch0Port0Focus Auths.Qualification.NativeBorrowView.branch0Schema0.plan current)
def branch0Port0Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch0Port0NativePlan) : Option (Data Atom outputShape) :=
  restore branch0Port0Focus Auths.Qualification.NativeBorrowView.branch0Schema0.plan current (branch0Port0FromNative Atom update)
theorem branch0Port0_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch0Port0Restore Atom current (branch0Port0Extract Atom current) = some current := by
  simp [branch0Port0Restore, branch0Port0Extract, branch0Port0_candidate_round_trip, restore_extracted_current]
theorem branch0Port0_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch0Port0NativePlan) (accepted : branch0Port0Restore Atom current update = some after) :
    branch0Port0Extract Atom after = update := by
  have exactView := restored_view_is_update branch0Port0Focus Auths.Qualification.NativeBorrowView.branch0Schema0.plan current after (branch0Port0FromNative Atom update) accepted
  simpa [branch0Port0Extract, exactView, branch0Port0_native_round_trip]
theorem branch0Port0_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch0Port0NativePlan) :
    put (liftPlan branch0Port0Focus Auths.Qualification.NativeBorrowView.branch0Schema0.plan) current
      (liftView branch0Port0Focus Auths.Qualification.NativeBorrowView.branch0Schema0.plan (branch0Port0FromNative Atom update)) = branch0Port0Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch0Port0_separate_from_input1 : Disjoint branch0Port0Focus input1Focus := .named (.secondFirst (.first (.named (.borrow (.here)))) (.named (.here)))
theorem branch0Port0_preserves_current_input1 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch0Port0NativePlan) (accepted : branch0Port0Restore Atom current update = some after) :
    recoverInput1 Atom after = recoverInput1 Atom current :=
  restoration_preserves_disjoint_current branch0Port0_separate_from_input1 Auths.Qualification.NativeBorrowView.branch0Schema0.plan current after (branch0Port0FromNative Atom update) accepted
def branch0Port1Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch0Schema0.shape := .named (.second (.first (.named (.borrow (.here)))))
def branch0Port1Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch0Port1NativePlan :=
  branch0Port1ToNative Atom (extract branch0Port1Focus Auths.Qualification.NativeBorrowView.branch0Schema0.plan current)
def branch0Port1Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch0Port1NativePlan) : Option (Data Atom outputShape) :=
  restore branch0Port1Focus Auths.Qualification.NativeBorrowView.branch0Schema0.plan current (branch0Port1FromNative Atom update)
theorem branch0Port1_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch0Port1Restore Atom current (branch0Port1Extract Atom current) = some current := by
  simp [branch0Port1Restore, branch0Port1Extract, branch0Port1_candidate_round_trip, restore_extracted_current]
theorem branch0Port1_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch0Port1NativePlan) (accepted : branch0Port1Restore Atom current update = some after) :
    branch0Port1Extract Atom after = update := by
  have exactView := restored_view_is_update branch0Port1Focus Auths.Qualification.NativeBorrowView.branch0Schema0.plan current after (branch0Port1FromNative Atom update) accepted
  simpa [branch0Port1Extract, exactView, branch0Port1_native_round_trip]
theorem branch0Port1_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch0Port1NativePlan) :
    put (liftPlan branch0Port1Focus Auths.Qualification.NativeBorrowView.branch0Schema0.plan) current
      (liftView branch0Port1Focus Auths.Qualification.NativeBorrowView.branch0Schema0.plan (branch0Port1FromNative Atom update)) = branch0Port1Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch0Port1_separate_from_input1 : Disjoint branch0Port1Focus input1Focus := .named (.secondFirst (.first (.named (.borrow (.here)))) (.named (.here)))
theorem branch0Port1_preserves_current_input1 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch0Port1NativePlan) (accepted : branch0Port1Restore Atom current update = some after) :
    recoverInput1 Atom after = recoverInput1 Atom current :=
  restoration_preserves_disjoint_current branch0Port1_separate_from_input1 Auths.Qualification.NativeBorrowView.branch0Schema0.plan current after (branch0Port1FromNative Atom update) accepted
def branch1Parent0Plan : Plan outputShape := select [.parameter 0] outputShape
def branch1Parent0Current (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch1Parent0Plan :=
  get branch1Parent0Plan current
theorem branch1Parent0_restores_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    put branch1Parent0Plan current (branch1Parent0Current Atom current) = some current := get_then_put _ _
def branch1Port0Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch1Schema0.shape := .named (.first (.named (.named (.first (.named (.named (.first (.named (.borrow (.here))))))))))
def branch1Port0Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch1Port0NativePlan :=
  branch1Port0ToNative Atom (extract branch1Port0Focus Auths.Qualification.NativeBorrowView.branch1Schema0.plan current)
def branch1Port0Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch1Port0NativePlan) : Option (Data Atom outputShape) :=
  restore branch1Port0Focus Auths.Qualification.NativeBorrowView.branch1Schema0.plan current (branch1Port0FromNative Atom update)
theorem branch1Port0_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch1Port0Restore Atom current (branch1Port0Extract Atom current) = some current := by
  simp [branch1Port0Restore, branch1Port0Extract, branch1Port0_candidate_round_trip, restore_extracted_current]
theorem branch1Port0_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch1Port0NativePlan) (accepted : branch1Port0Restore Atom current update = some after) :
    branch1Port0Extract Atom after = update := by
  have exactView := restored_view_is_update branch1Port0Focus Auths.Qualification.NativeBorrowView.branch1Schema0.plan current after (branch1Port0FromNative Atom update) accepted
  simpa [branch1Port0Extract, exactView, branch1Port0_native_round_trip]
theorem branch1Port0_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch1Port0NativePlan) :
    put (liftPlan branch1Port0Focus Auths.Qualification.NativeBorrowView.branch1Schema0.plan) current
      (liftView branch1Port0Focus Auths.Qualification.NativeBorrowView.branch1Schema0.plan (branch1Port0FromNative Atom update)) = branch1Port0Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch1Port0_separate_from_input0 : Disjoint branch1Port0Focus input0Focus := .named (.firstSecond (.named (.named (.first (.named (.named (.first (.named (.borrow (.here))))))))) (.first (.named (.here))))
theorem branch1Port0_preserves_current_input0 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch1Port0NativePlan) (accepted : branch1Port0Restore Atom current update = some after) :
    recoverInput0 Atom after = recoverInput0 Atom current :=
  restoration_preserves_disjoint_current branch1Port0_separate_from_input0 Auths.Qualification.NativeBorrowView.branch1Schema0.plan current after (branch1Port0FromNative Atom update) accepted
def branch1Port1Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch1Schema0.shape := .named (.first (.named (.named (.first (.named (.named (.first (.named (.borrow (.here))))))))))
def branch1Port1Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch1Port1NativePlan :=
  branch1Port1ToNative Atom (extract branch1Port1Focus Auths.Qualification.NativeBorrowView.branch1Schema0.plan current)
def branch1Port1Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch1Port1NativePlan) : Option (Data Atom outputShape) :=
  restore branch1Port1Focus Auths.Qualification.NativeBorrowView.branch1Schema0.plan current (branch1Port1FromNative Atom update)
theorem branch1Port1_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch1Port1Restore Atom current (branch1Port1Extract Atom current) = some current := by
  simp [branch1Port1Restore, branch1Port1Extract, branch1Port1_candidate_round_trip, restore_extracted_current]
theorem branch1Port1_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch1Port1NativePlan) (accepted : branch1Port1Restore Atom current update = some after) :
    branch1Port1Extract Atom after = update := by
  have exactView := restored_view_is_update branch1Port1Focus Auths.Qualification.NativeBorrowView.branch1Schema0.plan current after (branch1Port1FromNative Atom update) accepted
  simpa [branch1Port1Extract, exactView, branch1Port1_native_round_trip]
theorem branch1Port1_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch1Port1NativePlan) :
    put (liftPlan branch1Port1Focus Auths.Qualification.NativeBorrowView.branch1Schema0.plan) current
      (liftView branch1Port1Focus Auths.Qualification.NativeBorrowView.branch1Schema0.plan (branch1Port1FromNative Atom update)) = branch1Port1Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch1Port1_separate_from_input0 : Disjoint branch1Port1Focus input0Focus := .named (.firstSecond (.named (.named (.first (.named (.named (.first (.named (.borrow (.here))))))))) (.first (.named (.here))))
theorem branch1Port1_preserves_current_input0 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch1Port1NativePlan) (accepted : branch1Port1Restore Atom current update = some after) :
    recoverInput0 Atom after = recoverInput0 Atom current :=
  restoration_preserves_disjoint_current branch1Port1_separate_from_input0 Auths.Qualification.NativeBorrowView.branch1Schema0.plan current after (branch1Port1FromNative Atom update) accepted
def branch2Parent0Plan : Plan outputShape := select [.parameter 0] outputShape
def branch2Parent0Current (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch2Parent0Plan :=
  get branch2Parent0Plan current
theorem branch2Parent0_restores_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    put branch2Parent0Plan current (branch2Parent0Current Atom current) = some current := get_then_put _ _
def branch2Parent1Plan : Plan outputShape := select [.parameter 1] outputShape
def branch2Parent1Current (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch2Parent1Plan :=
  get branch2Parent1Plan current
theorem branch2Parent1_restores_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    put branch2Parent1Plan current (branch2Parent1Current Atom current) = some current := get_then_put _ _
def branch2Port0Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch2Schema0.shape := .named (.first (.named (.named (.first (.named (.named (.first (.named (.borrow (.here))))))))))
def branch2Port0Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch2Port0NativePlan :=
  branch2Port0ToNative Atom (extract branch2Port0Focus Auths.Qualification.NativeBorrowView.branch2Schema0.plan current)
def branch2Port0Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch2Port0NativePlan) : Option (Data Atom outputShape) :=
  restore branch2Port0Focus Auths.Qualification.NativeBorrowView.branch2Schema0.plan current (branch2Port0FromNative Atom update)
theorem branch2Port0_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch2Port0Restore Atom current (branch2Port0Extract Atom current) = some current := by
  simp [branch2Port0Restore, branch2Port0Extract, branch2Port0_candidate_round_trip, restore_extracted_current]
theorem branch2Port0_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch2Port0NativePlan) (accepted : branch2Port0Restore Atom current update = some after) :
    branch2Port0Extract Atom after = update := by
  have exactView := restored_view_is_update branch2Port0Focus Auths.Qualification.NativeBorrowView.branch2Schema0.plan current after (branch2Port0FromNative Atom update) accepted
  simpa [branch2Port0Extract, exactView, branch2Port0_native_round_trip]
theorem branch2Port0_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch2Port0NativePlan) :
    put (liftPlan branch2Port0Focus Auths.Qualification.NativeBorrowView.branch2Schema0.plan) current
      (liftView branch2Port0Focus Auths.Qualification.NativeBorrowView.branch2Schema0.plan (branch2Port0FromNative Atom update)) = branch2Port0Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch2Port0_separate_from_input0 : Disjoint branch2Port0Focus input0Focus := .named (.firstSecond (.named (.named (.first (.named (.named (.first (.named (.borrow (.here))))))))) (.first (.named (.here))))
theorem branch2Port0_preserves_current_input0 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch2Port0NativePlan) (accepted : branch2Port0Restore Atom current update = some after) :
    recoverInput0 Atom after = recoverInput0 Atom current :=
  restoration_preserves_disjoint_current branch2Port0_separate_from_input0 Auths.Qualification.NativeBorrowView.branch2Schema0.plan current after (branch2Port0FromNative Atom update) accepted
def branch2Port1Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch2Schema1.shape := .named (.first (.named (.named (.first (.named (.named (.first (.named (.borrow (.named (.here)))))))))))
def branch2Port1Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch2Port1NativePlan :=
  branch2Port1ToNative Atom (extract branch2Port1Focus Auths.Qualification.NativeBorrowView.branch2Schema1.plan current)
def branch2Port1Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch2Port1NativePlan) : Option (Data Atom outputShape) :=
  restore branch2Port1Focus Auths.Qualification.NativeBorrowView.branch2Schema1.plan current (branch2Port1FromNative Atom update)
theorem branch2Port1_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch2Port1Restore Atom current (branch2Port1Extract Atom current) = some current := by
  simp [branch2Port1Restore, branch2Port1Extract, branch2Port1_candidate_round_trip, restore_extracted_current]
theorem branch2Port1_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch2Port1NativePlan) (accepted : branch2Port1Restore Atom current update = some after) :
    branch2Port1Extract Atom after = update := by
  have exactView := restored_view_is_update branch2Port1Focus Auths.Qualification.NativeBorrowView.branch2Schema1.plan current after (branch2Port1FromNative Atom update) accepted
  simpa [branch2Port1Extract, exactView, branch2Port1_native_round_trip]
theorem branch2Port1_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch2Port1NativePlan) :
    put (liftPlan branch2Port1Focus Auths.Qualification.NativeBorrowView.branch2Schema1.plan) current
      (liftView branch2Port1Focus Auths.Qualification.NativeBorrowView.branch2Schema1.plan (branch2Port1FromNative Atom update)) = branch2Port1Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch2Port1_separate_from_input0 : Disjoint branch2Port1Focus input0Focus := .named (.firstSecond (.named (.named (.first (.named (.named (.first (.named (.borrow (.named (.here)))))))))) (.first (.named (.here))))
theorem branch2Port1_preserves_current_input0 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch2Port1NativePlan) (accepted : branch2Port1Restore Atom current update = some after) :
    recoverInput0 Atom after = recoverInput0 Atom current :=
  restoration_preserves_disjoint_current branch2Port1_separate_from_input0 Auths.Qualification.NativeBorrowView.branch2Schema1.plan current after (branch2Port1FromNative Atom update) accepted
def branch2Port2Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch2Schema0.shape := .named (.first (.named (.named (.first (.named (.named (.first (.named (.borrow (.here))))))))))
def branch2Port2Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch2Port2NativePlan :=
  branch2Port2ToNative Atom (extract branch2Port2Focus Auths.Qualification.NativeBorrowView.branch2Schema0.plan current)
def branch2Port2Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch2Port2NativePlan) : Option (Data Atom outputShape) :=
  restore branch2Port2Focus Auths.Qualification.NativeBorrowView.branch2Schema0.plan current (branch2Port2FromNative Atom update)
theorem branch2Port2_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch2Port2Restore Atom current (branch2Port2Extract Atom current) = some current := by
  simp [branch2Port2Restore, branch2Port2Extract, branch2Port2_candidate_round_trip, restore_extracted_current]
theorem branch2Port2_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch2Port2NativePlan) (accepted : branch2Port2Restore Atom current update = some after) :
    branch2Port2Extract Atom after = update := by
  have exactView := restored_view_is_update branch2Port2Focus Auths.Qualification.NativeBorrowView.branch2Schema0.plan current after (branch2Port2FromNative Atom update) accepted
  simpa [branch2Port2Extract, exactView, branch2Port2_native_round_trip]
theorem branch2Port2_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch2Port2NativePlan) :
    put (liftPlan branch2Port2Focus Auths.Qualification.NativeBorrowView.branch2Schema0.plan) current
      (liftView branch2Port2Focus Auths.Qualification.NativeBorrowView.branch2Schema0.plan (branch2Port2FromNative Atom update)) = branch2Port2Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch2Port2_separate_from_input0 : Disjoint branch2Port2Focus input0Focus := .named (.firstSecond (.named (.named (.first (.named (.named (.first (.named (.borrow (.here))))))))) (.first (.named (.here))))
theorem branch2Port2_preserves_current_input0 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch2Port2NativePlan) (accepted : branch2Port2Restore Atom current update = some after) :
    recoverInput0 Atom after = recoverInput0 Atom current :=
  restoration_preserves_disjoint_current branch2Port2_separate_from_input0 Auths.Qualification.NativeBorrowView.branch2Schema0.plan current after (branch2Port2FromNative Atom update) accepted
def branch2Port3Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch2Schema1.shape := .named (.first (.named (.named (.first (.named (.named (.first (.named (.borrow (.named (.here)))))))))))
def branch2Port3Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch2Port3NativePlan :=
  branch2Port3ToNative Atom (extract branch2Port3Focus Auths.Qualification.NativeBorrowView.branch2Schema1.plan current)
def branch2Port3Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch2Port3NativePlan) : Option (Data Atom outputShape) :=
  restore branch2Port3Focus Auths.Qualification.NativeBorrowView.branch2Schema1.plan current (branch2Port3FromNative Atom update)
theorem branch2Port3_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch2Port3Restore Atom current (branch2Port3Extract Atom current) = some current := by
  simp [branch2Port3Restore, branch2Port3Extract, branch2Port3_candidate_round_trip, restore_extracted_current]
theorem branch2Port3_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch2Port3NativePlan) (accepted : branch2Port3Restore Atom current update = some after) :
    branch2Port3Extract Atom after = update := by
  have exactView := restored_view_is_update branch2Port3Focus Auths.Qualification.NativeBorrowView.branch2Schema1.plan current after (branch2Port3FromNative Atom update) accepted
  simpa [branch2Port3Extract, exactView, branch2Port3_native_round_trip]
theorem branch2Port3_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch2Port3NativePlan) :
    put (liftPlan branch2Port3Focus Auths.Qualification.NativeBorrowView.branch2Schema1.plan) current
      (liftView branch2Port3Focus Auths.Qualification.NativeBorrowView.branch2Schema1.plan (branch2Port3FromNative Atom update)) = branch2Port3Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch2Port3_separate_from_input0 : Disjoint branch2Port3Focus input0Focus := .named (.firstSecond (.named (.named (.first (.named (.named (.first (.named (.borrow (.named (.here)))))))))) (.first (.named (.here))))
theorem branch2Port3_preserves_current_input0 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch2Port3NativePlan) (accepted : branch2Port3Restore Atom current update = some after) :
    recoverInput0 Atom after = recoverInput0 Atom current :=
  restoration_preserves_disjoint_current branch2Port3_separate_from_input0 Auths.Qualification.NativeBorrowView.branch2Schema1.plan current after (branch2Port3FromNative Atom update) accepted
def branch3Parent0Plan : Plan outputShape := select [.parameter 0] outputShape
def branch3Parent0Current (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch3Parent0Plan :=
  get branch3Parent0Plan current
theorem branch3Parent0_restores_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    put branch3Parent0Plan current (branch3Parent0Current Atom current) = some current := get_then_put _ _
def branch3Parent2Plan : Plan outputShape := select [.parameter 2] outputShape
def branch3Parent2Current (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch3Parent2Plan :=
  get branch3Parent2Plan current
theorem branch3Parent2_restores_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    put branch3Parent2Plan current (branch3Parent2Current Atom current) = some current := get_then_put _ _
def branch3Port0Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch3Schema0.shape := .named (.first (.named (.named (.first (.named (.named (.first (.named (.borrow (.named (.here)))))))))))
def branch3Port0Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch3Port0NativePlan :=
  branch3Port0ToNative Atom (extract branch3Port0Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan current)
def branch3Port0Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch3Port0NativePlan) : Option (Data Atom outputShape) :=
  restore branch3Port0Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan current (branch3Port0FromNative Atom update)
theorem branch3Port0_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch3Port0Restore Atom current (branch3Port0Extract Atom current) = some current := by
  simp [branch3Port0Restore, branch3Port0Extract, branch3Port0_candidate_round_trip, restore_extracted_current]
theorem branch3Port0_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch3Port0NativePlan) (accepted : branch3Port0Restore Atom current update = some after) :
    branch3Port0Extract Atom after = update := by
  have exactView := restored_view_is_update branch3Port0Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan current after (branch3Port0FromNative Atom update) accepted
  simpa [branch3Port0Extract, exactView, branch3Port0_native_round_trip]
theorem branch3Port0_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch3Port0NativePlan) :
    put (liftPlan branch3Port0Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan) current
      (liftView branch3Port0Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan (branch3Port0FromNative Atom update)) = branch3Port0Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch3Port0_separate_from_input0 : Disjoint branch3Port0Focus input0Focus := .named (.firstSecond (.named (.named (.first (.named (.named (.first (.named (.borrow (.named (.here)))))))))) (.first (.named (.here))))
theorem branch3Port0_preserves_current_input0 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch3Port0NativePlan) (accepted : branch3Port0Restore Atom current update = some after) :
    recoverInput0 Atom after = recoverInput0 Atom current :=
  restoration_preserves_disjoint_current branch3Port0_separate_from_input0 Auths.Qualification.NativeBorrowView.branch3Schema0.plan current after (branch3Port0FromNative Atom update) accepted
def branch3Port1Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch3Schema1.shape := .named (.first (.named (.named (.first (.named (.named (.first (.named (.borrow (.here))))))))))
def branch3Port1Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch3Port1NativePlan :=
  branch3Port1ToNative Atom (extract branch3Port1Focus Auths.Qualification.NativeBorrowView.branch3Schema1.plan current)
def branch3Port1Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch3Port1NativePlan) : Option (Data Atom outputShape) :=
  restore branch3Port1Focus Auths.Qualification.NativeBorrowView.branch3Schema1.plan current (branch3Port1FromNative Atom update)
theorem branch3Port1_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch3Port1Restore Atom current (branch3Port1Extract Atom current) = some current := by
  simp [branch3Port1Restore, branch3Port1Extract, branch3Port1_candidate_round_trip, restore_extracted_current]
theorem branch3Port1_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch3Port1NativePlan) (accepted : branch3Port1Restore Atom current update = some after) :
    branch3Port1Extract Atom after = update := by
  have exactView := restored_view_is_update branch3Port1Focus Auths.Qualification.NativeBorrowView.branch3Schema1.plan current after (branch3Port1FromNative Atom update) accepted
  simpa [branch3Port1Extract, exactView, branch3Port1_native_round_trip]
theorem branch3Port1_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch3Port1NativePlan) :
    put (liftPlan branch3Port1Focus Auths.Qualification.NativeBorrowView.branch3Schema1.plan) current
      (liftView branch3Port1Focus Auths.Qualification.NativeBorrowView.branch3Schema1.plan (branch3Port1FromNative Atom update)) = branch3Port1Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch3Port1_separate_from_input0 : Disjoint branch3Port1Focus input0Focus := .named (.firstSecond (.named (.named (.first (.named (.named (.first (.named (.borrow (.here))))))))) (.first (.named (.here))))
theorem branch3Port1_preserves_current_input0 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch3Port1NativePlan) (accepted : branch3Port1Restore Atom current update = some after) :
    recoverInput0 Atom after = recoverInput0 Atom current :=
  restoration_preserves_disjoint_current branch3Port1_separate_from_input0 Auths.Qualification.NativeBorrowView.branch3Schema1.plan current after (branch3Port1FromNative Atom update) accepted
def branch3Port2Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch3Schema0.shape := .named (.first (.named (.named (.first (.named (.named (.first (.named (.borrow (.named (.here)))))))))))
def branch3Port2Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch3Port2NativePlan :=
  branch3Port2ToNative Atom (extract branch3Port2Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan current)
def branch3Port2Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch3Port2NativePlan) : Option (Data Atom outputShape) :=
  restore branch3Port2Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan current (branch3Port2FromNative Atom update)
theorem branch3Port2_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch3Port2Restore Atom current (branch3Port2Extract Atom current) = some current := by
  simp [branch3Port2Restore, branch3Port2Extract, branch3Port2_candidate_round_trip, restore_extracted_current]
theorem branch3Port2_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch3Port2NativePlan) (accepted : branch3Port2Restore Atom current update = some after) :
    branch3Port2Extract Atom after = update := by
  have exactView := restored_view_is_update branch3Port2Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan current after (branch3Port2FromNative Atom update) accepted
  simpa [branch3Port2Extract, exactView, branch3Port2_native_round_trip]
theorem branch3Port2_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch3Port2NativePlan) :
    put (liftPlan branch3Port2Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan) current
      (liftView branch3Port2Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan (branch3Port2FromNative Atom update)) = branch3Port2Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch3Port2_separate_from_input0 : Disjoint branch3Port2Focus input0Focus := .named (.firstSecond (.named (.named (.first (.named (.named (.first (.named (.borrow (.named (.here)))))))))) (.first (.named (.here))))
theorem branch3Port2_preserves_current_input0 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch3Port2NativePlan) (accepted : branch3Port2Restore Atom current update = some after) :
    recoverInput0 Atom after = recoverInput0 Atom current :=
  restoration_preserves_disjoint_current branch3Port2_separate_from_input0 Auths.Qualification.NativeBorrowView.branch3Schema0.plan current after (branch3Port2FromNative Atom update) accepted
def branch3Port3Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch3Schema0.shape := .named (.first (.named (.named (.first (.named (.named (.first (.named (.borrow (.named (.here)))))))))))
def branch3Port3Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch3Port3NativePlan :=
  branch3Port3ToNative Atom (extract branch3Port3Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan current)
def branch3Port3Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch3Port3NativePlan) : Option (Data Atom outputShape) :=
  restore branch3Port3Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan current (branch3Port3FromNative Atom update)
theorem branch3Port3_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch3Port3Restore Atom current (branch3Port3Extract Atom current) = some current := by
  simp [branch3Port3Restore, branch3Port3Extract, branch3Port3_candidate_round_trip, restore_extracted_current]
theorem branch3Port3_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch3Port3NativePlan) (accepted : branch3Port3Restore Atom current update = some after) :
    branch3Port3Extract Atom after = update := by
  have exactView := restored_view_is_update branch3Port3Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan current after (branch3Port3FromNative Atom update) accepted
  simpa [branch3Port3Extract, exactView, branch3Port3_native_round_trip]
theorem branch3Port3_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch3Port3NativePlan) :
    put (liftPlan branch3Port3Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan) current
      (liftView branch3Port3Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan (branch3Port3FromNative Atom update)) = branch3Port3Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch3Port3_separate_from_input0 : Disjoint branch3Port3Focus input0Focus := .named (.firstSecond (.named (.named (.first (.named (.named (.first (.named (.borrow (.named (.here)))))))))) (.first (.named (.here))))
theorem branch3Port3_preserves_current_input0 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch3Port3NativePlan) (accepted : branch3Port3Restore Atom current update = some after) :
    recoverInput0 Atom after = recoverInput0 Atom current :=
  restoration_preserves_disjoint_current branch3Port3_separate_from_input0 Auths.Qualification.NativeBorrowView.branch3Schema0.plan current after (branch3Port3FromNative Atom update) accepted
def branch3Port4Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch3Schema1.shape := .named (.first (.named (.named (.first (.named (.named (.first (.named (.borrow (.here))))))))))
def branch3Port4Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch3Port4NativePlan :=
  branch3Port4ToNative Atom (extract branch3Port4Focus Auths.Qualification.NativeBorrowView.branch3Schema1.plan current)
def branch3Port4Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch3Port4NativePlan) : Option (Data Atom outputShape) :=
  restore branch3Port4Focus Auths.Qualification.NativeBorrowView.branch3Schema1.plan current (branch3Port4FromNative Atom update)
theorem branch3Port4_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch3Port4Restore Atom current (branch3Port4Extract Atom current) = some current := by
  simp [branch3Port4Restore, branch3Port4Extract, branch3Port4_candidate_round_trip, restore_extracted_current]
theorem branch3Port4_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch3Port4NativePlan) (accepted : branch3Port4Restore Atom current update = some after) :
    branch3Port4Extract Atom after = update := by
  have exactView := restored_view_is_update branch3Port4Focus Auths.Qualification.NativeBorrowView.branch3Schema1.plan current after (branch3Port4FromNative Atom update) accepted
  simpa [branch3Port4Extract, exactView, branch3Port4_native_round_trip]
theorem branch3Port4_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch3Port4NativePlan) :
    put (liftPlan branch3Port4Focus Auths.Qualification.NativeBorrowView.branch3Schema1.plan) current
      (liftView branch3Port4Focus Auths.Qualification.NativeBorrowView.branch3Schema1.plan (branch3Port4FromNative Atom update)) = branch3Port4Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch3Port4_separate_from_input0 : Disjoint branch3Port4Focus input0Focus := .named (.firstSecond (.named (.named (.first (.named (.named (.first (.named (.borrow (.here))))))))) (.first (.named (.here))))
theorem branch3Port4_preserves_current_input0 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch3Port4NativePlan) (accepted : branch3Port4Restore Atom current update = some after) :
    recoverInput0 Atom after = recoverInput0 Atom current :=
  restoration_preserves_disjoint_current branch3Port4_separate_from_input0 Auths.Qualification.NativeBorrowView.branch3Schema1.plan current after (branch3Port4FromNative Atom update) accepted
def branch3Port5Focus : Focus outputShape Auths.Qualification.NativeBorrowView.branch3Schema0.shape := .named (.first (.named (.named (.first (.named (.named (.first (.named (.borrow (.named (.here)))))))))))
def branch3Port5Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom branch3Port5NativePlan :=
  branch3Port5ToNative Atom (extract branch3Port5Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan current)
def branch3Port5Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom branch3Port5NativePlan) : Option (Data Atom outputShape) :=
  restore branch3Port5Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan current (branch3Port5FromNative Atom update)
theorem branch3Port5_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :
    branch3Port5Restore Atom current (branch3Port5Extract Atom current) = some current := by
  simp [branch3Port5Restore, branch3Port5Extract, branch3Port5_candidate_round_trip, restore_extracted_current]
theorem branch3Port5_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch3Port5NativePlan) (accepted : branch3Port5Restore Atom current update = some after) :
    branch3Port5Extract Atom after = update := by
  have exactView := restored_view_is_update branch3Port5Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan current after (branch3Port5FromNative Atom update) accepted
  simpa [branch3Port5Extract, exactView, branch3Port5_native_round_trip]
theorem branch3Port5_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)
    (update : View Atom branch3Port5NativePlan) :
    put (liftPlan branch3Port5Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan) current
      (liftView branch3Port5Focus Auths.Qualification.NativeBorrowView.branch3Schema0.plan (branch3Port5FromNative Atom update)) = branch3Port5Restore Atom current update :=
  restore_is_whole_carrier_put _ _ _ _
theorem branch3Port5_separate_from_input0 : Disjoint branch3Port5Focus input0Focus := .named (.firstSecond (.named (.named (.first (.named (.named (.first (.named (.borrow (.named (.here)))))))))) (.first (.named (.here))))
theorem branch3Port5_preserves_current_input0 (Atom : Expr → Type u) (current after : Data Atom outputShape)
    (update : View Atom branch3Port5NativePlan) (accepted : branch3Port5Restore Atom current update = some after) :
    recoverInput0 Atom after = recoverInput0 Atom current :=
  restoration_preserves_disjoint_current branch3Port5_separate_from_input0 Auths.Qualification.NativeBorrowView.branch3Schema0.plan current after (branch3Port5FromNative Atom update) accepted
end Auths.Qualification.CurrentBorrowCarrier
