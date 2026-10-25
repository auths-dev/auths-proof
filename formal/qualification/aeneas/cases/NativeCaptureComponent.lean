import qualification.aeneas.cases.NativeCaptureValue
import qualification.aeneas.cases.NativeBorrowExecution

/-!
The actual candidate capture's pure-data value and four curried backward
interfaces in one component. Its forward statement refers to the retained
native value interpreter, and each backward statement refers to execution of
every actual selected-level ending. These new scripts are unelaborated and
unqualified. Original erased-return/native ADT ABI/default-selection and
Rust/native heap/loan/alias/lifetime adequacy remain required.
-/
namespace Auths.Qualification.NativeCaptureComponent
open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection
open Auths.Qualification.BorrowProjection.Candidate3400
open Auths.Qualification.NativeBorrowExecution
open Auths.Qualification.NativeBorrowDefaults
universe u

structure Component (Atom : Expr → Type u) where
  value : Data Atom outputShape
  backward0 : View Atom branch0Operation0Access.nativePlan →
    View Atom branch0Operation1Access.nativePlan
  backward1 : View Atom branch1Operation2Access.nativePlan →
    View Atom branch1Operation3Access.nativePlan
  backward2 : View Atom branch2Operation2Access.nativePlan →
    View Atom branch2Operation3Access.nativePlan
  backward3 : View Atom branch3Operation4Access.nativePlan →
    View Atom branch3Operation6Access.nativePlan →
    (View Atom branch3Operation5Access.nativePlan ×
      View Atom branch3Operation7Access.nativePlan)

def capture (Atom : Expr → Type u) (input0 : Data Atom input0Shape)
    (input1 : Data Atom input1Shape) : Component Atom :=
  { value := construct Atom input0 input1
    backward0 := branch0Backward Atom
    backward1 := branch1Backward Atom
    backward2 := branch2Backward Atom
    backward3 := branch3Backward Atom }

theorem forward_matches_actual_native_value_trace (Atom : Expr → Type u)
    (input0 : Data Atom input0Shape) (input1 : Data Atom input1Shape) :
    Auths.Support.NativeCaptureValue.run Auths.Qualification.NativeCaptureValue.actualProgram
      [⟨input0Shape, input0⟩, ⟨input1Shape, input1⟩] =
      some ⟨outputShape, (capture Atom input0 input1).value⟩ :=
  Auths.Qualification.NativeCaptureValue.native_forward_value_matches_source_capture Atom input0 input1

theorem backward0_matches_actual_endings (Atom : Expr → Type u)
    (input0 : Data Atom input0Shape) (input1 : Data Atom input1Shape)
    (counter : Data Atom branch0Symbol7CandidateShape)
    (writer : Data Atom branch2Symbol11CandidateShape)
    (update : View Atom branch0Operation0Access.nativePlan) :
    branch0Execute Atom (initialCurrent Atom counter writer) update =
      some ((capture Atom input0 input1).backward0 update) :=
  branch0_execution_normalizes_all_actual_endings Atom counter writer update

theorem backward1_matches_actual_endings (Atom : Expr → Type u)
    (input0 : Data Atom input0Shape) (input1 : Data Atom input1Shape)
    (counter : Data Atom branch0Symbol7CandidateShape)
    (writer : Data Atom branch2Symbol11CandidateShape)
    (update : View Atom branch1Operation2Access.nativePlan) :
    branch1Execute Atom (initialCurrent Atom counter writer) update =
      some ((capture Atom input0 input1).backward1 update) :=
  branch1_execution_normalizes_all_actual_endings Atom counter writer update

theorem backward2_matches_actual_endings (Atom : Expr → Type u)
    (input0 : Data Atom input0Shape) (input1 : Data Atom input1Shape)
    (counter : Data Atom branch0Symbol7CandidateShape)
    (writer : Data Atom branch2Symbol11CandidateShape)
    (update : View Atom branch2Operation2Access.nativePlan) :
    branch2Execute Atom (initialCurrent Atom counter writer) update =
      some ((capture Atom input0 input1).backward2 update) :=
  branch2_execution_normalizes_all_actual_endings Atom counter writer update

theorem backward3_matches_actual_endings (Atom : Expr → Type u)
    (input0 : Data Atom input0Shape) (input1 : Data Atom input1Shape)
    (counter : Data Atom branch0Symbol7CandidateShape)
    (writer : Data Atom branch2Symbol11CandidateShape)
    (level1 : View Atom branch3Operation4Access.nativePlan)
    (level0 : View Atom branch3Operation6Access.nativePlan) :
    branch3Execute Atom (initialCurrent Atom counter writer) level1 level0 =
      some ((capture Atom input0 input1).backward3 level1 level0) :=
  branch3_execution_normalizes_all_actual_endings Atom counter writer level1 level0

end Auths.Qualification.NativeCaptureComponent
